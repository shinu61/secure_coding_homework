# -*- coding: utf-8 -*-
"""신고 담합(Sybil) 방어 + 엔드포인트 속도 제한(Flask-Limiter) 테스트.

두 기능은 서버 설정이 상반되므로(속도 제한 ON이면 담합 테스트의 다수 요청이 429가 됨)
PHASE 환경변수로 위상을 나눠 실행한다:
  PHASE=sybil     : 서버를 RATELIMIT_ENABLED=false 로 띄우고 담합 방어 검증
  PHASE=ratelimit : 서버를 RATELIMIT_ENABLED=true  로 띄우고 429 반환 검증

flagged/status 같은 서버 내부 상태는 market.db를 직접 읽어 정확히 단언한다.
"""
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone

import requests

BASE = "http://127.0.0.1:5000"
DB_PATH = os.environ.get("DATABASE_PATH", "market.db")
PW = "TestPass123!"
PHASE = os.environ.get("PHASE", "sybil")

results = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    results.append((status, name, detail))
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))


def get_csrf(sess, url):
    r = sess.get(url)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else None


def register(sess, username, password=PW):
    token = get_csrf(sess, f"{BASE}/register")
    return sess.post(f"{BASE}/register", data={
        "csrf_token": token, "username": username, "password": password})


def login(sess, username, password=PW):
    token = get_csrf(sess, f"{BASE}/login")
    return sess.post(f"{BASE}/login", data={
        "csrf_token": token, "username": username, "password": password})


def new_account(username):
    s = requests.Session()
    register(s, username)
    login(s, username)
    return s


def create_product(sess, title):
    token = get_csrf(sess, f"{BASE}/product/new")
    sess.post(f"{BASE}/product/new", data={
        "csrf_token": token, "title": title, "description": "설명", "price": "1000"})
    r = sess.get(f"{BASE}/dashboard")
    m = re.search(r'/product/([0-9a-f-]{36})"[^>]*>' + re.escape(title), r.text)
    return m.group(1) if m else None


def report_target(sess, ttype, tid, reason="담합 신고 테스트"):
    token = get_csrf(sess, f"{BASE}/report")
    return sess.post(f"{BASE}/report", data={
        "csrf_token": token, "target_type": ttype, "target_id": tid, "reason": reason})


def db_conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def product_row(pid):
    c = db_conn()
    row = c.execute("SELECT status, flagged FROM product WHERE id=?", (pid,)).fetchone()
    c.close()
    return row


def user_id_of(username):
    c = db_conn()
    row = c.execute("SELECT id FROM user WHERE username=?", (username,)).fetchone()
    c.close()
    return row["id"] if row else None


def user_row(uid):
    c = db_conn()
    row = c.execute("SELECT status, flagged FROM user WHERE id=?", (uid,)).fetchone()
    c.close()
    return row


def backdate_account(username, days=2):
    """계정 created_at을 과거로 이동시켜 '신뢰 계정'(가중치 1.0)으로 만든다."""
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    c = db_conn()
    c.execute("UPDATE user SET created_at=? WHERE username=?", (old, username))
    c.commit()
    c.close()


def run_sybil():
    suffix = uuid.uuid4().hex[:6]

    # 피해자(정상 사용자)와 그가 등록한 상품 2개
    victim = new_account(f"vic_{suffix}")
    p_fresh = create_product(victim, f"정상상품A_{suffix}")   # 신규계정 담합 대상
    p_estab = create_product(victim, f"정상상품B_{suffix}")   # 신뢰계정 신고 대상
    check("setup: victim products created", bool(p_fresh and p_estab))

    # 비소유자 관찰용 계정
    observer = new_account(f"obs_{suffix}")

    # ---- 시나리오 1: 갓 만든 계정 3개의 담합 -> 자동 차단/큐 진입 모두 실패 ----
    fresh = [new_account(f"fresh{i}_{suffix}") for i in range(3)]
    for s in fresh:
        r = report_target(s, "product", p_fresh)
        assert "신고가 접수" in r.text or "이미" in r.text
    row = product_row(p_fresh)
    check("Sybil(신규3): 상품이 차단되지 않음", row["status"] == "active")
    check("Sybil(신규3): 검토 큐에도 오르지 않음(flagged=0)", row["flagged"] == 0)
    # 비소유자도 정상적으로 열람 가능(차단 아님)
    r = observer.get(f"{BASE}/product/{p_fresh}", allow_redirects=True)
    check("Sybil(신규3): 타인도 정상 열람", f"정상상품A_{suffix}" in r.text and "차단된 상품" not in r.text)

    # ---- 시나리오 2: 신뢰(오래된) 계정 3개 신고 -> 검토 큐 진입하나 승인 전엔 차단 안 됨 ----
    estab = []
    for i in range(3):
        uname = f"old{i}_{suffix}"
        s = new_account(uname)
        backdate_account(uname, days=2)   # 신고 전 계정 나이를 2일로 -> 가중치 1.0
        estab.append(s)
    for s in estab:
        r = report_target(s, "product", p_estab)
        assert "신고가 접수" in r.text
    row = product_row(p_estab)
    check("신뢰3: 검토 큐 등록됨(flagged=1)", row["flagged"] == 1)
    check("신뢰3: 관리자 승인 전에는 차단되지 않음(status=active)", row["status"] == "active")
    r = observer.get(f"{BASE}/product/{p_estab}", allow_redirects=True)
    check("신뢰3: 승인 전 타인도 정상 열람", f"정상상품B_{suffix}" in r.text and "차단된 상품" not in r.text)

    # 관리자 로그인 -> 검토 큐 노출 확인
    admin = requests.Session()
    login(admin, "admin", os.environ.get("ADMIN_PASSWORD", "ChangeMe123!"))
    r = admin.get(f"{BASE}/admin")
    check("관리자 검토 큐에 대상 노출", "신고 검토 큐" in r.text and f"정상상품B_{suffix}" in r.text)

    # 관리자 승인 -> 이제서야 차단 확정
    token = get_csrf(admin, f"{BASE}/admin")
    r = admin.post(f"{BASE}/admin/product/{p_estab}/block", data={"csrf_token": token})
    check("관리자 승인 시 차단 확정", "상품을 차단" in r.text)
    row = product_row(p_estab)
    check("승인 후 status=blocked, flagged=0", row["status"] == "blocked" and row["flagged"] == 0)
    r = observer.get(f"{BASE}/product/{p_estab}", allow_redirects=True)
    check("승인 후 타인 열람 차단", "차단된 상품" in r.text)

    # ---- 시나리오 3: 사용자 대상 담합 + 자기 자신 신고 차단 ----
    # 신뢰 계정 3개가 victim(사용자)을 신고 -> 큐 등록되나 휴면은 승인에서만
    victim_id = user_id_of(f"vic_{suffix}")
    for s in estab:
        r = report_target(s, "user", victim_id)
        assert "신고가 접수" in r.text
    urow = user_row(victim_id)
    check("사용자 신뢰3: 검토 큐 등록(flagged=1)", urow["flagged"] == 1)
    check("사용자 신뢰3: 승인 전 휴면 아님(active)", urow["status"] == "active")

    # 자기 자신(사용자) 신고 차단
    r = report_target(victim, "user", victim_id)
    check("자기 자신(사용자) 신고 차단", "본인 계정은 신고할 수 없습니다" in r.text)

    # 관리자 휴면 승인 -> 확정
    token = get_csrf(admin, f"{BASE}/admin")
    r = admin.post(f"{BASE}/admin/user/{victim_id}/suspend", data={"csrf_token": token})
    check("관리자 휴면 승인", "휴면 처리" in r.text)
    urow = user_row(victim_id)
    check("휴면 승인 후 status=suspended, flagged=0",
          urow["status"] == "suspended" and urow["flagged"] == 0)

    # 관리자 반려 흐름: fresh 상품에 신뢰계정으로 다시 신고해 큐에 올린 뒤 반려
    for s in estab:
        report_target(s, "product", p_fresh)
    check("반려 준비: p_fresh 큐 등록", product_row(p_fresh)["flagged"] == 1)
    token = get_csrf(admin, f"{BASE}/admin")
    r = admin.post(f"{BASE}/admin/product/{p_fresh}/dismiss", data={"csrf_token": token})
    check("관리자 반려 처리", "반려" in r.text)
    row = product_row(p_fresh)
    check("반려 후 차단 안 됨, 큐에서 제거(active, flagged=0)",
          row["status"] == "active" and row["flagged"] == 0)


def run_ratelimit():
    suffix = uuid.uuid4().hex[:6]

    # register: 10/분 -> 11번째 POST에서 429
    saw_429_register = False
    reg_statuses = []
    for i in range(13):
        s = requests.Session()
        token = get_csrf(s, f"{BASE}/register")
        r = s.post(f"{BASE}/register", data={
            "csrf_token": token, "username": f"rl{i}_{suffix}", "password": PW},
            allow_redirects=False)
        reg_statuses.append(r.status_code)
        if r.status_code == 429:
            saw_429_register = True
            body = r.text
    check("register 한도 초과 시 429 반환", saw_429_register, f"statuses={reg_statuses}")
    if saw_429_register:
        check("429 응답에 사용자 친화 메시지", "요청이 너무 많습니다" in body)

    # login: 10/분 -> 11번째 POST에서 429 (존재하지 않는 계정 -> 계정 잠금과 무관)
    saw_429_login = False
    login_statuses = []
    for i in range(13):
        s = requests.Session()
        token = get_csrf(s, f"{BASE}/login")
        r = s.post(f"{BASE}/login", data={
            "csrf_token": token, "username": f"nouser_{suffix}_{i}", "password": PW},
            allow_redirects=False)
        login_statuses.append(r.status_code)
        if r.status_code == 429:
            saw_429_login = True
    check("login 한도 초과 시 429 반환", saw_429_login, f"statuses={login_statuses}")


if __name__ == "__main__":
    print(f"=== PHASE={PHASE} ===")
    if PHASE == "sybil":
        run_sybil()
    elif PHASE == "ratelimit":
        run_ratelimit()
    else:
        print(f"unknown PHASE: {PHASE}")
        sys.exit(2)

    fails = [x for x in results if x[0] == "FAIL"]
    print("\n========================================")
    print(f"[{PHASE}] TOTAL: {len(results)}  PASS: {len(results)-len(fails)}  FAIL: {len(fails)}")
    for f in fails:
        print(f"  FAIL: {f[1]} -- {f[2]}")
    sys.exit(1 if fails else 0)
