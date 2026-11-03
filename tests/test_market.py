# -*- coding: utf-8 -*-
"""tiny-secondhand-market end-to-end functional test"""
import re
import sys
import time
import uuid

import requests

BASE = "http://127.0.0.1:5000"
results = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    results.append((status, name, detail))
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))


def get_csrf(sess, url):
    r = sess.get(url)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else None


def register(sess, username, password):
    token = get_csrf(sess, f"{BASE}/register")
    return sess.post(f"{BASE}/register", data={
        "csrf_token": token, "username": username, "password": password})


def login(sess, username, password):
    token = get_csrf(sess, f"{BASE}/login")
    return sess.post(f"{BASE}/login", data={
        "csrf_token": token, "username": username, "password": password})


suffix = uuid.uuid4().hex[:6]
U = {name: f"{name}_{suffix}" for name in ("alice", "bob", "carol", "dave", "eve")}
PW = "TestPass123!"

S = {name: requests.Session() for name in U}

# ---------------- 1. Registration ----------------
r = register(S["alice"], U["alice"], PW)
check("register alice", "로그인 해주세요" in r.text or "로그인" in r.text)

# invalid username
r = register(requests.Session(), "한글이름!!", PW)
check("register rejects invalid username", "영문/숫자/밑줄" in r.text)

# short password
r = register(requests.Session(), f"x_{suffix}", "short")
check("register rejects short password", "8~64자" in r.text)

# duplicate username
r = register(requests.Session(), U["alice"], PW)
check("register rejects duplicate username", "이미 존재" in r.text)

for name in ("bob", "carol", "dave", "eve"):
    register(S[name], U[name], PW)

# ---------------- 2. Login ----------------
r = login(S["alice"], U["alice"], PW)
check("login alice", "로그인 성공" in r.text)
for name in ("bob", "carol", "dave", "eve"):
    r = login(S[name], U[name], PW)
    check(f"login {name}", "로그인 성공" in r.text)

# wrong password generic message
r = login(requests.Session(), U["alice"], "WrongPass1!")
check("login wrong pw generic msg", "아이디 또는 비밀번호가 올바르지 않습니다" in r.text)

# ---------------- 3. Auth required ----------------
r = requests.get(f"{BASE}/dashboard", allow_redirects=True)
check("dashboard requires login", "로그인이 필요" in r.text or "로그인" in r.text)

# ---------------- 4. Product create ----------------
title = f"테스트상품_{suffix}"
token = get_csrf(S["alice"], f"{BASE}/product/new")
r = S["alice"].post(f"{BASE}/product/new", data={
    "csrf_token": token, "title": title, "description": "설명입니다", "price": "10000"})
check("alice creates product", "상품이 등록되었습니다" in r.text)

# find product id from dashboard
r = S["alice"].get(f"{BASE}/dashboard")
m = re.search(r'/product/([0-9a-f-]{36})"[^>]*>' + re.escape(title), r.text)
check("product appears on dashboard", m is not None)
pid = m.group(1) if m else None

# invalid price
token = get_csrf(S["alice"], f"{BASE}/product/new")
r = S["alice"].post(f"{BASE}/product/new", data={
    "csrf_token": token, "title": "bad", "description": "x", "price": "-5"})
check("product rejects negative price", "가격은" in r.text)

# XSS attempt in product title -> should be escaped on dashboard
xss_title = f'<script>alert(1)</script>{suffix}'
token = get_csrf(S["alice"], f"{BASE}/product/new")
r = S["alice"].post(f"{BASE}/product/new", data={
    "csrf_token": token, "title": xss_title, "description": "xss test", "price": "1"})
r = S["alice"].get(f"{BASE}/dashboard")
check("XSS title escaped", "<script>alert(1)</script>" not in r.text
      and "&lt;script&gt;" in r.text)

# ---------------- 5. Search ----------------
r = S["bob"].get(f"{BASE}/search", params={"q": title[:5]})
check("search finds product", title in r.text)
r = S["bob"].get(f"{BASE}/search", params={"q": "' OR 1=1 --"})
check("search SQLi returns no products", title not in r.text)

# ---------------- 6. Ownership ----------------
r = S["bob"].get(f"{BASE}/product/{pid}")
check("bob sees product page", title in r.text)
check("bob does not see edit/delete", "삭제하시겠습니까" not in r.text)

r = S["bob"].get(f"{BASE}/product/{pid}/edit")
check("bob GET edit -> 403", r.status_code == 403)

token = get_csrf(S["bob"], f"{BASE}/transfer")  # any page with csrf
r = S["bob"].post(f"{BASE}/product/{pid}/delete", data={"csrf_token": token})
check("bob POST delete -> 403", r.status_code == 403)

# CSRF missing token
r = S["alice"].post(f"{BASE}/product/{pid}/delete", data={})
check("delete without CSRF token rejected", r.status_code == 400)

# alice can edit
token = get_csrf(S["alice"], f"{BASE}/product/{pid}/edit")
r = S["alice"].post(f"{BASE}/product/{pid}/edit", data={
    "csrf_token": token, "title": title, "description": "수정된 설명", "price": "20000"})
check("alice edits own product", "수정되었습니다" in r.text)

# ---------------- 7. Profile ----------------
token = get_csrf(S["alice"], f"{BASE}/profile")
r = S["alice"].post(f"{BASE}/profile", data={"csrf_token": token, "bio": "안녕하세요 <b>bold</b>"})
check("profile bio update", "업데이트되었습니다" in r.text)
r = S["alice"].get(f"{BASE}/profile")
check("bio XSS escaped", "<b>bold</b>" not in r.text)

# password change wrong current
token = get_csrf(S["alice"], f"{BASE}/profile")
r = S["alice"].post(f"{BASE}/profile/password", data={
    "csrf_token": token, "current_password": "wrong", "new_password": "NewPass123!"})
check("pw change rejects wrong current pw", "현재 비밀번호가 올바르지" in r.text)

# password change success + relogin
token = get_csrf(S["alice"], f"{BASE}/profile")
r = S["alice"].post(f"{BASE}/profile/password", data={
    "csrf_token": token, "current_password": PW, "new_password": "NewPass123!"})
check("pw change success", "비밀번호가 변경되었습니다" in r.text)
s2 = requests.Session()
r = login(s2, U["alice"], "NewPass123!")
check("login with new pw", "로그인 성공" in r.text)
# restore
token = get_csrf(S["alice"], f"{BASE}/profile")
S["alice"].post(f"{BASE}/profile/password", data={
    "csrf_token": token, "current_password": "NewPass123!", "new_password": PW})

# ---------------- 8. Transfer ----------------
def get_balance(sess):
    r = sess.get(f"{BASE}/transfer")
    m = re.search(r"내 잔액: <strong>([\d,]+)원", r.text)
    return int(m.group(1).replace(",", "")) if m else None

bal_bob_before = get_balance(S["bob"])
bal_alice_before = get_balance(S["alice"])
token = get_csrf(S["bob"], f"{BASE}/transfer")
r = S["bob"].post(f"{BASE}/transfer", data={
    "csrf_token": token, "to_username": U["alice"], "amount": "5000"})
check("bob transfers 5000 to alice", "송금했습니다" in r.text)
check("bob balance decreased", get_balance(S["bob"]) == bal_bob_before - 5000)
check("alice balance increased", get_balance(S["alice"]) == bal_alice_before + 5000)

# overdraft (상한 이내지만 잔액 초과 -> 잔액 부족으로 거부)
token = get_csrf(S["bob"], f"{BASE}/transfer")
r = S["bob"].post(f"{BASE}/transfer", data={
    "csrf_token": token, "to_username": U["alice"], "amount": "50000000"})
check("overdraft rejected", "잔액이 부족" in r.text)

# 상한 초과 (1억 초과 -> 상한 검증에서 거부)
token = get_csrf(S["bob"], f"{BASE}/transfer")
r = S["bob"].post(f"{BASE}/transfer", data={
    "csrf_token": token, "to_username": U["alice"], "amount": "100000001"})
check("transfer above cap rejected", "최대" in r.text and "가능합니다" in r.text)

# self transfer
token = get_csrf(S["bob"], f"{BASE}/transfer")
r = S["bob"].post(f"{BASE}/transfer", data={
    "csrf_token": token, "to_username": U["bob"], "amount": "100"})
check("self transfer rejected", "본인에게는" in r.text)

# negative amount
token = get_csrf(S["bob"], f"{BASE}/transfer")
r = S["bob"].post(f"{BASE}/transfer", data={
    "csrf_token": token, "to_username": U["alice"], "amount": "-100"})
check("negative amount rejected", "1 이상의 숫자" in r.text)

# unknown user
token = get_csrf(S["bob"], f"{BASE}/transfer")
r = S["bob"].post(f"{BASE}/transfer", data={
    "csrf_token": token, "to_username": "no_such_user_xyz", "amount": "100"})
check("unknown receiver rejected", "받는 사람을 찾을 수 없습니다" in r.text)

# ---------------- 9. Report (Sybil 방어: 자동차단 없음) ----------------
def report_target(sess, ttype, tid, reason="사기 의심"):
    token = get_csrf(sess, f"{BASE}/report")
    return sess.post(f"{BASE}/report", data={
        "csrf_token": token, "target_type": ttype, "target_id": tid, "reason": reason})

r = report_target(S["bob"], "product", pid)
check("bob reports product", "신고가 접수" in r.text)
r = report_target(S["bob"], "product", pid)
check("duplicate report rejected", "이미 해당 대상을 신고" in r.text)
r = report_target(S["carol"], "product", pid)
check("carol reports product", "신고가 접수" in r.text)
r = report_target(S["dave"], "product", pid)
check("dave reports product (3rd)", "신고가 접수" in r.text)

# 신규 계정 3개 신고로는 자동 차단되지 않아야 함 (가중 0.5*3=1.5 < 3.0) — Sybil 방어
r = S["bob"].get(f"{BASE}/dashboard")
check("product NOT auto-blocked by fresh accounts", f'/product/{pid}"' in r.text)
r = S["bob"].get(f"{BASE}/product/{pid}", allow_redirects=True)
check("product still viewable (not blocked)", title in r.text and "차단된 상품" not in r.text)

# 자기 자신 신고 차단: alice는 pid의 판매자이므로 본인 상품 신고 불가
r = report_target(S["alice"], "product", pid)
check("self product report rejected", "본인이 등록한 상품" in r.text)

# invalid report target
r = report_target(S["bob"], "product", "nonexistent-id")
check("report unknown target rejected", "신고 대상을 찾을 수 없습니다" in r.text)

# ---------------- 10. Login lockout ----------------
lock_user = f"lock_{suffix}"
ls = requests.Session()
register(ls, lock_user, PW)
for i in range(5):
    r = login(requests.Session(), lock_user, "WrongPass!!")
r = login(requests.Session(), lock_user, PW)
check("account locked after 5 failures", "잠시 잠겼습니다" in r.text)

# ---------------- 11. Admin ----------------
A = requests.Session()
r = login(A, "admin", "ChangeMe123!")
check("admin login", "로그인 성공" in r.text)

r = S["bob"].get(f"{BASE}/admin")
check("non-admin blocked from /admin", r.status_code == 403)

r = A.get(f"{BASE}/admin")
check("admin dashboard loads", "관리자" in r.text or r.status_code == 200)
check("admin sees open reports", "open" in r.text or "신고" in r.text)
check("admin review queue present", "신고 검토 큐" in r.text)

# admin이 직접 상품 차단(관리자 조치는 항상 허용) -> 차단/해제 흐름 검증
token = get_csrf(A, f"{BASE}/admin")
r = A.post(f"{BASE}/admin/product/{pid}/block", data={"csrf_token": token})
check("admin blocks product", "상품을 차단" in r.text)
r = S["bob"].get(f"{BASE}/product/{pid}", allow_redirects=True)
check("blocked product inaccessible to others", "차단된 상품" in r.text)
r = S["alice"].get(f"{BASE}/product/{pid}")
check("owner can still view blocked product", title in r.text)

# admin unblock product
token = get_csrf(A, f"{BASE}/admin")
r = A.post(f"{BASE}/admin/product/{pid}/unblock", data={"csrf_token": token})
check("admin unblocks product", "차단을 해제" in r.text)
r = S["bob"].get(f"{BASE}/product/{pid}")
check("product visible again", title in r.text)

# admin suspend user eve
r = A.get(f"{BASE}/admin")
m = re.search(r'/admin/user/([0-9a-f-]{36})/suspend', r.text)
# find eve's id via form on admin page -- instead suspend via username lookup:
# simpler: report eve 3 times to test auto-suspend
# get eve id from a product she creates
token = get_csrf(S["eve"], f"{BASE}/product/new")
S["eve"].post(f"{BASE}/product/new", data={
    "csrf_token": token, "title": f"eve상품_{suffix}", "description": "d", "price": "1"})
r = S["eve"].get(f"{BASE}/dashboard")
m = re.search(r'/product/([0-9a-f-]{36})"[^>]*>' + re.escape(f"eve상품_{suffix}"), r.text)
eve_pid = m.group(1)
r = S["bob"].get(f"{BASE}/product/{eve_pid}")
# seller id not directly exposed; get via admin page
r = A.get(f"{BASE}/admin")
m = re.search(r"<td>" + re.escape(U["eve"]) + r"</td>.*?/admin/user/([0-9a-f-]{36})/suspend",
              r.text, re.S)
if not m:
    m = re.search(re.escape(U["eve"]) + r".*?/admin/user/([0-9a-f-]{36})/", r.text, re.S)
eve_id = m.group(1) if m else None
check("found eve id on admin page", eve_id is not None)

token = get_csrf(A, f"{BASE}/admin")
r = A.post(f"{BASE}/admin/user/{eve_id}/suspend", data={"csrf_token": token})
check("admin suspends eve", "휴면 처리" in r.text)

r = S["eve"].get(f"{BASE}/dashboard", allow_redirects=True)
check("suspended eve kicked out", "휴면" in r.text)
r = login(requests.Session(), U["eve"], PW)
check("suspended eve cannot login", "휴면" in r.text)

token = get_csrf(A, f"{BASE}/admin")
r = A.post(f"{BASE}/admin/user/{eve_id}/unsuspend", data={"csrf_token": token})
check("admin unsuspends eve", "휴면을 해제" in r.text)
r = login(S["eve"], U["eve"], PW)
check("eve can login again", "로그인 성공" in r.text)

# admin resolve report (open 신고 하나 생성 후 처리) - carol이 eve 상품 신고(판매자!=carol)
report_target(S["carol"], "product", eve_pid)
r = A.get(f"{BASE}/admin")
m = re.search(r'/admin/report/([0-9a-f-]{36})/resolve', r.text)
if m:
    token = get_csrf(A, f"{BASE}/admin")
    r = A.post(f"{BASE}/admin/report/{m.group(1)}/resolve", data={"csrf_token": token})
    check("admin resolves report", "처리 완료" in r.text)
else:
    check("admin resolves report", False, "no open report found on admin page")

# admin delete product
token = get_csrf(A, f"{BASE}/admin")
r = A.post(f"{BASE}/admin/product/{eve_pid}/delete", data={"csrf_token": token})
check("admin deletes product", "상품을 삭제" in r.text)

# ---------------- 12. Chat (websocket) ----------------
try:
    import socketio as sio_client

    received = []
    c1 = sio_client.Client()
    c2 = sio_client.Client()

    cookie1 = "; ".join(f"{k}={v}" for k, v in S["alice"].cookies.get_dict().items())
    cookie2 = "; ".join(f"{k}={v}" for k, v in S["bob"].cookies.get_dict().items())

    @c2.on("message")
    def on_msg(data):
        received.append(data)

    c1.connect(BASE, headers={"Cookie": cookie1})
    c2.connect(BASE, headers={"Cookie": cookie2})
    c1.emit("join", {"room": "general"})
    c2.emit("join", {"room": "general"})
    time.sleep(0.5)
    c1.emit("send_message", {"room": "general", "message": f"안녕하세요 {suffix}"})
    time.sleep(1.5)
    check("chat message delivered", any(f"안녕하세요 {suffix}" in str(d) for d in received),
          str(received))
    check("chat username from server session",
          any(d.get("username") == U["alice"] for d in received if isinstance(d, dict)))

    # rate limit: two messages within 0.5s -> only one delivered.
    # 서버가 두 이벤트를 동시에 처리하면 도착 순서가 바뀔 수 있으므로
    # "어느 쪽이든 정확히 하나만 전달"을 확인한다.
    received.clear()
    c1.emit("send_message", {"room": "general", "message": "msg1"})
    c1.emit("send_message", {"room": "general", "message": "msg2"})
    time.sleep(1.5)
    texts = [d.get("message") for d in received
             if isinstance(d, dict) and d.get("message") in ("msg1", "msg2")]
    check("chat rate limit drops rapid 2nd msg", len(texts) == 1, str(texts))

    c1.disconnect(); c2.disconnect()

    # unauthenticated socket rejected
    c3 = sio_client.Client()
    rejected = False
    try:
        c3.connect(BASE, wait_timeout=5)
        time.sleep(0.5)
        ok = c3.connected
        c3.disconnect()
        rejected = not ok
    except Exception:
        rejected = True
    check("unauthenticated socket rejected", rejected)
except Exception as e:
    check("chat websocket test", False, repr(e))

# chat page history renders
r = S["alice"].get(f"{BASE}/chat")
check("general chat page loads", "전체 채팅" in r.text)

# DM page
r = A.get(f"{BASE}/admin")
m = re.search(re.escape(U["bob"]) + r".*?/admin/user/([0-9a-f-]{36})/", r.text, re.S)
bob_id = m.group(1)
r = S["alice"].get(f"{BASE}/chat/{bob_id}")
check("DM chat page loads", "님과의 채팅" in r.text)

# ---------------- Summary ----------------
fails = [x for x in results if x[0] == "FAIL"]
print("\n========================================")
print(f"TOTAL: {len(results)}  PASS: {len(results)-len(fails)}  FAIL: {len(fails)}")
for f in fails:
    print(f"  FAIL: {f[1]} -- {f[2]}")
sys.exit(1 if fails else 0)
