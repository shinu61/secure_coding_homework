# -*- coding: utf-8 -*-
"""송금 경쟁 조건(이중지불) 동시성 테스트.

공격 시나리오: 잔액이 정확히 N원인 계정에서, 각 N원짜리 송금 요청을
여러 개 동시에 발사한다. 취약한 코드(읽고-비교-쓰기 분리)라면 여러 요청이
동시에 잔액 검사를 통과해 이중지불이 발생하고, 보낸 계정 잔액이 음수가 되거나
받은 계정이 실제 차감액보다 많은 돈을 받는다.

수정된 코드(WHERE balance >= ? 원자적 검사 + BEGIN IMMEDIATE)라면
정확히 1건만 성공하고 나머지는 '잔액 부족'으로 거부되어야 한다.
"""
import re
import sys
import threading
import uuid

import requests

BASE = "http://127.0.0.1:5000"
PW = "TestPass123!"


def get_csrf(sess, url):
    r = sess.get(url)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else None


def register(sess, username, password):
    token = get_csrf(sess, f"{BASE}/register")
    sess.post(f"{BASE}/register", data={
        "csrf_token": token, "username": username, "password": password})


def login(sess, username, password):
    token = get_csrf(sess, f"{BASE}/login")
    sess.post(f"{BASE}/login", data={
        "csrf_token": token, "username": username, "password": password})


def get_balance(sess):
    r = sess.get(f"{BASE}/transfer")
    m = re.search(r"내 잔액: <strong>([\d,-]+)원", r.text)
    return int(m.group(1).replace(",", "")) if m else None


suffix = uuid.uuid4().hex[:6]
attacker = f"atk_{suffix}"
victim = f"vic_{suffix}"

sa = requests.Session()
sv = requests.Session()
register(sa, attacker, PW)
register(sv, victim, PW)
login(sa, attacker, PW)
login(sv, victim, PW)

# 공격자 잔액을 정확히 N원으로 맞춘다.
# 신규 계정 기본 잔액 1,000,000원. victim에게 여분을 전부 보내 attacker를 N원으로 세팅.
N = 10_000            # 한 번만 성공해야 할 송금액
CONCURRENCY = 20      # 동시에 쏘는 요청 수

start_bal = get_balance(sa)
drain = start_bal - N
token = get_csrf(sa, f"{BASE}/transfer")
sa.post(f"{BASE}/transfer", data={
    "csrf_token": token, "to_username": victim, "amount": str(drain)})

atk_before = get_balance(sa)
vic_before = get_balance(sv)
print(f"[setup] attacker balance = {atk_before:,} (target N={N:,}), victim balance = {vic_before:,}")
assert atk_before == N, f"셋업 실패: attacker 잔액이 {atk_before}, 기대값 {N}"

# CSRF 토큰은 미리 하나 확보 (같은 세션에서 재사용 가능)
csrf = get_csrf(sa, f"{BASE}/transfer")

results = []
barrier = threading.Barrier(CONCURRENCY)


def attack():
    # 모든 스레드가 동시에 출발하도록 배리어로 정렬 -> 경쟁 조건 극대화
    s = requests.Session()
    s.cookies.update(sa.cookies)
    barrier.wait()
    try:
        r = s.post(f"{BASE}/transfer",
                   data={"csrf_token": csrf, "to_username": victim, "amount": str(N)},
                   timeout=30)
        ok = "송금했습니다" in r.text
        insufficient = "잔액이 부족" in r.text
        results.append("success" if ok else ("insufficient" if insufficient else "other"))
    except Exception as e:
        results.append(f"error:{e!r}")


threads = [threading.Thread(target=attack) for _ in range(CONCURRENCY)]
for t in threads:
    t.start()
for t in threads:
    t.join()

successes = results.count("success")
insufficients = results.count("insufficient")
others = [r for r in results if r not in ("success", "insufficient")]

atk_after = get_balance(sa)
vic_after = get_balance(sv)

print(f"\n[result] {CONCURRENCY}개 동시 요청 중: 성공={successes}, 잔액부족거부={insufficients}, 기타={others}")
print(f"[result] attacker balance: {atk_before:,} -> {atk_after:,}")
print(f"[result] victim balance:   {vic_before:,} -> {vic_after:,}")

fails = []
if successes != 1:
    fails.append(f"성공 건수가 {successes} (정확히 1이어야 이중지불 없음)")
if atk_after < 0:
    fails.append(f"attacker 잔액이 음수({atk_after}) -> 이중지불 발생")
if atk_after != atk_before - N * successes:
    fails.append(f"attacker 차감액 불일치: {atk_before}-{N}*{successes} != {atk_after}")
if vic_after != vic_before + N * successes:
    fails.append(f"victim 증가액 불일치: 통화량 보존 위반")
if others:
    fails.append(f"예상 못한 응답: {others}")

print("\n========================================")
if fails:
    print("RACE TEST: FAIL")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("RACE TEST: PASS  (동시 요청에도 정확히 1건만 성공, 이중지불 없음, 통화량 보존)")
    sys.exit(0)
