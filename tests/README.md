# 자동 테스트

실행 중인 서버(`python app.py`, 기본 http://127.0.0.1:5000)를 대상으로 하는
HTTP/웹소켓 기반 엔드투엔드 테스트입니다. 별도 실행 중인 서버가 필요합니다.

의존성(서버 의존성 외 테스트 전용):

```bash
pip install requests websocket-client
```

## 파일

| 파일 | 내용 | 서버 실행 조건 |
|---|---|---|
| `test_market.py` | 전체 기능 회귀 (회원가입/로그인/상품/검색/소유자검증/CSRF/XSS/SQLi/송금/신고/관리자/채팅) | `RATELIMIT_ENABLED=false` |
| `test_race.py` | 송금 경쟁 조건(이중지불) 동시성 테스트 (20개 동시 요청) | `RATELIMIT_ENABLED=false` |
| `test_sybil_ratelimit.py` | 신고 담합(Sybil) 방어 + 속도 제한 429. `PHASE`로 위상 분리 | 아래 참고 |

`test_sybil_ratelimit.py`는 두 기능의 서버 설정이 상반되므로 위상을 나눠 실행합니다.

```bash
# 1) 담합 방어: 서버를 RATELIMIT_ENABLED=false 로 띄운 뒤
PHASE=sybil     python tests/test_sybil_ratelimit.py

# 2) 속도 제한: 서버를 RATELIMIT_ENABLED=true 로 띄운 뒤
PHASE=ratelimit python tests/test_sybil_ratelimit.py
```

## 실행 예시 (Windows PowerShell)

```powershell
# 회귀/동시성/담합 (속도 제한 OFF)
$env:RATELIMIT_ENABLED='false'; python app.py    # 별도 터미널
python tests\test_market.py
python tests\test_race.py
$env:PHASE='sybil'; python tests\test_sybil_ratelimit.py

# 속도 제한 (429) 검증 (속도 제한 ON)
$env:RATELIMIT_ENABLED='true'; python app.py     # 서버 재시작
$env:PHASE='ratelimit'; python tests\test_sybil_ratelimit.py
```

> 참고: 파이썬 `requests`로 접속할 때 `localhost`는 IPv6 경로 때문에 요청당 지연이
> 생길 수 있어 테스트는 `127.0.0.1`을 사용합니다.
