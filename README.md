# Tiny Second-hand Shopping Platform (중고거래 플랫폼)

Secure Coding 과제 제출용 프로젝트입니다. Flask + Flask-SocketIO + SQLite 기반으로,
교수님이 제공하신 취약한 스타터 코드(`https://github.com/ugonfor/secure-coding`)를
확장하여 7가지 요구사항을 구현하고, `secure_coding_checklist.csv`의 모든 보안 항목을
반영했습니다.

## 주요 기능

- 회원가입 / 로그인 / 로그아웃 (비밀번호 해시 저장, 로그인 실패 잠금)
- 상품 등록 / 조회 / 수정 / 삭제 (소유자 검증)
- 상품 검색
- 전체 채팅 + 1:1 채팅 (Socket.IO)
- 신고 기능 (상품/사용자). 누적 신고는 **자동 차단하지 않고 관리자 검토 큐(pending)**에만
  올리며, 최종 차단/휴면은 관리자 승인에서 확정 — 소수 계정 담합(Sybil) 방어. 신고자
  계정 나이에 따라 신고 가중치 차등(신규 계정 영향 축소)
- 유저 간 송금 (가상 잔액, 경쟁 조건 방지 원자적 트랜잭션)
- 관리자 페이지 (신고 검토 큐 승인/반려, 사용자 휴면 처리, 상품 차단/삭제, 신고 처리)
- 엔드포인트 속도 제한 (Flask-Limiter: 로그인/회원가입/송금/신고)

## 환경 설정

```bash
# 1. (권장) 가상환경 생성
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate (또는 venv\bin\Activate.ps1)

# 2. 의존성 설치
pip install -r requirements.txt
```

## 실행 방법

```bash
python app.py
```

기본적으로 `http://localhost:5000` 에서 서버가 실행됩니다.
최초 실행 시 `market.db` 파일이 자동 생성되고, 관리자 계정(`admin`)이 자동으로
만들어집니다. 초기 비밀번호는 콘솔 로그에 출력되니 **최초 로그인 후 반드시 비밀번호를
변경**하세요.

외부에서 접속 테스트가 필요하면 ngrok으로 포워딩할 수 있습니다.

```bash
ngrok http 5000
```

### 환경변수 (선택)

| 변수 | 설명 | 기본값 |
|---|---|---|
| `SECRET_KEY` | Flask 세션 서명 키 | 실행 시 랜덤 생성 |
| `ADMIN_PASSWORD` | 최초 admin 계정 비밀번호 | `ChangeMe123!` |
| `COOKIE_SECURE` | 세션 쿠키 Secure 플래그 (HTTPS 배포 시 `true`) | `false` |
| `FLASK_DEBUG` | 디버그 모드 (운영 배포 시 반드시 `false`) | `false` |
| `DATABASE_PATH` | SQLite 파일 경로 | `market.db` |
| `RATELIMIT_ENABLED` | 엔드포인트 속도 제한 on/off (자동화 테스트 시 `false`) | `true` |
| `REPORTER_TRUST_AGE_SECONDS` | 신고 가중치 1.0을 받는 계정 최소 나이(초). 미만이면 0.5 | `86400` (24h) |

운영 환경(HTTPS)에 배포할 경우 반드시 `COOKIE_SECURE=true`로 설정하세요.

### 신고 남용(Sybil) 방어

누적 신고가 임계치에 도달해도 **즉시 자동 차단하지 않습니다.** 신고자 계정 나이로 가중한
점수(신규 계정 0.5, 24시간 경과 계정 1.0)가 임계치(3.0) 이상이면 대상을 관리자 검토
큐(`flagged`)에만 올리고, 관리자가 대시보드의 "신고 검토 큐"에서 **승인**해야 실제
차단/휴면이 확정됩니다. 이로써 소수의 갓 만든 가짜 계정 담합만으로 정상 사용자·상품을
차단시키는 공격을 완화합니다. 자기 자신(본인 계정/본인 상품) 신고와 동일 대상 중복 신고는
차단됩니다.

### 엔드포인트 속도 제한 (Flask-Limiter)

무차별 대입·스팸·자동화 남용을 막기 위해 IP 기준 요청 속도 제한을 적용합니다.
한도 초과 시 `429 Too Many Requests`와 함께 사용자 친화적 안내 페이지를 반환합니다.

| 엔드포인트 | 한도 |
|---|---|
| `POST /login` | 10회/분 (계정별 5회 실패 잠금과 별개로 동작) |
| `POST /register` | 10회/분 |
| `POST /transfer` | 30회/분 |
| `POST /report` | 20회/분 |

개발 환경 저장소는 인메모리(`memory://`)이며, 다중 프로세스 운영 시에는 Redis 등 공유
저장소로 변경해야 정확히 동작합니다. 자동화 테스트에서는 `RATELIMIT_ENABLED=false`로
제한을 끄고, 속도 제한 전용 테스트에서만 켜서 429를 검증합니다.

## 운영 배포 시 보안 권장사항

로컬 개발 환경에서는 적용할 수 없어 문서화로 대체한 항목들입니다
(`secure_coding_checklist.csv`의 "문서화(운영시 필요)" 항목에 대응).

- **HTTPS / WSS 적용**: nginx 등 리버스 프록시에서 TLS를 종단하고 앱으로 프록시하면
  웹 트래픽은 HTTPS, Socket.IO 웹소켓은 WSS로 자동 암호화됩니다.
  이때 `COOKIE_SECURE=true`를 함께 설정해야 합니다.
- **데이터베이스 권한**: 개발용 SQLite는 파일 기반이라 DB 계정 권한 분리가 없습니다.
  운영에서는 PostgreSQL/MySQL 등 별도 DB 서버를 사용하고, 애플리케이션 전용 계정에
  필요한 최소 권한(SELECT/INSERT/UPDATE/DELETE)만 부여하세요.
- **의존성 보안 점검**: `pip list --outdated` 및 `pip-audit`를 주기적으로 실행하여
  사용 중인 라이브러리의 보안 패치를 적용하세요.
- **WSGI 서버**: 내장 Werkzeug 개발 서버 대신 gunicorn(+eventlet/gevent) 등
  운영용 WSGI 서버를 사용하세요.

## 프로젝트 구조

```
app.py                      # Flask 애플리케이션 (전체 라우트 + Socket.IO 이벤트)
templates/                  # Jinja2 템플릿
static/js/                  # 클라이언트 스크립트 (CSP 준수를 위해 인라인 스크립트 대신 분리)
secure_coding_checklist.csv # 보안 체크리스트 (점검 결과 반영)
requirements.txt
README.md
```

## 보안 체크리스트

`secure_coding_checklist.csv`에 각 항목별 구현 여부와 관련 코드 위치를 정리해
두었습니다. 자세한 설계/구현/테스트 과정은 제출용 보고서(PDF)를 참고하세요.
