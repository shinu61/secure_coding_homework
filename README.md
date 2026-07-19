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
- 신고 기능 (상품/사용자, 누적 3회 이상 시 자동 차단·휴면)
- 유저 간 송금 (가상 잔액)
- 관리자 페이지 (사용자 휴면 처리, 상품 차단/삭제, 신고 처리)

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

운영 환경(HTTPS)에 배포할 경우 반드시 `COOKIE_SECURE=true`로 설정하세요.

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
