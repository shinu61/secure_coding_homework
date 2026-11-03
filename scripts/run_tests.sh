#!/usr/bin/env bash
# 전체 테스트를 한 번에 실행한다.
# 서버를 직접 띄우고(속도 제한 OFF → ON 두 단계), 끝나면 정리한다.
#   사용: bash scripts/run_tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python}"
BASE="http://127.0.0.1:5000"
DB="$(mktemp -d)/market.db"
export DATABASE_PATH="$DB"
FAIL=0
SERVER_PID=""

start_server() {
  rm -f "$DB"
  RATELIMIT_ENABLED="$1" "$PY" app.py > server.log 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 30); do
    curl -s -o /dev/null "$BASE/login" && return 0
    sleep 1
  done
  echo "서버가 뜨지 않았습니다"; cat server.log; exit 1
}

stop_server() {
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  SERVER_PID=""
}
trap stop_server EXIT

run() {
  echo; echo "▶ $*"
  if ! env "$@"; then FAIL=1; fi
}

# 1단계: 기능 회귀 · 동시성 · 신고 담합 (속도 제한 OFF)
start_server false
run "$PY" tests/test_market.py
run "$PY" tests/test_race.py
run PHASE=sybil "$PY" tests/test_sybil_ratelimit.py
stop_server

# 2단계: 속도 제한 429 (속도 제한 ON)
start_server true
run PHASE=ratelimit "$PY" tests/test_sybil_ratelimit.py
stop_server

echo
if [ "$FAIL" -ne 0 ]; then echo "❌ 실패한 테스트가 있습니다"; exit 1; fi
echo "✅ 전체 테스트 통과"
