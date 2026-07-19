import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort
)
from flask_socketio import SocketIO, emit, join_room
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------------------------------------------------
# 기본 설정
# --------------------------------------------------------------------------
app = Flask(__name__)
# [checklist: 전체 시스템 - 보안 헤더/설정] 운영 배포 시 반드시 환경변수로 교체할 것
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
DATABASE = os.environ.get('DATABASE_PATH', 'market.db')

# [checklist: 회원가입 및 프로필관리 - 세션 쿠키 설정]
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# 로컬(HTTP)에서 테스트할 때는 False, 운영(HTTPS) 배포 시 반드시 True로 변경
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'
# [checklist: 세션 만료 및 재인증]
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

csrf = CSRFProtect(app)  # [checklist: CSRF 보호] 모든 POST 폼에 자동 적용
socketio = SocketIO(app)

# [checklist: 엔드포인트 속도 제한] Flask-Limiter로 IP 기준 요청 속도 제한.
# RATELIMIT_ENABLED=false 로 두면 자동화 테스트/개발 시 제한을 끌 수 있음(기본 true).
app.config['RATELIMIT_ENABLED'] = os.environ.get('RATELIMIT_ENABLED', 'true').lower() == 'true'
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],           # 전역 기본 제한 없음. 민감 엔드포인트에만 개별 적용
    storage_uri='memory://',     # 개발용 인메모리 저장소(운영은 Redis 등 권장 - README 참고)
)

# 로그인 실패 방어 설정 [checklist: 실패 로그인 방어]
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 5

# 신고 남용 방지 설정 [checklist: 신고 남용 방지]
# 즉시 자동 차단하지 않고, 가중 신고 점수가 임계치 이상이면 '관리자 검토 큐(flagged)'에만 올림.
# 최종 차단/휴면은 관리자 승인에서만 확정 -> 소수 계정 담합(Sybil)으로 정상 대상을 즉시
# 차단시키는 공격을 완화.
REPORT_THRESHOLD = 3.0  # 이 가중 점수 이상이면 관리자 검토 큐에 등록
# 신고자 계정 나이 가중치: 갓 만든 계정의 신고 영향력을 낮춤 [checklist: 신고 남용 방지]
REPORTER_TRUST_AGE_SECONDS = int(os.environ.get('REPORTER_TRUST_AGE_SECONDS', 24 * 3600))
NEW_ACCOUNT_WEIGHT = 0.5   # 가입 후 REPORTER_TRUST_AGE_SECONDS 미만 계정의 신고 가중치
TRUSTED_ACCOUNT_WEIGHT = 1.0  # 그 이상 경과한 계정의 신고 가중치

# 송금 상한 [checklist: 폼 입력 검증] 비정상적으로 큰 값/정수 오버플로 방지
MAX_TRANSFER_AMOUNT = 100_000_000

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')


# --------------------------------------------------------------------------
# DB 연결 관리
# --------------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # isolation_level=None -> autocommit 모드. 트랜잭션 경계를 코드에서 명시적으로
        # 제어(BEGIN IMMEDIATE/COMMIT/ROLLBACK)하기 위함. [checklist: 데이터 무결성]
        db = g._database = sqlite3.connect(DATABASE, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        # 동시 쓰기 시 잠금 대기(기본 0 -> 즉시 실패 방지). 경쟁 조건 하에서
        # 뒤늦은 트랜잭션이 최대 5초까지 락을 기다렸다가 순차 처리되도록 함.
        db.execute("PRAGMA busy_timeout = 5000")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def _add_column_if_missing(db, table, column, coldef):
    cols = [r['name'] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")


def init_db():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                bio TEXT DEFAULT '',
                role TEXT NOT NULL DEFAULT 'user',        -- 'user' | 'admin'
                status TEXT NOT NULL DEFAULT 'active',    -- 'active' | 'suspended'
                balance INTEGER NOT NULL DEFAULT 1000000, -- 송금용 가상 잔액
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                flagged INTEGER NOT NULL DEFAULT 0,        -- 1이면 신고 누적으로 관리자 검토 대기
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'blocked' | 'sold'
                report_count INTEGER NOT NULL DEFAULT 0,
                flagged INTEGER NOT NULL DEFAULT 0,     -- 1이면 신고 누적으로 관리자 검토 대기
                created_at TEXT NOT NULL,
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_type TEXT NOT NULL,   -- 'user' | 'product'
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',  -- 'open' | 'resolved'
                created_at TEXT NOT NULL,
                UNIQUE(reporter_id, target_type, target_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                room TEXT NOT NULL,          -- 'general' 또는 'dm:<id1>:<id2>'
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.commit()

        # 기존 DB 호환: flagged 컬럼이 없으면 추가 (신규 신고 검토 큐 기능)
        _add_column_if_missing(db, 'product', 'flagged', 'INTEGER NOT NULL DEFAULT 0')
        _add_column_if_missing(db, 'user', 'flagged', 'INTEGER NOT NULL DEFAULT 0')
        db.commit()

        # 최초 실행 시 관리자 계정 자동 생성 [요구사항: 관리자가 플랫폼의 모든 요소를 관리]
        cur.execute("SELECT * FROM user WHERE username = ?", ('admin',))
        if cur.fetchone() is None:
            admin_pw = os.environ.get('ADMIN_PASSWORD', 'ChangeMe123!')
            cur.execute(
                "INSERT INTO user (id, username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, 'admin', ?)",
                (str(uuid.uuid4()), 'admin', generate_password_hash(admin_pw), now())
            )
            db.commit()
            print(f"[init] 관리자 계정 생성됨 (username=admin, password={admin_pw}) "
                  f"- 최초 로그인 후 반드시 비밀번호를 변경하세요.")


def utcnow():
    return datetime.now(timezone.utc)


def now():
    return utcnow().isoformat()


def _parse_dt(iso_str):
    """ISO 문자열 -> tz-aware datetime (구버전 naive 값도 UTC로 보정)."""
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def reporter_weight(created_at_iso):
    """신고자 계정 나이에 따른 신고 가중치. [checklist: 신고 남용 방지]
    갓 만든 계정(가입 후 REPORTER_TRUST_AGE_SECONDS 미만)의 신고 영향력을 낮춰
    소수의 신규 가짜 계정 담합(Sybil)으로 정상 대상을 검토 큐에 올리기 어렵게 함."""
    try:
        age = (utcnow() - _parse_dt(created_at_iso)).total_seconds()
    except (ValueError, TypeError):
        age = 0
    return TRUSTED_ACCOUNT_WEIGHT if age >= REPORTER_TRUST_AGE_SECONDS else NEW_ACCOUNT_WEIGHT


def weighted_report_score(db, target_type, target_id):
    """대상에 대한 '미처리(open)' 신고들의 가중 합산 점수."""
    rows = db.execute(
        "SELECT u.created_at FROM report r JOIN user u ON u.id = r.reporter_id "
        "WHERE r.target_type = ? AND r.target_id = ? AND r.status = 'open'",
        (target_type, target_id)
    ).fetchall()
    return sum(reporter_weight(r['created_at']) for r in rows)


# --------------------------------------------------------------------------
# 헬퍼 / 데코레이터
# --------------------------------------------------------------------------
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM user WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        if user['status'] == 'suspended':
            session.clear()
            flash('휴면(정지) 처리된 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


@app.context_processor
def inject_nav_user():
    # 모든 템플릿에서 네비게이션 바에 사용할 로그인 사용자 정보 주입
    return {'nav_user': current_user()}


def admin_required(view):
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None or user['role'] != 'admin':
            abort(403)
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# [checklist: 보안 헤더 설정]
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'same-origin'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:"
    )
    return resp


# [checklist: 오류 메시지] 내부 정보(스택 트레이스 등) 노출 방지
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='접근 권한이 없습니다.'), 403


# [checklist: 엔드포인트 속도 제한] 한도 초과 시 사용자 친화적 429 응답
@app.errorhandler(429)
def ratelimit_exceeded(e):
    return render_template(
        'error.html', code=429,
        message='요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.'
    ), 429


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='페이지를 찾을 수 없습니다.'), 404


@app.errorhandler(500)
def server_error(e):
    app.logger.exception(e)  # 서버 로그에만 상세 내용 기록, 사용자에게는 노출하지 않음
    return render_template('error.html', code=500, message='서버 오류가 발생했습니다.'), 500


# --------------------------------------------------------------------------
# 기본 라우트
# --------------------------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# --------------------------------------------------------------------------
# 회원가입 / 로그인 / 로그아웃
# --------------------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per minute', methods=['POST'])  # [checklist: 엔드포인트 속도 제한]
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # [checklist: 서버측 입력 검증]
        if not USERNAME_RE.match(username):
            flash('사용자명은 영문/숫자/밑줄 3~20자여야 합니다.')
            return redirect(url_for('register'))
        if len(password) < 8 or len(password) > 64:
            flash('비밀번호는 8~64자여야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id FROM user WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        # [checklist: 비밀번호 보안] 평문 저장 금지 -> 솔트 포함 해시 저장
        cur.execute(
            "INSERT INTO user (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (user_id, username, generate_password_hash(password), now())
        )
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
# [checklist: 엔드포인트 속도 제한] IP 기준 로그인 속도 제한 (계정별 5회 실패 잠금과 별개로 동작)
@limiter.limit('10 per minute', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cur.fetchone()

        # [checklist: 실패 로그인 방어] 계정 잠금 확인
        if user is not None and user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if utcnow() < locked_until:
                flash('로그인 시도가 너무 많아 계정이 잠시 잠겼습니다. 잠시 후 다시 시도하세요.')
                return redirect(url_for('login'))

        # 사용자명/비밀번호 오류를 구분하지 않는 일반 메시지 사용 [checklist: 오류 메시지]
        if user is None or not check_password_hash(user['password_hash'], password):
            if user is not None:
                attempts = user['failed_attempts'] + 1
                locked_until = None
                if attempts >= MAX_FAILED_ATTEMPTS:
                    locked_until = (utcnow() + timedelta(minutes=LOCK_MINUTES)).isoformat()
                    attempts = 0
                cur.execute(
                    "UPDATE user SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (attempts, locked_until, user['id'])
                )
                db.commit()
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

        if user['status'] == 'suspended':
            flash('휴면(정지) 처리된 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))

        cur.execute(
            "UPDATE user SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user['id'],)
        )
        db.commit()

        session.clear()
        session.permanent = True  # [checklist: 세션 만료] PERMANENT_SESSION_LIFETIME 적용
        session['user_id'] = user['id']
        flash('로그인 성공!')
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# --------------------------------------------------------------------------
# 대시보드 / 검색
# --------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    products = db.execute(
        "SELECT * FROM product WHERE status = 'active' ORDER BY created_at DESC"
    ).fetchall()
    return render_template('dashboard.html', products=products, user=current_user(), query='')


@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()
    db = get_db()
    if q:
        # [checklist: ORM 및 파라미터 바인딩] LIKE 절도 파라미터 바인딩 사용, 문자열 결합 금지
        like_pattern = f"%{q}%"
        products = db.execute(
            "SELECT * FROM product WHERE status = 'active' AND title LIKE ? "
            "ORDER BY created_at DESC",
            (like_pattern,)
        ).fetchall()
    else:
        products = db.execute(
            "SELECT * FROM product WHERE status = 'active' ORDER BY created_at DESC"
        ).fetchall()
    return render_template('dashboard.html', products=products, user=current_user(), query=q)


# --------------------------------------------------------------------------
# 프로필 (소개글 / 비밀번호 변경)
# --------------------------------------------------------------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user()
    db = get_db()
    if request.method == 'POST':
        bio = request.form.get('bio', '')[:500]  # [checklist: 폼 입력 검증] 길이 제한
        db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, user['id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


@app.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    user = current_user()
    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')

    # [checklist: 세션 만료 및 재인증] 민감 작업(비밀번호 변경) 전 현재 비밀번호 재확인
    if not check_password_hash(user['password_hash'], current_pw):
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('profile'))
    if len(new_pw) < 8 or len(new_pw) > 64:
        flash('새 비밀번호는 8~64자여야 합니다.')
        return redirect(url_for('profile'))

    db = get_db()
    db.execute(
        "UPDATE user SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_pw), user['id'])
    )
    db.commit()
    flash('비밀번호가 변경되었습니다.')
    return redirect(url_for('profile'))


# --------------------------------------------------------------------------
# 상품 등록 / 조회 / 수정 / 삭제
# --------------------------------------------------------------------------
def validate_product_form(title, description, price_raw):
    if not title or len(title) > 100:
        return '제목은 1~100자여야 합니다.'
    if not description or len(description) > 1000:
        return '설명은 1~1000자여야 합니다.'
    if not price_raw.isdigit() or not (0 <= int(price_raw) <= 100_000_000):
        return '가격은 0~100,000,000 사이의 숫자여야 합니다.'
    return None


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()

        error = validate_product_form(title, description, price_raw)  # [checklist: 폼 입력 검증]
        if error:
            flash(error)
            return redirect(url_for('new_product'))

        db = get_db()
        product_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO product (id, title, description, price, seller_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, int(price_raw), session['user_id'], now())
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    user = current_user()
    is_owner = product['seller_id'] == user['id']
    if product['status'] == 'blocked' and not is_owner and user['role'] != 'admin':
        flash('차단된 상품입니다.')
        return redirect(url_for('dashboard'))

    seller = db.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],)).fetchone()
    return render_template(
        'view_product.html', product=product, seller=seller,
        is_owner=is_owner, user=user
    )


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        abort(404)
    user = current_user()
    # [checklist: 소유자 확인] 등록자 본인 또는 관리자만 수정 가능
    if product['seller_id'] != user['id'] and user['role'] != 'admin':
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()
        error = validate_product_form(title, description, price_raw)
        if error:
            flash(error)
            return redirect(url_for('edit_product', product_id=product_id))
        db.execute(
            "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
            (title, description, int(price_raw), product_id)
        )
        db.commit()
        flash('상품 정보가 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        abort(404)
    user = current_user()
    if product['seller_id'] != user['id'] and user['role'] != 'admin':  # [checklist: 소유자 확인]
        abort(403)
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))


# --------------------------------------------------------------------------
# 신고 (사용자/상품 차단)
# --------------------------------------------------------------------------
@app.route('/report', methods=['GET', 'POST'])
@login_required
@limiter.limit('20 per minute', methods=['POST'])  # [checklist: 엔드포인트 속도 제한]
def report():
    db = get_db()
    if request.method == 'POST':
        reporter_id = session['user_id']
        target_type = request.form.get('target_type', '')
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '').strip()

        # [checklist: 폼 입력 검증]
        if target_type not in ('user', 'product'):
            flash('신고 대상 유형이 올바르지 않습니다.')
            return redirect(url_for('report'))
        if not reason or len(reason) > 500:
            flash('신고 사유는 1~500자여야 합니다.')
            return redirect(url_for('report'))

        if target_type == 'user':
            target = db.execute("SELECT * FROM user WHERE id = ?", (target_id,)).fetchone()
        else:
            target = db.execute("SELECT * FROM product WHERE id = ?", (target_id,)).fetchone()
        if not target:
            flash('신고 대상을 찾을 수 없습니다.')
            return redirect(url_for('report'))

        # [checklist: 신고 남용 방지] 자기 자신 신고 차단
        # (사용자: 본인 계정 / 상품: 본인이 등록한 상품)
        if target_type == 'user' and target['id'] == reporter_id:
            flash('본인 계정은 신고할 수 없습니다.')
            return redirect(url_for('report'))
        if target_type == 'product' and target['seller_id'] == reporter_id:
            flash('본인이 등록한 상품은 신고할 수 없습니다.')
            return redirect(url_for('report'))

        try:
            # UNIQUE(reporter_id, target_type, target_id) 제약으로 중복신고 방지 [checklist: 신고 남용 방지]
            db.execute(
                "INSERT INTO report (id, reporter_id, target_type, target_id, reason, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), reporter_id, target_type, target_id, reason, now())
            )
        except sqlite3.IntegrityError:
            flash('이미 해당 대상을 신고했습니다.')
            return redirect(url_for('report'))

        if target_type == 'product':
            db.execute(
                "UPDATE product SET report_count = report_count + 1 WHERE id = ?", (target_id,)
            )

        # [checklist: 신고 남용 방지 - Sybil 완화]
        # 즉시 자동 차단/휴면하지 않는다. 신고자 계정 나이로 가중한 점수가 임계치 이상이면
        # '관리자 검토 큐(flagged=1)'에만 올리고, 최종 차단/휴면은 관리자 승인에서 확정한다.
        # 이렇게 하면 소수의 신규 가짜 계정 담합만으로는 정상 대상을 차단시킬 수 없다.
        score = weighted_report_score(db, target_type, target_id)
        if score >= REPORT_THRESHOLD:
            if target_type == 'product':
                # 아직 정상(active)인 상품만 검토 큐로. 이미 차단된 건 건드리지 않음.
                db.execute(
                    "UPDATE product SET flagged = 1 WHERE id = ? AND status = 'active'",
                    (target_id,)
                )
            else:
                db.execute(
                    "UPDATE user SET flagged = 1 WHERE id = ? AND status = 'active' AND role != 'admin'",
                    (target_id,)
                )

        db.commit()
        flash('신고가 접수되었습니다. 관리자 검토 후 조치됩니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')


# --------------------------------------------------------------------------
# 송금
# --------------------------------------------------------------------------
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
@limiter.limit('30 per minute', methods=['POST'])  # [checklist: 엔드포인트 속도 제한]
def transfer():
    user = current_user()
    db = get_db()
    if request.method == 'POST':
        to_username = request.form.get('to_username', '').strip()
        amount_raw = request.form.get('amount', '').strip()

        # [checklist: 폼 입력 검증] 숫자/범위 검증 (상한 포함)
        if not amount_raw.isdigit() or int(amount_raw) <= 0:
            flash('송금액은 1 이상의 숫자여야 합니다.')
            return redirect(url_for('transfer'))
        amount = int(amount_raw)
        if amount > MAX_TRANSFER_AMOUNT:
            flash(f'송금액은 최대 {MAX_TRANSFER_AMOUNT:,}원까지 가능합니다.')
            return redirect(url_for('transfer'))

        receiver = db.execute(
            "SELECT * FROM user WHERE username = ?", (to_username,)
        ).fetchone()
        if not receiver:
            flash('받는 사람을 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == user['id']:
            flash('본인에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        # [checklist: 데이터 무결성] 경쟁 조건(TOCTOU)으로 인한 이중지불 방지.
        # 잔액 검사를 UPDATE의 WHERE 절에 포함시켜 DB가 원자적으로 판단하게 하고,
        # 차감/증가/기록을 BEGIN IMMEDIATE 트랜잭션으로 묶어 중간 실패 시 전체 롤백.
        db.execute("BEGIN IMMEDIATE")
        try:
            cur = db.execute(
                "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
                (amount, user['id'], amount)
            )
            if cur.rowcount == 0:
                # 조건 불충족(잔액 부족) -> 차감 자체가 발생하지 않음
                db.execute("ROLLBACK")
                flash('잔액이 부족합니다.')
                return redirect(url_for('transfer'))

            db.execute(
                "UPDATE user SET balance = balance + ? WHERE id = ?",
                (amount, receiver['id'])
            )
            db.execute(
                "INSERT INTO transfer (id, sender_id, receiver_id, amount, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), user['id'], receiver['id'], amount, now())
            )
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise

        flash(f'{to_username}님에게 {amount}원을 송금했습니다.')
        return redirect(url_for('transfer'))

    history = db.execute(
        "SELECT t.*, su.username AS sender_name, ru.username AS receiver_name "
        "FROM transfer t "
        "JOIN user su ON su.id = t.sender_id "
        "JOIN user ru ON ru.id = t.receiver_id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.created_at DESC LIMIT 50",
        (user['id'], user['id'])
    ).fetchall()
    return render_template('transfer.html', user=user, history=history)


# --------------------------------------------------------------------------
# 채팅 (전체 채팅 + 1:1 채팅)
# --------------------------------------------------------------------------
@app.route('/chat')
@login_required
def chat_general():
    db = get_db()
    history = db.execute(
        "SELECT m.*, u.username FROM message m JOIN user u ON u.id = m.sender_id "
        "WHERE m.room = 'general' ORDER BY m.created_at DESC LIMIT 50"
    ).fetchall()
    return render_template(
        'chat.html', room='general', user=current_user(),
        history=list(reversed(history)), peer=None
    )


@app.route('/chat/<other_id>')
@login_required
def chat_dm(other_id):
    db = get_db()
    other = db.execute("SELECT * FROM user WHERE id = ?", (other_id,)).fetchone()
    if not other:
        abort(404)
    user = current_user()
    room = dm_room_name(user['id'], other_id)
    history = db.execute(
        "SELECT m.*, u.username FROM message m JOIN user u ON u.id = m.sender_id "
        "WHERE m.room = ? ORDER BY m.created_at DESC LIMIT 50",
        (room,)
    ).fetchall()
    return render_template(
        'chat.html', room=room, user=user,
        history=list(reversed(history)), peer=other
    )


def dm_room_name(id1, id2):
    ids = sorted([id1, id2])
    return f"dm:{ids[0]}:{ids[1]}"


# socket.io 연결별 상태 (인메모리, 프로세스 재시작 시 초기화됨)
_last_message_time = {}
MIN_MESSAGE_INTERVAL = 0.5  # 초 [checklist: Rate Limiting]
MAX_MESSAGE_LEN = 500


@socketio.on('connect')
def handle_connect():
    # [checklist: 사용자 인증] 로그인하지 않은 사용자는 소켓 연결 거부
    if 'user_id' not in session:
        return False  # 연결 거부


@socketio.on('join')
def handle_join(data):
    if 'user_id' not in session:
        return
    room = data.get('room')
    if not room:
        return
    # 1:1 채팅방은 대화 당사자만 입장 가능하도록 검증
    if room.startswith('dm:'):
        parts = room.split(':')
        if len(parts) != 3 or session['user_id'] not in (parts[1], parts[2]):
            return
    join_room(room)


@socketio.on('send_message')
def handle_send_message_event(data):
    user_id = session.get('user_id')
    if not user_id:
        return  # [checklist: 사용자 인증]

    db = get_db()
    user = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    if not user or user['status'] == 'suspended':
        return

    # [checklist: Rate Limiting]
    last = _last_message_time.get(user_id, 0)
    if time.time() - last < MIN_MESSAGE_INTERVAL:
        return
    _last_message_time[user_id] = time.time()

    room = data.get('room')
    content = str(data.get('message', ''))[:MAX_MESSAGE_LEN].strip()  # [checklist: 메시지 내용 검증]
    if not room or not content:
        return
    if room.startswith('dm:'):
        parts = room.split(':')
        if len(parts) != 3 or user_id not in (parts[1], parts[2]):
            return  # 대화 당사자가 아니면 거부

    db.execute(
        "INSERT INTO message (id, room, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), room, user_id, content, now())
    )
    db.commit()

    emit('message', {
        'username': user['username'],   # 서버가 신뢰하는 세션 정보로만 표시 (클라이언트 값 신뢰 안 함)
        'message': content,
    }, room=room)


# --------------------------------------------------------------------------
# 관리자 페이지
# --------------------------------------------------------------------------
def _gather_open_reports(db, target_type, target_id):
    """검토 큐 표시용: 대상에 대한 미처리 신고자 목록과 각 신고자의 계정 나이/가중치."""
    rows = db.execute(
        "SELECT r.reason, u.username, u.created_at AS uc "
        "FROM report r JOIN user u ON u.id = r.reporter_id "
        "WHERE r.target_type = ? AND r.target_id = ? AND r.status = 'open' "
        "ORDER BY r.created_at",
        (target_type, target_id)
    ).fetchall()
    items = []
    for r in rows:
        try:
            age_days = (utcnow() - _parse_dt(r['uc'])).total_seconds() / 86400
        except (ValueError, TypeError):
            age_days = 0
        items.append({
            'username': r['username'],
            'reason': r['reason'],
            'age_days': age_days,
            'weight': reporter_weight(r['uc']),
        })
    return items


@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM user ORDER BY created_at DESC").fetchall()
    products = db.execute("SELECT * FROM product ORDER BY created_at DESC").fetchall()
    reports = db.execute(
        "SELECT * FROM report WHERE status = 'open' ORDER BY created_at DESC"
    ).fetchall()

    # [checklist: 신고 남용 방지 - Sybil 완화] 관리자 검토 큐:
    # 신고 누적으로 flagged 되었으나 아직 차단/휴면되지 않은(정상 상태) 대상들.
    # 관리자가 여기서 승인해야 실제 차단/휴면이 확정된다.
    flagged_products = db.execute(
        "SELECT * FROM product WHERE flagged = 1 AND status = 'active' ORDER BY created_at DESC"
    ).fetchall()
    flagged_users = db.execute(
        "SELECT * FROM user WHERE flagged = 1 AND status = 'active' AND role != 'admin' "
        "ORDER BY created_at DESC"
    ).fetchall()
    review_products = [
        {'p': p,
         'score': weighted_report_score(db, 'product', p['id']),
         'reports': _gather_open_reports(db, 'product', p['id'])}
        for p in flagged_products
    ]
    review_users = [
        {'u': u,
         'score': weighted_report_score(db, 'user', u['id']),
         'reports': _gather_open_reports(db, 'user', u['id'])}
        for u in flagged_users
    ]
    return render_template(
        'admin.html', users=users, products=products, reports=reports,
        review_products=review_products, review_users=review_users,
        report_threshold=REPORT_THRESHOLD
    )


@app.route('/admin/user/<user_id>/suspend', methods=['POST'])
@admin_required
def admin_suspend_user(user_id):
    # [checklist: 신고 남용 방지] 관리자 승인 -> 휴면 확정 + 검토 큐에서 제거 + 관련 신고 처리완료
    db = get_db()
    db.execute("UPDATE user SET status = 'suspended', flagged = 0 WHERE id = ?", (user_id,))
    db.execute(
        "UPDATE report SET status = 'resolved' WHERE target_type = 'user' AND target_id = ? "
        "AND status = 'open'",
        (user_id,)
    )
    db.commit()
    flash('사용자를 휴면 처리했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<user_id>/unsuspend', methods=['POST'])
@admin_required
def admin_unsuspend_user(user_id):
    db = get_db()
    db.execute(
        "UPDATE user SET status = 'active', flagged = 0, failed_attempts = 0, "
        "locked_until = NULL WHERE id = ?",
        (user_id,)
    )
    db.commit()
    flash('사용자 휴면을 해제했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<user_id>/dismiss', methods=['POST'])
@admin_required
def admin_dismiss_user_reports(user_id):
    # [checklist: 신고 남용 방지] 관리자 반려 -> 차단하지 않고 검토 큐에서 제거, 신고 처리완료
    db = get_db()
    db.execute("UPDATE user SET flagged = 0 WHERE id = ?", (user_id,))
    db.execute(
        "UPDATE report SET status = 'resolved' WHERE target_type = 'user' AND target_id = ? "
        "AND status = 'open'",
        (user_id,)
    )
    db.commit()
    flash('해당 사용자에 대한 신고를 반려했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/block', methods=['POST'])
@admin_required
def admin_block_product(product_id):
    # [checklist: 신고 남용 방지] 관리자 승인 -> 차단 확정 + 검토 큐에서 제거 + 관련 신고 처리완료
    db = get_db()
    db.execute("UPDATE product SET status = 'blocked', flagged = 0 WHERE id = ?", (product_id,))
    db.execute(
        "UPDATE report SET status = 'resolved' WHERE target_type = 'product' AND target_id = ? "
        "AND status = 'open'",
        (product_id,)
    )
    db.commit()
    flash('상품을 차단했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/unblock', methods=['POST'])
@admin_required
def admin_unblock_product(product_id):
    db = get_db()
    db.execute("UPDATE product SET status = 'active', flagged = 0 WHERE id = ?", (product_id,))
    db.commit()
    flash('상품 차단을 해제했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/dismiss', methods=['POST'])
@admin_required
def admin_dismiss_product_reports(product_id):
    # [checklist: 신고 남용 방지] 관리자 반려 -> 차단하지 않고 검토 큐에서 제거, 신고 처리완료
    db = get_db()
    db.execute("UPDATE product SET flagged = 0 WHERE id = ?", (product_id,))
    db.execute(
        "UPDATE report SET status = 'resolved' WHERE target_type = 'product' AND target_id = ? "
        "AND status = 'open'",
        (product_id,)
    )
    db.commit()
    flash('해당 상품에 대한 신고를 반려했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품을 삭제했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/report/<report_id>/resolve', methods=['POST'])
@admin_required
def admin_resolve_report(report_id):
    db = get_db()
    db.execute("UPDATE report SET status = 'resolved' WHERE id = ?", (report_id,))
    db.commit()
    flash('신고를 처리 완료로 표시했습니다.')
    return redirect(url_for('admin_dashboard'))


# --------------------------------------------------------------------------
# 실행
# --------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'  # [checklist: 오류 메시지] 운영 시 반드시 false
    # allow_unsafe_werkzeug: 로컬 개발 서버 실행용. 운영 배포 시에는 gunicorn 등 WSGI 서버 사용
    socketio.run(app, host='0.0.0.0', port=5000, debug=debug_mode,
                 allow_unsafe_werkzeug=True)
