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

# 로그인 실패 방어 설정 [checklist: 실패 로그인 방어]
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 5

# 신고 남용 방지 설정 [checklist: 신고 남용 방지]
REPORT_THRESHOLD = 3  # 이 횟수 이상 신고되면 자동 차단/휴면 처리

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')


# --------------------------------------------------------------------------
# DB 연결 관리
# --------------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


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
def report():
    db = get_db()
    if request.method == 'POST':
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

        try:
            # UNIQUE(reporter_id, target_type, target_id) 제약으로 중복신고 방지 [checklist: 신고 남용 방지]
            db.execute(
                "INSERT INTO report (id, reporter_id, target_type, target_id, reason, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), session['user_id'], target_type, target_id, reason, now())
            )
        except sqlite3.IntegrityError:
            flash('이미 해당 대상을 신고했습니다.')
            return redirect(url_for('report'))

        if target_type == 'product':
            db.execute(
                "UPDATE product SET report_count = report_count + 1 WHERE id = ?", (target_id,)
            )
            new_count = target['report_count'] + 1
            if new_count >= REPORT_THRESHOLD:
                db.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (target_id,))
        else:
            open_reports = db.execute(
                "SELECT COUNT(*) c FROM report WHERE target_type='user' AND target_id=?",
                (target_id,)
            ).fetchone()['c']
            if open_reports >= REPORT_THRESHOLD:
                db.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (target_id,))

        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')


# --------------------------------------------------------------------------
# 송금
# --------------------------------------------------------------------------
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    user = current_user()
    db = get_db()
    if request.method == 'POST':
        to_username = request.form.get('to_username', '').strip()
        amount_raw = request.form.get('amount', '').strip()

        if not amount_raw.isdigit() or int(amount_raw) <= 0:
            flash('송금액은 1 이상의 숫자여야 합니다.')
            return redirect(url_for('transfer'))
        amount = int(amount_raw)

        receiver = db.execute(
            "SELECT * FROM user WHERE username = ?", (to_username,)
        ).fetchone()
        if not receiver:
            flash('받는 사람을 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == user['id']:
            flash('본인에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))
        if user['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        # 잔액 검증 후 원자적으로 차감/증가 (간단한 트랜잭션)
        db.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, user['id']))
        db.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        db.execute(
            "INSERT INTO transfer (id, sender_id, receiver_id, amount, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), user['id'], receiver['id'], amount, now())
        )
        db.commit()
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
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM user ORDER BY created_at DESC").fetchall()
    products = db.execute("SELECT * FROM product ORDER BY created_at DESC").fetchall()
    reports = db.execute(
        "SELECT * FROM report WHERE status = 'open' ORDER BY created_at DESC"
    ).fetchall()
    return render_template('admin.html', users=users, products=products, reports=reports)


@app.route('/admin/user/<user_id>/suspend', methods=['POST'])
@admin_required
def admin_suspend_user(user_id):
    db = get_db()
    db.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (user_id,))
    db.commit()
    flash('사용자를 휴면 처리했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<user_id>/unsuspend', methods=['POST'])
@admin_required
def admin_unsuspend_user(user_id):
    db = get_db()
    db.execute(
        "UPDATE user SET status = 'active', failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,)
    )
    db.commit()
    flash('사용자 휴면을 해제했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/block', methods=['POST'])
@admin_required
def admin_block_product(product_id):
    db = get_db()
    db.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (product_id,))
    db.commit()
    flash('상품을 차단했습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/unblock', methods=['POST'])
@admin_required
def admin_unblock_product(product_id):
    db = get_db()
    db.execute("UPDATE product SET status = 'active' WHERE id = ?", (product_id,))
    db.commit()
    flash('상품 차단을 해제했습니다.')
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
