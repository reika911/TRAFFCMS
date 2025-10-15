import os
import datetime as dt
import random
import string
import logging
import json
from io import BytesIO, StringIO
from urllib.parse import urlparse

from dotenv import load_dotenv
import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, make_response, send_from_directory, Response, session as flask_session
)
from flask_sqlalchemy import SQLAlchemy
from user_agents import parse as parse_ua
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageOps

# ----------------------------------
# Setup
# ----------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': os.getenv('SECRET_KEY', 'dev-secret-key-123'),
    'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL', 'sqlite:///app.db'),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'CAPTCHA_LENGTH': 6,
    'CAPTCHA_EXPIRE_MINUTES': 5,
    'ALLOWED_DOMAINS': os.getenv('ALLOWED_DOMAINS', '*').split(','),
    'ADMIN_PASSWORD': os.getenv('ADMIN_PASSWORD', 'Nii[sdOOJkljcs'),
})

db = SQLAlchemy(app)

# ----------------------------------
# Models
# ----------------------------------

class Visit(db.Model):
    __tablename__ = 'visits'
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=dt.datetime.utcnow, index=True)
    ip = db.Column(db.String(64), index=True)
    country = db.Column(db.String(64))
    country_code = db.Column(db.String(8))
    os = db.Column(db.String(64))
    user_agent = db.Column(db.Text)
    domain = db.Column(db.String(256), index=True)
    verified = db.Column(db.Boolean, default=False)
    captcha_text = db.Column(db.String(32))
    captcha_expire = db.Column(db.DateTime)
    verification_token = db.Column(db.String(64), unique=True)
    verification_code = db.Column(db.String(128))


class FileDownload(db.Model):
    __tablename__ = 'file_downloads'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), index=True)
    download_count = db.Column(db.Integer, default=0)
    last_downloaded = db.Column(db.DateTime)
    ip = db.Column(db.String(64))
    country = db.Column(db.String(64))
    country_code = db.Column(db.String(8))
    user_agent = db.Column(db.Text)
    referrer = db.Column(db.String(512))


class Setting(db.Model):
    __tablename__ = 'settings'
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text)

    @classmethod
    def get(cls, key, default=''):
        try:
            with db.session() as session:
                setting = session.get(cls, key)
                return setting.value if setting else default
        except Exception as e:
            logger.error(f"Error getting setting {key}: {str(e)}")
            return default

    @classmethod
    def set(cls, key, value):
        try:
            with db.session() as session:
                setting = session.get(cls, key) or cls(key=key)
                setting.value = value
                session.add(setting)
                session.commit()
        except Exception as e:
            logger.error(f"Error setting {key}: {str(e)}")
            db.session.rollback()


class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), unique=True, index=True, nullable=False)
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow, index=True)


class HumanVerification(db.Model):
    __tablename__ = 'human_verifications'
    id = db.Column(db.Integer, primary_key=True)
    js_enabled = db.Column(db.Boolean)
    cookies_enabled = db.Column(db.Boolean)
    screen_resolution = db.Column(db.String(20))
    timezone = db.Column(db.String(50))
    language = db.Column(db.String(50))
    hardware_concurrency = db.Column(db.Integer)
    device_memory = db.Column(db.Integer)
    touch_support = db.Column(db.Boolean)
    plugins = db.Column(db.Text)
    fonts = db.Column(db.Text)
    canvas_hash = db.Column(db.String(64))
    webgl_vendor = db.Column(db.String(100))
    webgl_renderer = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)


# ----------------------------------
# Helpers
# ----------------------------------

def get_client_domain():
    referer = request.headers.get('Referer')
    origin = request.headers.get('Origin')
    if referer:
        domain = urlparse(referer).netloc
    elif origin:
        domain = urlparse(origin).netloc
    else:
        domain = request.args.get('domain', 'direct')
    return domain.split(':')[0].lower()


def get_client_ip():
    """Resolve real client IP behind proxies."""
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.headers.get("X-Real-IP"):
        ip = request.headers.get("X-Real-IP").strip()
    else:
        ip = request.remote_addr or '127.0.0.1'
    return ip


def verify_domain(domain):
    allowed = app.config['ALLOWED_DOMAINS']
    if '*' in allowed:
        return True
    for allowed_domain in allowed:
        allowed_domain = allowed_domain.strip()
        if not allowed_domain:
            continue
        if allowed_domain.startswith('*.'):
            if domain.endswith(allowed_domain[1:]) or domain == allowed_domain[2:]:
                return True
        elif domain == allowed_domain:
            return True
    return False


def generate_verification_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=64))


def generate_cloudflare_style_captcha():
    # Higher resolution
    width, height = 600, 200
    bg_color = (245, 247, 249)
    image = Image.new('RGB', (width, height), bg_color)
    draw = ImageDraw.Draw(image)

    # CAPTCHA text (excluding similar characters)
    chars = ''.join([c for c in string.ascii_uppercase if c not in 'IO'])
    captcha_text = ''.join(random.choices(chars, k=6))

    # Try to use a modern font
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "arial.ttf"
    ]
    font = None
    for path in font_paths:
        try:
            font = ImageFont.truetype(path, 80)
            break
        except Exception:
            continue
    if not font:
        font = ImageFont.load_default()

    # Draw each character with random transformations
    for i, char in enumerate(captcha_text):
        font_size = random.randint(70, 90)
        angle = random.randint(-30, 30)
        x_offset = 40 + i * 90 + random.randint(-10, 10)
        y_offset = random.randint(40, 80)
        color = (random.randint(0, 80), random.randint(0, 80), random.randint(120, 255))
        try:
            char_font = ImageFont.truetype(font.path, font_size) if hasattr(font, 'path') else font
        except Exception:
            char_font = font
        char_image = Image.new('RGBA', (120, 120), (0, 0, 0, 0))
        char_draw = ImageDraw.Draw(char_image)
        char_draw.text((20, 10), char, font=char_font, fill=color)
        char_image = char_image.rotate(angle, expand=1, resample=Image.BICUBIC)
        image.paste(char_image, (x_offset, y_offset), char_image)

    # Add random Bezier curves for distortion
    for _ in range(3):
        points = [
            (random.randint(0, width), random.randint(0, height)) for _ in range(4)
        ]
        draw.line(points, fill=(random.randint(100, 200), random.randint(100, 200), random.randint(100, 200)), width=6)

    # Add random lines
    for _ in range(10):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(200, 200, 200), width=3)

    # Add random dots
    for _ in range(800):
        x, y = random.randint(0, width), random.randint(0, height)
        draw.point((x, y), fill=(random.randint(150, 255), random.randint(150, 255), random.randint(150, 255)))

    # Apply blur and slight edge enhancement
    image = image.filter(ImageFilter.GaussianBlur(radius=1.2))
    image = image.filter(ImageFilter.EDGE_ENHANCE_MORE)

    # Add border
    image = ImageOps.expand(image, border=10, fill=(180, 180, 180))
    image = ImageOps.expand(image, border=6, fill=(100, 100, 100))

    # Save with high quality
    buf = BytesIO()
    image.save(buf, format='PNG', optimize=True)
    return captcha_text, buf.getvalue()


def generate_material_captcha():
    width, height = 480, 160
    bg_color = (250, 250, 250)
    accent_color = (33, 150, 243)  # Material Blue 500
    shadow_color = (120, 144, 156, 80)  # Blue Grey 400 with alpha
    text_color = (33, 33, 33)
    image = Image.new('RGBA', (width, height), bg_color)
    draw = ImageDraw.Draw(image)

    # Accent bar
    draw.rectangle([0, height-12, width, height], fill=accent_color)

    # CAPTCHA text
    chars = ''.join([c for c in string.ascii_uppercase if c not in 'IO'])
    captcha_text = ''.join(random.choices(chars, k=6))

    # Font selection
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/roboto/Roboto-Bold.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "arial.ttf"
    ]
    font = None
    for path in font_paths:
        try:
            font = ImageFont.truetype(path, 72)
            break
        except Exception:
            continue
    if not font:
        font = ImageFont.load_default()

    # Calculate text size and position using textbbox for compatibility
    bbox = draw.textbbox((0, 0), captcha_text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (width - text_width) // 2
    y = (height - text_height) // 2 - 10

    # Draw shadow
    shadow_offset = 4
    shadow_layer = Image.new('RGBA', image.size, (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow_layer)
    shadow_draw.text((x + shadow_offset, y + shadow_offset), captcha_text, font=font, fill=shadow_color)
    image = Image.alpha_composite(image, shadow_layer)

    # Draw main text
    draw = ImageDraw.Draw(image)
    draw.text((x, y), captcha_text, font=font, fill=text_color)

    # Accent circles
    for i in range(2):
        cx = random.randint(60, width-60)
        cy = random.randint(40, height-40)
        r = random.randint(18, 32)
        draw.ellipse([cx-r, cy-r, cx+r, cy+r], outline=accent_color, width=3)

    # Minimal clean lines
    for _ in range(2):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=accent_color, width=2)

    # Convert to RGB for PNG
    out_img = image.convert('RGB')
    buf = BytesIO()
    out_img.save(buf, format='PNG', optimize=True)
    return captcha_text, buf.getvalue()


def get_geo_info(ip):
    try:
        if ip in ['127.0.0.1', '::1']:
            return 'Local', ''
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode",
            timeout=3
        )
        if resp.ok:
            data = resp.json()
            if data.get('status') == 'success':
                return data.get('country', 'Unknown'), data.get('countryCode', '')
    except Exception as e:
        logger.error(f"Error getting geo info for {ip}: {str(e)}")
    return 'Unknown', ''


def detect_os(ua_string):
    try:
        return parse_ua(ua_string).os.family or 'Unknown'
    except Exception as e:
        logger.error(f"Error detecting OS: {str(e)}")
        return 'Unknown'


def visits_24h_buckets(session):
    """Aggregate last 24h visits & verified by hour."""
    now = dt.datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    start = now - dt.timedelta(hours=23)
    buckets = {(start + dt.timedelta(hours=i)).strftime('%H:%M'): {'total': 0, 'verified': 0}
               for i in range(24)}
    rows = (session.query(Visit.ts, Visit.verified)
            .filter(Visit.ts >= start)
            .order_by(Visit.ts.asc())
            .all())
    for ts, verified in rows:
        key = ts.replace(minute=0, second=0, microsecond=0).strftime('%H:%M')
        if key in buckets:
            buckets[key]['total'] += 1
            if verified:
                buckets[key]['verified'] += 1
    return [{'ts': k, 'total': v['total'], 'verified': v['verified']} for k, v in sorted(buckets.items())]


class HumanVerificationSystem:
    @staticmethod
    def verify_javascript_challenge(data):
        """Verify JavaScript challenge data for human verification."""
        try:
            # Basic validation
            required_fields = ['js_enabled', 'cookies_enabled', 'screen_resolution']
            for field in required_fields:
                if field not in data:
                    return False
            
            # Check if JavaScript is enabled (should be True for humans)
            if not data.get('js_enabled'):
                return False
            
            # Check if cookies are enabled (should be True for most humans)
            if not data.get('cookies_enabled'):
                return False
            
            # Validate screen resolution format (e.g., "1920x1080")
            screen_res = data.get('screen_resolution', '')
            if not screen_res or 'x' not in screen_res:
                return False
            
            # Additional validation checks can be added here
            # For example, check timezone, language, etc.
            
            return True
            
        except Exception as e:
            logger.error(f"JS challenge verification error: {e}")
            return False


def get_session():
    """Get a database session."""
    return db.session()


# ----------------------------------
# App init
# ----------------------------------

def initialize_app():
    with app.app_context():
        db.create_all()
        defaults = {
            'clipboard_text': 'Your verification code: VRF-{random}',
            'modal_title': 'Please complete the security check',
            'modal_body': 'This helps us prevent automated access',
            'verify_button_text': 'Verify',
            'preloader_ms': '6000',
            'allowed_domains': '*,*.yourdomain.com',
            'verification_expire_minutes': '15',
        }
        for key, value in defaults.items():
            if not Setting.get(key):
                Setting.set(key, value)
        app.config['ALLOWED_DOMAINS'] = Setting.get('allowed_domains').split(',')
        logger.info("Application initialized successfully")

initialize_app()

# ----------------------------------
# Routes
# ----------------------------------

@app.route('/')
def verification_gate():
    try:
        domain = get_client_domain()
        if not verify_domain(domain):
            return render_template('blocked.html', domain=domain), 403

        ip = get_client_ip()

        # Enforce blocklist if present
        try:
            with db.session() as session:
                if session.query(BlockedIP).filter_by(ip=ip).first():
                    return render_template('blocked.html', domain=domain), 403
        except Exception as e:
            logger.warning(f"Blocklist check failed: {e}")

        country, country_code = get_geo_info(ip)
        user_agent = request.headers.get('User-Agent', '')

        session = db.session()
        try:
            visit = Visit(
                ip=ip,
                country=country,
                country_code=country_code,
                os=detect_os(user_agent),
                user_agent=user_agent,
                domain=domain,
                captcha_expire=dt.datetime.utcnow() + dt.timedelta(minutes=app.config['CAPTCHA_EXPIRE_MINUTES']),
                verification_token=generate_verification_token(),
            )
            session.add(visit)
            session.commit()

            visit_id = visit.id
            verification_token = visit.verification_token

            response = make_response(render_template('verification.html', **{
                'modal_title': Setting.get('modal_title'),
                'modal_body': Setting.get('modal_body'),
                'verify_button_text': Setting.get('verify_button_text'),
                'preloader_ms': Setting.get('preloader_ms'),
                'domain': domain,
            }))

            # For HTTP local dev, allow non-secure cookies; use secure in prod
            secure_cookie = False if app.debug else True
            response.set_cookie('v_id', str(visit_id),
                                httponly=True, samesite='Lax', secure=secure_cookie)
            response.set_cookie('v_token', verification_token,
                                httponly=True, samesite='Lax', secure=secure_cookie)
            return response

        except Exception as e:
            session.rollback()
            logger.error(f"Database error in verification_gate: {str(e)}", exc_info=True)
            return render_template('error.html', error="Database error occurred"), 500
        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error in verification_gate: {str(e)}", exc_info=True)
        return render_template('error.html', error="Service temporarily unavailable"), 500


@app.route('/download/<filename>')
def download_file(filename):
    try:
        safe_filename = os.path.basename(filename)
        if not safe_filename:
            return "Invalid filename", 400

        downloads_dir = os.path.join(app.root_path, 'downloads')
        file_path = os.path.join(downloads_dir, safe_filename)

        if not os.path.exists(file_path):
            return "File not found", 404

        ip = get_client_ip()
        country, country_code = get_geo_info(ip)
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', 'direct')

        with db.session() as session:
            download = FileDownload(
                filename=safe_filename,
                ip=ip,
                country=country,
                country_code=country_code,
                user_agent=user_agent,
                referrer=referrer,
                last_downloaded=dt.datetime.utcnow(),
            )
            session.add(download)
            session.commit()

        return send_from_directory(
            downloads_dir,
            safe_filename,
            as_attachment=True,
            download_name=safe_filename
        )

    except Exception as e:
        logger.error(f"Error in download_file: {str(e)}")
        return "Internal Server Error", 500


@app.route('/captcha')
def serve_captcha():
    try:
        visit_id = request.cookies.get('v_id')
        verification_token = request.cookies.get('v_token')

        if not visit_id or not verification_token:
            return "Invalid request", 400

        with db.session() as session:
            visit = session.get(Visit, visit_id)
            if not visit or visit.verification_token != verification_token:
                return "Invalid session", 400

            if visit.captcha_expire < dt.datetime.utcnow():
                return "CAPTCHA expired", 400

            captcha_text, image_bytes = generate_material_captcha()
            visit.captcha_text = captcha_text
            session.commit()

        response = make_response(image_bytes)
        response.headers['Content-Type'] = 'image/png'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        return response

    except Exception as e:
        logger.error(f"Error in serve_captcha: {str(e)}")
        return "Internal Server Error", 500


@app.route('/verify', methods=['POST'])
def verify_captcha():
    try:
        visit_id = request.cookies.get('v_id')
        verification_token = request.cookies.get('v_token')
        captcha_input = request.form.get('captcha', '').strip().upper()

        if not visit_id or not verification_token:
            return jsonify({'success': False, 'error_type': 'session',
                            'error': 'Invalid session. Please refresh the page and try again.'})

        with db.session() as session:
            visit = session.get(Visit, visit_id)
            if not visit or visit.verification_token != verification_token:
                return jsonify({'success': False, 'error_type': 'session',
                                'error': 'Session expired. Please refresh the page.'})

            if visit.captcha_expire < dt.datetime.utcnow():
                return jsonify({'success': False, 'error_type': 'captcha',
                                'error': 'CAPTCHA expired. Please refresh the CAPTCHA.'})

            if not captcha_input or captcha_input != visit.captcha_text:
                return jsonify({'success': False, 'error_type': 'captcha',
                                'error': 'Incorrect CAPTCHA. Please try again.'})

            # Human verification code
            verification_id = ''.join(random.choices('abcdef0123456789', k=6))
            verification_code = f"CLOUDFLARE-VERIFICATION-ID: {verification_id}"

            visit.verified = True
            visit.verification_code = verification_code
            session.commit()

            return jsonify({
                'success': True,
                'verification_id': verification_id,
                'verification_code': verification_code,
                'instructions': [
                    "Press & hold the Windows Key + R",
                    "In the verification window, press Ctrl + V",
                    "Press Enter on the keyboard to finish"
                ],
                'message': "You fully agree: I am not a robot"
            })

    except Exception as e:
        logger.error(f"Error in verify_captcha: {str(e)}")
        return jsonify({'success': False, 'error_type': 'server',
                        'error': 'Server error. Please try again later.'}), 500


@app.route('/api/verify_js', methods=['POST'])
def verify_javascript():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid data'})
        
        if not HumanVerificationSystem.verify_javascript_challenge(data):
            return jsonify({'success': False, 'error': 'Verification failed'})
        
        session = get_session()
        try:
            verification = HumanVerification(
                js_enabled=data.get('js_enabled'),
                cookies_enabled=data.get('cookies_enabled'),
                screen_resolution=data.get('screen_resolution'),
                timezone=data.get('timezone'),
                language=data.get('language'),
                hardware_concurrency=data.get('hardware_concurrency'),
                device_memory=data.get('device_memory'),
                touch_support=data.get('touch_support'),
                plugins=json.dumps(data.get('plugins', [])),
                fonts=json.dumps(data.get('fonts', [])),
                canvas_hash=data.get('canvas_hash'),
                webgl_vendor=data.get('webgl_vendor'),
                webgl_renderer=data.get('webgl_renderer')
            )
            session.add(verification)
            session.commit()
            
            return jsonify({'success': True, 'verified': True})
            
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"JS verification error: {e}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route('/babakapcha', methods=['GET', 'POST'])
def admin_panel():
    try:
        # Authentication check
        if request.method == 'POST' and 'password' in request.form:
            if request.form['password'] == app.config['ADMIN_PASSWORD']:
                resp = redirect(url_for('admin_panel'))
                secure_cookie = False if app.debug else True
                resp.set_cookie('admin_auth', '1', httponly=True, samesite='Strict', secure=secure_cookie)
                return resp
            flash('Invalid password', 'error')

        if request.cookies.get('admin_auth') != '1':
            return render_template('admin_login.html')

        # Handle settings update
        if request.method == 'POST':
            for key in ['clipboard_text', 'modal_title', 'modal_body',
                        'verify_button_text', 'preloader_ms', 'allowed_domains',
                        'verification_expire_minutes']:
                if key in request.form:
                    Setting.set(key, request.form[key])
            
            # Handle password change
            if request.form.get('admin_password'):
                Setting.set('ADMIN_PASSWORD', request.form['admin_password'])
                app.config['ADMIN_PASSWORD'] = request.form['admin_password']
            
            app.config['ALLOWED_DOMAINS'] = Setting.get('allowed_domains').split(',')
            flash('Settings updated successfully', 'success')
            return redirect(url_for('admin_panel'))

        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        with db.session() as session:
            # Get paginated visits
            visits_query = session.query(Visit).order_by(Visit.ts.desc())
            total_visits = visits_query.count()
            paginated_visits = visits_query.paginate(
                page=page, per_page=per_page, error_out=False
            )

            # Get JavaScript verification statistics - ИСПРАВЛЕННЫЙ КОД
            js_stats = session.query(
                db.func.count(HumanVerification.id).label('js_verifications'),
                db.func.sum(db.cast(HumanVerification.js_enabled, db.Integer)).label('js_enabled'),
                db.func.sum(db.cast(HumanVerification.cookies_enabled, db.Integer)).label('cookies_enabled'),
                db.func.avg(HumanVerification.hardware_concurrency).label('avg_concurrency'),
                db.func.sum(db.cast(HumanVerification.hardware_concurrency.isnot(None), db.Integer)).label('hardware_detected'),
                db.func.sum(db.cast(HumanVerification.timezone.isnot(None), db.Integer)).label('timezone_detected'),
                db.func.sum(db.cast(HumanVerification.webgl_vendor.isnot(None), db.Integer)).label('webgl_available')
            ).first()

            # Преобразуем результат в словарь для удобства
            js_stats_dict = {
                'js_verifications': js_stats.js_verifications or 0 if js_stats else 0,
                'js_enabled': js_stats.js_enabled or 0 if js_stats else 0,
                'cookies_enabled': js_stats.cookies_enabled or 0 if js_stats else 0,
                'avg_concurrency': round(js_stats.avg_concurrency or 0, 1) if js_stats and js_stats.avg_concurrency else 0,
                'hardware_detected': js_stats.hardware_detected or 0 if js_stats else 0,
                'timezone_detected': js_stats.timezone_detected or 0 if js_stats else 0,
                'webgl_available': js_stats.webgl_available or 0 if js_stats else 0
            }

            stats = {
                'total_visits': total_visits,
                'verified_visits': session.query(Visit).filter_by(verified=True).count(),
                'recent_visits': paginated_visits.items,
                'domains': session.query(
                    Visit.domain,
                    db.func.count(Visit.id),
                    db.func.sum(db.cast(Visit.verified, db.Integer))
                ).group_by(Visit.domain).order_by(db.func.count(Visit.id).desc()).all(),
                'countries': session.query(
                    Visit.country, Visit.country_code,
                    db.func.count(Visit.id),
                    db.func.sum(db.cast(Visit.verified, db.Integer))
                ).group_by(Visit.country, Visit.country_code).order_by(db.func.count(Visit.id).desc()).all(),
                'file_downloads': session.query(
                    FileDownload.filename,
                    db.func.count(FileDownload.id),
                    db.func.max(FileDownload.last_downloaded)
                ).group_by(FileDownload.filename).order_by(db.func.count(FileDownload.id).desc()).all(),
                'recent_downloads': session.query(FileDownload).order_by(FileDownload.last_downloaded.desc()).limit(20).all(),
                'total_downloads': session.query(db.func.count(FileDownload.id)).scalar(),
                'visits_24h': visits_24h_buckets(session),
                'pagination': paginated_visits,
                'blocked_ips': session.query(BlockedIP).order_by(BlockedIP.created_at.desc()).all(),
                # Добавляем статистику JavaScript верификации
                'js_verifications': js_stats_dict['js_verifications'],
                'js_enabled': js_stats_dict['js_enabled'],
                'cookies_enabled': js_stats_dict['cookies_enabled'],
                'avg_concurrency': js_stats_dict['avg_concurrency'],
                'hardware_detected': js_stats_dict['hardware_detected'],
                'timezone_detected': js_stats_dict['timezone_detected'],
                'webgl_available': js_stats_dict['webgl_available']
            }

        return render_template('admin_panel.html',
            settings={key: Setting.get(key) for key in [
                'clipboard_text', 'modal_title', 'modal_body',
                'verify_button_text', 'preloader_ms', 'allowed_domains',
                'verification_expire_minutes'
            ]},
            stats=stats
        )

    except Exception as e:
        logger.error(f"Error in admin_panel: {str(e)}")
        flash('An error occurred', 'error')
        return render_template('error.html'), 500


@app.route('/admin/logout')
def admin_logout():
    response = redirect(url_for('admin_panel'))
    response.set_cookie('admin_auth', '', expires=0)
    return response


@app.route('/captcha-widget.js')
def captcha_widget_js():
    """Serve the embeddable widget JavaScript."""
    response = make_response(render_template('captcha_widget.js'))
    response.headers['Content-Type'] = 'application/javascript'
    # Allow embedding from any origin in dev, restrict in prod
    if app.debug:
        response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/widget')
def captcha_widget():
    """Serve the widget iframe content."""
    return render_template('verification.html', 
                         is_widget=True,
                         modal_title=Setting.get('modal_title'),
                         modal_body=Setting.get('modal_body'),
                         verify_button_text=Setting.get('verify_button_text'),
                         preloader_ms=Setting.get('preloader_ms'))


# ---------------------------
# API used by Tabler UI bits
# ---------------------------

@app.post('/api/block_ip')
def api_block_ip():
    if request.cookies.get('admin_auth') != '1':
        return jsonify({'ok': False, 'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or '').strip()
    reason = data.get('reason') or 'Manual block'
    if not ip:
        return jsonify({'ok': False, 'error': 'ip required'}), 400
    try:
        with db.session() as session:
            entry = session.query(BlockedIP).filter_by(ip=ip).one_or_none()
            if not entry:
                entry = BlockedIP(ip=ip, reason=reason)
                session.add(entry)
            session.commit()
        return jsonify({'ok': True})
    except Exception as e:
        logger.error(f"block_ip failed: {e}", exc_info=True)
        return jsonify({'ok': False, 'error': 'server error'}), 500


@app.post('/api/unblock_ip')
def api_unblock_ip():
    if request.cookies.get('admin_auth') != '1':
        return jsonify({'ok': False, 'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or '').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'ip required'}), 400
    try:
        with db.session() as session:
            entry = session.query(BlockedIP).filter_by(ip=ip).one_or_none()
            if entry:
                session.delete(entry)
                session.commit()
        return jsonify({'ok': True})
    except Exception as e:
        logger.error(f"unblock_ip failed: {e}", exc_info=True)
        return jsonify({'ok': False, 'error': 'server error'}), 500


@app.get('/api/export.csv')
def api_export_csv():
    if request.cookies.get('admin_auth') != '1':
        return "unauthorized", 401
    with db.session() as session:
        rows = session.query(Visit).order_by(Visit.ts.desc()).limit(5000).all()

    def generate():
        import csv
        from io import StringIO
        out = StringIO()
        writer = csv.writer(out)
        writer.writerow(['ts', 'ip', 'country', 'country_code', 'os', 'domain', 'verified'])
        for v in rows:
            writer.writerow([
                (v.ts or '').isoformat(sep=' ', timespec='seconds'),
                v.ip or '', v.country or '', v.country_code or '', v.os or '', v.domain or '',
                int(bool(v.verified)),
            ])
        yield out.getvalue().encode('utf-8')

    headers = {
        'Content-Disposition': 'attachment; filename="visits_export.csv"',
        'Content-Type': 'text/csv; charset=utf-8',
        'Cache-Control': 'no-store',
    }
    return Response(generate(), headers=headers)


@app.get('/api/stats')
def api_stats():
    if request.cookies.get('admin_auth') != '1':
        return jsonify({'ok': False, 'error': 'unauthorized'}), 401
    with db.session() as session:
        # Get JavaScript verification statistics
        js_stats = session.query(
            db.func.count(HumanVerification.id).label('js_verifications'),
            db.func.sum(db.cast(HumanVerification.js_enabled, db.Integer)).label('js_enabled'),
            db.func.sum(db.cast(HumanVerification.cookies_enabled, db.Integer)).label('cookies_enabled'),
            db.func.avg(HumanVerification.hardware_concurrency).label('avg_concurrency'),
            db.func.sum(db.cast(HumanVerification.hardware_concurrency.isnot(None), db.Integer)).label('hardware_detected'),
            db.func.sum(db.cast(HumanVerification.timezone.isnot(None), db.Integer)).label('timezone_detected'),
            db.func.sum(db.cast(HumanVerification.webgl_vendor.isnot(None), db.Integer)).label('webgl_available')
        ).first()

        payload = {
            'visits_24h': visits_24h_buckets(session),
            'totals': {
                'visits': session.query(db.func.count(Visit.id)).scalar(),
                'verified': session.query(db.func.count()).select_from(Visit).filter(Visit.verified == True).scalar(),
            },
            'js_stats': {
                'js_verifications': js_stats.js_verifications or 0,
                'js_enabled': js_stats.js_enabled or 0,
                'cookies_enabled': js_stats.cookies_enabled or 0,
                'avg_concurrency': round(js_stats.avg_concurrency or 0, 1),
                'hardware_detected': js_stats.hardware_detected or 0,
                'timezone_detected': js_stats.timezone_detected or 0,
                'webgl_available': js_stats.webgl_available or 0,
            }
        }
    return jsonify({'ok': True, **payload})


# ----------------------------------
# Entrypoint
# ----------------------------------

if __name__ == '__main__':
    # For local dev over http, set debug=True to allow non-secure cookies above
    app.run(host='0.0.0.0', port=5000, debug=True)