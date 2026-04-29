import os
import json
import hashlib
import platform
import socket
import time
import random
import string
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from user_agents import parse
import requests

# ============================================
# إعدادات التطبيق
# ============================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', ''.join(random.choices(string.hexdigits, k=32)))

# إعداد قاعدة البيانات (دعم SQLite محلياً و PostgreSQL في الإنتاج)
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres'):
    # تعديل الرابط ليتوافق مع SQLAlchemy
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 5,
        'pool_recycle': 300,
        'pool_pre_ping': True
    }
else:
    # استخدام SQLite محلياً
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.environ.get('DATABASE_PATH', os.path.join(basedir, 'fingerprints.db'))
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False

# تمكين CORS للـ API
CORS(app)

db = SQLAlchemy(app)

# ============================================
# نموذج قاعدة البيانات
# ============================================

class Fingerprint(db.Model):
    """نموذج تخزين بصمة الجهاز"""
    __tablename__ = 'fingerprints'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(200), index=True)
    fingerprint_hash = db.Column(db.String(64), index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # بيانات المتصفح الأساسية
    user_agent = db.Column(db.Text)
    browser_name = db.Column(db.String(100))
    browser_version = db.Column(db.String(50))
    os_name = db.Column(db.String(100))
    os_version = db.Column(db.String(50))
    device_type = db.Column(db.String(50))
    device_brand = db.Column(db.String(50))
    device_model = db.Column(db.String(50))
    
    # بيانات الشاشة والجهاز
    screen_width = db.Column(db.Integer)
    screen_height = db.Column(db.Integer)
    screen_avail_width = db.Column(db.Integer)
    screen_avail_height = db.Column(db.Integer)
    color_depth = db.Column(db.Integer)
    pixel_ratio = db.Column(db.Float)
    device_pixel_ratio = db.Column(db.Float)
    
    # بيانات اللغة والمنطقة
    language = db.Column(db.String(20))
    languages = db.Column(db.Text)  # JSON array
    timezone = db.Column(db.String(100))
    timezone_offset = db.Column(db.Integer)
    
    # بيانات النظام
    platform = db.Column(db.String(100))
    hardware_concurrency = db.Column(db.Integer)
    device_memory = db.Column(db.Float)
    max_touch_points = db.Column(db.Integer)
    
    # بيانات الشبكة
    ip_address = db.Column(db.String(50))
    public_ip = db.Column(db.String(50), index=True)
    ip_country = db.Column(db.String(50))
    ip_city = db.Column(db.String(100))
    ip_isp = db.Column(db.String(200))
    
    # البصمات المتقدمة
    canvas_hash = db.Column(db.String(64))
    canvas_winding_hash = db.Column(db.String(64))
    webgl_vendor = db.Column(db.String(200))
    webgl_renderer = db.Column(db.String(200))
    webgl_hash = db.Column(db.String(64))
    fonts_hash = db.Column(db.String(64))
    audio_hash = db.Column(db.String(64))
    
    # ميزات المتصفح
    do_not_track = db.Column(db.String(10))
    cookies_enabled = db.Column(db.Boolean)
    local_storage = db.Column(db.Boolean)
    session_storage = db.Column(db.Boolean)
    indexed_db = db.Column(db.Boolean)
    java_enabled = db.Column(db.Boolean)
    
    # وسائل الحماية
    vpn_detected = db.Column(db.Boolean, default=False)
    proxy_detected = db.Column(db.Boolean, default=False)
    tor_detected = db.Column(db.Boolean, default=False)
    datacenter_ip = db.Column(db.Boolean, default=False)
    
    # بيانات إضافية
    referer = db.Column(db.Text)
    accept_language = db.Column(db.Text)
    accept_encoding = db.Column(db.Text)
    
    def to_dict(self, detailed=True):
        """تحويل السجل إلى قاموس"""
        data = {
            'id': self.id,
            'session_id': self.session_id,
            'fingerprint_hash': self.fingerprint_hash,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
            'browser': f"{self.browser_name or '?'} {self.browser_version or ''}".strip(),
            'os': f"{self.os_name or '?'} {self.os_version or ''}".strip(),
            'device': self.device_type or 'Desktop',
            'screen': f"{self.screen_width}x{self.screen_height}",
            'ip': self.public_ip or self.ip_address,
            'location': f"{self.ip_city or '?'}, {self.ip_country or '?'}" if self.ip_city or self.ip_country else None,
            'canvas_hash': self.canvas_hash[:16] + '...' if self.canvas_hash else None,
            'unique_id': self.fingerprint_hash[:8] if self.fingerprint_hash else None,
            'is_bot': self.vpn_detected or self.proxy_detected or self.tor_detected
        }
        
        if detailed:
            data.update({
                'browser_name': self.browser_name,
                'browser_version': self.browser_version,
                'os_name': self.os_name,
                'os_version': self.os_version,
                'device_type': self.device_type,
                'screen_width': self.screen_width,
                'screen_height': self.screen_height,
                'color_depth': self.color_depth,
                'pixel_ratio': self.pixel_ratio,
                'language': self.language,
                'timezone': self.timezone,
                'platform': self.platform,
                'hardware_concurrency': self.hardware_concurrency,
                'device_memory': self.device_memory,
                'ip_address': self.ip_address,
                'public_ip': self.public_ip,
                'ip_country': self.ip_country,
                'ip_city': self.ip_city,
                'webgl_vendor': self.webgl_vendor,
                'webgl_renderer': self.webgl_renderer,
                'fonts_hash': self.fonts_hash,
                'audio_hash': self.audio_hash,
                'vpn_detected': self.vpn_detected,
                'proxy_detected': self.proxy_detected,
                'tor_detected': self.tor_detected
            })
        
        return data

# إنشاء الجداول (مع التحقق من البيئة)
with app.app_context():
    db.create_all()
    print("✅ قاعدة البيانات جاهزة")

# ============================================
# دوال مساعدة
# ============================================

def get_client_ip():
    """الحصول على عنوان IP الحقيقي للزائر"""
    if request.headers.get('CF-Connecting-IP'):  # Cloudflare
        return request.headers.get('CF-Connecting-IP')
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or '0.0.0.0'

def get_ip_geolocation(ip):
    """الحصول على معلومات جغرافية عن IP (مجاني ومحدود)"""
    if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
        return None, None, None
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data.get('country'), data.get('city'), data.get('isp')
    except:
        pass
    return None, None, None

def check_vpn_proxy(ip):
    """التحقق مما إذا كان IP يتبع VPN/Proxy (خدمة مجانية محدودة)"""
    try:
        response = requests.get(f'https://vpnapi.io/api/{ip}?key=demo', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'vpn': data.get('security', {}).get('vpn', False),
                'proxy': data.get('security', {}).get('proxy', False),
                'tor': data.get('security', {}).get('tor', False),
                'datacenter': data.get('security', {}).get('hosting', False)
            }
    except:
        pass
    return {'vpn': False, 'proxy': False, 'tor': False, 'datacenter': False}

def generate_fingerprint_hash(data):
    """توليد هاش فريد من البيانات"""
    fingerprint_string = json.dumps(data, sort_keys=True)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

def generate_session_id():
    """توليد معرف جلسة فريد"""
    return f"{int(time.time() * 1000)}_{''.join(random.choices(string.ascii_letters + string.digits, k=16))}"

def require_api_key(f):
    """Decorator لحماية API بمفتاح (اختياري)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = os.environ.get('API_KEY')
        if api_key:
            provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            if provided_key != api_key:
                return jsonify({'error': 'Unauthorized', 'message': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# Routes
# ============================================

@app.route('/')
def index():
    """الصفحة الرئيسية - تجميع البصمة"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """لوحة التحكم"""
    total_count = Fingerprint.query.count()
    unique_fingerprints = db.session.query(Fingerprint.fingerprint_hash).distinct().count()
    last_24h = Fingerprint.query.filter(
        Fingerprint.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    
    return render_template('dashboard.html', stats={
        'total': total_count,
        'unique': unique_fingerprints,
        'last_24h': last_24h
    })

@app.route('/collect', methods=['POST'])
def collect_data():
    """نقطة نهاية لجمع البيانات من الزائر"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # الحصول على أو إنشاء معرف الجلسة
        session_id = request.cookies.get('session_id')
        if not session_id:
            session_id = generate_session_id()
        
        # تحليل User-Agent
        ua_string = request.headers.get('User-Agent', '')
        ua_parsed = parse(ua_string)
        
        # الحصول على معلومات IP
        ip_address = get_client_ip()
        public_ip = ip_address if not ip_address.startswith(('127.', '192.168.', '10.')) else None
        country, city, isp = get_ip_geolocation(public_ip) if public_ip else (None, None, None)
        
        # التحقق من VPN/Proxy (اختياري، قد يبطئ العملية)
        security_check = check_vpn_proxy(public_ip) if public_ip else {}
        
        # معالجة اللغات (قد تكون مصفوفة)
        languages = data.get('languages', [])
        if isinstance(languages, list):
            languages = ','.join(languages[:5])
        
        # إنشاء هاش فريد للبصمة
        fingerprint_data = {
            'canvas': data.get('canvas_hash'),
            'webgl': data.get('webgl_vendor'),
            'fonts': data.get('fonts_hash'),
            'resolution': f"{data.get('screen_width')}x{data.get('screen_height')}",
            'platform': data.get('platform'),
            'timezone': data.get('timezone')
        }
        fingerprint_hash = generate_fingerprint_hash(fingerprint_data)
        
        # إضافة سجل جديد
        fingerprint = Fingerprint(
            session_id=session_id,
            fingerprint_hash=fingerprint_hash,
            user_agent=ua_string[:500],
            browser_name=ua_parsed.browser.family,
            browser_version=ua_parsed.browser.version_string,
            os_name=ua_parsed.os.family,
            os_version=ua_parsed.os.version_string,
            device_type=ua_parsed.device.family,
            device_brand=ua_parsed.device.brand,
            device_model=ua_parsed.device.model,
            screen_width=data.get('screen_width'),
            screen_height=data.get('screen_height'),
            screen_avail_width=data.get('screen_avail_width'),
            screen_avail_height=data.get('screen_avail_height'),
            color_depth=data.get('color_depth'),
            pixel_ratio=data.get('pixel_ratio'),
            device_pixel_ratio=data.get('device_pixel_ratio'),
            language=data.get('language'),
            languages=languages[:500] if languages else None,
            timezone=data.get('timezone'),
            timezone_offset=data.get('timezone_offset'),
            platform=data.get('platform'),
            hardware_concurrency=data.get('hardware_concurrency'),
            device_memory=data.get('device_memory'),
            max_touch_points=data.get('max_touch_points'),
            ip_address=ip_address,
            public_ip=public_ip,
            ip_country=country,
            ip_city=city,
            ip_isp=isp,
            canvas_hash=data.get('canvas_hash'),
            canvas_winding_hash=data.get('canvas_winding_hash'),
            webgl_vendor=data.get('webgl_vendor'),
            webgl_renderer=data.get('webgl_renderer'),
            webgl_hash=data.get('webgl_hash'),
            fonts_hash=data.get('fonts_hash'),
            audio_hash=data.get('audio_hash'),
            do_not_track=str(data.get('do_not_track')) if data.get('do_not_track') else None,
            cookies_enabled=data.get('cookies_enabled'),
            local_storage=data.get('local_storage'),
            session_storage=data.get('session_storage'),
            indexed_db=data.get('indexed_db'),
            java_enabled=data.get('java_enabled'),
            vpn_detected=security_check.get('vpn', False),
            proxy_detected=security_check.get('proxy', False),
            tor_detected=security_check.get('tor', False),
            datacenter_ip=security_check.get('datacenter', False),
            referer=request.headers.get('Referer', '')[:500],
            accept_language=request.headers.get('Accept-Language', '')[:200],
            accept_encoding=request.headers.get('Accept-Encoding', '')[:200]
        )
        
        db.session.add(fingerprint)
        db.session.commit()
        
        # إعداد الرد مع كوكي الجلسة
        response = make_response(jsonify({
            'status': 'success',
            'message': 'Data collected successfully',
            'fingerprint_id': fingerprint.id,
            'fingerprint_hash': fingerprint_hash[:16],
            'is_new_session': not request.cookies.get('session_id')
        }))
        
        response.set_cookie('session_id', session_id, max_age=365*24*60*60, httponly=True)
        return response
        
    except Exception as e:
        db.session.rollback()
        print(f"Error in collect_data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/fingerprints')
@require_api_key
def get_fingerprints():
    """API لجلب جميع البصمات (محمي بمفتاح)"""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    fingerprint_hash = request.args.get('hash')
    
    query = Fingerprint.query
    if fingerprint_hash:
        query = query.filter(Fingerprint.fingerprint_hash.like(f'%{fingerprint_hash}%'))
    
    fingerprints = query.order_by(Fingerprint.timestamp.desc()).offset(offset).limit(limit).all()
    
    return jsonify({
        'total': query.count(),
        'limit': limit,
        'offset': offset,
        'data': [f.to_dict() for f in fingerprints]
    })

@app.route('/api/fingerprints/<int:id>')
@require_api_key
def get_fingerprint(id):
    """API لجلب بصمة محددة"""
    fingerprint = Fingerprint.query.get_or_404(id)
    return jsonify(fingerprint.to_dict())

@app.route('/api/stats')
@require_api_key
def get_stats():
    """API لإحصائيات عامة"""
    total = Fingerprint.query.count()
    unique = db.session.query(Fingerprint.fingerprint_hash).distinct().count()
    
    # البصمات الأكثر تكراراً
    top_fingerprints = db.session.query(
        Fingerprint.fingerprint_hash,
        db.func.count(Fingerprint.id).label('count')
    ).group_by(Fingerprint.fingerprint_hash).order_by(db.text('count DESC')).limit(10).all()
    
    # المتصفحات الأكثر استخداماً
    top_browsers = db.session.query(
        Fingerprint.browser_name,
        db.func.count(Fingerprint.id).label('count')
    ).filter(Fingerprint.browser_name.isnot(None)).group_by(Fingerprint.browser_name).order_by(db.text('count DESC')).limit(5).all()
    
    return jsonify({
        'total_fingerprints': total,
        'unique_visitors': unique,
        'top_fingerprints': [{'hash': h[:16], 'count': c} for h, c in top_fingerprints],
        'top_browsers': [{'browser': b, 'count': c} for b, c in top_browsers]
    })

@app.route('/api/compare/<int:id1>/<int:id2>')
@require_api_key
def compare_fingerprints(id1, id2):
    """مقارنة بين بصمتين"""
    fp1 = Fingerprint.query.get_or_404(id1)
    fp2 = Fingerprint.query.get_or_404(id2)
    
    fields_to_compare = [
        'canvas_hash', 'webgl_vendor', 'webgl_renderer', 'fonts_hash',
        'screen_width', 'screen_height', 'platform', 'timezone', 'language'
    ]
    
    differences = {}
    for field in fields_to_compare:
        val1 = getattr(fp1, field)
        val2 = getattr(fp2, field)
        differences[field] = {
            'changed': val1 != val2,
            'value1': val1,
            'value2': val2
        }
    
    return jsonify({
        'fingerprint_1': fp1.to_dict(detailed=False),
        'fingerprint_2': fp2.to_dict(detailed=False),
        'same_fingerprint': fp1.fingerprint_hash == fp2.fingerprint_hash,
        'differences': differences
    })

@app.route('/api/clear-old', methods=['POST'])
@require_api_key
def clear_old_data():
    """حذف البيانات القديمة (أكثر من 30 يوماً)"""
    days = request.args.get('days', 30, type=int)
    cutoff_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    from datetime import timedelta
    cutoff_date -= timedelta(days=days)
    
    deleted = Fingerprint.query.filter(Fingerprint.timestamp < cutoff_date).delete()
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'deleted_records': deleted,
        'older_than_days': days
    })

@app.route('/health')
def health_check():
    """نقطة نهاية للتحقق من صحة التطبيق"""
    try:
        Fingerprint.query.first()
        db_status = 'healthy'
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    return jsonify({
        'status': 'running',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': 'The requested URL was not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error', 'message': 'An error occurred'}), 500

# ============================================
# تشغيل التطبيق
# ============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print("=" * 60)
    print("🚀 Fingerprint Collector App")
    print("=" * 60)
    print(f"📍 Database: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}...")
    print(f"🌐 Port: {port}")
    print(f"🐛 Debug: {debug}")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
