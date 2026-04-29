from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import hashlib
import platform
import os
import socket
import requests
from user_agents import parse

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fingerprints.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ============ نموذج قاعدة البيانات ============
class Fingerprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # بيانات المتصفح
    user_agent = db.Column(db.Text)
    browser_name = db.Column(db.String(100))
    browser_version = db.Column(db.String(50))
    os_name = db.Column(db.String(100))
    os_version = db.Column(db.String(50))
    device_type = db.Column(db.String(50))
    
    # بيانات الجهاز
    screen_width = db.Column(db.Integer)
    screen_height = db.Column(db.Integer)
    color_depth = db.Column(db.Integer)
    pixel_ratio = db.Column(db.Float)
    language = db.Column(db.String(20))
    platform = db.Column(db.String(100))
    hardware_concurrency = db.Column(db.Integer)
    device_memory = db.Column(db.Float)
    
    # بيانات الشبكة
    ip_address = db.Column(db.String(50))
    public_ip = db.Column(db.String(50))
    timezone = db.Column(db.String(100))
    
    # بصمات متقدمة
    canvas_hash = db.Column(db.String(100))
    webgl_vendor = db.Column(db.String(200))
    webgl_renderer = db.Column(db.String(200))
    fonts_hash = db.Column(db.String(100))
    audio_hash = db.Column(db.String(100))
    
    # بيانات إضافية
    do_not_track = db.Column(db.String(10))
    cookies_enabled = db.Column(db.Boolean)
    local_storage = db.Column(db.Boolean)
    session_storage = db.Column(db.Boolean)
    
    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'browser': f"{self.browser_name} {self.browser_version}",
            'os': f"{self.os_name} {self.os_version}",
            'device_type': self.device_type,
            'screen': f"{self.screen_width}x{self.screen_height}",
            'ip': self.ip_address,
            'public_ip': self.public_ip,
            'canvas_hash': self.canvas_hash[:20] + '...' if self.canvas_hash else 'N/A',
            'unique_fingerprint': hashlib.md5(f"{self.canvas_hash}{self.webgl_vendor}{self.fonts_hash}".encode()).hexdigest()[:8]
        }

# ============ إنشاء قاعدة البيانات ============
with app.app_context():
    db.create_all()

# ============ دوال مساعدة ============
def get_client_ip():
    """الحصول على IP الزائر"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip

def get_public_ip():
    """الحصول على IP العام (خارج الشبكة المحلية)"""
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        return response.json()['ip']
    except:
        return "غير متاح"

# ============ Routes ============
@app.route('/')
def index():
    """صفحة تجميع البيانات الرئيسية"""
    return render_template('index.html')

@app.route('/collect', methods=['POST'])
def collect_data():
    """نقطة نهاية لاستقبال البيانات من الزائر"""
    try:
        data = request.json
        session_id = request.cookies.get('session_id', 'unknown')
        
        # تحليل User-Agent
        ua_string = request.headers.get('User-Agent', '')
        ua_parsed = parse(ua_string)
        
        # الحصول على IP
        ip_address = get_client_ip()
        public_ip = get_public_ip()
        
        # إنشاء سجل جديد في قاعدة البيانات
        fingerprint = Fingerprint(
            session_id=session_id,
            user_agent=ua_string,
            browser_name=ua_parsed.browser.family,
            browser_version=ua_parsed.browser.version_string,
            os_name=ua_parsed.os.family,
            os_version=ua_parsed.os.version_string,
            device_type=ua_parsed.device.family,
            screen_width=data.get('screen_width'),
            screen_height=data.get('screen_height'),
            color_depth=data.get('color_depth'),
            pixel_ratio=data.get('pixel_ratio'),
            language=data.get('language'),
            platform=data.get('platform'),
            hardware_concurrency=data.get('hardware_concurrency'),
            device_memory=data.get('device_memory'),
            ip_address=ip_address,
            public_ip=public_ip,
            timezone=data.get('timezone'),
            canvas_hash=data.get('canvas_hash'),
            webgl_vendor=data.get('webgl_vendor'),
            webgl_renderer=data.get('webgl_renderer'),
            fonts_hash=data.get('fonts_hash'),
            audio_hash=data.get('audio_hash'),
            do_not_track=data.get('do_not_track'),
            cookies_enabled=data.get('cookies_enabled'),
            local_storage=data.get('local_storage'),
            session_storage=data.get('session_storage')
        )
        
        db.session.add(fingerprint)
        db.session.commit()
        
        # حساب بصمة فريدة
        unique_fingerprint = hashlib.md5(
            f"{data.get('canvas_hash')}{data.get('webgl_vendor')}{data.get('fonts_hash')}".encode()
        ).hexdigest()
        
        return jsonify({
            'status': 'success',
            'message': 'تم حفظ البيانات بنجاح',
            'fingerprint_id': fingerprint.id,
            'unique_fingerprint': unique_fingerprint[:8]
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/dashboard')
def dashboard():
    """لوحة تحكم لعرض جميع البيانات"""
    fingerprints = Fingerprint.query.order_by(Fingerprint.timestamp.desc()).all()
    return render_template('dashboard.html', fingerprints=fingerprints)

@app.route('/api/fingerprints')
def api_fingerprints():
    """API لعرض البيانات بتنسيق JSON"""
    fingerprints = Fingerprint.query.order_by(Fingerprint.timestamp.desc()).all()
    return jsonify([f.to_dict() for f in fingerprints])

@app.route('/compare/<int:id1>/<int:id2>')
def compare_fingerprints(id1, id2):
    """مقارنة بين جلسيتين"""
    fp1 = Fingerprint.query.get_or_404(id1)
    fp2 = Fingerprint.query.get_or_404(id2)
    
    comparison = {
        'session_1': fp1.to_dict(),
        'session_2': fp2.to_dict(),
        'differences': {
            'canvas_changed': fp1.canvas_hash != fp2.canvas_hash,
            'webgl_changed': fp1.webgl_vendor != fp2.webgl_vendor,
            'resolution_changed': (fp1.screen_width, fp1.screen_height) != (fp2.screen_width, fp2.screen_height),
            'ip_changed': fp1.public_ip != fp2.public_ip,
            'user_agent_changed': fp1.user_agent != fp2.user_agent
        }
    }
    return jsonify(comparison)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
