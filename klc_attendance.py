#!/usr/bin/env python3
import os
import sqlite3
import hashlib
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, request, render_template_string, redirect, url_for, session, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, desc
import csv
from io import StringIO
from PIL import Image
from pyzbar import pyzbar
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'klc-attendance-secret-key')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'change-me')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///klc.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# HTTPS Configuration
USE_HTTPS_ADMIN = os.environ.get('USE_HTTPS_ADMIN', 'False').lower() == 'true'

def is_local_network_request(request):
    """Check if request is from local network"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if not client_ip:
        return True
    
    # Check for local network IP ranges
    local_ranges = [
        '192.168.',
        '10.',
        '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
        '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '127.',
        'localhost'
    ]
    
    return any(client_ip.startswith(prefix) for prefix in local_ranges)

def is_ios_safari(user_agent):
    """Detect iOS Safari user agent"""
    ua = user_agent.lower()
    return ('iphone' in ua or 'ipad' in ua) and 'safari' in ua and 'crios' not in ua

def get_admin_url(request):
    """Generate admin URL based on configuration and client detection"""
    # Always use HTTP for local network requests
    if is_local_network_request(request):
        host = request.headers.get('Host', 'localhost:5000')
        return f"http://{host}/admin"
    
    # For external requests, use HTTPS if configured
    if USE_HTTPS_ADMIN:
        return request.url_root.replace('http://', 'https://') + 'admin'
    
    # Default to HTTP
    host = request.headers.get('Host', 'localhost:5000')
    return f"http://{host}/admin"

def get_correct_protocol_url(request, path=""):
    """Get URL with correct protocol based on request context"""
    if is_local_network_request(request):
        host = request.headers.get('Host', 'localhost:5000')
        return f"http://{host}{path}"
    
    if USE_HTTPS_ADMIN:
        return request.url_root.replace('http://', 'https://').rstrip('/') + path
    
    host = request.headers.get('Host', 'localhost:5000')
    return f"http://{host}{path}"

# Rate limiting storage (simple in-memory)
rate_limit_storage = {}

# Models
class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    started_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    ended_at = db.Column(db.DateTime, nullable=True)
    
    scans = db.relationship('Scan', backref='event', lazy=True)
    
    @property
    def is_active(self):
        return self.ended_at is None

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    code = db.Column(db.String(512), nullable=False)
    ts = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    ip = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='scanlive')

# Helper functions
def init_db():
    """Initialize database tables"""
    with app.app_context():
        db.create_all()

def get_active_event():
    """Get the currently active event"""
    return Event.query.filter_by(ended_at=None).first()

def require_admin():
    """Check if user is authenticated as admin"""
    return session.get('admin_authenticated') == True

def sanitize_code(code):
    """Sanitize and validate QR code"""
    if not code:
        return None
    code = str(code).strip()
    if len(code) > 512:
        code = code[:512]
    return code

def rate_limit_check(ip, max_requests=5, window_seconds=1):
    """Simple rate limiting - max 5 requests per second per IP"""
    now = time.time()
    
    if ip not in rate_limit_storage:
        rate_limit_storage[ip] = []
    
    # Clean old requests
    rate_limit_storage[ip] = [req_time for req_time in rate_limit_storage[ip] 
                             if now - req_time < window_seconds]
    
    if len(rate_limit_storage[ip]) >= max_requests:
        return False
    
    rate_limit_storage[ip].append(now)
    return True

# Routes
@app.route('/scan')
def scan():
    """Legacy scan endpoint - redirects to scanlive"""
    return redirect(url_for('scanlive'))

@app.route('/api/checkin', methods=['POST'])
def api_checkin():
    """API endpoint for QR code check-ins with server-side deduplication"""
    try:
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not rate_limit_check(client_ip):
            return jsonify({"ok": False, "error": "Rate limit exceeded"}), 429
        
        # Parse JSON data
        data = request.get_json()
        if not data:
            return jsonify({"ok": False, "error": "Invalid JSON"}), 400
        
        code = sanitize_code(data.get('code', ''))
        ts_str = data.get('ts', '')
        ua = data.get('ua', request.headers.get('User-Agent', ''))
        source = data.get('source', 'scanlive')
        
        if not code:
            return jsonify({"ok": False, "error": "Missing or invalid code"}), 400
        
        # Get or create active event
        active_event = get_active_event()
        if not active_event:
            # Auto-create default event
            active_event = Event(name="Attendance")
            db.session.add(active_event)
            db.session.commit()
        
        # Parse timestamp
        if ts_str:
            try:
                scan_time = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                if scan_time.tzinfo is None:
                    scan_time = scan_time.replace(tzinfo=timezone.utc)
            except ValueError:
                scan_time = datetime.now(timezone.utc)
        else:
            scan_time = datetime.now(timezone.utc)
        
        # Check for duplicate scan (same event + code within 20 seconds)
        cutoff_time = scan_time - timedelta(seconds=20)
        existing_scan = Scan.query.filter(
            Scan.event_id == active_event.id,
            Scan.code == code,
            Scan.ts > cutoff_time
        ).first()
        
        if existing_scan:
            return jsonify({"ok": True, "duplicated": True})
        
        # Create new scan
        new_scan = Scan(
            event_id=active_event.id,
            code=code,
            ts=scan_time,
            ip=client_ip,
            user_agent=ua,
            source=source
        )
        
        db.session.add(new_scan)
        db.session.commit()
        
        return jsonify({"ok": True, "duplicated": False})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/event/<int:event_id>/stats')
def api_event_stats(event_id):
    """Get statistics for a specific event"""
    event = Event.query.get_or_404(event_id)
    
    stats = db.session.query(
        func.count(Scan.id).label('count_total'),
        func.count(func.distinct(Scan.code)).label('count_distinct_codes'),
        func.min(Scan.ts).label('first_ts'),
        func.max(Scan.ts).label('last_ts')
    ).filter(Scan.event_id == event_id).first()
    
    return jsonify({
        "count_total": stats.count_total or 0,
        "count_distinct_codes": stats.count_distinct_codes or 0,
        "first_ts": stats.first_ts.isoformat() if stats.first_ts else None,
        "last_ts": stats.last_ts.isoformat() if stats.last_ts else None
    })

@app.route('/start_event', methods=['POST'])
def start_event():
    """Start a new event"""
    if not require_admin():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    force = data.get('force', False)
    
    if not name:
        return jsonify({"ok": False, "error": "Event name is required"}), 400
    
    # Check for existing active event
    active_event = get_active_event()
    if active_event and not force:
        return jsonify({
            "ok": False, 
            "error": "An active event already exists",
            "active_event": {"id": active_event.id, "name": active_event.name}
        }), 409
    
    # End existing active event if force=True
    if active_event and force:
        active_event.ended_at = datetime.now(timezone.utc)
        db.session.commit()
    
    # Create new event
    new_event = Event(name=name)
    db.session.add(new_event)
    db.session.commit()
    
    session['active_event_id'] = new_event.id
    
    return jsonify({"ok": True, "event_id": new_event.id})

@app.route('/end_event', methods=['POST'])
def end_event():
    """End the current active event"""
    if not require_admin():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    active_event = get_active_event()
    if not active_event:
        return jsonify({"ok": False, "error": "No active event"}), 400
    
    active_event.ended_at = datetime.now(timezone.utc)
    db.session.commit()
    
    session.pop('active_event_id', None)
    
    return jsonify({"ok": True})

@app.route('/', methods=['GET'])
@app.route('/admin', methods=['GET'])
def admin_dashboard():
    """Admin dashboard with comprehensive event management - accessible via HTTP for local network"""
    if not require_admin():
        return render_template_string(LOGIN_TEMPLATE)
    
    active_event = get_active_event()
    
    # Get metrics for active event
    live_stats = {"count_total": 0, "count_distinct_codes": 0, "last_scan": None}
    if active_event:
        stats = db.session.query(
            func.count(Scan.id).label('count_total'),
            func.count(func.distinct(Scan.code)).label('count_distinct_codes'),
            func.max(Scan.ts).label('last_scan')
        ).filter(Scan.event_id == active_event.id).first()
        
        live_stats = {
            "count_total": stats.count_total or 0,
            "count_distinct_codes": stats.count_distinct_codes or 0,
            "last_scan": stats.last_scan
        }
    
    # Get recent scans for active event
    recent_scans = []
    if active_event:
        recent_scans = Scan.query.filter_by(event_id=active_event.id)\
                                .order_by(desc(Scan.ts))\
                                .limit(50).all()
    
    # Get past events with stats
    past_events_query = db.session.query(
        Event,
        func.count(func.distinct(Scan.code)).label('distinct_attendees'),
        func.count(Scan.id).label('total_scans')
    ).outerjoin(Scan).group_by(Event.id)
    
    if active_event:
        past_events_query = past_events_query.filter(Event.id != active_event.id)
    
    past_events = past_events_query.order_by(desc(Event.started_at)).limit(10).all()
    
    # Pass the correct admin URL to template
    admin_url = get_correct_protocol_url(request, "/admin")
    
    return render_template_string(ADMIN_DASHBOARD_TEMPLATE,
                                active_event=active_event,
                                live_stats=live_stats,
                                recent_scans=recent_scans,
                                past_events=past_events,
                                admin_url=admin_url)

@app.route('/admin-secure')
def admin_dashboard_secure():
    """Secure HTTPS-only admin dashboard"""
    return admin_dashboard()

@app.route('/admin/event/<int:event_id>')
def admin_event_detail(event_id):
    """Detailed view of a specific event"""
    if not require_admin():
        return redirect(url_for('admin_dashboard'))
    
    event = Event.query.get_or_404(event_id)
    
    # Get filters from query params
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    search_code = request.args.get('search_code', '').strip()
    page = int(request.args.get('page', 1))
    
    # Build query
    query = Scan.query.filter_by(event_id=event_id)
    
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
            query = query.filter(Scan.ts >= start_dt)
        except ValueError:
            pass
    
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date).replace(tzinfo=timezone.utc)
            query = query.filter(Scan.ts <= end_dt)
        except ValueError:
            pass
    
    if search_code:
        query = query.filter(Scan.code.contains(search_code))
    
    # Paginate
    scans = query.order_by(desc(Scan.ts)).paginate(
        page=page, per_page=50, error_out=False
    )
    
    # Get event stats
    stats = db.session.query(
        func.count(Scan.id).label('count_total'),
        func.count(func.distinct(Scan.code)).label('count_distinct_codes'),
        func.min(Scan.ts).label('first_ts'),
        func.max(Scan.ts).label('last_ts')
    ).filter(Scan.event_id == event_id).first()
    
    event_stats = {
        "count_total": stats.count_total or 0,
        "count_distinct_codes": stats.count_distinct_codes or 0,
        "first_ts": stats.first_ts,
        "last_ts": stats.last_ts
    }
    
    return render_template_string(EVENT_DETAIL_TEMPLATE,
                                event=event,
                                event_stats=event_stats,
                                scans=scans,
                                filters={
                                    'start_date': start_date,
                                    'end_date': end_date,
                                    'search_code': search_code
                                })

@app.route('/login', methods=['POST'])
def login():
    """Admin login"""
    password = request.form.get('password')
    if password == ADMIN_PASSWORD:
        session['admin_authenticated'] = True
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template_string(LOGIN_TEMPLATE, error="Invalid password")

@app.route('/logout')
def logout():
    """Admin logout"""
    session.pop('admin_authenticated', None)
    return redirect(url_for('admin_dashboard'))

@app.route('/export/event/<int:event_id>.csv')
def export_event_csv(event_id):
    """Export scans for a specific event as CSV"""
    if not require_admin():
        return redirect(url_for('admin_dashboard'))
    
    event = Event.query.get_or_404(event_id)
    scans = Scan.query.filter_by(event_id=event_id).order_by(desc(Scan.ts)).all()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['event_id', 'code', 'ts', 'ip', 'user_agent', 'source'])
    
    for scan in scans:
        writer.writerow([
            scan.event_id,
            scan.code,
            scan.ts.isoformat(),
            scan.ip,
            scan.user_agent,
            scan.source
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=klc_event_{event_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

@app.route('/export/all.csv')
def export_all_csv():
    """Export all scans as CSV"""
    if not require_admin():
        return redirect(url_for('admin_dashboard'))
    
    scans = db.session.query(Scan, Event.name.label('event_name'))\
                     .join(Event)\
                     .order_by(desc(Scan.ts)).all()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['event_id', 'event_name', 'code', 'ts', 'ip', 'user_agent', 'source'])
    
    for scan, event_name in scans:
        writer.writerow([
            scan.event_id,
            event_name,
            scan.code,
            scan.ts.isoformat(),
            scan.ip,
            scan.user_agent,
            scan.source
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=klc_all_scans_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

@app.route('/usher')
def usher():
    """Minimal scanner page for ushers - no data access required"""
    return render_template_string(USHER_TEMPLATE)

@app.route('/scanlive')
def scanlive():
    """Live QR scanner PWA"""
    return render_template_string(SCANLIVE_TEMPLATE)

@app.route('/manifest.json')
def manifest():
    """PWA manifest file"""
    return jsonify({
        "name": "KLC Scanner",
        "short_name": "KLC Scanner",
        "description": "Kingdom Light Chapel QR Code Scanner",
        "start_url": "/scanlive",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#f59e0b",
        "orientation": "portrait",
        "icons": [
            {
                "src": "https://files.catbox.moe/nl6wp1.jpeg",
                "sizes": "192x192",
                "type": "image/jpeg",
                "purpose": "any maskable"
            },
            {
                "src": "https://files.catbox.moe/nl6wp1.jpeg",
                "sizes": "512x512",
                "type": "image/jpeg",
                "purpose": "any maskable"
            }
        ],
        "categories": ["productivity", "utilities"],
        "lang": "en",
        "dir": "ltr"
    })

@app.route('/sw.js')
def service_worker():
    """Service worker for PWA"""
    sw_content = '''
const CACHE_NAME = 'klc-scanner-v2';
const urlsToCache = [
    '/scanlive',
    '/usher',
    '/manifest.json',
    'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js',
    'https://files.catbox.moe/nl6wp1.jpeg'
];

self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                return cache.addAll(urlsToCache);
            })
    );
});

self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                if (response) {
                    return response;
                }
                return fetch(event.request);
            }
        )
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});
'''
    response = make_response(sw_content)
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Service-Worker-Allowed'] = '/'
    return response

@app.route('/health')
def health_check():
    """Health check endpoint to verify DB connectivity"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        active_event = get_active_event()
        
        return jsonify({
            "ok": True,
            "database": "connected",
            "active_event": active_event.name if active_event else None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

# HTML Templates with white/orange professional theme
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KLC Attendance - Admin Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #ffffff;
            color: #000000;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container { 
            background: #ffffff;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 8px 28px rgba(0,0,0,.06);
            width: 100%;
            max-width: 400px;
            border: 1px solid #f3f4f6;
        }
        .logo {
            width: 80px;
            height: 80px;
            border-radius: 12px;
            margin: 0 auto 20px;
            display: block;
            object-fit: cover;
        }
        h1 { 
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-align: center;
            margin-bottom: 30px;
            font-size: 24px;
            font-weight: 700;
        }
        input[type="password"] { 
            width: 100%;
            padding: 16px;
            margin: 16px 0;
            border: 1px solid #d1d5db;
            border-radius: 12px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus {
            outline: none;
            border-color: #f59e0b;
            box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.1);
        }
        button { 
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: #000000;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-1px); }
        .error { 
            color: #ef4444;
            text-align: center;
            margin-top: 16px;
            padding: 12px;
            background: #fef2f2;
            border-radius: 8px;
            border: 1px solid #fecaca;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://files.catbox.moe/nl6wp1.jpeg" alt="KLC Logo" class="logo">
        <h1>Kingdom Light Chapel<br>Attendance Admin</h1>
        <form method="POST" action="/login">
            <input type="password" name="password" placeholder="Admin Password" required>
            <button type="submit">Login</button>
        </form>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
    </div>
</body>
</html>
'''

ADMIN_DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KLC Attendance Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #ffffff;
            color: #000000;
            line-height: 1.6;
        }
        .container { 
            max-width: 1100px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: #ffffff;
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 8px 28px rgba(0,0,0,.06);
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid #f3f4f6;
        }
        .header h1 {
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 28px;
            font-weight: 700;
        }
        .logout { 
            color: #6b7280;
            text-decoration: none;
            padding: 8px 16px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            transition: all 0.2s;
        }
        .logout:hover { 
            background: #f9fafb;
            color: #374151;
        }
        .card { 
            background: #ffffff;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 20px;
            box-shadow: 0 8px 28px rgba(0,0,0,.06);
            border: 1px solid #f3f4f6;
        }
        .card h2, .card h3 {
            color: #111827;
            margin-bottom: 16px;
            font-weight: 600;
        }
        .active-event { 
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: #000000;
            border: none;
        }
        .active-event h2 { color: #000000; }
        .metrics { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 16px 0;
        }
        .metric { 
            text-align: center;
            padding: 16px;
            background: #f9fafb;
            border-radius: 12px;
        }
        .metric h3 { 
            font-size: 32px;
            color: #f59e0b;
            margin-bottom: 4px;
        }
        .metric p { 
            color: #6b7280;
            font-size: 14px;
        }
        .btn { 
            padding: 12px 20px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
            margin: 4px;
        }
        .btn-primary { 
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: #000000;
        }
        .btn-primary:hover { transform: translateY(-1px); }
        .btn-danger { 
            background: #ef4444;
            color: #ffffff;
        }
        .btn-danger:hover { background: #dc2626; }
        .btn-outline { 
            background: transparent;
            color: #374151;
            border: 1px solid #d1d5db;
        }
        .btn-outline:hover { 
            background: #f9fafb;
            border-color: #9ca3af;
        }
        .form-group { 
            margin-bottom: 16px;
        }
        .form-group input { 
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 16px;
        }
        .form-group input:focus {
            outline: none;
            border-color: #f59e0b;
            box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.1);
        }
        .table-container {
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid #e5e7eb;
        }
        table { 
            width: 100%;
            border-collapse: collapse;
        }
        thead { 
            background: #f9fafb;
            position: sticky;
            top: 0;
        }
        th, td { 
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        th { 
            font-weight: 600;
            color: #374151;
        }
        tbody tr:nth-child(even) { 
            background: #fafafa;
        }
        tbody tr:hover { 
            background: #f3f4f6;
        }
        .code-cell { 
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            background: #f3f4f6;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
        }
        .code-cell:hover { 
            background: #e5e7eb;
        }
        .truncate { 
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .header { 
                flex-direction: column;
                gap: 16px;
                text-align: center;
            }
            .metrics { 
                grid-template-columns: 1fr;
            }
            .table-container {
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Kingdom Light Chapel — Attendance Dashboard</h1>
            <a href="/logout" class="logout">Logout</a>
        </div>

        {% if active_event %}
        <div class="card active-event">
            <h2>Active Event: {{ active_event.name }}</h2>
            <p>Started: {{ active_event.started_at.strftime('%Y-%m-%d %H:%M UTC') }}</p>
            <button onclick="endEvent()" class="btn btn-danger" style="margin-top: 16px;">End Event</button>
        </div>
        {% else %}
        <div class="card">
            <h3>Start New Event</h3>
            <div class="form-group">
                <input type="text" id="eventName" placeholder="Event Name" required>
            </div>
            <button onclick="startEvent()" class="btn btn-primary">Start Event</button>
        </div>
        {% endif %}

        <div class="card">
            <h3>Live Metrics</h3>
            <div class="metrics">
                <div class="metric">
                    <h3>{{ live_stats.count_distinct_codes }}</h3>
                    <p>Unique Attendees</p>
                </div>
                <div class="metric">
                    <h3>{{ live_stats.count_total }}</h3>
                    <p>Total Scans</p>
                </div>
                <div class="metric">
                    <h3>{% if live_stats.last_scan %}{{ live_stats.last_scan.strftime('%H:%M') }}{% else %}--{% endif %}</h3>
                    <p>Last Scan</p>
                </div>
            </div>
        </div>

        {% if recent_scans %}
        <div class="card">
            <h3>Recent Scans (Last 50)</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Code</th>
                            <th>IP</th>
                            <th>Source</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for scan in recent_scans %}
                        <tr>
                            <td>{{ scan.ts.strftime('%H:%M:%S') }}</td>
                            <td><span class="code-cell" onclick="copyToClipboard('{{ scan.code }}')">{{ scan.code[:20] }}{% if scan.code|length > 20 %}...{% endif %}</span></td>
                            <td>{{ scan.ip }}</td>
                            <td>{{ scan.source }}</td>
                            <td class="truncate">{{ scan.user_agent[:50] }}{% if scan.user_agent|length > 50 %}...{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        {% if past_events %}
        <div class="card">
            <h3>Past Events</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Unique Attendees</th>
                            <th>Total Scans</th>
                            <th>Started</th>
                            <th>Ended</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for event, distinct_attendees, total_scans in past_events %}
                        <tr>
                            <td>{{ event.name }}</td>
                            <td>{{ distinct_attendees }}</td>
                            <td>{{ total_scans }}</td>
                            <td>{{ event.started_at.strftime('%Y-%m-%d %H:%M') }}</td>
                            <td>{% if event.ended_at %}{{ event.ended_at.strftime('%Y-%m-%d %H:%M') }}{% else %}Active{% endif %}</td>
                            <td>
                                <a href="/admin/event/{{ event.id }}" class="btn btn-outline">View</a>
                                <a href="/export/event/{{ event.id }}.csv" class="btn btn-outline">Export CSV</a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <div class="card">
            <h3>Export Data</h3>
            {% if active_event %}
            <a href="/export/event/{{ active_event.id }}.csv" class="btn btn-primary">Export Active Event CSV</a>
            {% endif %}
            <a href="/export/all.csv" class="btn btn-outline">Export All CSV</a>
        </div>
    </div>

    <script>
        async function startEvent() {
            const name = document.getElementById('eventName').value.trim();
            if (!name) {
                alert('Please enter an event name');
                return;
            }

            try {
                const response = await fetch('/start_event', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name })
                });

                const result = await response.json();
                if (result.ok) {
                    location.reload();
                } else {
                    alert(result.error || 'Failed to start event');
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        }

        async function endEvent() {
            if (!confirm('Are you sure you want to end the current event?')) {
                return;
            }

            try {
                const response = await fetch('/end_event', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                const result = await response.json();
                if (result.ok) {
                    location.reload();
                } else {
                    alert(result.error || 'Failed to end event');
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Visual feedback
                event.target.style.background = '#10b981';
                event.target.style.color = '#ffffff';
                setTimeout(() => {
                    event.target.style.background = '#f3f4f6';
                    event.target.style.color = '#000000';
                }, 500);
            });
        }
    </script>
</body>
</html>
'''

EVENT_DETAIL_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ event.name }} - Event Details</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #ffffff;
            color: #000000;
            line-height: 1.6;
        }
        .container { 
            max-width: 1100px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: #ffffff;
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0 8px 28px rgba(0,0,0,.06);
            margin-bottom: 20px;
            border: 1px solid #f3f4f6;
        }
        .header h1 {
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .breadcrumb {
            color: #6b7280;
            margin-bottom: 16px;
        }
        .breadcrumb a {
            color: #f59e0b;
            text-decoration: none;
        }
        .card { 
            background: #ffffff;
            padding: 20px;
            border-radius: 16px;
            margin-bottom: 20px;
            box-shadow: 0 8px 28px rgba(0,0,0,.06);
            border: 1px solid #f3f4f6;
        }
        .stats { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 16px 0;
        }
        .stat { 
            text-align: center;
            padding: 16px;
            background: #f9fafb;
            border-radius: 12px;
        }
        .stat h3 { 
            font-size: 24px;
            color: #f59e0b;
            margin-bottom: 4px;
        }
        .filters {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 14px;
        }
        .btn { 
            padding: 12px 20px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
            margin: 4px;
        }
        .btn-primary { 
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: #000000;
        }
        .btn-outline { 
            background: transparent;
            color: #374151;
            border: 1px solid #d1d5db;
        }
        .table-container {
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid #e5e7eb;
        }
        table { 
            width: 100%;
            border-collapse: collapse;
        }
        thead { 
            background: #f9fafb;
            position: sticky;
            top: 0;
        }
        th, td { 
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        tbody tr:nth-child(even) { 
            background: #fafafa;
        }
        .code-cell { 
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            background: #f3f4f6;
            padding: 4px 8px;
            border-radius: 4px;
        }
        .pagination {
            display: flex;
            justify-content: center;
            gap: 8px;
            margin-top: 20px;
        }
        .pagination a {
            padding: 8px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            text-decoration: none;
            color: #374151;
        }
        .pagination a.current {
            background: #f59e0b;
            color: #000000;
            border-color: #f59e0b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="breadcrumb">
                <a href="/admin">Dashboard</a> / Event Details
            </div>
            <h1>{{ event.name }}</h1>
            <p>Started: {{ event.started_at.strftime('%Y-%m-%d %H:%M UTC') }}</p>
            {% if event.ended_at %}
            <p>Ended: {{ event.ended_at.strftime('%Y-%m-%d %H:%M UTC') }}</p>
            {% else %}
            <p style="color: #10b981; font-weight: 600;">Currently Active</p>
            {% endif %}
        </div>

        <div class="card">
            <h3>Event Statistics</h3>
            <div class="stats">
                <div class="stat">
                    <h3>{{ event_stats.count_distinct_codes }}</h3>
                    <p>Unique Attendees</p>
                </div>
                <div class="stat">
                    <h3>{{ event_stats.count_total }}</h3>
                    <p>Total Scans</p>
                </div>
                <div class="stat">
                    <h3>{% if event_stats.first_ts %}{{ event_stats.first_ts.strftime('%H:%M') }}{% else %}--{% endif %}</h3>
                    <p>First Scan</p>
                </div>
                <div class="stat">
                    <h3>{% if event_stats.last_ts %}{{ event_stats.last_ts.strftime('%H:%M') }}{% else %}--{% endif %}</h3>
                    <p>Last Scan</p>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>Filters</h3>
            <form method="GET">
                <div class="filters">
                    <div class="form-group">
                        <input type="datetime-local" name="start_date" value="{{ filters.start_date }}" placeholder="Start Date">
                    </div>
                    <div class="form-group">
                        <input type="datetime-local" name="end_date" value="{{ filters.end_date }}" placeholder="End Date">
                    </div>
                    <div class="form-group">
                        <input type="text" name="search_code" value="{{ filters.search_code }}" placeholder="Search Code">
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary">Apply Filters</button>
                        <a href="/admin/event/{{ event.id }}" class="btn btn-outline">Clear</a>
                    </div>
                </div>
            </form>
        </div>

        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h3>Scans ({{ scans.total }} total)</h3>
                <a href="/export/event/{{ event.id }}.csv" class="btn btn-primary">Export CSV</a>
            </div>
            
            {% if scans.items %}
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Code</th>
                            <th>IP</th>
                            <th>Source</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for scan in scans.items %}
                        <tr>
                            <td>{{ scan.ts.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                            <td><span class="code-cell">{{ scan.code }}</span></td>
                            <td>{{ scan.ip }}</td>
                            <td>{{ scan.source }}</td>
                            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">{{ scan.user_agent[:100] }}{% if scan.user_agent|length > 100 %}...{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

            <div class="pagination">
                {% if scans.has_prev %}
                <a href="{{ url_for('admin_event_detail', event_id=event.id, page=scans.prev_num, **filters) }}">&laquo; Previous</a>
                {% endif %}
                
                {% for page_num in scans.iter_pages() %}
                    {% if page_num %}
                        {% if page_num != scans.page %}
                        <a href="{{ url_for('admin_event_detail', event_id=event.id, page=page_num, **filters) }}">{{ page_num }}</a>
                        {% else %}
                        <a href="#" class="current">{{ page_num }}</a>
                        {% endif %}
                    {% endif %}
                {% endfor %}
                
                {% if scans.has_next %}
                <a href="{{ url_for('admin_event_detail', event_id=event.id, page=scans.next_num, **filters) }}">Next &raquo;</a>
                {% endif %}
            </div>
            {% else %}
            <p style="text-align: center; color: #6b7280; padding: 40px;">No scans found for the current filters.</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

USHER_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>KLC Scanner - Usher Mode</title>
    
    <script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #ffffff;
            color: #000000;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            position: relative;
            user-select: none;
            -webkit-user-select: none;
        }
        
        .header {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: #ffffff;
            border-bottom: 1px solid rgba(245, 158, 11, 0.1);
        }
        
        .logo-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logo {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            border: 2px solid rgba(245, 158, 11, 0.3);
            box-shadow: 0 0 20px rgba(245, 158, 11, 0.2);
            object-fit: cover;
        }
        
        .title {
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            background-size: 200% 200%;
            animation: gradientShift 4s ease infinite;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 24px;
            font-weight: 700;
            letter-spacing: 2px;
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
            gap: 30px;
            background: #ffffff;
        }
        
        #reader {
            width: 100%;
            max-width: 350px;
            height: 350px;
            border: 3px solid #f59e0b;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 0 40px rgba(245, 158, 11, 0.4);
            transition: all 0.3s ease;
            position: relative;
            background: rgba(248, 248, 248, 0.5);
        }
        
        #reader video {
            border-radius: 17px;
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        @keyframes greenFlash {
            0% { 
                border-color: #f59e0b;
                box-shadow: 0 0 40px rgba(245, 158, 11, 0.4);
            }
            50% { 
                border-color: #10b981;
                box-shadow: 0 0 60px rgba(16, 185, 129, 0.8);
            }
            100% { 
                border-color: #f59e0b;
                box-shadow: 0 0 40px rgba(245, 158, 11, 0.4);
            }
        }
        
        #reader.success-flash {
            animation: greenFlash 0.5s ease-in-out;
        }
        
        .controls {
            display: flex;
            flex-direction: column;
            gap: 15px;
            width: 100%;
            max-width: 350px;
        }
        
        .btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            padding: 18px 24px;
            border: none;
            border-radius: 15px;
            color: #ffffff;
            text-decoration: none;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            min-height: 60px;
            position: relative;
            overflow: hidden;
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-start {
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: #000000;
            box-shadow: 0 6px 20px rgba(245, 158, 11, 0.4);
        }
        
        .btn-start:hover:not(:disabled) {
            background: linear-gradient(135deg, #fbbf24, #f59e0b);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(245, 158, 11, 0.5);
        }
        
        .btn-stop {
            background: linear-gradient(135deg, #dc3545, #c82333);
            box-shadow: 0 6px 20px rgba(220, 53, 69, 0.4);
        }
        
        .btn-stop:hover:not(:disabled) {
            background: linear-gradient(135deg, #e74c3c, #dc3545);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(220, 53, 69, 0.5);
        }
        
        .btn-torch {
            background: linear-gradient(135deg, #6b7280, #4b5563);
            box-shadow: 0 6px 20px rgba(107, 114, 128, 0.4);
            display: none;
        }
        
        .btn-torch:hover:not(:disabled) {
            background: linear-gradient(135deg, #4b5563, #374151);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(107, 114, 128, 0.5);
        }
        
        .btn-torch.active {
            background: linear-gradient(135deg, #fbbf24, #f59e0b);
            color: #000000;
        }
        
        .toast {
            position: fixed;
            top: 80px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(16, 185, 129, 0.95);
            color: #000000;
            padding: 15px 25px;
            border-radius: 30px;
            font-weight: 600;
            z-index: 1001;
            opacity: 0;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.3);
        }
        
        .toast.show {
            opacity: 1;
            transform: translateX(-50%) translateY(10px);
        }
        
        .toast.error {
            background: rgba(239, 68, 68, 0.95);
            color: #ffffff;
            box-shadow: 0 4px 20px rgba(239, 68, 68, 0.3);
        }
        
        .icon {
            width: 22px;
            height: 22px;
            fill: currentColor;
        }
        
        .back-link {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 20px;
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid #d1d5db;
            border-radius: 12px;
            color: #374151;
            text-decoration: none;
            font-size: 14px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }
        
        .back-link:hover {
            background: rgba(249, 250, 251, 0.95);
            transform: translateY(-2px);
        }
        
        @media (max-width: 768px) {
            .header {
                padding: 15px;
            }
            
            .logo {
                width: 40px;
                height: 40px;
            }
            
            .title {
                font-size: 20px;
                letter-spacing: 1px;
            }
            
            #reader {
                max-width: 300px;
                height: 300px;
            }
            
            .btn {
                padding: 16px 20px;
                font-size: 15px;
                min-height: 55px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-container">
            <img src="https://files.catbox.moe/nl6wp1.jpeg" alt="KLC Logo" class="logo">
            <h1 class="title">KLC SCANNER</h1>
        </div>
    </div>

    <div class="main-content">
        <div id="reader"></div>
        
        <div class="controls">
            <button id="startBtn" class="btn btn-start" onclick="startScanning()">
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M8 5v14l11-7z"/>
                </svg>
                Start Scanner
            </button>
            
            <button id="stopBtn" class="btn btn-stop" onclick="stopScanning()" disabled>
                <svg class="icon" viewBox="0 0 24 24">
                    <rect x="6" y="6" width="12" height="12"/>
                </svg>
                Stop Scanner
            </button>
            
            <button id="torchBtn" class="btn btn-torch" onclick="toggleTorch()" disabled>
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M9 2h6l1 3h4v16H4V5h4l1-3z"/>
                    <circle cx="12" cy="13" r="3"/>
                </svg>
                <span id="torchText">Torch Off</span>
            </button>
        </div>
    </div>

    <div id="toast" class="toast"></div>
    
    <a href="/scanlive" class="back-link">← Full Scanner</a>

    <script>
        let html5QrcodeScanner = null;
        let isScanning = false;
        let torchEnabled = false;
        let lastScannedCode = null;
        let lastScannedTime = 0;
        const DUPLICATE_PREVENTION_MS = 2000;

        function showToast(message, isError = false, duration = 2500) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = `toast ${isError ? 'error' : ''}`;
            toast.classList.add('show');
            
            setTimeout(() => {
                toast.classList.remove('show');
            }, duration);
        }

        function flashGreen() {
            const readerEl = document.getElementById('reader');
            readerEl.classList.add('success-flash');
            setTimeout(() => {
                readerEl.classList.remove('success-flash');
            }, 500);
        }

        async function onScanSuccess(decodedText, decodedResult) {
            const now = Date.now();
            
            if (lastScannedCode === decodedText && (now - lastScannedTime) < DUPLICATE_PREVENTION_MS) {
                return;
            }
            
            lastScannedCode = decodedText;
            lastScannedTime = now;
            
            flashGreen();
            showToast('✓ Scanned');
            
            // Haptic feedback for mobile
            if (navigator.vibrate) {
                navigator.vibrate(100);
            }
            
            try {
                const response = await fetch('/api/checkin', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        code: decodedText,
                        ts: new Date().toISOString(),
                        ua: navigator.userAgent,
                        source: 'usher'
                    })
                });
                
                const result = await response.json();
                
                if (!result.ok) {
                    showToast('⚠ ' + (result.error || 'Check-in failed'), true, 3000);
                }
                
            } catch (error) {
                console.error('Check-in error:', error);
                showToast('⚠ Network error', true, 3000);
            }
        }

        function onScanFailure(error) {
            // Silent - normal when no QR code visible
        }

        async function startScanning() {
            try {
                // Calculate qrbox size based on viewport (use iOS optimizations for better compatibility)
                const viewportWidth = Math.min(window.innerWidth, 400);
                const viewportHeight = Math.min(window.innerHeight, 400);
                const qrboxSize = Math.min(viewportWidth, viewportHeight) * 0.85;
        
                const config = {
                    fps: 12,
                    qrbox: { width: qrboxSize, height: qrboxSize },
                    aspectRatio: 1.0,
                    facingMode: "environment",
                    useBarCodeDetectorIfSupported: true,
                    videoConstraints: {
                        width: { ideal: 1920 },
                        height: { ideal: 1080 },
                        facingMode: "environment"
                    }
                };
        
                html5QrcodeScanner = new Html5Qrcode("reader");
                const cameras = await Html5Qrcode.getCameras();
        
                if (cameras && cameras.length > 0) {
                    let cameraId = cameras[0].id;
                    for (const camera of cameras) {
                        if (camera.label.toLowerCase().includes('back') || 
                            camera.label.toLowerCase().includes('rear') ||
                            camera.label.toLowerCase().includes('environment')) {
                            cameraId = camera.id;
                            break;
                        }
                    }
        
                    await html5QrcodeScanner.start(
                        cameraId,
                        config,
                        onScanSuccess,
                        onScanFailure
                    );
        
                    isScanning = true;
                    document.getElementById('startBtn').disabled = true;
                    document.getElementById('stopBtn').disabled = false;
        
                    // Check for torch capability
                    try {
                        const capabilities = html5QrcodeScanner.getRunningTrackCapabilities();
                        if (capabilities && capabilities.torch) {
                            document.getElementById('torchBtn').style.display = 'flex';
                            document.getElementById('torchBtn').disabled = false;
                        }
                    } catch (e) {
                        // Torch not supported
                    }
        
                } else {
                    showToast('⚠ No cameras found', true, 3000);
                }
        
            } catch (error) {
                console.error('Error starting scanner:', error);
                showToast('⚠ Camera access failed', true, 3000);
            }
        }

        async function stopScanning() {
            if (html5QrcodeScanner && isScanning) {
                try {
                    await html5QrcodeScanner.stop();
                    html5QrcodeScanner.clear();
                } catch (error) {
                    console.error('Error stopping scanner:', error);
                }
            }
        
            isScanning = false;
            torchEnabled = false;
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            document.getElementById('torchBtn').disabled = true;
            document.getElementById('torchBtn').style.display = 'none';
            document.getElementById('torchBtn').classList.remove('active');
            document.getElementById('torchText').textContent = 'Torch Off';
        }

        async function toggleTorch() {
            if (!html5QrcodeScanner || !isScanning) return;
        
            try {
                await html5QrcodeScanner.applyVideoConstraints({
                    advanced: [{ torch: !torchEnabled }]
                });
        
                torchEnabled = !torchEnabled;
                const torchBtn = document.getElementById('torchBtn');
                const torchText = document.getElementById('torchText');
        
                if (torchEnabled) {
                    torchBtn.classList.add('active');
                    torchText.textContent = 'Torch On';
                } else {
                    torchBtn.classList.remove('active');
                    torchText.textContent = 'Torch Off';
                }
            } catch (error) {
                console.error('Error toggling torch:', error);
                showToast('⚠ Torch not available', true, 2000);
            }
        }

        // Auto-start scanning
        window.addEventListener('load', () => {
            setTimeout(startScanning, 800);
        });

        // Handle page visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.hidden && isScanning) {
                stopScanning();
            } else if (!document.hidden && !isScanning) {
                setTimeout(startScanning, 500);
            }
        });

        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            if (isScanning) {
                stopScanning();
            }
        });

        // Prevent zoom on double tap
        let lastTouchEnd = 0;
        document.addEventListener('touchend', function (event) {
            const now = (new Date()).getTime();
            if (now - lastTouchEnd <= 300) {
                event.preventDefault();
            }
            lastTouchEnd = now;
        }, false);
    </script>
</body>
</html>
'''

SCANLIVE_TEMPLATE = r'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>KLC Scanner</title>
    
    <!-- PWA Meta Tags -->
    <meta name="description" content="Kingdom Light Chapel QR Code Scanner">
    <meta name="theme-color" content="#f59e0b">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="KLC Scanner">
    <meta name="mobile-web-app-capable" content="yes">
    
    <!-- PWA Icons -->
    <link rel="icon" type="image/jpeg" href="https://files.catbox.moe/nl6wp1.jpeg">
    <link rel="apple-touch-icon" href="https://files.catbox.moe/nl6wp1.jpeg">
    <link rel="manifest" href="/manifest.json">
    
    <script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #ffffff;
            color: #000000;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            position: relative;
            user-select: none;
            -webkit-user-select: none;
        }
        
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px;
            position: relative;
            z-index: 100;
            background: #ffffff;
            border-bottom: 1px solid rgba(245, 158, 11, 0.1);
        }
        
        .logo-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logo {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            border: 2px solid rgba(245, 158, 11, 0.3);
            box-shadow: 0 0 20px rgba(245, 158, 11, 0.2);
            object-fit: cover;
        }
        
        .title {
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            background-size: 200% 200%;
            animation: gradientShift 4s ease infinite;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 24px;
            font-weight: 700;
            letter-spacing: 2px;
            text-shadow: 0 0 30px rgba(245, 158, 11, 0.5);
            filter: drop-shadow(0 0 10px rgba(245, 158, 11, 0.3));
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .admin-btn {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            background: transparent;
            border: 1px solid #f59e0b;
            border-radius: 10px;
            color: #f59e0b;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .admin-btn:hover {
            background: rgba(245, 158, 11, 0.1);
            box-shadow: 0 0 15px rgba(245, 158, 11, 0.3);
            transform: translateY(-1px);
        }
        
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
            gap: 30px;
            background: #ffffff;
        }
        
        #reader {
            width: 100%;
            max-width: 350px;
            height: 350px;
            border: 3px solid #f59e0b;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 0 40px rgba(245, 158, 11, 0.4);
            transition: all 0.3s ease;
            position: relative;
            background: rgba(248, 248, 248, 0.5);
        }
        
        #reader video {
            border-radius: 17px;
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        @keyframes greenFlash {
            0% { 
                border-color: #f59e0b;
                box-shadow: 0 0 40px rgba(245, 158, 11, 0.4);
            }
            50% { 
                border-color: #10b981;
                box-shadow: 0 0 60px rgba(16, 185, 129, 0.8);
            }
            100% { 
                border-color: #f59e0b;
                box-shadow: 0 0 40px rgba(245, 158, 11, 0.4);
            }
        }
        
        #reader.success-flash {
            animation: greenFlash 0.5s ease-in-out;
        }
        
        .controls {
            display: flex;
            flex-direction: column;
            gap: 15px;
            width: 100%;
            max-width: 350px;
        }
        
        .btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            padding: 18px 24px;
            border: none;
            border-radius: 15px;
            color: #ffffff;
            text-decoration: none;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            min-height: 60px;
            position: relative;
            overflow: hidden;
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-start {
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: #000000;
            box-shadow: 0 6px 20px rgba(245, 158, 11, 0.4);
        }
        
        .btn-start:hover:not(:disabled) {
            background: linear-gradient(135deg, #fbbf24, #f59e0b);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(245, 158, 11, 0.5);
        }
        
        .btn-stop {
            background: linear-gradient(135deg, #dc3545, #c82333);
            box-shadow: 0 6px 20px rgba(220, 53, 69, 0.4);
        }
        
        .btn-stop:hover:not(:disabled) {
            background: linear-gradient(135deg, #e74c3c, #dc3545);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(220, 53, 69, 0.5);
        }
        
        .toast {
            position: fixed;
            top: 80px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(16, 185, 129, 0.95);
            color: #000000;
            padding: 15px 25px;
            border-radius: 30px;
            font-weight: 600;
            z-index: 1001;
            opacity: 0;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.3);
        }
        
        .toast.show {
            opacity: 1;
            transform: translateX(-50%) translateY(10px);
        }
        
        .toast.error {
            background: rgba(239, 68, 68, 0.95);
            color: #ffffff;
            box-shadow: 0 4px 20px rgba(239, 68, 68, 0.3);
        }
        
        .icon {
            width: 22px;
            height: 22px;
            fill: currentColor;
        }
        
        .install-prompt {
            position: fixed;
            bottom: 20px;
            left: 20px;
            right: 20px;
            background: rgba(255, 255, 255, 0.95);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 15px;
            padding: 15px;
            display: none;
            align-items: center;
            gap: 15px;
            backdrop-filter: blur(10px);
            z-index: 1000;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        }
        
        .install-prompt.show {
            display: flex;
        }
        
        .install-text {
            flex: 1;
            font-size: 14px;
            color: #000000;
        }
        
        .install-btn {
            padding: 8px 16px;
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: #000000;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .install-btn:hover {
            background: linear-gradient(135deg, #fbbf24, #f59e0b);
            transform: translateY(-1px);
        }
        
        .close-btn {
            background: none;
            border: none;
            color: #666;
            font-size: 18px;
            cursor: pointer;
            padding: 4px;
        }
        
        @media (max-width: 768px) {
            .header {
                padding: 15px;
            }
            
            .logo {
                width: 40px;
                height: 40px;
            }
            
            .title {
                font-size: 20px;
                letter-spacing: 1px;
            }
            
            .admin-btn {
                padding: 8px 12px;
                font-size: 12px;
            }
            
            #reader {
                max-width: 300px;
                height: 300px;
            }
            
            .btn {
                padding: 16px 20px;
                font-size: 15px;
                min-height: 55px;
            }
        }
        
        @media (max-width: 480px) {
            .main-content {
                padding: 15px;
                gap: 20px;
            }
            
            #reader {
                max-width: 280px;
                height: 280px;
            }
        }

        .btn-outline { 
            background: transparent;
            color: #374151;
            border: 1px solid #d1d5db;
        }

        .btn-outline:hover:not(:disabled) { 
            background: #f9fafb;
            border-color: #9ca3af;
            transform: translateY(-1px);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-container">
            <img src="https://files.catbox.moe/nl6wp1.jpeg" alt="KLC Logo" class="logo">
            <h1 class="title">KLC SCANNER</h1>
        </div>
        <a href="/admin" class="admin-btn">
            <svg class="icon" viewBox="0 0 24 24" style="width: 18px; height: 18px;">
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
            </svg>
            Admin Panel
        </a>
    </div>

    <div class="main-content">
        <div id="reader"></div>
        
        <div class="controls">
            <button id="startBtn" class="btn btn-start" onclick="startScanning()">
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M8 5v14l11-7z"/>
                </svg>
                Start Scanner
            </button>
            
            <button id="stopBtn" class="btn btn-stop" onclick="stopScanning()" disabled>
                <svg class="icon" viewBox="0 0 24 24">
                    <rect x="6" y="6" width="12" height="12"/>
                </svg>
                Stop Scanner
            </button>

            <button id="iosToggleBtn" class="btn btn-outline" onclick="toggleIosMode()" style="font-size: 14px; min-height: 50px;">
                <svg class="icon" viewBox="0 0 24 24" style="width: 18px; height: 18px;">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
                <span id="iosToggleText">iOS Mode: ON</span>
            </button>
        </div>
    </div>

    <div id="toast" class="toast"></div>
    
    <div id="installPrompt" class="install-prompt">
        <div class="install-text">Install KLC Scanner for quick access</div>
        <button id="installBtn" class="install-btn">Install</button>
        <button id="closePrompt" class="close-btn">&times;</button>
    </div>

    <script>
        let html5QrcodeScanner = null;
        let isScanning = false;
        let lastScannedCode = null;
        let lastScannedTime = 0;
        let deferredPrompt = null;
        const DUPLICATE_PREVENTION_MS = 2000;

        // Add iOS detection and mode toggle variables after the existing variables
        let iosMode = /iPad|iPhone|iPod/.test(navigator.userAgent);
        let useIosOptimizations = iosMode;

        // PWA Install Logic
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            document.getElementById('installPrompt').classList.add('show');
        });

        document.getElementById('installBtn').addEventListener('click', async () => {
            if (deferredPrompt) {
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                if (outcome === 'accepted') {
                    document.getElementById('installPrompt').classList.remove('show');
                }
                deferredPrompt = null;
            }
        });

        document.getElementById('closePrompt').addEventListener('click', () => {
            document.getElementById('installPrompt').classList.remove('show');
        });

        // Register Service Worker
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/sw.js')
                    .then((registration) => {
                        console.log('SW registered: ', registration);
                    })
                    .catch((registrationError) => {
                        console.log('SW registration failed: ', registrationError);
                    });
            });
        }

        function showToast(message, isError = false, duration = 2500) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = `toast ${isError ? 'error' : ''}`;
            toast.classList.add('show');
            
            setTimeout(() => {
                toast.classList.remove('show');
            }, duration);
        }

        function flashGreen() {
            const readerEl = document.getElementById('reader');
            readerEl.classList.add('success-flash');
            setTimeout(() => {
                readerEl.classList.remove('success-flash');
            }, 500);
        }

        async function onScanSuccess(decodedText, decodedResult) {
            const now = Date.now();
            
            if (lastScannedCode === decodedText && (now - lastScannedTime) < DUPLICATE_PREVENTION_MS) {
                return;
            }
            
            lastScannedCode = decodedText;
            lastScannedTime = now;
            
            flashGreen();
            showToast('✓ Check-in successful');
            
            // Haptic feedback for mobile
            if (navigator.vibrate) {
                navigator.vibrate(100);
            }
            
            try {
                const response = await fetch('/api/checkin', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        code: decodedText,
                        ts: new Date().toISOString(),
                        ua: navigator.userAgent
                    })
                });
                
                const result = await response.json();
                
                if (!result.ok) {
                    showToast('⚠ ' + (result.error || 'Check-in failed'), true, 3000);
                }
                
            } catch (error) {
                console.error('Check-in error:', error);
                showToast('⚠ Network error', true, 3000);
            }
        }

        function onScanFailure(error) {
            // Silent - normal when no QR code visible
        }

        async function startScanning() {
            try {
                // Calculate qrbox size based on viewport and mode
                const viewportWidth = Math.min(window.innerWidth, 400);
                const viewportHeight = Math.min(window.innerHeight, 400);
                const qrboxSize = Math.min(viewportWidth, viewportHeight) * (useIosOptimizations ? 0.9 : 0.82);
                
                const config = {
                    fps: useIosOptimizations ? 10 : 15,
                    qrbox: { width: qrboxSize, height: qrboxSize },
                    aspectRatio: 1.0,
                    facingMode: "environment",
                    useBarCodeDetectorIfSupported: true,
                    videoConstraints: {
                        width: { ideal: 1920 },
                        height: { ideal: 1080 },
                        facingMode: "environment"
                    }
                };
                
                html5QrcodeScanner = new Html5Qrcode("reader");
                const cameras = await Html5Qrcode.getCameras();
                
                if (cameras && cameras.length > 0) {
                    let cameraId = cameras[0].id;
                    for (const camera of cameras) {
                        if (camera.label.toLowerCase().includes('back') || 
                            camera.label.toLowerCase().includes('rear') ||
                            camera.label.toLowerCase().includes('environment')) {
                            cameraId = camera.id;
                            break;
                        }
                    }
                    
                    await html5QrcodeScanner.start(
                        cameraId,
                        config,
                        onScanSuccess,
                        onScanFailure
                    );
                    
                    isScanning = true;
                    document.getElementById('startBtn').disabled = true;
                    document.getElementById('stopBtn').disabled = false;
                    
                } else {
                    showToast('⚠ No cameras found', true, 3000);
                }
                
            } catch (error) {
                console.error('Error starting scanner:', error);
                showToast('⚠ Camera access failed', true, 3000);
            }
        }

        function toggleIosMode() {
            useIosOptimizations = !useIosOptimizations;
            const toggleText = document.getElementById('iosToggleText');
            toggleText.textContent = `iOS Mode: ${useIosOptimizations ? 'ON' : 'OFF'}`;
            
            // Restart scanner with new settings if currently running
            if (isScanning) {
                stopScanning().then(() => {
                    setTimeout(startScanning, 500);
                });
            }
            
            showToast(`iOS Mode ${useIosOptimizations ? 'enabled' : 'disabled'}`, false, 1500);
        }

        async function stopScanning() {
            if (html5QrcodeScanner && isScanning) {
                try {
                    await html5QrcodeScanner.stop();
                    html5QrcodeScanner.clear();
                } catch (error) {
                    console.error('Error stopping scanner:', error);
                }
            }
            
            isScanning = false;
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
        }

        // Auto-start scanning
        window.addEventListener('load', () => {
            // Set initial iOS toggle state
            const toggleText = document.getElementById('iosToggleText');
            if (toggleText) {
                toggleText.textContent = `iOS Mode: ${useIosOptimizations ? 'ON' : 'OFF'}`;
            }
            setTimeout(startScanning, 800);
        });

        // Handle page visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.hidden && isScanning) {
                stopScanning();
            } else if (!document.hidden && !isScanning) {
                setTimeout(startScanning, 500);
            }
        });

        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            if (isScanning) {
                stopScanning();
            }
        });

        // Prevent zoom on double tap
        let lastTouchEnd = 0;
        document.addEventListener('touchend', function (event) {
            const now = (new Date()).getTime();
            if (now - lastTouchEnd <= 300) {
                event.preventDefault();
            }
            lastTouchEnd = now;
        }, false);

        // Dynamic admin URL based on local network detection
        function getAdminUrl() {
            const host = window.location.host;
            const isLocalNetwork = host.startsWith('192.168.') || 
                                 host.startsWith('10.') || 
                                 host.startsWith('172.') || 
                                 host.startsWith('127.') || 
                                 host === 'localhost:5000';
            
            if (isLocalNetwork) {
                return `http://${host}/admin`;
            }
            
            return '/admin';
        }

        // Update admin button on page load
        window.addEventListener('load', () => {
            const adminBtn = document.querySelector('.admin-btn');
            if (adminBtn) {
                adminBtn.href = getAdminUrl();
            }
        });
    </script>
</body>
</html>
'''

@app.route('/admin-redirect')
def admin_redirect():
    """Redirect to correct admin URL based on request context"""
    correct_url = get_admin_url(request)
    return redirect(correct_url)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
