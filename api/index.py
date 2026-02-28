from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime
import json
import random
import os
import tempfile

app = Flask(__name__, 
            static_folder='../public', 
            static_url_path='')
CORS(app)

# Use /tmp for database in serverless environment
tmp_dir = tempfile.gettempdir()
db_path = os.path.join(tmp_dir, 'scanner.db')

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vercel-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 1,
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

db = SQLAlchemy(app)

# Database Models
class ScanJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255))
    scan_type = db.Column(db.String(50))
    port_range = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    results = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), unique=True)
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    solution = db.Column(db.Text)

# Create tables
with app.app_context():
    db.create_all()
    
    # Seed vulnerabilities if empty
    if Vulnerability.query.count() == 0:
        vulns = [
            Vulnerability(cve_id='CVE-2021-1234', port=21, service='FTP', severity='CRITICAL',
                         description='vsFTPd 2.3.4 backdoor vulnerability',
                         solution='Update to vsFTPd 3.0.0 or later'),
            Vulnerability(cve_id='CVE-2020-1234', port=22, service='SSH', severity='HIGH',
                         description='OpenSSH authentication bypass',
                         solution='Update OpenSSH to version 8.3 or later'),
            Vulnerability(cve_id='CVE-2021-5678', port=80, service='HTTP', severity='MEDIUM',
                         description='Apache information disclosure',
                         solution='Update Apache to version 2.4.47')
        ]
        db.session.add_all(vulns)
        db.session.commit()

# Serve static files
@app.route('/')
def serve_index():
    return send_from_directory('../public', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('../public', path)

# API Routes
@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.json
        target = data.get('target', '127.0.0.1')
        scan_type = data.get('scan_type', 'tcp')
        port_start = int(data.get('port_start', 1))
        port_end = int(data.get('port_end', 1000))
        
        scan_job = ScanJob(
            target=target,
            scan_type=scan_type,
            port_range=f"{port_start}-{port_end}",
            status='scanning'
        )
        db.session.add(scan_job)
        db.session.commit()
        
        results = simulate_scan(target, port_start, port_end, scan_type)
        
        scan_job.status = 'completed'
        scan_job.results = json.dumps(results)
        db.session.commit()
        
        return jsonify({'success': True, 'job_id': scan_job.id, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/<int:job_id>', methods=['GET'])
def get_scan_results(job_id):
    scan_job = ScanJob.query.get_or_404(job_id)
    return jsonify({
        'target': scan_job.target,
        'status': scan_job.status,
        'results': json.loads(scan_job.results) if scan_job.results else []
    })

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    vulns = Vulnerability.query.all()
    return jsonify([{
        'id': v.id,
        'cve_id': v.cve_id,
        'port': v.port,
        'service': v.service,
        'severity': v.severity,
        'description': v.description,
        'solution': v.solution
    } for v in vulns])

def simulate_scan(target, port_start, port_end, scan_type):
    results = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    for port in range(port_start, port_end + 1, 10):
        if port in common_ports:
            status = random.choices(['open', 'filtered', 'closed'], weights=[0.7, 0.2, 0.1])[0]
        else:
            status = random.choices(['closed', 'filtered', 'open'], weights=[0.7, 0.25, 0.05])[0]
        
        if status == 'open':
            service = get_service_for_port(port)
            vulns = Vulnerability.query.filter_by(port=port).all()
            
            results.append({
                'port': port,
                'state': status,
                'service': service,
                'version': f"{service} {random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}",
                'cves': [{'id': v.cve_id, 'severity': v.severity} for v in vulns]
            })
    
    return results

def get_service_for_port(port):
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP-Alt'
    }
    return services.get(port, f'unknown-{port}')

# This is important for Vercel
app = app
