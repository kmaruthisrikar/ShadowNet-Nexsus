"""
ShadowNet Nexus - Backend API Server
Provides REST API for the dashboard
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Import ShadowNet modules
from core import (
    NetworkMonitor,
    FileIntegrityMonitor,
    AlertManager,
    ResponseEngine,
    SIEMIntegration
)
from core.data_manager import data_manager
from utils import os_detector

app = Flask(__name__)
CORS(app)  # Enable CORS for React dashboard

# Initialize modules
network_monitor = NetworkMonitor()
file_monitor = FileIntegrityMonitor()
alert_manager = AlertManager()
response_engine = ResponseEngine(require_confirmation=True)
siem = SIEMIntegration()


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'version': '3.0.0',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_data():
    """Get complete dashboard data from centralized DataManager"""
    
    # Get shared state
    state = data_manager.get_dashboard_data()
    
    # Update ephemeral system stats
    network_stats = network_monitor.get_statistics()
    file_stats = file_monitor.get_statistics()
    alert_stats = alert_manager.get_statistics()
    response_stats = response_engine.get_statistics()
    siem_stats = siem.get_statistics()
    
    return jsonify({
        'stats': state['stats'],
        'threats': state['threats'][:10],  # Last 10 detected threats
        'network': {
            'active_connections': len(network_monitor.get_active_connections()),
            'suspicious': network_stats['suspicious_connections'],
            'blocked': network_stats.get('blocked_connections', 0)
        },
        'files': {
            'monitored': file_stats['total_files_monitored'],
            'changes': file_stats['changes_detected'],
            'ransomware_indicators': file_stats['ransomware_indicators']
        },
        'alerts': {
            'total': alert_stats['total_alerts_sent'],
            'by_severity': alert_stats['alerts_by_severity']
        },
        'response': {
            'total': response_stats['total_responses'],
            'success_rate': response_stats['success_rate']
        },
        'siem': {
            'events_sent': siem_stats['total_events_sent'],
            'platforms': siem_stats['configured_platforms']
        }
    })


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get recent threats from DataManager"""
    state = data_manager.get_dashboard_data()
    return jsonify({
        'threats': state['threats'][:20],
        'total': len(state['threats'])
    })


@app.route('/api/network', methods=['GET'])
def get_network_data():
    """Get network monitoring data"""
    connections = network_monitor.get_active_connections()
    stats = network_monitor.get_statistics()
    
    return jsonify({
        'connections': connections[:50],  # Limit to 50
        'stats': stats
    })


@app.route('/api/files', methods=['GET'])
def get_file_data():
    """Get file integrity data"""
    stats = file_monitor.get_statistics()
    
    return jsonify({
        'stats': stats
    })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alert history"""
    stats = alert_manager.get_statistics()
    
    return jsonify({
        'stats': stats
    })


@app.route('/api/response', methods=['GET'])
def get_response_data():
    """Get response engine data"""
    stats = response_engine.get_statistics()
    recent = response_engine.get_recent_responses(10)
    
    return jsonify({
        'stats': stats,
        'recent_responses': recent
    })


@app.route('/api/siem', methods=['GET'])
def get_siem_data():
    """Get SIEM integration data"""
    stats = siem.get_statistics()
    
    return jsonify({
        'stats': stats
    })


@app.route('/api/system', methods=['GET'])
def get_system_info():
    """Get system information"""
    state = data_manager.get_dashboard_data()
    return jsonify({
        'os': os_detector.os_type,
        'is_admin': os_detector.is_admin,
        'hostname': os_detector.hostname,
        'version': '3.0.0',
        'uptime': (datetime.now() - datetime.fromisoformat(state['stats']['start_time'])).total_seconds()
    })


@app.route('/api/simulate-threat', methods=['POST'])
def simulate_threat():
    """Simulate a threat for testing (demo mode) and persist it"""
    threat_type = request.json.get('type', 'suspicious_process')
    
    threat = {
        'id': f"SIM-{datetime.now().strftime('%H%M%S')}",
        'type': threat_type,
        'title': f'Simulated {threat_type.replace("_", " ").title()}',
        'severity': 'high',
        'description': 'This is a simulated threat for testing persistent data flow',
        'timestamp': datetime.now().isoformat(),
        'source': os_detector.hostname
    }
    
    data_manager.add_threat(threat)
    
    return jsonify({
        'success': True,
        'threat': threat
    })


@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all available forensic reports"""
    reports_dir = "./evidence/reports"
    reports_list = []
    
    if os.path.exists(reports_dir):
        # List all .md files, sorted by newest first
        files = [f for f in os.listdir(reports_dir) if f.endswith('.md')]
        files.sort(key=lambda x: os.path.getmtime(os.path.join(reports_dir, x)), reverse=True)
        
        for f in files:
            path = os.path.join(reports_dir, f)
            stats = os.stat(path)
            reports_list.append({
                'filename': f,
                'size_bytes': stats.st_size,
                'created': datetime.fromtimestamp(stats.st_ctime).isoformat()
            })
            
    return jsonify({
        'reports': reports_list,
        'count': len(reports_list)
    })


@app.route('/api/view-report', methods=['GET'])
def view_report():
    """Get content of a specific report"""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'Filename required'}), 400
        
    report_path = os.path.join("./evidence/reports", filename)
    
    # Security check: prevent directory traversal
    if ".." in filename or not os.path.abspath(report_path).startswith(os.path.abspath("./evidence/reports")):
        return jsonify({'error': 'Invalid filename'}), 403
        
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404
        
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({
            'filename': filename,
            'content': content
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/test/execute', methods=['POST'])
def execute_test():
    """Execute a real test scenario on the host"""
    test_type = request.json.get('type')
    
    import subprocess
    cmd = []
    
    if test_type == 'ransomware_sim':
        cmd = ["vssadmin", "list", "shadows"]
    elif test_type == 'network_sim':
        cmd = ["ping", "-n", "1", "8.8.8.8"]
    elif test_type == 'obfuscation_sim':
        cmd = ["powershell", "-Enc", "V3JpdGUtSG9zdCAiU2hhZG93TmV0IFRlc3Qi"]
    else:
        return jsonify({'error': 'Invalid test type'}), 400
        
    try:
        subprocess.Popen(cmd, shell=True)
        return jsonify({'success': True, 'message': f'Started test: {test_type}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- CONFIGURATION MANAGEMENT ---
@app.route('/api/config', methods=['GET'])
def get_config():
    """Read the current configuration file"""
    try:
        with open('config/config.yaml', 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update the configuration file"""
    try:
        new_content = request.json.get('content')
        if not new_content:
            return jsonify({'error': 'No content provided'}), 400
            
        # Basic validation could go here (check if valid YAML)
        import yaml
        try:
            yaml.safe_load(new_content)
        except yaml.YAMLError as e:
            return jsonify({'error': f'Invalid YAML: {str(e)}'}), 400
            
        with open('config/config.yaml', 'w') as f:
            f.write(new_content)
            
        return jsonify({'success': True, 'message': 'Configuration updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- EVIDENCE / ARTIFACTS ---
@app.route('/api/artifacts', methods=['GET'])
def list_artifacts():
    """List raw forensic artifacts (files)"""
    artifacts_dir = "./evidence/artifacts"
    artifacts_list = []
    
    if os.path.exists(artifacts_dir):
        # Recursively or flat list? Flat list of recent artifacts
        # We look inside incident subfolders or just the root artifacts structure
        # Implementation depends on EvidenceVault structure.
        # EvidenceVault puts them in artifacts/INCIDENT_ID/
        
        for incident_id in os.listdir(artifacts_dir):
            incident_path = os.path.join(artifacts_dir, incident_id)
            if os.path.isdir(incident_path):
                for f in os.listdir(incident_path):
                    path = os.path.join(incident_path, f)
                    stats = os.stat(path)
                    artifacts_list.append({
                        'incident_id': incident_id,
                        'filename': f,
                        'size_bytes': stats.st_size,
                        'created': datetime.fromtimestamp(stats.st_ctime).isoformat()
                    })
    
    # Sort by newest
    artifacts_list.sort(key=lambda x: x['created'], reverse=True)
    return jsonify({'artifacts': artifacts_list})


if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  SHADOWNET NEXUS v3.0 - API SERVER")
    print("=" * 70)
    print()
    print("✅ API Server starting...")
    print("✅ Dashboard API: http://10.97.239.162:8000")
    print("✅ Health Check: http://10.97.239.162:8000/api/health")
    print()
    print("Available Endpoints:")
    print("  GET  /api/health          - Health check")
    print("  GET  /api/dashboard       - Complete dashboard data")
    print("  GET  /api/reports         - List forensic reports")
    print("  GET  /api/view-report     - Read specific report")
    print("  GET  /api/threats         - Recent threats")
    print("  GET  /api/config          - Read/Write Config (NEW)")
    print("  GET  /api/artifacts       - List Evidence (NEW)")
    print("  POST /api/test/execute    - Run REAL test on host")
    print()
    print("=" * 70)
    print()
    
    app.run(host='0.0.0.0', port=8000, debug=True)
