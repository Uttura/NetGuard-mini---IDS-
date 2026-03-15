"""
NETGUARD - Network Monitoring & IDS System
Flask-based web dashboard for home network intrusion detection

Features:
- Real-time network monitoring
- Packet capture and analysis
- Threat detection with IDS rules
- WebSocket for live updates
- REST API endpoints

Requirements:
- For mock data: Works out of the box
- For real packet capture: Requires root/admin privileges and scapy

Usage:
    # Mock data mode (no special privileges required):
    python app.py
    
    # Real packet capture mode (requires root):
    sudo python app.py --capture
"""

from flask import Flask, render_template, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import random
import argparse
from datetime import datetime
from collections import deque
import psutil

# Try to import packet capture module
CAPTURE_AVAILABLE = False
try:
    from packet_capture import PacketAnalyzer
    CAPTURE_AVAILABLE = True
except ImportError:
    print("⚠️  Scapy not installed. Running in mock data mode.")
    print("   To enable real packet capture: pip install scapy")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global data stores
recent_logs = deque(maxlen=100)
recent_threats = deque(maxlen=50)
network_stats = {
    'packets_per_sec': 0,
    'active_connections': 0,
    'blocked_attempts': 0,
    'bandwidth': 0
}

# IDS configuration
IDS_RULES = {
    'port_scan': {
        'description': 'Multiple port access from single IP',
        'severity': 'HIGH',
        'threshold': 50,  # Increased from 10
        'time_window': 60  # Within 60 seconds
    },
    'brute_force': {
        'description': 'Multiple failed authentication attempts',
        'severity': 'HIGH',
        'threshold': 20,  # Increased from 5
        'time_window': 300  # Within 5 minutes
    },
    'suspicious_traffic': {
        'description': 'Unusual traffic pattern detected',
        'severity': 'MEDIUM',
        'threshold': 500,  # Increased from 50
        'time_window': 60
    },
    'ddos_attempt': {
        'description': 'High volume traffic from single source',
        'severity': 'HIGH',
        'threshold': 1000,  # Increased from 100 - real DDoS is thousands per second
        'time_window': 10  # Within 10 seconds
    },
    'syn_flood': {
        'description': 'Potential SYN flood attack',
        'severity': 'HIGH',
        'threshold': 500,  # NEW - separate SYN flood detection
        'time_window': 5
    }
}

# Tracking structures
connection_tracker = {}
port_access_tracker = {}
use_real_capture = False


def get_network_interfaces():
    """Get network interface statistics"""
    try:
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    except:
        return None


def get_active_connections():
    """Get current network connections count"""
    try:
        connections = psutil.net_connections(kind='inet')
        return len([c for c in connections if c.status == 'ESTABLISHED'])
    except:
        return 0


def detect_threats(log_entry):
    """Detect threats based on log patterns"""
    source_ip = log_entry.get('source')
    dest_port = log_entry.get('port')
    
    if source_ip not in port_access_tracker:
        port_access_tracker[source_ip] = {'ports': set(), 'timestamp': time.time()}
    
    port_access_tracker[source_ip]['ports'].add(dest_port)
    
    # Clean old entries
    current_time = time.time()
    for ip in list(port_access_tracker.keys()):
        if current_time - port_access_tracker[ip]['timestamp'] > 60:
            del port_access_tracker[ip]
    
    # Port scan detection
    if len(port_access_tracker[source_ip]['ports']) >= IDS_RULES['port_scan']['threshold']:
        return {
            'type': 'Port Scan',
            'severity': IDS_RULES['port_scan']['severity'],
            'description': f"Detected port scan from {source_ip} - accessed {len(port_access_tracker[source_ip]['ports'])} different ports",
            'source': source_ip
        }
    
    # Suspicious port detection
    suspicious_ports = [23, 3389, 4444, 1234, 31337, 12345, 5900, 6667]
    if dest_port in suspicious_ports:
        return {
            'type': 'Suspicious Port Access',
            'severity': 'MEDIUM',
            'description': f"Access attempt to suspicious port {dest_port}",
            'source': source_ip
        }
    
    return None


def generate_mock_traffic():
    """Generate realistic mock network traffic"""
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
    log_types = ['NORMAL', 'INFO', 'WARNING', 'ALERT']
    
    internal_ips = [
        f"192.168.1.{random.randint(10, 254)}",
        f"192.168.0.{random.randint(10, 254)}",
        f"10.0.0.{random.randint(10, 254)}",
        f"172.16.0.{random.randint(10, 254)}"
    ]
    
    external_ips = [
        '8.8.8.8', '8.8.4.4',  # Google DNS
        '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
        '142.250.185.46',       # Google
        '151.101.1.140',        # Reddit
        '13.107.42.14',         # Microsoft
        f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    ]
    
    common_ports = [80, 443, 53, 22, 21, 25, 110, 143, 3306, 5432, 8080, 8443, 9000]
    suspicious_ports = [23, 3389, 4444, 1234, 31337, 5900, 6667]
    
    normal_messages = [
        'Connection established',
        'Packet received',
        'Data transfer in progress',
        'DNS query resolved',
        'SSL handshake completed',
        'HTTP request processed',
        'Authentication successful',
        'Session initiated',
        'Keep-alive packet',
        'Connection closed gracefully',
        'ACK received',
        'Data acknowledged'
    ]
    
    alert_messages = [
        'Unusual traffic pattern detected',
        'Multiple connection attempts',
        'Suspicious payload detected',
        'Authentication failed - invalid credentials',
        'Potential intrusion attempt blocked',
        'Firewall rule triggered',
        'Rate limit exceeded',
        'Unknown protocol detected',
        'Malformed packet detected',
        'Connection attempt from blacklisted IP'
    ]
    
    # 15% chance of suspicious activity
    is_suspicious = random.random() < 0.15
    
    log_entry = {
        'id': int(time.time() * 1000000),
        'timestamp': datetime.now().isoformat(),
        'type': 'ALERT' if is_suspicious else random.choice(log_types),
        'source': random.choice(internal_ips),
        'destination': random.choice(external_ips),
        'protocol': random.choice(protocols),
        'port': random.choice(suspicious_ports if is_suspicious else common_ports),
        'message': random.choice(alert_messages if is_suspicious else normal_messages),
        'bytes': random.randint(64, 65536)
    }
    
    return log_entry


def packet_capture_callback(log_entry, threat):
    """Callback for real packet capture"""
    recent_logs.append(log_entry)
    socketio.emit('new_log', log_entry)
    
    if threat:
        threat['id'] = int(time.time() * 1000000)
        threat['timestamp'] = datetime.now().isoformat()
        recent_threats.append(threat)
        socketio.emit('new_threat', threat)


def monitor_network_mock():
    """Mock network monitoring loop"""
    prev_stats = get_network_interfaces()
    
    while True:
        try:
            # Generate mock traffic
            log_entry = generate_mock_traffic()
            recent_logs.append(log_entry)
            
            # Detect threats
            threat = detect_threats(log_entry)
            if threat:
                threat['id'] = int(time.time() * 1000000)
                threat['timestamp'] = datetime.now().isoformat()
                recent_threats.append(threat)
                socketio.emit('new_threat', threat)
            
            # Emit new log
            socketio.emit('new_log', log_entry)
            
            # Update statistics
            current_stats = get_network_interfaces()
            if prev_stats and current_stats:
                packets_diff = (current_stats['packets_recv'] - prev_stats['packets_recv'])
                bytes_diff = (current_stats['bytes_recv'] - prev_stats['bytes_recv'])
                
                network_stats['packets_per_sec'] = max(0, packets_diff)
                network_stats['bandwidth'] = round(bytes_diff / 1024 / 1024, 2)
                prev_stats = current_stats
            else:
                # Fallback to mock stats
                network_stats['packets_per_sec'] = random.randint(1000, 5000)
                network_stats['bandwidth'] = round(random.random() * 100, 2)
            
            network_stats['active_connections'] = get_active_connections()
            network_stats['blocked_attempts'] = len(recent_threats)
            
            # Emit stats update
            socketio.emit('stats_update', network_stats)
            
            time.sleep(2)
            
        except Exception as e:
            print(f"Error in monitoring loop: {e}")
            time.sleep(5)


def monitor_network_real():
    """Real network monitoring with packet capture"""
    print("🔍 Starting real packet capture...")
    print("   This may take a moment to initialize...")
    
    analyzer = PacketAnalyzer(callback=packet_capture_callback)
    
    # Start packet capture in a separate thread
    def capture_loop():
        try:
            analyzer.start_capture()
        except Exception as e:
            print(f"Packet capture error: {e}")
            print("Falling back to mock data mode...")
            global use_real_capture
            use_real_capture = False
            monitor_network_mock()
    
    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()
    
    # Update stats in main thread
    prev_stats = get_network_interfaces()
    while True:
        try:
            current_stats = get_network_interfaces()
            if prev_stats and current_stats:
                packets_diff = (current_stats['packets_recv'] - prev_stats['packets_recv'])
                bytes_diff = (current_stats['bytes_recv'] - prev_stats['bytes_recv'])
                
                network_stats['packets_per_sec'] = max(0, packets_diff)
                network_stats['bandwidth'] = round(bytes_diff / 1024 / 1024, 2)
                prev_stats = current_stats
            
            network_stats['active_connections'] = get_active_connections()
            network_stats['blocked_attempts'] = len(recent_threats)
            
            socketio.emit('stats_update', network_stats)
            time.sleep(2)
            
        except Exception as e:
            print(f"Error updating stats: {e}")
            time.sleep(5)


@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('index.html')


@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    return jsonify(list(recent_logs))


@app.route('/api/threats')
def get_threats():
    """Get recent threats"""
    return jsonify(list(recent_threats))


@app.route('/api/stats')
def get_stats():
    """Get current network statistics"""
    return jsonify(network_stats)


@app.route('/api/status')
def get_status():
    """Get system status"""
    return jsonify({
        'mode': 'real_capture' if use_real_capture else 'mock_data',
        'capture_available': CAPTURE_AVAILABLE,
        'total_logs': len(recent_logs),
        'total_threats': len(recent_threats)
    })


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f'✓ Client connected from {threading.current_thread().name}')
    emit('connection_response', {
        'status': 'connected',
        'mode': 'real_capture' if use_real_capture else 'mock_data'
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('✗ Client disconnected')


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='NETGUARD Network Monitoring System')
    parser.add_argument('--capture', action='store_true', 
                       help='Enable real packet capture (requires root/admin)')
    parser.add_argument('--port', type=int, default=5000,
                       help='Port to run the web server on (default: 5000)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                       help='Host to bind to (default: 0.0.0.0)')
    
    args = parser.parse_args()
    
    global use_real_capture
    use_real_capture = args.capture and CAPTURE_AVAILABLE
    
    print("=" * 60)
    print("🛡️  NETGUARD - Network Monitoring & IDS System")
    print("=" * 60)
    
    if use_real_capture:
        print("Mode: REAL PACKET CAPTURE")
        print("⚠️  Running with packet capture requires root/admin privileges")
        monitor_func = monitor_network_real
    else:
        print("Mode: MOCK DATA (Demo)")
        if args.capture and not CAPTURE_AVAILABLE:
            print("⚠️  Real capture requested but Scapy not available")
            print("   Install with: pip install scapy")
        monitor_func = monitor_network_mock
    
    print(f"\nStarting Flask server on http://{args.host}:{args.port}")
    print(f"Dashboard: http://localhost:{args.port}")
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server\n")
    
    # Start network monitoring in background thread
    monitor_thread = threading.Thread(target=monitor_func, daemon=True)
    monitor_thread.start()
    
    # Run Flask app with SocketIO
    try:
        socketio.run(
            app, 
            debug=False,  # Set to False for production
            host=args.host, 
            port=args.port,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down NETGUARD...")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == '__main__':
    main()
