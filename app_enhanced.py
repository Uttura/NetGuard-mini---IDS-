"""
NETGUARD - Network Monitoring & IDS System
Flask-based web dashboard for home network intrusion detection

Features:
- Real-time network monitoring with Scapy
- Packet capture and analysis
- Threat detection with IDS rules
- WebSocket for live updates
- REST API endpoints

Requirements:
- Python 3.8+
- Root/admin privileges for packet capture
- Dependencies: flask, flask-cors, flask-socketio, scapy, psutil

Usage:
    sudo python3 app.py
    
Then open browser to: http://localhost:5000
"""

from flask import Flask, render_template, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import argparse
from datetime import datetime
from collections import deque
import psutil
import os
import sys

# Check for required dependencies
try:
    from packet_capture import PacketAnalyzer
except ImportError:
    print("❌ Error: packet_capture module not found!")
    print("   Make sure packet_capture.py is in the same directory")
    sys.exit(1)

try:
    import scapy
except ImportError:
    print("❌ Error: Scapy not installed!")
    print("   Install with: sudo pip3 install scapy --break-system-packages")
    sys.exit(1)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'netguard-secret-key-change-in-production'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global data stores
recent_logs = deque(maxlen=100)
recent_threats = deque(maxlen=50)
network_stats = {
    'packets_per_sec': 0,
    'active_connections': 0,
    'blocked_attempts': 0,
    'bandwidth': 0,
    'total_packets': 0
}

# IDS configuration - Adjusted thresholds for home network
IDS_RULES = {
    'port_scan': {
        'description': 'Multiple port access from single IP',
        'severity': 'HIGH',
        'threshold': 50,
        'time_window': 60
    },
    'brute_force': {
        'description': 'Multiple failed authentication attempts',
        'severity': 'HIGH',
        'threshold': 20,
        'time_window': 300
    },
    'suspicious_traffic': {
        'description': 'Unusual traffic pattern detected',
        'severity': 'MEDIUM',
        'threshold': 500,
        'time_window': 60
    },
    'ddos_attempt': {
        'description': 'High volume traffic from single source',
        'severity': 'HIGH',
        'threshold': 1000,
        'time_window': 10
    },
    'syn_flood': {
        'description': 'Potential SYN flood attack',
        'severity': 'HIGH',
        'threshold': 500,
        'time_window': 5
    }
}

# Tracking structures
port_access_tracker = {}


def get_network_interfaces():
    """Get network interface statistics using psutil"""
    try:
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    except Exception as e:
        print(f"Error getting network stats: {e}")
        return None


def get_active_connections():
    """Get current network connections count"""
    try:
        connections = psutil.net_connections(kind='inet')
        return len([c for c in connections if c.status == 'ESTABLISHED'])
    except Exception as e:
        return 0


def detect_threats(log_entry):
    """
    Detect threats based on log patterns
    This is called by the packet capture callback
    """
    source_ip = log_entry.get('source')
    dest_port = log_entry.get('port')
    
    if not source_ip or not dest_port:
        return None
    
    # Initialize tracking for this IP
    if source_ip not in port_access_tracker:
        port_access_tracker[source_ip] = {
            'ports': set(), 
            'timestamp': time.time()
        }
    
    port_access_tracker[source_ip]['ports'].add(dest_port)
    
    # Clean old entries (older than 60 seconds)
    current_time = time.time()
    for ip in list(port_access_tracker.keys()):
        if current_time - port_access_tracker[ip]['timestamp'] > 60:
            del port_access_tracker[ip]
    
    # Port scan detection
    ports_accessed = len(port_access_tracker[source_ip]['ports'])
    if ports_accessed >= IDS_RULES['port_scan']['threshold']:
        return {
            'type': 'Port Scan',
            'severity': IDS_RULES['port_scan']['severity'],
            'description': f"Port scan detected from {source_ip} - accessed {ports_accessed} different ports",
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


def packet_capture_callback(log_entry, threat):
    """
    Callback function for real packet capture
    Called by PacketAnalyzer when a packet is captured
    """
    # Add to logs
    recent_logs.append(log_entry)
    
    # Update total packet count
    network_stats['total_packets'] += 1
    
    # Emit to connected clients
    socketio.emit('new_log', log_entry)
    
    # Handle threats
    if threat:
        threat['id'] = int(time.time() * 1000000)
        threat['timestamp'] = datetime.now().isoformat()
        recent_threats.append(threat)
        socketio.emit('new_threat', threat)
        print(f"⚠️  THREAT DETECTED: {threat['type']} from {threat.get('source', 'unknown')}")


def monitor_network_stats():
    """
    Monitor and update network statistics
    Runs in background thread
    """
    prev_stats = get_network_interfaces()
    
    while True:
        try:
            # Get current network stats
            current_stats = get_network_interfaces()
            
            if prev_stats and current_stats:
                # Calculate differences
                packets_diff = current_stats['packets_recv'] - prev_stats['packets_recv']
                bytes_diff = current_stats['bytes_recv'] - prev_stats['bytes_recv']
                
                # Update global stats
                network_stats['packets_per_sec'] = max(0, packets_diff)
                network_stats['bandwidth'] = round(bytes_diff / 1024 / 1024, 2)  # MB/s
                prev_stats = current_stats
            
            # Update connection count
            network_stats['active_connections'] = get_active_connections()
            network_stats['blocked_attempts'] = len(recent_threats)
            
            # Emit stats update to clients
            socketio.emit('stats_update', network_stats)
            
            # Sleep for 2 seconds
            time.sleep(2)
            
        except Exception as e:
            print(f"Error updating stats: {e}")
            time.sleep(5)


def start_packet_capture(interface='any'):
    """
    Start real packet capture
    Runs in background thread
    """
    print(f"🔍 Starting packet capture on interface: {interface}")
    print("   This may take a moment to initialize...")
    
    try:
        analyzer = PacketAnalyzer(callback=packet_capture_callback)
        analyzer.start_capture(interface=interface)
    except PermissionError:
        print("❌ Permission denied! Packet capture requires root privileges.")
        print("   Please run with: sudo python3 app.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Packet capture error: {e}")
        sys.exit(1)


# ==================== Flask Routes ====================

@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('index.html')


@app.route('/api/logs')
def get_logs():
    """Get recent network logs"""
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
        'mode': 'real_capture',
        'total_logs': len(recent_logs),
        'total_threats': len(recent_threats),
        'uptime': time.time()  # Could track actual uptime if needed
    })


@app.route('/api/rules')
def get_rules():
    """Get IDS rules configuration"""
    return jsonify(IDS_RULES)


# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    client_id = threading.current_thread().name
    print(f'✓ Client connected: {client_id}')
    
    emit('connection_response', {
        'status': 'connected',
        'mode': 'real_capture',
        'message': 'Connected to NetGuard'
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('✗ Client disconnected')


@socketio.on('request_stats')
def handle_stats_request():
    """Handle request for current stats"""
    emit('stats_update', network_stats)


@socketio.on('request_logs')
def handle_logs_request():
    """Handle request for recent logs"""
    emit('logs_update', list(recent_logs))


# ==================== Main Entry Point ====================

def main():
    """Main application entry point"""
    
    # Check if running as root
    if os.geteuid() != 0:
        print("=" * 60)
        print("❌ ERROR: NetGuard requires root privileges!")
        print("=" * 60)
        print("\nPacket capture requires root access to network interfaces.")
        print("Please run with:\n")
        print("    sudo python3 app.py")
        print("\n" + "=" * 60)
        sys.exit(1)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='NETGUARD - Network Monitoring & IDS System'
    )
    parser.add_argument(
        '--port', 
        type=int, 
        default=5000,
        help='Port to run the web server on (default: 5000)'
    )
    parser.add_argument(
        '--host', 
        type=str, 
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--interface',
        type=str,
        default='any',
        help='Network interface to monitor (default: any)'
    )
    
    args = parser.parse_args()
    
    # Print startup banner
    print("\n" + "=" * 60)
    print("🛡️  NETGUARD - Network Monitoring & IDS System")
    print("=" * 60)
    print(f"\n📡 Mode: REAL PACKET CAPTURE")
    print(f"🔌 Interface: {args.interface}")
    print(f"🌐 Web Server: http://{args.host}:{args.port}")
    print(f"📊 Dashboard: http://localhost:{args.port}")
    print("\n⚠️  Running with root privileges for packet capture")
    print("=" * 60)
    print("\n🚀 Starting NetGuard...\n")
    
    # Start packet capture in background thread
    capture_thread = threading.Thread(
        target=start_packet_capture,
        args=(args.interface,),
        daemon=True
    )
    capture_thread.start()
    
    # Start stats monitoring in background thread
    stats_thread = threading.Thread(
        target=monitor_network_stats,
        daemon=True
    )
    stats_thread.start()
    
    # Give threads time to initialize
    time.sleep(1)
    
    print("✅ Packet capture started")
    print("✅ Stats monitoring started")
    print(f"✅ Web server starting on port {args.port}...")
    print("\n" + "=" * 60)
    print("Press Ctrl+C to stop NetGuard")
    print("=" * 60 + "\n")
    
    # Run Flask app with SocketIO
    try:
        socketio.run(
            app, 
            debug=False,
            host=args.host, 
            port=args.port,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n\n" + "=" * 60)
        print("👋 Shutting down NetGuard...")
        print("=" * 60)
        print("\nThank you for using NetGuard!\n")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()