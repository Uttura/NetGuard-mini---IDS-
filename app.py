from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import scapy.all as scapy
from scapy.layers import http
import threading
import time
from datetime import datetime
from collections import defaultdict, deque
import psutil
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Data storage
network_logs = deque(maxlen=100)
threat_alerts = deque(maxlen=50)
connection_tracker = defaultdict(int)
packet_stats = {
    'packets_per_sec': 0,
    'total_packets': 0,
    'bandwidth': 0,
    'blocked_attempts': 0,
    'active_connections': 0
}

# Threat detection patterns
SUSPICIOUS_PORTS = [23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379]
SCAN_THRESHOLD = 5  # Number of different ports from same IP to trigger scan alert
port_scan_tracker = defaultdict(set)

# Track packets for rate calculation
packet_counter = {'count': 0, 'last_reset': time.time()}

def detect_threats(packet):
    """Analyze packets for potential security threats"""
    threats = []
    
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # TCP layer analysis
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            src_port = packet[scapy.TCP].sport
            flags = packet[scapy.TCP].flags
            
            # Port scan detection
            port_scan_tracker[src_ip].add(dst_port)
            if len(port_scan_tracker[src_ip]) > SCAN_THRESHOLD:
                threats.append({
                    'type': 'Port Scan',
                    'severity': 'HIGH',
                    'source': src_ip,
                    'description': f'Potential port scan detected from {src_ip} - {len(port_scan_tracker[src_ip])} ports probed'
                })
                port_scan_tracker[src_ip].clear()
            
            # SYN flood detection
            if flags == 'S':  # SYN flag
                if connection_tracker[src_ip] > 20:
                    threats.append({
                        'type': 'SYN Flood',
                        'severity': 'HIGH',
                        'source': src_ip,
                        'description': f'Possible SYN flood attack from {src_ip}'
                    })
            
            # Suspicious port access
            if dst_port in SUSPICIOUS_PORTS:
                threats.append({
                    'type': 'Suspicious Port Access',
                    'severity': 'MEDIUM',
                    'source': src_ip,
                    'description': f'Access attempt to sensitive port {dst_port} from {src_ip}'
                })
        
        # HTTP layer analysis
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet[http.HTTPRequest]
            
            # SQL injection detection
            if http_layer.Method == b'GET' and http_layer.Path:
                path = http_layer.Path.decode('utf-8', errors='ignore')
                sql_patterns = ['union', 'select', 'insert', 'drop', 'delete', '--', ';']
                if any(pattern in path.lower() for pattern in sql_patterns):
                    threats.append({
                        'type': 'SQL Injection Attempt',
                        'severity': 'HIGH',
                        'source': src_ip,
                        'description': f'Potential SQL injection in HTTP request from {src_ip}'
                    })
    
    return threats

def packet_callback(packet):
    """Process each captured packet"""
    global packet_counter, packet_stats
    
    try:
        packet_counter['count'] += 1
        
        # Calculate packets per second
        current_time = time.time()
        if current_time - packet_counter['last_reset'] >= 1:
            packet_stats['packets_per_sec'] = packet_counter['count']
            packet_counter['count'] = 0
            packet_counter['last_reset'] = current_time
        
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = 'IP'
            src_port = dst_port = 'N/A'
            
            # Extract protocol and ports
            if packet.haslayer(scapy.TCP):
                protocol = 'TCP'
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                connection_tracker[src_ip] += 1
            elif packet.haslayer(scapy.UDP):
                protocol = 'UDP'
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
            elif packet.haslayer(scapy.ICMP):
                protocol = 'ICMP'
            
            # Detect threats
            threats = detect_threats(packet)
            
            # Determine log type
            log_type = 'ALERT' if threats else 'NORMAL'
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                log_type = 'INFO'
            
            # Create log entry
            log_entry = {
                'id': int(time.time() * 1000000),
                'timestamp': datetime.now().isoformat(),
                'type': log_type,
                'source': src_ip,
                'destination': dst_ip,
                'protocol': protocol,
                'port': dst_port if dst_port != 'N/A' else src_port,
                'message': 'Connection established' if protocol == 'TCP' else 'Packet received',
                'size': len(packet)
            }
            
            network_logs.append(log_entry)
            
            # Add threats to alert list
            for threat in threats:
                threat['id'] = int(time.time() * 1000000)
                threat['timestamp'] = datetime.now().isoformat()
                threat_alerts.append(threat)
                packet_stats['blocked_attempts'] += 1
            
            # Emit to connected clients
            socketio.emit('new_log', log_entry)
            for threat in threats:
                socketio.emit('new_threat', threat)
    
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface='eth0'):
    """Start packet capture on specified interface"""
    try:
        print(f"Starting packet capture on interface: {interface}")
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print("Permission denied. Please run with sudo/administrator privileges.")
    except Exception as e:
        print(f"Error starting packet capture: {e}")
        print("Falling back to simulation mode...")
        simulate_traffic()

def simulate_traffic():
    """Simulate network traffic for demo purposes"""
    import random
    
    sources = ['192.168.1.24', '192.168.1.45', '192.168.1.102', '10.0.0.5', '172.16.0.33']
    destinations = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '142.250.185.46', '13.107.42.14']
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']
    ports = [80, 443, 22, 53, 8080, 3306, 5432, 23, 445]
    
    messages = [
        'Connection established',
        'Packet received',
        'Data transfer in progress',
        'DNS query resolved',
        'SSL handshake completed',
        'Authentication successful',
        'File transfer complete'
    ]
    
    threat_messages = [
        'Unusual traffic pattern detected',
        'Port scan attempt blocked',
        'Multiple failed authentication attempts',
        'Potential intrusion attempt',
        'Suspicious payload detected'
    ]
    
    while True:
        time.sleep(random.uniform(0.5, 2))
        
        # Update packet stats
        packet_stats['packets_per_sec'] = random.randint(1000, 5000)
        packet_stats['total_packets'] += random.randint(10, 50)
        packet_stats['bandwidth'] = round(random.uniform(5, 100), 2)
        packet_stats['active_connections'] = len(connection_tracker)
        
        # Generate log entry
        is_threat = random.random() < 0.15  # 15% chance of threat
        
        log_entry = {
            'id': int(time.time() * 1000000),
            'timestamp': datetime.now().isoformat(),
            'type': 'ALERT' if is_threat else random.choice(['NORMAL', 'INFO', 'WARNING']),
            'source': random.choice(sources),
            'destination': random.choice(destinations),
            'protocol': random.choice(protocols),
            'port': random.choice(ports),
            'message': random.choice(threat_messages if is_threat else messages),
            'size': random.randint(64, 1500)
        }
        
        network_logs.append(log_entry)
        socketio.emit('new_log', log_entry)
        
        # Generate threat alert
        if is_threat:
            threat = {
                'id': int(time.time() * 1000000),
                'timestamp': datetime.now().isoformat(),
                'severity': random.choice(['HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'MEDIUM']),
                'type': random.choice(['Port Scan', 'Brute Force', 'DDoS Attempt', 'Suspicious Traffic', 'SQL Injection']),
                'source': log_entry['source'],
                'description': log_entry['message']
            }
            threat_alerts.append(threat)
            packet_stats['blocked_attempts'] += 1
            socketio.emit('new_threat', threat)

def update_network_stats():
    """Periodically update network statistics"""
    while True:
        time.sleep(2)
        
        # Get network interface statistics
        net_io = psutil.net_io_counters()
        packet_stats['active_connections'] = len(psutil.net_connections())
        
        # Emit stats update
        socketio.emit('stats_update', packet_stats)

@app.route('/')
def index():
    """Serve the dashboard"""
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    """Get recent network logs"""
    return jsonify(list(network_logs))

@app.route('/api/threats')
def get_threats():
    """Get recent threats"""
    return jsonify(list(threat_alerts))

@app.route('/api/stats')
def get_stats():
    """Get current network statistics"""
    return jsonify(packet_stats)

@app.route('/api/connections')
def get_connections():
    """Get active connections"""
    try:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                    'status': conn.status,
                    'pid': conn.pid
                })
        return jsonify(connections[:50])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('initial_data', {
        'logs': list(network_logs),
        'threats': list(threat_alerts),
        'stats': packet_stats
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

if __name__ == '__main__':
    # Start network monitoring in background thread
    # For real packet capture, uncomment and specify your network interface:
    # monitor_thread = threading.Thread(target=start_sniffing, args=('eth0',), daemon=True)
    
    # For simulation mode (no root/admin required):
    monitor_thread = threading.Thread(target=simulate_traffic, daemon=True)
    monitor_thread.start()
    
    # Start stats updater
    stats_thread = threading.Thread(target=update_network_stats, daemon=True)
    stats_thread.start()
    
    print("=" * 60)
    print("Network Monitoring Dashboard Starting...")
    print("=" * 60)
    print("Access the dashboard at: http://localhost:5000")
    print("=" * 60)
    
    # Run Flask app
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
