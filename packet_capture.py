"""
Enhanced Network Packet Capture Module with Deep Packet Inspection
Advanced monitoring: DNS, HTTP, payload analysis, connection tracking, geo-location, etc.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from collections import defaultdict, deque
import threading
import time
from datetime import datetime
import re
import hashlib

class EnhancedPacketAnalyzer:
    def __init__(self, callback=None):
        self.callback = callback
        self.packet_count = 0
        
        # Advanced tracking
        self.connection_tracker = defaultdict(lambda: {
            'count': 0, 'bytes': 0, 'last_seen': 0, 'syn_count': 0, 
            'packets': [], 'protocols': set()
        })
        self.port_scanner_detection = defaultdict(lambda: {
            'ports': set(), 'first_seen': 0, 'packet_count': 0
        })
        self.dns_tracker = defaultdict(list)  # Track DNS queries
        self.http_tracker = defaultdict(list)  # Track HTTP requests
        self.payload_patterns = []  # Suspicious payload patterns
        self.data_exfiltration = defaultdict(int)  # Track large outbound data
        self.suspicious_ips = set()
        self.failed_connections = defaultdict(int)
        self.flag_tracker = defaultdict(lambda: defaultdict(int))  # Track flag patterns per IP
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'dns_queries': 0,
            'http_requests': 0,
            'suspicious_payloads': 0,
            'failed_handshakes': 0,
            'syn_scans': 0,
            'fin_scans': 0,
            'xmas_scans': 0,
            'null_scans': 0
        }
        
        # Suspicious payload patterns (basic malware/attack signatures)
        self.load_suspicious_patterns()
    
    def load_suspicious_patterns(self):
        """Load suspicious payload patterns"""
        self.payload_patterns = [
            (b'cmd.exe', 'Command execution'),
            (b'/bin/sh', 'Shell execution'),
            (b'/bin/bash', 'Bash execution'),
            (b'powershell', 'PowerShell execution'),
            (b'<script>', 'XSS attempt'),
            (b'SELECT.*FROM', 'SQL injection'),
            (b'UNION.*SELECT', 'SQL injection'),
            (b'../../../', 'Path traversal'),
            (b'%00', 'Null byte injection'),
            (b'eval(', 'Code injection'),
            (b'base64_decode', 'Obfuscation detected'),
        ]
    
    def analyze_packet(self, packet):
        """Deep packet analysis"""
        try:
            self.stats['total_packets'] += 1
            
            if not IP in packet:
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)
            
            # Protocol-specific analysis
            protocol_name = 'OTHER'
            src_port = dst_port = 0
            flags = None
            threat = None
            
            # TCP Analysis
            if TCP in packet:
                protocol_name = 'TCP'
                self.stats['tcp_packets'] += 1
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Analyze TCP-specific threats
                threat = self.analyze_tcp(packet, src_ip, dst_ip, src_port, dst_port, flags)
                
                # HTTP Detection (port 80 or common web ports)
                if dst_port in [80, 8080, 8000] or src_port in [80, 8080, 8000]:
                    self.analyze_http(packet, src_ip, dst_ip)
            
            # UDP Analysis
            elif UDP in packet:
                protocol_name = 'UDP'
                self.stats['udp_packets'] += 1
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                # DNS Detection
                if dst_port == 53 or src_port == 53:
                    self.analyze_dns(packet, src_ip, dst_ip)
                
                threat = self.analyze_udp(packet, src_ip, dst_ip, src_port, dst_port)
            
            # ICMP Analysis
            elif ICMP in packet:
                protocol_name = 'ICMP'
                self.stats['icmp_packets'] += 1
                threat = self.analyze_icmp(packet, src_ip, dst_ip)
            
            # Payload inspection
            if not threat and Raw in packet:
                threat = self.analyze_payload(packet, src_ip, dst_ip)
            
            # Connection tracking
            self.track_connection(src_ip, dst_ip, protocol_name, packet_size)
            
            # Port scan detection
            if dst_port > 0:
                port_scan_threat = self.detect_port_scan(src_ip, dst_port)
                if port_scan_threat and not threat:
                    threat = port_scan_threat
            
            # Data exfiltration detection
            exfil_threat = self.detect_data_exfiltration(src_ip, dst_ip, packet_size)
            if exfil_threat and not threat:
                threat = exfil_threat
            
            # Flag-based scan detection (TCP only)
            if protocol_name == 'TCP' and flags:
                flag_threat = self.detect_flag_scans(src_ip, dst_ip, dst_port, flags)
                if flag_threat and not threat:
                    threat = flag_threat
            
            # Create log entry
            log_entry = {
                'id': int(time.time() * 1000000),
                'timestamp': datetime.now().isoformat(),
                'type': 'ALERT' if threat else 'NORMAL',
                'source': src_ip,
                'destination': dst_ip,
                'protocol': protocol_name,
                'sport': src_port,
                'port': dst_port,
                'flags': str(flags) if flags else None,
                'message': threat['description'] if threat else f'Packet captured ({packet_size} bytes)',
                'bytes': packet_size,
                'threat_type': threat['type'] if threat else None
            }
            
            # Callback
            if self.callback:
                self.callback(log_entry, threat)
                
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def analyze_tcp(self, packet, src_ip, dst_ip, src_port, dst_port, flags):
        """Analyze TCP-specific threats"""
        current_time = time.time()
        
        # Track SYN packets (SYN flood detection)
        if 'S' in str(flags) and 'A' not in str(flags):
            key = f"{src_ip}_{dst_ip}"
            self.connection_tracker[key]['syn_count'] += 1
            
            if self.connection_tracker[key]['syn_count'] > 100:
                return {
                    'type': 'SYN Flood',
                    'severity': 'HIGH',
                    'description': f'SYN flood from {src_ip} - {self.connection_tracker[key]["syn_count"]} SYN packets',
                    'source': src_ip
                }
        
        # Failed connection attempts (RST packets)
        if 'R' in str(flags):
            self.failed_connections[src_ip] += 1
            self.stats['failed_handshakes'] += 1
            
            if self.failed_connections[src_ip] > 50:
                return {
                    'type': 'Connection Scan',
                    'severity': 'MEDIUM',
                    'description': f'{self.failed_connections[src_ip]} failed connections from {src_ip}',
                    'source': src_ip
                }
        
        # Suspicious high ports (possible backdoor)
        if dst_port > 49152 and dst_port not in [51413, 58846]:  # Exclude common P2P
            if dst_port in [4444, 5555, 31337, 12345]:
                return {
                    'type': 'Backdoor Port',
                    'severity': 'HIGH',
                    'description': f'Known backdoor port {dst_port} accessed',
                    'source': src_ip
                }
        
        return None
    
    def analyze_udp(self, packet, src_ip, dst_ip, src_port, dst_port):
        """Analyze UDP-specific threats"""
        
        # UDP flood detection
        key = f"{src_ip}_{dst_ip}_{dst_port}"
        self.connection_tracker[key]['count'] += 1
        
        if self.connection_tracker[key]['count'] > 200:
            return {
                'type': 'UDP Flood',
                'severity': 'HIGH',
                'description': f'UDP flood to {dst_ip}:{dst_port} - {self.connection_tracker[key]["count"]} packets',
                'source': src_ip
            }
        
        # DNS amplification detection
        if src_port == 53 and len(packet) > 512:
            return {
                'type': 'DNS Amplification',
                'severity': 'HIGH',
                'description': f'Large DNS response ({len(packet)} bytes) - possible amplification attack',
                'source': src_ip
            }
        
        return None
    
    def analyze_icmp(self, packet, src_ip, dst_ip):
        """Analyze ICMP threats"""
        
        # ICMP flood detection
        key = f"icmp_{src_ip}_{dst_ip}"
        self.connection_tracker[key]['count'] += 1
        
        if self.connection_tracker[key]['count'] > 100:
            return {
                'type': 'ICMP Flood',
                'severity': 'MEDIUM',
                'description': f'ICMP flood from {src_ip} - {self.connection_tracker[key]["count"]} packets',
                'source': src_ip
            }
        
        return None
    
    def analyze_dns(self, packet, src_ip, dst_ip):
        """Analyze DNS queries and responses"""
        try:
            if DNS in packet and DNSQR in packet:
                # DNS Query
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                self.stats['dns_queries'] += 1
                self.dns_tracker[src_ip].append({
                    'query': query,
                    'timestamp': time.time()
                })
                
                # Suspicious domain patterns
                suspicious_patterns = [
                    r'.*\.tk$',  # Free TLD often used for malware
                    r'.*\.ml$',
                    r'.*\.ga$',
                    r'.*\.cf$',
                    r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',  # IP-like domain
                    r'[a-f0-9]{32,}',  # Long hex strings (DGA)
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, query, re.IGNORECASE):
                        return {
                            'type': 'Suspicious DNS',
                            'severity': 'MEDIUM',
                            'description': f'Suspicious DNS query: {query}',
                            'source': src_ip
                        }
        except:
            pass
    
    def analyze_http(self, packet, src_ip, dst_ip):
        """Analyze HTTP requests"""
        try:
            if Raw in packet:
                payload = packet[Raw].load
                
                # Look for HTTP request
                if b'GET ' in payload or b'POST ' in payload or b'PUT ' in payload:
                    self.stats['http_requests'] += 1
                    
                    # Extract URL
                    try:
                        http_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        self.http_tracker[src_ip].append({
                            'request': http_line,
                            'timestamp': time.time()
                        })
                    except:
                        pass
        except:
            pass
    
    def analyze_payload(self, packet, src_ip, dst_ip):
        """Analyze packet payload for suspicious content"""
        try:
            payload = packet[Raw].load
            
            # Check against suspicious patterns
            for pattern, description in self.payload_patterns:
                if pattern in payload:
                    self.stats['suspicious_payloads'] += 1
                    return {
                        'type': 'Suspicious Payload',
                        'severity': 'HIGH',
                        'description': f'{description} detected in payload',
                        'source': src_ip
                    }
        except:
            pass
        
        return None
    
    def track_connection(self, src_ip, dst_ip, protocol, size):
        """Track connection statistics"""
        key = f"{src_ip}_{dst_ip}"
        current_time = time.time()
        
        self.connection_tracker[key]['count'] += 1
        self.connection_tracker[key]['bytes'] += size
        self.connection_tracker[key]['last_seen'] = current_time
        self.connection_tracker[key]['protocols'].add(protocol)
    
    def detect_port_scan(self, src_ip, dst_port):
        """Enhanced port scan detection"""
        # Skip internal IPs (your own network)
        if src_ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                              '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                              '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                              '172.29.', '172.30.', '172.31.', '127.')):
            return None
        
        current_time = time.time()
        
        if self.port_scanner_detection[src_ip]['first_seen'] == 0:
            self.port_scanner_detection[src_ip]['first_seen'] = current_time
        
        self.port_scanner_detection[src_ip]['ports'].add(dst_port)
        self.port_scanner_detection[src_ip]['packet_count'] += 1
        
        time_window = current_time - self.port_scanner_detection[src_ip]['first_seen']
        port_count = len(self.port_scanner_detection[src_ip]['ports'])
        
        # Port scan: >20 ports in <60 seconds
        if time_window < 60 and port_count > 20:
            if src_ip not in self.suspicious_ips:
                self.suspicious_ips.add(src_ip)
                return {
                    'type': 'Port Scan',
                    'severity': 'HIGH',
                    'description': f'Port scan from {src_ip} - {port_count} ports in {int(time_window)}s',
                    'source': src_ip
                }
        
        # Vertical scan: >50 packets to same port
        if self.port_scanner_detection[src_ip]['packet_count'] > 50 and port_count < 5:
            return {
                'type': 'Vertical Scan',
                'severity': 'MEDIUM',
                'description': f'Vertical scan from {src_ip} - targeting port {dst_port}',
                'source': src_ip
            }
        
        return None
    
    def detect_data_exfiltration(self, src_ip, dst_ip, size):
        """Detect potential data exfiltration"""
        
        # Track outbound data per IP
        if src_ip.startswith('192.168.') or src_ip.startswith('10.'):
            self.data_exfiltration[dst_ip] += size
            
            # Large amount of data to single external IP (>10MB)
            if self.data_exfiltration[dst_ip] > 10 * 1024 * 1024:
                total_mb = self.data_exfiltration[dst_ip] / 1024 / 1024
                return {
                    'type': 'Data Exfiltration',
                    'severity': 'HIGH',
                    'description': f'Large data transfer to {dst_ip} - {total_mb:.2f} MB',
                    'source': src_ip
                }
        
        return None
    
    def detect_flag_scans(self, src_ip, dst_ip, dst_port, flags):
        """
        Detect flag-based scanning techniques
        - SYN scan: S flag only
        - FIN scan: F flag only  
        - XMAS scan: FPU flags
        - NULL scan: No flags
        """
        # Skip internal IPs
        if src_ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                              '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                              '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                              '172.29.', '172.30.', '172.31.', '127.')):
            return None
        
        flag_str = str(flags)
        current_time = time.time()
        
        # Initialize tracking
        if 'first_seen' not in self.flag_tracker[src_ip]:
            self.flag_tracker[src_ip]['first_seen'] = current_time
        
        # FIN Scan Detection: F flag without ACK (stealth scan)
        if 'F' in flag_str and 'A' not in flag_str and 'S' not in flag_str:
            self.flag_tracker[src_ip]['fin_count'] += 1
            self.stats['fin_scans'] += 1
            if self.flag_tracker[src_ip]['fin_count'] > 10:
                return {
                    'type': 'FIN Scan',
                    'severity': 'HIGH',
                    'description': f'FIN scan from {src_ip} - stealth port scanning detected',
                    'source': src_ip,
                    'flags': flag_str
                }
        
        # XMAS Scan Detection: FPU flags (Christmas tree packet)
        if 'F' in flag_str and 'P' in flag_str and 'U' in flag_str:
            self.flag_tracker[src_ip]['xmas_count'] += 1
            self.stats['xmas_scans'] += 1
            if self.flag_tracker[src_ip]['xmas_count'] > 5:
                return {
                    'type': 'XMAS Scan',
                    'severity': 'HIGH',
                    'description': f'XMAS scan from {src_ip} - advanced stealth scanning',
                    'source': src_ip,
                    'flags': flag_str
                }
        
        # NULL Scan Detection: No flags set
        if flag_str == '' or flag_str == '0':
            self.flag_tracker[src_ip]['null_count'] += 1
            self.stats['null_scans'] += 1
            if self.flag_tracker[src_ip]['null_count'] > 10:
                return {
                    'type': 'NULL Scan',
                    'severity': 'HIGH',
                    'description': f'NULL scan from {src_ip} - firewall evasion attempt',
                    'source': src_ip,
                    'flags': 'NONE'
                }
        
        # SYN Scan Detection: S flag only (standard port scan)
        if 'S' in flag_str and 'A' not in flag_str:
            self.flag_tracker[src_ip]['syn_scan_count'] += 1
            self.stats['syn_scans'] += 1
            time_window = current_time - self.flag_tracker[src_ip]['first_seen']
            
            # >30 SYN packets in 60 seconds
            if time_window < 60 and self.flag_tracker[src_ip]['syn_scan_count'] > 30:
                return {
                    'type': 'SYN Scan',
                    'severity': 'MEDIUM',
                    'description': f'SYN scan from {src_ip} - {self.flag_tracker[src_ip]["syn_scan_count"]} probes',
                    'source': src_ip,
                    'flags': flag_str
                }
        
        # ACK Scan Detection: A flag without SYN (firewall rule detection)
        if 'A' in flag_str and 'S' not in flag_str and 'F' not in flag_str and 'R' not in flag_str:
            self.flag_tracker[src_ip]['ack_scan_count'] += 1
            if self.flag_tracker[src_ip]['ack_scan_count'] > 20:
                return {
                    'type': 'ACK Scan',
                    'severity': 'MEDIUM',
                    'description': f'ACK scan from {src_ip} - firewall rule mapping',
                    'source': src_ip,
                    'flags': flag_str
                }
        
        return None
    
    def get_statistics(self):
        """Get detailed statistics"""
        return {
            **self.stats,
            'active_connections': len(self.connection_tracker),
            'monitored_ips': len(self.port_scanner_detection),
            'suspicious_ips': len(self.suspicious_ips)
        }
    
    def cleanup_old_data(self):
        """Cleanup old tracking data"""
        current_time = time.time()
        
        # Cleanup connections older than 5 minutes
        for key in list(self.connection_tracker.keys()):
            if current_time - self.connection_tracker[key]['last_seen'] > 300:
                del self.connection_tracker[key]
        
        # Cleanup port scan data older than 2 minutes
        for ip in list(self.port_scanner_detection.keys()):
            if current_time - self.port_scanner_detection[ip]['first_seen'] > 120:
                del self.port_scanner_detection[ip]
        
        # Cleanup DNS tracker
        for ip in list(self.dns_tracker.keys()):
            self.dns_tracker[ip] = [
                q for q in self.dns_tracker[ip] 
                if current_time - q['timestamp'] < 300
            ]
    
    def start_capture(self, interface=None, packet_count=0):
        """Start enhanced packet capture"""
        print(f"🔍 Starting enhanced packet capture on: {interface or 'all interfaces'}")
        print("📊 Monitoring: TCP/UDP/ICMP, DNS, HTTP, Payloads, Port Scans, Data Exfiltration")
        print("Press Ctrl+C to stop...\n")
        
        # Start cleanup thread
        def cleanup_loop():
            while True:
                time.sleep(60)
                self.cleanup_old_data()
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        
        try:
            sniff(
                iface=interface,
                prn=self.analyze_packet,
                store=False,
                count=packet_count
            )
        except PermissionError:
            print("❌ Permission denied! Requires root privileges.")
            print("   Run with: sudo python3 packet_capture.py")
        except Exception as e:
            print(f"❌ Error: {e}")


def main():
    """Standalone test"""
    print("=" * 70)
    print("🛡️  ENHANCED NETGUARD PACKET ANALYZER")
    print("=" * 70)
    
    def callback(log_entry, threat):
        if threat:
            print(f"⚠️  [{log_entry['timestamp']}] THREAT: {threat['type']}")
            print(f"    {threat['description']}")
        else:
            print(f"📦 [{log_entry['timestamp']}] {log_entry['source']}:{log_entry['sport']} → {log_entry['destination']}:{log_entry['port']} ({log_entry['protocol']})")
    
    analyzer = EnhancedPacketAnalyzer(callback=callback)
    
    # Print stats every 10 seconds
    def print_stats():
        while True:
            time.sleep(10)
            stats = analyzer.get_statistics()
            print(f"\n📊 Stats: {stats['total_packets']} packets | {stats['dns_queries']} DNS | {stats['http_requests']} HTTP\n")
    
    stats_thread = threading.Thread(target=print_stats, daemon=True)
    stats_thread.start()
    
    analyzer.start_capture()


if __name__ == "__main__":
    main()
