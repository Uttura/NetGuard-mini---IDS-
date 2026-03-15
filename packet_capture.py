"""
Advanced Network Packet Capture Module using Scapy
This module provides real network packet capture and analysis capabilities.
Requires root/admin privileges to capture packets.

Usage:
    sudo python packet_capture.py

Note: This is an optional enhancement. The main app.py works without this,
using simulated data. This module enables real packet capture when run with
proper privileges.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from collections import defaultdict
import threading
import time
from datetime import datetime

class PacketAnalyzer:
    def __init__(self, callback=None):
        self.callback = callback
        self.packet_count = 0
        self.connection_tracker = defaultdict(lambda: {'count': 0, 'last_seen': 0})
        self.port_scanner_detection = defaultdict(set)
        self.suspicious_ips = set()
        
    def analyze_packet(self, packet):
        """Analyze a captured packet for threats and patterns"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Determine protocol name
                if TCP in packet:
                    protocol_name = 'TCP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = packet[TCP].flags
                elif UDP in packet:
                    protocol_name = 'UDP'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    flags = None
                elif ICMP in packet:
                    protocol_name = 'ICMP'
                    src_port = 0
                    dst_port = 0
                    flags = None
                else:
                    protocol_name = 'OTHER'
                    src_port = 0
                    dst_port = 0
                    flags = None
                
                # Packet details
                packet_size = len(packet)
                
                # Create log entry
                log_entry = {
                    'id': int(time.time() * 1000000),
                    'timestamp': datetime.now().isoformat(),
                    'type': 'NORMAL',
                    'source': src_ip,
                    'destination': dst_ip,
                    'protocol': protocol_name,
                    'port': dst_port,
                    'message': f'Packet captured ({packet_size} bytes)',
                    'bytes': packet_size
                }
                
                # Detect suspicious activity
                threat = self.detect_threats(src_ip, dst_ip, dst_port, protocol_name, flags)
                if threat:
                    log_entry['type'] = 'ALERT'
                    log_entry['message'] = threat['description']
                
                # Update tracking
                self.packet_count += 1
                
                # Call callback with log entry
                if self.callback:
                    self.callback(log_entry, threat)
                    
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def detect_threats(self, src_ip, dst_ip, dst_port, protocol, flags):
        """Detect various network threats"""
        current_time = time.time()
        
        # Port scan detection
        self.port_scanner_detection[src_ip].add(dst_port)
        
        # Check if IP has accessed many different ports (potential port scan)
        if len(self.port_scanner_detection[src_ip]) > 10:
            if src_ip not in self.suspicious_ips:
                self.suspicious_ips.add(src_ip)
                return {
                    'type': 'Port Scan',
                    'severity': 'HIGH',
                    'description': f'Port scan detected from {src_ip} - accessed {len(self.port_scanner_detection[src_ip])} different ports',
                    'source': src_ip
                }
        
        # Detect SYN flood (potential DDoS)
        if protocol == 'TCP' and flags:
            if 'S' in str(flags) and 'A' not in str(flags):  # SYN flag without ACK
                key = f"{src_ip}_{dst_ip}"
                self.connection_tracker[key]['count'] += 1
                self.connection_tracker[key]['last_seen'] = current_time
                
                if self.connection_tracker[key]['count'] > 50:
                    return {
                        'type': 'DDoS Attempt',
                        'severity': 'HIGH',
                        'description': f'Potential SYN flood from {src_ip} - {self.connection_tracker[key]["count"]} SYN packets',
                        'source': src_ip
                    }
        
        # Detect access to suspicious ports
        suspicious_ports = [23, 3389, 4444, 1234, 31337, 12345]
        if dst_port in suspicious_ports:
            return {
                'type': 'Suspicious Port Access',
                'severity': 'MEDIUM',
                'description': f'Access to suspicious port {dst_port}',
                'source': src_ip
            }
        
        # Clean up old connection tracking data
        for key in list(self.connection_tracker.keys()):
            if current_time - self.connection_tracker[key]['last_seen'] > 60:
                del self.connection_tracker[key]
        
        # Clean up port scanner tracking (reset after 2 minutes)
        for ip in list(self.port_scanner_detection.keys()):
            # This is a simple cleanup - in production, track timestamps per IP
            if len(self.port_scanner_detection[ip]) > 100:
                self.port_scanner_detection[ip] = set()
        
        return None
    
    def start_capture(self, interface=None, packet_count=0):
        """Start capturing packets on the specified interface"""
        print(f"Starting packet capture on interface: {interface or 'all'}")
        print("Press Ctrl+C to stop...")
        
        try:
            # Capture packets
            # filter="ip" captures only IP packets (not ARP, etc.)
            sniff(
                iface=interface,
                prn=self.analyze_packet,
                store=False,
                count=packet_count
            )
        except PermissionError:
            print("\n❌ Permission denied! Packet capture requires root/admin privileges.")
            print("   Run with: sudo python packet_capture.py")
        except Exception as e:
            print(f"\n❌ Error during packet capture: {e}")


def main():
    """Main function for standalone packet capture"""
    print("=" * 60)
    print("🔍 NETGUARD Packet Capture Module")
    print("=" * 60)
    
    def packet_callback(log_entry, threat):
        """Callback function for captured packets"""
        print(f"[{log_entry['timestamp']}] {log_entry['type']} - {log_entry['source']} -> {log_entry['destination']}:{log_entry['port']} ({log_entry['protocol']})")
        if threat:
            print(f"  ⚠️  THREAT DETECTED: {threat['type']} - {threat['description']}")
    
    analyzer = PacketAnalyzer(callback=packet_callback)
    analyzer.start_capture()


if __name__ == "__main__":
    main()
