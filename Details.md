# NetGuard - Code Architecture & Data Flow Documentation

## Overview

NetGuard is a real-time network monitoring and intrusion detection system built with Python (Flask + Scapy) and live browser updates via Socket.IO.

**Key Components:**
- `packet_capture_enhanced.py` - Deep packet inspection and threat detection
- `app_clean.py` - Flask web server and API
- `index_enhanced.html` - Real-time dashboard

**Data Storage:** In-memory only (RAM) - no database persistence

---

## packet_capture_enhanced.py

### Main Class: `EnhancedPacketAnalyzer`

#### `__init__()`
- Initializes all tracking dictionaries (connections, DNS, HTTP, port scans)
- Loads suspicious payload patterns (cmd.exe, SQL injection, etc.)
- Sets up statistics counters

#### `analyze_packet(packet)`
- Entry point for each captured packet
- Extracts IP/protocol/port info, routes to protocol-specific analyzers
- Calls threat detection, updates stats, triggers callback with results

#### `analyze_tcp(packet, src_ip, dst_ip, src_port, dst_port, flags)`
- Detects SYN floods (100+ SYN packets without ACK)
- Tracks failed connections (RST flags)
- Identifies backdoor ports (4444, 31337, etc.)

#### `analyze_udp(packet, src_ip, dst_ip, src_port, dst_port)`
- Detects UDP floods (200+ packets to same destination)
- Identifies DNS amplification attacks (responses >512 bytes)
- Tracks abnormal UDP traffic patterns

#### `analyze_icmp(packet, src_ip, dst_ip)`
- Detects ICMP floods (100+ ping packets)
- Monitors for ping-based DDoS attempts
- Simple volume-based detection

#### `analyze_dns(packet, src_ip, dst_ip)`
- Extracts DNS queries from port 53 traffic
- Detects suspicious domains (.tk, .ml, hex strings)
- Stores queries in `dns_tracker` by IP

#### `analyze_http(packet, src_ip, dst_ip)`
- Parses HTTP GET/POST/PUT requests from port 80/8080
- Extracts request URLs and methods
- Stores in `http_tracker` by source IP

#### `analyze_payload(packet, src_ip, dst_ip)`
- Scans packet data for malicious patterns
- Matches against signatures (cmd.exe, SQL injection, XSS)
- Returns threat if pattern found

#### `track_connection(src_ip, dst_ip, protocol, size)`
- Maintains connection statistics per IP pair
- Tracks bytes transferred, packet count, protocols used
- Used for exfiltration detection

#### `detect_port_scan(src_ip, dst_port)`
- Tracks unique ports accessed per IP
- Horizontal scan: 20+ ports in 60 seconds
- Vertical scan: 50+ packets to same port

#### `detect_data_exfiltration(src_ip, dst_ip, size)`
- Accumulates outbound data per destination
- Flags transfers >10MB to single external IP
- Only monitors internal → external traffic

#### `cleanup_old_data()`
- Removes stale entries (5+ minutes old)
- Runs every 60 seconds in background thread
- Prevents memory bloat

#### `get_statistics()`
- Returns comprehensive statistics dictionary
- Includes packet counts, DNS/HTTP activity, threat metrics
- Called by Flask API endpoint

#### `start_capture(interface='any')`
- Starts Scapy packet sniffing on specified interface
- Launches cleanup thread in background
- Calls `analyze_packet()` for each captured packet

---

## app_clean.py

### Global Data Structures

```python
recent_logs = deque(maxlen=100)      # Last 100 packets
recent_threats = deque(maxlen=50)    # Last 50 threats  
network_stats = {}                    # Live statistics
analyzer = None                       # Global PacketAnalyzer instance
port_access_tracker = {}              # Port scan tracking
```

### Core Functions

#### `get_network_interfaces()`
- Uses psutil to read system network stats
- Returns bytes/packets sent/received
- Calculates bandwidth from differences

#### `get_active_connections()`
- Queries system for ESTABLISHED TCP connections
- Returns count of active connections
- Uses `psutil.net_connections()`

#### `detect_threats(log_entry)`
- Additional threat detection on top of analyzer
- Tracks port access patterns per IP
- Detects port scans and suspicious ports

#### `packet_capture_callback(log_entry, threat)`
- Called by PacketAnalyzer for each packet
- Adds to `recent_logs`, updates `network_stats`
- Emits to browser via Socket.IO

#### `monitor_network_stats()`
- Background thread running every 2 seconds
- Calculates packets/sec and bandwidth
- Emits stats updates via Socket.IO

#### `start_packet_capture(interface='any')`
- Creates PacketAnalyzer with callback
- Starts capture in background thread
- Exits on permission errors

### Flask API Routes

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serves main HTML dashboard |
| `/api/logs` | GET | Returns last 100 packets as JSON |
| `/api/threats` | GET | Returns last 50 threats as JSON |
| `/api/stats` | GET | Returns current network statistics |
| `/api/dns` | GET | Returns DNS query history from analyzer |
| `/api/http` | GET | Returns HTTP request history from analyzer |
| `/api/statistics` | GET | Returns detailed packet breakdown (TCP/UDP/ICMP) |
| `/api/status` | GET | Returns system status and uptime |
| `/api/rules` | GET | Returns IDS rules configuration |

### Socket.IO Events

#### Server → Client (Emit)

**`connection_response`**
- Fires when browser connects
- Sends welcome message with mode info

**`new_log`**
- Pushes each packet to browser instantly
- Triggers on every captured packet
- Updates live logs tab

**`new_threat`**
- Pushes threats to browser instantly
- Triggers when threat detected
- Updates threats tab and overview

**`stats_update`**
- Pushes stats every 2 seconds
- Updates dashboard counters live
- Updates bandwidth/connection metrics

#### Client → Server (Receive)

**`connect`**
- Browser connects to server
- Triggers connection handler

**`disconnect`**
- Browser disconnects
- Logs disconnection

**`request_stats`**
- Client requests current stats
- Server responds with stats_update

**`request_logs`**
- Client requests recent logs
- Server responds with logs_update

---

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Interface (eth0/wlan0)            │
└──────────────────────────┬──────────────────────────────────┘
                           │ Raw packets
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Scapy Packet Capture                      │
│                    (packet_capture_enhanced.py)              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                  analyze_packet()
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   analyze_tcp()      analyze_udp()     analyze_icmp()
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   analyze_dns()      analyze_http()    analyze_payload()
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                           ▼
                  detect_threats()
                  detect_port_scan()
                  detect_data_exfiltration()
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              packet_capture_callback()                       │
│              (app_clean.py)                                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   recent_logs[]     recent_threats[]    network_stats{}
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Socket.IO Emit                            │
│              (Real-time push to browser)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                 Browser Dashboard (HTML/JS)                  │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐ │
│  │  Overview   │   Threats   │     DNS     │     HTTP    │ │
│  │  (live)     │   (live)    │   (live)    │   (live)    │ │
│  └─────────────┴─────────────┴─────────────┴─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Memory Data Structures

### In packet_capture_enhanced.py

```python
self.connection_tracker = defaultdict(dict)
# Structure: {'src_ip_dst_ip': {'count': 0, 'bytes': 0, 'last_seen': timestamp}}

self.port_scanner_detection = defaultdict(dict)
# Structure: {'src_ip': {'ports': set(), 'first_seen': timestamp, 'packet_count': 0}}

self.dns_tracker = defaultdict(list)
# Structure: {'src_ip': [{'query': 'example.com', 'timestamp': 123456}]}

self.http_tracker = defaultdict(list)
# Structure: {'src_ip': [{'request': 'GET /path', 'timestamp': 123456}]}

self.data_exfiltration = defaultdict(int)
# Structure: {'dst_ip': total_bytes}

self.suspicious_ips = set()
# Structure: {'ip1', 'ip2', ...}
```

### In app_clean.py

```python
recent_logs = deque(maxlen=100)
# Structure: [{'timestamp': ..., 'source': ..., 'destination': ..., ...}]

recent_threats = deque(maxlen=50)
# Structure: [{'type': ..., 'severity': ..., 'description': ..., ...}]

network_stats = {
    'packets_per_sec': 0,
    'active_connections': 0,
    'blocked_attempts': 0,
    'bandwidth': 0.0,
    'total_packets': 0
}

port_access_tracker = {}
# Structure: {'src_ip': {'ports': set(), 'timestamp': 123456}}
```

---

## Threat Detection Logic

### Port Scan Detection
1. Track unique ports accessed by each source IP
2. If 20+ ports in 60 seconds → **Horizontal Port Scan** (HIGH)
3. If 50+ packets to same port → **Vertical Scan** (MEDIUM)
4. Internal IPs (192.168.x.x) are whitelisted

### SYN Flood Detection
1. Count SYN packets without ACK flag
2. If 100+ SYN packets from single IP → **SYN Flood** (HIGH)
3. Typical DDoS attack pattern

### Data Exfiltration Detection
1. Track outbound data from internal IPs
2. If >10MB to single external IP → **Data Exfiltration** (HIGH)
3. Only monitors internal → external traffic

### Payload Analysis
1. Scan packet raw data for signatures
2. Patterns: cmd.exe, SQL injection, XSS, path traversal
3. Match found → **Suspicious Payload** (HIGH)

### DNS Analysis
1. Extract queries from port 53 traffic
2. Check for suspicious TLDs (.tk, .ml, .ga, .cf)
3. Check for DGA patterns (long hex strings)
4. Match found → **Suspicious DNS** (MEDIUM)

---

## Performance Considerations

### Memory Management
- `deque(maxlen=N)` automatically drops old entries
- Cleanup thread runs every 60 seconds
- Removes data older than 5 minutes
- No database = no disk I/O bottleneck

### Packet Processing Rate
- Can handle 1000-5000 packets/second
- Protocol analysis adds ~0.5ms per packet
- Threat detection adds ~0.2ms per packet
- Total: ~0.7ms processing per packet

### Real-time Updates
- Socket.IO pushes data instantly (no polling)
- Browser receives updates within milliseconds
- Stats updated every 2 seconds (configurable)

---

## Security Considerations

### Requires Root Privileges
- Packet capture needs raw socket access
- Run with `sudo` or use `setcap` capability

### Data Privacy
- All data stays in memory (RAM)
- No data written to disk
- Data disappears on app restart

### False Positives
- Internal IPs whitelisted from port scan detection
- High thresholds to reduce normal traffic alerts
- User's own browsing can trigger vertical scans (port 443)

---

## Extension Points

### Adding New Threat Detection
1. Create new detection function in `EnhancedPacketAnalyzer`
2. Call from `analyze_packet()` or protocol-specific analyzer
3. Return threat dict with type, severity, description

### Adding New Data Collection
1. Create tracking structure in `__init__()`
2. Populate in protocol analyzer (e.g., `analyze_tcp()`)
3. Add API endpoint in `app_clean.py` to expose data
4. Update HTML to display new data

### Adding Persistence
1. Import database library (SQLAlchemy, MongoDB)
2. Add write operations in `packet_capture_callback()`
3. Create API endpoints to query historical data
4. Note: Will reduce real-time performance

---

## Troubleshooting

### No Packets Captured
- Check interface name: `ip link show`
- Verify root privileges: `sudo python3 app_clean.py`
- Test with specific interface: `--interface wlan0`

### High Memory Usage
- Reduce `maxlen` in deques
- Decrease cleanup interval
- Lower detection thresholds

### False Positives
- Increase threat detection thresholds
- Whitelist more IP ranges
- Adjust time windows

### Socket.IO Not Connecting
- Check firewall allows port 5000
- Verify Flask server started successfully
- Check browser console for errors

---

## File Structure

```
NetGuard/
├── app_clean.py                    # Flask backend & API
├── packet_capture_enhanced.py      # Packet analysis engine
├── templates/
│   └── index_enhanced.html         # Browser dashboard
├── static/                         # (optional) CSS/JS files
└── README.md                       # This file
```

---

## Dependencies

```bash
pip install flask flask-cors flask-socketio scapy psutil
```

## Usage

```bash
# Start NetGuard
sudo python3 app_clean.py --interface wlan0

# Open browser
http://localhost:5000
```

---

*Documentation generated for NetGuard v1.0 - Real-time Network Monitoring & IDS*
