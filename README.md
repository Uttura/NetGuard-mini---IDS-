#### NETGUARD - Network Monitoring & IDS Dashboard

A professional network monitoring dashboard with Intrusion Detection System (IDS) capabilities for home networks, built with Flask and Python.

![NETGUARD Dashboard](preview.png)

## Features

- **Real-time Network Monitoring**: Track packets per second, active connections, bandwidth usage
- **Threat Detection**: Built-in IDS rules for detecting port scans, suspicious traffic, and potential attacks
- **Live Activity Feed**: See network traffic as it happens
- **WebSocket Integration**: Real-time updates without page refresh
- **Modern UI**: Cybersecurity-inspired dark theme with neon accents
- **Dual Mode**: Works with mock data (demo) or real packet capture

## Quick Start (Mock Data Mode)

No special privileges required - perfect for testing and learning:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the application
python app.py

# 3. Open your browser
# http://localhost:5000
```

## Real Packet Capture Mode

To monitor your actual network traffic:

### Prerequisites

- Linux/macOS (recommended) or Windows with npcap
- Root/administrator privileges
- Python 3.8+

### Installation

```bash
# Install all dependencies including Scapy
pip install -r requirements.txt

# On Linux, you may need additional packages:
sudo apt-get install libpcap-dev python3-dev

# On macOS:
brew install libpcap
```

### Running with Real Capture

```bash
# Linux/macOS
sudo python app_enhanced.py --capture

# The dashboard will capture real network packets
# and analyze them for threats
```

## Architecture

```
NETGUARD/
├── app.py                  # Basic Flask app (mock data)
├── app_enhanced.py         # Enhanced app with real capture support
├── packet_capture.py       # Scapy-based packet capture module
├── requirements.txt        # Python dependencies
└── templates/
    └── index.html         # Dashboard frontend
```

## IDS Rules

The system includes detection for:

- **Port Scanning**: Detects when a single IP attempts to access many different ports
- **Suspicious Ports**: Flags access to commonly exploited ports (23, 3389, 4444, etc.)
- **SYN Floods**: Identifies potential DDoS attacks
- **Traffic Anomalies**: Monitors for unusual patterns

## API Endpoints

- `GET /` - Dashboard UI
- `GET /api/logs` - Get recent network logs
- `GET /api/threats` - Get detected threats
- `GET /api/stats` - Get current network statistics
- `GET /api/status` - Get system status

## WebSocket Events

- `connect` - Client connection established
- `new_log` - New network log entry
- `new_threat` - New threat detected
- `stats_update` - Network statistics update

## Configuration

### Command Line Options

```bash
python app_enhanced.py [options]

Options:
  --capture        Enable real packet capture (requires root)
  --port PORT      Port to run server on (default: 5000)
  --host HOST      Host to bind to (default: 0.0.0.0)
```

### IDS Rule Thresholds

Edit the `IDS_RULES` dictionary in `app.py` or `app_enhanced.py`:

```python
IDS_RULES = {
    'port_scan': {
        'description': 'Multiple port access from single IP',
        'severity': 'HIGH',
        'threshold': 10  # Number of different ports before alerting
    },
    # ... more rules
}
```

## Advanced Setup

### Running as a Service (Linux)

Create `/etc/systemd/system/netguard.service`:

```ini
[Unit]
Description=NETGUARD Network Monitoring Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/netg
