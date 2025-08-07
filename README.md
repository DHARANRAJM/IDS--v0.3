# Network-Based Intrusion Detection System (IDS)

A lightweight, shell-based Intrusion Detection System designed for real-time network monitoring and threat detection. This project demonstrates how simple shell scripting can be used to create an effective IDS that's resource-friendly and highly customizable.

## 🎯 Project Overview

This IDS monitors network traffic in real-time to detect various types of attacks and suspicious activities:

- **ARP Spoofing Detection**: Monitors ARP tables for suspicious MAC-IP mappings
- **Port Scanning Detection**: Detects rapid connection attempts to multiple ports
- **SSH Brute-force Detection**: Monitors failed SSH login attempts
- **USB Insertion Detection**: Tracks USB device insertions for security compliance
- **Anomaly Detection**: Optional ML-based analysis of network patterns

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Network       │    │   Detection     │    │   Alert &       │
│   Monitoring    │───▶│   Modules       │───▶│   Logging       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   tcpdump       │    │   Shell Scripts │    │   Log Files     │
│   arp           │    │   - arp_spoof   │    │   - alert-log   │
│   netstat       │    │   - port_scan   │    │   - system.log  │
│   dmesg         │    │   - ssh_brute   │    │   - usb.log     │
│   udevadm       │    │   - usb_detect  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Features

### Core Detection Capabilities
- **Real-time Network Monitoring**: Continuous monitoring using native Linux tools
- **ARP Spoofing Detection**: Identifies suspicious MAC-IP address mappings
- **Port Scanning Detection**: Detects rapid sequential port connection attempts
- **SSH Brute-force Detection**: Monitors failed authentication attempts
- **USB Device Monitoring**: Tracks USB insertions for security compliance
- **Configurable Alerting**: Customizable alert thresholds and notifications

### Advanced Features
- **Whitelist Support**: Configurable MAC address whitelist
- **Log Rotation**: Automatic log management and rotation
- **Performance Monitoring**: Resource usage tracking
- **ML Integration**: Optional Python-based anomaly detection

## 🚀 Installation & Setup

### Prerequisites
- Linux system (Kali Linux, Ubuntu, or similar)
- Root/sudo privileges
- Basic networking tools (usually pre-installed)

### Quick Start
```bash
# Clone the repository
git clone <your-repo-url>
cd IDS

# Make scripts executable
chmod +x ids_monitor.sh
chmod +x modules/*.sh
chmod +x test/*.sh

# Start the IDS
sudo ./ids_monitor.sh
```

### Configuration
1. Edit `config/whitelist_macs.txt` to add trusted MAC addresses
2. Modify detection thresholds in individual module scripts
3. Configure alert notifications in `ids_monitor.sh`

## 📖 Usage

### Basic Monitoring
```bash
# Start monitoring with default settings
sudo ./ids_monitor.sh

# Start with custom log file
sudo ./ids_monitor.sh --log-file /var/log/ids-custom.log

# Start with specific modules
sudo ./ids_monitor.sh --modules arp,port_scan,ssh_brute
```

### Individual Module Testing
```bash
# Test ARP spoofing detection
sudo ./modules/arp_spoof.sh

# Test port scanning detection
sudo ./modules/port_scan.sh

# Test USB detection
sudo ./modules/usb_detect.sh
```

## 🧪 Testing Scenarios

### 1. Port Scanning Test
```bash
# In one terminal, start the IDS
sudo ./ids_monitor.sh

# In another terminal, run a port scan
nmap -sS -p 1-1000 localhost
```

### 2. ARP Spoofing Test
```bash
# Start monitoring
sudo ./ids_monitor.sh

# Simulate ARP spoofing (requires two machines)
sudo arping -I eth0 -s <spoofed_ip> <target_ip>
```

### 3. SSH Brute-force Test
```bash
# Start monitoring
sudo ./ids_monitor.sh

# Simulate brute-force attack
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://localhost
```

### 4. USB Insertion Test
```bash
# Start monitoring
sudo ./ids_monitor.sh

# Insert a USB device and check logs
tail -f logs/alert-log.txt
```

## 📊 Comparison with Other IDS Tools

| Feature | Shell IDS | Snort | Suricata | Zeek |
|---------|-----------|-------|----------|------|
| **Resource Usage** | Very Low | Medium | High | High |
| **Customization** | High | Medium | Medium | High |
| **Learning Curve** | Low | High | High | High |
| **Deployment** | Simple | Complex | Complex | Complex |
| **Real-time** | Yes | Yes | Yes | Yes |
| **Log Analysis** | Basic | Advanced | Advanced | Advanced |
| **ML Integration** | Optional | Limited | Limited | Good |

### Advantages of Shell-based IDS
- **Lightweight**: Minimal resource consumption
- **Transparent**: Easy to understand and modify
- **Native Tools**: Uses built-in Linux commands
- **Customizable**: Highly adaptable to specific needs
- **Educational**: Great for learning IDS concepts

### Limitations
- **Basic Detection**: Limited compared to commercial tools
- **Manual Tuning**: Requires more manual configuration
- **Limited Protocols**: Focuses on common attack vectors
- **No GUI**: Command-line only interface

## 📁 Project Structure

```
IDS/
├── README.md                    # This file
├── ids_monitor.sh              # Main monitoring script
├── modules/                     # Detection modules
│   ├── arp_spoof.sh           # ARP spoofing detection
│   ├── port_scan.sh           # Port scanning detection
│   ├── ssh_brute.sh           # SSH brute-force detection
│   └── usb_detect.sh          # USB insertion detection
├── logs/                        # Alert logs
│   ├── alert-log.txt          # Main alert log
│   ├── system.log             # System events
│   └── usb.log                # USB device events
├── config/                      # Configuration files
│   ├── whitelist_macs.txt     # Trusted MAC addresses
│   └── thresholds.conf         # Detection thresholds
├── test/                        # Testing scripts
│   ├── test_port_scan.sh      # Port scan testing
│   ├── test_arp_spoof.sh      # ARP spoof testing
│   ├── test_ssh_brute.sh      # SSH brute-force testing
│   └── test_usb.sh            # USB insertion testing
└── ml_detection/               # Optional ML integration
    ├── anomaly_detector.py     # Python ML script
    ├── requirements.txt        # Python dependencies
    └── models/                 # Trained models
```

## 🔧 Configuration

### Detection Thresholds
Edit `config/thresholds.conf` to adjust sensitivity:
```bash
# ARP spoofing detection
ARP_CHECK_INTERVAL=5
ARP_SUSPICIOUS_THRESHOLD=3

# Port scanning detection
PORT_SCAN_WINDOW=60
PORT_SCAN_THRESHOLD=10

# SSH brute-force detection
SSH_FAILURE_THRESHOLD=5
SSH_TIME_WINDOW=300
```

### Whitelist Configuration
Add trusted MAC addresses to `config/whitelist_macs.txt`:
```
00:11:22:33:44:55
aa:bb:cc:dd:ee:ff
```

## 📈 Performance Monitoring

The IDS includes built-in performance monitoring:
- CPU usage tracking
- Memory consumption
- Network I/O statistics
- Detection rate metrics

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Linux community for excellent networking tools
- Snort, Suricata, and Zeek teams for inspiration
- Open source security community

## 📞 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Contact: [your-email@domain.com]
- Documentation: [link-to-docs]

---

**Note**: This IDS is designed for educational purposes and basic network monitoring. For production environments, consider using established tools like Snort or Suricata alongside this system.
