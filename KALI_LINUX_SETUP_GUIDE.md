# 🛡️ IDS Setup and Testing Guide for Kali Linux

## 📋 **Table of Contents**
- [Prerequisites](#prerequisites)
- [Initial Setup](#initial-setup)
- [Dependencies Installation](#dependencies-installation)
- [IDS Configuration](#ids-configuration)
- [Starting the IDS](#starting-the-ids)
- [Testing Procedures](#testing-procedures)
- [Advanced Testing](#advanced-testing)
- [Monitoring and Analysis](#monitoring-and-analysis)
- [Troubleshooting](#troubleshooting)
- [Validation Checklist](#validation-checklist)

---

## 🔧 **Prerequisites**

### System Requirements
- Kali Linux (latest version recommended)
- Root privileges (required for IDS monitoring)
- At least 2GB RAM
- 10GB free disk space
- Network interface for monitoring

### Required Tools
```bash
# Core tools (usually pre-installed on Kali)
tcpdump, nmap, hydra, arping, net-tools, iproute2
udev, usbutils, dmesg, bc, python3, python3-pip

# Optional: Additional testing tools
wireshark, metasploit-framework, sqlmap
```

---

## 🚀 **Initial Setup**

### Step 1: Navigate to Project Directory
```bash
# Navigate to your IDS project directory
cd /path/to/your/IDS--v0.3

# Verify you're in the correct directory
ls -la
# Should show: README.md, ids_monitor.sh, modules/, config/, etc.
```

### Step 2: Check Root Privileges
```bash
# Ensure you have root privileges
sudo su

# Verify root access
whoami
# Should output: root
```

### Step 3: Make Scripts Executable
```bash
# Make all shell scripts executable
chmod +x *.sh
chmod +x modules/*.sh
chmod +x test/*.sh
chmod +x setup.sh
```

### Step 4: Run Setup Script
```bash
# Run the comprehensive setup script
sudo ./setup.sh

# This will:
# ✓ Check system requirements
# ✓ Verify dependencies
# ✓ Create directory structure
# ✓ Make all scripts executable
# ✓ Create log files
# ✓ Validate configuration
# ✓ Test IDS modules
```

---

## 📦 **Dependencies Installation**

### Automatic Installation (Recommended)
```bash
# Update package list
sudo apt update

# Install all required dependencies
sudo apt install -y \
    tcpdump \
    nmap \
    hydra \
    arping \
    net-tools \
    iproute2 \
    udev \
    usbutils \
    dmesg \
    bc \
    python3 \
    python3-pip \
    curl \
    wget \
    git

# Install Python ML dependencies (optional)
cd ml_detection
pip3 install -r requirements.txt
cd ..
```

### Manual Verification
```bash
# Check if all tools are available
which tcpdump nmap hydra arping netstat ip udevadm lsusb dmesg bc python3

# Test basic functionality
tcpdump --version
nmap --version
hydra --version
```

---

## ⚙️ **IDS Configuration**

### Step 1: Configure Detection Thresholds
```bash
# Edit the main configuration file
nano config/thresholds.conf

# Key settings to adjust:
# ARP_SUSPICIOUS_THRESHOLD=5      # Lower = more sensitive
# PORT_SCAN_THRESHOLD=10          # Lower = more sensitive
# SSH_FAILURE_THRESHOLD=5         # Lower = more sensitive
# USB_CHECK_INTERVAL=30           # Seconds between USB checks
```

### Step 2: Configure Whitelist
```bash
# Add trusted MAC addresses
nano config/whitelist_macs.txt

# Add your trusted devices:
# 00:11:22:33:44:55  # Your laptop
# AA:BB:CC:DD:EE:FF  # Your phone
# 12:34:56:78:9A:BC  # Your router
```

### Step 3: Verify Configuration
```bash
# Check configuration syntax
sudo ./setup.sh --validate-config

# Test configuration loading
sudo ./ids_monitor.sh --test-config
```

### Step 4: Configure Email Notifications (Optional)
```bash
# Set up email notifications
sudo ./setup_email.sh --configure

# Test email configuration
sudo ./setup_email.sh --test

# Check email status
sudo ./setup_email.sh --status
```

---

## 🏁 **Starting the IDS**

### Method 1: Daemon Mode (Recommended)
```bash
# Start IDS in background
sudo ./ids_monitor.sh -d

# Check if it's running
sudo ./ids_monitor.sh --status

# View process
ps aux | grep ids_monitor
```

### Method 2: Verbose Mode (Debugging)
```bash
# Start with verbose output
sudo ./ids_monitor.sh -v

# This shows real-time detection events
```

### Method 3: Interactive Mode
```bash
# Start in foreground
sudo ./ids_monitor.sh

# Press Ctrl+C to stop
```

### IDS Management Commands
```bash
# Check status
sudo ./ids_monitor.sh --status

# Stop IDS
sudo ./ids_monitor.sh --stop

# Restart IDS
sudo ./ids_monitor.sh --restart

# Show help
sudo ./ids_monitor.sh --help

# Email management
sudo ./ids_monitor.sh --email-config    # Configure email alerts
sudo ./ids_monitor.sh --email-test      # Test email configuration
sudo ./ids_monitor.sh --email-status    # Show email status
```

---

## 🧪 **Testing Procedures**

### Real-Time Monitoring Setup
```bash
# Monitor alerts in real-time (open in separate terminal)
tail -f logs/alert-log.txt

# Monitor system logs
tail -f logs/system.log

# Monitor USB events
tail -f logs/usb.log
```

### Test 1: Port Scanning Detection
```bash
# Run comprehensive port scan test
sudo ./test/test_port_scan.sh

# Or test specific types:
sudo ./test/test_port_scan.sh -b  # Basic scanning
sudo ./test/test_port_scan.sh -r  # Rapid scanning
sudo ./test/test_port_scan.sh -a  # Advanced scanning

# Manual test:
nmap -sS -p 1-1000 localhost
nmap -sT -p 22,80,443,8080 localhost
```

### Test 2: ARP Spoofing Detection
```bash
# Run ARP spoofing test
sudo ./test/test_arp_spoof.sh

# Or test specific types:
sudo ./test/test_arp_spoof.sh -b  # Basic manipulation
sudo ./test/test_arp_spoof.sh -s  # Spoofing simulation
sudo ./test/test_arp_spoof.sh -p  # Cache poisoning

# Manual test:
sudo arping -I eth0 -s 192.168.1.100 192.168.1.1
```

### Test 3: SSH Brute-force Detection
```bash
# Run SSH brute-force test
sudo ./test/test_ssh_brute.sh

# Or test specific types:
sudo ./test/test_ssh_brute.sh -b  # Basic attempts
sudo ./test/test_ssh_brute.sh -d  # Dictionary attacks
sudo ./test/test_ssh_brute.sh -e  # Username enumeration

# Manual test:
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://localhost
```

### Test 4: USB Insertion Detection
```bash
# Run USB detection test
sudo ./test/test_usb.sh

# Or test specific types:
sudo ./test/test_usb.sh -d  # Device detection
sudo ./test/test_usb.sh -s  # Storage devices
sudo ./test/test_usb.sh -c  # Security checks

# Manual test:
# Insert a USB device and check logs
tail -f logs/usb.log
```

---

## 🔬 **Advanced Testing**

### Comprehensive Attack Simulation
```bash
# Create comprehensive test script
cat > test_comprehensive.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting Comprehensive IDS Test..."

# Start IDS
sudo ./ids_monitor.sh -d &
IDS_PID=$!

# Wait for IDS to start
sleep 5

echo "📡 IDS started with PID: $IDS_PID"

# Run all tests simultaneously
echo "🧪 Running Port Scan Test..."
sudo ./test/test_port_scan.sh &
PORT_PID=$!

echo "🧪 Running ARP Spoof Test..."
sudo ./test/test_arp_spoof.sh &
ARP_PID=$!

echo "🧪 Running SSH Brute Test..."
sudo ./test/test_ssh_brute.sh &
SSH_PID=$!

echo "🧪 Running USB Detection Test..."
sudo ./test/test_usb.sh &
USB_PID=$!

# Wait for all tests to complete
wait $PORT_PID $ARP_PID $SSH_PID $USB_PID

# Stop IDS
sudo ./ids_monitor.sh --stop

echo "✅ Comprehensive test completed!"
echo "📊 Check logs/alert-log.txt for results"
EOF

chmod +x test_comprehensive.sh
sudo ./test_comprehensive.sh
```

### Performance Testing
```bash
# High-load port scanning test
for i in {1..20}; do
    nmap -sS -p 1-1000 localhost &
    echo "Started scan $i"
done

# Monitor system resources
htop

# Check IDS performance
sudo ./ids_monitor.sh --status
```

### Network Stress Testing
```bash
# Create network stress test
cat > stress_test.sh << 'EOF'
#!/bin/bash

echo "🔥 Starting Network Stress Test..."

# Multiple simultaneous attacks
for i in {1..10}; do
    # Port scanning
    nmap -sS -p 1-1000 localhost &
    
    # ARP spoofing
    sudo arping -I eth0 -s 192.168.1.$i 192.168.1.1 &
    
    # SSH attempts
    sshpass -p wrongpass ssh -o ConnectTimeout=1 root@localhost &
    
    echo "Started attack batch $i"
    sleep 2
done

wait
echo "🔥 Stress test completed!"
EOF

chmod +x stress_test.sh
sudo ./stress_test.sh
```

---

## 📧 **Email Notifications**

### Gmail Setup Requirements
```bash
# Before configuring email alerts, ensure you have:
# 1. Gmail account with 2-Step Verification enabled
# 2. App Password generated for 'Mail' application
# 3. Internet connection for SMTP access
```

### Email Configuration
```bash
# Configure email notifications
sudo ./setup_email.sh --configure

# This will prompt you for:
# - Gmail address
# - Gmail App Password (not regular password)
# - Recipient email address
# - CC email address (optional)
# - Alert types to email
# - Email frequency
```

### Email Testing
```bash
# Test email configuration
sudo ./setup_email.sh --test

# Check email status
sudo ./setup_email.sh --status

# View email logs
tail -f logs/email.log
```

### Email Alert Types
- **Port Scan Alerts**: When port scanning is detected
- **ARP Spoof Alerts**: When ARP spoofing is detected  
- **SSH Brute Force Alerts**: When SSH attacks are detected
- **USB Alerts**: When USB devices are inserted/removed

### Email Templates
- **Simple**: Basic alert information
- **Detailed**: Includes system information and recent alerts
- **HTML**: Formatted HTML email with tables

---

## 📊 **Monitoring and Analysis**

### Real-Time Monitoring Commands
```bash
# Monitor all logs simultaneously
tail -f logs/alert-log.txt logs/system.log logs/usb.log

# Monitor with timestamps
tail -f logs/alert-log.txt | while read line; do
    echo "$(date '+%H:%M:%S') $line"
done

# Monitor specific alert types
grep "PORT_SCAN" logs/alert-log.txt
grep "ARP_SPOOF" logs/alert-log.txt
grep "SSH_BRUTE" logs/alert-log.txt
grep "USB" logs/alert-log.txt
```

### Log Analysis
```bash
# Count alerts by type
awk -F'|' '{print $2}' logs/alert-log.txt | sort | uniq -c

# Show recent alerts
tail -20 logs/alert-log.txt

# Show alerts from last hour
grep "$(date '+%Y-%m-%d %H')" logs/alert-log.txt

# Show high-priority alerts
grep "HIGH" logs/alert-log.txt
```

### ML Analysis (Optional)
```bash
# Navigate to ML directory
cd ml_detection

# Install dependencies
pip3 install -r requirements.txt

# Run anomaly detection
python3 anomaly_detector.py

# Run with specific method
python3 anomaly_detector.py --method isolation_forest
python3 anomaly_detector.py --method kmeans
python3 anomaly_detector.py --method dbscan

# View results
ls -la results/
cat results/anomaly_report_*.json
```

---

## 🔧 **Troubleshooting**

### Common Issues and Solutions

#### Issue 1: Permission Denied
```bash
# Solution: Check and fix permissions
sudo chmod +x *.sh
sudo chmod +x modules/*.sh
sudo chmod +x test/*.sh
```

#### Issue 2: IDS Not Starting
```bash
# Check if already running
ps aux | grep ids_monitor

# Kill existing process
sudo pkill -f ids_monitor

# Check for errors
sudo ./ids_monitor.sh -v
```

#### Issue 3: No Alerts Generated
```bash
# Check configuration
cat config/thresholds.conf

# Test individual modules
sudo ./modules/arp_spoof.sh
sudo ./modules/port_scan.sh
sudo ./modules/ssh_brute.sh
sudo ./modules/usb_detect.sh

# Check log files
ls -la logs/
cat logs/system.log
```

#### Issue 4: High False Positives
```bash
# Adjust sensitivity in config
nano config/thresholds.conf

# Increase thresholds:
# ARP_SUSPICIOUS_THRESHOLD=10
# PORT_SCAN_THRESHOLD=20
# SSH_FAILURE_THRESHOLD=10
```

#### Issue 5: Missing Dependencies
```bash
# Check dependencies
sudo ./setup.sh --check-deps

# Install missing tools
sudo apt install -y [missing_tool_name]

# Verify installation
which [tool_name]
```

### Debug Mode
```bash
# Run with debug output
bash -x ./ids_monitor.sh

# Run individual modules with debug
bash -x ./modules/arp_spoof.sh
bash -x ./modules/port_scan.sh
bash -x ./modules/ssh_brute.sh
bash -x ./modules/usb_detect.sh
```

### System Resource Monitoring
```bash
# Monitor CPU and memory usage
htop

# Monitor disk usage
df -h

# Monitor network interfaces
ip addr show

# Monitor system logs
journalctl -f
```

---

## ✅ **Validation Checklist**

### Pre-Testing Setup
- [ ] ✅ Run `sudo ./setup.sh` successfully
- [ ] ✅ Install all missing dependencies
- [ ] ✅ Configure `config/thresholds.conf`
- [ ] ✅ Add trusted MACs to `config/whitelist_macs.txt`
- [ ] ✅ Start IDS: `sudo ./ids_monitor.sh -d`
- [ ] ✅ Verify IDS is running: `sudo ./ids_monitor.sh --status`

### Core Functionality Tests
- [ ] ✅ Port scanning detection: `sudo ./test/test_port_scan.sh`
- [ ] ✅ ARP spoofing detection: `sudo ./test/test_arp_spoof.sh`
- [ ] ✅ SSH brute-force detection: `sudo ./test/test_ssh_brute.sh`
- [ ] ✅ USB insertion detection: `sudo ./test/test_usb.sh`

### Advanced Tests
- [ ] ✅ ML anomaly detection: `cd ml_detection && python3 anomaly_detector.py`
- [ ] ✅ Performance under load testing
- [ ] ✅ Configuration sensitivity testing
- [ ] ✅ Log analysis and verification

### Validation Checks
- [ ] ✅ Check alert logs for expected detections
- [ ] ✅ Verify false positive rate is acceptable
- [ ] ✅ Test different sensitivity levels
- [ ] ✅ Monitor system resource usage
- [ ] ✅ Verify log rotation is working
- [ ] ✅ Test IDS restart functionality

### Expected Results
- [ ] ✅ Port scanning alerts when running `nmap`
- [ ] ✅ ARP spoofing alerts when using `arping`
- [ ] ✅ SSH brute-force alerts when using `hydra`
- [ ] ✅ USB alerts when inserting/removing devices
- [ ] ✅ System is lightweight and responsive
- [ ] ✅ Clear, actionable alerts in log files

---

## 📈 **Performance Benchmarks**

### Expected Performance Metrics
- **CPU Usage**: < 5% during normal operation
- **Memory Usage**: < 100MB
- **Disk Usage**: < 50MB for logs
- **Response Time**: < 1 second for alert generation
- **False Positive Rate**: < 10%

### Monitoring Commands
```bash
# Monitor resource usage
top -p $(pgrep ids_monitor)

# Monitor disk usage
du -sh logs/

# Monitor network activity
tcpdump -i any -c 10

# Monitor system calls
strace -p $(pgrep ids_monitor) -c
```

---

## 🎯 **Final Verification**

### Complete System Test
```bash
# Run complete verification
cat > verify_system.sh << 'EOF'
#!/bin/bash

echo "🔍 Starting Complete System Verification..."

# Check IDS status
echo "1. Checking IDS status..."
sudo ./ids_monitor.sh --status

# Check all modules
echo "2. Testing all detection modules..."
for module in arp_spoof port_scan ssh_brute usb_detect; do
    echo "Testing $module..."
    sudo ./modules/${module}.sh
done

# Check logs
echo "3. Checking log files..."
ls -la logs/
echo "Recent alerts:"
tail -5 logs/alert-log.txt

# Check configuration
echo "4. Verifying configuration..."
cat config/thresholds.conf
cat config/whitelist_macs.txt

echo "✅ System verification completed!"
EOF

chmod +x verify_system.sh
sudo ./verify_system.sh
```

---

## 📚 **Additional Resources**

### Useful Commands Reference
```bash
# IDS Management
sudo ./ids_monitor.sh -d          # Start daemon
sudo ./ids_monitor.sh --stop      # Stop daemon
sudo ./ids_monitor.sh --status    # Check status
sudo ./ids_monitor.sh -v          # Verbose mode

# Testing
sudo ./test/test_port_scan.sh     # Test port scanning
sudo ./test/test_arp_spoof.sh     # Test ARP spoofing
sudo ./test/test_ssh_brute.sh     # Test SSH brute-force
sudo ./test/test_usb.sh           # Test USB detection

# Monitoring
tail -f logs/alert-log.txt        # Monitor alerts
tail -f logs/system.log           # Monitor system logs
tail -f logs/usb.log              # Monitor USB events

# Analysis
cd ml_detection && python3 anomaly_detector.py  # ML analysis
```

### Configuration Files
- `config/thresholds.conf` - Detection sensitivity settings
- `config/whitelist_macs.txt` - Trusted MAC addresses
- `logs/alert-log.txt` - Main alert log
- `logs/system.log` - System events log
- `logs/usb.log` - USB events log

### Log File Locations
- `/path/to/IDS--v0.3/logs/alert-log.txt`
- `/path/to/IDS--v0.3/logs/system.log`
- `/path/to/IDS--v0.3/logs/usb.log`
- `/path/to/IDS--v0.3/ml_detection/anomaly_detector.log`

---

## 🎉 **Success Criteria**

Your IDS is successfully deployed when:

1. **✅ All setup steps complete without errors**
2. **✅ IDS starts and runs in daemon mode**
3. **✅ All detection modules respond to test scenarios**
4. **✅ Alerts are generated and logged properly**
5. **✅ System performance is within acceptable limits**
6. **✅ ML analysis produces meaningful results (optional)**
7. **✅ Configuration changes take effect immediately**
8. **✅ Log rotation and management work correctly**

---

**🎯 Congratulations! Your Network-Based Intrusion Detection System is now fully operational on Kali Linux!**

For support or questions, refer to the main `README.md` file or check the logs for detailed information.
