#!/bin/bash

# Network-Based Intrusion Detection System (IDS)
# Main monitoring script
# Author: [Your Name]
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config"
LOGS_DIR="$SCRIPT_DIR/logs"
MODULES_DIR="$SCRIPT_DIR/modules"
ALERT_LOG="$LOGS_DIR/alert-log.txt"
SYSTEM_LOG="$LOGS_DIR/system.log"
PID_FILE="/tmp/ids_monitor.pid"

# Default settings
LOG_FILE="$ALERT_LOG"
ENABLED_MODULES="arp_spoof,port_scan,ssh_brute,usb_detect"
CHECK_INTERVAL=5
VERBOSE=false
DAEMON_MODE=false

# Function to print colored output
print_status() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $timestamp: $message" | tee -a "$SYSTEM_LOG"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp: $message" | tee -a "$SYSTEM_LOG"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp: $message" | tee -a "$SYSTEM_LOG"
            ;;
        "ALERT")
            echo -e "${RED}[ALERT]${NC} $timestamp: $message" | tee -a "$ALERT_LOG"
            ;;
    esac
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to create necessary directories
setup_directories() {
    mkdir -p "$LOGS_DIR" "$CONFIG_DIR" "$MODULES_DIR"
    
    # Create default log files if they don't exist
    touch "$ALERT_LOG" "$SYSTEM_LOG"
    
    # Create default whitelist if it doesn't exist
    if [[ ! -f "$CONFIG_DIR/whitelist_macs.txt" ]]; then
        echo "# Trusted MAC addresses (one per line)" > "$CONFIG_DIR/whitelist_macs.txt"
        echo "# Example: 00:11:22:33:44:55" >> "$CONFIG_DIR/whitelist_macs.txt"
    fi
    
    # Create default thresholds if they don't exist
    if [[ ! -f "$CONFIG_DIR/thresholds.conf" ]]; then
        cat > "$CONFIG_DIR/thresholds.conf" << EOF
# Detection thresholds configuration
ARP_CHECK_INTERVAL=5
ARP_SUSPICIOUS_THRESHOLD=3

PORT_SCAN_WINDOW=60
PORT_SCAN_THRESHOLD=10

SSH_FAILURE_THRESHOLD=5
SSH_TIME_WINDOW=300

USB_ALERT_ENABLED=true
EOF
    fi
}

# Function to check dependencies
check_dependencies() {
    local deps=("tcpdump" "arp" "netstat" "dmesg" "udevadm" "grep" "awk" "sed")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_status "ERROR" "Missing dependencies: ${missing_deps[*]}"
        print_status "INFO" "Please install missing packages and try again"
        exit 1
    fi
    
    print_status "INFO" "All dependencies are available"
}

# Function to load configuration
load_config() {
    if [[ -f "$CONFIG_DIR/thresholds.conf" ]]; then
        source "$CONFIG_DIR/thresholds.conf"
    fi
    
    print_status "INFO" "Configuration loaded"
}

# Function to check if module exists and is executable
check_module() {
    local module="$1"
    local module_path="$MODULES_DIR/${module}.sh"
    
    if [[ ! -f "$module_path" ]]; then
        print_status "ERROR" "Module $module not found: $module_path"
        return 1
    fi
    
    if [[ ! -x "$module_path" ]]; then
        print_status "WARN" "Module $module is not executable, making it executable"
        chmod +x "$module_path"
    fi
    
    return 0
}

# Function to run a detection module
run_module() {
    local module="$1"
    local module_path="$MODULES_DIR/${module}.sh"
    
    if check_module "$module"; then
        if $VERBOSE; then
            print_status "INFO" "Running module: $module"
        fi
        
        # Run module and capture output
        local output
        if output=$("$module_path" 2>&1); then
            if [[ -n "$output" ]]; then
                print_status "ALERT" "[$module] $output"
            fi
        else
            print_status "ERROR" "Module $module failed: $output"
        fi
    fi
}

# Function to run all enabled modules
run_detection_cycle() {
    local IFS=','
    for module in $ENABLED_MODULES; do
        run_module "$module" &
    done
    wait
}

# Function to monitor system resources
monitor_resources() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    local memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        print_status "WARN" "High CPU usage: ${cpu_usage}%"
    fi
    
    if (( $(echo "$memory_usage > 80" | bc -l) )); then
        print_status "WARN" "High memory usage: ${memory_usage}%"
    fi
    
    if [[ $disk_usage -gt 80 ]]; then
        print_status "WARN" "High disk usage: ${disk_usage}%"
    fi
}

# Function to rotate logs
rotate_logs() {
    local max_size_mb=10
    local max_size_bytes=$((max_size_mb * 1024 * 1024))
    
    for log_file in "$ALERT_LOG" "$SYSTEM_LOG"; do
        if [[ -f "$log_file" ]] && [[ $(stat -c%s "$log_file") -gt $max_size_bytes ]]; then
            local backup_file="${log_file}.$(date +%Y%m%d_%H%M%S)"
            mv "$log_file" "$backup_file"
            touch "$log_file"
            print_status "INFO" "Rotated log file: $backup_file"
        fi
    done
}

# Function to show help
show_help() {
    cat << EOF
Network-Based Intrusion Detection System (IDS)

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -d, --daemon            Run in daemon mode
    -l, --log-file FILE     Specify custom log file
    -m, --modules LIST      Comma-separated list of modules to run
    -i, --interval SECONDS  Set check interval (default: 5)
    --status                Show current status
    --stop                  Stop the daemon

Modules:
    arp_spoof              ARP spoofing detection
    port_scan              Port scanning detection
    ssh_brute              SSH brute-force detection
    usb_detect             USB insertion detection

Examples:
    $0                      # Start with default settings
    $0 -v -m arp_spoof     # Run only ARP spoofing detection with verbose output
    $0 -d -i 10            # Run as daemon with 10-second intervals
    $0 --status            # Show current status
    $0 --stop              # Stop the daemon

EOF
}

# Function to show status
show_status() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_status "INFO" "IDS is running (PID: $pid)"
            echo "Log files:"
            echo "  Alert log: $ALERT_LOG"
            echo "  System log: $SYSTEM_LOG"
            echo "Recent alerts:"
            tail -5 "$ALERT_LOG" 2>/dev/null || echo "  No alerts yet"
        else
            print_status "WARN" "PID file exists but process is not running"
            rm -f "$PID_FILE"
        fi
    else
        print_status "INFO" "IDS is not running"
    fi
}

# Function to stop daemon
stop_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            rm -f "$PID_FILE"
            print_status "INFO" "IDS daemon stopped (PID: $pid)"
        else
            print_status "WARN" "Process not running, removing stale PID file"
            rm -f "$PID_FILE"
        fi
    else
        print_status "INFO" "No PID file found"
    fi
}

# Function to start daemon
start_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_status "ERROR" "IDS is already running (PID: $pid)"
            exit 1
        else
            rm -f "$PID_FILE"
        fi
    fi
    
    print_status "INFO" "Starting IDS daemon..."
    nohup "$0" --daemon > /dev/null 2>&1 &
    echo $! > "$PID_FILE"
    print_status "INFO" "IDS daemon started (PID: $!)"
}

# Function to run main monitoring loop
run_monitoring_loop() {
    print_status "INFO" "Starting IDS monitoring..."
    print_status "INFO" "Enabled modules: $ENABLED_MODULES"
    print_status "INFO" "Check interval: ${CHECK_INTERVAL}s"
    print_status "INFO" "Log file: $LOG_FILE"
    
    # Trap signals for graceful shutdown
    trap 'print_status "INFO" "Shutting down IDS..."; exit 0' SIGTERM SIGINT
    
    local cycle_count=0
    
    while true; do
        cycle_count=$((cycle_count + 1))
        
        if $VERBOSE; then
            print_status "INFO" "Starting detection cycle #$cycle_count"
        fi
        
        # Run detection modules
        run_detection_cycle
        
        # Monitor system resources
        monitor_resources
        
        # Rotate logs if needed
        rotate_logs
        
        if $VERBOSE; then
            print_status "INFO" "Completed detection cycle #$cycle_count"
        fi
        
        sleep "$CHECK_INTERVAL"
    done
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -d|--daemon)
            DAEMON_MODE=true
            shift
            ;;
        -l|--log-file)
            LOG_FILE="$2"
            ALERT_LOG="$LOG_FILE"
            shift 2
            ;;
        -m|--modules)
            ENABLED_MODULES="$2"
            shift 2
            ;;
        -i|--interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        --status)
            show_status
            exit 0
            ;;
        --stop)
            stop_daemon
            exit 0
            ;;
        *)
            print_status "ERROR" "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
main() {
    check_root
    setup_directories
    check_dependencies
    load_config
    
    if $DAEMON_MODE; then
        run_monitoring_loop
    else
        if [[ -f "$PID_FILE" ]]; then
            local pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                print_status "ERROR" "IDS daemon is already running (PID: $pid)"
                print_status "INFO" "Use '$0 --stop' to stop the daemon"
                exit 1
            fi
        fi
        
        start_daemon
    fi
}

# Run main function
main "$@"
