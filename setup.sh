#!/bin/bash

# Network-Based Intrusion Detection System (IDS) - Setup Script
# Sets up the IDS environment and makes all scripts executable
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

# Function to print colored output
print_status() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $timestamp: $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp: $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp: $message"
            ;;
        "SUCCESS")
            echo -e "${BLUE}[SUCCESS]${NC} $timestamp: $message"
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

# Function to check system requirements
check_system_requirements() {
    print_status "INFO" "Checking system requirements..."
    
    # Check OS
    if [[ -f /etc/os-release ]]; then
        local os_name=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2)
        print_status "INFO" "Operating System: $os_name"
    else
        print_status "WARN" "Could not determine operating system"
    fi
    
    # Check kernel version
    local kernel_version=$(uname -r)
    print_status "INFO" "Kernel Version: $kernel_version"
    
    # Check available memory
    local total_mem=$(free -m | grep Mem | awk '{print $2}')
    print_status "INFO" "Total Memory: ${total_mem}MB"
    
    if [[ $total_mem -lt 512 ]]; then
        print_status "WARN" "Low memory detected. IDS may run slowly."
    fi
    
    # Check disk space
    local available_space=$(df / | tail -1 | awk '{print $4}')
    print_status "INFO" "Available Disk Space: ${available_space}KB"
    
    if [[ $available_space -lt 1048576 ]]; then  # Less than 1GB
        print_status "WARN" "Low disk space detected. Consider cleaning up."
    fi
}

# Function to check dependencies
check_dependencies() {
    print_status "INFO" "Checking dependencies..."
    
    local deps=(
        "bash" "grep" "awk" "sed" "sort" "uniq" "wc" "head" "tail"
        "tcpdump" "arp" "netstat" "dmesg" "udevadm" "lsusb"
        "nmap" "hydra" "arping" "ip" "ping" "mount"
    )
    
    local missing_deps=()
    local available_deps=()
    
    for dep in "${deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            available_deps+=("$dep")
        else
            missing_deps+=("$dep")
        fi
    done
    
    print_status "INFO" "Available dependencies (${#available_deps[@]}/${#deps[@]}):"
    for dep in "${available_deps[@]}"; do
        echo "  ✓ $dep"
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_status "WARN" "Missing dependencies (${#missing_deps[@]}):"
        for dep in "${missing_deps[@]}"; do
            echo "  ✗ $dep"
        done
        
        print_status "INFO" "Install missing dependencies with:"
        echo "  sudo apt-get install ${missing_deps[*]}"
    fi
}

# Function to create directory structure
create_directory_structure() {
    print_status "INFO" "Creating directory structure..."
    
    local directories=(
        "logs"
        "config"
        "modules"
        "test"
        "ml_detection"
        "ml_detection/results"
        "ml_detection/models"
    )
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            print_status "INFO" "Created directory: $dir"
        else
            print_status "INFO" "Directory exists: $dir"
        fi
    done
}

# Function to make scripts executable
make_scripts_executable() {
    print_status "INFO" "Making scripts executable..."
    
    local scripts=(
        "ids_monitor.sh"
        "modules/arp_spoof.sh"
        "modules/port_scan.sh"
        "modules/ssh_brute.sh"
        "modules/usb_detect.sh"
        "test/test_port_scan.sh"
        "test/test_arp_spoof.sh"
        "test/test_ssh_brute.sh"
        "test/test_usb.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$script" ]]; then
            chmod +x "$script"
            print_status "INFO" "Made executable: $script"
        else
            print_status "WARN" "Script not found: $script"
        fi
    done
}

# Function to create log files
create_log_files() {
    print_status "INFO" "Creating log files..."
    
    local log_files=(
        "logs/alert-log.txt"
        "logs/system.log"
        "logs/usb.log"
    )
    
    for log_file in "${log_files[@]}"; do
        if [[ ! -f "$log_file" ]]; then
            touch "$log_file"
            print_status "INFO" "Created log file: $log_file"
        else
            print_status "INFO" "Log file exists: $log_file"
        fi
    done
}

# Function to check Python ML dependencies
check_python_dependencies() {
    print_status "INFO" "Checking Python ML dependencies..."
    
    if command -v python3 &> /dev/null; then
        print_status "INFO" "Python 3 is available"
        
        # Check if pip is available
        if command -v pip3 &> /dev/null; then
            print_status "INFO" "pip3 is available"
            
            # Check ML dependencies
            local ml_deps=("numpy" "pandas" "scikit-learn" "matplotlib" "seaborn")
            local missing_ml_deps=()
            
            for dep in "${ml_deps[@]}"; do
                if python3 -c "import $dep" 2>/dev/null; then
                    print_status "INFO" "✓ $dep is installed"
                else
                    missing_ml_deps+=("$dep")
                fi
            done
            
            if [[ ${#missing_ml_deps[@]} -gt 0 ]]; then
                print_status "WARN" "Missing Python ML dependencies:"
                for dep in "${missing_ml_deps[@]}"; do
                    echo "  ✗ $dep"
                done
                
                print_status "INFO" "Install ML dependencies with:"
                echo "  pip3 install -r ml_detection/requirements.txt"
            fi
        else
            print_status "WARN" "pip3 not found. Install with: sudo apt-get install python3-pip"
        fi
    else
        print_status "WARN" "Python 3 not found. Install with: sudo apt-get install python3"
    fi
}

# Function to validate configuration files
validate_configuration() {
    print_status "INFO" "Validating configuration files..."
    
    # Check thresholds configuration
    if [[ -f "config/thresholds.conf" ]]; then
        print_status "INFO" "✓ Thresholds configuration exists"
        
        # Validate configuration values
        source "config/thresholds.conf" 2>/dev/null || true
        
        if [[ -n "${ARP_CHECK_INTERVAL:-}" ]]; then
            print_status "INFO" "  ARP_CHECK_INTERVAL: $ARP_CHECK_INTERVAL"
        fi
        
        if [[ -n "${PORT_SCAN_THRESHOLD:-}" ]]; then
            print_status "INFO" "  PORT_SCAN_THRESHOLD: $PORT_SCAN_THRESHOLD"
        fi
        
        if [[ -n "${SSH_FAILURE_THRESHOLD:-}" ]]; then
            print_status "INFO" "  SSH_FAILURE_THRESHOLD: $SSH_FAILURE_THRESHOLD"
        fi
    else
        print_status "WARN" "✗ Thresholds configuration not found"
    fi
    
    # Check whitelist configuration
    if [[ -f "config/whitelist_macs.txt" ]]; then
        print_status "INFO" "✓ MAC whitelist exists"
        local whitelist_count=$(grep -v "^#" "config/whitelist_macs.txt" | grep -v "^$" | wc -l)
        print_status "INFO" "  Whitelist entries: $whitelist_count"
    else
        print_status "WARN" "✗ MAC whitelist not found"
    fi
}

# Function to test IDS modules
test_ids_modules() {
    print_status "INFO" "Testing IDS modules..."
    
    local modules=(
        "modules/arp_spoof.sh"
        "modules/port_scan.sh"
        "modules/ssh_brute.sh"
        "modules/usb_detect.sh"
    )
    
    for module in "${modules[@]}"; do
        if [[ -f "$module" && -x "$module" ]]; then
            print_status "INFO" "Testing module: $module"
            
            # Test module syntax
            if bash -n "$module" 2>/dev/null; then
                print_status "INFO" "  ✓ Syntax OK"
            else
                print_status "WARN" "  ✗ Syntax errors found"
            fi
        else
            print_status "WARN" "Module not found or not executable: $module"
        fi
    done
}

# Function to show usage instructions
show_usage_instructions() {
    print_status "SUCCESS" "IDS setup completed successfully!"
    
    echo
    echo "=== USAGE INSTRUCTIONS ==="
    echo
    echo "1. Start the IDS:"
    echo "   sudo ./ids_monitor.sh"
    echo
    echo "2. Start with specific modules:"
    echo "   sudo ./ids_monitor.sh --modules arp_spoof,port_scan"
    echo
    echo "3. Start in daemon mode:"
    echo "   sudo ./ids_monitor.sh -d"
    echo
    echo "4. Check IDS status:"
    echo "   sudo ./ids_monitor.sh --status"
    echo
    echo "5. Stop the IDS:"
    echo "   sudo ./ids_monitor.sh --stop"
    echo
    echo "=== TESTING ==="
    echo
    echo "6. Test port scanning detection:"
    echo "   sudo ./test/test_port_scan.sh"
    echo
    echo "7. Test ARP spoofing detection:"
    echo "   sudo ./test/test_arp_spoof.sh"
    echo
    echo "8. Test SSH brute-force detection:"
    echo "   sudo ./test/test_ssh_brute.sh"
    echo
    echo "9. Test USB insertion detection:"
    echo "   sudo ./test/test_usb.sh"
    echo
    echo "=== ML ANALYSIS ==="
    echo
    echo "10. Run ML anomaly detection:"
    echo "    cd ml_detection && python3 anomaly_detector.py"
    echo
    echo "=== LOGS ==="
    echo
    echo "11. Monitor alerts:"
    echo "    tail -f logs/alert-log.txt"
    echo
    echo "12. Monitor system logs:"
    echo "    tail -f logs/system.log"
    echo
    echo "=== CONFIGURATION ==="
    echo
    echo "13. Edit detection thresholds:"
    echo "    nano config/thresholds.conf"
    echo
    echo "14. Add trusted MAC addresses:"
    echo "    nano config/whitelist_macs.txt"
    echo
    echo "=== TROUBLESHOOTING ==="
    echo
    echo "15. Check dependencies:"
    echo "    sudo ./setup.sh --check-deps"
    echo
    echo "16. View help:"
    echo "    sudo ./ids_monitor.sh --help"
    echo
}

# Function to show help
show_help() {
    cat << EOF
Network-Based Intrusion Detection System (IDS) - Setup Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    --check-deps            Check dependencies only
    --test-modules          Test IDS modules only
    --validate-config       Validate configuration only
    --full-setup            Run full setup (default)

Actions:
    Full Setup: Complete environment setup
    Check Dependencies: Verify system requirements
    Test Modules: Validate IDS module syntax
    Validate Config: Check configuration files

Examples:
    $0                      # Run full setup
    $0 --check-deps         # Check dependencies only
    $0 --test-modules       # Test modules only

EOF
}

# Main execution
main() {
    local check_deps_only=false
    local test_modules_only=false
    local validate_config_only=false
    local full_setup=true
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --check-deps)
                check_deps_only=true
                full_setup=false
                shift
                ;;
            --test-modules)
                test_modules_only=true
                full_setup=false
                shift
                ;;
            --validate-config)
                validate_config_only=true
                full_setup=false
                shift
                ;;
            --full-setup)
                full_setup=true
                shift
                ;;
            *)
                print_status "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_status "INFO" "Starting IDS setup..."
    
    # Check if running as root
    check_root
    
    if $check_deps_only; then
        check_system_requirements
        check_dependencies
        check_python_dependencies
        exit 0
    fi
    
    if $test_modules_only; then
        test_ids_modules
        exit 0
    fi
    
    if $validate_config_only; then
        validate_configuration
        exit 0
    fi
    
    if $full_setup; then
        # Run full setup
        check_system_requirements
        check_dependencies
        create_directory_structure
        make_scripts_executable
        create_log_files
        check_python_dependencies
        validate_configuration
        test_ids_modules
        
        # Show usage instructions
        show_usage_instructions
    fi
}

# Run main function
main "$@"
