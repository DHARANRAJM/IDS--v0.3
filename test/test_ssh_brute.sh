#!/bin/bash

# SSH Brute-force Test Script
# Simulates SSH brute-force attacks to test the IDS
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
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

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
    esac
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to check dependencies
check_dependencies() {
    local deps=("ssh" "hydra" "nmap" "medusa" "patator")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_status "WARN" "Missing dependencies: ${missing_deps[*]}"
        print_status "INFO" "Some tests may not work without these tools"
    else
        print_status "INFO" "All dependencies are available"
    fi
}

# Function to check SSH service status
check_ssh_service() {
    if ! systemctl is-active --quiet sshd && ! systemctl is-active --quiet ssh; then
        print_status "WARN" "SSH service is not running"
        print_status "INFO" "Starting SSH service for testing..."
        systemctl start sshd 2>/dev/null || systemctl start ssh 2>/dev/null || true
    fi
}

# Function to test basic SSH connection attempts
test_basic_ssh_attempts() {
    print_status "INFO" "Starting basic SSH connection attempts test..."
    
    # Test 1: Basic SSH connection attempts
    print_status "INFO" "Test 1: Basic SSH connection attempts"
    
    local test_users=("root" "admin" "user" "test" "guest")
    local test_passwords=("password" "123456" "admin" "root" "test")
    
    for user in "${test_users[@]}"; do
        for password in "${test_passwords[@]}"; do
            print_status "INFO" "Testing SSH login: $user:$password"
            timeout 5 sshpass -p "$password" ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no "$user@localhost" exit 2>/dev/null || true
        done
    done
    
    print_status "INFO" "Basic SSH connection attempts test completed"
}

# Function to test rapid SSH attempts
test_rapid_ssh_attempts() {
    print_status "INFO" "Starting rapid SSH attempts test..."
    
    # Test 2: Rapid successive attempts
    print_status "INFO" "Test 2: Rapid successive SSH attempts"
    
    for i in {1..20}; do
        print_status "INFO" "Rapid attempt $i"
        timeout 2 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no "fakeuser@localhost" exit 2>/dev/null || true
    done
    
    print_status "INFO" "Rapid SSH attempts test completed"
}

# Function to test dictionary attack simulation
test_dictionary_attack() {
    print_status "INFO" "Starting dictionary attack simulation test..."
    
    # Test 3: Dictionary attack with hydra
    print_status "INFO" "Test 3: Dictionary attack with hydra"
    
    # Create a small wordlist for testing
    local wordlist="/tmp/test_wordlist.txt"
    cat > "$wordlist" << EOF
password
123456
admin
root
test
user
guest
secret
qwerty
letmein
EOF
    
    # Run hydra attack
    print_status "INFO" "Running hydra SSH attack..."
    timeout 30 hydra -l root -P "$wordlist" -t 4 ssh://localhost 2>/dev/null || true
    
    # Clean up
    rm -f "$wordlist"
    
    print_status "INFO" "Dictionary attack simulation test completed"
}

# Function to test username enumeration
test_username_enumeration() {
    print_status "INFO" "Starting username enumeration test..."
    
    # Test 4: Username enumeration
    print_status "INFO" "Test 4: Username enumeration"
    
    local common_users=("root" "admin" "user" "test" "guest" "administrator" "manager" "operator" "service" "system")
    
    for user in "${common_users[@]}"; do
        print_status "INFO" "Testing username: $user"
        timeout 3 ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no "$user@localhost" exit 2>/dev/null || true
    done
    
    print_status "INFO" "Username enumeration test completed"
}

# Function to test brute-force with different tools
test_brute_force_tools() {
    print_status "INFO" "Starting brute-force tools test..."
    
    # Test 5: Using nmap for SSH brute-force
    print_status "INFO" "Test 5: Using nmap for SSH brute-force"
    
    # Create a simple user/pass list
    local userpass_file="/tmp/ssh_userpass.txt"
    cat > "$userpass_file" << EOF
root:password
admin:admin
user:user
test:test
EOF
    
    # Run nmap SSH brute-force
    print_status "INFO" "Running nmap SSH brute-force..."
    timeout 30 nmap --script ssh-brute --script-args userdb="$userpass_file",passdb="$userpass_file" localhost 2>/dev/null || true
    
    # Clean up
    rm -f "$userpass_file"
    
    print_status "INFO" "Brute-force tools test completed"
}

# Function to test SSH service monitoring
test_ssh_service_monitoring() {
    print_status "INFO" "Starting SSH service monitoring test..."
    
    # Test 6: Monitor SSH service logs
    print_status "INFO" "Test 6: Monitoring SSH service logs"
    
    # Check SSH logs
    local log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/messages")
    
    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            print_status "INFO" "Checking SSH logs in: $log_file"
            grep -i "sshd" "$log_file" | tail -10 || true
        fi
    done
    
    print_status "INFO" "SSH service monitoring test completed"
}

# Function to test SSH configuration vulnerabilities
test_ssh_config_vulnerabilities() {
    print_status "INFO" "Starting SSH configuration vulnerabilities test..."
    
    # Test 7: Check SSH configuration
    print_status "INFO" "Test 7: Checking SSH configuration vulnerabilities"
    
    local ssh_config="/etc/ssh/sshd_config"
    if [[ -f "$ssh_config" ]]; then
        print_status "INFO" "Checking SSH configuration..."
        
        # Check for weak configurations
        if grep -q "PermitRootLogin yes" "$ssh_config"; then
            print_status "WARN" "Root login is enabled in SSH configuration"
        fi
        
        if grep -q "PasswordAuthentication yes" "$ssh_config"; then
            print_status "WARN" "Password authentication is enabled in SSH configuration"
        fi
        
        if grep -q "Protocol 1" "$ssh_config"; then
            print_status "WARN" "SSH Protocol 1 is enabled (insecure)"
        fi
    fi
    
    print_status "INFO" "SSH configuration vulnerabilities test completed"
}

# Function to test SSH brute-force detection
test_ssh_brute_detection() {
    print_status "INFO" "Starting SSH brute-force detection test..."
    
    # Test 8: Test IDS SSH brute-force detection
    print_status "INFO" "Test 8: Testing IDS SSH brute-force detection"
    
    # Run the SSH brute-force detection module
    if [[ -f "$PROJECT_DIR/modules/ssh_brute.sh" ]]; then
        print_status "INFO" "Running SSH brute-force detection module"
        "$PROJECT_DIR/modules/ssh_brute.sh"
    else
        print_status "WARN" "SSH brute-force detection module not found"
    fi
    
    print_status "INFO" "SSH brute-force detection test completed"
}

# Function to test SSH connection patterns
test_ssh_connection_patterns() {
    print_status "INFO" "Starting SSH connection patterns test..."
    
    # Test 9: Test different SSH connection patterns
    print_status "INFO" "Test 9: Testing SSH connection patterns"
    
    # Test with different SSH options
    local ssh_options=(
        "-o ConnectTimeout=1"
        "-o ConnectTimeout=1 -o StrictHostKeyChecking=no"
        "-o ConnectTimeout=1 -o UserKnownHostsFile=/dev/null"
        "-o ConnectTimeout=1 -o PasswordAuthentication=yes"
    )
    
    for options in "${ssh_options[@]}"; do
        print_status "INFO" "Testing SSH with options: $options"
        timeout 3 ssh $options fakeuser@localhost exit 2>/dev/null || true
    done
    
    print_status "INFO" "SSH connection patterns test completed"
}

# Function to show test results
show_test_results() {
    print_status "INFO" "SSH brute-force tests completed"
    print_status "INFO" "Check the IDS logs for detection alerts:"
    echo "  Alert log: $PROJECT_DIR/logs/alert-log.txt"
    echo "  System log: $PROJECT_DIR/logs/system.log"
    
    print_status "INFO" "Recent SSH-related alerts:"
    if [[ -f "$PROJECT_DIR/logs/alert-log.txt" ]]; then
        tail -10 "$PROJECT_DIR/logs/alert-log.txt" | grep -i "ssh" 2>/dev/null || echo "  No SSH alerts yet"
    else
        echo "  No alert log file found"
    fi
    
    print_status "INFO" "Recent SSH auth logs:"
    if [[ -f "/var/log/auth.log" ]]; then
        tail -5 /var/log/auth.log | grep -i "sshd" 2>/dev/null || echo "  No recent SSH auth logs"
    fi
}

# Function to show help
show_help() {
    cat << EOF
SSH Brute-force Test Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -b, --basic             Run basic SSH connection tests only
    -r, --rapid             Run rapid SSH attempts tests only
    -d, --dictionary        Run dictionary attack tests only
    -e, --enumeration       Run username enumeration tests only
    -t, --tools             Run brute-force tools tests only
    -m, --monitoring        Run SSH service monitoring tests only
    -c, --config            Run SSH configuration tests only
    --all                   Run all tests (default)

Tests:
    Basic: Simple SSH connection attempts
    Rapid: High-speed successive attempts
    Dictionary: Dictionary-based attacks
    Enumeration: Username enumeration
    Tools: Different brute-force tools
    Monitoring: SSH service monitoring
    Config: SSH configuration vulnerabilities

Examples:
    $0                      # Run all tests
    $0 -b                   # Run basic tests only
    $0 -d -e                # Run dictionary and enumeration tests

Note: This script simulates SSH brute-force attacks.
      Make sure the IDS is running to detect these tests.

EOF
}

# Main execution
main() {
    local run_basic=false
    local run_rapid=false
    local run_dictionary=false
    local run_enumeration=false
    local run_tools=false
    local run_monitoring=false
    local run_config=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -b|--basic)
                run_basic=true
                shift
                ;;
            -r|--rapid)
                run_rapid=true
                shift
                ;;
            -d|--dictionary)
                run_dictionary=true
                shift
                ;;
            -e|--enumeration)
                run_enumeration=true
                shift
                ;;
            -t|--tools)
                run_tools=true
                shift
                ;;
            -m|--monitoring)
                run_monitoring=true
                shift
                ;;
            -c|--config)
                run_config=true
                shift
                ;;
            --all)
                run_basic=true
                run_rapid=true
                run_dictionary=true
                run_enumeration=true
                run_tools=true
                run_monitoring=true
                run_config=true
                shift
                ;;
            *)
                print_status "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # If no specific tests selected, run all
    if [[ "$run_basic" == "false" && "$run_rapid" == "false" && "$run_dictionary" == "false" && "$run_enumeration" == "false" && "$run_tools" == "false" && "$run_monitoring" == "false" && "$run_config" == "false" ]]; then
        run_basic=true
        run_rapid=true
        run_dictionary=true
        run_enumeration=true
        run_tools=true
        run_monitoring=true
        run_config=true
    fi
    
    # Check prerequisites
    check_root
    check_dependencies
    check_ssh_service
    
    print_status "INFO" "Starting SSH brute-force tests..."
    print_status "INFO" "Make sure the IDS is running to detect these tests"
    
    # Run selected tests
    if $run_basic; then
        test_basic_ssh_attempts
    fi
    
    if $run_rapid; then
        test_rapid_ssh_attempts
    fi
    
    if $run_dictionary; then
        test_dictionary_attack
    fi
    
    if $run_enumeration; then
        test_username_enumeration
    fi
    
    if $run_tools; then
        test_brute_force_tools
    fi
    
    if $run_monitoring; then
        test_ssh_service_monitoring
    fi
    
    if $run_config; then
        test_ssh_config_vulnerabilities
    fi
    
    # Additional tests
    test_ssh_brute_detection
    test_ssh_connection_patterns
    
    # Show results
    show_test_results
}

# Run main function
main "$@"
