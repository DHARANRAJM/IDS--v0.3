#!/bin/bash

# Port Scanning Test Script
# Simulates port scanning activities to test the IDS
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
    local deps=("nmap" "netcat" "telnet" "curl")
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

# Function to test basic port scanning
test_basic_port_scan() {
    print_status "INFO" "Starting basic port scan test..."
    
    # Test 1: Scan common ports
    print_status "INFO" "Test 1: Scanning common ports (1-1000)"
    nmap -sS -p 1-1000 localhost 2>/dev/null || true
    
    # Test 2: Scan specific service ports
    print_status "INFO" "Test 2: Scanning specific service ports"
    nmap -sS -p 21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,5900,8080 localhost 2>/dev/null || true
    
    print_status "INFO" "Basic port scan test completed"
}

# Function to test rapid port scanning
test_rapid_port_scan() {
    print_status "INFO" "Starting rapid port scan test..."
    
    # Test 3: Rapid sequential port scanning
    print_status "INFO" "Test 3: Rapid sequential port scanning"
    for port in {1..50}; do
        timeout 1 bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null || true
    done
    
    # Test 4: Multiple port scanning tools
    print_status "INFO" "Test 4: Using multiple scanning methods"
    
    # Netcat scan
    for port in 22 80 443 8080; do
        timeout 1 nc -zv localhost $port 2>/dev/null || true
    done
    
    # Telnet scan
    for port in 22 23 80; do
        timeout 1 telnet localhost $port 2>/dev/null || true
    done
    
    print_status "INFO" "Rapid port scan test completed"
}

# Function to test port scanning with different techniques
test_advanced_port_scan() {
    print_status "INFO" "Starting advanced port scan test..."
    
    # Test 5: TCP SYN scan
    print_status "INFO" "Test 5: TCP SYN scan"
    nmap -sS -p 1-100 localhost 2>/dev/null || true
    
    # Test 6: UDP scan
    print_status "INFO" "Test 6: UDP scan"
    nmap -sU -p 53,67,68,69,123,161,162,514 localhost 2>/dev/null || true
    
    # Test 7: Service version detection
    print_status "INFO" "Test 7: Service version detection"
    nmap -sV -p 22,80,443 localhost 2>/dev/null || true
    
    print_status "INFO" "Advanced port scan test completed"
}

# Function to test connection rate limiting
test_connection_rate() {
    print_status "INFO" "Starting connection rate test..."
    
    # Test 8: High connection rate
    print_status "INFO" "Test 8: High connection rate"
    for i in {1..100}; do
        timeout 0.1 bash -c "echo >/dev/tcp/localhost/80" 2>/dev/null || true
    done
    
    # Test 9: Multiple simultaneous connections
    print_status "INFO" "Test 9: Multiple simultaneous connections"
    for i in {1..20}; do
        (timeout 2 bash -c "echo >/dev/tcp/localhost/22" 2>/dev/null || true) &
    done
    wait
    
    print_status "INFO" "Connection rate test completed"
}

# Function to test port scanning from different sources
test_multiple_sources() {
    print_status "INFO" "Starting multiple source test..."
    
    # Test 10: Scan from different local interfaces
    print_status "INFO" "Test 10: Scanning from different interfaces"
    
    # Get local IP addresses
    local ips=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' || echo "127.0.0.1")
    
    for ip in $ips; do
        print_status "INFO" "Scanning from $ip"
        nmap -sS -p 22,80,443 "$ip" 2>/dev/null || true
    done
    
    print_status "INFO" "Multiple source test completed"
}

# Function to test stealth scanning
test_stealth_scanning() {
    print_status "INFO" "Starting stealth scanning test..."
    
    # Test 11: Slow scan
    print_status "INFO" "Test 11: Slow scan (may take time)"
    nmap -sS -T1 -p 1-50 localhost 2>/dev/null || true
    
    # Test 12: Fragmented scan
    print_status "INFO" "Test 12: Fragmented scan"
    nmap -sS -f -p 22,80,443 localhost 2>/dev/null || true
    
    print_status "INFO" "Stealth scanning test completed"
}

# Function to show test results
show_test_results() {
    print_status "INFO" "Port scanning tests completed"
    print_status "INFO" "Check the IDS logs for detection alerts:"
    echo "  Alert log: $PROJECT_DIR/logs/alert-log.txt"
    echo "  System log: $PROJECT_DIR/logs/system.log"
    
    print_status "INFO" "Recent alerts:"
    if [[ -f "$PROJECT_DIR/logs/alert-log.txt" ]]; then
        tail -10 "$PROJECT_DIR/logs/alert-log.txt" 2>/dev/null || echo "  No alerts yet"
    else
        echo "  No alert log file found"
    fi
}

# Function to show help
show_help() {
    cat << EOF
Port Scanning Test Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -b, --basic             Run basic port scan tests only
    -r, --rapid             Run rapid port scan tests only
    -a, --advanced          Run advanced port scan tests only
    -s, --stealth           Run stealth scanning tests only
    --all                   Run all tests (default)

Tests:
    Basic: Common port scanning with nmap
    Rapid: High-speed sequential port scanning
    Advanced: Different scanning techniques
    Stealth: Slow and fragmented scanning

Examples:
    $0                      # Run all tests
    $0 -b                   # Run basic tests only
    $0 -r -a                # Run rapid and advanced tests

Note: This script simulates port scanning activities.
      Make sure the IDS is running to detect these tests.

EOF
}

# Main execution
main() {
    local run_basic=false
    local run_rapid=false
    local run_advanced=false
    local run_stealth=false
    
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
            -a|--advanced)
                run_advanced=true
                shift
                ;;
            -s|--stealth)
                run_stealth=true
                shift
                ;;
            --all)
                run_basic=true
                run_rapid=true
                run_advanced=true
                run_stealth=true
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
    if [[ "$run_basic" == "false" && "$run_rapid" == "false" && "$run_advanced" == "false" && "$run_stealth" == "false" ]]; then
        run_basic=true
        run_rapid=true
        run_advanced=true
        run_stealth=true
    fi
    
    # Check prerequisites
    check_root
    check_dependencies
    
    print_status "INFO" "Starting port scanning tests..."
    print_status "INFO" "Make sure the IDS is running to detect these tests"
    
    # Run selected tests
    if $run_basic; then
        test_basic_port_scan
    fi
    
    if $run_rapid; then
        test_rapid_port_scan
    fi
    
    if $run_advanced; then
        test_advanced_port_scan
    fi
    
    if $run_stealth; then
        test_stealth_scanning
    fi
    
    # Additional tests
    test_connection_rate
    test_multiple_sources
    
    # Show results
    show_test_results
}

# Run main function
main "$@"
