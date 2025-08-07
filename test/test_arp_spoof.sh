#!/bin/bash

# ARP Spoofing Test Script
# Simulates ARP spoofing activities to test the IDS
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
    local deps=("arp" "arping" "ip" "ping" "tcpdump")
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

# Function to get network interfaces
get_interfaces() {
    ip link show | grep -E "^[0-9]+:" | awk -F: '{print $2}' | tr -d ' '
}

# Function to get local IP addresses
get_local_ips() {
    ip addr show | grep -E "inet " | awk '{print $2}' | cut -d/ -f1
}

# Function to test basic ARP manipulation
test_basic_arp_manipulation() {
    print_status "INFO" "Starting basic ARP manipulation test..."
    
    # Test 1: View current ARP table
    print_status "INFO" "Test 1: Viewing current ARP table"
    arp -n
    
    # Test 2: Add a static ARP entry
    print_status "INFO" "Test 2: Adding static ARP entry"
    local gateway_ip=$(ip route | grep default | awk '{print $3}' | head -1)
    if [[ -n "$gateway_ip" ]]; then
        local fake_mac="00:11:22:33:44:55"
        arp -s "$gateway_ip" "$fake_mac" || true
        print_status "INFO" "Added static ARP entry: $gateway_ip -> $fake_mac"
        
        # Verify the entry
        arp -n | grep "$gateway_ip"
        
        # Clean up
        arp -d "$gateway_ip" || true
    fi
    
    print_status "INFO" "Basic ARP manipulation test completed"
}

# Function to test ARP spoofing simulation
test_arp_spoofing_simulation() {
    print_status "INFO" "Starting ARP spoofing simulation test..."
    
    # Test 3: Simulate ARP spoofing with arping
    print_status "INFO" "Test 3: Simulating ARP spoofing with arping"
    
    local interfaces=$(get_interfaces)
    local local_ips=$(get_local_ips)
    
    for interface in $interfaces; do
        if [[ "$interface" != "lo" ]]; then
            for ip in $local_ips; do
                if [[ "$ip" != "127.0.0.1" ]]; then
                    print_status "INFO" "Testing ARP spoofing on interface $interface with IP $ip"
                    
                    # Send spoofed ARP packets
                    timeout 5 arping -I "$interface" -s "$ip" "$ip" 2>/dev/null || true
                    
                    # Check ARP table for changes
                    arp -n | grep "$ip"
                fi
            done
        fi
    done
    
    print_status "INFO" "ARP spoofing simulation test completed"
}

# Function to test ARP cache poisoning
test_arp_cache_poisoning() {
    print_status "INFO" "Starting ARP cache poisoning test..."
    
    # Test 4: Monitor ARP traffic
    print_status "INFO" "Test 4: Monitoring ARP traffic"
    
    # Start tcpdump to monitor ARP packets
    timeout 10 tcpdump -i any -n arp 2>/dev/null | head -20 || true
    
    # Test 5: Send fake ARP replies
    print_status "INFO" "Test 5: Sending fake ARP replies"
    
    local gateway_ip=$(ip route | grep default | awk '{print $3}' | head -1)
    if [[ -n "$gateway_ip" ]]; then
        local fake_mac="aa:bb:cc:dd:ee:ff"
        
        # Send fake ARP reply
        arping -I eth0 -s "$gateway_ip" "$gateway_ip" 2>/dev/null || true
        
        # Check if ARP table was poisoned
        arp -n | grep "$gateway_ip"
    fi
    
    print_status "INFO" "ARP cache poisoning test completed"
}

# Function to test ARP flooding
test_arp_flooding() {
    print_status "INFO" "Starting ARP flooding test..."
    
    # Test 6: ARP flooding attack simulation
    print_status "INFO" "Test 6: ARP flooding attack simulation"
    
    local interfaces=$(get_interfaces)
    for interface in $interfaces; do
        if [[ "$interface" != "lo" ]]; then
            print_status "INFO" "Flooding ARP packets on interface $interface"
            
            # Send multiple ARP requests
            for i in {1..10}; do
                local fake_ip="192.168.1.$i"
                arping -I "$interface" -s "$fake_ip" "$fake_ip" 2>/dev/null || true
            done
        fi
    done
    
    print_status "INFO" "ARP flooding test completed"
}

# Function to test ARP table monitoring
test_arp_table_monitoring() {
    print_status "INFO" "Starting ARP table monitoring test..."
    
    # Test 7: Monitor ARP table changes
    print_status "INFO" "Test 7: Monitoring ARP table changes"
    
    # Get initial ARP table
    local initial_arp=$(arp -n)
    print_status "INFO" "Initial ARP table:"
    echo "$initial_arp"
    
    # Wait for changes
    sleep 5
    
    # Get current ARP table
    local current_arp=$(arp -n)
    print_status "INFO" "Current ARP table:"
    echo "$current_arp"
    
    # Compare tables
    if [[ "$initial_arp" != "$current_arp" ]]; then
        print_status "INFO" "ARP table changes detected"
    else
        print_status "INFO" "No ARP table changes detected"
    fi
    
    print_status "INFO" "ARP table monitoring test completed"
}

# Function to test network scanning with ARP
test_network_scanning_arp() {
    print_status "INFO" "Starting network scanning with ARP test..."
    
    # Test 8: Network discovery using ARP
    print_status "INFO" "Test 8: Network discovery using ARP"
    
    local network=$(ip route | grep -E "link src" | awk '{print $1}' | head -1)
    if [[ -n "$network" ]]; then
        print_status "INFO" "Scanning network: $network"
        
        # Scan network using ARP
        for i in {1..10}; do
            local target_ip=$(echo "$network" | sed "s/0\/24/$i/")
            arping -c 1 "$target_ip" 2>/dev/null || true
        done
    fi
    
    print_status "INFO" "Network scanning with ARP test completed"
}

# Function to test ARP spoofing detection
test_arp_spoofing_detection() {
    print_status "INFO" "Starting ARP spoofing detection test..."
    
    # Test 9: Test IDS ARP spoofing detection
    print_status "INFO" "Test 9: Testing IDS ARP spoofing detection"
    
    # Run the ARP spoofing detection module
    if [[ -f "$PROJECT_DIR/modules/arp_spoof.sh" ]]; then
        print_status "INFO" "Running ARP spoofing detection module"
        "$PROJECT_DIR/modules/arp_spoof.sh"
    else
        print_status "WARN" "ARP spoofing detection module not found"
    fi
    
    print_status "INFO" "ARP spoofing detection test completed"
}

# Function to show test results
show_test_results() {
    print_status "INFO" "ARP spoofing tests completed"
    print_status "INFO" "Check the IDS logs for detection alerts:"
    echo "  Alert log: $PROJECT_DIR/logs/alert-log.txt"
    echo "  System log: $PROJECT_DIR/logs/system.log"
    
    print_status "INFO" "Recent alerts:"
    if [[ -f "$PROJECT_DIR/logs/alert-log.txt" ]]; then
        tail -10 "$PROJECT_DIR/logs/alert-log.txt" 2>/dev/null || echo "  No alerts yet"
    else
        echo "  No alert log file found"
    fi
    
    print_status "INFO" "Current ARP table:"
    arp -n
}

# Function to show help
show_help() {
    cat << EOF
ARP Spoofing Test Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -b, --basic             Run basic ARP manipulation tests only
    -s, --spoofing          Run ARP spoofing simulation tests only
    -p, --poisoning         Run ARP cache poisoning tests only
    -f, --flooding          Run ARP flooding tests only
    -m, --monitoring        Run ARP table monitoring tests only
    --all                   Run all tests (default)

Tests:
    Basic: ARP table manipulation and static entries
    Spoofing: ARP spoofing simulation with arping
    Poisoning: ARP cache poisoning attacks
    Flooding: ARP flooding attack simulation
    Monitoring: ARP table change monitoring

Examples:
    $0                      # Run all tests
    $0 -b                   # Run basic tests only
    $0 -s -p                # Run spoofing and poisoning tests

Note: This script simulates ARP spoofing activities.
      Make sure the IDS is running to detect these tests.

EOF
}

# Main execution
main() {
    local run_basic=false
    local run_spoofing=false
    local run_poisoning=false
    local run_flooding=false
    local run_monitoring=false
    
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
            -s|--spoofing)
                run_spoofing=true
                shift
                ;;
            -p|--poisoning)
                run_poisoning=true
                shift
                ;;
            -f|--flooding)
                run_flooding=true
                shift
                ;;
            -m|--monitoring)
                run_monitoring=true
                shift
                ;;
            --all)
                run_basic=true
                run_spoofing=true
                run_poisoning=true
                run_flooding=true
                run_monitoring=true
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
    if [[ "$run_basic" == "false" && "$run_spoofing" == "false" && "$run_poisoning" == "false" && "$run_flooding" == "false" && "$run_monitoring" == "false" ]]; then
        run_basic=true
        run_spoofing=true
        run_poisoning=true
        run_flooding=true
        run_monitoring=true
    fi
    
    # Check prerequisites
    check_root
    check_dependencies
    
    print_status "INFO" "Starting ARP spoofing tests..."
    print_status "INFO" "Make sure the IDS is running to detect these tests"
    
    # Run selected tests
    if $run_basic; then
        test_basic_arp_manipulation
    fi
    
    if $run_spoofing; then
        test_arp_spoofing_simulation
    fi
    
    if $run_poisoning; then
        test_arp_cache_poisoning
    fi
    
    if $run_flooding; then
        test_arp_flooding
    fi
    
    if $run_monitoring; then
        test_arp_table_monitoring
    fi
    
    # Additional tests
    test_network_scanning_arp
    test_arp_spoofing_detection
    
    # Show results
    show_test_results
}

# Run main function
main "$@"
