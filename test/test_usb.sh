#!/bin/bash

# USB Insertion Test Script
# Simulates USB device insertions and removals to test the IDS
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
    local deps=("lsusb" "udevadm" "dmesg" "mount" "fdisk" "blkid")
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

# Function to get current USB devices
get_current_usb_devices() {
    print_status "INFO" "Current USB devices:"
    lsusb 2>/dev/null || echo "  No USB devices found"
}

# Function to test USB device detection
test_usb_device_detection() {
    print_status "INFO" "Starting USB device detection test..."
    
    # Test 1: List all USB devices
    print_status "INFO" "Test 1: Listing all USB devices"
    get_current_usb_devices
    
    # Test 2: Monitor USB events
    print_status "INFO" "Test 2: Monitoring USB events"
    
    # Monitor udev events for USB
    timeout 10 udevadm monitor --property --subsystem-match=usb 2>/dev/null | head -20 || true
    
    print_status "INFO" "USB device detection test completed"
}

# Function to test USB storage device simulation
test_usb_storage_simulation() {
    print_status "INFO" "Starting USB storage device simulation test..."
    
    # Test 3: Simulate USB storage device insertion
    print_status "INFO" "Test 3: Simulating USB storage device insertion"
    
    # Check for existing USB storage devices
    local usb_storage=$(lsusb 2>/dev/null | grep -i "storage\|disk\|flash" || true)
    
    if [[ -n "$usb_storage" ]]; then
        print_status "INFO" "Found USB storage devices:"
        echo "$usb_storage"
        
        # Check if any are mounted
        local mounted_usb=$(mount | grep -E "usb|sd[a-z]" || true)
        if [[ -n "$mounted_usb" ]]; then
            print_status "INFO" "Mounted USB devices:"
            echo "$mounted_usb"
        fi
    else
        print_status "INFO" "No USB storage devices detected"
    fi
    
    print_status "INFO" "USB storage device simulation test completed"
}

# Function to test USB device monitoring
test_usb_device_monitoring() {
    print_status "INFO" "Starting USB device monitoring test..."
    
    # Test 4: Monitor USB device changes
    print_status "INFO" "Test 4: Monitoring USB device changes"
    
    # Get initial USB device list
    local initial_devices=$(lsusb 2>/dev/null | wc -l)
    print_status "INFO" "Initial USB device count: $initial_devices"
    
    # Monitor for 10 seconds
    print_status "INFO" "Monitoring USB devices for 10 seconds..."
    for i in {1..10}; do
        local current_devices=$(lsusb 2>/dev/null | wc -l)
        if [[ $current_devices -ne $initial_devices ]]; then
            print_status "INFO" "USB device count changed: $initial_devices -> $current_devices"
            break
        fi
        sleep 1
    done
    
    print_status "INFO" "USB device monitoring test completed"
}

# Function to test USB device information
test_usb_device_information() {
    print_status "INFO" "Starting USB device information test..."
    
    # Test 5: Get detailed USB device information
    print_status "INFO" "Test 5: Getting detailed USB device information"
    
    # Get USB device details using udevadm
    local usb_devices=$(find /sys/bus/usb/devices/ -name "usb*" 2>/dev/null || true)
    
    for device in $usb_devices; do
        if [[ -d "$device" ]]; then
            local device_name=$(basename "$device")
            print_status "INFO" "Device: $device_name"
            
            # Get device properties
            udevadm info --query=property --name="$device" 2>/dev/null | grep -E "(ID_VENDOR|ID_MODEL|ID_SERIAL)" || true
        fi
    done
    
    print_status "INFO" "USB device information test completed"
}

# Function to test USB device removal simulation
test_usb_device_removal() {
    print_status "INFO" "Starting USB device removal simulation test..."
    
    # Test 6: Simulate USB device removal
    print_status "INFO" "Test 6: Simulating USB device removal"
    
    # Check dmesg for USB removal events
    local usb_removals=$(dmesg | grep -i "usb.*remove\|usb.*disconnect" | tail -5 || true)
    
    if [[ -n "$usb_removals" ]]; then
        print_status "INFO" "Recent USB removal events:"
        echo "$usb_removals"
    else
        print_status "INFO" "No recent USB removal events found"
    fi
    
    print_status "INFO" "USB device removal simulation test completed"
}

# Function to test USB device enumeration
test_usb_device_enumeration() {
    print_status "INFO" "Starting USB device enumeration test..."
    
    # Test 7: Enumerate USB devices
    print_status "INFO" "Test 7: Enumerating USB devices"
    
    # Get USB device tree
    local usb_tree=$(find /sys/bus/usb/devices/ -name "*" -type d 2>/dev/null | head -20 || true)
    
    print_status "INFO" "USB device tree (first 20 entries):"
    for device in $usb_tree; do
        if [[ -d "$device" ]]; then
            local device_name=$(basename "$device")
            echo "  $device_name"
        fi
    done
    
    print_status "INFO" "USB device enumeration test completed"
}

# Function to test USB device security
test_usb_device_security() {
    print_status "INFO" "Starting USB device security test..."
    
    # Test 8: Check USB device security
    print_status "INFO" "Test 8: Checking USB device security"
    
    # Check for unauthorized USB devices
    local suspicious_devices=$(lsusb 2>/dev/null | grep -E "(keyboard|mouse|storage|network)" || true)
    
    if [[ -n "$suspicious_devices" ]]; then
        print_status "WARN" "Potentially suspicious USB devices detected:"
        echo "$suspicious_devices"
    else
        print_status "INFO" "No suspicious USB devices detected"
    fi
    
    # Check for USB storage devices
    local storage_devices=$(lsusb 2>/dev/null | grep -i "storage\|disk\|flash" || true)
    
    if [[ -n "$storage_devices" ]]; then
        print_status "WARN" "USB storage devices detected:"
        echo "$storage_devices"
        
        # Check if any are mounted
        local mounted_storage=$(mount | grep -E "usb|sd[a-z]" || true)
        if [[ -n "$mounted_storage" ]]; then
            print_status "WARN" "Mounted USB storage devices:"
            echo "$mounted_storage"
        fi
    fi
    
    print_status "INFO" "USB device security test completed"
}

# Function to test USB device logging
test_usb_device_logging() {
    print_status "INFO" "Starting USB device logging test..."
    
    # Test 9: Check USB device logs
    print_status "INFO" "Test 9: Checking USB device logs"
    
    # Check system logs for USB events
    local usb_logs=$(dmesg | grep -i "usb" | tail -10 || true)
    
    if [[ -n "$usb_logs" ]]; then
        print_status "INFO" "Recent USB system logs:"
        echo "$usb_logs"
    else
        print_status "INFO" "No recent USB system logs found"
    fi
    
    # Check udev logs
    local udev_logs=$(journalctl -u systemd-udevd --since "5 minutes ago" | grep -i "usb" || true)
    
    if [[ -n "$udev_logs" ]]; then
        print_status "INFO" "Recent udev USB logs:"
        echo "$udev_logs"
    else
        print_status "INFO" "No recent udev USB logs found"
    fi
    
    print_status "INFO" "USB device logging test completed"
}

# Function to test USB device detection module
test_usb_detection_module() {
    print_status "INFO" "Starting USB device detection module test..."
    
    # Test 10: Test IDS USB detection module
    print_status "INFO" "Test 10: Testing IDS USB detection module"
    
    # Run the USB detection module
    if [[ -f "$PROJECT_DIR/modules/usb_detect.sh" ]]; then
        print_status "INFO" "Running USB detection module"
        "$PROJECT_DIR/modules/usb_detect.sh"
    else
        print_status "WARN" "USB detection module not found"
    fi
    
    print_status "INFO" "USB device detection module test completed"
}

# Function to show test results
show_test_results() {
    print_status "INFO" "USB insertion tests completed"
    print_status "INFO" "Check the IDS logs for detection alerts:"
    echo "  Alert log: $PROJECT_DIR/logs/alert-log.txt"
    echo "  System log: $PROJECT_DIR/logs/system.log"
    echo "  USB log: $PROJECT_DIR/logs/usb.log"
    
    print_status "INFO" "Recent USB-related alerts:"
    if [[ -f "$PROJECT_DIR/logs/alert-log.txt" ]]; then
        tail -10 "$PROJECT_DIR/logs/alert-log.txt" | grep -i "usb" 2>/dev/null || echo "  No USB alerts yet"
    else
        echo "  No alert log file found"
    fi
    
    print_status "INFO" "Current USB devices:"
    get_current_usb_devices
}

# Function to show help
show_help() {
    cat << EOF
USB Insertion Test Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -d, --detection         Run USB device detection tests only
    -s, --storage           Run USB storage device tests only
    -m, --monitoring        Run USB device monitoring tests only
    -i, --information       Run USB device information tests only
    -r, --removal           Run USB device removal tests only
    -e, --enumeration       Run USB device enumeration tests only
    -c, --security          Run USB device security tests only
    -l, --logging           Run USB device logging tests only
    --all                   Run all tests (default)

Tests:
    Detection: Basic USB device detection
    Storage: USB storage device simulation
    Monitoring: USB device change monitoring
    Information: Detailed USB device information
    Removal: USB device removal simulation
    Enumeration: USB device enumeration
    Security: USB device security checks
    Logging: USB device log analysis

Examples:
    $0                      # Run all tests
    $0 -d                   # Run detection tests only
    $0 -s -c                # Run storage and security tests

Note: This script simulates USB device activities.
      Make sure the IDS is running to detect these tests.
      Insert a USB device to test real detection.

EOF
}

# Main execution
main() {
    local run_detection=false
    local run_storage=false
    local run_monitoring=false
    local run_information=false
    local run_removal=false
    local run_enumeration=false
    local run_security=false
    local run_logging=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--detection)
                run_detection=true
                shift
                ;;
            -s|--storage)
                run_storage=true
                shift
                ;;
            -m|--monitoring)
                run_monitoring=true
                shift
                ;;
            -i|--information)
                run_information=true
                shift
                ;;
            -r|--removal)
                run_removal=true
                shift
                ;;
            -e|--enumeration)
                run_enumeration=true
                shift
                ;;
            -c|--security)
                run_security=true
                shift
                ;;
            -l|--logging)
                run_logging=true
                shift
                ;;
            --all)
                run_detection=true
                run_storage=true
                run_monitoring=true
                run_information=true
                run_removal=true
                run_enumeration=true
                run_security=true
                run_logging=true
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
    if [[ "$run_detection" == "false" && "$run_storage" == "false" && "$run_monitoring" == "false" && "$run_information" == "false" && "$run_removal" == "false" && "$run_enumeration" == "false" && "$run_security" == "false" && "$run_logging" == "false" ]]; then
        run_detection=true
        run_storage=true
        run_monitoring=true
        run_information=true
        run_removal=true
        run_enumeration=true
        run_security=true
        run_logging=true
    fi
    
    # Check prerequisites
    check_root
    check_dependencies
    
    print_status "INFO" "Starting USB insertion tests..."
    print_status "INFO" "Make sure the IDS is running to detect these tests"
    print_status "INFO" "Insert a USB device to test real detection"
    
    # Run selected tests
    if $run_detection; then
        test_usb_device_detection
    fi
    
    if $run_storage; then
        test_usb_storage_simulation
    fi
    
    if $run_monitoring; then
        test_usb_device_monitoring
    fi
    
    if $run_information; then
        test_usb_device_information
    fi
    
    if $run_removal; then
        test_usb_device_removal
    fi
    
    if $run_enumeration; then
        test_usb_device_enumeration
    fi
    
    if $run_security; then
        test_usb_device_security
    fi
    
    if $run_logging; then
        test_usb_device_logging
    fi
    
    # Additional tests
    test_usb_detection_module
    
    # Show results
    show_test_results
}

# Run main function
main "$@"
