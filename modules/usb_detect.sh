#!/bin/bash

# USB Insertion Detection Module
# Monitors USB device insertions and removals
# Author: [Your Name]
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"
LOGS_DIR="$(dirname "$SCRIPT_DIR")/logs"
ALERT_LOG="$LOGS_DIR/alert-log.txt"
USB_LOG="$LOGS_DIR/usb.log"
USB_HISTORY="/tmp/usb_history.txt"
USB_DEVICES="/tmp/usb_devices.txt"

# Default thresholds (can be overridden by config)
USB_ALERT_ENABLED=${USB_ALERT_ENABLED:-true}
USB_CHECK_INTERVAL=${USB_CHECK_INTERVAL:-5}

# Function to print colored output
print_alert() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[0;31m[USB_ALERT]\033[0m $timestamp: $message"
}

# Function to get current USB devices
get_usb_devices() {
    # Get USB devices using udevadm
    udevadm info --query=property --name=/sys/bus/usb/devices/* 2>/dev/null | \
    grep -E "(ID_VENDOR_ID|ID_MODEL_ID|ID_VENDOR|ID_MODEL|ID_SERIAL)" | \
    sort | uniq
}

# Function to get USB device details
get_device_details() {
    local device_path="$1"
    
    # Get vendor and product information
    local vendor_id=$(udevadm info --query=property --name="$device_path" 2>/dev/null | grep "ID_VENDOR_ID" | cut -d= -f2)
    local product_id=$(udevadm info --query=property --name="$device_path" 2>/dev/null | grep "ID_MODEL_ID" | cut -d= -f2)
    local vendor_name=$(udevadm info --query=property --name="$device_path" 2>/dev/null | grep "ID_VENDOR" | cut -d= -f2)
    local product_name=$(udevadm info --query=property --name="$device_path" 2>/dev/null | grep "ID_MODEL" | cut -d= -f2)
    local serial=$(udevadm info --query=property --name="$device_path" 2>/dev/null | grep "ID_SERIAL" | cut -d= -f2)
    
    echo "$vendor_id|$product_id|$vendor_name|$product_name|$serial"
}

# Function to detect USB device insertions
detect_usb_insertions() {
    local current_devices="/tmp/current_usb_$$.txt"
    local previous_devices="/tmp/previous_usb_$$.txt"
    
    # Get current USB devices
    lsusb 2>/dev/null | awk '{print $6}' | sort > "$current_devices"
    
    # If we have previous device data, compare them
    if [[ -f "$USB_DEVICES" ]]; then
        cp "$USB_DEVICES" "$previous_devices"
        
        # Find new devices
        comm -13 "$previous_devices" "$current_devices" | while IFS= read -r device; do
            if [[ -n "$device" ]]; then
                local device_info=$(get_device_details "$device")
                print_alert "USB device inserted: $device ($device_info)"
                log_usb_event "$device" "$device_info" "INSERTION"
                
                # Check if device is suspicious
                check_suspicious_device "$device" "$device_info"
            fi
        done
        
        # Find removed devices
        comm -23 "$previous_devices" "$current_devices" | while IFS= read -r device; do
            if [[ -n "$device" ]]; then
                print_alert "USB device removed: $device"
                log_usb_event "$device" "REMOVED" "REMOVAL"
            fi
        done
    fi
    
    # Update device list
    cp "$current_devices" "$USB_DEVICES"
    
    # Cleanup
    rm -f "$current_devices" "$previous_devices"
}

# Function to check for suspicious USB devices
check_suspicious_device() {
    local device="$1"
    local device_info="$2"
    
    # Extract vendor and product IDs
    local vendor_id=$(echo "$device_info" | cut -d'|' -f1)
    local product_id=$(echo "$device_info" | cut -d'|' -f2)
    local vendor_name=$(echo "$device_info" | cut -d'|' -f3)
    local product_name=$(echo "$device_info" | cut -d'|' -f4)
    
    # Check for unknown vendors (common suspicious indicator)
    local known_vendors=("8086" "045e" "046d" "0bda" "0951" "0781" "0a5c" "0bb4" "0e0f" "0f0e")
    local is_known=false
    
    for known_vendor in "${known_vendors[@]}"; do
        if [[ "$vendor_id" == "$known_vendor" ]]; then
            is_known=true
            break
        fi
    done
    
    if [[ "$is_known" == "false" ]]; then
        print_alert "Suspicious USB device detected: Unknown vendor $vendor_id ($vendor_name)"
        log_usb_event "$device" "$device_info" "SUSPICIOUS_VENDOR"
    fi
    
    # Check for storage devices
    if [[ "$product_name" == *"Storage"* || "$product_name" == *"Disk"* || "$product_name" == *"Flash"* ]]; then
        print_alert "Storage device detected: $product_name"
        log_usb_event "$device" "$device_info" "STORAGE_DEVICE"
        
        # Check for unauthorized storage devices
        check_unauthorized_storage "$device" "$device_info"
    fi
    
    # Check for HID devices (keyboards, mice, etc.)
    if [[ "$product_name" == *"Keyboard"* || "$product_name" == *"Mouse"* || "$product_name" == *"HID"* ]]; then
        print_alert "HID device detected: $product_name"
        log_usb_event "$device" "$device_info" "HID_DEVICE"
    fi
    
    # Check for network devices
    if [[ "$product_name" == *"Network"* || "$product_name" == *"Ethernet"* || "$product_name" == *"WiFi"* ]]; then
        print_alert "Network device detected: $product_name"
        log_usb_event "$device" "$device_info" "NETWORK_DEVICE"
    fi
}

# Function to check for unauthorized storage devices
check_unauthorized_storage() {
    local device="$1"
    local device_info="$2"
    
    # Check if storage device is mounted
    local mount_points=$(mount | grep -E "usb|sd[a-z]" | awk '{print $3}' || true)
    
    if [[ -n "$mount_points" ]]; then
        print_alert "Storage device mounted: $mount_points"
        
        # Check for sensitive files on mounted devices
        for mount_point in $mount_points; do
            if [[ -d "$mount_point" ]]; then
                # Look for common sensitive file types
                local sensitive_files=$(find "$mount_point" -type f \( -name "*.txt" -o -name "*.doc" -o -name "*.pdf" -o -name "*.xls" -o -name "*.db" -o -name "*.sql" \) 2>/dev/null | head -10)
                
                if [[ -n "$sensitive_files" ]]; then
                    print_alert "Sensitive files detected on USB storage: $(echo "$sensitive_files" | wc -l) files"
                    log_usb_event "$device" "$device_info" "SENSITIVE_FILES"
                fi
            fi
        done
    fi
}

# Function to monitor USB events using udev
monitor_udev_events() {
    # Monitor udev events for USB devices
    local udev_events=$(udevadm monitor --property --subsystem-match=usb 2>/dev/null | head -20 || true)
    
    if [[ -n "$udev_events" ]]; then
        # Parse udev events
        echo "$udev_events" | while IFS= read -r event; do
            if [[ "$event" == *"add"* ]]; then
                local device=$(echo "$event" | grep -o "usb[0-9]*" | head -1)
                if [[ -n "$device" ]]; then
                    print_alert "USB device added via udev: $device"
                    log_usb_event "$device" "UDEV_ADD" "UDEV_INSERTION"
                fi
            elif [[ "$event" == *"remove"* ]]; then
                local device=$(echo "$event" | grep -o "usb[0-9]*" | head -1)
                if [[ -n "$device" ]]; then
                    print_alert "USB device removed via udev: $device"
                    log_usb_event "$device" "UDEV_REMOVE" "UDEV_REMOVAL"
                fi
            fi
        done
    fi
}

# Function to check for USB mass storage devices
check_mass_storage() {
    # Check for USB mass storage devices
    local mass_storage=$(lsusb 2>/dev/null | grep -i "mass storage" || true)
    
    if [[ -n "$mass_storage" ]]; then
        print_alert "USB mass storage device detected"
        echo "$mass_storage" | while IFS= read -r device; do
            print_alert "Mass storage: $device"
            log_usb_event "$device" "MASS_STORAGE" "MASS_STORAGE_DEVICE"
        done
    fi
}

# Function to check for USB hubs
check_usb_hubs() {
    # Check for USB hubs (potential for multiple device connections)
    local usb_hubs=$(lsusb 2>/dev/null | grep -i "hub" || true)
    
    if [[ -n "$usb_hubs" ]]; then
        print_alert "USB hub detected"
        echo "$usb_hubs" | while IFS= read -r hub; do
            print_alert "USB hub: $hub"
            log_usb_event "$hub" "USB_HUB" "USB_HUB_DEVICE"
        done
    fi
}

# Function to monitor dmesg for USB events
monitor_dmesg_events() {
    # Check dmesg for recent USB events
    local usb_events=$(dmesg | grep -i "usb" | tail -20 || true)
    
    if [[ -n "$usb_events" ]]; then
        # Look for insertion/removal events
        local insertions=$(echo "$usb_events" | grep -i "new" | wc -l)
        local removals=$(echo "$usb_events" | grep -i "disconnect" | wc -l)
        
        if [[ $insertions -gt 0 ]]; then
            print_alert "USB device insertions detected in dmesg: $insertions events"
        fi
        
        if [[ $removals -gt 0 ]]; then
            print_alert "USB device removals detected in dmesg: $removals events"
        fi
    fi
}

# Function to check for unauthorized USB devices
check_unauthorized_devices() {
    # Define authorized device patterns (customize as needed)
    local authorized_patterns=(
        "046d:c52b"  # Logitech Unifying Receiver
        "045e:0745"  # Microsoft Wireless Keyboard
        "0bda:0129"  # Realtek USB 2.0 Card Reader
    )
    
    # Get current USB devices
    local current_devices=$(lsusb 2>/dev/null | awk '{print $6}' || true)
    
    while IFS= read -r device; do
        if [[ -n "$device" ]]; then
            local is_authorized=false
            
            for pattern in "${authorized_patterns[@]}"; do
                if [[ "$device" == *"$pattern"* ]]; then
                    is_authorized=true
                    break
                fi
            done
            
            if [[ "$is_authorized" == "false" ]]; then
                print_alert "Unauthorized USB device detected: $device"
                log_usb_event "$device" "UNAUTHORIZED" "UNAUTHORIZED_DEVICE"
            fi
        fi
    done <<< "$current_devices"
}

# Function to log USB events
log_usb_event() {
    local device="$1"
    local details="$2"
    local event_type="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$timestamp|$event_type|$device|$details" >> "$USB_HISTORY"
    echo "$timestamp|$event_type|$device|$details" >> "$USB_LOG"
}

# Function to analyze USB history
analyze_usb_history() {
    if [[ ! -f "$USB_HISTORY" ]]; then
        return
    fi
    
    # Count recent USB events
    local recent_events=$(tail -50 "$USB_HISTORY" | wc -l)
    
    if [[ $recent_events -gt 10 ]]; then
        print_alert "High frequency of USB events: $recent_events events in recent history"
    fi
    
    # Check for repeated device insertions
    local repeated_devices=$(tail -100 "$USB_HISTORY" | awk -F'|' '$2 == "INSERTION" {print $3}' | sort | uniq -c | awk '$1 > 3 {print $2}' | wc -l)
    
    if [[ $repeated_devices -gt 0 ]]; then
        print_alert "Repeated USB device insertions detected: $repeated_devices devices"
    fi
    
    # Check for suspicious device types
    local suspicious_events=$(tail -100 "$USB_HISTORY" | grep -E "SUSPICIOUS|UNAUTHORIZED|SENSITIVE" | wc -l)
    
    if [[ $suspicious_events -gt 0 ]]; then
        print_alert "Suspicious USB activity detected: $suspicious_events events"
    fi
}

# Function to show USB statistics
show_usb_stats() {
    local total_devices=$(lsusb 2>/dev/null | wc -l)
    local unique_vendors=$(lsusb 2>/dev/null | awk '{print $6}' | cut -d: -f1 | sort -u | wc -l)
    local storage_devices=$(lsusb 2>/dev/null | grep -i "storage\|disk\|flash" | wc -l)
    local hid_devices=$(lsusb 2>/dev/null | grep -i "keyboard\|mouse\|hid" | wc -l)
    
    echo "USB Device Statistics:"
    echo "  Total USB devices: $total_devices"
    echo "  Unique vendors: $unique_vendors"
    echo "  Storage devices: $storage_devices"
    echo "  HID devices: $hid_devices"
    
    if [[ $storage_devices -gt 0 ]]; then
        echo "  WARNING: Storage devices detected"
    fi
}

# Function to clean up old files
cleanup() {
    # Remove old USB history files (older than 1 hour)
    find /tmp -name "usb_history.txt" -mmin +60 -delete 2>/dev/null || true
    find /tmp -name "usb_devices.txt" -mmin +60 -delete 2>/dev/null || true
}

# Main detection function
main() {
    # Create necessary files if they don't exist
    touch "$USB_LOG" "$USB_HISTORY" "$USB_DEVICES" 2>/dev/null || true
    
    # Run detection checks
    detect_usb_insertions
    check_mass_storage
    check_usb_hubs
    monitor_dmesg_events
    check_unauthorized_devices
    analyze_usb_history
    
    # Monitor udev events (optional, can be resource intensive)
    # monitor_udev_events
    
    # Cleanup old files
    cleanup
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
