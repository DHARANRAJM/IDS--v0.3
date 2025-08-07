#!/bin/bash

# ARP Spoofing Detection Module
# Monitors ARP tables for suspicious MAC-IP mappings
# Author: [Your Name]
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"
LOGS_DIR="$(dirname "$SCRIPT_DIR")/logs"
ALERT_LOG="$LOGS_DIR/alert-log.txt"
ARP_CACHE_FILE="/tmp/arp_cache.txt"
ARP_HISTORY_FILE="/tmp/arp_history.txt"
WHITELIST_FILE="$CONFIG_DIR/whitelist_macs.txt"

# Default thresholds (can be overridden by config)
ARP_CHECK_INTERVAL=${ARP_CHECK_INTERVAL:-5}
ARP_SUSPICIOUS_THRESHOLD=${ARP_SUSPICIOUS_THRESHOLD:-3}

# Function to print colored output
print_alert() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[0;31m[ARP_SPOOF_ALERT]\033[0m $timestamp: $message"
}

# Function to check if MAC address is whitelisted
is_whitelisted() {
    local mac="$1"
    
    if [[ ! -f "$WHITELIST_FILE" ]]; then
        return 1
    fi
    
    # Check if MAC is in whitelist (case insensitive)
    grep -qi "^[[:space:]]*$mac[[:space:]]*$" "$WHITELIST_FILE" 2>/dev/null
}

# Function to get current ARP table
get_arp_table() {
    arp -n | grep -v "incomplete" | awk '{print $1, $3}' | sort
}

# Function to detect ARP spoofing
detect_arp_spoofing() {
    local current_arp_file="/tmp/current_arp_$$.txt"
    local previous_arp_file="/tmp/previous_arp_$$.txt"
    
    # Get current ARP table
    get_arp_table > "$current_arp_file"
    
    # If we have a previous ARP table, compare them
    if [[ -f "$ARP_CACHE_FILE" ]]; then
        cp "$ARP_CACHE_FILE" "$previous_arp_file"
        
        # Find new or changed entries
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local ip=$(echo "$line" | awk '{print $1}')
                local mac=$(echo "$line" | awk '{print $2}')
                
                # Skip if MAC is whitelisted
                if is_whitelisted "$mac"; then
                    continue
                fi
                
                # Check if this IP-MAC mapping is new or changed
                local previous_mac=$(grep "^$ip " "$previous_arp_file" 2>/dev/null | awk '{print $2}')
                
                if [[ -n "$previous_mac" && "$previous_mac" != "$mac" ]]; then
                    # MAC address changed for the same IP
                    print_alert "ARP spoofing detected: IP $ip changed from $previous_mac to $mac"
                    log_arp_event "$ip" "$previous_mac" "$mac" "MAC_CHANGE"
                elif [[ -z "$previous_mac" ]]; then
                    # New IP-MAC mapping
                    print_alert "New ARP entry detected: IP $ip -> MAC $mac"
                    log_arp_event "$ip" "" "$mac" "NEW_ENTRY"
                fi
            fi
        done < "$current_arp_file"
        
        # Check for suspicious patterns
        check_suspicious_patterns "$current_arp_file"
    fi
    
    # Update ARP cache
    cp "$current_arp_file" "$ARP_CACHE_FILE"
    
    # Cleanup
    rm -f "$current_arp_file" "$previous_arp_file"
}

# Function to check for suspicious patterns
check_suspicious_patterns() {
    local arp_file="$1"
    
    # Check for multiple IPs with same MAC (potential spoofing)
    local duplicate_macs=$(awk '{print $2}' "$arp_file" | sort | uniq -d)
    
    if [[ -n "$duplicate_macs" ]]; then
        for mac in $duplicate_macs; do
            if ! is_whitelisted "$mac"; then
                local ips=$(awk -v mac="$mac" '$2 == mac {print $1}' "$arp_file" | tr '\n' ', ')
                print_alert "Suspicious pattern: MAC $mac associated with multiple IPs: $ips"
                log_arp_event "MULTIPLE_IPS" "" "$mac" "DUPLICATE_MAC"
            fi
        done
    fi
    
    # Check for broadcast MAC addresses
    local broadcast_macs=$(grep -E "ff:ff:ff:ff:ff:ff|00:00:00:00:00:00" "$arp_file" 2>/dev/null || true)
    if [[ -n "$broadcast_macs" ]]; then
        print_alert "Suspicious broadcast MAC addresses detected in ARP table"
        log_arp_event "BROADCAST" "" "broadcast" "BROADCAST_MAC"
    fi
}

# Function to log ARP events
log_arp_event() {
    local ip="$1"
    local old_mac="$2"
    local new_mac="$3"
    local event_type="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$timestamp|$event_type|$ip|$old_mac|$new_mac" >> "$ARP_HISTORY_FILE"
}

# Function to analyze ARP history for patterns
analyze_arp_history() {
    if [[ ! -f "$ARP_HISTORY_FILE" ]]; then
        return
    fi
    
    # Count recent MAC changes
    local recent_changes=$(tail -50 "$ARP_HISTORY_FILE" | grep "MAC_CHANGE" | wc -l)
    
    if [[ $recent_changes -gt $ARP_SUSPICIOUS_THRESHOLD ]]; then
        print_alert "High frequency of ARP changes detected: $recent_changes changes in recent history"
    fi
    
    # Check for rapid MAC changes for same IP
    local rapid_changes=$(tail -20 "$ARP_HISTORY_FILE" | awk -F'|' '$2 == "MAC_CHANGE" {print $3}' | sort | uniq -c | awk '$1 > 2 {print $2}' | wc -l)
    
    if [[ $rapid_changes -gt 0 ]]; then
        print_alert "Rapid MAC changes detected for $rapid_changes IP addresses"
    fi
}

# Function to check for static ARP entries
check_static_arp_entries() {
    # Look for static ARP entries that might be suspicious
    local static_entries=$(arp -n | grep -E "PERM|static" 2>/dev/null || true)
    
    if [[ -n "$static_entries" ]]; then
        while IFS= read -r entry; do
            if [[ -n "$entry" ]]; then
                local ip=$(echo "$entry" | awk '{print $1}')
                local mac=$(echo "$entry" | awk '{print $3}')
                
                if ! is_whitelisted "$mac"; then
                    print_alert "Static ARP entry detected: IP $ip -> MAC $mac"
                fi
            fi
        done <<< "$static_entries"
    fi
}

# Function to monitor ARP requests
monitor_arp_requests() {
    # Use tcpdump to monitor ARP requests in real-time
    local arp_requests=$(timeout 5 tcpdump -i any -n arp 2>/dev/null | head -10 || true)
    
    if [[ -n "$arp_requests" ]]; then
        # Look for suspicious patterns in ARP requests
        local suspicious_requests=$(echo "$arp_requests" | grep -E "who-has.*tell.*|is-at.*tell.*" | grep -v "incomplete" || true)
        
        if [[ -n "$suspicious_requests" ]]; then
            local request_count=$(echo "$suspicious_requests" | wc -l)
            if [[ $request_count -gt 5 ]]; then
                print_alert "High volume of ARP requests detected: $request_count requests in 5 seconds"
            fi
        fi
    fi
}

# Function to validate MAC address format
validate_mac() {
    local mac="$1"
    # Check if MAC address is in valid format (xx:xx:xx:xx:xx:xx)
    [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

# Function to check for invalid MAC addresses
check_invalid_macs() {
    local arp_file="/tmp/current_arp_$$.txt"
    get_arp_table > "$arp_file"
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local ip=$(echo "$line" | awk '{print $1}')
            local mac=$(echo "$line" | awk '{print $2}')
            
            if ! validate_mac "$mac"; then
                print_alert "Invalid MAC address format detected: IP $ip -> MAC $mac"
                log_arp_event "$ip" "" "$mac" "INVALID_MAC"
            fi
        fi
    done < "$arp_file"
    
    rm -f "$arp_file"
}

# Function to show ARP statistics
show_arp_stats() {
    local total_entries=$(get_arp_table | wc -l)
    local unique_macs=$(get_arp_table | awk '{print $2}' | sort -u | wc -l)
    local unique_ips=$(get_arp_table | awk '{print $1}' | sort -u | wc -l)
    
    echo "ARP Statistics:"
    echo "  Total entries: $total_entries"
    echo "  Unique MACs: $unique_macs"
    echo "  Unique IPs: $unique_ips"
    
    if [[ $total_entries -gt $unique_macs ]]; then
        local duplicate_count=$((total_entries - unique_macs))
        echo "  Duplicate MACs: $duplicate_count"
    fi
}

# Function to clean up old files
cleanup() {
    # Remove old ARP cache files (older than 1 hour)
    find /tmp -name "arp_cache.txt" -mmin +60 -delete 2>/dev/null || true
    find /tmp -name "arp_history.txt" -mmin +60 -delete 2>/dev/null || true
}

# Main detection function
main() {
    # Create necessary files if they don't exist
    touch "$ARP_CACHE_FILE" "$ARP_HISTORY_FILE" 2>/dev/null || true
    
    # Run detection checks
    detect_arp_spoofing
    check_static_arp_entries
    check_invalid_macs
    analyze_arp_history
    
    # Monitor ARP requests (optional, can be resource intensive)
    # monitor_arp_requests
    
    # Cleanup old files
    cleanup
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
