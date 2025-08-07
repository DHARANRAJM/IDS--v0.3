#!/bin/bash

# Port Scanning Detection Module
# Monitors network connections for rapid sequential port access
# Author: [Your Name]
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"
LOGS_DIR="$(dirname "$SCRIPT_DIR")/logs"
ALERT_LOG="$LOGS_DIR/alert-log.txt"
PORT_SCAN_LOG="/tmp/port_scan_activity.txt"
CONNECTION_LOG="/tmp/connection_history.txt"

# Default thresholds (can be overridden by config)
PORT_SCAN_WINDOW=${PORT_SCAN_WINDOW:-60}
PORT_SCAN_THRESHOLD=${PORT_SCAN_THRESHOLD:-10}
PORT_SCAN_TIME_WINDOW=${PORT_SCAN_TIME_WINDOW:-300}

# Function to print colored output
print_alert() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[0;31m[PORT_SCAN_ALERT]\033[0m $timestamp: $message"
}

# Function to get current network connections
get_connections() {
    # Get active TCP connections
    netstat -tn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f2 | sort -n
}

# Function to get connection history from logs
get_connection_history() {
    # Monitor system logs for connection attempts
    local log_sources=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/messages"
        "/var/log/syslog"
    )
    
    for log_file in "${log_sources[@]}"; do
        if [[ -f "$log_file" ]]; then
            # Extract connection attempts from logs
            grep -E "(connection|connect|port|tcp)" "$log_file" 2>/dev/null | tail -50 || true
        fi
    done
}

# Function to monitor real-time connections using tcpdump
monitor_connections() {
    local duration=10
    local output_file="/tmp/tcpdump_output_$$.txt"
    
    # Capture TCP connections for a short duration
    timeout "$duration" tcpdump -i any -n tcp 2>/dev/null > "$output_file" || true
    
    if [[ -f "$output_file" ]]; then
        # Extract destination ports
        awk '/^[0-9]/ {print $5}' "$output_file" | cut -d. -f5 | sort -n
        rm -f "$output_file"
    fi
}

# Function to detect port scanning patterns
detect_port_scanning() {
    local current_connections="/tmp/current_connections_$$.txt"
    local previous_connections="/tmp/previous_connections_$$.txt"
    
    # Get current connections
    get_connections > "$current_connections"
    
    # If we have previous connection data, analyze patterns
    if [[ -f "$CONNECTION_LOG" ]]; then
        cp "$CONNECTION_LOG" "$previous_connections"
        
        # Analyze connection patterns
        analyze_connection_patterns "$current_connections" "$previous_connections"
    fi
    
    # Update connection log
    cat "$current_connections" >> "$CONNECTION_LOG"
    
    # Keep only recent connections (last 1000 entries)
    tail -1000 "$CONNECTION_LOG" > "$CONNECTION_LOG.tmp" && mv "$CONNECTION_LOG.tmp" "$CONNECTION_LOG"
    
    # Cleanup
    rm -f "$current_connections" "$previous_connections"
}

# Function to analyze connection patterns
analyze_connection_patterns() {
    local current_file="$1"
    local previous_file="$2"
    
    # Get unique source IPs and their port access patterns
    local source_ips=$(netstat -tn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u)
    
    for ip in $source_ips; do
        # Get ports accessed by this IP
        local ports=$(netstat -tn 2>/dev/null | grep "$ip" | awk '{print $5}' | cut -d: -f2 | sort -n)
        local port_count=$(echo "$ports" | wc -l)
        
        if [[ $port_count -gt $PORT_SCAN_THRESHOLD ]]; then
            # Check if ports are sequential (indicating port scan)
            local sequential_count=$(echo "$ports" | awk 'NR>1 {if($1-prev==1) count++; prev=$1} END {print count+1}' | tail -1)
            
            if [[ $sequential_count -gt 5 ]]; then
                print_alert "Port scanning detected from $ip: $port_count ports accessed, $sequential_count sequential"
                log_port_scan_event "$ip" "$port_count" "$sequential_count" "SEQUENTIAL_SCAN"
            else
                print_alert "Multiple port access detected from $ip: $port_count ports accessed"
                log_port_scan_event "$ip" "$port_count" "0" "MULTIPLE_PORTS"
            fi
        fi
    done
}

# Function to monitor for rapid port access
monitor_rapid_access() {
    local time_window=60
    local access_log="/tmp/port_access_$$.txt"
    
    # Monitor connections for a time window
    timeout "$time_window" tcpdump -i any -n tcp 2>/dev/null | \
    awk '{print $3, $5}' | cut -d. -f5 | sort | uniq -c | \
    awk '$1 > 5 {print $2, $1}' > "$access_log"
    
    if [[ -s "$access_log" ]]; then
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local port=$(echo "$line" | awk '{print $1}')
                local count=$(echo "$line" | awk '{print $2}')
                
                if [[ $count -gt $PORT_SCAN_THRESHOLD ]]; then
                    print_alert "Rapid access to port $port: $count attempts in $time_window seconds"
                    log_port_scan_event "UNKNOWN" "$count" "0" "RAPID_ACCESS"
                fi
            fi
        done < "$access_log"
    fi
    
    rm -f "$access_log"
}

# Function to detect common port scanning tools
detect_scanning_tools() {
    # Check for common scanning tools in process list
    local scanning_processes=$(ps aux 2>/dev/null | grep -E "(nmap|masscan|zmap|unicornscan)" | grep -v grep || true)
    
    if [[ -n "$scanning_processes" ]]; then
        print_alert "Port scanning tools detected running on system"
        echo "$scanning_processes" | while IFS= read -r process; do
            print_alert "Scanning process: $process"
        done
    fi
    
    # Check for recent nmap activity in logs
    local nmap_logs=$(grep -i "nmap" /var/log/* 2>/dev/null | tail -10 || true)
    if [[ -n "$nmap_logs" ]]; then
        print_alert "Nmap activity detected in system logs"
    fi
}

# Function to analyze port ranges
analyze_port_ranges() {
    local connections="/tmp/port_ranges_$$.txt"
    get_connections > "$connections"
    
    if [[ -s "$connections" ]]; then
        # Group ports by ranges
        local port_ranges=$(awk '
        {
            if ($1 < 1024) range="well-known"
            else if ($1 < 49152) range="registered"
            else range="dynamic"
            print range, $1
        }' "$connections" | sort)
        
        # Count ports in each range
        local well_known=$(echo "$port_ranges" | grep "well-known" | wc -l)
        local registered=$(echo "$port_ranges" | grep "registered" | wc -l)
        local dynamic=$(echo "$port_ranges" | grep "dynamic" | wc -l)
        
        # Alert if unusual port range distribution
        if [[ $dynamic -gt $((well_known + registered)) ]]; then
            print_alert "Unusual port access pattern: $dynamic dynamic ports vs $well_known well-known ports"
        fi
        
        # Check for access to common scanning ports
        local scanning_ports=$(echo "$port_ranges" | awk '$2 ~ /^(21|22|23|25|53|80|110|143|443|993|995|1433|3306|3389|5432|5900|8080)$/ {print $2}' | wc -l)
        
        if [[ $scanning_ports -gt 5 ]]; then
            print_alert "Multiple common service ports accessed: $scanning_ports ports"
        fi
    fi
    
    rm -f "$connections"
}

# Function to log port scan events
log_port_scan_event() {
    local source_ip="$1"
    local port_count="$2"
    local sequential_count="$3"
    local event_type="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$timestamp|$event_type|$source_ip|$port_count|$sequential_count" >> "$PORT_SCAN_LOG"
}

# Function to analyze historical port scan data
analyze_historical_data() {
    if [[ ! -f "$PORT_SCAN_LOG" ]]; then
        return
    fi
    
    # Count recent port scan events
    local recent_scans=$(tail -50 "$PORT_SCAN_LOG" | wc -l)
    
    if [[ $recent_scans -gt 10 ]]; then
        print_alert "High frequency of port scan events: $recent_scans events in recent history"
    fi
    
    # Check for repeated scans from same IP
    local repeated_ips=$(tail -100 "$PORT_SCAN_LOG" | awk -F'|' '{print $3}' | sort | uniq -c | awk '$1 > 3 {print $2}' | wc -l)
    
    if [[ $repeated_ips -gt 0 ]]; then
        print_alert "Repeated port scanning detected from $repeated_ips IP addresses"
    fi
}

# Function to check for suspicious port combinations
check_suspicious_combinations() {
    local connections="/tmp/suspicious_ports_$$.txt"
    get_connections > "$connections"
    
    if [[ -s "$connections" ]]; then
        # Check for common scanning port combinations
        local ssh_port=$(grep -c "^22$" "$connections" || echo "0")
        local ftp_port=$(grep -c "^21$" "$connections" || echo "0")
        local telnet_port=$(grep -c "^23$" "$connections" || echo "0")
        local smtp_port=$(grep -c "^25$" "$connections" || echo "0")
        local http_port=$(grep -c "^80$" "$connections" || echo "0")
        local https_port=$(grep -c "^443$" "$connections" || echo "0")
        
        local total_common=$((ssh_port + ftp_port + telnet_port + smtp_port + http_port + https_port))
        
        if [[ $total_common -gt 3 ]]; then
            print_alert "Multiple common service ports accessed simultaneously: $total_common ports"
        fi
        
        # Check for database port access
        local db_ports=$(grep -c -E "^(1433|3306|5432|1521|6379|27017)$" "$connections" || echo "0")
        if [[ $db_ports -gt 2 ]]; then
            print_alert "Multiple database ports accessed: $db_ports ports"
        fi
    fi
    
    rm -f "$connections"
}

# Function to monitor for connection rate limiting
monitor_connection_rate() {
    local time_window=30
    local max_connections=50
    
    # Count new connections in time window
    local connection_count=$(timeout "$time_window" tcpdump -i any -n tcp 2>/dev/null | wc -l)
    
    if [[ $connection_count -gt $max_connections ]]; then
        print_alert "High connection rate detected: $connection_count connections in $time_window seconds"
        log_port_scan_event "RATE_LIMIT" "$connection_count" "0" "HIGH_RATE"
    fi
}

# Function to show port scan statistics
show_port_scan_stats() {
    local total_connections=$(get_connections | wc -l)
    local unique_ports=$(get_connections | sort -u | wc -l)
    local unique_ips=$(netstat -tn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | wc -l)
    
    echo "Port Scan Statistics:"
    echo "  Total connections: $total_connections"
    echo "  Unique ports: $unique_ports"
    echo "  Unique source IPs: $unique_ips"
    
    if [[ $total_connections -gt 0 ]]; then
        local avg_ports_per_ip=$((total_connections / unique_ips))
        echo "  Average ports per IP: $avg_ports_per_ip"
        
        if [[ $avg_ports_per_ip -gt 5 ]]; then
            echo "  WARNING: High average ports per IP"
        fi
    fi
}

# Function to clean up old files
cleanup() {
    # Remove old log files (older than 1 hour)
    find /tmp -name "port_scan_activity.txt" -mmin +60 -delete 2>/dev/null || true
    find /tmp -name "connection_history.txt" -mmin +60 -delete 2>/dev/null || true
}

# Main detection function
main() {
    # Create necessary files if they don't exist
    touch "$PORT_SCAN_LOG" "$CONNECTION_LOG" 2>/dev/null || true
    
    # Run detection checks
    detect_port_scanning
    monitor_rapid_access
    detect_scanning_tools
    analyze_port_ranges
    check_suspicious_combinations
    analyze_historical_data
    
    # Monitor connection rate (optional, can be resource intensive)
    # monitor_connection_rate
    
    # Cleanup old files
    cleanup
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
