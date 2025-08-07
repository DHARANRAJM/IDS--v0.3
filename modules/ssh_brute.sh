#!/bin/bash

# SSH Brute-force Detection Module
# Monitors SSH authentication attempts for brute-force patterns
# Author: [Your Name]
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"
LOGS_DIR="$(dirname "$SCRIPT_DIR")/logs"
ALERT_LOG="$LOGS_DIR/alert-log.txt"
SSH_LOG="/tmp/ssh_brute_activity.txt"
AUTH_LOG="/tmp/auth_history.txt"

# Default thresholds (can be overridden by config)
SSH_FAILURE_THRESHOLD=${SSH_FAILURE_THRESHOLD:-5}
SSH_TIME_WINDOW=${SSH_TIME_WINDOW:-300}
SSH_BLOCK_DURATION=${SSH_BLOCK_DURATION:-3600}

# Function to print colored output
print_alert() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[0;31m[SSH_BRUTE_ALERT]\033[0m $timestamp: $message"
}

# Function to get SSH log files
get_ssh_logs() {
    local log_files=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/messages"
        "/var/log/syslog"
    )
    
    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            echo "$log_file"
        fi
    done
}

# Function to extract SSH authentication attempts
extract_ssh_attempts() {
    local log_file="$1"
    local time_window="$2"
    
    # Get SSH attempts from the last time window
    local start_time=$(date -d "$time_window seconds ago" '+%b %d %H:%M:%S' 2>/dev/null || echo "")
    
    if [[ -n "$start_time" ]]; then
        # Extract SSH authentication attempts
        awk -v start="$start_time" '
        $0 ~ /sshd.*Failed password/ || $0 ~ /sshd.*Invalid user/ || $0 ~ /sshd.*authentication failure/ {
            if ($0 >= start) {
                print $0
            }
        }' "$log_file" 2>/dev/null || true
    else
        # Fallback: get last 100 lines
        tail -100 "$log_file" 2>/dev/null | grep -E "sshd.*Failed password|sshd.*Invalid user|sshd.*authentication failure" || true
    fi
}

# Function to parse SSH log entries
parse_ssh_entry() {
    local entry="$1"
    
    # Extract timestamp, IP, and username
    local timestamp=$(echo "$entry" | awk '{print $1, $2, $3}')
    local ip=$(echo "$entry" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
    local user=$(echo "$entry" | grep -oE 'for [^ ]+' | awk '{print $2}')
    local type=$(echo "$entry" | grep -oE 'Failed password|Invalid user|authentication failure')
    
    echo "$timestamp|$ip|$user|$type"
}

# Function to detect SSH brute-force attacks
detect_ssh_brute_force() {
    local log_files=$(get_ssh_logs)
    local current_time=$(date +%s)
    local temp_file="/tmp/ssh_attempts_$$.txt"
    
    # Collect all SSH attempts from log files
    for log_file in $log_files; do
        extract_ssh_attempts "$log_file" "$SSH_TIME_WINDOW" >> "$temp_file"
    done
    
    if [[ -s "$temp_file" ]]; then
        # Group attempts by IP address
        local ip_attempts=$(awk -F'|' '{print $2}' "$temp_file" | sort | uniq -c | sort -nr)
        
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local attempt_count=$(echo "$line" | awk '{print $1}')
                local ip=$(echo "$line" | awk '{print $2}')
                
                if [[ $attempt_count -gt $SSH_FAILURE_THRESHOLD ]]; then
                    # Get details for this IP
                    local ip_details=$(grep "$ip" "$temp_file" | tail -5)
                    local usernames=$(echo "$ip_details" | awk -F'|' '{print $3}' | sort -u | tr '\n' ', ')
                    
                    print_alert "SSH brute-force detected from $ip: $attempt_count attempts, users: $usernames"
                    log_ssh_event "$ip" "$attempt_count" "$usernames" "BRUTE_FORCE"
                    
                    # Check if this IP should be blocked
                    check_ip_blocking "$ip" "$attempt_count"
                fi
            fi
        done <<< "$ip_attempts"
        
        # Check for rapid successive attempts
        check_rapid_attempts "$temp_file"
    fi
    
    rm -f "$temp_file"
}

# Function to check for rapid successive attempts
check_rapid_attempts() {
    local attempts_file="$1"
    
    # Group attempts by IP and check timing
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local ip=$(echo "$line" | awk -F'|' '{print $2}')
            local timestamp=$(echo "$line" | awk -F'|' '{print $1}')
            
            # Count attempts from this IP in the last minute
            local recent_attempts=$(grep "$ip" "$attempts_file" | tail -10 | wc -l)
            
            if [[ $recent_attempts -gt 3 ]]; then
                print_alert "Rapid SSH attempts from $ip: $recent_attempts attempts in recent history"
                log_ssh_event "$ip" "$recent_attempts" "RAPID" "RAPID_ATTEMPTS"
            fi
        fi
    done < "$attempts_file"
}

# Function to check for invalid usernames
check_invalid_usernames() {
    local log_files=$(get_ssh_logs)
    local temp_file="/tmp/invalid_users_$$.txt"
    
    # Collect invalid user attempts
    for log_file in $log_files; do
        if [[ -f "$log_file" ]]; then
            grep "Invalid user" "$log_file" 2>/dev/null | tail -20 >> "$temp_file" || true
        fi
    done
    
    if [[ -s "$temp_file" ]]; then
        # Count attempts per username
        local user_attempts=$(awk '{print $NF}' "$temp_file" | sort | uniq -c | sort -nr)
        
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local attempt_count=$(echo "$line" | awk '{print $1}')
                local username=$(echo "$line" | awk '{print $2}')
                
                if [[ $attempt_count -gt 3 ]]; then
                    print_alert "Multiple invalid username attempts: '$username' ($attempt_count times)"
                    log_ssh_event "INVALID_USER" "$attempt_count" "$username" "INVALID_USERNAME"
                fi
            fi
        done <<< "$user_attempts"
    fi
    
    rm -f "$temp_file"
}

# Function to check for common attack patterns
check_attack_patterns() {
    local log_files=$(get_ssh_logs)
    local temp_file="/tmp/attack_patterns_$$.txt"
    
    # Collect recent SSH attempts
    for log_file in $log_files; do
        if [[ -f "$log_file" ]]; then
            tail -50 "$log_file" 2>/dev/null | grep -E "sshd.*Failed|sshd.*Invalid" >> "$temp_file" || true
        fi
    done
    
    if [[ -s "$temp_file" ]]; then
        # Check for dictionary attack patterns
        local common_users=("root" "admin" "user" "test" "guest" "administrator")
        
        for user in "${common_users[@]}"; do
            local user_attempts=$(grep -c "for $user" "$temp_file" || echo "0")
            
            if [[ $user_attempts -gt 2 ]]; then
                print_alert "Dictionary attack detected: $user_attempts attempts for user '$user'"
                log_ssh_event "DICTIONARY" "$user_attempts" "$user" "DICTIONARY_ATTACK"
            fi
        done
        
        # Check for sequential username attempts
        local unique_users=$(awk '{print $NF}' "$temp_file" | sort -u | wc -l)
        local total_attempts=$(wc -l < "$temp_file")
        
        if [[ $unique_users -gt 5 && $total_attempts -gt 10 ]]; then
            print_alert "Username enumeration detected: $unique_users unique users, $total_attempts total attempts"
            log_ssh_event "ENUMERATION" "$total_attempts" "$unique_users" "USERNAME_ENUMERATION"
        fi
    fi
    
    rm -f "$temp_file"
}

# Function to check IP blocking status
check_ip_blocking() {
    local ip="$1"
    local attempt_count="$2"
    
    # Check if IP is already blocked
    if command -v iptables &> /dev/null; then
        local is_blocked=$(iptables -L INPUT -n | grep -c "$ip" || echo "0")
        
        if [[ $is_blocked -eq 0 && $attempt_count -gt 10 ]]; then
            print_alert "Blocking IP $ip due to excessive SSH attempts"
            
            # Block the IP (optional - uncomment to enable)
            # iptables -A INPUT -s "$ip" -j DROP
            # echo "$ip blocked at $(date)" >> /var/log/ids_blocks.log
        fi
    fi
}

# Function to monitor SSH service status
monitor_ssh_service() {
    # Check if SSH service is running
    if ! systemctl is-active --quiet sshd && ! systemctl is-active --quiet ssh; then
        print_alert "SSH service is not running"
        return
    fi
    
    # Check SSH configuration
    local ssh_config="/etc/ssh/sshd_config"
    if [[ -f "$ssh_config" ]]; then
        # Check for weak configurations
        local permit_root=$(grep -i "PermitRootLogin" "$ssh_config" | grep -v "^#" | awk '{print $2}' || echo "no")
        local password_auth=$(grep -i "PasswordAuthentication" "$ssh_config" | grep -v "^#" | awk '{print $2}' || echo "yes")
        
        if [[ "$permit_root" == "yes" ]]; then
            print_alert "WARNING: Root login is enabled in SSH configuration"
        fi
        
        if [[ "$password_auth" == "yes" ]]; then
            print_alert "WARNING: Password authentication is enabled in SSH configuration"
        fi
    fi
}

# Function to analyze SSH connection patterns
analyze_connection_patterns() {
    local log_files=$(get_ssh_logs)
    local temp_file="/tmp/ssh_patterns_$$.txt"
    
    # Collect successful and failed logins
    for log_file in $log_files; do
        if [[ -f "$log_file" ]]; then
            tail -100 "$log_file" 2>/dev/null | grep -E "sshd.*Accepted|sshd.*Failed" >> "$temp_file" || true
        fi
    done
    
    if [[ -s "$temp_file" ]]; then
        # Calculate success/failure ratio
        local total_attempts=$(wc -l < "$temp_file")
        local successful_logins=$(grep -c "Accepted" "$temp_file" || echo "0")
        local failed_logins=$(grep -c "Failed" "$temp_file" || echo "0")
        
        if [[ $total_attempts -gt 0 ]]; then
            local success_rate=$((successful_logins * 100 / total_attempts))
            local failure_rate=$((failed_logins * 100 / total_attempts))
            
            if [[ $failure_rate -gt 80 ]]; then
                print_alert "High SSH failure rate: $failure_rate% failures, $success_rate% successes"
                log_ssh_event "HIGH_FAILURE_RATE" "$failure_rate" "$success_rate" "FAILURE_RATE"
            fi
        fi
        
        # Check for unusual login times
        check_unusual_login_times "$temp_file"
    fi
    
    rm -f "$temp_file"
}

# Function to check for unusual login times
check_unusual_login_times() {
    local log_file="$1"
    
    # Extract login times
    local login_times=$(awk '{print $3}' "$log_file" | cut -d: -f1 | sort | uniq -c | sort -nr)
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local count=$(echo "$line" | awk '{print $1}')
            local hour=$(echo "$line" | awk '{print $2}')
            
            # Alert for unusual login times (late night/early morning)
            if [[ $hour -lt 6 || $hour -gt 22 ]]; then
                if [[ $count -gt 3 ]]; then
                    print_alert "Unusual SSH activity at hour $hour: $count attempts"
                    log_ssh_event "UNUSUAL_TIME" "$count" "$hour" "UNUSUAL_LOGIN_TIME"
                fi
            fi
        fi
    done <<< "$login_times"
}

# Function to log SSH events
log_ssh_event() {
    local ip="$1"
    local attempt_count="$2"
    local details="$3"
    local event_type="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$timestamp|$event_type|$ip|$attempt_count|$details" >> "$SSH_LOG"
}

# Function to analyze historical SSH data
analyze_historical_data() {
    if [[ ! -f "$SSH_LOG" ]]; then
        return
    fi
    
    # Count recent SSH brute-force events
    local recent_events=$(tail -50 "$SSH_LOG" | wc -l)
    
    if [[ $recent_events -gt 5 ]]; then
        print_alert "High frequency of SSH brute-force events: $recent_events events in recent history"
    fi
    
    # Check for repeated attacks from same IP
    local repeated_ips=$(tail -100 "$SSH_LOG" | awk -F'|' '{print $3}' | sort | uniq -c | awk '$1 > 2 {print $2}' | wc -l)
    
    if [[ $repeated_ips -gt 0 ]]; then
        print_alert "Repeated SSH attacks detected from $repeated_ips IP addresses"
    fi
}

# Function to show SSH statistics
show_ssh_stats() {
    local log_files=$(get_ssh_logs)
    local total_attempts=0
    local unique_ips=0
    local unique_users=0
    
    # Collect statistics from all log files
    for log_file in $log_files; do
        if [[ -f "$log_file" ]]; then
            local file_attempts=$(grep -c "Failed password\|Invalid user" "$log_file" 2>/dev/null || echo "0")
            total_attempts=$((total_attempts + file_attempts))
        fi
    done
    
    # Get unique IPs and users from recent logs
    local temp_file="/tmp/ssh_stats_$$.txt"
    for log_file in $log_files; do
        if [[ -f "$log_file" ]]; then
            tail -100 "$log_file" 2>/dev/null | grep -E "Failed password|Invalid user" >> "$temp_file" || true
        fi
    done
    
    if [[ -s "$temp_file" ]]; then
        unique_ips=$(awk '{print $NF}' "$temp_file" | sort -u | wc -l)
        unique_users=$(awk '{print $NF}' "$temp_file" | sort -u | wc -l)
    fi
    
    echo "SSH Brute-force Statistics:"
    echo "  Total failed attempts: $total_attempts"
    echo "  Unique source IPs: $unique_ips"
    echo "  Unique usernames: $unique_users"
    
    rm -f "$temp_file"
}

# Function to clean up old files
cleanup() {
    # Remove old log files (older than 1 hour)
    find /tmp -name "ssh_brute_activity.txt" -mmin +60 -delete 2>/dev/null || true
    find /tmp -name "auth_history.txt" -mmin +60 -delete 2>/dev/null || true
}

# Main detection function
main() {
    # Create necessary files if they don't exist
    touch "$SSH_LOG" "$AUTH_LOG" 2>/dev/null || true
    
    # Run detection checks
    detect_ssh_brute_force
    check_invalid_usernames
    check_attack_patterns
    monitor_ssh_service
    analyze_connection_patterns
    analyze_historical_data
    
    # Cleanup old files
    cleanup
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
