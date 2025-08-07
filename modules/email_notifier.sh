#!/bin/bash

# Email Notification Module for IDS
# Sends alerts via Gmail SMTP

# Source configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/../config/email_config.conf"
LOG_FILE="$SCRIPT_DIR/../logs/email.log"
ALERT_LOG="$SCRIPT_DIR/../logs/alert-log.txt"

# Email rate limiting
RATE_LIMIT_FILE="$SCRIPT_DIR/../logs/email_rate_limit.txt"
MAX_EMAILS_PER_HOUR=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[EMAIL]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[EMAIL SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[EMAIL WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[EMAIL ERROR]${NC} $1"
}

# Function to load email configuration
load_email_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "Email configuration file not found: $CONFIG_FILE"
        return 1
    fi
    
    # Source the configuration file
    source "$CONFIG_FILE"
    
    # Validate required settings
    if [[ -z "$GMAIL_USERNAME" || "$GMAIL_USERNAME" == "your_email@gmail.com" ]]; then
        print_error "Gmail username not configured. Please edit $CONFIG_FILE"
        return 1
    fi
    
    if [[ -z "$GMAIL_PASSWORD" || "$GMAIL_PASSWORD" == "your_app_password" ]]; then
        print_error "Gmail password not configured. Please edit $CONFIG_FILE"
        return 1
    fi
    
    if [[ -z "$RECIPIENT_EMAIL" || "$RECIPIENT_EMAIL" == "admin@yourdomain.com" ]]; then
        print_error "Recipient email not configured. Please edit $CONFIG_FILE"
        return 1
    fi
    
    print_success "Email configuration loaded successfully"
    return 0
}

# Function to check rate limiting
check_rate_limit() {
    local current_hour=$(date '+%Y-%m-%d %H')
    local email_count=0
    
    if [[ -f "$RATE_LIMIT_FILE" ]]; then
        email_count=$(grep "$current_hour" "$RATE_LIMIT_FILE" | wc -l)
    fi
    
    if [[ $email_count -ge $MAX_EMAILS_PER_HOUR ]]; then
        print_warning "Rate limit exceeded. Maximum $MAX_EMAILS_PER_HOUR emails per hour."
        return 1
    fi
    
    return 0
}

# Function to update rate limit counter
update_rate_limit() {
    local current_hour=$(date '+%Y-%m-%d %H')
    echo "$current_hour" >> "$RATE_LIMIT_FILE"
    
    # Clean up old entries (older than 24 hours)
    local yesterday=$(date -d '24 hours ago' '+%Y-%m-%d %H')
    sed -i "/$yesterday/d" "$RATE_LIMIT_FILE" 2>/dev/null
}

# Function to get system information
get_system_info() {
    local info=""
    info+="Hostname: $(hostname)\n"
    info+="OS: $(uname -a)\n"
    info+="Uptime: $(uptime)\n"
    info+="Load Average: $(cat /proc/loadavg | awk '{print $1, $2, $3}')\n"
    info+="Memory Usage: $(free -h | grep Mem | awk '{print $3 "/" $2}')\n"
    info+="Disk Usage: $(df -h / | tail -1 | awk '{print $5}')\n"
    info+="Network Interfaces:\n"
    info+="$(ip addr show | grep -E 'inet.*global' | awk '{print "  " $2}')\n"
    
    echo -e "$info"
}

# Function to get recent alerts
get_recent_alerts() {
    if [[ -f "$ALERT_LOG" ]]; then
        echo "Recent Alerts (last 10):"
        tail -10 "$ALERT_LOG" | while read line; do
            echo "  $line"
        done
    else
        echo "No alert log found"
    fi
}

# Function to create email content
create_email_content() {
    local alert_type="$1"
    local alert_message="$2"
    local priority="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local subject="$EMAIL_SUBJECT_PREFIX $alert_type - $priority Priority"
    local body=""
    
    # Create email body based on template
    case "$EMAIL_TEMPLATE" in
        "simple")
            body="Alert Type: $alert_type\nPriority: $priority\nTime: $timestamp\nMessage: $alert_message"
            ;;
        "detailed")
            body="=== IDS ALERT ===\n"
            body+="Alert Type: $alert_type\n"
            body+="Priority: $priority\n"
            body+="Timestamp: $timestamp\n"
            body+="Message: $alert_message\n\n"
            
            if [[ "$INCLUDE_SYSTEM_INFO" == "true" ]]; then
                body+="=== SYSTEM INFORMATION ===\n"
                body+="$(get_system_info)\n"
            fi
            
            if [[ "$INCLUDE_LOG_DETAILS" == "true" ]]; then
                body+="=== RECENT ALERTS ===\n"
                body+="$(get_recent_alerts)\n"
            fi
            ;;
        "html")
            body="<html><body>"
            body+="<h2>IDS Alert</h2>"
            body+="<table border='1'>"
            body+="<tr><td><strong>Alert Type:</strong></td><td>$alert_type</td></tr>"
            body+="<tr><td><strong>Priority:</strong></td><td>$priority</td></tr>"
            body+="<tr><td><strong>Timestamp:</strong></td><td>$timestamp</td></tr>"
            body+="<tr><td><strong>Message:</strong></td><td>$alert_message</td></tr>"
            body+="</table>"
            
            if [[ "$INCLUDE_SYSTEM_INFO" == "true" ]]; then
                body+="<h3>System Information</h3>"
                body+="<pre>$(get_system_info)</pre>"
            fi
            
            if [[ "$INCLUDE_LOG_DETAILS" == "true" ]]; then
                body+="<h3>Recent Alerts</h3>"
                body+="<pre>$(get_recent_alerts)</pre>"
            fi
            
            body+="</body></html>"
            ;;
    esac
    
    echo "$subject|$body"
}

# Function to send email using curl
send_email_curl() {
    local subject="$1"
    local body="$2"
    local recipient="$3"
    local cc="$4"
    
    # Create email headers
    local headers=""
    headers+="From: $GMAIL_USERNAME\n"
    headers+="To: $recipient\n"
    if [[ -n "$cc" ]]; then
        headers+="Cc: $cc\n"
    fi
    headers+="Subject: $subject\n"
    headers+="Content-Type: text/plain; charset=UTF-8\n"
    headers+="\n"
    
    # Create email content
    local email_content="$headers$body"
    
    # Send email using curl
    local curl_cmd="curl --silent --show-error"
    curl_cmd+=" --mail-from '$GMAIL_USERNAME'"
    curl_cmd+=" --mail-rcpt '$recipient'"
    if [[ -n "$cc" ]]; then
        curl_cmd+=" --mail-rcpt '$cc'"
    fi
    curl_cmd+=" --upload-file -"
    curl_cmd+=" --ssl-reqd"
    curl_cmd+=" --user '$GMAIL_USERNAME:$GMAIL_PASSWORD'"
    curl_cmd+=" smtp://$GMAIL_SMTP_SERVER:$GMAIL_SMTP_PORT"
    
    # Send the email
    local result=$(echo -e "$email_content" | eval $curl_cmd 2>&1)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Email sent successfully to $recipient"
        echo "$(date '+%Y-%m-%d %H:%M:%S')|EMAIL_SENT|$recipient|$subject" >> "$LOG_FILE"
        return 0
    else
        print_error "Failed to send email: $result"
        echo "$(date '+%Y-%m-%d %H:%M:%S')|EMAIL_FAILED|$recipient|$result" >> "$LOG_FILE"
        return 1
    fi
}

# Function to send email using sendmail (alternative method)
send_email_sendmail() {
    local subject="$1"
    local body="$2"
    local recipient="$3"
    local cc="$4"
    
    # Create email content
    local email_content=""
    email_content+="From: $GMAIL_USERNAME\n"
    email_content+="To: $recipient\n"
    if [[ -n "$cc" ]]; then
        email_content+="Cc: $cc\n"
    fi
    email_content+="Subject: $subject\n"
    email_content+="Content-Type: text/plain; charset=UTF-8\n"
    email_content+="\n"
    email_content+="$body"
    
    # Send using sendmail
    local result=$(echo -e "$email_content" | sendmail -t 2>&1)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Email sent successfully to $recipient"
        echo "$(date '+%Y-%m-%d %H:%M:%S')|EMAIL_SENT|$recipient|$subject" >> "$LOG_FILE"
        return 0
    else
        print_error "Failed to send email: $result"
        echo "$(date '+%Y-%m-%d %H:%M:%S')|EMAIL_FAILED|$recipient|$result" >> "$LOG_FILE"
        return 1
    fi
}

# Function to send email alert
send_email_alert() {
    local alert_type="$1"
    local alert_message="$2"
    local priority="$3"
    
    # Check if email alerts are enabled
    if [[ "$SEND_EMAIL_ALERTS" != "true" ]]; then
        print_warning "Email alerts are disabled"
        return 0
    fi
    
    # Check rate limiting
    if ! check_rate_limit; then
        return 1
    fi
    
    # Check if this alert type should be emailed
    local email_var="EMAIL_${alert_type}_ALERTS"
    if [[ "${!email_var}" != "true" ]]; then
        print_warning "Email alerts for $alert_type are disabled"
        return 0
    fi
    
    # Check priority filtering
    if [[ "$EMAIL_HIGH_PRIORITY_ONLY" == "true" && "$priority" != "HIGH" ]]; then
        print_warning "Only high priority alerts are enabled for email"
        return 0
    fi
    
    # Load email configuration
    if ! load_email_config; then
        return 1
    fi
    
    # Create email content
    local email_data=$(create_email_content "$alert_type" "$alert_message" "$priority")
    local subject=$(echo "$email_data" | cut -d'|' -f1)
    local body=$(echo "$email_data" | cut -d'|' -f2-)
    
    # Send email
    local success=false
    
    # Try curl method first
    if command -v curl >/dev/null 2>&1; then
        if send_email_curl "$subject" "$body" "$RECIPIENT_EMAIL" "$CC_EMAIL"; then
            success=true
        fi
    fi
    
    # Fallback to sendmail if curl fails
    if [[ "$success" == "false" ]] && command -v sendmail >/dev/null 2>&1; then
        if send_email_sendmail "$subject" "$body" "$RECIPIENT_EMAIL" "$CC_EMAIL"; then
            success=true
        fi
    fi
    
    if [[ "$success" == "true" ]]; then
        update_rate_limit
        return 0
    else
        return 1
    fi
}

# Function to test email configuration
test_email_config() {
    print_status "Testing email configuration..."
    
    if ! load_email_config; then
        return 1
    fi
    
    # Test SMTP connection
    if command -v curl >/dev/null 2>&1; then
        print_status "Testing SMTP connection..."
        local test_result=$(curl --silent --connect-timeout 10 \
            --user "$GMAIL_USERNAME:$GMAIL_PASSWORD" \
            smtp://$GMAIL_SMTP_SERVER:$GMAIL_SMTP_PORT 2>&1)
        
        if [[ $? -eq 0 ]]; then
            print_success "SMTP connection successful"
        else
            print_error "SMTP connection failed: $test_result"
            return 1
        fi
    fi
    
    # Send test email
    print_status "Sending test email..."
    if send_email_alert "TEST" "This is a test email from IDS system" "LOW"; then
        print_success "Test email sent successfully"
        return 0
    else
        print_error "Test email failed"
        return 1
    fi
}

# Function to configure email settings
configure_email() {
    print_status "Email Configuration Setup"
    echo "=================================="
    
    # Create config file if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cp "$SCRIPT_DIR/../config/email_config.conf" "$CONFIG_FILE" 2>/dev/null || {
            print_error "Could not create email config file"
            return 1
        }
    fi
    
    echo "Please configure your Gmail settings:"
    echo ""
    
    # Get Gmail username
    read -p "Enter your Gmail address: " gmail_username
    if [[ -n "$gmail_username" ]]; then
        sed -i "s/GMAIL_USERNAME=.*/GMAIL_USERNAME=\"$gmail_username\"/" "$CONFIG_FILE"
    fi
    
    # Get Gmail app password
    echo ""
    echo "Note: You need to create an App Password for Gmail:"
    echo "1. Go to your Google Account settings"
    echo "2. Enable 2-Step Verification if not already enabled"
    echo "3. Go to Security > App passwords"
    echo "4. Generate a new app password for 'Mail'"
    echo ""
    read -s -p "Enter your Gmail App Password: " gmail_password
    echo ""
    if [[ -n "$gmail_password" ]]; then
        sed -i "s/GMAIL_PASSWORD=.*/GMAIL_PASSWORD=\"$gmail_password\"/" "$CONFIG_FILE"
    fi
    
    # Get recipient email
    read -p "Enter recipient email address: " recipient_email
    if [[ -n "$recipient_email" ]]; then
        sed -i "s/RECIPIENT_EMAIL=.*/RECIPIENT_EMAIL=\"$recipient_email\"/" "$CONFIG_FILE"
    fi
    
    # Get CC email (optional)
    read -p "Enter CC email address (optional): " cc_email
    if [[ -n "$cc_email" ]]; then
        sed -i "s/CC_EMAIL=.*/CC_EMAIL=\"$cc_email\"/" "$CONFIG_FILE"
    fi
    
    # Configure alert types
    echo ""
    echo "Configure which alerts to email:"
    read -p "Email port scan alerts? (y/n): " email_port_scan
    if [[ "$email_port_scan" == "y" ]]; then
        sed -i "s/EMAIL_PORT_SCAN_ALERTS=.*/EMAIL_PORT_SCAN_ALERTS=\"true\"/" "$CONFIG_FILE"
    fi
    
    read -p "Email ARP spoof alerts? (y/n): " email_arp_spoof
    if [[ "$email_arp_spoof" == "y" ]]; then
        sed -i "s/EMAIL_ARP_SPOOF_ALERTS=.*/EMAIL_ARP_SPOOF_ALERTS=\"true\"/" "$CONFIG_FILE"
    fi
    
    read -p "Email SSH brute force alerts? (y/n): " email_ssh_brute
    if [[ "$email_ssh_brute" == "y" ]]; then
        sed -i "s/EMAIL_SSH_BRUTE_ALERTS=.*/EMAIL_SSH_BRUTE_ALERTS=\"true\"/" "$CONFIG_FILE"
    fi
    
    read -p "Email USB alerts? (y/n): " email_usb
    if [[ "$email_usb" == "y" ]]; then
        sed -i "s/EMAIL_USB_ALERTS=.*/EMAIL_USB_ALERTS=\"true\"/" "$CONFIG_FILE"
    fi
    
    # Configure frequency
    echo ""
    echo "Email frequency options:"
    echo "1. immediate - Send emails immediately"
    echo "2. hourly - Send summary emails hourly"
    echo "3. daily - Send summary emails daily"
    read -p "Choose email frequency (1-3): " email_freq
    
    case $email_freq in
        1) sed -i "s/EMAIL_FREQUENCY=.*/EMAIL_FREQUENCY=\"immediate\"/" "$CONFIG_FILE" ;;
        2) sed -i "s/EMAIL_FREQUENCY=.*/EMAIL_FREQUENCY=\"hourly\"/" "$CONFIG_FILE" ;;
        3) sed -i "s/EMAIL_FREQUENCY=.*/EMAIL_FREQUENCY=\"daily\"/" "$CONFIG_FILE" ;;
    esac
    
    # Enable email alerts
    sed -i "s/SEND_EMAIL_ALERTS=.*/SEND_EMAIL_ALERTS=\"true\"/" "$CONFIG_FILE"
    
    print_success "Email configuration completed!"
    echo ""
    echo "Configuration saved to: $CONFIG_FILE"
    echo ""
    echo "To test the configuration, run:"
    echo "  sudo ./modules/email_notifier.sh --test"
}

# Function to show email status
show_email_status() {
    print_status "Email Notification Status"
    echo "=============================="
    
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Configuration file: $CONFIG_FILE"
        source "$CONFIG_FILE"
        
        echo ""
        echo "Email Settings:"
        echo "  Enabled: $SEND_EMAIL_ALERTS"
        echo "  Gmail: $GMAIL_USERNAME"
        echo "  Recipient: $RECIPIENT_EMAIL"
        echo "  CC: $CC_EMAIL"
        echo "  Frequency: $EMAIL_FREQUENCY"
        echo "  Rate Limit: $MAX_EMAILS_PER_HOUR emails/hour"
        
        echo ""
        echo "Alert Types:"
        echo "  Port Scan: $EMAIL_PORT_SCAN_ALERTS"
        echo "  ARP Spoof: $EMAIL_ARP_SPOOF_ALERTS"
        echo "  SSH Brute: $EMAIL_SSH_BRUTE_ALERTS"
        echo "  USB: $EMAIL_USB_ALERTS"
        echo "  High Priority Only: $EMAIL_HIGH_PRIORITY_ONLY"
        
        if [[ -f "$LOG_FILE" ]]; then
            echo ""
            echo "Recent Email Activity:"
            tail -5 "$LOG_FILE" | while read line; do
                echo "  $line"
            done
        fi
    else
        echo "Email configuration file not found"
        echo "Run: sudo ./modules/email_notifier.sh --configure"
    fi
}

# Function to show help
show_help() {
    echo "Email Notifier Module for IDS"
    echo "============================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --send <type> <message> <priority>  Send email alert"
    echo "  --test                               Test email configuration"
    echo "  --configure                          Configure email settings"
    echo "  --status                             Show email status"
    echo "  --help                               Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --send PORT_SCAN 'Port scan detected' HIGH"
    echo "  $0 --test"
    echo "  $0 --configure"
    echo "  $0 --status"
}

# Main function
main() {
    case "$1" in
        --send)
            if [[ $# -eq 4 ]]; then
                send_email_alert "$2" "$3" "$4"
            else
                print_error "Usage: $0 --send <type> <message> <priority>"
                exit 1
            fi
            ;;
        --test)
            test_email_config
            ;;
        --configure)
            configure_email
            ;;
        --status)
            show_email_status
            ;;
        --help)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
