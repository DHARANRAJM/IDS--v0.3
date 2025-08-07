#!/bin/bash

# Email Setup Script for IDS
# Helps users configure Gmail notifications

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EMAIL_MODULE="$SCRIPT_DIR/modules/email_notifier.sh"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[EMAIL SETUP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if email module exists
check_email_module() {
    if [[ ! -f "$EMAIL_MODULE" ]]; then
        print_error "Email notifier module not found: $EMAIL_MODULE"
        return 1
    fi
    
    if [[ ! -x "$EMAIL_MODULE" ]]; then
        print_warning "Email module is not executable, making it executable"
        chmod +x "$EMAIL_MODULE"
    fi
    
    return 0
}

# Function to show Gmail setup instructions
show_gmail_setup() {
    echo ""
    echo "📧 Gmail Setup Instructions"
    echo "=========================="
    echo ""
    echo "To use Gmail for IDS alerts, you need to:"
    echo ""
    echo "1. Enable 2-Step Verification:"
    echo "   - Go to your Google Account settings"
    echo "   - Navigate to Security"
    echo "   - Enable 2-Step Verification"
    echo ""
    echo "2. Create an App Password:"
    echo "   - Go to Security > App passwords"
    echo "   - Select 'Mail' as the app"
    echo "   - Generate the password"
    echo "   - Copy the 16-character password"
    echo ""
    echo "3. Use the App Password (not your regular Gmail password)"
    echo ""
    echo "Note: Regular Gmail passwords won't work due to security restrictions."
    echo ""
}

# Function to run email configuration
run_email_config() {
    print_status "Starting email configuration..."
    
    if ! check_email_module; then
        return 1
    fi
    
    show_gmail_setup
    
    read -p "Press Enter to continue with configuration..."
    
    # Run the email configuration
    "$EMAIL_MODULE" --configure
    
    if [[ $? -eq 0 ]]; then
        print_success "Email configuration completed!"
        echo ""
        echo "Next steps:"
        echo "1. Test the configuration: sudo ./setup_email.sh --test"
        echo "2. Start IDS with email alerts: sudo ./ids_monitor.sh -d"
        echo "3. Check email status: sudo ./ids_monitor.sh --email-status"
    else
        print_error "Email configuration failed"
        return 1
    fi
}

# Function to test email configuration
test_email_config() {
    print_status "Testing email configuration..."
    
    if ! check_email_module; then
        return 1
    fi
    
    # Run the email test
    "$EMAIL_MODULE" --test
    
    if [[ $? -eq 0 ]]; then
        print_success "Email test completed successfully!"
        echo ""
        echo "If you received the test email, your configuration is working."
        echo "You can now start the IDS with email alerts enabled."
    else
        print_error "Email test failed"
        echo ""
        echo "Common issues:"
        echo "1. Check your Gmail username and app password"
        echo "2. Ensure 2-Step Verification is enabled"
        echo "3. Verify the app password is correct"
        echo "4. Check your internet connection"
        return 1
    fi
}

# Function to show email status
show_email_status() {
    print_status "Checking email status..."
    
    if ! check_email_module; then
        return 1
    fi
    
    # Run the email status check
    "$EMAIL_MODULE" --status
}

# Function to show help
show_help() {
    echo "Email Setup Script for IDS"
    echo "=========================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --configure    Configure email notifications"
    echo "  --test         Test email configuration"
    echo "  --status       Show email status"
    echo "  --help         Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --configure    # Set up email notifications"
    echo "  $0 --test         # Test email configuration"
    echo "  $0 --status       # Check email status"
    echo ""
    echo "Note: You need a Gmail account with 2-Step Verification enabled"
    echo "and an App Password generated for this to work."
}

# Main function
main() {
    case "$1" in
        --configure)
            run_email_config
            ;;
        --test)
            test_email_config
            ;;
        --status)
            show_email_status
            ;;
        --help)
            show_help
            ;;
        "")
            echo "Email Setup for IDS"
            echo "==================="
            echo ""
            echo "This script helps you configure email notifications for the IDS."
            echo ""
            echo "Available options:"
            echo "  --configure    Set up email notifications"
            echo "  --test         Test email configuration"
            echo "  --status       Show email status"
            echo "  --help         Show detailed help"
            echo ""
            echo "To get started, run: $0 --configure"
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
