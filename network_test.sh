#!/bin/zsh

################################################################################
# Wireless Network Testing Script for macOS
# Author: David Crosby (Bing)
# Description: Comprehensive wireless network diagnostics and connectivity testing
#              Tests SSID, speed, stability, DNS, and cloud service access
# Usage: ./network_test.sh
################################################################################

# Enable strict error handling
set -euo pipefail

# Colour codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Colour
readonly BOLD='\033[1m'

# Test results tracking
declare -i TESTS_PASSED=0
declare -i TESTS_FAILED=0
declare -i TESTS_WARNING=0

# Log file with timestamp
readonly LOG_FILE="/tmp/wifi_test_$(date +%Y%m%d_%H%M%S).log"
readonly RESULTS_FILE="/tmp/wifi_test_results_$(date +%Y%m%d_%H%M%S).txt"

################################################################################
# Function: log_message
# Description: Logs messages to both console and log file with timestamp
# Parameters: $1 - Message to log
################################################################################
log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

################################################################################
# Function: print_header
# Description: Prints a formatted section header
# Parameters: $1 - Header text
################################################################################
print_header() {
    echo ""
    echo "${BOLD}${BLUE}========================================${NC}" | tee -a "$LOG_FILE"
    echo "${BOLD}${BLUE}$1${NC}" | tee -a "$LOG_FILE"
    echo "${BOLD}${BLUE}========================================${NC}" | tee -a "$LOG_FILE"
    log_message "Starting test: $1"
}

################################################################################
# Function: print_result
# Description: Prints test result with appropriate colouring
# Parameters: $1 - Status (PASS/FAIL/WARN), $2 - Message
################################################################################
print_result() {
    local test_status=$1
    local message=$2
    
    case $test_status in
        "PASS")
            echo "${GREEN}✓ PASS:${NC} $message" | tee -a "$LOG_FILE"
            ((TESTS_PASSED++))
            ;;
        "FAIL")
            echo "${RED}✗ FAIL:${NC} $message" | tee -a "$LOG_FILE"
            ((TESTS_FAILED++))
            ;;
        "WARN")
            echo "${YELLOW}⚠ WARN:${NC} $message" | tee -a "$LOG_FILE"
            ((TESTS_WARNING++))
            ;;
    esac
}

################################################################################
# Function: get_wifi_interface
# Description: Detects the active WiFi interface on macOS
# Returns: WiFi interface name (e.g., en0)
################################################################################
get_wifi_interface() {
    log_message "Detecting WiFi interface..."
    
    # Get list of network interfaces
    local interfaces=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
    
    if [[ -z "$interfaces" ]]; then
        print_result "FAIL" "No WiFi interface found"
        exit 1
    fi
    
    # Return first WiFi interface
    echo "$interfaces" | head -n 1
}

################################################################################
# Function: test_wifi_status
# Description: Checks WiFi status, SSID, and signal strength
################################################################################
test_wifi_status() {
    print_header "WiFi Status and SSID Check"
    
    local wifi_interface=$(get_wifi_interface)
    log_message "WiFi interface detected: $wifi_interface"
    
    # Check if WiFi is powered on
    local wifi_power=$(networksetup -getairportpower "$wifi_interface" | awk '{print $4}')
    
    if [[ "$wifi_power" != "On" ]]; then
        print_result "FAIL" "WiFi is powered off"
        return 1
    fi
    
    print_result "PASS" "WiFi is powered on"
    
    # Get current SSID
    local ssid=$(/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/ SSID/ {print $2}')
    
    if [[ -z "$ssid" ]]; then
        print_result "FAIL" "Not connected to any WiFi network"
        return 1
    fi
    
    print_result "PASS" "Connected to SSID: ${BOLD}$ssid${NC}"
    
    # Get detailed WiFi information
    local wifi_info=$(/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I)
    
    # Extract signal strength (RSSI)
    local rssi=$(echo "$wifi_info" | awk '/agrCtlRSSI/ {print $2}')
    local noise=$(echo "$wifi_info" | awk '/agrCtlNoise/ {print $2}')
    
    if [[ -n "$rssi" ]]; then
        log_message "Signal Strength (RSSI): $rssi dBm"
        log_message "Noise Level: $noise dBm"
        
        # Calculate SNR (Signal-to-Noise Ratio)
        local snr=$((rssi - noise))
        log_message "Signal-to-Noise Ratio: $snr dB"
        
        # Evaluate signal quality
        if [[ $rssi -ge -50 ]]; then
            print_result "PASS" "Excellent signal strength: $rssi dBm"
        elif [[ $rssi -ge -60 ]]; then
            print_result "PASS" "Good signal strength: $rssi dBm"
        elif [[ $rssi -ge -70 ]]; then
            print_result "WARN" "Fair signal strength: $rssi dBm"
        else
            print_result "WARN" "Weak signal strength: $rssi dBm"
        fi
    fi
    
    # Get channel information
    local channel=$(echo "$wifi_info" | awk '/channel/ {print $2}')
    log_message "Channel: $channel"
    
    # Get PHY mode
    local phy_mode=$(echo "$wifi_info" | awk '/lastTxRate/ {print $2}')
    log_message "Last TX Rate: $phy_mode Mbps"
    
    # Get BSSID (MAC address of access point)
    local bssid=$(echo "$wifi_info" | awk '/BSSID/ {print $2}')
    log_message "BSSID: $bssid"
    
    # Write full WiFi info to log
    log_message "Full WiFi Information:"
    echo "$wifi_info" >> "$LOG_FILE"
}

################################################################################
# Function: test_ip_configuration
# Description: Checks IP address configuration and routing
################################################################################
test_ip_configuration() {
    print_header "IP Configuration Check"
    
    local wifi_interface=$(get_wifi_interface)
    
    # Get IP address
    local ip_address=$(ipconfig getifaddr "$wifi_interface" 2>/dev/null)
    
    if [[ -z "$ip_address" ]]; then
        print_result "FAIL" "No IP address assigned"
        return 1
    fi
    
    print_result "PASS" "IP Address: $ip_address"
    
    # Get subnet mask
    local subnet=$(ifconfig "$wifi_interface" | awk '/netmask/ {print $4}')
    log_message "Subnet Mask: $subnet"
    
    # Get router/gateway
    local router=$(netstat -nr | grep default | grep "$wifi_interface" | awk '{print $2}' | head -n 1)
    
    if [[ -n "$router" ]]; then
        print_result "PASS" "Default Gateway: $router"
    else
        print_result "WARN" "No default gateway found"
    fi
    
    # Get DNS servers
    local dns_servers=$(scutil --dns | grep 'nameserver\[[0-9]*\]' | awk '{print $3}' | sort -u)
    
    if [[ -n "$dns_servers" ]]; then
        print_result "PASS" "DNS Servers configured"
        echo "$dns_servers" | while read -r dns; do
            log_message "  DNS Server: $dns"
        done
    else
        print_result "WARN" "No DNS servers found"
    fi
}

################################################################################
# Function: test_gateway_connectivity
# Description: Tests connectivity to the default gateway
################################################################################
test_gateway_connectivity() {
    print_header "Gateway Connectivity Test"
    
    local wifi_interface=$(get_wifi_interface)
    local router=$(netstat -nr | grep default | grep "$wifi_interface" | awk '{print $2}' | head -n 1)
    
    if [[ -z "$router" ]]; then
        print_result "FAIL" "No gateway to test"
        return 1
    fi
    
    log_message "Pinging gateway: $router"
    
    # Ping gateway with 5 packets
    local ping_result=$(ping -c 5 -W 2000 "$router" 2>&1)
    local ping_exit=$?
    
    if [[ $ping_exit -eq 0 ]]; then
        # Extract statistics
        local packet_loss=$(echo "$ping_result" | grep 'packet loss' | awk '{print $7}')
        local avg_time=$(echo "$ping_result" | grep 'min/avg/max' | awk -F'/' '{print $5}')
        
        print_result "PASS" "Gateway reachable - Avg latency: ${avg_time}ms, Loss: $packet_loss"
        log_message "Ping results: $ping_result"
    else
        print_result "FAIL" "Cannot reach gateway"
        log_message "Ping output: $ping_result"
    fi
}

################################################################################
# Function: test_internet_connectivity
# Description: Tests basic internet connectivity using multiple methods
################################################################################
test_internet_connectivity() {
    print_header "Internet Connectivity Test"
    
    # Test using ping to major DNS servers
    local test_hosts=("8.8.8.8" "1.1.1.1" "9.9.9.9")
    local passed=0
    
    for host in "${test_hosts[@]}"; do
        log_message "Testing connectivity to $host"
        
        if ping -c 3 -W 2000 "$host" &>/dev/null; then
            print_result "PASS" "Can reach $host"
            ((passed++))
        else
            print_result "FAIL" "Cannot reach $host"
        fi
    done
    
    if [[ $passed -gt 0 ]]; then
        print_result "PASS" "Internet connectivity confirmed ($passed/3 hosts reachable)"
    else
        print_result "FAIL" "No internet connectivity detected"
    fi
}

################################################################################
# Function: test_dns_resolution
# Description: Tests DNS resolution with multiple domains
################################################################################
test_dns_resolution() {
    print_header "DNS Resolution Test"
    
    local test_domains=("google.com" "microsoft.com" "cloudflare.com" "amazon.com")
    local passed=0
    
    for domain in "${test_domains[@]}"; do
        log_message "Resolving $domain"
        
        local dns_result=$(dig +short +time=3 +tries=2 "$domain" 2>&1)
        
        if [[ -n "$dns_result" ]] && [[ ! "$dns_result" =~ "connection timed out" ]]; then
            print_result "PASS" "Resolved $domain → $dns_result"
            ((passed++))
        else
            print_result "FAIL" "Failed to resolve $domain"
            log_message "DNS error: $dns_result"
        fi
    done
    
    if [[ $passed -eq ${#test_domains[@]} ]]; then
        print_result "PASS" "All DNS lookups successful"
    elif [[ $passed -gt 0 ]]; then
        print_result "WARN" "Partial DNS resolution ($passed/${#test_domains[@]} succeeded)"
    else
        print_result "FAIL" "DNS resolution completely failed"
    fi
}

################################################################################
# Function: test_network_speed
# Description: Tests network latency and jitter
################################################################################
test_network_speed() {
    print_header "Network Speed and Stability Test"
    
    # Test latency to multiple endpoints
    local test_hosts=("8.8.8.8" "1.1.1.1")
    
    for host in "${test_hosts[@]}"; do
        log_message "Testing latency to $host"
        
        # Send 20 pings to measure stability
        local ping_result=$(ping -c 20 -i 0.2 "$host" 2>&1)
        
        if [[ $? -eq 0 ]]; then
            local packet_loss=$(echo "$ping_result" | grep 'packet loss' | awk '{print $7}')
            local stats=$(echo "$ping_result" | grep 'min/avg/max/stddev' | awk -F'[=/]' '{print $2, $3, $4, $5}')
            
            read -r min avg max stddev <<< "$stats"
            
            log_message "Latency to $host - Min: ${min}ms, Avg: ${avg}ms, Max: ${max}ms, StdDev: ${stddev}ms"
            log_message "Packet Loss: $packet_loss"
            
            # Evaluate jitter (standard deviation)
            if (( $(echo "$stddev < 10" | bc -l) )); then
                print_result "PASS" "Stable connection to $host (jitter: ${stddev}ms)"
            elif (( $(echo "$stddev < 30" | bc -l) )); then
                print_result "WARN" "Moderate jitter to $host (${stddev}ms)"
            else
                print_result "WARN" "High jitter to $host (${stddev}ms) - unstable connection"
            fi
            
            # Check packet loss
            local loss_value=$(echo "$packet_loss" | sed 's/%//')
            if (( $(echo "$loss_value == 0" | bc -l) )); then
                print_result "PASS" "No packet loss to $host"
            elif (( $(echo "$loss_value < 5" | bc -l) )); then
                print_result "WARN" "Minor packet loss to $host ($packet_loss)"
            else
                print_result "FAIL" "Significant packet loss to $host ($packet_loss)"
            fi
        else
            print_result "FAIL" "Cannot perform latency test to $host"
        fi
    done
}

################################################################################
# Function: test_http_connectivity
# Description: Tests HTTP/HTTPS connectivity to a specific URL
# Parameters: $1 - URL to test, $2 - Service name
################################################################################
test_http_connectivity() {
    local url=$1
    local service_name=$2
    
    log_message "Testing HTTP(S) connectivity to $service_name: $url"
    
    # Perform HTTP request with timeout
    local http_code=$(curl -o /dev/null -s -w "%{http_code}" --connect-timeout 10 --max-time 15 "$url" 2>&1)
    local curl_exit=$?
    
    if [[ $curl_exit -eq 0 ]]; then
        if [[ "$http_code" =~ ^[23] ]]; then
            print_result "PASS" "$service_name accessible (HTTP $http_code)"
        elif [[ "$http_code" == "000" ]]; then
            print_result "FAIL" "$service_name unreachable"
        else
            print_result "WARN" "$service_name responded with HTTP $http_code"
        fi
    else
        print_result "FAIL" "$service_name connection failed (curl exit: $curl_exit)"
    fi
    
    # Test SSL certificate validity for HTTPS URLs
    if [[ "$url" =~ ^https ]]; then
        local ssl_check=$(echo | openssl s_client -connect "$(echo $url | sed 's|https://||' | sed 's|/.*||'):443" -servername "$(echo $url | sed 's|https://||' | sed 's|/.*||')" 2>&1 | grep "Verify return code")
        log_message "SSL Check for $service_name: $ssl_check"
        
        if [[ "$ssl_check" =~ "0 (ok)" ]]; then
            print_result "PASS" "$service_name SSL certificate valid"
        else
            print_result "WARN" "$service_name SSL issue: $ssl_check"
        fi
    fi
}

################################################################################
# Function: test_cloud_services
# Description: Tests connectivity to major cloud service providers
################################################################################
test_cloud_services() {
    print_header "Cloud Services Connectivity Tests"
    
    # Microsoft 365
    log_message "Testing Microsoft 365 services..."
    test_http_connectivity "https://portal.office.com" "Microsoft 365 Portal"
    test_http_connectivity "https://outlook.office.com" "Outlook Online"
    test_http_connectivity "https://teams.microsoft.com" "Microsoft Teams"
    test_http_connectivity "https://login.microsoftonline.com" "Azure AD Login"
    
    # ServiceNow
    log_message "Testing ServiceNow services..."
    test_http_connectivity "https://www.servicenow.com" "ServiceNow"
    
    # Jira/Atlassian
    log_message "Testing Jira/Atlassian services..."
    test_http_connectivity "https://www.atlassian.com" "Atlassian Cloud"
    test_http_connectivity "https://id.atlassian.com" "Atlassian ID"
    
    # Jamf
    log_message "Testing Jamf Cloud services..."
    test_http_connectivity "https://www.jamf.com" "Jamf Main Site"
    
    # Optional: Test specific Jamf tenant (uncomment and update with your tenant)
    # test_http_connectivity "https://your-tenant.jamfcloud.com" "Jamf Cloud Tenant"
    
    # Azure
    log_message "Testing Azure services..."
    test_http_connectivity "https://portal.azure.com" "Azure Portal"
    test_http_connectivity "https://management.azure.com" "Azure Resource Manager"
    
    # AWS
    log_message "Testing AWS services..."
    test_http_connectivity "https://console.aws.amazon.com" "AWS Console"
    test_http_connectivity "https://s3.amazonaws.com" "AWS S3"
}

################################################################################
# Function: test_additional_network_features
# Description: Additional useful network diagnostics
################################################################################
test_additional_network_features() {
    print_header "Additional Network Diagnostics"
    
    # Test IPv6 connectivity
    log_message "Testing IPv6 connectivity..."
    if ping6 -c 3 2001:4860:4860::8888 &>/dev/null; then
        print_result "PASS" "IPv6 connectivity available"
    else
        print_result "WARN" "IPv6 not available or not configured"
    fi
    
    # Test MTU
    log_message "Testing MTU and fragmentation..."
    local wifi_interface=$(get_wifi_interface)
    local mtu=$(ifconfig "$wifi_interface" | grep mtu | awk '{print $4}')
    log_message "Current MTU: $mtu"
    
    # Test with ping without fragmentation
    if ping -c 3 -D -s 1472 8.8.8.8 &>/dev/null; then
        print_result "PASS" "Standard MTU working correctly (1500 bytes)"
    else
        print_result "WARN" "Potential MTU issues detected"
    fi
    
    # Check for captive portal
    log_message "Checking for captive portal..."
    local captive_check=$(curl -s -I http://captive.apple.com | head -n 1)
    
    if [[ "$captive_check" =~ "200 OK" ]]; then
        print_result "PASS" "No captive portal detected"
    else
        print_result "WARN" "Possible captive portal present"
        log_message "Captive portal response: $captive_check"
    fi
    
    # Test common ports
    log_message "Testing common service ports..."
    local test_ports=("80:HTTP" "443:HTTPS" "53:DNS" "22:SSH")
    
    for port_info in "${test_ports[@]}"; do
        IFS=: read -r port service <<< "$port_info"
        if nc -zv -w 3 8.8.8.8 "$port" &>/dev/null; then
            print_result "PASS" "Port $port ($service) is accessible"
        else
            print_result "WARN" "Port $port ($service) may be blocked"
        fi
    done
    
    # Traceroute to internet
    log_message "Performing traceroute to 8.8.8.8 (limited to 10 hops)..."
    local traceroute_result=$(traceroute -m 10 -w 2 8.8.8.8 2>&1 | head -n 15)
    log_message "Traceroute results:"
    echo "$traceroute_result" >> "$LOG_FILE"
    
    local hop_count=$(echo "$traceroute_result" | grep -c "^[[:space:]]*[0-9]")
    log_message "Hops to reach Google DNS: $hop_count"
}

################################################################################
# Function: generate_summary_report
# Description: Generates a summary report of all tests
################################################################################
generate_summary_report() {
    print_header "Test Summary Report"
    
    local total_tests=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))
    
    echo ""
    echo "${BOLD}Test Results Summary:${NC}" | tee -a "$RESULTS_FILE"
    echo "────────────────────────────────────────" | tee -a "$RESULTS_FILE"
    echo "${GREEN}Passed:${NC}   $TESTS_PASSED" | tee -a "$RESULTS_FILE"
    echo "${RED}Failed:${NC}   $TESTS_FAILED" | tee -a "$RESULTS_FILE"
    echo "${YELLOW}Warnings:${NC} $TESTS_WARNING" | tee -a "$RESULTS_FILE"
    echo "Total:    $total_tests" | tee -a "$RESULTS_FILE"
    echo "────────────────────────────────────────" | tee -a "$RESULTS_FILE"
    echo "" | tee -a "$RESULTS_FILE"
    
    # Calculate success percentage
    if [[ $total_tests -gt 0 ]]; then
        local success_rate=$(( (TESTS_PASSED * 100) / total_tests ))
        echo "Success Rate: ${success_rate}%" | tee -a "$RESULTS_FILE"
    fi
    
    # Overall assessment
    echo "" | tee -a "$RESULTS_FILE"
    if [[ $TESTS_FAILED -eq 0 ]] && [[ $TESTS_WARNING -eq 0 ]]; then
        echo "${GREEN}${BOLD}Overall Status: EXCELLENT${NC}" | tee -a "$RESULTS_FILE"
        echo "All network tests passed successfully." | tee -a "$RESULTS_FILE"
    elif [[ $TESTS_FAILED -eq 0 ]] && [[ $TESTS_WARNING -gt 0 ]]; then
        echo "${YELLOW}${BOLD}Overall Status: GOOD WITH WARNINGS${NC}" | tee -a "$RESULTS_FILE"
        echo "Network is functional but some issues detected." | tee -a "$RESULTS_FILE"
    elif [[ $TESTS_FAILED -gt 0 ]] && [[ $TESTS_FAILED -le 3 ]]; then
        echo "${YELLOW}${BOLD}Overall Status: DEGRADED${NC}" | tee -a "$RESULTS_FILE"
        echo "Network has some failures but core connectivity works." | tee -a "$RESULTS_FILE"
    else
        echo "${RED}${BOLD}Overall Status: CRITICAL${NC}" | tee -a "$RESULTS_FILE"
        echo "Network has significant issues requiring attention." | tee -a "$RESULTS_FILE"
    fi
    
    echo "" | tee -a "$RESULTS_FILE"
    echo "Detailed logs saved to: $LOG_FILE" | tee -a "$RESULTS_FILE"
    echo "Results summary saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
}

################################################################################
# Function: collect_system_info
# Description: Collects system information for diagnostics
################################################################################
collect_system_info() {
    print_header "System Information"
    
    log_message "macOS Version: $(sw_vers -productVersion)"
    log_message "Build: $(sw_vers -buildVersion)"
    log_message "Computer Name: $(scutil --get ComputerName)"
    log_message "Hostname: $(hostname)"
    log_message "Current User: $(whoami)"
    log_message "Test Date: $(date)"
    
    # Get network interface list
    log_message "Network Interfaces:"
    ifconfig | grep "^[a-z]" | awk '{print $1}' | while read -r iface; do
        log_message "  - $iface"
    done
}

################################################################################
# Main execution function
################################################################################
main() {
    clear
    
    echo "${BOLD}${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║     macOS Wireless Network Testing & Diagnostics Suite        ║"
    echo "║                    Version 1.0                                 ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo "${NC}"
    
    log_message "========== Starting Wireless Network Test Suite =========="
    
    # Check if running on macOS
    if [[ "$(uname)" != "Darwin" ]]; then
        print_result "FAIL" "This script must be run on macOS"
        exit 1
    fi
    
    # Collect system information
    collect_system_info
    
    # Run all tests
    test_wifi_status || true
    test_ip_configuration || true
    test_gateway_connectivity || true
    test_internet_connectivity || true
    test_dns_resolution || true
    test_network_speed || true
    test_cloud_services || true
    test_additional_network_features || true
    
    # Generate final report
    generate_summary_report
    
    log_message "========== Network Test Suite Completed =========="
    
    echo ""
    echo "${BOLD}Testing complete!${NC}"
    echo "Review the detailed logs at: ${BLUE}$LOG_FILE${NC}"
    echo ""
}

# Execute main function
main "$@"