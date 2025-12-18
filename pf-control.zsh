#!/bin/zsh

setopt ERR_EXIT NO_UNSET PIPE_FAIL

readonly SCRIPT_VERSION="1.0.0"

# Configuration
@@@
readonly LOG_FILE="/var/log/file-sharing-manager.log"
readonly AUDIT_LOG="/var/log/file-sharing-audit.log"
readonly PF_ANCHOR="file-sharing-block"
readonly DEBUG_MODE="${FILE_SHARING_DEBUG:-false}"
readonly PING_TIMEOUT_MS=2000
readonly MAX_RETRIES=2
readonly RETRY_DELAY_SECONDS=1
readonly SERVICE_STOP_TIMEOUT=5

# Ports to block when file sharing should be disabled
readonly BLOCK_PORTS=(
    "139"
    "445"
    "548"
    "137"
    "138"
    "5353"
)

readonly SERVICES=(
    "com.apple.smbd"
    "com.apple.AppleFileServer"
    "com.apple.netbiosd"
)

typeset -g TEMP_RULES_FILE=""
typeset -g LOGGING_AVAILABLE=false

cleanup() {
    if [[ -n "${TEMP_RULES_FILE}" ]] && [[ -f "${TEMP_RULES_FILE}" ]]; then
        rm -f "${TEMP_RULES_FILE}"
    fi
}

trap cleanup EXIT INT TERM

ensure_log_file() {
    local log_dir
    log_dir=$(dirname "${LOG_FILE}")
    
    if [[ ! -d "${log_dir}" ]]; then
        if ! mkdir -p "${log_dir}"; then
            echo "ERROR: Cannot create log directory: ${log_dir}" >&2
            return 1
        fi
        chmod 755 "${log_dir}" 2>/dev/null || true
    fi
    
    if [[ ! -f "${LOG_FILE}" ]]; then
        if ! touch "${LOG_FILE}"; then
            echo "ERROR: Cannot create log file: ${LOG_FILE}" >&2
            return 1
        fi
        chmod 644 "${LOG_FILE}" 2>/dev/null || true
    fi
    
    if [[ ! -w "${LOG_FILE}" ]]; then
        echo "ERROR: Log file not writable: ${LOG_FILE}" >&2
        return 1
    fi
    
    return 0
}

ensure_audit_log() {
    local log_dir
    log_dir=$(dirname "${AUDIT_LOG}")
    
    if [[ ! -d "${log_dir}" ]]; then
        mkdir -p "${log_dir}" 2>/dev/null || true
    fi
    
    if [[ ! -f "${AUDIT_LOG}" ]]; then
        touch "${AUDIT_LOG}" 2>/dev/null || true
        chmod 600 "${AUDIT_LOG}" 2>/dev/null || true
    fi
}

log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    local syslog_level
    
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    if [[ "${LOGGING_AVAILABLE}" == true ]]; then
        echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
    else
        echo "[${timestamp}] [${level}] ${message}"
    fi
    
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        case "${level}" in
            warn) syslog_level="warning" ;;
            error) syslog_level="err" ;;
            *) syslog_level="${level}" ;;
        esac
        logger -t "file-sharing-manager" -p "user.${syslog_level}" "${message}" 2>/dev/null || true
    fi
}

audit_log() {
    local action="$1"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S %z")
    
    if [[ -w "${AUDIT_LOG}" ]]; then
        echo "[${timestamp}] ${action}" >> "${AUDIT_LOG}"
    fi
}

get_wireless_interface() {
    local interface
    
    interface=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
    
    if [[ -z "${interface}" ]]; then
        log_message "error" "Failed to identify wireless interface"
        return 1
    fi
    
    if ! ifconfig "${interface}" >/dev/null 2>&1; then
        log_message "error" "Interface ${interface} does not exist"
        return 1
    fi
    
    echo "${interface}"
}

get_current_ssid() {
    local interface="$1"
    local ssid
    
    if [[ -z "${interface}" ]]; then
        return 1
    fi
    
    ssid=$(networksetup -getairportnetwork "${interface}" 2>/dev/null | awk -F': ' 'NF==2 {print $2}')
    
    if [[ -z "${ssid}" ]] && [[ -x "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport" ]]; then
        ssid=$(/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/ SSID/ {print $2}')
    fi
    
    echo "${ssid}"
}

check_dns_suffix() {
    local suffixes
    local suffix
    
    suffixes=$(scutil --dns | awk '/domain.*:/ {print $3}')
    
    if [[ -z "${suffixes}" ]]; then
        log_message "debug" "No DNS suffixes found"
        return 1
    fi
    
    while IFS= read -r suffix; do
        if [[ -n "${suffix}" ]] && [[ "${suffix}" == "${EXPECTED_DNS_SUFFIX}" ]]; then
            return 0
        fi
    done <<< "${suffixes}"
    
    return 1
}

check_cyberark_reachable() {
    local attempt
    
    for attempt in {1..$MAX_RETRIES}; do
        if ping -c 1 -W ${PING_TIMEOUT_MS} "${TEST_HOST}" &>/dev/null; then
            return 0
        fi
        
        if [[ ${attempt} -lt ${MAX_RETRIES} ]]; then
            sleep ${RETRY_DELAY_SECONDS}
        fi
    done
    
    return 1
}

check_vpn_connection() {
    scutil --nc list 2>/dev/null | grep -q "Connected"
}

determine_network_location() {
    local interface
    local ssid
    local on_corporate_wifi=false
    local cyberark_reachable=false
    local correct_dns=false
    local vpn_connected=false
    
    if ! interface=$(get_wireless_interface); then
        log_message "warn" "Could not determine wireless interface"
        echo "unknown"
        return 1
    fi
    
    ssid=$(get_current_ssid "${interface}")
    if [[ -n "${ssid}" ]] && [[ "${ssid}" == "${CORPORATE_SSID}" ]]; then
        on_corporate_wifi=true
        log_message "info" "Connected to corporate WiFi: ${CORPORATE_SSID}"
    fi
    
    if check_dns_suffix; then
        correct_dns=true
        log_message "info" "DNS suffix matches corporate: ${EXPECTED_DNS_SUFFIX}"
    fi
    
    if check_cyberark_reachable; then
        cyberark_reachable=true
        log_message "info" "CyberArk server reachable"
    fi
    
    if check_vpn_connection; then
        vpn_connected=true
        log_message "info" "VPN connection detected"
    fi
    
    if [[ "${on_corporate_wifi}" == true ]] && [[ "${correct_dns}" == true ]] && [[ "${cyberark_reachable}" == true ]]; then
        echo "corporate"
        return 0
    elif [[ "${cyberark_reachable}" == true ]] && ([[ "${correct_dns}" == true ]] || [[ "${vpn_connected}" == true ]]); then
        echo "vpn"
        return 0
    else
        echo "external"
        return 0
    fi
}

is_service_enabled() {
    local service="$1"
    
    if launchctl print-disabled system 2>/dev/null | grep -q "\"${service}\" => disabled"; then
        return 1
    fi
    
    return 0
}

is_service_running() {
    local service="$1"
    
    launchctl list 2>/dev/null | grep -q "${service}"
}

verify_service_stopped() {
    local service="$1"
    local count=0
    
    while [[ ${count} -lt ${SERVICE_STOP_TIMEOUT} ]]; do
        if ! is_service_running "${service}"; then
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    log_message "error" "Service ${service} still running after ${SERVICE_STOP_TIMEOUT} seconds"
    return 1
}

verify_service_started() {
    local service="$1"
    local count=0
    
    while [[ ${count} -lt ${SERVICE_STOP_TIMEOUT} ]]; do
        if is_service_running "${service}"; then
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    log_message "error" "Service ${service} not running after ${SERVICE_STOP_TIMEOUT} seconds"
    return 1
}

enable_smb_service() {
    local bootstrap_failed=false
    local kickstart_failed=false
    
    log_message "info" "Enabling SMB file sharing"
    
    if launchctl enable system/com.apple.smbd 2>/dev/null; then
        log_message "info" "Enabled system/com.apple.smbd"
    else
        if is_service_enabled "com.apple.smbd"; then
            log_message "debug" "SMB service already enabled"
        else
            log_message "warn" "Failed to enable SMB service via launchctl"
        fi
    fi
    
    if ! launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.smbd.plist 2>/dev/null; then
        bootstrap_failed=true
        log_message "debug" "Failed to bootstrap SMB service (may already be loaded)"
    fi
    
    if ! launchctl kickstart -k system/com.apple.smbd 2>/dev/null; then
        kickstart_failed=true
        log_message "warn" "Failed to kickstart SMB service"
    fi
    
    if [[ "${bootstrap_failed}" == true ]] && [[ "${kickstart_failed}" == true ]]; then
        log_message "error" "SMB service control failed"
        return 1
    fi
    
    if ! verify_service_started "com.apple.smbd"; then
        log_message "error" "SMB service failed to start"
        return 1
    fi
    
    log_message "info" "SMB service started successfully"
    return 0
}

disable_smb_service() {
    log_message "info" "Disabling SMB file sharing"
    
    if is_service_running "com.apple.smbd"; then
        launchctl kill SIGTERM system/com.apple.smbd 2>/dev/null || true
        sleep 1
    fi
    
    launchctl bootout system /System/Library/LaunchDaemons/com.apple.smbd.plist 2>/dev/null || true
    
    if launchctl disable system/com.apple.smbd 2>/dev/null; then
        log_message "info" "Disabled system/com.apple.smbd"
    else
        if ! is_service_enabled "com.apple.smbd"; then
            log_message "debug" "SMB service already disabled"
        else
            log_message "warn" "Failed to disable SMB service via launchctl"
        fi
    fi
    
    if ! verify_service_stopped "com.apple.smbd"; then
        log_message "error" "SMB service failed to stop"
        return 1
    fi
    
    log_message "info" "SMB service stopped successfully"
    return 0
}

enable_afp_service() {
    local bootstrap_failed=false
    local kickstart_failed=false
    
    log_message "info" "Enabling AFP file sharing"
    
    if launchctl enable system/com.apple.AppleFileServer 2>/dev/null; then
        log_message "info" "Enabled system/com.apple.AppleFileServer"
    else
        if is_service_enabled "com.apple.AppleFileServer"; then
            log_message "debug" "AFP service already enabled"
        else
            log_message "warn" "Failed to enable AFP service via launchctl"
        fi
    fi
    
    if ! launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist 2>/dev/null; then
        bootstrap_failed=true
        log_message "debug" "Failed to bootstrap AFP service (may already be loaded)"
    fi
    
    if ! launchctl kickstart -k system/com.apple.AppleFileServer 2>/dev/null; then
        kickstart_failed=true
        log_message "warn" "Failed to kickstart AFP service"
    fi
    
    if [[ "${bootstrap_failed}" == true ]] && [[ "${kickstart_failed}" == true ]]; then
        log_message "error" "AFP service control failed"
        return 1
    fi
    
    if ! verify_service_started "com.apple.AppleFileServer"; then
        log_message "error" "AFP service failed to start"
        return 1
    fi
    
    log_message "info" "AFP service started successfully"
    return 0
}

disable_afp_service() {
    log_message "info" "Disabling AFP file sharing"
    
    if is_service_running "com.apple.AppleFileServer"; then
        launchctl kill SIGTERM system/com.apple.AppleFileServer 2>/dev/null || true
        sleep 1
    fi
    
    launchctl bootout system /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist 2>/dev/null || true
    
    if launchctl disable system/com.apple.AppleFileServer 2>/dev/null; then
        log_message "info" "Disabled system/com.apple.AppleFileServer"
    else
        if ! is_service_enabled "com.apple.AppleFileServer"; then
            log_message "debug" "AFP service already disabled"
        else
            log_message "warn" "Failed to disable AFP service via launchctl"
        fi
    fi
    
    if ! verify_service_stopped "com.apple.AppleFileServer"; then
        log_message "error" "AFP service failed to stop"
        return 1
    fi
    
    log_message "info" "AFP service stopped successfully"
    return 0
}

enable_netbios_service() {
    local bootstrap_failed=false
    local kickstart_failed=false
    
    log_message "info" "Enabling NetBIOS service"
    
    if launchctl enable system/com.apple.netbiosd 2>/dev/null; then
        log_message "info" "Enabled system/com.apple.netbiosd"
    else
        if is_service_enabled "com.apple.netbiosd"; then
            log_message "debug" "NetBIOS service already enabled"
        else
            log_message "warn" "Failed to enable NetBIOS service via launchctl"
        fi
    fi
    
    if ! launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.netbiosd.plist 2>/dev/null; then
        bootstrap_failed=true
        log_message "debug" "Failed to bootstrap NetBIOS service (may already be loaded)"
    fi
    
    if ! launchctl kickstart -k system/com.apple.netbiosd 2>/dev/null; then
        kickstart_failed=true
        log_message "warn" "Failed to kickstart NetBIOS service"
    fi
    
    if [[ "${bootstrap_failed}" == true ]] && [[ "${kickstart_failed}" == true ]]; then
        log_message "error" "NetBIOS service control failed"
        return 1
    fi
    
    if ! verify_service_started "com.apple.netbiosd"; then
        log_message "error" "NetBIOS service failed to start"
        return 1
    fi
    
    log_message "info" "NetBIOS service started successfully"
    return 0
}

disable_netbios_service() {
    log_message "info" "Disabling NetBIOS service"
    
    if is_service_running "com.apple.netbiosd"; then
        launchctl kill SIGTERM system/com.apple.netbiosd 2>/dev/null || true
        sleep 1
    fi
    
    launchctl bootout system /System/Library/LaunchDaemons/com.apple.netbiosd.plist 2>/dev/null || true
    
    if launchctl disable system/com.apple.netbiosd 2>/dev/null; then
        log_message "info" "Disabled system/com.apple.netbiosd"
    else
        if ! is_service_enabled "com.apple.netbiosd"; then
            log_message "debug" "NetBIOS service already disabled"
        else
            log_message "warn" "Failed to disable NetBIOS service via launchctl"
        fi
    fi
    
    if ! verify_service_stopped "com.apple.netbiosd"; then
        log_message "error" "NetBIOS service failed to stop"
        return 1
    fi
    
    log_message "info" "NetBIOS service stopped successfully"
    return 0
}

enable_file_sharing() {
    local failed_services=()
    
    log_message "info" "Enabling file sharing services"
    
    if ! enable_smb_service; then
        failed_services+=("SMB")
    fi
    
    if ! enable_afp_service; then
        failed_services+=("AFP")
    fi
    
    if ! enable_netbios_service; then
        failed_services+=("NetBIOS")
    fi
    
    remove_pf_rules
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_message "error" "Failed to enable services: ${failed_services[*]}"
        audit_log "ENABLE_FAILED - Services: ${failed_services[*]}"
        return 1
    fi
    
    audit_log "ENABLE_SUCCESS - All file sharing services enabled"
    return 0
}

disable_file_sharing() {
    local failed_services=()
    
    log_message "info" "Disabling file sharing services"
    
    if ! disable_smb_service; then
        failed_services+=("SMB")
    fi
    
    if ! disable_afp_service; then
        failed_services+=("AFP")
    fi
    
    if ! disable_netbios_service; then
        failed_services+=("NetBIOS")
    fi
    
    if ! apply_pf_rules; then
        log_message "error" "Failed to apply PF rules"
        audit_log "DISABLE_FAILED - PF rules not applied"
        return 1
    fi
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_message "warn" "Some services failed to stop: ${failed_services[*]}"
        log_message "info" "PF rules are in place as additional protection"
        audit_log "DISABLE_PARTIAL - Failed services: ${failed_services[*]}, PF rules active"
        return 1
    fi
    
    audit_log "DISABLE_SUCCESS - All file sharing services disabled, PF rules active"
    return 0
}

ensure_pf_anchor_loaded() {
    local pf_conf="/etc/pf.conf"
    local anchor_line="anchor \"${PF_ANCHOR}\""
    local load_anchor_line="load anchor \"${PF_ANCHOR}\" from \"/etc/pf.anchors/${PF_ANCHOR}\""
    local pf_conf_modified=false
    
    if [[ ! -f "${pf_conf}" ]]; then
        log_message "warn" "PF configuration file ${pf_conf} does not exist, creating default"
        cat > "${pf_conf}" << 'EOF'
# Default PF configuration for macOS
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
EOF
        pf_conf_modified=true
    fi
    
    if ! grep -q "^anchor \"${PF_ANCHOR}\"" "${pf_conf}" 2>/dev/null; then
        log_message "info" "Adding anchor reference to ${pf_conf}"
        echo "" >> "${pf_conf}"
        echo "# File sharing manager anchor" >> "${pf_conf}"
        echo "${anchor_line}" >> "${pf_conf}"
        pf_conf_modified=true
    fi
    
    if [[ "${pf_conf_modified}" == true ]]; then
        if ! pfctl -f "${pf_conf}" 2>/dev/null; then
            log_message "error" "Failed to reload PF configuration"
            return 1
        fi
        log_message "info" "PF configuration reloaded"
    fi
    
    return 0
}

apply_pf_rules() {
    local port
    local pf_was_enabled=false
    local rules_file="/etc/pf.anchors/${PF_ANCHOR}"
    
    log_message "info" "Applying PF firewall rules to block file sharing ports"
    
    if [[ ! -d "/etc/pf.anchors" ]]; then
        mkdir -p "/etc/pf.anchors"
        chmod 755 "/etc/pf.anchors"
    fi
    
    TEMP_RULES_FILE=$(mktemp /tmp/pf-file-sharing.XXXXXX)
    
    cat > "${TEMP_RULES_FILE}" << 'EOF'
# Block all file sharing ports inbound and outbound
EOF
    
    for port in "${BLOCK_PORTS[@]}"; do
        echo "block drop in quick proto tcp from any to any port ${port}" >> "${TEMP_RULES_FILE}"
        echo "block drop out quick proto tcp from any to any port ${port}" >> "${TEMP_RULES_FILE}"
        echo "block drop in quick proto udp from any to any port ${port}" >> "${TEMP_RULES_FILE}"
        echo "block drop out quick proto udp from any to any port ${port}" >> "${TEMP_RULES_FILE}"
    done
    
    cp "${TEMP_RULES_FILE}" "${rules_file}"
    chmod 644 "${rules_file}"
    
    if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
        pf_was_enabled=true
    fi
    
    if ! ensure_pf_anchor_loaded; then
        log_message "error" "Failed to configure PF anchor"
        return 1
    fi
    
    if [[ "${pf_was_enabled}" == false ]]; then
        log_message "info" "Enabling PF firewall"
        if ! pfctl -e 2>/dev/null; then
            log_message "error" "Failed to enable PF firewall"
            return 1
        fi
    fi
    
    if ! pfctl -a "${PF_ANCHOR}" -f "${rules_file}" 2>/dev/null; then
        log_message "error" "Failed to apply PF rules"
        
        if [[ "${pf_was_enabled}" == false ]]; then
            log_message "warn" "Disabling PF as rule loading failed"
            pfctl -d 2>/dev/null || true
        fi
        return 1
    fi
    
    if ! verify_pf_rules_active; then
        log_message "error" "PF rules loaded but not active"
        return 1
    fi
    
    log_message "info" "PF rules applied and verified active"
    return 0
}

verify_pf_rules_active() {
    local rules_count
    
    rules_count=$(pfctl -a "${PF_ANCHOR}" -sr 2>/dev/null | wc -l | tr -d ' ')
    
    if [[ "${rules_count}" -eq 0 ]]; then
        log_message "error" "No rules found in anchor ${PF_ANCHOR}"
        return 1
    fi
    
    log_message "debug" "PF anchor contains ${rules_count} active rules"
    return 0
}

remove_pf_rules() {
    local rules_file="/etc/pf.anchors/${PF_ANCHOR}"
    
    log_message "info" "Removing PF firewall rules"
    
    if pfctl -a "${PF_ANCHOR}" -F all 2>/dev/null; then
        log_message "info" "PF rules flushed from anchor"
    else
        log_message "debug" "No PF rules to flush from anchor"
    fi
    
    if [[ -f "${rules_file}" ]]; then
        rm -f "${rules_file}"
        log_message "debug" "Removed anchor rules file"
    fi
    
    local rules_count
    rules_count=$(pfctl -a "${PF_ANCHOR}" -sr 2>/dev/null | wc -l | tr -d ' ')
    
    if [[ ${rules_count} -gt 0 ]]; then
        log_message "warn" "PF rules still active after removal attempt (${rules_count} rules remain)"
        return 1
    fi
    
    log_message "info" "PF rules removed successfully"
    return 0
}

check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run with root privileges" >&2
        echo "Please run: sudo ${0:A}" >&2
        exit 1
    fi
}

validate_configuration() {
    if [[ -z "${CORPORATE_SSID}" ]]; then
        log_message "error" "CORPORATE_SSID not configured"
        return 1
    fi
    
    if [[ -z "${TEST_HOST}" ]]; then
        log_message "error" "TEST_HOST not configured"
        return 1
    fi
    
    if [[ -z "${EXPECTED_DNS_SUFFIX}" ]]; then
        log_message "error" "EXPECTED_DNS_SUFFIX not configured"
        return 1
    fi
    
    return 0
}

show_status() {
    echo "File Sharing Manager Status"
    echo "============================"
    echo ""
    echo "Services:"
    for service in "${SERVICES[@]}"; do
        if is_service_running "${service}"; then
            echo "  ${service}: RUNNING"
        else
            echo "  ${service}: STOPPED"
        fi
        
        if is_service_enabled "${service}"; then
            echo "    Enabled: YES"
        else
            echo "    Enabled: NO"
        fi
    done
    echo ""
    echo "PF Firewall Configuration:"
    if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
        echo "  PF Status: ENABLED"
    else
        echo "  PF Status: DISABLED"
    fi
    
    if grep -q "^anchor \"${PF_ANCHOR}\"" /etc/pf.conf 2>/dev/null; then
        echo "  Anchor in pf.conf: YES"
    else
        echo "  Anchor in pf.conf: NO (rules will not be active)"
    fi
    
    if [[ -f "/etc/pf.anchors/${PF_ANCHOR}" ]]; then
        echo "  Anchor file exists: YES"
    else
        echo "  Anchor file exists: NO"
    fi
    
    echo ""
    echo "Active PF Rules in Anchor:"
    local rules_output
    rules_output=$(pfctl -a "${PF_ANCHOR}" -sr 2>/dev/null)
    
    if [[ -n "${rules_output}" ]]; then
        echo "${rules_output}" | head -10
        local rule_count
        rule_count=$(echo "${rules_output}" | wc -l | tr -d ' ')
        if [[ ${rule_count} -gt 10 ]]; then
            echo "  ... (${rule_count} total rules, showing first 10)"
        fi
    else
        echo "  NO ACTIVE RULES (file sharing not blocked)"
    fi
}

show_usage() {
    cat << EOF
Usage: ${0:t} [OPTIONS]

Network-aware file sharing manager for macOS

Automatically enables file sharing on trusted networks (corporate WiFi or VPN)
and disables it on untrusted networks, with PF firewall protection.

OPTIONS:
    -h, --help      Show this help message
    -v, --version   Show version information
    -s, --status    Show current file sharing and firewall status

ENVIRONMENT VARIABLES:
    FILE_SHARING_DEBUG=true    Enable debug logging to syslog

CONFIGURATION:
    Corporate SSID:     ${CORPORATE_SSID}
    Test Host:          ${TEST_HOST}
    DNS Suffix:         ${EXPECTED_DNS_SUFFIX}
    Log File:           ${LOG_FILE}
    Audit Log:          ${AUDIT_LOG}

EXAMPLES:
    sudo ${0:t}                 # Run normally
    sudo ${0:t} --status        # Show current status
    FILE_SHARING_DEBUG=true sudo ${0:t}  # Run with debug logging

EXIT CODES:
    0    Success
    1    Error (network detection failed, service control failed, etc.)

EOF
}

show_version() {
    echo "${0:t} version ${SCRIPT_VERSION}"
}

main() {
    local location
    
    if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
        show_usage
        exit 0
    fi
    
    if [[ "${1:-}" == "-v" ]] || [[ "${1:-}" == "--version" ]]; then
        show_version
        exit 0
    fi
    
    check_root_privileges
    
    if [[ "${1:-}" == "-s" ]] || [[ "${1:-}" == "--status" ]]; then
        show_status
        exit 0
    fi
    
    if ! ensure_log_file; then
        echo "CRITICAL: Cannot initialise logging, exiting" >&2
        exit 1
    fi
    
    LOGGING_AVAILABLE=true
    ensure_audit_log
    
    if ! validate_configuration; then
        log_message "error" "Configuration validation failed"
        exit 1
    fi
    
    log_message "info" "Starting file sharing management check (version ${SCRIPT_VERSION})"
    
    if ! location=$(determine_network_location); then
        log_message "error" "Failed to determine network location, defaulting to secure state"
        audit_log "NETWORK_UNKNOWN - Defaulting to secure state"
        if ! disable_file_sharing; then
            log_message "error" "Failed to disable file sharing in secure default state"
            exit 1
        fi
        exit 1
    fi
    
    log_message "info" "Network location determined: ${location}"
    audit_log "NETWORK_LOCATION - ${location}"
    
    case "${location}" in
        corporate|vpn)
            log_message "info" "On trusted network, enabling file sharing"
            if ! enable_file_sharing; then
                log_message "error" "Failed to enable file sharing"
                audit_log "ENABLE_FAILED - Location: ${location}"
                exit 1
            fi
            ;;
        external|unknown)
            log_message "info" "On untrusted network, disabling file sharing"
            if ! disable_file_sharing; then
                log_message "error" "Failed to disable file sharing completely"
                audit_log "DISABLE_FAILED - Location: ${location}"
                exit 1
            fi
            ;;
        *)
            log_message "error" "Unknown network state, defaulting to secure state"
            audit_log "NETWORK_INVALID - ${location}, defaulting to secure state"
            if ! disable_file_sharing; then
                log_message "error" "Failed to disable file sharing in secure default state"
                exit 1
            fi
            exit 1
            ;;
    esac
    
    log_message "info" "File sharing management completed successfully"
}

main "$@"
