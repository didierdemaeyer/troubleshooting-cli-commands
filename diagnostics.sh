#!/usr/bin/env bash
# ------------------------------------------------------------
# diagnostics.sh – One‑stop diagnostics for Linux, macOS, Windows via WSL
# ------------------------------------------------------------
# What it does (per OS):
#   • Network config & IP address
#   • Ping & traceroute to a target (default: 8.8.8.8)
#   • DNS lookup (dig / nslookup)
#   • Listening sockets / open ports
#   • Process snapshot
#   • Disk usage summary
#   • Basic hardware / system info
# ------------------------------------------------------------

set -euo pipefail # safety: exit on error, treat unset vars as error

# ---------- Configurable parameters ----------
TARGET_HOST=${1:-8.8.8.8} # you can pass a host/IP as first argument
REPORT_ROOT="${HOME}/diagnostics-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${REPORT_ROOT}"

log() {
    echo "[*] $*" | tee -a "${REPORT_ROOT}/summary.log"
}

# ---------- OS detection ----------
OS_TYPE="$(uname -s)"
case "${OS_TYPE}" in
Linux*) OS="linux" ;;
Darwin*) OS="macos" ;;
CYGWIN* | MINGW* | MSYS*) OS="windows" ;; # Not native Bash, but catches Git‑Bash / MSYS
*) OS="unknown" ;;
esac

log "Detected OS: ${OS}"
log "Target host for ping/traceroute: ${TARGET_HOST}"
log "Report directory: ${REPORT_ROOT}"
echo "" >>"${REPORT_ROOT}/summary.log"

# ---------- Helper to save command output ----------
run_and_save() {
    local cmd_desc="$1"
    local cmd="$2"
    local outfile="${REPORT_ROOT}/${cmd_desc}.txt"

    log "Running: ${cmd_desc}"
    echo "=== ${cmd_desc} ===" >"${outfile}"
    eval "${cmd}" >>"${outfile}" 2>&1 || echo "(command failed)" >>"${outfile}"
    echo "" >>"${outfile}"
}

# ---------- Linux section ----------
if [[ "${OS}" == "linux" ]]; then
    run_and_save "network_interfaces" "ip addr show"
    run_and_save "routing_table" "ip route show"
    run_and_save "ping" "ping -c 4 ${TARGET_HOST}"
    run_and_save "traceroute" "traceroute ${TARGET_HOST}"
    run_and_save "dns_dig" "dig ${TARGET_HOST} +short"
    run_and_save "listening_ports" "ss -tulnp"
    run_and_save "process_snapshot" "ps aux --sort=-%cpu | head -n 20"
    run_and_save "disk_usage" "df -hT"
    run_and_save "hardware_summary" "lshw -short 2>/dev/null || echo 'lshw not installed'"
    run_and_save "system_logs_recent" "journalctl -p 3 -xb --no-pager | tail -n 50"

# ---------- macOS section ----------
elif [[ "${OS}" == "macos" ]]; then
    run_and_save "network_interfaces" "ifconfig"
    run_and_save "routing_table" "netstat -nr"
    run_and_save "ping" "ping -c 4 ${TARGET_HOST}"
    run_and_save "traceroute" "traceroute ${TARGET_HOST}"
    run_and_save "dns_dig" "dig ${TARGET_HOST} +short"
    run_and_save "listening_ports" "lsof -iTCP -sTCP:LISTEN -Pn"
    run_and_save "process_snapshot" "ps aux --sort=-%cpu | head -n 20"
    run_and_save "disk_usage" "df -h"
    run_and_save "hardware_summary" "system_profiler SPHardwareDataType"
    run_and_save "battery_status" "pmset -g batt"
    run_and_save "system_logs_recent" "log show --predicate 'eventMessage contains \"error\"' --last 1h | tail -n 50"

# ---------- Windows (WSL / Git‑Bash) ----------
elif [[ "${OS}" == "windows" ]]; then
    # Most Windows‑specific tools are PowerShell cmdlets; we invoke them via `powershell -NoProfile -Command`.
    run_and_save "network_interfaces" "powershell -NoProfile -Command \"Get-NetIPAddress | Format-Table\""
    run_and_save "routing_table" "powershell -NoProfile -Command \"Get-NetRoute | Format-Table\""
    run_and_save "ping" "ping -n 4 ${TARGET_HOST}"
    run_and_save "tracert" "tracert ${TARGET_HOST}"
    run_and_save "dns_nslookup" "nslookup ${TARGET_HOST}"
    run_and_save "listening_ports" "powershell -NoProfile -Command \"Get-NetTCPConnection -State Listen | Format-Table\""
    run_and_save "process_snapshot" "powershell -NoProfile -Command \"Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table\""
    run_and_save "disk_usage" "powershell -NoProfile -Command \"Get-PSDrive -PSProvider FileSystem | Format-Table\""
    run_and_save "systeminfo" "systeminfo"
    run_and_save "eventlog_errors" "powershell -NoProfile -Command \"Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 30 | Format-Table TimeCreated, Id, Message -AutoSize\""

else
    log "Unsupported OS – exiting."
    exit 1
fi

log ""
log "=== Diagnostic collection complete ==="
log "All files are stored in: ${REPORT_ROOT}"
log "You can archive them with:"
log "    tar -czvf diagnostics-$(date +%Y%m%d-%H%M%S).tar.gz -C \"${REPORT_ROOT}\" ."
log "Happy troubleshooting!"

exit 0
