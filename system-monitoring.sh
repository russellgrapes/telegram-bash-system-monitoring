#!/bin/bash

#  _________   _________   _________
# |         | |         | |         |
# |   six   | |    2    | |   one   |
# |_________| |_________| |_________|
#     |||         |||         |||
# -----------------------------------
#    system-monitoring.sh v5.4.2
# -----------------------------------

# Telegram Bash System Monitoring (single-file)
#
# Run model:
#   Start once at boot via crontab "@reboot". The script stays alive and monitors.
#
# First run (important):
#   Run manually as root once to create /etc/telegram.secrets (cron/@reboot has no TTY).
#
# Telegram Credentials:
#   Stored in /etc/telegram.secrets (root:root, chmod 600, not a symlink).
#   Format:
#     GROUP_ID="12345678"
#     BOT_TOKEN="123456:ABC..."
#
# Maintenance mute:
#   echo 1 >/root/telegramm_lock.state   # mute Telegram alerts
#   rm -f /root/telegramm_lock.state    # unmute (cooldowns reset on unlock)
#
# Control plane (must be used alone):
#   --STATUS   --RELOAD   --KILL
#
# Repo: https://github.com/russellgrapes/telegram-bash-system-monitoring
#
# For icons in Telegram: ☮⚠ https://www.w3schools.com/charsets/ref_utf_symbols.asp
#
# Author: https://github.com/russellgrapes/






# -------------------------------------------------------------------------------------------------------------------------- #
#                                                                                                                            #
#        Crontab @reboot
#
# Start once at boot and keep running (the core design of this script):
#   @reboot /usr/local/bin/system-monitoring.sh --NAME MyServer --CPU --RAM --DISK --TEMP --LA1 --LA5 --LA15 --SSH --SFTP --REBOOT >>/var/log/system-monitoring.log 2>&1
#
# PATH hardening (root):
# Keep PATH minimal to reduce PATH hijack risk.
# Add extra dirs only if you must:
#   SYSTEM_MONITORING_EXTRA_PATH="/opt/bin:/usr/local/sbin"
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
if [[ -n "${SYSTEM_MONITORING_EXTRA_PATH:-}" ]]; then
    PATH="${PATH}:${SYSTEM_MONITORING_EXTRA_PATH}"
fi
export PATH
readonly PATH
#                                                                                                                            #
# -------------------------------------------------------------------------------------------------------------------------- #






# -------------------------------------------------------------------------------------------------------------------------- #
#                                                                                                                            #
#         User settings                                                                                                      #
#                                                                                                                            #
# Most behavior is configured via CLI flags. Edit below only if you want different defaults.                                 #
#                                                                                                                            #
# Telegram host label (override per run with: --NAME)
HOST_NAME=$(hostname)
#
# Internal state (locks, last-alert timestamps, ssh/sftp session snapshots).
# Safe to delete if you want a clean reset.
SYSTEM_MONITORING_STATE_DIR="/usr/local/bin/.system-monitoring"
#
# Telegram mute switch (maintenance mode):
#   "1" = locked (no alerts)
#   missing/empty/anything else = alerts enabled
TELEGRAMM_LOCK_STATE="/usr/local/bin/telegramm_lock.state"
#
# Telegram credentials (created interactively on first run WITH a TTY).
# cron/@reboot has no TTY → create this file before enabling @reboot.
SECRETS_FILE="/etc/telegram.secrets"
#
# Loop timing:
# FAST: CPU/RAM/LA1 + SSH/SFTP activity polling
# SLOW: disk/temp/LA15 and slow-moving checks
FAST_CHECK_INTERVAL=60     # seconds (1 minute)
SLOW_CHECK_INTERVAL=5400   # seconds (90 minutes)
#
# Default remote check interval used by --PING / --PING-LIST when Interval= is not provided
PING_CHECK_INTERVAL=30     # seconds
#
# Alert cooldowns (seconds): minimum time between repeated alerts while still above threshold.
# Set to 0 to disable cooldown (usually means spam).
CPU_ALERT_COOLDOWN=600     # seconds | affects --CPU alerts
LA_ALERT_COOLDOWN=600      # seconds | shared across --LA1/--LA5/--LA15 alerts
RAM_ALERT_COOLDOWN=600     # seconds | affects --RAM alerts
DISK_ALERT_COOLDOWN=86400  # seconds | affects --DISK alerts (per mount); default: 24h
#
# SSH_ACTIVITY_EXCLUDED_IPS is an array that holds IP literals or CIDR ranges (IPv4 and/or IPv6) that should be
# ignored by the --SSH and --SFTP monitoring feature. When specified, the script will not send
# alerts for SSH/SFTP activity originating from these IPs. Examples:
# - IPv4 single host:   "192.168.1.1" or "192.168.2.4/32"
# - IPv4 subnet:        "192.168.1.0/24" or "10.10.0.0/16"
# - IPv6 single host:   "2001:db8::1" or "2001:db8::1/128"
# - IPv6 subnet:        "2001:db8::/32" or "fd00:1234:5678::/48"
# SSH_ACTIVITY_EXCLUDED_IPS=("10.10.0.0/16" "192.168.1.1" "2001:db8::/32" "fd00:1234:5678::/48")
SSH_ACTIVITY_EXCLUDED_IPS=()

# Advanced env knobs (optional):
#   SSHD_LOG_SOURCE="/var/log/auth.log"   or   SSHD_LOG_SOURCE="JOURNAL"
#   SYSTEM_MONITORING_NOLOCK=1            # bypass single-instance lock (not recommended)
#                                                                                                                            #
# -------------------------------------------------------------------------------------------------------------------------- #






# -------------------------------------------------------------------------------------------------------------------------- #
#                                                                                                                            #
#         Usage instructions                                                                                                 #
#                                                                                                                            #
#                                                                                                                            #
print_help() {
    echo ""
    echo "Usage: $0 [options]"
    echo "Monitors internal system resources and (optionally) remote hosts/services. Sends alerts via Telegram."
    echo "Requires: Bash 4.3+ (associative arrays + namerefs)."
    echo ""
    echo "System Monitoring Options:"
    echo "  --NAME host_name              Specifies a custom identifier for the host being monitored."
    echo "  --CPU [CPU_%]                 CPU usage alert threshold (default: 86%)."
    echo "  --TEMP [TEMP_°C]              CPU temperature alert threshold (default: 65°C)."
    echo "  --RAM [RAM_%]                 RAM usage alert threshold (default: 86%)."
    echo "  --LA1 [threshold]             Sets a custom or auto-threshold (equal to CPU cores) for the 1-minute Load Average."
    echo "  --LA5 [threshold]             Sets a custom or 75% CPU cores auto-threshold for the 5-minute Load Average."
    echo "  --LA15 [threshold]            Sets a custom or 50% CPU cores auto-threshold for the 15-minute Load Average."
    echo "  --SSH                         Activates monitoring of SSH logins and sends alerts for logins from non-excluded IPs."
    echo "  --SFTP                        Activates monitoring of SFTP sessions and sends alerts for new sessions from non-excluded IPs."
    echo "  --REBOOT                      Sends an alert if the server has been rebooted since the last script execution."
    echo "  --DISK [DISK_%]               Disk usage alert threshold (default: 90%)."
    echo "  --DISK-TARGET <mount_point>   Specifies the mount point to monitor for disk usage. Must be used with --DISK."
    echo "  --DISK-LIST <file>            Loads disk targets+thresholds from a file (one entry per line, '#' comments allowed)."
    echo ""
    echo "Ping Monitoring Options (remote hosts/services):"
    echo "  --PING <spec>                 Adds a remote target to monitor (repeatable)."
    echo "                                   spec (key/value): Name=<name>|Host=<host>|Ping=true|Port=22,80,443|Interval=11|MaxFails=3"
    echo "                                     Name     = display name (optional; defaults to Host)"
    echo "                                     Host     = IPv4 / IPv6 / DNS"
    echo "                                     Ping     = true/false (optional; default true)"
    echo "                                     Port     = comma-separated TCP ports (e.g. 22,80,443) or '-' for none"
    echo "                                     Interval = optional; seconds between checks (default: ${PING_CHECK_INTERVAL}s)"
    echo "                                     MaxFails = optional; consecutive failures before DOWN alert (default: ${EXTERNAL_FAILURE_THRESHOLD})"
    echo "  --PING-LIST <file>            Loads ping targets from a file (one spec per line, '#' comments allowed)."
    echo ""
    echo "Optional BOT_TOKEN/GROUP_ID runtime overrides (usually NOT needed):"
    echo "⚠ DANGEROUS: running with '--GROUP-ID <chat_id> --BOT-TOKEN <token>' can expose the id/token via logs and process lists (ps/top/htop/etc.)."
    echo "  On first start, the script creates a secure secrets file for Telegram credentials, so do NOT pass below keys on the CLI in production."
    echo "  --GROUP-ID <chat_id>           Telegram chat/group id for alerts (overrides secrets file for this run)."
    echo "  --BOT-TOKEN <token>            Telegram bot token (overrides secrets file for this run)."
    echo ""
    echo "Other Options:"
    echo "  --STATUS                      Shows whether a monitor instance is running and prints its PID(s). Must be used alone."
    echo "  --RELOAD                      Reloads dynamic config (secrets, DISK-LIST, PING-LIST) in the running monitor (SIGHUP, fallback: SIGCONT). Must be used alone."
    echo "  --KILL                        Stops the currently running monitor (SIGTERM -> SIGKILL). Must be used alone."
    echo "  -h, --help                    Displays this help message."
    echo ""
    echo "Files:"
    echo "  $TELEGRAMM_LOCK_STATE        Path to the file that controls Telegram notifications (A content of '1' prevents messages)."
    echo "  $SYSTEM_MONITORING_STATE_DIR/         SSH, SFTP sessions and other working ${0##*/} files are here."
    echo ""
    echo "Example --DISK-LIST <file> contents:"
    echo "    # One entry per line. Lines starting with # are comments; blank lines are ignored."
    echo "    Mount=/|Threshold=90"
    echo "    Mount=/mnt/data|Threshold=85"
    echo "    Mount=/var|Threshold=80"
    echo ""
    echo "Example --PING-LIST <file> contents:"
    echo "    # One spec per line. Lines starting with # are comments; blank lines are ignored."
    echo "    Name=router|Host=10.10.10.1|Ping=true|Port=22,80,443|Interval=11|MaxFails=3"
    echo "    Name=dns1|Host=1.1.1.1|Ping=true|Port=-|Interval=30|MaxFails=2"
    echo "    Host=8.8.8.8"
    echo "    Name=v6-web|Host=[2001:db8::10]|Ping=false|Port=443|Interval=11|MaxFails=3"
    echo ""
    echo "Usage Examples:"
    echo "  $0 --NAME MyServer --CPU 80 --RAM 70 --DISK 90 --TEMP 66 --LA1 2 --LA5 2 --LA15 1"
    echo "  $0 --NAME MyServer --LA1 --LA5 --LA15 --SSH --SFTP --REBOOT"
    echo "  $0 --NAME MyServer --DISK 90 --DISK-TARGET /mnt/my_disk"
    echo "  $0 --NAME MyServer --DISK-LIST /etc/system-monitoring.disk.list"
    echo "  $0 --NAME MonitorBox --PING \"Name=router|Host=10.10.10.1|Ping=true|Port=22,80,443|Interval=11|MaxFails=3\""
    echo "  $0 --NAME MonitorBox --PING \"Host=8.8.8.8\" --PING \"Host=1.1.1.1\""
    echo "  $0 --NAME MonitorBox --PING-LIST /etc/system-monitoring.ping.list"
    echo ""
}
#                                                                                                                            #
# -------------------------------------------------------------------------------------------------------------------------- #









# -------------------------------------------------------------------------------------------------------------------------- #
#                                                                                                                            #
#         Code                                                                                                               #
#                                                                                                                            #
#                                                                                                                            #
DISK_LIST_FILE=""
DISK_MONITORING=0
DISK_TARGETS=()
DISK_THRESHOLDS=()
# Holds a human-readable reason when parse_disk_target_spec()/resolve_disk_mountpoint() fails.
DISK_SPEC_ERROR=""

# Optional runtime overrides (CLI flags). If set, they override secrets file for this run.
CLI_GROUP_ID=""
CLI_BOT_TOKEN=""

# SSH/SFTP activity snapshot (user-facing)
SSH_ACTIVITY_LOGINS="$SYSTEM_MONITORING_STATE_DIR/ssh_activity_logins.txt"

# Internal state files (normally you do not need to touch these)
SSH_ACTIVITY_STATE_FILE="${SYSTEM_MONITORING_STATE_DIR}/ssh_activity_state.txt"
SFTP_ACTIVITY_LOGINS="${SYSTEM_MONITORING_STATE_DIR}/sftp_activity_state.txt"

# Reboot detector state (used by --REBOOT; stores last observed boot time token)
LAST_BOOT_TIME_FILE="${SYSTEM_MONITORING_STATE_DIR}/last_boot_time.txt"

# Tracks which SSH/SFTP sessions we've already alerted on (prevents baseline -> "Ended" noise).
SSH_ACTIVITY_ALERTED="${SYSTEM_MONITORING_STATE_DIR}/ssh_activity_alerted.txt"
SFTP_ACTIVITY_ALERTED="${SYSTEM_MONITORING_STATE_DIR}/sftp_activity_alerted.txt"

# Cache SFTP alert details for "Ended" notifications (process/socket may already be gone).
SFTP_ACTIVITY_DETAILS="${SYSTEM_MONITORING_STATE_DIR}/sftp_activity_details.txt"

# Auth-log cursors for flash SSH/SFTP detection (reads /var/log/auth.log|/var/log/secure or journald).
SSH_AUTHLOG_STATE_FILE="${SYSTEM_MONITORING_STATE_DIR}/ssh_authlog.state"
SFTP_AUTHLOG_STATE_FILE="${SYSTEM_MONITORING_STATE_DIR}/sftp_authlog.state"

# One-time warning marker if log flash detection is unavailable/misconfigured.
AUTHLOG_FLASH_WARN_STATE="${SYSTEM_MONITORING_STATE_DIR}/authlog_flash.warned"
TEMP_SENSOR_WARN_STATE="${SYSTEM_MONITORING_STATE_DIR}/temp_sensor.warned"
# TEMP availability is determined once per script run (non-persistent).
TEMP_MONITORING_DISABLED=0
TEMP_MONITORING_WARNED=0

# Tracks Telegram lock transitions so cooldown timestamps can be reset after unlock.
TELEGRAM_LOCK_PREV_STATE_FILE="${SYSTEM_MONITORING_STATE_DIR}/telegram.lock.prev"

# External monitor: stores "DOWN alerts suppressed while Telegram is locked" markers
EXTERNAL_PENDING_DIR="${SYSTEM_MONITORING_STATE_DIR}/external.pending"

# Runtime control: PID file for the *main* monitor process (used by --KILL / --RELOAD)
SYSTEM_MONITORING_MAIN_PID_FILE="${SYSTEM_MONITORING_STATE_DIR}/system-monitoring.main.pid"

# Set to 1 by SIGHUP trap to request a configuration reload.
SYSTEM_MONITORING_RELOAD_REQUESTED=0


# Requires Bash 4.3+ (namerefs: local -n / declare -n; associative arrays: declare -A).
if [[ -z "${BASH_VERSINFO[*]:-}" ]]; then
    echo "Error: This script must be run with bash." >&2
    exit 2
fi
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    echo "Error: $0 requires Bash 4.3+ (found: ${BASH_VERSION})." >&2
    echo "Install a newer bash and run it explicitly (e.g., /usr/bin/bash or /opt/homebrew/bin/bash)." >&2
    exit 2
fi

# OS guard: this script is Linux-only (relies on /proc, sysfs, Linux 'free', Linux ping flags, etc.)
SYSTEM_MONITORING_OS="$(uname -s 2>/dev/null || echo unknown)"
if [[ "$SYSTEM_MONITORING_OS" != "Linux" ]]; then
  echo "Error: system-monitoring.sh is Linux-only (detected: $SYSTEM_MONITORING_OS)." >&2
  exit 1
fi
readonly SYSTEM_MONITORING_OS




#---------------------------------
# Telegram functions
#---------------------------------

# Set to 1 once a fatal/startup notification was sent successfully (prevents duplicates).
TELEGRAM_FATAL_NOTIFIED=0

# Human-readable phase marker used by the EXIT trap (helps in cron/@reboot runs).
SYSTEM_MONITORING_PHASE="startup"

# Function to Test the Telegram API Connection
test_telegram_connection() {
    local response curl_rc tg_text api

    tg_text=$'---------------------------------\n\n*Test message* from monitoring script\n\n---------------------------------'
    
    local __xtrace_was_on_conn=
    [[ $- == *x* ]] && __xtrace_was_on_conn=1 && set +x
    
    # First-time secrets setup calls this BEFORE dependency checks.
    # Give a direct error if curl is missing instead of a misleading network/DNS hint.
    if ! command -v curl >/dev/null 2>&1; then
        echo ""
        echo "Error: curl is not installed (required to reach Telegram API)."
        echo "Install curl and re-run. Examples:"
        echo "  apt-get update && apt-get install -y curl"
        echo "  dnf install -y curl   # or yum install -y curl"
        echo "  apk add curl"
        echo ""
        [[ -n "${__xtrace_was_on_conn:-}" ]] && set -x
        return 1
    fi
    
    api="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"
    
    response=$(printf '%s' "$tg_text" | curl -q -sS --connect-timeout 10 --max-time 20 \
    --config <(cat <<CURLCFG
url = "$api"
data = "chat_id=$GROUP_ID"
data = "parse_mode=Markdown"
data-urlencode = "text@-"
CURLCFG
))
    curl_rc=$?
    
    [[ -n "${__xtrace_was_on_conn:-}" ]] && set -x

    # If curl failed or the body is empty, this is NOT success.
    if [[ $curl_rc -ne 0 || -z "$response" ]]; then
        echo ""
        if [[ $curl_rc -eq 127 ]]; then
            echo "Error: curl is not installed (required to reach Telegram API)."
            echo "Install curl and re-run. Examples:"
            echo "  apt-get update && apt-get install -y curl"
            echo "  dnf install -y curl   # or yum install -y curl"
            echo "  apk add curl"
        elif [[ $curl_rc -eq 126 ]]; then
            echo "Error: curl is present but not executable (permission/loader issue)."
            echo "Reinstall curl and re-run."
        else
            echo "Error: Unable to reach Telegram API (curl exit: $curl_rc)."
            echo "Check network/DNS/connectivity and try again."
        fi
        echo ""
        return 1
    fi

    # Require explicit success from Telegram.
    if echo "$response" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
        return 0
    fi

    # Known credential/config errors
    if echo "$response" | grep -Eq '"error_code"[[:space:]]*:[[:space:]]*401'; then
        echo ""
        echo "Error: BOT_TOKEN is wrong."
        echo ""
        rm -f "$SECRETS_FILE"
        echo "Secrets file '$SECRETS_FILE' deleted."
        exit 1
    elif echo "$response" | grep -Eq '"error_code"[[:space:]]*:[[:space:]]*400' && echo "$response" | grep -qi 'chat not found'; then
        echo ""
        echo "Error: GROUP_ID is wrong."
        echo ""
        rm -f "$SECRETS_FILE"
        echo "Secrets file '$SECRETS_FILE' deleted."
        exit 1
    fi

    # Any other non-success response (rate limit, Telegram outage, etc.)
    echo ""
    echo "Error: Telegram API returned a non-success response."
    echo "Response: $response"
    echo ""
    return 1
}

# Function to load secrets from file.
# Note: do NOT do dependency checks here. We want secrets to load even when deps are missing,
# so we can notify startup failures via Telegram (when curl is available).
function load_secrets {
    # Start with CLI overrides (if provided)
    GROUP_ID="${CLI_GROUP_ID:-}"
    BOT_TOKEN="${CLI_BOT_TOKEN:-}"

    # If both are provided via CLI, do not touch the secrets file at all.
    if [[ -n "$GROUP_ID" && -n "$BOT_TOKEN" ]]; then
        return 0
    fi

    # If secrets file is missing:
    # - normal behavior: interactive create
    # - BUT if user tried to override only one value, fail fast (don’t hang / don’t create partial state)
    if [[ ! -f "$SECRETS_FILE" ]]; then
        if [[ -n "$GROUP_ID" || -n "$BOT_TOKEN" ]]; then
            echo "Error: Secrets file '$SECRETS_FILE' is missing."
            echo "Provide both --GROUP-ID and --BOT-TOKEN to run without a secrets file,"
            echo "or create '$SECRETS_FILE' first."
            exit 1
        fi
        create_secrets_file
        return 0
    fi
    
        # Security: refuse insecure secrets file (symlink / wrong owner / wrong perms)
    if [[ -L "$SECRETS_FILE" ]]; then
        echo "Error: Secrets file '$SECRETS_FILE' must not be a symlink."
        echo "Fix: rm -f '$SECRETS_FILE' && re-run to recreate it."
        exit 1
    fi

    # Need GNU/coreutils-style: stat -c ...
    if ! command -v stat >/dev/null 2>&1; then
        echo "Error: Required command 'stat' is not installed (needed to validate '$SECRETS_FILE' ownership/perms)."
        echo "Fix: install coreutils (provides 'stat') and re-run."
        exit 1
    fi

    local _uid _gid _mode _stat_out
    if ! _stat_out="$(stat -c '%u %g %a' "$SECRETS_FILE" 2>/dev/null)"; then
        echo "Error: 'stat' failed or is incompatible on this system."
        echo "This script requires a GNU/coreutils 'stat' that supports: stat -c '%u %g %a'"
        exit 1
    fi
    read -r _uid _gid _mode <<< "$_stat_out"

    if [[ "$_uid" -ne 0 || "$_gid" -ne 0 ]]; then
        echo "Error: Secrets file '$SECRETS_FILE' must be owned by root:root (is ${_uid}:${_gid})."
        echo "Fix: chown root:root '$SECRETS_FILE'"
        exit 1
    fi

    if [[ "$_mode" != "600" ]]; then
        echo "Error: Secrets file '$SECRETS_FILE' permissions are $_mode; expected 600."
        echo "Fix: chmod 600 '$SECRETS_FILE'"
        exit 1
    fi
    
    local __xtrace_was_on_secrets=
    [[ $- == *x* ]] && __xtrace_was_on_secrets=1 && set +x

    # Read secrets as data (do NOT execute the file)
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        # Drop CRLF and trim whitespace
        key="${key%$'\r'}"
        value="${value%$'\r'}"
        key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"
        value="${value#"${value%%[![:space:]]*}"}"; value="${value%"${value##*[![:space:]]}"}"

        # Skip blanks/comments
        [[ -z "$key" || "$key" == \#* ]] && continue

        # Allow optional 'export KEY=...'
        key="${key#export }"
        key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"

        # Remove surrounding quotes if present
        if [[ "$value" == \"*\" && "$value" == *\" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
            value="${value:1:${#value}-2}"
        fi

        case "$key" in
            GROUP_ID)  [[ -z "$GROUP_ID"  ]] && GROUP_ID="$value" ;;
            BOT_TOKEN) [[ -z "$BOT_TOKEN" ]] && BOT_TOKEN="$value" ;;
        esac
    done < "$SECRETS_FILE"
    
    [[ -n "${__xtrace_was_on_secrets:-}" ]] && set -x

    if [[ -z "$GROUP_ID" || -z "$BOT_TOKEN" ]]; then
        echo "Error: Could not read GROUP_ID and BOT_TOKEN from '$SECRETS_FILE'."
        echo "Expected lines like:"
        echo 'GROUP_ID="12345678"'
        echo 'BOT_TOKEN="123456:ABC..."'
        exit 1
    fi
}

# Function to create secret file if it does not exist
function create_secrets_file {
    echo ""
    echo "The secrets file '$SECRETS_FILE' does not exist."

    # Non-interactive safety: don't hang or create an empty secrets file.
    # If there's no controlling TTY (cron/@reboot/systemd), abort with instructions.
    if ! { exec 3</dev/tty 4>/dev/tty; } 2>/dev/null; then
        echo "Error: Secrets file '$SECRETS_FILE' is missing, but this run has no TTY for interactive setup."
        echo "Create it manually before running unattended. Expected contents:"
        echo '  GROUP_ID="12345678"'
        echo '  BOT_TOKEN="123456:ABC..."'
        exit 1
    fi
    
    # 'stty' is required to hide BOT_TOKEN input during interactive setup.
    if ! command -v stty >/dev/null 2>&1; then
        echo "Error: Required command 'stty' is not installed."
        echo "It is needed to hide BOT_TOKEN input during interactive secrets setup."
        echo "Fix: install coreutils (provides 'stty') or create '$SECRETS_FILE' manually."
        exec 3<&- 4>&- 2>/dev/null || true
        exit 1
    fi

    echo "Let's create it."
    echo ""

    echo "GROUP_ID should be set to the Telegram group ID where alerts will be sent."
    echo "BOT_TOKEN is the token for the Telegram bot that will send the messages."

    echo ""
    echo "Example GROUP_ID:  12345678"
    echo "Example BOT_TOKEN: 9987654321:RtG8kL5vX7bQw9mP2nR4aD1uY6jZ3eN5fC8oK4hV1xL7"

    echo ""
    echo "Initial setup requires a Telegram group ID and bot token."
    echo "The bot token input is hidden as you type, like a password:"
    echo ""

    # Read from the controlling terminal (not stdin), so redirections/pipes don't break prompts.
    printf "Enter the Telegram group ID (GROUP_ID): " >&4
    read -r -u 3 GROUP_ID

    printf "Enter the Telegram bot token (BOT_TOKEN): " >&4
    
    # Ensure terminal settings are restored even if user hits Ctrl-C / TERM mid-entry.
    local _tty_state
    _tty_state=$(stty -g <&3 2>/dev/null || true)
    
    _cleanup_tty() {
        [[ -n "$_tty_state" ]] && stty "$_tty_state" <&3 2>/dev/null || stty echo <&3 2>/dev/null
    }
    
    trap '_cleanup_tty; exec 3<&- 4>&- 2>/dev/null; exit 130' INT TERM
    
    stty -echo <&3
    IFS= read -r -u 3 BOT_TOKEN
    _cleanup_tty
    
    trap - INT TERM
    printf "\n" >&4

    # Close TTY FDs early; everything after this should behave normally.
    exec 3<&- 4>&-

    if [[ -z "$GROUP_ID" || -z "$BOT_TOKEN" ]]; then
        echo "Error: GROUP_ID and BOT_TOKEN cannot be empty."
        exit 1
    fi
    
    # Write secrets file securely (no permissive window; atomic replace).
    local _old_umask _tmp
    _old_umask=$(umask)
    umask 077
    
    _tmp=$(mktemp "${SECRETS_FILE}.tmp.XXXXXX") || {
        echo "Error: failed to create temporary secrets file."
        umask "$_old_umask"
        exit 1
    }
    
    local __xtrace_was_on_write=
    [[ $- == *x* ]] && __xtrace_was_on_write=1 && set +x
    
    {
        echo "GROUP_ID=\"$GROUP_ID\""
        echo "BOT_TOKEN=\"$BOT_TOKEN\""
    } > "$_tmp"
    
    [[ -n "${__xtrace_was_on_write:-}" ]] && set -x
    
    chmod 600 "$_tmp" 2>/dev/null || true
    mv -f "$_tmp" "$SECRETS_FILE"
    
    umask "$_old_umask"
    
    echo ""
    echo "Secrets file '$SECRETS_FILE' created with permissions set to 600."
    
    # Test Telegram connection
    if test_telegram_connection; then
        echo "Successfully connected to Telegram. A test message has been sent."
    else
        echo "Error: Failed to connect to Telegram. Please check your GROUP_ID and BOT_TOKEN."
        exit 1
    fi
}

# Function to check if messages should be sent based on lock state
should_send_message() {
    # Check if the lock file exists and is not empty
    if [[ ! -f "${TELEGRAMM_LOCK_STATE}" ]] || [[ ! -s "${TELEGRAMM_LOCK_STATE}" ]]; then
        # Lock file doesn't exist or is empty, send message
        return 0
    fi

    # Lock file exists and has content, read the state
    local state
    state="$(<"${TELEGRAMM_LOCK_STATE}")"
    # Trim all whitespace (spaces, tabs, newlines, CRLF). "1" means locked.
    state="${state//[[:space:]]/}"
    [[ "$state" != "1" ]]
}

# ------------------------------------------------------------
# Telegram lock transition handling
# - If alerts were locked and become unlocked, clear cooldown state
#   so we do not miss alerts due to cooldown timestamps written while locked.
# ------------------------------------------------------------

_sm_reset_alert_cooldowns() {
    # Safety guard: never run with an empty/unsafe state dir
    if [[ -z "${SYSTEM_MONITORING_STATE_DIR:-}" || "$SYSTEM_MONITORING_STATE_DIR" == "/" ]]; then
        return 0
    fi

    # CPU/RAM cooldown files (may be overridden via env vars)
    rm -f -- "${CPU_ALERT_STATE_FILE:-${SYSTEM_MONITORING_STATE_DIR}/cpu.lastalert}" 2>/dev/null || true
    rm -f -- "${RAM_ALERT_STATE_FILE:-${SYSTEM_MONITORING_STATE_DIR}/ram.lastalert}" 2>/dev/null || true

    # Load Average cooldown files (LA1/LA5/LA15)
    if declare -F __la_state_file_for >/dev/null 2>&1; then
        local la1 la5 la15
        la1="$(__la_state_file_for "LA1")"
        la5="$(__la_state_file_for "LA5")"
        la15="$(__la_state_file_for "LA15")"

        rm -f -- "$la1" "$la5" "$la15" 2>/dev/null || true
        rm -f -- "${la1}.lock" "${la5}.lock" "${la15}.lock" 2>/dev/null || true
    else
        rm -f -- \
            "${SYSTEM_MONITORING_STATE_DIR}/la1.lastalert" \
            "${SYSTEM_MONITORING_STATE_DIR}/la5.lastalert" \
            "${SYSTEM_MONITORING_STATE_DIR}/la15.lastalert" \
            "${SYSTEM_MONITORING_STATE_DIR}/la1.lastalert.lock" \
            "${SYSTEM_MONITORING_STATE_DIR}/la5.lastalert.lock" \
            "${SYSTEM_MONITORING_STATE_DIR}/la15.lastalert.lock" 2>/dev/null || true
    fi

    # Disk cooldown files (per-mount)
    local -a _disk_files=()
    shopt -s nullglob
    _disk_files=( "${SYSTEM_MONITORING_STATE_DIR}/disk.lastalert."* )
    shopt -u nullglob
    if ((${#_disk_files[@]})); then
        rm -f -- "${_disk_files[@]}" 2>/dev/null || true
    fi
}

_sm_handle_telegram_lock_transition() {
    # If state tracking path is not configured, do nothing.
    if [[ -z "${TELEGRAM_LOCK_PREV_STATE_FILE:-}" ]]; then
        return 0
    fi

    local now_locked="0"
    if ! should_send_message; then
        now_locked="1"
    fi

    local prev_locked=""
    if [[ -r "$TELEGRAM_LOCK_PREV_STATE_FILE" ]]; then
        read -r prev_locked < "$TELEGRAM_LOCK_PREV_STATE_FILE" 2>/dev/null || true
        prev_locked="${prev_locked//[[:space:]]/}"
        if [[ "$prev_locked" != "0" && "$prev_locked" != "1" ]]; then
            prev_locked=""
        fi
    fi

    # First run: just record current state (no reset)
    if [[ -z "$prev_locked" ]]; then
        printf "%s\n" "$now_locked" > "$TELEGRAM_LOCK_PREV_STATE_FILE" 2>/dev/null || true
        return 0
    fi

    # No change
    if [[ "$prev_locked" == "$now_locked" ]]; then
        return 0
    fi

    # If we just unlocked (1 -> 0), clear cooldowns so alerts resume immediately.
    if [[ "$prev_locked" == "1" && "$now_locked" == "0" ]]; then
        echo "Telegram alerts unlocked: resetting cooldown state files."
        _sm_reset_alert_cooldowns
    fi

    # Persist new state
    printf "%s\n" "$now_locked" > "$TELEGRAM_LOCK_PREV_STATE_FILE" 2>/dev/null || true
}

# Real CPU utilization for footer (0..100%), returns "NN%"
# Uses /proc/stat deltas; avoids the LA1/cores "fake CPU%" that can exceed 100.
get_cpu_usage_percent() {
    local load1="${1:-}"
    local num_cores="${2:-}"
    local interval="${CPU_FOOTER_WINDOW:-1}"

    [[ "$interval" =~ ^[0-9]+$ ]] || interval=1
    (( interval < 1 )) && interval=1

    # Real CPU% via /proc/stat
    if [[ -r /proc/stat ]]; then
        local u1 n1 s1 i1 w1 irq1 sirq1 st1
        local u2 n2 s2 i2 w2 irq2 sirq2 st2

        if read -r _ u1 n1 s1 i1 w1 irq1 sirq1 st1 _ < /proc/stat 2>/dev/null; then
            sleep "$interval" 2>/dev/null || true
            if read -r _ u2 n2 s2 i2 w2 irq2 sirq2 st2 _ < /proc/stat 2>/dev/null; then
                if [[ "$u1" =~ ^[0-9]+$ && "$u2" =~ ^[0-9]+$ ]]; then
                    local idle1=$((i1 + w1))
                    local idle2=$((i2 + w2))
                    local tot1=$((u1 + n1 + s1 + i1 + w1 + irq1 + sirq1 + st1))
                    local tot2=$((u2 + n2 + s2 + i2 + w2 + irq2 + sirq2 + st2))
                    local dt=$((tot2 - tot1))
                    local didle=$((idle2 - idle1))

                    if (( dt > 0 )); then
                        local pct=$(( (dt - didle) * 100 / dt ))
                        (( pct < 0 )) && pct=0
                        (( pct > 100 )) && pct=100
                        echo "${pct}%"
                        return 0
                    fi
                fi
            fi
        fi
    fi

    # Fallback: old behavior (LA1/cores), but capped at 100 so you never get 1090% again
    if [[ -n "$load1" && -n "$num_cores" && "$num_cores" =~ ^[0-9]+$ && "$num_cores" -gt 0 ]]; then
        local fb
        fb="$(awk -v cores="$num_cores" -v load0="$load1" 'BEGIN { printf "%.0f", (load0 * 100) / cores }')"
        [[ "$fb" =~ ^[0-9]+$ ]] || fb=0
        (( fb > 100 )) && fb=100
        (( fb < 0 )) && fb=0
        echo "${fb}%"
        return 0
    fi

    echo "N/A"
    return 0
}

# The `send_telegram_alert` function formats and sends alert messages to Telegram. It gathers
# current system metrics such as Load Averages, CPU, RAM, and Disk usage, formatting them according
# to the alert type. If the messaging lock is not engaged, it sends the alert with a timestamp
# and hostname to the specified Telegram group.
send_telegram_alert() {
    local alert_type=$1
    local message=$2
# Optional:   local server_ip=$(get_server_ip)
    local time_stamp=$(LC_ALL=C date "+%H:%M:%S║%b %d")

    # Fast-path: if Telegram alerts are locked, exit quietly (avoid stdout spam + wasted work)
    if ! should_send_message; then
        return 2
    fi

    # Gather system metrics
    local load1 load5 load15 _loadavg_rest=""
    if ! read -r load1 load5 load15 _loadavg_rest < /proc/loadavg 2>/dev/null; then
        load1="0"; load5="0"; load15="0"
    fi
    local ram_usage=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')
    local num_cores=$(nproc)
    local cpu_usage
    cpu_usage="$(get_cpu_usage_percent "$load1" "$num_cores")"
    local disk_mount="/" # Should be always “/” by design
    local disk_usage=$(df -P -- "$disk_mount" 2>/dev/null | awk 'NR==2{print $5}')  # Disk usage for the monitored mount (defaults to / if not set)
#    local disk_usage=$(df -P "$disk_mount" 2>/dev/null | awk 'NR==2{print $5}')

    # Make disk_usage explicit in the footer when monitoring a non-root mount
#    if [[ -n "$DISK_TARGET" && "$DISK_TARGET" != "/" ]]; then
#        disk_usage="${disk_usage} (${disk_mount})"
#    fi

    # Uptime footer (locale-independent): derive from /proc/uptime
    local uptime_seconds days hours mins
    uptime_seconds=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)

    days=$(( uptime_seconds / 86400 ))
    hours=$(( (uptime_seconds % 86400) / 3600 ))
    mins=$(( (uptime_seconds % 3600) / 60 ))

    local uptime_info=""
    (( days > 0 )) && uptime_info="${days}d"
    (( hours > 0 )) && uptime_info+="${uptime_info:+, }${hours}h"
    # Always show minutes if nothing else is shown (e.g., very short uptimes)
    if (( mins > 0 )) || [[ -z "$uptime_info" ]]; then
        uptime_info+="${uptime_info:+, }${mins}m"
    fi
    
    # Check if the message should be sent
    if should_send_message; then
        # Format the message based on the type of alert
        local formatted_message
        case $alert_type in
            CPU)
                # Accept either a plain number (avg) OR a multi-line "\n..." block from check_cpu().
                local avg details
                avg="${message%%\\n*}"
                details=""
                if [[ "$message" == *\\n* ]]; then
                    details="${message#*\\n}"
                fi

                # Avoid double-percent if caller ever includes one.
                avg="${avg%%%}"

                formatted_message="║ *CPU* usage is high: *${avg}%*"
                if [[ -n "$details" ]]; then
                    formatted_message+="\n${details}"
                fi
                ;;
            RAM)
                local ram
                ram="${message%%%}"
                formatted_message="║ *RAM* usage is high: *${ram}%*"
                ;;
            TEMP)
                # If message is a number -> normal high-temp alert.
                # Otherwise -> treat as preformatted TEMP warning/error text from caller.
                if [[ "$message" =~ ^[0-9]+$ ]]; then
                    formatted_message="║ *TEMP* is high: *${message}°C*"
                else
                    formatted_message="$message"
                fi
                ;;
            DISK)
                formatted_message="║ *${alert_type}* high usage: $message"
            ;;
            LA1|LA5|LA15)
                # Make LA alerts self-describing (which interval triggered + threshold used)
                local la_threshold
                case "$alert_type" in
                    LA1)  la_threshold=${LA1_THRESHOLD:-$num_cores} ;;
                    LA5)  la_threshold=${LA5_THRESHOLD:-$(echo "$num_cores * 0.75" | bc)} ;;
                    LA15) la_threshold=${LA15_THRESHOLD:-$(echo "$num_cores * 0.5" | bc)} ;;
                esac

                formatted_message="║ *${alert_type}* is high: *$message* (Max $la_threshold)"
# Optional:                formatted_message="║ *${alert_type}* is high: *$message*\n║ Threshold: *$la_threshold*"
                ;;

            SSH-LOGIN|SFTP-MONITOR|REBOOT|EXTERNAL)
                # Message already formatted by the caller
                formatted_message="$message"
                ;;
            *)
                echo "Unknown alert type: $alert_type"
                return 1
                ;;
        esac

        # Convert only the literal "\n" sequences we intentionally use into real newlines.
        # Do NOT interpret other backslash escapes coming from interpolated/untrusted content.
        local formatted_message_nl
        formatted_message_nl="${formatted_message//\\n/$'\n'}"

        local tg_text
        tg_text=$'\n'"⚠ *$HOST_NAME*║$time_stamp ⚠"$'\n'"╔═ ═ ═ ═"$'\n'"${formatted_message_nl}"$'\n'"╚═ ═ ═ ═"$'\n'"CPU: $cpu_usage║RAM: $ram_usage║DISK: $disk_usage"$'\n'"Uptime: $uptime_info"

        local response curl_rc
        
        local __xtrace_was_on_send=
        [[ $- == *x* ]] && __xtrace_was_on_send=1 && set +x
        
        # First try: keep Markdown formatting, but URL-encode text and verify success
        response=$(printf '%s' "$tg_text" | curl -q -sS --connect-timeout 10 --max-time 20 \
        --config <(cat <<CURLCFG
url = "$TELEGRAM_API"
data = "chat_id=$GROUP_ID"
data = "parse_mode=Markdown"
data-urlencode = "text@-"
CURLCFG
))
        curl_rc=$?
        
        [[ -n "${__xtrace_was_on_send:-}" ]] && set -x
        
        if [[ $curl_rc -ne 0 || -z "$response" ]]; then
            echo "Error: Telegram send failed (curl exit: $curl_rc)." >&2
            return 1
        fi
        
        if echo "$response" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
            return 0
        fi
        
        # Common failure: Markdown parse errors due to unescaped content.
        # Retry WITHOUT parse_mode so the alert still arrives (as plain text with * chars visible).
        if echo "$response" | grep -qi "can't parse entities"; then
            local __xtrace_was_on_send2=
            [[ $- == *x* ]] && __xtrace_was_on_send2=1 && set +x

            response=$(printf '%s' "$tg_text" | curl -q -sS --connect-timeout 10 --max-time 20 \
            --config <(cat <<CURLCFG
url = "$TELEGRAM_API"
data = "chat_id=$GROUP_ID"
data-urlencode = "text@-"
CURLCFG
))
            curl_rc=$?
            
            [[ -n "${__xtrace_was_on_send2:-}" ]] && set -x
        
            if [[ $curl_rc -eq 0 && -n "$response" ]] && echo "$response" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
                echo "Warning: Telegram Markdown parse failed; resent without parse_mode." >&2
                return 0
            fi
        fi
        
        echo "Error: Telegram API returned non-success response: $response" >&2
        return 1

    else
        return 2  # locked: message intentionally not sent
    fi
}

# For ERROR notifications we do NOT respect the lock file. If the script is broken, the user should know.
telegram_can_notify_error() {
    [[ -n "${GROUP_ID:-}" && -n "${BOT_TOKEN:-}" ]] || return 1
    command -v curl >/dev/null 2>&1 || return 1
    return 0
}

# Minimal Telegram sender that does NOT rely on free/df/nproc/bc/etc.
# Use this for startup failures and unexpected script exits.
send_telegram_error_notice() {
    local title="$1"
    local body="$2"

    telegram_can_notify_error || return 1

    local host ts api text header footer response curl_rc max_total
    host="${HOST_NAME:-$(hostname 2>/dev/null || echo unknown)}"
    ts="$(LC_ALL=C date '+%Y-%m-%d %H:%M:%S%z')"
    
    local __xtrace_was_on_api=
    [[ $- == *x* ]] && __xtrace_was_on_api=1 && set +x
    
    api="${TELEGRAM_API:-https://api.telegram.org/bot${BOT_TOKEN}/sendMessage}"
    
    [[ -n "${__xtrace_was_on_api:-}" ]] && set -x


    # Match the "test message" look (top/bottom separators + bold header).
    # Try Markdown first, then fall back to plain text if Telegram rejects formatting.
    header=$'---------------------------------\n\n*SYSTEM-MONITORING ERROR*\n\n'
    footer=$'\n\n---------------------------------'

    text="${header}Host: ${host}"$'\n'"Time: ${ts}"$'\n'"Phase: ${SYSTEM_MONITORING_PHASE:-unknown}"$'\n\n'"${title}"
    if [[ -n "$body" ]]; then
        text+=$'\n'
        text+="$body"
    fi

    # Support callers that accidentally pass literal "\n" sequences
    text="${text//\\n/$'\n'}"

    # Hard cap while keeping the footer intact.
    max_total=3500
    if (( ${#text} > max_total - ${#footer} )); then
        text="${text:0:max_total-${#footer}}"
        text+=$'\n...(truncated)'
    fi
    text+="${footer}"

    # Attempt 1: Markdown (so it renders like the test message)
    local __xtrace_was_on_err1=
    [[ $- == *x* ]] && __xtrace_was_on_err1=1 && set +x
    
    response=$(printf '%s' "$text" | curl -q -sS --connect-timeout 10 --max-time 20 \
    --config <(cat <<CURLCFG
url = "$api"
data = "chat_id=$GROUP_ID"
data = "parse_mode=Markdown"
data-urlencode = "text@-"
CURLCFG
))
    curl_rc=$?
    
    [[ -n "${__xtrace_was_on_err1:-}" ]] && set -x

    if [[ $curl_rc -eq 0 && -n "$response" ]] && echo "$response" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
        TELEGRAM_FATAL_NOTIFIED=1
        return 0
    fi

    # If Markdown failed due to unescaped characters in title/body, retry as plain text.
    if [[ $curl_rc -eq 0 && -n "$response" ]] && echo "$response" | grep -qi "can't parse entities"; then
        local __xtrace_was_on_err2=
        [[ $- == *x* ]] && __xtrace_was_on_err2=1 && set +x
        
        response=$(printf '%s' "$text" | curl -q -sS --connect-timeout 10 --max-time 20 \
        --config <(cat <<CURLCFG
url = "$api"
data = "chat_id=$GROUP_ID"
data-urlencode = "text@-"
CURLCFG
))
        curl_rc=$?
        
        [[ -n "${__xtrace_was_on_err2:-}" ]] && set -x

        if [[ $curl_rc -eq 0 && -n "$response" ]] && echo "$response" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
            TELEGRAM_FATAL_NOTIFIED=1
            return 0
        fi
    fi

    return 1
}






#---------------------------------
# Helpers functions
#---------------------------------

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "Error: this script must be run as root."
        echo "It writes to: $SECRETS_FILE, $SSH_ACTIVITY_LOGINS and internal state under $SYSTEM_MONITORING_STATE_DIR."
        echo "It also uses 'ss -tnp' (process info usually requires root)."
        echo "Run it with sudo, or put it in root's crontab (sudo crontab -e)."
        exit 1
    fi

    # Ensure internal state directory exists (keeps /root clean).
    if [[ -n "${SYSTEM_MONITORING_STATE_DIR:-}" ]]; then
        if ! mkdir -p "$SYSTEM_MONITORING_STATE_DIR" 2>/dev/null; then
            echo "Error: cannot create state directory: $SYSTEM_MONITORING_STATE_DIR"
            exit 1
        fi
        chmod 700 "$SYSTEM_MONITORING_STATE_DIR" 2>/dev/null || true
        
        # External monitor: pending DOWN alerts suppressed while Telegram was locked
        if [[ -n "${EXTERNAL_PENDING_DIR:-}" ]]; then
            mkdir -p -- "$EXTERNAL_PENDING_DIR" 2>/dev/null || true
            chmod 700 "$EXTERNAL_PENDING_DIR" 2>/dev/null || true
        fi
        
        # ------------------------------------------------------------------
        # Single-instance lock (prevents duplicate monitors + state file races)
        # ------------------------------------------------------------------
        # Set SYSTEM_MONITORING_NOLOCK=1 to bypass (not recommended).
        if [[ "${SYSTEM_MONITORING_NOLOCK:-0}" -ne 1 ]]; then
            SYSTEM_MONITORING_LOCK_FILE="${SYSTEM_MONITORING_STATE_DIR}/system-monitoring.lock"
    
            if command -v flock >/dev/null 2>&1; then
                # Keep the FD open for the lifetime of the script so the lock stays held.
                exec {SYSTEM_MONITORING_LOCK_FD}>"$SYSTEM_MONITORING_LOCK_FILE" || {
                    echo "Error: cannot open lock file: $SYSTEM_MONITORING_LOCK_FILE" >&2
                    exit 1
                }
    
                if ! flock -n "$SYSTEM_MONITORING_LOCK_FD"; then
                    echo "Another instance of ${0##*/} is already running (lock: $SYSTEM_MONITORING_LOCK_FILE). Exiting." >&2
                    exit 0
                fi
            else
                # Fallback if 'flock' is missing: atomic PID file (noclobber).
                SYSTEM_MONITORING_PID_FILE="${SYSTEM_MONITORING_STATE_DIR}/system-monitoring.pid"
    
                if ( set -o noclobber; echo "$$" > "$SYSTEM_MONITORING_PID_FILE" ) 2>/dev/null; then
                    :
                else
                    local other_pid=""
                    other_pid="$(head -n1 "$SYSTEM_MONITORING_PID_FILE" 2>/dev/null || true)"
    
                    if [[ "$other_pid" =~ ^[0-9]+$ ]] && kill -0 "$other_pid" 2>/dev/null; then
                        # If we can verify it's really this script, treat it as running.
                        if [[ -r "/proc/$other_pid/cmdline" ]]; then
                            if tr '\0' ' ' < "/proc/$other_pid/cmdline" | grep -Fq -- "${0##*/}"; then
                                echo "Another instance of ${0##*/} is already running (pid: $other_pid). Exiting." >&2
                                exit 0
                            fi
                            # PID exists but does NOT look like this script -> stale pidfile, replace below.
                        else
                            # Can't verify; safest is to assume running and exit.
                            echo "Another instance appears to be running (pid: $other_pid). Exiting." >&2
                            exit 0
                        fi
                    fi
    
                    # Stale PID file -> replace it
                    rm -f "$SYSTEM_MONITORING_PID_FILE" 2>/dev/null || true
                    ( set -o noclobber; echo "$$" > "$SYSTEM_MONITORING_PID_FILE" ) 2>/dev/null || {
                        echo "Error: cannot create PID lock file: $SYSTEM_MONITORING_PID_FILE" >&2
                        exit 1
                    }
                fi
            fi
        fi
    fi
}

# Kill a process and all of its descendants (Linux /proc first, ps fallback).
# This prevents leaking nested helpers (e.g. fast_monitor_resources -> check_cpu -> sleep/awk),
# which can otherwise keep the single-instance lock FD open.
_sm_kill_tree() {
    local pid="$1"
    local sig="${2:-TERM}"

    [[ "$pid" =~ ^[0-9]+$ ]] || return 0

    # Avoid accidental self-kill
    if [[ "$pid" -eq "$$" ]]; then
        return 0
    fi

    local child=""
    if [[ -r "/proc/${pid}/task/${pid}/children" ]]; then
        for child in $(<"/proc/${pid}/task/${pid}/children"); do
            _sm_kill_tree "$child" "$sig"
        done
    else
        for child in $(ps -o pid= --ppid "$pid" 2>/dev/null); do
            _sm_kill_tree "$child" "$sig"
        done
    fi

    kill -s "$sig" "$pid" 2>/dev/null || true
}
        
# Make sure we clean up the background loops on shutdown (SIGINT/SIGTERM/EXIT)
cleanup() {
    local rc="${1:-$?}"
    trap - INT TERM EXIT HUP CONT

    # Best-effort: remove runtime pid marker early so a new instance can start without confusion.
    _sm_remove_main_pid_file 2>/dev/null || true

    local pids=()
    mapfile -t pids < <(jobs -p 2>/dev/null || true)

    if ((${#pids[@]})); then
        local pid=""

        # Graceful stop: TERM the whole subtree of each background job
        for pid in "${pids[@]}"; do
            _sm_kill_tree "$pid" TERM
        done

        # Small grace period, then hard-kill anything still alive
        sleep 0.2
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                _sm_kill_tree "$pid" KILL
            fi
        done

        # Reap direct children (prevents zombies)
        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    fi

    # Notify only on real errors (not clean exit / Ctrl-C / SIGTERM) and only once.
    if [[ $rc -ne 0 && $rc -ne 130 && $rc -ne 143 && "${TELEGRAM_FATAL_NOTIFIED:-0}" -ne 1 ]]; then
        send_telegram_error_notice "Script exited with error (exit code: $rc)" "" || true
    fi

    exit $rc
}

# ---------------------------------
# Control plane: PID file + --KILL/--RELOAD + in-place reload (SIGHUP)
# ---------------------------------

_sm_write_main_pid_file() {
    [[ -n "${SYSTEM_MONITORING_MAIN_PID_FILE:-}" ]] || return 1
    [[ -n "${SYSTEM_MONITORING_STATE_DIR:-}" && "$SYSTEM_MONITORING_STATE_DIR" != "/" ]] || return 1

    local old_umask
    old_umask=$(umask 2>/dev/null || echo 022)
    umask 077

    local tmp="${SYSTEM_MONITORING_MAIN_PID_FILE}.$$"
    if ! printf '%s\n' "$$" > "$tmp" 2>/dev/null; then
        umask "$old_umask" 2>/dev/null || true
        rm -f -- "$tmp" 2>/dev/null || true
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true

    if ! mv -f -- "$tmp" "$SYSTEM_MONITORING_MAIN_PID_FILE" 2>/dev/null; then
        umask "$old_umask" 2>/dev/null || true
        rm -f -- "$tmp" 2>/dev/null || true
        return 1
    fi

    umask "$old_umask" 2>/dev/null || true
    return 0
}

_sm_remove_main_pid_file() {
    [[ -n "${SYSTEM_MONITORING_MAIN_PID_FILE:-}" ]] || return 0
    rm -f -- "$SYSTEM_MONITORING_MAIN_PID_FILE" 2>/dev/null || true
}

_sm_read_main_pid_file() {
    local pid=""
    [[ -r "${SYSTEM_MONITORING_MAIN_PID_FILE:-}" ]] || return 1
    read -r pid < "$SYSTEM_MONITORING_MAIN_PID_FILE" 2>/dev/null || return 1
    pid="${pid//[[:space:]]/}"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    echo "$pid"
}

_sm_pid_is_monitor() {
    local pid="$1"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    [[ "$pid" -ne "$$" ]] || return 1

    # Process exists? (kill -0 may return EPERM for other users; treat /proc as source of truth.)
    if ! kill -0 "$pid" 2>/dev/null; then
        [[ -d "/proc/$pid" ]] || return 1
    fi

    [[ -r "/proc/$pid/cmdline" ]] || return 1

    # Read argv tokens (NUL-delimited).
    local -a argv=()
    local arg
    while IFS= read -r -d '' arg; do
        argv+=("$arg")
    done < "/proc/$pid/cmdline" 2>/dev/null || true

    ((${#argv[@]} > 0)) || return 1

    # Require the executable is bash (avoid false-positives from sudo/vim/grep/etc.).
    local exe_path exe_base
    exe_path="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    exe_base="${exe_path##*/}"
    exe_base="${exe_base% (deleted)}"
    [[ -n "$exe_base" ]] || exe_base="${argv[0]##*/}"
    [[ "$exe_base" == "bash" ]] || return 1

    # Identify the script file as bash sees it: bash [opts] script [args].
    # We intentionally IGNORE bash "-c" mode because the script name could appear inside the command string.
    local i=1 a
    while (( i < ${#argv[@]} )); do
        a="${argv[$i]}"

        # End of bash options; next token is the script (if any).
        if [[ "$a" == "--" ]]; then
            ((i++))
            break
        fi

        # "-c" may appear alone or inside combined short options (e.g. -lc).
        if [[ "$a" == "-c" || "$a" =~ ^-[A-Za-z]*c[A-Za-z]*$ ]]; then
            return 1
        fi

        # Options that consume the next argument.
        case "$a" in
            -o|-O|--rcfile|--init-file)
                ((i+=2))
                continue
                ;;
        esac

        # Long options (no arg) and short option bundles.
        if [[ "$a" == --* ]]; then
            ((i++))
            continue
        fi
        if [[ "$a" == -* && "$a" != "-" ]]; then
            ((i++))
            continue
        fi

        break
    done

    (( i < ${#argv[@]} )) || return 1

    local script_arg="${argv[$i]}"
    local needle="${0##*/}"

    # Script must be its own argv element (not a substring, not inside bash -c).
    local script_base="${script_arg##*/}"
    [[ "$script_base" == "$needle" ]] || return 1
    [[ "$script_arg" == "$needle" || "$script_arg" == */"$needle" ]] || return 1

    # Exclude control-plane invocations.
    local j
    for ((j=i+1; j<${#argv[@]}; j++)); do
        case "${argv[$j]}" in
            --STATUS|--KILL|--RELOAD)
                return 1
                ;;
        esac
    done

    return 0
}

_sm_find_running_root_pids() {
    local -A cand=()
    local -A ppid_of=()

    local f pid ppid
    for f in /proc/[0-9]*/cmdline; do
        pid="${f#/proc/}"
        pid="${pid%%/*}"
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [[ "$pid" -ne "$$" ]] || continue

        # Strict match: only count real monitor instances (not wrappers / control calls).
        _sm_pid_is_monitor "$pid" || continue

        cand["$pid"]=1

        ppid=""
        if [[ -r "/proc/$pid/status" ]]; then
            ppid="$(awk '/^PPid:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)"
        fi
        [[ "$ppid" =~ ^[0-9]+$ ]] || ppid=""
        ppid_of["$pid"]="$ppid"
    done

    local -a roots=()
    for pid in "${!cand[@]}"; do
        ppid="${ppid_of[$pid]:-}"
        if [[ -z "$ppid" || -z "${cand[$ppid]+x}" ]]; then
            roots+=("$pid")
        fi
    done

    if ((${#roots[@]})); then
        printf '%s\n' "${roots[@]}" | sort -n
    fi
}

_sm_control_resolve_root_pids() {
    local pid=""
    pid="$(_sm_read_main_pid_file 2>/dev/null || true)"
    if [[ -n "$pid" ]] && _sm_pid_is_monitor "$pid"; then
        echo "$pid"
        return 0
    fi

    _sm_find_running_root_pids
}

_sm_control_kill() {
    local used_kill=0

    local -a roots=()
    mapfile -t roots < <(_sm_control_resolve_root_pids)

    if ((${#roots[@]} == 0)); then
        echo "No running ${0##*/} instances found."
        # If the pid file exists but points nowhere, remove it.
        _sm_remove_main_pid_file
        return 0
    fi

    local pid

    # Graceful stop: TERM the WHOLE subtree for each instance root.
    # This avoids leaking descendant subshells/external commands that may hold the flock FD open.
    for pid in "${roots[@]}"; do
        echo "Stopping ${0##*/} (pid $pid) ..."
        _sm_kill_tree "$pid" TERM
    done

    local deadline
    deadline=$(( $(LC_ALL=C date +%s) + 8 ))

    while true; do
        mapfile -t roots < <(_sm_control_resolve_root_pids)
        ((${#roots[@]} == 0)) && break
        (( $(LC_ALL=C date +%s) >= deadline )) && break
        sleep 0.2
    done

    # Escalation: SIGKILL the remaining trees.
    if ((${#roots[@]})); then
        used_kill=1
        for pid in "${roots[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                echo "Force killing ${0##*/} (pid $pid) ..."
                _sm_kill_tree "$pid" KILL
            fi
        done

        # Short final wait + re-check
        local deadline2
        deadline2=$(( $(LC_ALL=C date +%s) + 2 ))
        while true; do
            mapfile -t roots < <(_sm_control_resolve_root_pids)
            ((${#roots[@]} == 0)) && break
            (( $(LC_ALL=C date +%s) >= deadline2 )) && break
            sleep 0.2
        done
    fi

    # Only remove the pidfile if the instance is actually gone.
    if ((${#roots[@]} == 0)); then
        _sm_remove_main_pid_file

        if (( used_kill == 1 )); then
            echo "Done (SIGKILL was used for at least one process)."
        else
            echo "Done."
        fi
        return 0
    fi

    echo "Warning: ${0##*/} still appears to be running (remaining root PID(s): ${roots[*]})."
    echo "Not removing pidfile: ${SYSTEM_MONITORING_MAIN_PID_FILE}"
    return 2
}

_sm_control_reload() {
    local -a roots=()
    mapfile -t roots < <(_sm_control_resolve_root_pids)

    if ((${#roots[@]} == 0)); then
        echo "No running ${0##*/} instances found."
        # If the pid file exists but points nowhere, remove it.
        _sm_remove_main_pid_file
        return 3
    fi

    local delivered=0
    local pid

    for pid in "${roots[@]}"; do
        # Prefer SIGHUP if (and only if) the target process is actually catching it.
        # This prevents accidental termination of older instances that do not trap HUP.
        local sig="HUP"
        local catches=0

        local sigcgt_hex="" sigcgt=0
        if [[ -r "/proc/$pid/status" ]]; then
            sigcgt_hex="$(awk '/^SigCgt:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)"
        fi
        if [[ "$sigcgt_hex" =~ ^[0-9A-Fa-f]+$ ]]; then
            sigcgt=$((16#$sigcgt_hex))
        fi

        # Signal numbers: HUP=1, CONT=18. In /proc/*/status masks, bit is (signum-1).
        if (( sigcgt & (1 << 0) )); then
            sig="HUP"
            catches=1
        elif (( sigcgt & (1 << 17) )); then
            sig="CONT"
            catches=1
        else
            sig="CONT"  # safe default (won't kill if not handled)
            catches=0
        fi

        if [[ "$sig" == "HUP" ]]; then
            echo "Reloading ${0##*/} (pid $pid) via SIGHUP ..."
        else
            echo "Reloading ${0##*/} (pid $pid) via SIGCONT ..."
        fi

        if kill -s "$sig" "$pid" 2>/dev/null; then
            if (( catches == 1 )); then
                delivered=1
            else
                echo "Warning: pid $pid does not appear to handle SIGHUP/SIGCONT; reload may be unsupported for this instance."
            fi
        else
            echo "Warning: failed to send SIG${sig} to pid $pid."
        fi
    done

    if (( delivered == 1 )); then
        return 0
    fi

    echo "Error: reload request was not delivered to any running instance."
    return 2
}

_sm_request_reload() {
    SYSTEM_MONITORING_RELOAD_REQUESTED=1
}

# Start all monitor loops in background and remember their PIDs.
_sm_start_monitoring_loops() {
    SYSTEM_MONITORING_LOOP_PIDS=()

    fast_monitor_resources &
    SYSTEM_MONITORING_LOOP_PIDS+=("$!")

    slow_monitor_resources &
    SYSTEM_MONITORING_LOOP_PIDS+=("$!")

    if [[ "${EXTERNAL_MONITORING:-0}" -eq 1 ]]; then
        external_monitor_resources &
        SYSTEM_MONITORING_LOOP_PIDS+=("$!")
    fi
}

# Stop all monitor loops (TERM -> KILL) without exiting the script.
_sm_stop_monitoring_loops() {
    local -a pids=()

    if ((${#SYSTEM_MONITORING_LOOP_PIDS[@]})); then
        pids=("${SYSTEM_MONITORING_LOOP_PIDS[@]}")
    else
        mapfile -t pids < <(jobs -p 2>/dev/null || true)
    fi

    if ((${#pids[@]})); then
        local pid
        for pid in "${pids[@]}"; do
            _sm_kill_tree "$pid" TERM
        done

        sleep 0.2
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                _sm_kill_tree "$pid" KILL
            fi
        done

        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    fi

    SYSTEM_MONITORING_LOOP_PIDS=()
}

_sm_reload_and_restart_loops() {
    echo ""
    echo "Reload requested: reloading configuration and restarting loops..."

    _sm_stop_monitoring_loops

    # Reload secrets (allows BOT_TOKEN/GROUP_ID changes in /etc/telegram.secrets)
    SYSTEM_MONITORING_PHASE="reload-load-secrets"
    load_secrets

    # Rebuild TELEGRAM_API (BOT_TOKEN may have changed)
    local __xtrace_was_on=
    [[ $- == *x* ]] && __xtrace_was_on=1 && set +x
    TELEGRAM_API="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"
    [[ -n "${__xtrace_was_on:-}" ]] && set -x
    unset __xtrace_was_on

    SYSTEM_MONITORING_PHASE="reload-load-external-targets"
    load_external_targets

    SYSTEM_MONITORING_PHASE="reload-dependency-check"
    check_required_software

    SYSTEM_MONITORING_PHASE="reload-load-disk-targets"
    load_disk_targets

    SYSTEM_MONITORING_PHASE="reload-validate-configuration"
    validate_thresholds

    SYSTEM_MONITORING_PHASE="running"

    _sm_start_monitoring_loops

    echo "Reload complete."
}

# Supervisor: waits for children and handles reload requests.
_sm_supervise() {
    while true; do
        # Handle pending reload BEFORE we block in wait -n.
        # This prevents reload requests from being stranded if a HUP arrives during an earlier reload.
        if [[ "${SYSTEM_MONITORING_RELOAD_REQUESTED:-0}" -eq 1 ]]; then
            SYSTEM_MONITORING_RELOAD_REQUESTED=0
            _sm_reload_and_restart_loops
            continue
        fi

        wait -n 2>/dev/null
        local rc=$?

        # Handle reload requests that arrived while we were blocked in wait -n.
        if [[ "${SYSTEM_MONITORING_RELOAD_REQUESTED:-0}" -eq 1 ]]; then
            SYSTEM_MONITORING_RELOAD_REQUESTED=0
            _sm_reload_and_restart_loops
            continue
        fi

        echo "Error: a monitoring loop exited unexpectedly (wait rc: $rc)."
        cleanup 1
    done
}

# ---------------------------------
# Control plane: --STATUS (read-only)
# ---------------------------------

# Fallback: discover instance roots by scanning /proc for this script name.
# (If you already added _sm_control_resolve_root_pids from the --KILL/--RELOAD work,
# status will use that instead.)
_sm_status_find_root_pids_fallback() {
    # Use the shared /proc scanner (keeps status + kill behavior consistent).
    _sm_find_running_root_pids
}

_sm_control_status() {
    local pid_file="${SYSTEM_MONITORING_MAIN_PID_FILE:-${SYSTEM_MONITORING_STATE_DIR}/system-monitoring.main.pid}"
    local main_pid=""

    # If the kill/reload patch exists, prefer its pidfile reader (stricter validation).
    if declare -F _sm_read_main_pid_file >/dev/null 2>&1; then
        main_pid="$(_sm_read_main_pid_file 2>/dev/null || true)"
    elif [[ -r "$pid_file" ]]; then
        read -r main_pid < "$pid_file" 2>/dev/null || true
        main_pid="${main_pid//[[:space:]]/}"
    fi

    local -a roots=()
    if declare -F _sm_control_resolve_root_pids >/dev/null 2>&1; then
        mapfile -t roots < <(_sm_control_resolve_root_pids)
    else
        mapfile -t roots < <(_sm_status_find_root_pids_fallback)
    fi

    echo ""
    echo "${0##*/} --STATUS"
    echo "State dir: ${SYSTEM_MONITORING_STATE_DIR}"
    echo "Main pidfile: ${pid_file}"

    if [[ -n "$main_pid" ]]; then
        if [[ -d "/proc/$main_pid" ]]; then
            echo "Main PID: $main_pid (process exists)"
        else
            echo "Main PID: $main_pid (stale pidfile)"
        fi
    else
        echo "Main PID: (unknown)"
    fi

    if ((${#roots[@]} == 0)); then
        echo "No running ${0##*/} instances found."
        # If the pid file exists but points nowhere, remove it.
        _sm_remove_main_pid_file
        return 3
    fi

    echo "Status: RUNNING"
    if ((${#roots[@]} > 1)); then
        echo "Warning: multiple instance roots found (${#roots[@]})."
    fi

    echo ""
    echo "Instance root PID(s):"
    local pid mark
    for pid in "${roots[@]}"; do
        mark=""
        [[ -n "$main_pid" && "$pid" == "$main_pid" ]] && mark=" (main)"

        if command -v ps >/dev/null 2>&1; then
            echo "  pid ${pid}${mark}:"
            ps -p "$pid" -o pid=,ppid=,etime=,cmd= 2>/dev/null || echo "    (ps failed)"
        else
            echo "  pid ${pid}${mark}"
        fi
    done

    return 0
}

# Function to check if an IP is within the specified CIDR ranges or is an exact IP match.
# Supports both IPv4 and IPv6 (exact IPs and CIDR ranges) in the SSH_ACTIVITY_EXCLUDED_IPS array.
# Uses Python's standard-library "ipaddress" module for correct and consistent matching.
#
# Returns:
#   "true"  -> IP is excluded (matches at least one entry)
#   "false" -> IP is NOT excluded (no match or invalid input)
check_ip_in_range() {
    local raw_ip="$1"

    [[ -z "$raw_ip" ]] && { echo "false"; return; }
    [[ ${#SSH_ACTIVITY_EXCLUDED_IPS[@]} -eq 0 ]] && { echo "false"; return; }

    # Prefer python3. Fallback to "python" only if it can import ipaddress.
    local py=""
    if command -v python3 >/dev/null 2>&1; then
        py="python3"
    elif command -v python >/dev/null 2>&1; then
        py="python"
    else
        # Without Python we cannot do reliable IPv6 CIDR matching.
        # Safer default: treat as NOT excluded so alerts still fire.
        echo "false"
        return
    fi

    # If "python" is present but lacks ipaddress, bail out safely.
    if ! "$py" - <<'PY' >/dev/null 2>&1
import ipaddress
PY
    then
        echo "false"
        return
    fi

    "$py" - "$raw_ip" "${SSH_ACTIVITY_EXCLUDED_IPS[@]}" <<'PY'
import ipaddress
import re
import sys

ip_s = sys.argv[1]
ranges = sys.argv[2:]

def norm(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""

    # Drop surrounding parentheses: "(2001:db8::1)" -> "2001:db8::1"
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        s = s[1:-1].strip()

    # Bracketed IPv6 with optional port: "[2001:db8::1]:22" -> "2001:db8::1"
    m = re.match(r'^\[([^\]]+)\](?::\d+)?$', s)
    if m:
        s = m.group(1)

    # Strip IPv6 zone id: "fe80::1%eth0" -> "fe80::1"
    if "%" in s:
        s = s.split("%", 1)[0]

    # Normalize IPv4-mapped IPv6 early (so we can also strip an IPv4 :port after de-mapping).
    low = s.lower()
    if low.startswith("::ffff:"):
        s = s[len("::ffff:"):]
    elif low.startswith("0:0:0:0:0:ffff:"):
        s = s[len("0:0:0:0:0:ffff:"):]

    # Strip IPv4 :port: "1.2.3.4:22" -> "1.2.3.4" (also catches IPv4-mapped forms after de-mapping)
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d+$', s):
        s = s.rsplit(":", 1)[0]

    return s

ip_s = norm(ip_s)
if not ip_s:
    print("false")
    sys.exit(0)

try:
    ip = ipaddress.ip_address(ip_s)
except ValueError:
    print("false")
    sys.exit(0)

for r in ranges:
    r = norm(r)
    if not r:
        continue
    try:
        if "/" in r:
            net = ipaddress.ip_network(r, strict=False)
            if net.version == ip.version and ip in net:
                print("true")
                sys.exit(0)
        else:
            addr = ipaddress.ip_address(r)
            if addr.version == ip.version and ip == addr:
                print("true")
                sys.exit(0)
    except ValueError:
        continue

print("false")
PY
}

# Function to check for necessary software on the system
check_required_software() {
    local missing_counter=0
    local install_cmd=""
    local pm="unknown"
    local -a failed_checks=()

    # Detect package manager (best-effort). If unknown, we still do checks and give generic hints.
    # This script enforces root, so don't print 'sudo' install hints when already root.
    local sudo_prefix=""
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        sudo_prefix="sudo "
    fi

    if command -v apt-get >/dev/null 2>&1 || command -v apt >/dev/null 2>&1; then
        install_cmd="${sudo_prefix}apt-get install"
        pm="apt"
    elif command -v dnf >/dev/null 2>&1; then
        install_cmd="${sudo_prefix}dnf install"
        pm="dnf"
    elif command -v yum >/dev/null 2>&1; then
        install_cmd="${sudo_prefix}yum install"
        pm="yum"
    elif command -v zypper >/dev/null 2>&1; then
        install_cmd="${sudo_prefix}zypper install"
        pm="zypper"
    elif command -v pacman >/dev/null 2>&1; then
        install_cmd="${sudo_prefix}pacman -S"
        pm="pacman"
    elif command -v apk >/dev/null 2>&1; then
        install_cmd="${sudo_prefix}apk add"
        pm="apk"
    fi

    # Package name hints (vary by distro family)
    local pkg_coreutils="coreutils"
    local pkg_procps="procps"
    local pkg_iproute="iproute2"
    local pkg_ping="iputils-ping"
    local pkg_python="python3"

    case "$pm" in
        yum|dnf)
            pkg_procps="procps-ng"
            pkg_iproute="iproute"
            pkg_ping="iputils"
            pkg_python="python3"
            ;;
        pacman)
            pkg_procps="procps-ng"
            pkg_iproute="iproute2"
            pkg_ping="iputils"
            pkg_python="python"
            ;;
        zypper)
            pkg_procps="procps"
            pkg_iproute="iproute2"
            pkg_ping="iputils"
            pkg_python="python3"
            ;;
        apk)
            pkg_procps="procps"
            pkg_iproute="iproute2"
            pkg_ping="iputils"
            pkg_python="python3"
            ;;
        apt)
            pkg_procps="procps"
            pkg_iproute="iproute2"
            pkg_ping="iputils-ping"
            pkg_python="python3"
            ;;
    esac

    # List of required commands and their corresponding package hints.
    # Keep this list minimal + accurate; add feature-specific deps conditionally.
    declare -A required_commands=(
        ["awk"]="gawk"
        ["curl"]="curl"
        ["grep"]="grep"
        ["stat"]="$pkg_coreutils"
        ["date"]="$pkg_coreutils"
        ["mktemp"]="$pkg_coreutils"
        ["free"]="$pkg_procps"
        ["df"]="$pkg_coreutils"
        ["nproc"]="$pkg_coreutils"
    )
    
    # Disk monitoring uses 'cksum' to create stable per-mount cooldown keys.
    # Only require it when disk monitoring is requested via --DISK or --DISK-LIST.
    if [[ -n "${DISK_THRESHOLD:-}" || -n "${DISK_LIST_FILE:-}" ]]; then
        required_commands["cksum"]="$pkg_coreutils"
    fi

    # SSH/SFTP monitoring (and auth-log "flash" detection) rely on these utilities.
    if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 || "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        required_commands["sed"]="sed"
        required_commands["tail"]="$pkg_coreutils"
        required_commands["head"]="$pkg_coreutils"
        required_commands["cut"]="$pkg_coreutils"
        required_commands["tr"]="$pkg_coreutils"
        required_commands["sort"]="$pkg_coreutils"
        required_commands["ls"]="$pkg_coreutils"
    fi

    # SFTP-only helpers
    if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        required_commands["paste"]="$pkg_coreutils"
    fi

    # Load Average checks need bc (float math/comparisons) — only require it when LA monitoring is enabled.
    if [[ -n "${LA1_THRESHOLD:-}" || -n "${LA5_THRESHOLD:-}" || -n "${LA15_THRESHOLD:-}" ]]; then
        required_commands["bc"]="bc"
    fi

    # SSH monitoring deps (only if enabled)
    if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        required_commands["who"]="$pkg_coreutils"
    fi
    
    # Reboot monitoring deps (only if enabled)
    if [[ "${REBOOT_MONITORING:-0}" -eq 1 ]]; then
        required_commands["who"]="$pkg_coreutils"
    fi

    # SFTP monitoring deps (only if enabled)
    if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        required_commands["ss"]="$pkg_iproute"
        required_commands["ps"]="$pkg_procps"
    fi

    # Ping monitoring deps (only if needed)
    if [[ "${EXTERNAL_NEED_PING:-0}" -eq 1 ]]; then
        required_commands["ping"]="$pkg_ping"
    fi

    echo "Checking for required software..."

    _install_hint() {
        local cmd="$1" pkg="$2"
        if [[ -n "$install_cmd" ]]; then
            echo "To install '$cmd', run: $install_cmd $pkg"
        else
            echo "To install '$cmd', use your distro's package manager to install a package that provides it (suggested: $pkg)."
        fi
    }
    
        # TCP port checks (only if configured) need Python (python3 or python) for socket connect.
    if [[ "${EXTERNAL_NEED_TCP:-0}" -eq 1 ]]; then
        local py=""
        if command -v python3 >/dev/null 2>&1; then
            py="python3"
        elif command -v python >/dev/null 2>&1; then
            py="python"
        fi

        if [[ -z "$py" ]]; then
            echo ""
            echo "Error: TCP port checks are enabled, but neither 'python3' nor 'python' is installed."
            _install_hint "python" "$pkg_python"
            failed_checks+=("TCP port checks enabled but python3/python is missing")
            ((missing_counter++))
        else
            # Sanity: ensure socket/getaddrinfo exists (no network required).
            if ! "$py" - <<'PY' >/dev/null 2>&1
import socket
socket.getaddrinfo("127.0.0.1", 1, socket.AF_UNSPEC, socket.SOCK_STREAM)
PY
            then
                echo ""
                echo "Error: $py is present but cannot run basic socket/getaddrinfo checks."
                _install_hint "python" "$pkg_python"
                failed_checks+=("$py present but socket/getaddrinfo failed (TCP port checks broken)")
                ((missing_counter++))
            fi
        fi
    fi

    for cmd in "${!required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo ""
            echo "Error: Required command '$cmd' is not installed."
            _install_hint "$cmd" "${required_commands[$cmd]}"

            # Also record for Telegram (best-effort; may still fail if curl is missing).
            local pkg="${required_commands[$cmd]}"
            local hint=""
            if [[ -n "$install_cmd" ]]; then
                hint="$install_cmd $pkg"
            else
                hint="install package: $pkg"
            fi
            failed_checks+=("Missing '$cmd' (try: $hint)")

            ((missing_counter++))
        fi
    done

    # Sanity checks for feature-specific tooling
    if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 && $missing_counter -eq 0 ]]; then
        # BusyBox who may not support -u; SSH monitoring requires the coreutils behavior.
        if command -v who >/dev/null 2>&1; then
            if ! LC_ALL=C who -u >/dev/null 2>&1; then
                echo ""
                echo "Error: 'who' on this system does not support: who -u"
                echo "SSH monitoring requires a coreutils 'who' (not BusyBox)."
                _install_hint "who" "$pkg_coreutils"
                failed_checks+=("Incompatible 'who' (does not support 'who -u'); need coreutils 'who'")
                ((missing_counter++))
            fi
        fi
    fi

    if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 && $missing_counter -eq 0 ]]; then
        # BusyBox ps lacks -eo/lstart; this breaks SFTP PID/start tracking.
        if command -v ps >/dev/null 2>&1; then
            if ! LC_ALL=C ps -eo pid,ppid,user,lstart,cmd >/dev/null 2>&1; then
                echo ""
                echo "Error: 'ps' on this system does not support: ps -eo pid,ppid,user,lstart,cmd"
                echo "SFTP monitoring requires a procps/procps-ng 'ps' (not BusyBox)."
                _install_hint "ps" "$pkg_procps"
                failed_checks+=("Incompatible 'ps' (does not support 'ps -eo pid,ppid,user,lstart,cmd'); need procps/procps-ng")
                ((missing_counter++))
            fi
        fi

        # ss must be able to show process info (-p). (root is enforced separately)
        if command -v ss >/dev/null 2>&1; then
            if ! ss -tnp >/dev/null 2>&1; then
                echo ""
                echo "Error: 'ss -tnp' failed. SFTP monitoring needs socket/process info."
                echo "Ensure you run as root and have the correct iproute package installed."
                _install_hint "ss" "$pkg_iproute"
                failed_checks+=("'ss -tnp' failed (need iproute2 + root permissions for -p)")
                ((missing_counter++))
            fi
        fi
    fi
    
    # Sanity checks for ping implementation (avoid BusyBox/inetutils incompatibilities).
    if [[ "${EXTERNAL_NEED_PING:-0}" -eq 1 && $missing_counter -eq 0 ]]; then
        if command -v ping >/dev/null 2>&1; then
            # Require the exact flags we rely on: -n -c -W and force IPv4 with -4.
            # Use localhost so this doesn't depend on external networking.
            if ! LC_ALL=C ping -4 -n -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
                echo ""
                echo "Error: 'ping' on this system is incompatible with ping monitoring."
                echo "Expected flags: ping -4 -n -c 1 -W 1 <host>"
                echo "Ping monitoring requires an iputils-style ping (not BusyBox/inetutils)."
                _install_hint "ping" "$pkg_ping"
                failed_checks+=("Incompatible 'ping' (missing -4/-n/-c/-W or cannot ping localhost); need iputils ping")
                ((missing_counter++))
            else
                # Verify '-6' is at least recognized (IPv6 itself may still be disabled; that's OK).
                local ping6_err=""
                ping6_err="$(LC_ALL=C ping -6 -n -c 1 -W 1 ::1 2>&1 || true)"
                if echo "$ping6_err" | grep -qiE 'unknown option|invalid option|illegal option|unrecognized option'; then
                    echo ""
                    echo "Error: 'ping' on this system does not support IPv6 forcing (-6)."
                    echo "IPv6 ping targets require ping with -6 support (iputils ping)."
                    _install_hint "ping" "$pkg_ping"
                    failed_checks+=("Incompatible 'ping' (no -6 support); need iputils ping for IPv6 targets")
                    ((missing_counter++))
                fi
            fi
        fi
    fi

    # Excluded IP/CIDR matching needs Python's ipaddress (only when exclusions are configured AND SSH/SFTP monitoring is enabled).
    if [[ ${#SSH_ACTIVITY_EXCLUDED_IPS[@]} -gt 0 && ( "${SSH_LOGIN_MONITORING:-0}" -eq 1 || "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ) ]]; then
        local py=""
        if command -v python3 >/dev/null 2>&1; then
            py="python3"
        elif command -v python >/dev/null 2>&1; then
            py="python"
        fi

        if [[ -z "$py" ]]; then
            echo ""
            echo "Error: SSH/SFTP excluded IP matching requires Python (ipaddress), but neither 'python3' nor 'python' is installed."
            _install_hint "python" "$pkg_python"
            failed_checks+=("Excluded IP/CIDR matching enabled but python3/python is missing")
            ((missing_counter++))
        else
            if ! "$py" - <<'PY' >/dev/null 2>&1
import ipaddress
PY
            then
                echo ""
                echo "Error: $py is present but cannot import the standard-library 'ipaddress' module."
                echo "Excluded IP/CIDR matching will not work until Python is fixed."
                _install_hint "python" "$pkg_python"
                failed_checks+=("$py present but cannot import ipaddress (excluded IP matching broken)")
                ((missing_counter++))
            else
                # Validate SSH_ACTIVITY_EXCLUDED_IPS entries early so typos don't silently disable exclusions.
                local invalid
                invalid="$($py - "${SSH_ACTIVITY_EXCLUDED_IPS[@]}" <<'PY'
import ipaddress, re, sys

def norm(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        s = s[1:-1].strip()
    m = re.match(r'^\[([^\]]+)\](?::\d+)?$', s)
    if m:
        s = m.group(1)
    if "%" in s:
        s = s.split("%", 1)[0]
    low = s.lower()
    if low.startswith("::ffff:"):
        s = s[len("::ffff:"):]
    elif low.startswith("0:0:0:0:0:ffff:"):
        s = s[len("0:0:0:0:0:ffff:"):]
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d+$', s):
        s = s.rsplit(":", 1)[0]
    return s

bad = []
for raw in sys.argv[1:]:
    r = norm(raw)
    if not r:
        continue
    try:
        if "/" in r:
            ipaddress.ip_network(r, strict=False)
        else:
            ipaddress.ip_address(r)
    except Exception:
        bad.append(raw)

if bad:
    for b in bad:
        print(b)
    sys.exit(1)
sys.exit(0)
PY
)"
                if [[ -n "$invalid" ]]; then
                    echo ""
                    echo "Error: One or more entries in SSH_ACTIVITY_EXCLUDED_IPS are invalid (must be IP or CIDR):"
                    echo "$invalid" | sed 's/^/  - /'

                    while IFS= read -r bad; do
                        [[ -z "$bad" ]] && continue
                        failed_checks+=("Invalid SSH_ACTIVITY_EXCLUDED_IPS entry: $bad")
                    done <<< "$invalid"

                    ((missing_counter++))
                fi
            fi
        fi
    fi

    if [[ missing_counter -ne 0 ]]; then
        # Send a minimal Telegram message (works even when other deps are missing).
        local body=""
        if ((${#failed_checks[@]})); then
            body="Failed checks:"$'\n'
            local item
            for item in "${failed_checks[@]}"; do
                body+="  - ${item}"$'\n'
            done
        fi
        send_telegram_error_notice "Startup aborted: required software checks failed ($missing_counter)" "$body" || true

        echo ""
        echo "Error: $missing_counter required checks failed."
        echo "Fix the issues above before running this script."
        exit 1
    else
        echo "All required software is installed."
    fi
}


# Function to get the primary IP address of the server (IPv4/IPv6)
# - Prefers the source address used for the default route (outbound).
# - Falls back to the first global address on any interface.
# - Returns a single line suitable for Telegram output.
get_server_ip() {
    local ipv4="" ipv6="" out

    # IPv4: default-route source (if any)
    out="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
    [[ -n "$out" ]] && ipv4="$out"

    # IPv6: default-route source (if any)
    out="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
    [[ -n "$out" ]] && ipv6="${out%%\%*}"  # strip zone id if present

    # Fallbacks: pick first global address on any interface
    if [[ -z "$ipv4" ]]; then
        ipv4="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    fi
    if [[ -z "$ipv6" ]]; then
        ipv6="$(ip -o -6 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
        ipv6="${ipv6%%\%*}"
    fi

    if [[ -n "$ipv4" && -n "$ipv6" ]]; then
        echo "$ipv4 | $ipv6"
    elif [[ -n "$ipv6" ]]; then
        echo "$ipv6"
    elif [[ -n "$ipv4" ]]; then
        echo "$ipv4"
    else
        echo "N/A"
    fi
}






# -------------------------------------------------------------------
# System Monitoring (local system)
# -------------------------------------------------------------------

# Function to check for new SSH logins
# This function monitors for new SSH logins by comparing the current sessions against a saved list.
# It checks each session's username, IP, date, and time. If a session is not in the saved list
# and the IP isn't excluded, it sends a Telegram alert with the login details.
# The function updates the saved list after each check.
check_ssh_activity() {
    # Fetch the current SSH sessions (interactive/utmp-based)

    # Extract username, IP/host, date, time and pid
    local current_logins=$(
        LC_ALL=C who -u | awk '
            BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " ") }
            {
                user = $1

                # Remote host (covers IPv4, IPv6, hostnames)
                ip = ""
                for (i=1; i<=NF; i++) {
                    if ($i ~ /^\([^)]*\)$/) { ip = $i; break }
                }

                # Some who implementations may not wrap host/IP in parentheses; best-effort fallback
                if (ip == "") {
                    for (i=NF; i>=1; i--) {
                        # IPv4 token
                        if ($i ~ /^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$/) { ip = "(" $i ")"; break }
                        # IPv6-ish token (avoid times like 12:34 or 12:34:56)
                        if ($i ~ /:/ && $i !~ /^[0-9][0-9]*:[0-9][0-9](:[0-9][0-9])?$/) { ip = "(" $i ")"; break }
                    }
                }

                # Skip entries with no remote host and skip local X display (:0) / (:0.0)
                if (ip == "" || ip ~ /^\(:[0-9][0-9]*(\.[0-9][0-9]*)?\)$/) next

                # PID: last pure number on the line
                pid = ""
                for (i=NF; i>=1; i--) {
                    if ($i ~ /^[0-9][0-9]*$/) { pid = $i; break }
                }
                if (pid == "") next

                mon = day = tim = ""

                # Detect login time in either ISO (YYYY-MM-DD HH:MM) or text (Mon DD HH:MM) form
                for (i=1; i<=NF; i++) {
                    # ISO: YYYY-MM-DD HH:MM
                    if ($i ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ &&
                        (i+1) <= NF && $(i+1) ~ /^[0-9][0-9]*:[0-9][0-9](:[0-9][0-9])?$/) {
                        split($i, d, "-")
                        mon = M[d[2]+0]
                        day = d[3]+0
                        tim = $(i+1)
                        break
                    }

                    # Text: Mon DD HH:MM
                    if ($i ~ /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/ &&
                        (i+2) <= NF && $(i+1) ~ /^[0-9][0-9]*$/ &&
                        $(i+2) ~ /^[0-9][0-9]*:[0-9][0-9](:[0-9][0-9])?$/) {
                        mon = $i
                        day = $(i+1)+0
                        tim = $(i+2)
                        break
                    }
                }
                if (mon == "" || day == "" || tim == "") next

                # Output exactly what the rest of the function expects:
                # user  (ip)  Mon  day  HH:MM  pid
                print user, ip, mon, day, substr(tim,1,5), pid
            }'
    )
    # Drop SFTP subsystem sessions from SSH monitoring by default.
    # Set SSH_INCLUDE_SFTP_AS_SSH=1 to keep the old behavior (SFTP also counts as SSH).
    if [[ "${SSH_INCLUDE_SFTP_AS_SSH:-0}" -ne 1 && -n "$current_logins" ]]; then
        local __filtered="" __line __pid
        while IFS= read -r __line; do
            [[ -z "$__line" ]] && continue
            __pid="$(awk '{print $6}' <<<"$__line")"
            if [[ -n "$__pid" ]] && pid_looks_like_sftp "$__pid"; then
                continue
            fi
            __filtered+="${__line}"$'\n'
        done <<< "$current_logins"
        current_logins="$(printf '%s' "$__filtered" | sed '/^$/d')"
    fi

    local state_header="# state: $(LC_ALL=C date '+%Y-%m-%d %H:%M:%S%z')"

    # Build user-facing snapshot lines for this tick (written later by write_activity_snapshot_file()).
    if [[ -n "$current_logins" ]]; then
        SSH_PUBLIC_LINES="$(awk '{
            ip=$2; gsub(/[()]/,"",ip);
            printf "  - user=%s from=%s since=%s %s %s\n", $1, ip, $3, $4, $5
        }' <<<"$current_logins")"
    else
        SSH_PUBLIC_LINES=""
    fi

    # Refresh live cache for Flash suppression (prefer PID-based suppression)
    # Patched: also cache a short ancestor lineage for each PID so log PIDs can be suppressed reliably.
    SSH_ACTIVE_KEYS=()
    SSH_ACTIVE_PIDS=()

    _ssh_cache_pid_lineage() {
        local _p="$1"
        local _depth=0

        while [[ -n "${_p:-}" && "${_p:-}" =~ ^[0-9]+$ && ${_p:-0} -gt 1 && $_depth -lt 8 ]]; do
            SSH_ACTIVE_PIDS["$_p"]=1

            local _pp
            _pp="$(awk '/^PPid:/{print $2; exit}' "/proc/${_p}/status" 2>/dev/null || true)"
            [[ -z "${_pp:-}" || "${_pp:-}" == "${_p:-}" ]] && break

            _p="$_pp"
            ((_depth++))
        done
    }

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local u ip pid
        u="$(awk '{print $1}' <<<"$line")"
        ip="$(awk '{print $2}' <<<"$line" | tr -d '()')"
        pid="$(awk '{print $6}' <<<"$line")"
        [[ -n "$u" && -n "$ip" ]] && SSH_ACTIVE_KEYS["$u|$ip"]=1

        # Add PID + ancestors (best-effort)
        [[ -n "$pid" ]] && _ssh_cache_pid_lineage "$pid"
    done <<< "$current_logins"
                    
    # Dedupe: if an SFTP session is currently active, make sure it is NOT tracked as "SSH alerted".
    # Prevents duplicate "SSH Ended" if you enable --SFTP after previously running --SSH-only.
    # Set SSH_INCLUDE_SFTP_AS_SSH=1 to keep the old behavior (SFTP also counts as SSH).
    if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 && "${SSH_INCLUDE_SFTP_AS_SSH:-0}" -ne 1 && -s "$SSH_ACTIVITY_ALERTED" ]]; then
        # IMPORTANT: iterate the *alerted* file, not $current_logins (which already has SFTP filtered out).
        local __line __pid __alerted_snapshot
        __alerted_snapshot="$(cat "$SSH_ACTIVITY_ALERTED" 2>/dev/null || true)"

        while IFS= read -r __line; do
            [[ -z "$__line" ]] && continue
            __pid="$(awk '{print $6}' <<<"$__line")"
            if [[ -n "$__pid" && -n "${SFTP_ACTIVE_PIDS[$__pid]:-}" ]]; then
                statefile_remove_line "$SSH_ACTIVITY_ALERTED" "$__line"
            fi
        done <<< "$__alerted_snapshot"
    fi

    # First run / missing or empty state: baseline and DO NOT alert
    if [[ ! -e "$SSH_ACTIVITY_STATE_FILE" || ! -s "$SSH_ACTIVITY_STATE_FILE" ]]; then
        # Fresh baseline -> drop any stale "alerted" entries so we don't emit "Ended" noise later.
        : > "$SSH_ACTIVITY_ALERTED" 2>/dev/null || true

        {
            echo "$state_header"
            [[ -n "$current_logins" ]] && echo "$current_logins"
        } > "$SSH_ACTIVITY_STATE_FILE"
        return 0
    fi

    local last_logins
    last_logins="$(grep -v '^#' "$SSH_ACTIVITY_STATE_FILE" 2>/dev/null || true)"
    
    # Track Telegram-send failures so we don't permanently miss "Active"/"Ended" alerts.
    # For Active: if Telegram send fails (curl/network), we do NOT commit the session into the state file,
    # so it stays "new" and we retry next tick.
    # For Ended: if Telegram send fails, we keep the ended session in the state file so we retry next tick.
    declare -A __ssh_skip_commit=()
    local __ssh_pending_ended=""

    # ----- Active (new) sessions -----
    while IFS= read -r current_login; do
        [[ -z "$current_login" ]] && continue

        # If the current session is not in the last recorded state, it's new
        if ! grep -Fqx -- "$current_login" <<< "$last_logins"; then
            local user ip pid
            user="$(awk '{print $1}' <<<"$current_login")"
            ip="$(awk '{print $2}' <<<"$current_login" | tr -d '()')"
            pid="$(awk '{print $6}' <<<"$current_login")"

            # Dedupe: if this "SSH" session PID is actually SFTP, don't also alert it as SSH.
            # Set SSH_INCLUDE_SFTP_AS_SSH=1 to keep the old behavior (SFTP also counts as SSH).
            if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 && "${SSH_INCLUDE_SFTP_AS_SSH:-0}" -ne 1 ]]; then
                if [[ -n "$pid" && -n "${SFTP_ACTIVE_PIDS[$pid]:-}" ]]; then
                    # Safety: if a previous run recorded it as SSH, drop it so "SSH Ended" won't fire later.
                    statefile_remove_line "$SSH_ACTIVITY_ALERTED" "$current_login"
                    continue
                fi
            fi

            # Check if the IP is within any of the excluded CIDR ranges or exact matches
            if [[ $(check_ip_in_range "$ip") == "false" ]]; then
                local message="║ SSH: *Active*\n║ User: *$user*\n║ PID: *${pid:-unknown}*\n║ From: *$ip*"
                echo "New SSH Session; Status: Active; User: $user; PID: ${pid:-unknown}; From: $ip"
                send_telegram_alert "SSH-LOGIN" "$message"
                local __rc=$?
                
                if [[ $__rc -eq 0 ]]; then
                    # Only mark as "alerted" when the message was actually delivered.
                    statefile_add_line "$SSH_ACTIVITY_ALERTED" "$current_login"
                elif [[ $__rc -ne 2 ]]; then
                    # Telegram failed (not "locked") -> keep it "new" so we retry next tick.
                    __ssh_skip_commit["$current_login"]=1
                fi
            else
                echo "SSH session Active (excluded): User *[ $user ]* from IP *$ip*. No alert sent."
            fi
        fi
    done <<< "$current_logins"

    # ----- Ended sessions -----
    while IFS= read -r ended_login; do
        [[ -z "$ended_login" ]] && continue

        if ! grep -Fqx -- "$ended_login" <<< "$current_logins"; then
            # Only alert Ended if we alerted Active for this session (prevents baseline noise)
            if statefile_has_line "$SSH_ACTIVITY_ALERTED" "$ended_login"; then
                # --- FIX: SSH Ended should be SSH (not SFTP) + retry on Telegram failure ---
                local user ip pid
                user="$(awk '{print $1}' <<<"$ended_login")"
                ip="$(awk '{print $2}' <<<"$ended_login" | tr -d '()')"
                pid="$(awk '{print $6}' <<<"$ended_login")"

                local __rc_end=0
                if [[ $(check_ip_in_range "$ip") == "false" ]]; then
                    local message="║ SSH: *Ended*\n║ User: *$user*\n║ PID: *${pid:-unknown}*\n║ From: *$ip*"
                    echo "SSH Session; Status: Ended; User: $user; PID: ${pid:-unknown}; From: $ip"
                    send_telegram_alert "SSH-LOGIN" "$message"
                    __rc_end=$?
                else
                    echo "SSH session Ended (excluded): User *[ $user ]* from IP *$ip*. No alert sent."
                    __rc_end=0
                fi

                if [[ $__rc_end -eq 0 || $__rc_end -eq 2 ]]; then
                    # Sent (0) OR intentionally suppressed via lock (2): clear state.
                    statefile_remove_line "$SSH_ACTIVITY_ALERTED" "$ended_login"
                else
                    # Telegram failed: keep it so we can retry Ended next tick.
                    __ssh_pending_ended+="${ended_login}"$'\n'
                fi
            fi
        fi
    done <<< "$last_logins"

    # Update the saved state with the current SSH sessions.
    # If Telegram send failed for a new session, we intentionally do NOT commit it so it remains "new" next tick.
    local __commit_body="" __l

    while IFS= read -r __l; do
        [[ -z "$__l" ]] && continue
        if [[ -n "${__ssh_skip_commit["$__l"]:-}" ]]; then
            continue
        fi
        __commit_body+="${__l}"$'\n'
    done <<< "$current_logins"

    # Keep "Ended" sessions in state when Telegram send failed so we retry next tick.
    if [[ -n "$__ssh_pending_ended" ]]; then
        __commit_body+="${__ssh_pending_ended}"
    fi

    # De-dupe + strip blanks (defensive)
    __commit_body="$(printf '%s' "$__commit_body" | sed '/^$/d' | awk '!seen[$0]++')"

    {
        echo "$state_header"
        [[ -n "$__commit_body" ]] && printf '%s\n' "$__commit_body"
    } > "$SSH_ACTIVITY_STATE_FILE"
}



# Function to check for new SFTP sessions
# This function monitors active SFTP sessions by comparing the current sessions against a previously saved list.
# It extracts each session's PID, start time, and associated network connections.
# If a session is not in the saved list and the source IP isn't excluded based on predefined criteria,
# it sends a Telegram alert with detailed connection information.
# After checking, the function updates the saved list with current session details to log new sessions for future comparisons.
# The goal is to monitor and alert on unauthorized or unexpected SFTP activity from non-excluded IP ranges.
check_sftp_activity() {
    # Fetch PIDs for both external sftp-server and internal-sftp (often shows as "sshd: user@internal-sftp")
    local current_sessions=$(
        LC_ALL=C ps -eo pid,ppid,user,lstart,cmd | awk '
            /sftp-server/ || /internal-sftp/ {
                # pid ppid user dow mon day hh:mm:ss year
                print $1, $2, $3, $4, $5, $6, $7, $8
            }'
    )

    # Build stable session keys + metadata maps.
    # Key format (new): "pid user dow mon day hh:mm:ss year" (PPID excluded on purpose)
    declare -A __sftp_ppid_by_key=()
    declare -A __sftp_user_by_key=()
    declare -A __sftp_started_by_key=()
    declare -A __sftp_pid_by_key=()

    local __keys_buf=""
    local __raw_line
    while IFS= read -r __raw_line; do
        __raw_line="$(echo "$__raw_line" | sed 's/^[ \t]*//;s/[ \t]*$//')"
        [[ -z "$__raw_line" ]] && continue

        local pid ppid user started key
        pid="$(awk '{print $1}' <<<"$__raw_line")"
        ppid="$(awk '{print $2}' <<<"$__raw_line")"
        user="$(awk '{print $3}' <<<"$__raw_line")"
        started="$(awk '{print $4, $5, $6, $7, $8}' <<<"$__raw_line")"

        [[ -z "$pid" || -z "$user" || -z "$started" ]] && continue

        key="$pid $user $started"

        __sftp_ppid_by_key["$key"]="$ppid"
        __sftp_user_by_key["$key"]="$user"
        __sftp_started_by_key["$key"]="$started"
        __sftp_pid_by_key["$key"]="$pid"

        __keys_buf+="${key}"$'\n'
    done <<< "$current_sessions"

    # Normalize once (trim + unique) so comparisons are stable
    local normalized_sessions
    normalized_sessions="$(printf '%s' "$__keys_buf" | sed -e 's/^[ \t]*//;s/[ \t]*$//' -e '/^$/d' | sort -u)"

    local state_header="# state: $(LC_ALL=C date '+%Y-%m-%d %H:%M:%S%z')"

    # Snapshot ss output once (cheaper than calling ss per PID)
    local ss_snapshot
    ss_snapshot="$(ss -tnp 2>/dev/null || true)"

    # Determine sshd listen ports (used to pick the real SSH transport socket and ignore port-forward noise)
    # Cached across ticks.
    local ssh_ports_list="${__SM_SSHD_LISTEN_PORTS_CACHE:-}"
    if [[ -z "$ssh_ports_list" ]]; then
        ssh_ports_list="$(
            ss -tlnp 2>/dev/null | awk '
                NR==1 {next}
                /sshd/ {
                    loc=$4
                    gsub(/\[|\]/,"",loc)
                    sub(/.*:/,"",loc)
                    if (loc ~ /^[0-9]+$/) print loc
                }' | sort -u | paste -sd" " -
        )"
        [[ -z "$ssh_ports_list" ]] && ssh_ports_list="22"
        __SM_SSHD_LISTEN_PORTS_CACHE="$ssh_ports_list"
    fi

    # Helper: extract normalized endpoints for this PID/PPID from ss snapshot
    _sftp_conn_details_for() {
        local pid="$1"
        local ppid="$2"
        [[ -z "$pid" ]] && return 0

        local block=""

        # Prefer exact PID match first; PPID is only a fallback.
        block="$(grep -F "pid=${pid}," <<<"$ss_snapshot" 2>/dev/null || true)"
        if [[ -z "$block" && -n "${ppid:-}" ]]; then
            block="$(grep -F "pid=${ppid}," <<<"$ss_snapshot" 2>/dev/null || true)"
        fi

        [[ -z "$block" ]] && return 0

        # NOTE: portable awk (no match(..., ..., array))
        awk -v ports="$ssh_ports_list" '
            function ep_port(ep,   s,n,a,port) {
                s = ep
                n = split(s, a, ":")
                port = a[n]
                gsub(/[^0-9]/, "", port)
                return port
            }
            function ep_ip(ep,   ip) {
                ip = ep
                # Drop trailing ":port" (works for IPv4 and IPv6 where port is last segment)
                sub(/:[^:]*$/, "", ip)
                # Strip brackets if present
                gsub(/^\[/, "", ip)
                gsub(/\]$/, "", ip)
                # Strip zone id (fe80::1%eth0)
                sub(/%[^ ]+$/, "", ip)
                # Normalize IPv4-mapped IPv6
                sub(/^::ffff:/, "", ip)
                sub(/^0:0:0:0:0:ffff:/, "", ip)
                # Drop obvious non-peers
                if (ip == "*" || ip == "0.0.0.0" || ip == "::") return ""
                return ip
            }
            BEGIN {
                n_ports = split(ports, P, /[ ,]+/)
                for (i=1; i<=n_ports; i++) if (P[i] ~ /^[0-9]+$/) allowed[P[i]] = 1
            }
            # Only established sockets; avoids LISTEN / wildcards.
            $1 ~ /^ESTAB/ {
                lp = ep_port($4)
                if (lp == "") next
                if (n_ports > 0 && !(lp in allowed)) next

                la = ep_ip($4)
                ra = ep_ip($5)
                if (length(la) > 0 && length(ra) > 0) {
                    print la, "<->", ra
                }
            }' <<<"$block"
    }

    # Refresh live cache for Flash suppression (prefer PID-based suppression)
    SFTP_ACTIVE_IPS=()
    SFTP_ACTIVE_PIDS=()
    SFTP_ACTIVE_NET_PIDS=()

    # Helper: cache a PID and a few of its ancestors into SFTP_ACTIVE_PIDS.
    # Why: on some systems `who -u` reports an ancestor PID (e.g. sshd-session/sshd[priv])
    # for SFTP sessions, so we cache a short PID lineage to dedupe SSH vs SFTP correctly.
    _sftp_cache_pid_lineage() {
        local _p="$1"
        local _depth=0

        # 8 levels is plenty (sshd master -> sshd-session/privsep -> user session -> subsystem)
        while [[ -n "${_p:-}" && "${_p:-}" =~ ^[0-9]+$ && ${_p:-0} -gt 1 && $_depth -lt 8 ]]; do
            SFTP_ACTIVE_PIDS["$_p"]=1

            # Read parent PID from /proc (fast, no extra deps)
            local _pp
            _pp="$(awk '/^PPid:/{print $2; exit}' "/proc/${_p}/status" 2>/dev/null || true)"
            [[ -z "${_pp:-}" || "${_pp:-}" == "${_p:-}" ]] && break

            _p="$_pp"
            ((_depth++))
        done
    }

    # Like _sftp_cache_pid_lineage, but only for sessions where ss() had network/process info.
    # This makes auth-log flash detection precise (prevents suppressing real SFTP:Flash events).
    _sftp_cache_pid_lineage_net() {
        local _p="$1"
        local _depth=0

        while [[ -n "${_p:-}" && "${_p:-}" =~ ^[0-9]+$ && ${_p:-0} -gt 1 && $_depth -lt 8 ]]; do
            SFTP_ACTIVE_NET_PIDS["$_p"]=1

            local _pp
            _pp="$(awk '/^PPid:/{print $2; exit}' "/proc/${_p}/status" 2>/dev/null || true)"
            [[ -z "${_pp:-}" || "${_pp:-}" == "${_p:-}" ]] && break

            _p="$_pp"
            ((_depth++))
        done
    }

    # Also build user-facing snapshot lines for this tick.
    SFTP_PUBLIC_LINES=""

    # Cache resolved IP lists per key so we don't re-grep ss() again in the "Active" loop.
    declare -A __sftp_src_ips_by_key=()  # newline-separated unique src ips

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue

        local pid ppid user started connection_details src_ips ips_joined src_ip

        pid="${__sftp_pid_by_key[$key]:-}"
        ppid="${__sftp_ppid_by_key[$key]:-}"
        user="${__sftp_user_by_key[$key]:-}"
        started="${__sftp_started_by_key[$key]:-}"

        # Cache PID lineage (pid + a few ancestors) so SSH live detection can reliably
        # suppress duplicate SSH alerts for SFTP sessions.
        [[ -n "$pid" ]] && _sftp_cache_pid_lineage "$pid"
        [[ -n "$ppid" ]] && _sftp_cache_pid_lineage "$ppid"

        connection_details="$(_sftp_conn_details_for "$pid" "$ppid")"
        if [[ -n "$connection_details" ]]; then
            # Only mark "net-visible" PIDs when ss() actually returned process/network info.
            [[ -n "$pid"  ]] && _sftp_cache_pid_lineage_net "$pid"
            [[ -n "$ppid" ]] && _sftp_cache_pid_lineage_net "$ppid"

            src_ips="$(awk '{print $3}' <<<"$connection_details" | sed '/^$/d' | sort -u)"
            ips_joined="$(echo "$src_ips" | paste -sd, -)"

            __sftp_src_ips_by_key["$key"]="$src_ips"

            while IFS= read -r src_ip; do
                [[ -n "$src_ip" ]] && SFTP_ACTIVE_IPS["$src_ip"]=1
            done <<< "$src_ips"
        else
            __sftp_src_ips_by_key["$key"]=""
            ips_joined=""
        fi

        [[ -z "$ips_joined" ]] && ips_joined="-"
        printf -v _line '  - user=%s from=%s pid=%s started=%s\n' "${user:-unknown}" "$ips_joined" "${pid:-unknown}" "$started"
        SFTP_PUBLIC_LINES+="${_line}"
    done <<< "$normalized_sessions"

    # First run / missing or empty state: baseline and DO NOT alert
    if [[ ! -e "$SFTP_ACTIVITY_LOGINS" || ! -s "$SFTP_ACTIVITY_LOGINS" ]]; then
        # Fresh baseline -> drop any stale "alerted" entries/details so we don't emit "Ended" noise later.
        : > "$SFTP_ACTIVITY_ALERTED" 2>/dev/null || true
        : > "$SFTP_ACTIVITY_DETAILS" 2>/dev/null || true

        {
            echo "$state_header"
            [[ -n "$normalized_sessions" ]] && echo "$normalized_sessions"
        } > "$SFTP_ACTIVITY_LOGINS"
        return 0
    fi

    # Canonicalize state lines (upgrade old "pid ppid user ..." format -> "pid user ...")
    _sftp_canon_key_from_state_line() {
        local line="$1"
        line="$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')"
        [[ -z "$line" ]] && return 0

        # Old format starts with: pid ppid user ...
        if [[ "$line" =~ ^[0-9]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+ ]]; then
            # pid user dow mon day hh:mm:ss year
            awk '{print $1, $3, $4, $5, $6, $7, $8}' <<<"$line"
        else
            echo "$line"
        fi
    }

    # Read last state (ignore header/comments) + canonicalize
    local last_sessions_raw last_sessions
    last_sessions_raw="$(grep -v '^#' "$SFTP_ACTIVITY_LOGINS" 2>/dev/null | sed 's/^[ \t]*//;s/[ \t]*$//' || true)"

    last_sessions=""
    while IFS= read -r __l; do
        __l="$(_sftp_canon_key_from_state_line "$__l")"
        [[ -n "$__l" ]] && last_sessions+="${__l}"$'\n'
    done <<< "$last_sessions_raw"
    last_sessions="$(printf '%s' "$last_sessions" | sed '/^$/d' | sort -u)"

    # Upgrade alerted file if it still contains old keys
    if [[ -s "$SFTP_ACTIVITY_ALERTED" ]]; then
        local __a_raw __a_new __a
        __a_raw="$(cat "$SFTP_ACTIVITY_ALERTED" 2>/dev/null || true)"
        __a_new=""
        while IFS= read -r __a; do
            __a="$(_sftp_canon_key_from_state_line "$__a")"
            [[ -n "$__a" ]] && __a_new+="${__a}"$'\n'
        done <<< "$__a_raw"
        __a_new="$(printf '%s' "$__a_new" | sed '/^$/d' | awk '!seen[$0]++')"
        if [[ -n "$__a_new" ]]; then
            printf '%s\n' "$__a_new" > "$SFTP_ACTIVITY_ALERTED"
        else
            : > "$SFTP_ACTIVITY_ALERTED" 2>/dev/null || true
        fi
    fi

    # Upgrade details mapping file if needed (key<TAB>value)
    if [[ -s "$SFTP_ACTIVITY_DETAILS" ]]; then
        local _tmp
        _tmp="$(mktemp "${SFTP_ACTIVITY_DETAILS}.tmp.XXXXXX" 2>/dev/null)" || _tmp="${SFTP_ACTIVITY_DETAILS}.tmp.${BASHPID:-$$}"
        awk -F'\t' '
            function canon(line,   out) {
                gsub(/^[ \t]+|[ \t]+$/, "", line)
                if (line ~ /^[0-9]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+/) {
                    # old: pid ppid user dow mon day time year
                    split(line, a, /[[:space:]]+/)
                    if (length(a) >= 8) {
                        out = a[1] " " a[3] " " a[4] " " a[5] " " a[6] " " a[7] " " a[8]
                        return out
                    }
                }
                return line
            }
            {
                key = canon($1)
                val = $2
                if (key != "") print key "\t" val
            }' "$SFTP_ACTIVITY_DETAILS" > "$_tmp" 2>/dev/null || true
        if [[ -s "$_tmp" ]]; then
            mv -f "$_tmp" "$SFTP_ACTIVITY_DETAILS" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
        else
            rm -f "$_tmp" 2>/dev/null || true
        fi
    fi

    # Track Telegram-send failures so we don't silently drop SFTP "Active"/"Ended".
    # For Active: if Telegram send fails, we do NOT commit the session into the state file so we retry next tick.
    # For Ended: if Telegram send fails, we keep the ended session in the state file so we retry next tick.
    declare -A __sftp_skip_commit=()
    local __sftp_pending_ended=""

    # ----- Active (new) sessions -----
    while IFS= read -r key; do
        [[ -z "$key" ]] && continue

        if ! grep -Fqx -- "$key" <<< "$last_sessions"; then
            local pid user ppid src_ips src_ip
            pid="${__sftp_pid_by_key[$key]:-}"
            ppid="${__sftp_ppid_by_key[$key]:-}"
            user="${__sftp_user_by_key[$key]:-}"

            # Pull cached src_ips from snapshot loop
            src_ips="${__sftp_src_ips_by_key[$key]:-}"

            # If there are no valid network details, do NOT commit this session.
            # This avoids the "silent absorb" bug where a session becomes non-new and never alerts later.
            if [[ -z "$src_ips" ]]; then
                __sftp_skip_commit["$key"]=1
                continue
            fi

            # Filter out excluded IPs, then alert once per new session
            local report_ips=()
            while IFS= read -r src_ip; do
                [[ -z "$src_ip" ]] && continue
                if [[ $(check_ip_in_range "$src_ip") == "false" ]]; then
                    report_ips+=("$src_ip")
                fi
            done <<< "$src_ips"

            if ((${#report_ips[@]})); then
                local ips_joined
                printf -v ips_joined '%s, ' "${report_ips[@]}"
                ips_joined=${ips_joined%, }

                local message="║ SFTP: *Active*\n║ User: *${user:-unknown}*\n║ PID: *${pid:-unknown}*\n║ From: *${ips_joined}*"
                echo "New SFTP session; Status: Active; User: ${user:-unknown}; PID: ${pid:-unknown}; From: ${ips_joined}"
                send_telegram_alert "SFTP-MONITOR" "$message"
                local __rc=$?

                if [[ $__rc -eq 0 ]]; then
                    statefile_add_line "$SFTP_ACTIVITY_ALERTED" "$key"
                    sftp_details_set "$key" "$ips_joined"
                elif [[ $__rc -ne 2 ]]; then
                    # Telegram failed (not "locked") -> keep it "new" so we retry next tick.
                    __sftp_skip_commit["$key"]=1
                fi
            else
                echo "SFTP session Active (excluded): $(echo "$src_ips" | paste -sd, - | sed 's/,/, /g'). No alert sent."
            fi
        fi
    done <<< "$normalized_sessions"

    # ----- Ended sessions -----
    while IFS= read -r ended_key; do
        ended_key="$(echo "$ended_key" | sed 's/^[ \t]*//;s/[ \t]*$//')"
        [[ -z "$ended_key" ]] && continue

        if ! grep -Fqx -- "$ended_key" <<< "$normalized_sessions"; then
            # Only alert Ended if we alerted Active for this session (prevents baseline noise)
            if statefile_has_line "$SFTP_ACTIVITY_ALERTED" "$ended_key"; then
                local ips_joined pid user
                ips_joined="$(sftp_details_get "$ended_key")"
                pid="$(awk '{print $1}' <<<"$ended_key")"
                user="$(awk '{print $2}' <<<"$ended_key")"

                local __rc_end=0
                if [[ -n "$ips_joined" ]]; then
                    local message="║ SFTP: *Ended*\n║ User: *${user:-unknown}*\n║ PID: *${pid:-unknown}*\n║ From: *${ips_joined}*"
                    echo "SFTP session; Status: Ended; User: ${user:-unknown}; PID: ${pid:-unknown}; From: ${ips_joined}"
                    send_telegram_alert "SFTP-MONITOR" "$message"
                    __rc_end=$?
                else
                    local message="║ SFTP: *Ended*\n║ User: *${user:-unknown}*\n║ PID: *${pid:-unknown}*"
                    echo "SFTP session; Status: Ended; User: ${user:-unknown}; PID: ${pid:-unknown}"
                    send_telegram_alert "SFTP-MONITOR" "$message"
                    __rc_end=$?
                fi

                if [[ $__rc_end -eq 0 || $__rc_end -eq 2 ]]; then
                    statefile_remove_line "$SFTP_ACTIVITY_ALERTED" "$ended_key"
                    sftp_details_del "$ended_key"
                else
                    __sftp_pending_ended+="${ended_key}"$'\n'
                fi
            fi
        fi
    done <<< "$last_sessions"

    # Save current state (bounded, stable).
    # - Exclude new sessions where Telegram send failed OR where ss() details are missing, so they stay "new".
    # - Keep ended sessions where Telegram send failed, so we retry Ended next tick.
    local __commit_body="" __k

    while IFS= read -r __k; do
        [[ -z "$__k" ]] && continue
        if [[ -n "${__sftp_skip_commit["$__k"]:-}" ]]; then
            continue
        fi
        __commit_body+="${__k}"$'\n'
    done <<< "$normalized_sessions"

    if [[ -n "$__sftp_pending_ended" ]]; then
        __commit_body+="${__sftp_pending_ended}"
    fi

    __commit_body="$(printf '%s' "$__commit_body" | sed '/^$/d' | awk '!seen[$0]++')"

    {
        echo "$state_header"
        [[ -n "$__commit_body" ]] && printf '%s\n' "$__commit_body"
    } > "$SFTP_ACTIVITY_LOGINS"
}




# Write a combined SSH+SFTP snapshot into $SSH_ACTIVITY_LOGINS (user-facing).
# This file is overwritten each FAST tick and is safe to tail/parse.
write_activity_snapshot_file() {
    [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 || "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]] || return 0

    local ts host ips
    ts="$(LC_ALL=C date '+%Y-%m-%d %H:%M:%S%z')"
    host="${HOST_NAME:-$(hostname)}"
    ips="$(get_server_ip 2>/dev/null || echo "N/A")"

    {
        echo "# system-monitoring activity snapshot"
        echo "# Host: ${host}"
        echo "# Server IP: ${ips}"
        echo "# Updated: ${ts}"
        echo ""

        if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 ]]; then
            echo "SSH sessions:"
            if [[ -n "${SSH_PUBLIC_LINES:-}" ]]; then
                echo "${SSH_PUBLIC_LINES}"
            else
                echo "  (none)"
            fi
            echo ""
        fi

        if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
            echo "SFTP sessions:"
            if [[ -n "${SFTP_PUBLIC_LINES:-}" ]]; then
                echo "${SFTP_PUBLIC_LINES}"
            else
                echo "  (none)"
            fi
            echo ""
        fi
    } > "$SSH_ACTIVITY_LOGINS"

    chmod 600 "$SSH_ACTIVITY_LOGINS" 2>/dev/null || true
}
             
            
            
# Session state helpers (used for Active/Ended + Flash de-dup)
        
# Live-session caches (set by check_ssh_activity / check_sftp_activity each FAST tick).
# Used to suppress log-based "Flash" alerts when we already see the session live.
declare -gA SSH_ACTIVE_KEYS=()   # key: "user|ip"
declare -gA SSH_ACTIVE_PIDS=()   # key: "pid" (sshd/login process PID from `who -u`)
declare -gA SFTP_ACTIVE_IPS=()   # key: "ip"
declare -gA SFTP_ACTIVE_PIDS=()  # key: "pid" (sshd PID for SFTP; includes parent PID)
declare -gA SFTP_ACTIVE_NET_PIDS=()  # key: "pid" (only when ss() had network info; used to suppress false Flash)
# User-facing snapshot lines (populated each FAST tick and written into $SSH_ACTIVITY_LOGINS)
declare -g SSH_PUBLIC_LINES=""
declare -g SFTP_PUBLIC_LINES=""

# Detect whether a PID belongs to an SFTP subsystem session (internal-sftp or sftp-server).
# Used to keep --SSH from misclassifying SFTP as SSH.
pid_looks_like_sftp() {
    local root_pid="$1"
    [[ -n "${root_pid:-}" && "${root_pid:-}" =~ ^[0-9]+$ && "${root_pid:-0}" -gt 1 ]] || return 1

    local max_depth="${SSH_SFTP_DETECT_DEPTH:-8}"
    local max_nodes="${SSH_SFTP_DETECT_MAX_NODES:-80}"

    declare -A seen=()
    local -a q_pids=()
    local -a q_depths=()
    q_pids=("$root_pid")
    q_depths=(0)

    local nodes=0
    while ((${#q_pids[@]})); do
        local pid="${q_pids[0]}"
        local depth="${q_depths[0]}"
        q_pids=("${q_pids[@]:1}")
        q_depths=("${q_depths[@]:1}")

        [[ -z "${pid:-}" || ! "${pid:-}" =~ ^[0-9]+$ ]] && continue
        [[ -n "${seen[$pid]:-}" ]] && continue
        seen["$pid"]=1
        nodes=$((nodes + 1))
        (( nodes > max_nodes )) && break

        local cmd=""
        if [[ -r "/proc/$pid/cmdline" ]]; then
            cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | tr -s ' ')"
        fi
        if [[ -z "$cmd" && -r "/proc/$pid/comm" ]]; then
            cmd="$(<"/proc/$pid/comm" 2>/dev/null || true)"
        fi
        cmd="${cmd,,}"
        if [[ "$cmd" == *"internal-sftp"* || "$cmd" == *"sftp-server"* ]]; then
            return 0
        fi

        # enqueue children
        if (( depth < max_depth )); then
            local children=""
            if [[ -r "/proc/$pid/task/$pid/children" ]]; then
                children="$(<"/proc/$pid/task/$pid/children" 2>/dev/null || true)"
            fi
            local child
            for child in $children; do
                [[ -z "${seen[$child]:-}" ]] && q_pids+=("$child") && q_depths+=("$((depth + 1))")
            done
        fi
    done

    # Also check a few ancestors (covers who -u reporting an ancestor pid)
    local p="$root_pid"
    local i=0
    while (( i < max_depth )); do
        local ppid
        ppid="$(awk '/^PPid:/{print $2; exit}' "/proc/${p}/status" 2>/dev/null || true)"
        [[ -z "${ppid:-}" || ! "${ppid:-}" =~ ^[0-9]+$ || "${ppid:-0}" -le 1 ]] && break

        local pcmd=""
        if [[ -r "/proc/${ppid}/cmdline" ]]; then
            pcmd="$(tr '\0' ' ' < "/proc/${ppid}/cmdline" 2>/dev/null | tr -s ' ')"
        fi
        if [[ -z "$pcmd" && -r "/proc/${ppid}/comm" ]]; then
            pcmd="$(<"/proc/${ppid}/comm" 2>/dev/null || true)"
        fi
        pcmd="${pcmd,,}"
        if [[ "$pcmd" == *"internal-sftp"* || "$pcmd" == *"sftp-server"* ]]; then
            return 0
        fi

        p="$ppid"
        i=$((i + 1))
    done

    return 1
}

# --- small file helpers (fixed-string exact line matching) ---
statefile_has_line() {
    local file="$1"
    local line="$2"
    [[ -f "$file" ]] && grep -Fqx -- "$line" "$file" 2>/dev/null
}

statefile_add_line() {
    local file="$1"
    local line="$2"
    [[ -z "$line" ]] && return 0
    printf '%s\n' "$line" >> "$file"
}

statefile_remove_line() {
    local file="$1"
    local line="$2"
    [[ ! -f "$file" || -z "$line" ]] && return 0

    local _tmp rc
    _tmp="$(mktemp "${file}.tmp.XXXXXX" 2>/dev/null)" || _tmp="${file}.tmp.${BASHPID:-$$}"

    grep -Fvx -- "$line" "$file" > "$_tmp" 2>/dev/null
    rc=$?
    # grep returns 0 (some lines), 1 (no lines), 2 (error)
    if [[ $rc -eq 0 || $rc -eq 1 ]]; then
        mv -f "$_tmp" "$file" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
    else
        rm -f "$_tmp" 2>/dev/null || true
    fi
}


# --- SFTP details mapping: "<session_line>\t<ips_joined>" ---
sftp_details_set() {
    local session_line="$1"
    local ips_joined="$2"
    [[ -z "$session_line" ]] && return 0

    # remove any existing entry for this session_line
    if [[ -f "$SFTP_ACTIVITY_DETAILS" ]]; then
        local _tmp
        _tmp="$(mktemp "${SFTP_ACTIVITY_DETAILS}.tmp.XXXXXX" 2>/dev/null)" || _tmp="${SFTP_ACTIVITY_DETAILS}.tmp.${BASHPID:-$$}"
        awk -F'\t' -v key="$session_line" '$1 != key {print}' "$SFTP_ACTIVITY_DETAILS" > "$_tmp" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            mv -f "$_tmp" "$SFTP_ACTIVITY_DETAILS" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
        else
            rm -f "$_tmp" 2>/dev/null || true
        fi
    fi

    printf '%s\t%s\n' "$session_line" "$ips_joined" >> "$SFTP_ACTIVITY_DETAILS"
}

sftp_details_get() {
    local session_line="$1"
    [[ -z "$session_line" || ! -f "$SFTP_ACTIVITY_DETAILS" ]] && return 0
    awk -F'\t' -v key="$session_line" '$1 == key {val=$2} END{if (val!="") print val}' "$SFTP_ACTIVITY_DETAILS" 2>/dev/null || true
}

sftp_details_del() {
    local session_line="$1"
    [[ -z "$session_line" || ! -f "$SFTP_ACTIVITY_DETAILS" ]] && return 0
    local _tmp
    _tmp="$(mktemp "${SFTP_ACTIVITY_DETAILS}.tmp.XXXXXX" 2>/dev/null)" || _tmp="${SFTP_ACTIVITY_DETAILS}.tmp.${BASHPID:-$$}"
    awk -F'\t' -v key="$session_line" '$1 != key {print}' "$SFTP_ACTIVITY_DETAILS" > "$_tmp" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        mv -f "$_tmp" "$SFTP_ACTIVITY_DETAILS" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
    else
        rm -f "$_tmp" 2>/dev/null || true
    fi
}



# Auth-log based "Flash" detection (covers short-lived SSH/SFTP activity)

# Detect best SSHD auth log source across common Linux distros.
# Output: path to log file OR "JOURNAL"
detect_sshd_log_source() {
    # Optional hard override (useful for weird/custom setups)
    # export SSHD_LOG_SOURCE=/path/to/log  OR  export SSHD_LOG_SOURCE=JOURNAL
    if [[ -n "${SSHD_LOG_SOURCE:-}" ]]; then
        echo "$SSHD_LOG_SOURCE"
        return 0
    fi

    # Common locations across Debian/Ubuntu, RHEL/CentOS/Fedora, SUSE, etc.
    # Keep auth-ish logs first.
    local candidates=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/messages"
        "/var/log/syslog"
        "/var/log/daemon.log"
        "/var/log/user.log"
        "/var/log/sshd.log"
    )

    # Match both "sshd[1234]:" and "sshd:" styles
    local pat='(^|[[:space:]])(sshd|sshd-session|sshd-auth)(\[[0-9]+\])?:'

    local first_readable=""

    _has_sshd_in_plain_file() {
        local f="$1"
        [[ -r "$f" ]] || return 1
        # Use a larger tail to avoid missing sshd on noisy logs
        LC_ALL=C tail -n 20000 -- "$f" 2>/dev/null | LC_ALL=C grep -aqm1 -E "$pat"
    }

    _has_sshd_in_rotations() {
        # Check the current file plus a couple common “most recent rotation” names.
        # (We return the *base* file as the source if any of these show sshd.)
        local base="$1"

        _has_sshd_in_plain_file "$base" && return 0
        _has_sshd_in_plain_file "${base}.1" && return 0
        _has_sshd_in_plain_file "${base}-1" && return 0

        # Some distros rotate with date suffixes (e.g. secure-20250112); cheap check:
        local dated
        dated=$(ls -1t "${base}-"* 2>/dev/null | head -n 1)
        [[ -n "$dated" ]] && _has_sshd_in_plain_file "$dated" && return 0

        return 1
    }

    _journal_has_sshd() {
        command -v journalctl >/dev/null 2>&1 || return 1

        # journalctl prints "-- No entries --" on stdout; do NOT treat that as a hit.
        local out
        out="$(
            journalctl --no-pager -t sshd -t sshd-session -t sshd-auth -n 5 --since '30 days ago' 2>/dev/null \
            | grep -v '^--' || true
        )"
        [[ -n "$out" ]]
    }

    # 1) Prefer a file if we can prove it has sshd entries (including recent rotations)
    local f
    for f in "${candidates[@]}"; do
        [[ -r "$f" ]] || continue
        [[ -z "$first_readable" ]] && first_readable="$f"
        if _has_sshd_in_rotations "$f"; then
            echo "$f"
            return 0
        fi
    done

    # 2) If journald clearly has sshd entries, use it
    if _journal_has_sshd; then
        echo "JOURNAL"
        return 0
    fi

    # 3) Otherwise: stay stable and use the first readable file if any exist
    if [[ -n "$first_readable" ]]; then
        echo "$first_readable"
        return 0
    fi

    # 4) Last resort: if journalctl works at all, fall back to it
    if command -v journalctl >/dev/null 2>&1 && journalctl --no-pager -n 1 >/dev/null 2>&1; then
        echo "JOURNAL"
        return 0
    fi

    return 1
}


# Read new auth-log lines since the last cursor/offset.
# - File logs: statefile format is "path inode size" (backward compatible with the old "inode size").
# - Journald: statefile format is a single cursor string.
read_new_sshd_log_lines() {
    local statefile="$1"
    local src
    src="$(detect_sshd_log_source)" || return 0

    if [[ "$src" == "JOURNAL" ]]; then
        local cursor="" out="" new_cursor="" rc=0
        local baseline_cursor=""

        # Statefile is a single cursor string (no spaces). If confirmed not cursor, treat as missing.
        if [[ -s "$statefile" ]]; then
            cursor="$(head -n1 "$statefile" 2>/dev/null || true)"
            [[ "$cursor" == *" "* || "$cursor" == /* ]] && cursor=""
        fi

        # Current cursor baseline (used if the saved cursor becomes invalid after rotation/vacuum).
        baseline_cursor="$(journalctl -n 1 --show-cursor -o short-iso --no-pager 2>/dev/null | awk '/^-- cursor: /{print $3; exit}')"

        # Baseline: store the *current* journal cursor even if there are no sshd entries yet.
        if [[ -z "$cursor" ]]; then
            [[ -n "$baseline_cursor" ]] && echo "$baseline_cursor" > "$statefile"
            return 0
        fi

        # Query sshd + sftp-related identifiers after the last cursor.
        out="$(journalctl --after-cursor "$cursor" --show-cursor -o short-iso --no-pager \
            -t sshd -t sshd-session -t sshd-auth -t internal-sftp -t sftp-server 2>/dev/null)"
        rc=$?

        # Fallback for systems that don't use syslog identifiers in the journal.
        if (( rc != 0 )) || [[ -z "$out" ]]; then
            out="$(journalctl --after-cursor "$cursor" --show-cursor -o short-iso --no-pager \
                _COMM=sshd + _COMM=sshd-session + _COMM=sshd-auth + _COMM=internal-sftp + _COMM=sftp-server 2>/dev/null)"
            rc=$?
        fi

        # If cursor became invalid (rotation/vacuum), reset baseline and avoid getting stuck forever.
        if (( rc != 0 )); then
            [[ -n "$baseline_cursor" ]] && echo "$baseline_cursor" > "$statefile"
            return 0
        fi

        # Always advance cursor if available (prevents re-processing on next tick)
        new_cursor="$(awk '/^-- cursor: /{c=$3} END{print c}' <<<"$out")"
        if [[ -n "$new_cursor" ]]; then
            echo "$new_cursor" > "$statefile"
        else
            [[ -n "$baseline_cursor" ]] && echo "$baseline_cursor" > "$statefile"
            return 0
        fi

        # Strip journald meta lines: "-- cursor:", "-- Logs begin", "-- No entries --"
        out="$(grep -v '^--' <<<"$out" || true)"

        [[ -n "$out" ]] && printf '%s\n' "$out"
        return 0
    fi

    # File-based logs
    local path="$src"
    [[ -r "$path" ]] || return 0

    local inode size
    inode="$(stat -c '%i' "$path" 2>/dev/null || true)"
    size="$(stat -c '%s' "$path" 2>/dev/null || echo 0)"

    # Baseline / state restore
    local last_path="" last_inode="" last_off=""
    if [[ -s "$statefile" ]]; then
        read -r last_path last_inode last_off < "$statefile" 2>/dev/null || true

        # Backward compat: old format was "inode size"
        if [[ -n "$last_path" && -n "$last_inode" && -z "$last_off" ]]; then
            last_off="$last_inode"
            last_inode="$last_path"
            last_path=""
        fi
    fi

    # If the previous state doesn't include a path (old format) or the path changed, baseline to end to avoid backscroll noise.
    if [[ -z "$last_path" || "$last_path" != "$path" || -z "$last_inode" || -z "$last_off" ]]; then
        echo "$path $inode $size" > "$statefile"
        return 0
    fi

    # Rotation/truncation handling
    if [[ "$last_inode" != "$inode" || "$size" -lt "$last_off" ]]; then
        last_off=0
    fi

    # Output only new bytes
    if [[ "$size" -gt "$last_off" ]]; then
        tail -c +$(( last_off + 1 )) -- "$path" 2>/dev/null || true
    fi

    # Update cursor
    echo "$path $inode $size" > "$statefile"
}

# Best-effort: resolve sshd loglevel (warn if it's too quiet for Accepted/subsystem lines).
get_sshd_effective_loglevel() {
    local lvl=""

    if command -v sshd >/dev/null 2>&1; then
        lvl="$(sshd -T 2>/dev/null | awk '$1=="loglevel"{print toupper($2); exit}')"
        # Some systems require a -C context for -T; best-effort retry
        if [[ -z "$lvl" ]]; then
            lvl="$(sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 -C laddr=127.0.0.1 -C lport=22 2>/dev/null | awk '$1=="loglevel"{print toupper($2); exit}')"
        fi
    fi

    if [[ -z "$lvl" && -r /etc/ssh/sshd_config ]]; then
        lvl="$(awk 'tolower($1)=="loglevel"{print toupper($2); exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
    fi

    [[ -z "$lvl" ]] && lvl="UNKNOWN"
    echo "$lvl"
}

# Warn (once) if flash detection can't work (no auth logs or sshd LogLevel too quiet).
authlog_flash_healthcheck() {
    # If neither SSH nor SFTP monitoring is enabled, do nothing.
    [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 || "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]] || return 0

    local reason="" hint="" soft_warn=0
    local src
    src="$(detect_sshd_log_source 2>/dev/null || true)"

    if [[ -z "$src" ]]; then
        reason="No readable auth log source found (checked /var/log/auth.log, /var/log/secure, /var/log/syslog, /var/log/messages) and journald is not available."
        hint="Set SSHD_LOG_SOURCE to the correct auth log file, or enable journald (journalctl)."
    elif [[ "$src" == "JOURNAL" ]]; then
        if ! command -v journalctl >/dev/null 2>&1; then
            reason="Flash detection selected journald, but journalctl is not available."
            hint="Install/enable journalctl, or set SSHD_LOG_SOURCE to a readable auth log file."
        fi
    else
        if [[ ! -r "$src" ]]; then
            reason="Flash detection selected \"$src\", but it is not readable."
            hint="Fix permissions for that log, or set SSHD_LOG_SOURCE to a readable auth log file / JOURNAL."
        fi
    fi

    # Verify sshd LogLevel is not too quiet (Accepted/subsystem lines are INFO-level).
    local lvl
    lvl="$(get_sshd_effective_loglevel)"
    case "$lvl" in
        QUIET|FATAL|ERROR)
            reason="sshd LogLevel is $lvl (too quiet). Flash detection needs LogLevel INFO (default) or more verbose."
            hint="Set 'LogLevel INFO' in /etc/ssh/sshd_config and restart sshd (systemctl restart sshd || systemctl restart ssh)."
            soft_warn=0
            ;;
    esac

    # Extra validation: detect_sshd_log_source() can fall back to "first readable file" even when it has no sshd entries.
    # Warn so flash detection doesn't silently do nothing.
    if [[ -z "$reason" ]]; then
        local pat='(^|[[:space:]])(sshd|sshd-session|sshd-auth)(\[[0-9]+\])?:'
        local has_entries=0

        if [[ "$src" == "JOURNAL" ]]; then
            if command -v journalctl >/dev/null 2>&1; then
                if journalctl --no-pager -t sshd -t sshd-session -t sshd-auth -n 5 --since '30 days ago' 2>/dev/null \
                    | grep -v '^--' | grep -q .; then
                    has_entries=1
                fi
            fi
        else
            if LC_ALL=C tail -n 20000 -- "$src" 2>/dev/null | LC_ALL=C grep -aqm1 -E "$pat"; then
                has_entries=1
            elif LC_ALL=C tail -n 20000 -- "${src}.1" 2>/dev/null | LC_ALL=C grep -aqm1 -E "$pat"; then
                has_entries=1
            elif LC_ALL=C tail -n 20000 -- "${src}-1" 2>/dev/null | LC_ALL=C grep -aqm1 -E "$pat"; then
                has_entries=1
            else
                local dated=""
                dated=$(ls -1t "${src}-"* 2>/dev/null | head -n 1)
                if [[ -n "$dated" ]] && LC_ALL=C tail -n 20000 -- "$dated" 2>/dev/null | LC_ALL=C grep -aqm1 -E "$pat"; then
                    has_entries=1
                fi
            fi
        fi

        if (( has_entries == 0 )); then
            reason="Flash detection selected \"$src\" but no sshd auth lines were found there (or in its recent rotations). Flash detection may be monitoring the wrong log and will be ineffective."
            hint="Set SSHD_LOG_SOURCE to the correct auth log file (or JOURNAL). If this server has had no SSH/SFTP activity recently, ignore this until the first login generates log entries."
            soft_warn=1
        fi
    fi

    if [[ -n "$reason" ]]; then
        local prev=""
        [[ -f "$AUTHLOG_FLASH_WARN_STATE" ]] && prev="$(<"$AUTHLOG_FLASH_WARN_STATE" 2>/dev/null || true)"

        if [[ "$reason" != "$prev" ]]; then
            echo "$reason" > "$AUTHLOG_FLASH_WARN_STATE" 2>/dev/null || true

            if (( soft_warn == 1 )); then
                echo "Warning: Auth-log flash detection may be ineffective: $reason" >&2
            else
                echo "Error: Auth-log flash detection is not active: $reason" >&2
            fi
            [[ -n "$hint" ]] && echo "Hint: $hint" >&2

            local status_text="is not active"
            (( soft_warn == 1 )) && status_text="may be ineffective"

            local message="║ *Auth-log flash detection* ${status_text}\n║ Reason: *$reason*"
            [[ -n "$hint" ]] && message+="\n║ Hint: $hint"
            send_telegram_alert "SSH-LOGIN" "$message"
        fi

        # Hard failures disable flash detection; soft warnings still allow it to run.
        (( soft_warn == 1 )) && return 0
        return 1
    fi

    # Healthy: clear any previous warning marker (so we can warn again if it breaks later)
    [[ -f "$AUTHLOG_FLASH_WARN_STATE" ]] && rm -f "$AUTHLOG_FLASH_WARN_STATE" 2>/dev/null || true
    return 0
}

# Best-effort lookup: find the most recent "Accepted ..." line for an sshd PID (helps resolve SFTP user/IP).
lookup_sshd_accept_for_pid() {
    local pid="$1"
    [[ -z "$pid" ]] && return 0

    local src line
    src="$(detect_sshd_log_source)" || return 0

    if [[ "$src" == "JOURNAL" ]]; then
        # Try syslog identifiers first
        line="$(
            journalctl -t sshd -t sshd-session -t sshd-auth -n 400 --no-pager 2>/dev/null \
            | grep -F -e "sshd[$pid]" -e "sshd-session[$pid]" -e "sshd-auth[$pid]" \
            | grep -F "Accepted " \
            | tail -n1 || true
        )"

        # Fallback: match by executable name (_COMM)
        if [[ -z "$line" ]]; then
            line="$(
                journalctl _COMM=sshd + _COMM=sshd-session + _COMM=sshd-auth -n 400 --no-pager 2>/dev/null \
                | grep -F -e "sshd[$pid]" -e "sshd-session[$pid]" -e "sshd-auth[$pid]" \
                | grep -F "Accepted " \
                | tail -n1 || true
            )"
        fi
    else
        # File-based logs
        line="$(
            tail -n 400 -- "$src" 2>/dev/null \
            | grep -F -e "sshd[$pid]" -e "sshd-session[$pid]" -e "sshd-auth[$pid]" \
            | grep -F "Accepted " \
            | tail -n1 || true
        )"
    fi

    [[ -z "$line" ]] && return 0

    local ip user_part user
    ip="$(sed -n 's/.* from \([^ ]\+\) port.*/\1/p' <<<"$line")"
    user_part="$(sed -n 's/.*Accepted [^ ]\+ for \(.*\) from .*/\1/p' <<<"$line")"

    [[ -z "$ip" || -z "$user_part" ]] && return 0

    if [[ "$user_part" =~ ^invalid[[:space:]]+user[[:space:]]+(.+)$ ]]; then
        user="${BASH_REMATCH[1]}"
    else
        user="$user_part"
    fi

    printf '%s|%s\n' "$user" "$ip"
}

lookup_sshd_sftp_marker_for_pid() {
    local pid="$1"
    [[ -z "$pid" ]] && return 1

    local src
    src="$(detect_sshd_log_source)" || return 1

    local mpat='subsystem request.*sftp|starting session:.*(sftp|internal-sftp|sftp-server)|internal-sftp|sftp-server'

    if [[ "$src" == "JOURNAL" ]]; then
        journalctl --no-pager --since "2 minutes ago" -t sshd -t sshd-session -t sshd-auth 2>/dev/null \
          | grep -aF "[$pid]" \
          | grep -aiE "$mpat" -m1 >/dev/null
        return $?
    fi

    # File log fallback
    tail -n 20000 -- "$src" 2>/dev/null \
      | grep -aF "[$pid]" \
      | grep -aiE "$mpat" -m1 >/dev/null
}


# Combined flash detection: reads auth logs and emits Status: Flash when a session is seen in logs
# but NOT visible via the existing "live" detectors (who/ps/ss).
check_ssh_sftp_flash_from_logs() {
    authlog_flash_healthcheck || return 0

    # Use a single cursor per tick to avoid reading the auth log twice.
    local statefile
    statefile="$SFTP_AUTHLOG_STATE_FILE"
    [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 ]] && statefile="$SSH_AUTHLOG_STATE_FILE"

    local new_lines
    new_lines="$(read_new_sshd_log_lines "$statefile")"

    # If both SSH and SFTP monitoring are enabled, keep both cursors in sync.
    if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 && "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        if [[ "$SSH_AUTHLOG_STATE_FILE" != "$SFTP_AUTHLOG_STATE_FILE" ]]; then
            cp -f "$statefile" "$([[ "$statefile" == "$SSH_AUTHLOG_STATE_FILE" ]] && echo "$SFTP_AUTHLOG_STATE_FILE" || echo "$SSH_AUTHLOG_STATE_FILE")" 2>/dev/null || true
        fi
    fi

    [[ -z "$new_lines" ]] && return 0

    declare -A pid_ip=()
    declare -A pid_user=()
    declare -A accepted_pids=()
    declare -A accepted_key_count=()  # "user|ip" -> number of Accepted lines in this log batch
    declare -A sftp_pids=()
    declare -A sftp_keys=()           # (kept) general SFTP activity keys for this tick
    declare -A sftp_keys_weak=()      # "user|ip" -> SFTP marker seen but PID mapping to Accepted failed

    # NEW: PID bridging + mapping Accepted/auth PID -> SFTP
    declare -A child_parent=()       # child_pid -> parent_pid ("User child is on pid ...")
    declare -A parent_children=()    # parent_pid -> "child1 child2 ..."
    declare -A sftp_accept_pids=()   # Accepted/auth PIDs that are actually SFTP (suppress SSH:Flash)
    declare -A sftp_pid_accept=()    # sftp_pid -> accepted/auth pid (for enriching user/ip)
    local last_accept_pid=""

    local line line_lc pid ip user_part user

    # Helper: check whether PID OR ANY of its ancestors is present in a given associative array.
    # Used to suppress Flash when the live detector sees a related PID (pid mismatch across sshd forks).
    _pid_or_ancestor_in_assoc() {
        local __pid="$1"
        local __assoc_name="$2"   # name of assoc array variable
        local __depth=0

        [[ -z "${__pid:-}" || ! "${__pid:-}" =~ ^[0-9]+$ ]] && return 1

        # Use a nameref (Bash 4.3+) so we can look up the chosen assoc array without eval.
        local -n __assoc_ref="$__assoc_name"

        while [[ -n "${__pid:-}" && "${__pid:-}" =~ ^[0-9]+$ && ${__pid:-0} -gt 1 && $__depth -lt 8 ]]; do
            if [[ -n "${__assoc_ref[$__pid]:-}" ]]; then
                return 0
            fi

            local __pp
            __pp="$(awk '/^PPid:/{print $2; exit}' "/proc/${__pid}/status" 2>/dev/null || true)"
            [[ -z "${__pp:-}" || "${__pp:-}" == "${__pid:-}" ]] && break
            __pid="$__pp"
            ((__depth++))
        done

        return 1
    }

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        line_lc="${line,,}"

        # Bridge parent<->child PIDs (common with sshd-auth/sshd-session split)
        if [[ "$line" =~ (sshd|sshd-session|sshd-auth)\[([0-9]+)\] ]] && [[ "$line" == *"User child is on pid "* ]]; then
            local ppid cpid
            ppid="${BASH_REMATCH[2]}"
            cpid="$(sed -n 's/.*User child is on pid \([0-9]\+\).*/\1/p' <<<"$line")"
            if [[ -n "$ppid" && -n "$cpid" ]]; then
                child_parent["$cpid"]="$ppid"
                parent_children["$ppid"]+="$cpid "
            fi
            continue
        fi

        # Successful auth line (covers SSH, SCP, SFTP, rsync, etc.)
        if [[ "$line" == *"Accepted "* && "$line" == *" from "* ]] && \
           [[ "$line" =~ (sshd|sshd-session|sshd-auth)\[([0-9]+)\] ]]; then
            pid="${BASH_REMATCH[2]}"
            ip="$(sed -n 's/.* from \([^ ]\+\) port.*/\1/p' <<<"$line")"
            user_part="$(sed -n 's/.*Accepted [^ ]\+ for \(.*\) from .*/\1/p' <<<"$line")"

            if [[ -n "$pid" && -n "$ip" && -n "$user_part" ]]; then
                if [[ "$user_part" =~ ^invalid[[:space:]]+user[[:space:]]+(.+)$ ]]; then
                    user="${BASH_REMATCH[1]}"
                else
                    user="$user_part"
                fi
                pid_ip["$pid"]="$ip"
                pid_user["$pid"]="$user"
                accepted_pids["$pid"]=1
                accepted_key_count["$user|$ip"]=$(( ${accepted_key_count["$user|$ip"]:-0} + 1 ))
                last_accept_pid="$pid"
            fi
            continue
        fi

        # SFTP start (Flash detection):
        # - "subsystem request ... sftp" (classic)
        # - "Starting session:" variants (subsystem / forced-command / command) that mention sftp/internal-sftp/sftp-server
        if [[ "$line" =~ (sshd|sshd-session|sshd-auth)\[([0-9]+)\] ]]; then
            pid="${BASH_REMATCH[2]}"
            if [[ ( "$line_lc" == *"subsystem request"* && "$line_lc" == *"sftp"* ) \
               || ( "$line_lc" == *"starting session:"* && ( "$line_lc" == *"sftp"* || "$line_lc" == *"internal-sftp"* || "$line_lc" == *"sftp-server"* ) ) \
               || ( "$line_lc" == *"force command"* && ( "$line_lc" == *"internal-sftp"* || "$line_lc" == *"sftp"* ) ) \
               || ( "$line_lc" == *"forced-command"* && ( "$line_lc" == *"internal-sftp"* || "$line_lc" == *"sftp"* ) ) ]]; then

                [[ -n "$pid" ]] && sftp_pids["$pid"]=1

                # Try to parse ip/user from this line (often absent on pure subsystem-request lines)
                ip="$(sed -n 's/.* from \([^ ]\+\) port.*/\1/p' <<<"$line")"
                user="$(sed -n 's/.* by user \([^ ]\+\).*/\1/p' <<<"$line")"
                [[ -z "$user" ]] && user="$(sed -n 's/.* for user \([^ ]\+\).*/\1/p' <<<"$line")"
                [[ -z "$user" ]] && user="$(sed -n 's/.* for \([^ ]\+\) from .*/\1/p' <<<"$line")"

                [[ -n "$pid" && -n "$ip" ]] && pid_ip["$pid"]="$ip"
                [[ -n "$pid" && -n "$user" ]] && pid_user["$pid"]="$user"

                # Map this SFTP marker PID back to the PID that logged "Accepted ..."
                local apid="" ppid kids k

                # 1) Same pid
                [[ -n "${accepted_pids[$pid]:-}" ]] && apid="$pid"

                # 2) If this pid is a child and parent had Accepted
                if [[ -z "$apid" ]]; then
                    ppid="${child_parent[$pid]:-}"
                    [[ -n "$ppid" && -n "${accepted_pids[$ppid]:-}" ]] && apid="$ppid"
                fi

                # 3) If this pid is a parent and one of its children had Accepted
                if [[ -z "$apid" ]]; then
                    kids="${parent_children[$pid]:-}"
                    for k in $kids; do
                        [[ -n "${accepted_pids[$k]:-}" ]] && apid="$k" && break
                    done
                fi

                # 4) Last resort: tie bare SFTP marker to most recent Accepted in this batch
                [[ -z "$apid" && -n "$last_accept_pid" ]] && apid="$last_accept_pid"

                if [[ -n "$apid" ]]; then
                    sftp_accept_pids["$apid"]=1
                    sftp_pid_accept["$pid"]="$apid"
                    # If SFTP line lacks user/ip, inherit from Accepted pid
                    [[ -z "${pid_ip[$pid]:-}"   && -n "${pid_ip[$apid]:-}"   ]] && pid_ip["$pid"]="${pid_ip[$apid]}"
                    [[ -z "${pid_user[$pid]:-}" && -n "${pid_user[$apid]:-}" ]] && pid_user["$pid"]="${pid_user[$apid]}"
                fi

                continue
            fi
        fi

        # Optional: internal-sftp may log under a different identifier on some setups
        if [[ "$line" == *"internal-sftp["* && "$line" == *"session opened"* ]]; then
            pid="$(sed -n 's/.*internal-sftp\[\([0-9]\+\)\].*/\1/p' <<<"$line")"
            [[ -n "$pid" ]] && sftp_pids["$pid"]=1

            # Best-effort parse of remote IP (may be bracketed)
            ip="$(sed -n 's/.* from \[\?\([^ ]\+\)\]\?.*/\1/p' <<<"$line")"
            # Best-effort parse of user
            user="$(sed -n 's/.* for \(local user \)\?\([^ ]\+\).*/\2/p' <<<"$line")"

            [[ -n "$pid" && -n "$ip" ]] && pid_ip["$pid"]="$ip"
            [[ -n "$pid" && -n "$user" ]] && pid_user["$pid"]="$user"

            # Best-effort map to last Accepted in this batch
            if [[ -n "$last_accept_pid" ]]; then
                sftp_accept_pids["$last_accept_pid"]=1
                sftp_pid_accept["$pid"]="$last_accept_pid"
                [[ -z "${pid_ip[$pid]:-}"   && -n "${pid_ip[$last_accept_pid]:-}"   ]] && pid_ip["$pid"]="${pid_ip[$last_accept_pid]}"
                [[ -z "${pid_user[$pid]:-}" && -n "${pid_user[$last_accept_pid]:-}" ]] && pid_user["$pid"]="${pid_user[$last_accept_pid]}"
            fi
            continue
        fi
    done <<< "$new_lines"

    # Build SFTP correlation keys even if SFTP monitoring is disabled.
    # This lets SSH-only mode suppress SSH:Flash when the session is actually SFTP.
    if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        for pid in "${!sftp_pids[@]}"; do
            local apid
            apid="${sftp_pid_accept[$pid]:-}"

            if [[ -n "$apid" ]]; then
                user="${pid_user[$apid]:-unknown}"
                ip="${pid_ip[$apid]:-}"
            else
                ip="${pid_ip[$pid]:-}"
                user="${pid_user[$pid]:-unknown}"

                # Fallback: try find matching Accepted line for this PID in recent logs
                if [[ -z "$ip" || "$user" == "unknown" ]]; then
                    local ui
                    ui="$(lookup_sshd_accept_for_pid "$pid")"
                    if [[ -n "$ui" ]]; then
                        user="${ui%%|*}"
                        ip="${ui#*|}"
                    fi
                fi

                # Extra correlation within THIS batch (weak fallback)
                if [[ -z "$ip" || "$user" == "unknown" ]]; then
                    local ap
                    for ap in "${!accepted_pids[@]}"; do
                        if [[ -z "$ip" && "$user" != "unknown" && "${pid_user[$ap]:-}" == "$user" ]]; then
                            ip="${pid_ip[$ap]:-}"
                            break
                        fi
                        if [[ -n "$ip" && "$user" == "unknown" && "${pid_ip[$ap]:-}" == "$ip" ]]; then
                            user="${pid_user[$ap]:-unknown}"
                            break
                        fi
                    done
                fi
            fi

            if [[ -n "$ip" && "$user" != "unknown" ]]; then
                # Only create a weak suppressor key when we could NOT map this SFTP marker back to an Accepted PID.
                # If we *can* map it, sftp_accept_pids[] already suppresses exactly the correct PID.
                if [[ -z "$apid" ]]; then
                    sftp_keys_weak["$user|$ip"]=1
                fi
            fi
        done
    fi

    # Prefer SFTP Flash over SSH Flash
    if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        for pid in "${!sftp_pids[@]}"; do
            local apid
            apid="${sftp_pid_accept[$pid]:-}"

            if [[ -n "$apid" ]]; then
                user="${pid_user[$apid]:-unknown}"
                ip="${pid_ip[$apid]:-}"
            else
                ip="${pid_ip[$pid]:-}"
                user="${pid_user[$pid]:-unknown}"
            fi

            # Track whether this PID is already visible in the live SFTP detector
            local __sftp_visible_live=0
            if _pid_or_ancestor_in_assoc "$pid" "SFTP_ACTIVE_NET_PIDS"; then
                __sftp_visible_live=1
            fi

            # Last fallback (kept for compatibility)
            if [[ -z "$ip" || "$user" == "unknown" ]]; then
                local ui
                ui="$(lookup_sshd_accept_for_pid "$pid")"
                if [[ -n "$ui" ]]; then
                    user="${ui%%|*}"
                    ip="${ui#*|}"
                fi
            fi

            [[ -z "$ip" ]] && ip="unknown"

            # Remember SFTP activity for this tick (used below to suppress SSH Flash misclassification)
            if [[ "$ip" != "unknown" && "$user" != "unknown" ]]; then
                sftp_keys["$user|$ip"]=1
            fi

            # If the session is visible in the live SFTP detector, Active/Ended handles it -> no Flash
            if (( __sftp_visible_live == 1 )); then
                continue
            fi

            # Skip excluded IPs (when known)
            if [[ "$ip" != "unknown" && $(check_ip_in_range "$ip") != "false" ]]; then
                continue
            fi

            local message="║ SFTP: *Flash*\n║ User: *$user*\n║ PID: *${pid:-unknown}*\n║ From: *$ip*"
            echo "New SFTP session; Status: Flash; User: $user; PID: ${pid:-unknown}; From: $ip"
            send_telegram_alert "SFTP-MONITOR" "$message"
        done
    fi

    if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        for pid in "${!accepted_pids[@]}"; do
            ip="${pid_ip[$pid]:-}"
            user="${pid_user[$pid]:-}"

            [[ -z "$ip" || -z "$user" ]] && continue

            # Strong suppressor: this Accepted/auth PID was mapped to SFTP
            [[ -n "${sftp_accept_pids[$pid]:-}" ]] && continue

            # If this PID did SFTP, don't emit an SSH Flash for it.
            [[ -n "${sftp_pids[$pid]:-}" ]] && continue

            # Weak suppressor (only when PID mapping failed):
            # Suppress SSH:Flash only if there was <= 1 Accepted for that user+IP in this batch.
            # This avoids hiding real SSH activity when a user does BOTH SFTP and SSH from the same IP.
            if [[ -n "${sftp_keys_weak["$user|$ip"]:-}" ]]; then
                if (( ${accepted_key_count["$user|$ip"]:-0} <= 1 )); then
                    continue
                fi
            fi

            # Last-chance dedupe: if auth logs show this PID actually ran SFTP, do NOT emit SSH:Flash.
            if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
                if lookup_sshd_sftp_marker_for_pid "$pid"; then
                    continue
                fi
            fi

            # If the session is visible in the live SSH detector (PID mismatch safe), we will send Active/Ended instead -> no Flash
            if _pid_or_ancestor_in_assoc "$pid" "SSH_ACTIVE_PIDS"; then
                continue
            fi

            # Skip excluded IPs
            if [[ $(check_ip_in_range "$ip") != "false" ]]; then
                continue
            fi

            local message="║ SSH: *Flash*\n║ User: *$user*\n║ PID: *${pid:-unknown}*\n║ From: *$ip*"
            echo "New SSH Session; Status: Flash; User: $user; PID: ${pid:-unknown}; From: $ip"
            send_telegram_alert "SSH-LOGIN" "$message"
        done
    fi
}




# Function to check CPU usage (real CPU%, cgroup-aware, filters short spikes)
check_cpu() {
  local cpu_threshold="$1"

  # ---- Tunables (override via env vars; defaults are sane) ----
  # Per-sample window used for CPU percentage calculation.
  # Smaller values react faster; larger values smooth more.
  local window_seconds="${CPU_CHECK_WINDOW:-5}"                 # seconds per sample

  # CPU must remain >= threshold for this long before alert (filters spikes).
  # With window_seconds=5 and sustain_seconds=20 -> needs 4 consecutive samples.
  local sustain_seconds="${CPU_ALERT_SUSTAIN_SECONDS:-20}"      # seconds above threshold before alert

  # Minimum seconds between CPU alerts (prevents spam).
  local cooldown_seconds="${CPU_ALERT_COOLDOWN:-600}"

  # Stores last alert epoch (so cooldown survives loop iterations).
  local state_file="${CPU_ALERT_STATE_FILE:-${SYSTEM_MONITORING_STATE_DIR}/cpu.lastalert}"

  # ---- sanitize tunables ----
  [[ "$window_seconds" =~ ^[0-9]+$ ]] || window_seconds=5
  (( window_seconds < 1 )) && window_seconds=1

  [[ "$sustain_seconds" =~ ^[0-9]+$ ]] || sustain_seconds=20
  (( sustain_seconds < 1 )) && sustain_seconds=1
  (( sustain_seconds < window_seconds )) && sustain_seconds="$window_seconds"

  [[ "$cooldown_seconds" =~ ^-?[0-9]+$ ]] || cooldown_seconds=600
  (( cooldown_seconds < 0 )) && cooldown_seconds=0

  # ---- cooldown pre-check (skip CPU sampling when still in cooldown) ----
  local now last=0
  now="$(date +%s)"
  if [[ -r "$state_file" ]]; then
    read -r last < "$state_file" 2>/dev/null || true
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
  fi
  if (( cooldown_seconds > 0 && now - last < cooldown_seconds )); then
    return 0
  fi

  # ---- helpers ----
  __check_cpu_count_cpuset_list() {  # "0-3,5" -> 5
    local s="$1"
    [[ -n "$s" ]] || { echo 0; return; }
    echo "$s" | awk -F, '
      {
        c=0
        for(i=1;i<=NF;i++){
          if($i ~ /-/){
            split($i,a,"-")
            c += (a[2]-a[1]+1)
          } else if(length($i)>0) {
            c += 1
          }
        }
        print c
      }'
  }

  __check_cpu_nproc() {
    if command -v nproc >/dev/null 2>&1; then
      nproc
    elif command -v getconf >/dev/null 2>&1; then
      getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
    elif command -v sysctl >/dev/null 2>&1; then
      sysctl -n hw.ncpu 2>/dev/null || echo 1
    else
      echo 1
    fi
  }

  __check_cpu_linux_is_container() {
    [[ -f /.dockerenv || -f /run/.containerenv ]] && return 0
    grep -qaE '(docker|kubepods|containerd|lxc|podman)' /proc/1/cgroup 2>/dev/null && return 0
    return 1
  }

  __check_cpu_linux_procstat_percent() {
    local interval="$1"
    local u1 n1 s1 i1 w1 irq1 sirq1 st1
    local u2 n2 s2 i2 w2 irq2 sirq2 st2

    read -r _ u1 n1 s1 i1 w1 irq1 sirq1 st1 _ < /proc/stat || return 1
    sleep "$interval" || return 1
    read -r _ u2 n2 s2 i2 w2 irq2 sirq2 st2 _ < /proc/stat || return 1

    awk -v u1="$u1" -v n1="$n1" -v s1="$s1" -v i1="$i1" -v w1="$w1" -v irq1="$irq1" -v sirq1="$sirq1" -v st1="$st1" \
        -v u2="$u2" -v n2="$n2" -v s2="$s2" -v i2="$i2" -v w2="$w2" -v irq2="$irq2" -v sirq2="$sirq2" -v st2="$st2" '
      BEGIN{
        idle1=i1+w1; idle2=i2+w2
        tot1=u1+n1+s1+i1+w1+irq1+sirq1+st1
        tot2=u2+n2+s2+i2+w2+irq2+sirq2+st2
        dt=tot2-tot1; didle=idle2-idle1
        if(dt<=0){ exit 1 }
        pct=((dt-didle)*100)/dt
        if(pct<0)pct=0; if(pct>100)pct=100
        printf "%.0f", pct
      }'
  }

  __check_cpu_linux_cgroup2_base() {
    local mnt cgpath
    mnt="$(awk '$0 ~ / - cgroup2 / {print $5; exit}' /proc/self/mountinfo 2>/dev/null)"
    [[ -n "$mnt" ]] || mnt="/sys/fs/cgroup"
    cgpath="$(awk -F: '$1=="0"{print $3; exit}' /proc/self/cgroup 2>/dev/null)"
    [[ "$cgpath" == "/" ]] && cgpath=""
    echo "${mnt}${cgpath}"
  }

  __check_cpu_linux_cgroup2_effective_cores() {
    local base="$1"
    local cores=""
    if [[ -r "$base/cpu.max" ]]; then
      # cpu.max: "max 100000" OR "<quota> <period>"
      read -r q p < "$base/cpu.max"
      if [[ "$q" != "max" && "$q" =~ ^[0-9]+$ && "$p" =~ ^[0-9]+$ && "$p" -gt 0 ]]; then
        cores="$(awk -v q="$q" -v p="$p" 'BEGIN{printf "%.6f", q/p}')"
      fi
    fi
    if [[ -z "$cores" ]]; then
      local cpus=""
      [[ -r "$base/cpuset.cpus.effective" ]] && cpus="$(tr -d ' \n' < "$base/cpuset.cpus.effective")"
      [[ -z "$cpus" && -r "$base/cpuset.cpus" ]] && cpus="$(tr -d ' \n' < "$base/cpuset.cpus")"
      local ccount="$(__check_cpu_count_cpuset_list "$cpus")"
      if [[ "$ccount" =~ ^[0-9]+$ && "$ccount" -gt 0 ]]; then
        cores="$ccount"
      else
        cores="$(__check_cpu_nproc)"
      fi
    fi
    echo "$cores"
  }

  __check_cpu_linux_cgroup2_percent() {
    local interval="$1"
    local base="$(__check_cpu_linux_cgroup2_base)"
    [[ -r "$base/cpu.stat" ]] || return 1

    local cores="$(__check_cpu_linux_cgroup2_effective_cores "$base")"
    [[ -n "$cores" ]] || cores="$(__check_cpu_nproc)"

    local u1 u2 unit="usec"
    u1="$(awk '$1=="usage_usec"{print $2}' "$base/cpu.stat" 2>/dev/null)"
    if [[ -z "$u1" ]]; then
      u1="$(awk '$1=="usage_nsec"{print $2}' "$base/cpu.stat" 2>/dev/null)"
      [[ -n "$u1" ]] || return 1
      unit="nsec"
    fi

    sleep "$interval" || return 1

    u2="$(awk -v key="usage_${unit}" '$1==key{print $2}' "$base/cpu.stat" 2>/dev/null)"
    [[ -n "$u2" ]] || return 1

    awk -v u1="$u1" -v u2="$u2" -v interval="$interval" -v cores="$cores" -v unit="$unit" '
      BEGIN{
        du=u2-u1
        if(du<0) du=0
        cap = (unit=="usec" ? interval*1000000 : interval*1000000000) * cores
        if(cap<=0){ exit 1 }
        pct = (du*100)/cap
        if(pct<0)pct=0
        if(pct>100)pct=100
        printf "%.0f", pct
      }'
  }

  __check_cpu_linux_cgroup1_mountpoint() { # controller -> mountpoint
    local ctl="$1"
    awk -v c="$ctl" '
      {
        dash=0
        for(i=1;i<=NF;i++) if($i=="-"){dash=i; break}
        if(!dash) next
        fstype=$(dash+1)
        super=$(dash+3)
        if(fstype!="cgroup") next
        if(index(","super",", ","c",")>0){ print $5; exit }
      }' /proc/self/mountinfo 2>/dev/null
  }

  __check_cpu_linux_cgroup1_path() { # controller -> cgroup path
    local ctl="$1"
    awk -F: -v c="$ctl" '$2 ~ "(^|,)"c"(,|$)" {print $3; exit}' /proc/self/cgroup 2>/dev/null
  }

  __check_cpu_linux_cgroup1_effective_cores() {
    local cpu_mnt="$1" cpu_path="$2"
    local cores=""

    if [[ -r "$cpu_mnt$cpu_path/cpu.cfs_quota_us" && -r "$cpu_mnt$cpu_path/cpu.cfs_period_us" ]]; then
      local q p
      q="$(cat "$cpu_mnt$cpu_path/cpu.cfs_quota_us" 2>/dev/null)"
      p="$(cat "$cpu_mnt$cpu_path/cpu.cfs_period_us" 2>/dev/null)"
      if [[ "$q" =~ ^-?[0-9]+$ && "$p" =~ ^[0-9]+$ && "$p" -gt 0 && "$q" -gt 0 ]]; then
        cores="$(awk -v q="$q" -v p="$p" 'BEGIN{printf "%.6f", q/p}')"
      fi
    fi

    if [[ -z "$cores" ]]; then
      local cp_mnt cp_path cpus ccount
      cp_mnt="$(__check_cpu_linux_cgroup1_mountpoint cpuset)"
      cp_path="$(__check_cpu_linux_cgroup1_path cpuset)"
      [[ "$cp_path" == "/" ]] && cp_path=""
      if [[ -n "$cp_mnt" && -r "$cp_mnt$cp_path/cpuset.cpus" ]]; then
        cpus="$(tr -d ' \n' < "$cp_mnt$cp_path/cpuset.cpus")"
        ccount="$(__check_cpu_count_cpuset_list "$cpus")"
        if [[ "$ccount" =~ ^[0-9]+$ && "$ccount" -gt 0 ]]; then
          cores="$ccount"
        fi
      fi
    fi

    [[ -n "$cores" ]] || cores="$(__check_cpu_nproc)"
    echo "$cores"
  }

  __check_cpu_linux_cgroup1_percent() {
    local interval="$1"
    local acct_mnt acct_path cpu_mnt cpu_path base usage1 usage2 cores

    acct_mnt="$(__check_cpu_linux_cgroup1_mountpoint cpuacct)"
    acct_path="$(__check_cpu_linux_cgroup1_path cpuacct)"
    [[ "$acct_path" == "/" ]] && acct_path=""
    [[ -n "$acct_mnt" ]] || return 1
    base="$acct_mnt$acct_path"
    [[ -r "$base/cpuacct.usage" ]] || return 1

    # quota lives under cpu controller (might be same mount)
    cpu_mnt="$(__check_cpu_linux_cgroup1_mountpoint cpu)"
    cpu_path="$(__check_cpu_linux_cgroup1_path cpu)"
    [[ "$cpu_path" == "/" ]] && cpu_path=""
    [[ -n "$cpu_mnt" ]] || cpu_mnt="$acct_mnt"
    [[ -n "$cpu_path" ]] || cpu_path="$acct_path"

    cores="$(__check_cpu_linux_cgroup1_effective_cores "$cpu_mnt" "$cpu_path")"

    usage1="$(cat "$base/cpuacct.usage" 2>/dev/null)" || return 1
    sleep "$interval" || return 1
    usage2="$(cat "$base/cpuacct.usage" 2>/dev/null)" || return 1

    awk -v u1="$usage1" -v u2="$usage2" -v interval="$interval" -v cores="$cores" '
      BEGIN{
        du=u2-u1
        if(du<0) du=0
        cap = interval*1000000000*cores
        if(cap<=0){ exit 1 }
        pct = (du*100)/cap
        if(pct<0)pct=0
        if(pct>100)pct=100
        printf "%.0f", pct
      }'
  }

  __check_cpu_linux_percent() {
    local interval="$1"

    # If you *want* cgroup scope on bare metal too, set CPU_CHECK_SCOPE=cgroup
    local scope="${CPU_CHECK_SCOPE:-auto}"

    if [[ "$scope" == "cgroup" ]]; then
      __check_cpu_linux_cgroup2_percent "$interval" 2>/dev/null && return 0
      __check_cpu_linux_cgroup1_percent "$interval" 2>/dev/null && return 0
      return 1
    fi

    if [[ "$scope" == "system" ]]; then
      __check_cpu_linux_procstat_percent "$interval" && return 0
      return 1
    fi

    # auto:
    if __check_cpu_linux_is_container; then
      __check_cpu_linux_cgroup2_percent "$interval" 2>/dev/null && return 0
      __check_cpu_linux_cgroup1_percent "$interval" 2>/dev/null && return 0
      # last resort inside container
      __check_cpu_linux_procstat_percent "$interval" && return 0
      return 1
    else
      # bare metal / VM: system-wide CPU
      __check_cpu_linux_procstat_percent "$interval" && return 0
      return 1
    fi
  }

  __check_cpu_sysctl_percent() {
    local interval="$1"
    local os
    os="$(uname -s)"

    command -v sysctl >/dev/null 2>&1 || return 1

    local a1 a2
    a1=($(sysctl -n kern.cp_time 2>/dev/null)) || return 1
    [[ ${#a1[@]} -ge 5 ]] || return 1
    sleep "$interval" || return 1
    a2=($(sysctl -n kern.cp_time 2>/dev/null)) || return 1
    [[ ${#a2[@]} -ge 5 ]] || return 1

    local idle1 idle2 total1 total2
    if [[ "$os" == "Darwin" ]]; then
      # Darwin: user nice system idle intr
      idle1="${a1[3]}"; idle2="${a2[3]}"
    else
      # *BSD: user nice system intr idle (common)
      idle1="${a1[4]}"; idle2="${a2[4]}"
    fi

    total1=$((a1[0]+a1[1]+a1[2]+a1[3]+a1[4]))
    total2=$((a2[0]+a2[1]+a2[2]+a2[3]+a2[4]))

    awk -v t1="$total1" -v t2="$total2" -v i1="$idle1" -v i2="$idle2" '
      BEGIN{
        dt=t2-t1; didle=i2-i1
        if(dt<=0){ exit 1 }
        pct=((dt-didle)*100)/dt
        if(pct<0)pct=0; if(pct>100)pct=100
        printf "%.0f", pct
      }'
  }

  __check_cpu_vmstat_percent() {
    local interval="$1"
    command -v vmstat >/dev/null 2>&1 || return 1

    local out header values idx idle
    out="$(vmstat "$interval" 2 2>/dev/null)" || return 1

    header="$(printf '%s\n' "$out" | awk '
      NF && $1 !~ /^[0-9-]/ && ($0 ~ /(^|[[:space:]])id([[:space:]]|$)/ || $0 ~ /(^|[[:space:]])idle([[:space:]]|$)/){h=$0}
      END{print h}')"
    values="$(printf '%s\n' "$out" | awk 'NF && $1 ~ /^[0-9]/ {v=$0} END{print v}')"

    [[ -n "$header" && -n "$values" ]] || return 1

    idx="$(printf '%s\n' "$header" | awk '{for(i=1;i<=NF;i++) if($i=="id"||$i=="idle"){print i; exit}}')"
    [[ -n "$idx" ]] || return 1

    idle="$(printf '%s\n' "$values" | awk -v i="$idx" '{print $i}')"
    [[ "$idle" =~ ^[0-9]+$ ]] || return 1

    echo $((100 - idle))
  }

  __check_cpu_percent() {
    local interval="$1"
    local os
    os="$(uname -s)"
    case "$os" in
      Linux)   __check_cpu_linux_percent "$interval" ;;
      Darwin|FreeBSD|OpenBSD|NetBSD) __check_cpu_sysctl_percent "$interval" || __check_cpu_vmstat_percent "$interval" ;;
      *)       __check_cpu_vmstat_percent "$interval" ;;
    esac
  }

  # ---- sustained check ----
  local required_samples=$(( (sustain_seconds + window_seconds - 1) / window_seconds ))
  local i cpu_usage sum=0 peak=0

  for ((i=1; i<=required_samples; i++)); do
    cpu_usage="$(__check_cpu_percent "$window_seconds")" || return 0
    [[ "$cpu_usage" =~ ^[0-9]+$ ]] || return 0

    # Treat any drop below threshold as "not sustained" and bail (filters spikes)
    if (( cpu_usage < cpu_threshold )); then
      return 0
    fi

    sum=$((sum + cpu_usage))
    (( cpu_usage > peak )) && peak="$cpu_usage"
  done

  local avg=$(( sum / required_samples ))

  # Re-check cooldown after sampling (sampling itself took time)
  now="$(date +%s)"
  last=0
  if [[ -r "$state_file" ]]; then
    read -r last < "$state_file" 2>/dev/null || true
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
  fi
  if (( cooldown_seconds > 0 && now - last < cooldown_seconds )); then
    return 0
  fi

  echo "CPU usage is high: ${avg}% (peak ${peak}%, sustained ~${required_samples}x${window_seconds}s)"
  send_telegram_alert "CPU" "$avg\n║ Peak: ${peak}%\n║ Sustained: ~${required_samples}x${window_seconds}s"
  local __rc=$?

  # Start cooldown on success (0) OR intentional suppression via lock (2).
  if [[ $__rc -eq 0 || $__rc -eq 2 ]]; then
    # Atomic write (tmp file then rename). Tmp is created in the state dir by default.
    local _tmp
    _tmp="$(mktemp "${SYSTEM_MONITORING_STATE_DIR}/cpu.lastalert.XXXXXX" 2>/dev/null)" || _tmp=""
    if [[ -n "$_tmp" ]]; then
      printf '%s\n' "$now" > "$_tmp" 2>/dev/null && mv -f "$_tmp" "$state_file" 2>/dev/null || rm -f "$_tmp" 2>/dev/null || true
    else
      printf '%s\n' "$now" > "$state_file" 2>/dev/null || true
    fi
  fi
}



# Function to check RAM usage
check_ram() {
    local ram_threshold=$1

    # Cooldown (prevents alert spam while RAM stays high)
    local cooldown_seconds="${RAM_ALERT_COOLDOWN:-600}"
    local state_file="${RAM_ALERT_STATE_FILE:-${SYSTEM_MONITORING_STATE_DIR}/ram.lastalert}"

    [[ "$cooldown_seconds" =~ ^-?[0-9]+$ ]] || cooldown_seconds=600
    (( cooldown_seconds < 0 )) && cooldown_seconds=0

    # Cooldown pre-check
    local now last=0
    now="$(date +%s)"
    if [[ -r "$state_file" ]]; then
        read -r last < "$state_file" 2>/dev/null || true
        [[ "$last" =~ ^[0-9]+$ ]] || last=0
    fi
    if (( cooldown_seconds > 0 && now - last < cooldown_seconds )); then
        return 0
    fi

    local ram_usage
    ram_usage=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2 }')

    # Compare using awk and interpret the result
    local comparison
    comparison=$(awk -v usage="$ram_usage" -v threshold="$ram_threshold" 'BEGIN {print (usage >= threshold) ? "1" : "0"}')

    if [ "$comparison" -eq 1 ]; then
        echo "RAM usage is high: $ram_usage%"
        send_telegram_alert "RAM" "$ram_usage"
        local __rc=$?

        # Start cooldown on success (0) OR intentional suppression via lock (2).
        if [[ $__rc -eq 0 || $__rc -eq 2 ]]; then
            printf '%s\n' "$now" > "$state_file" 2>/dev/null || true
        fi
    fi
}


# Function to check Disk usage
check_disk() {
    local disk_threshold=$1
    local mount_point=$2

    # Cooldown (prevents alert spam while disk stays high)
    # Default: 24h (86400s). Set DISK_ALERT_COOLDOWN=0 to disable.
    local cooldown_seconds="${DISK_ALERT_COOLDOWN:-86400}"
    [[ "$cooldown_seconds" =~ ^-?[0-9]+$ ]] || cooldown_seconds=86400
    (( cooldown_seconds < 0 )) && cooldown_seconds=0

    # Per-mount cooldown state file (so / and /mnt/data don't suppress each other)
    local mount_key
    mount_key="$(printf '%s' "$mount_point" | cksum | awk '{print $1}')"
    [[ -n "$mount_key" ]] || mount_key="unknown"
    local state_file="${SYSTEM_MONITORING_STATE_DIR}/disk.lastalert.${mount_key}"

    # Cooldown pre-check
    local now last=0
    now="$(date +%s)"
    if [[ -r "$state_file" ]]; then
        read -r last < "$state_file" 2>/dev/null || true
        [[ "$last" =~ ^[0-9]+$ ]] || last=0
    fi
    if (( cooldown_seconds > 0 && now - last < cooldown_seconds )); then
        return 0
    fi

    # Use POSIX df output (one entry per line) and query the target directly.
    # This avoids wrapped output and does not depend on matching $NF to the mount point.
    local disk_usage
    disk_usage=$(df -P -- "$mount_point" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')

    # If parsing failed (invalid path/mount or unexpected df output), do not spam arithmetic errors.
    if ! [[ "$disk_usage" =~ ^[0-9]+$ ]]; then
        echo "Unable to determine disk usage for '$mount_point'."
        return 1
    fi

    if (( disk_usage >= disk_threshold )); then
        local msg
        if [[ "$mount_point" != "/" ]]; then
            echo "Disk high usage: $disk_usage%; Mount: $mount_point"
            msg="*$disk_usage%*\n║ Mount: *$mount_point*"
        else
            echo "Disk high usage: $disk_usage%"
            msg="*$disk_usage%*"
        fi

        send_telegram_alert "DISK" "$msg"
        local __rc=$?

        # Start cooldown on success (0) OR intentional suppression via lock (2).
        if [[ $__rc -eq 0 || $__rc -eq 2 ]]; then
            printf '%s\n' "$now" > "$state_file" 2>/dev/null || true
        fi
    fi
}


# Function to check CPU temperature
# Monitors CPU temperature by reading from the sysfs thermal zone files.
# If no temperature data is available, it logs an error.
check_temp() {
    local temp_threshold=$1
    
    # If TEMP monitoring was already found unavailable in this run, skip further checks.
    if [[ "${TEMP_MONITORING_DISABLED:-0}" -eq 1 ]]; then
        return 0
    fi

    # Best candidate temperature in °C (integer). Start unset.
    local best_temp=-1
    local best_score=-1
    local best_src=""

    local z type raw temp
    # 1) Prefer thermal zones that clearly look like CPU/package temps
    for z in /sys/class/thermal/thermal_zone*; do
        [[ -r "$z/temp" ]] || continue
        type=""
        [[ -r "$z/type" ]] && type=$(<"$z/type")

        case "$type" in
            x86_pkg_temp|cpu-thermal|cpu_thermal|cpu|soc_thermal|soc-thermal|cpu0-thermal|cpu0_thermal)
                raw=$(<"$z/temp")
                raw=${raw//[^0-9]/}
                [[ -n "$raw" ]] || continue
                temp=$(( raw > 1000 ? raw/1000 : raw ))
                if (( temp > best_temp )); then
                    best_temp=$temp
                    best_src="$z/temp ($type)"
                fi
                ;;
        esac
    done

    # 2) Fallback: hwmon (Intel coretemp, AMD k10temp/zenpower, etc.)
    if (( best_temp < 0 )); then
        local h name input label label_file base score
        for h in /sys/class/hwmon/hwmon*; do
            [[ -r "$h/name" ]] || continue
            name=$(<"$h/name")

            base=0
            case "$name" in
                coretemp) base=50 ;;
                k10temp|zenpower|zenpower3|fam15h_power) base=45 ;;
            esac

            for input in "$h"/temp*_input; do
                [[ -r "$input" ]] || continue

                label=""
                label_file="${input%_input}_label"
                [[ -r "$label_file" ]] && label=$(<"$label_file")

                # If this hwmon device isn't a known CPU sensor, only keep entries whose label looks CPU-ish.
                if (( base == 0 )); then
                    case "$label" in
                        *Package*|*Tdie*|*Tctl*|*CPU*|*cpu*|*Core*|*core*) : ;;
                        *) continue ;;
                    esac
                fi

                raw=$(<"$input")
                raw=${raw//[^0-9]/}
                [[ -n "$raw" ]] || continue
                temp=$(( raw > 1000 ? raw/1000 : raw ))

                score=$base
                if [[ "$label" =~ Package[[:space:]]id ]]; then
                    score=$((score + 100))
                elif [[ "$label" =~ ^(Tdie|Tctl)$ ]]; then
                    score=$((score + 95))
                elif [[ "$label" =~ [Cc][Pp][Uu] ]]; then
                    score=$((score + 90))
                elif [[ "$label" =~ Core ]]; then
                    score=$((score + 80))
                else
                    score=$((score + 10))
                fi

                if (( score > best_score )) || { (( score == best_score )) && (( temp > best_temp )); }; then
                    best_score=$score
                    best_temp=$temp
                    best_src="$input ($name${label:+: $label})"
                fi
            done
        done
    fi

    # 3) Final fallback: keep original behavior (first readable thermal zone)
    if (( best_temp < 0 )); then
        local temp_path=""
        for temp_path in /sys/class/thermal/thermal_zone*/temp; do
            [[ -r "$temp_path" ]] || continue
            raw=$(<"$temp_path")
            raw=${raw//[^0-9]/}
            [[ -n "$raw" ]] || continue
            best_temp=$(( raw > 1000 ? raw/1000 : raw ))
            best_src="$temp_path (fallback)"
            break
        done
    fi

    if (( best_temp < 0 )); then
        local reason="No readable CPU temperature sensor found. TEMP monitoring will be skipped."

        # Disable TEMP checks for the rest of this script run (non-persistent).
        TEMP_MONITORING_DISABLED=1

        # Notify only once per run.
        if [[ "${TEMP_MONITORING_WARNED:-0}" -ne 1 ]]; then
            TEMP_MONITORING_WARNED=1
            echo "Error: $reason" >&2

            local message="║ *TEMP monitoring* is not available\n║ Reason: *No readable CPU temperature sensor found*\n║ (TEMP checks will be skipped)"
            send_telegram_alert "TEMP" "$message"
        fi

        return 1
    fi

    # Sensor is available again: clear warning marker so we can warn if it disappears later.
    [[ -f "$TEMP_SENSOR_WARN_STATE" ]] && rm -f "$TEMP_SENSOR_WARN_STATE" 2>/dev/null || true

    # Uncomment for debugging which sensor was used:
    # echo "Temp sensor: $best_src -> ${best_temp}°C"

    if (( best_temp >= temp_threshold )); then
        echo "CPU temperature is high: ${best_temp}°C"
        send_telegram_alert "TEMP" "$best_temp"
    fi
}

# Load Average alert cooldown (PER-LA1/LA5/LA15; all share LA_ALERT_COOLDOWN seconds)

__la_state_file_for() {
    local tag="$1"
    local t="${tag,,}"  # LA1 -> la1, etc.

    # Optional override:
    # - If LA_ALERT_STATE_FILE contains %TAG% or {TAG}, it will be templated.
    # - Otherwise we suffix it with ".<tag>" to keep files distinct.
    if [[ -n "${LA_ALERT_STATE_FILE:-}" ]]; then
        if [[ "$LA_ALERT_STATE_FILE" == *"%TAG%"* ]]; then
            echo "${LA_ALERT_STATE_FILE//%TAG%/$t}"
            return 0
        fi
        if [[ "$LA_ALERT_STATE_FILE" == *"{TAG}"* ]]; then
            echo "${LA_ALERT_STATE_FILE//{TAG}/$t}"
            return 0
        fi
        echo "${LA_ALERT_STATE_FILE}.${t}"
        return 0
    fi

    # Default: separate state file per LA in the script state dir
    echo "${SYSTEM_MONITORING_STATE_DIR}/${t}.lastalert"
}

__la_cooldown_ok() {
    local tag="$1"
    local cooldown_seconds="${LA_ALERT_COOLDOWN:-600}"
    local state_file
    state_file="$(__la_state_file_for "$tag")"

    [[ "$cooldown_seconds" =~ ^-?[0-9]+$ ]] || cooldown_seconds=600
    (( cooldown_seconds < 0 )) && cooldown_seconds=0
    (( cooldown_seconds == 0 )) && return 0

    local now last=0
    now="$(date +%s)"
    if [[ -r "$state_file" ]]; then
        read -r last < "$state_file" 2>/dev/null || true
        [[ "$last" =~ ^[0-9]+$ ]] || last=0
    fi

    (( now - last >= cooldown_seconds ))
}

__la_cooldown_mark_sent() {
    local tag="$1"
    local state_file
    state_file="$(__la_state_file_for "$tag")"
    printf '%s\n' "$(date +%s)" > "$state_file" 2>/dev/null || true
}

__la_send_guarded() {
    local tag="$1"
    local val="$2"

    local state_file lock_file
    state_file="$(__la_state_file_for "$tag")"
    lock_file="${state_file}.lock"

    # Lock across background loops so cooldown check+send+mark is atomic (per-LA).
    # Non-blocking: if another loop is already sending this SAME LA alert, just skip.
    if command -v flock >/dev/null 2>&1; then
        local fd=""
        exec {fd}>"$lock_file" 2>/dev/null || fd=""
        if [[ -n "$fd" ]]; then
            flock -n "$fd" 2>/dev/null || { exec {fd}>&-; return 0; }
            __la_cooldown_ok "$tag" || { exec {fd}>&-; return 0; }
            send_telegram_alert "$tag" "$val"
            local __rc=$?
            if [[ $__rc -eq 0 || $__rc -eq 2 ]]; then
                __la_cooldown_mark_sent "$tag"
            fi
            exec {fd}>&-
            return 0
        fi
    fi

    # Fallback: best-effort if flock isn't available.
    if __la_cooldown_ok "$tag"; then
        send_telegram_alert "$tag" "$val"
        local __rc=$?
        if [[ $__rc -eq 0 || $__rc -eq 2 ]]; then
            __la_cooldown_mark_sent "$tag"
        fi
    fi
}

# Function to check 1-minute Load Average against the threshold
check_la1() {
    __la_cooldown_ok "LA1" || return 0

    local la1
    la1=$(awk '{print $1}' /proc/loadavg)
    local la1_threshold=${1:-${LA1_THRESHOLD:-$(nproc)}}

    if (( $(echo "$la1 >= $la1_threshold" | bc -l) )); then
        echo "1-minute Load Average is high: $la1"
        __la_send_guarded "LA1" "$la1"
    fi
}

# Function to check 5-minute Load Average against the threshold
check_la5() {
    __la_cooldown_ok "LA5" || return 0

    local la5
    la5=$(awk '{print $2}' /proc/loadavg)
    local la5_threshold=${1:-${LA5_THRESHOLD:-$(echo "$(nproc) * 0.75" | bc)}}

    if (( $(echo "$la5 >= $la5_threshold" | bc -l) )); then
        echo "5-minute Load Average is high: $la5"
        __la_send_guarded "LA5" "$la5"
    fi
}

# Function to check 15-minute Load Average against the threshold
check_la15() {
    __la_cooldown_ok "LA15" || return 0

    local la15
    la15=$(awk '{print $3}' /proc/loadavg)
    local la15_threshold=${1:-${LA15_THRESHOLD:-$(echo "$(nproc) * 0.5" | bc)}}

    if (( $(echo "$la15 >= $la15_threshold" | bc -l) )); then
        echo "15-minute Load Average is high: $la15"
        __la_send_guarded "LA15" "$la15"
    fi
}


check_reboot() {
    local last_boot_time=""
    local who_out=""

    # Prefer coreutils `who -b` when it works. Some BusyBox variants don't support -b.
    if who_out="$(LC_ALL=C who -b 2>/dev/null)" && [[ -n "$who_out" ]]; then
        last_boot_time="$(awk '{ if ($3 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) { print $3, $4 } else { print $3, $4, $5 } }' <<<"$who_out")"
    fi

    # Fallback: Linux boot time from /proc/stat (epoch seconds).
    if [[ -z "$last_boot_time" ]]; then
        local btime=""
        btime="$(awk '/^btime[[:space:]]+/ {print $2; exit}' /proc/stat 2>/dev/null)"

        if [[ -n "$btime" ]]; then
            # Human-readable when possible; otherwise store a stable token.
            if command -v date >/dev/null 2>&1 && date -d "@$btime" "+%F %R" >/dev/null 2>&1; then
                last_boot_time="$(date -d "@$btime" "+%F %R")"
            else
                last_boot_time="epoch:$btime"
            fi
        fi
    fi

    # If we still couldn't determine boot time, don't clobber state or generate junk alerts.
    if [[ -z "$last_boot_time" ]]; then
        return 0
    fi

    # First run / missing state file: initialize state and do NOT alert
    if [[ ! -s "$LAST_BOOT_TIME_FILE" ]]; then
        echo "$last_boot_time" > "$LAST_BOOT_TIME_FILE"
        return 0
    fi

    local prev_boot_time=""
    prev_boot_time="$(cat "$LAST_BOOT_TIME_FILE" 2>/dev/null || true)"

    # If previous value is empty, treat as init.
    if [[ -z "$prev_boot_time" ]]; then
        echo "$last_boot_time" > "$LAST_BOOT_TIME_FILE"
        return 0
    fi

    if [[ "$last_boot_time" != "$prev_boot_time" ]]; then
        echo "REBOOT: Detected reboot (boot time changed: '${prev_boot_time}' -> '${last_boot_time}')"
        send_telegram_alert "REBOOT" "║ Status: *REBOOT DETECTED*\n║ Time: ${last_boot_time}\n║ Previous: ${prev_boot_time}"
        local __rc=$?
        
        # Only commit the new boot time if the alert was delivered, OR alerts are intentionally locked.
        # If Telegram/curl failed, keep the previous boot time so we can retry next check.
        if [[ $__rc -eq 0 || $__rc -eq 2 ]]; then
            echo "$last_boot_time" > "$LAST_BOOT_TIME_FILE"
        else
            echo "Warning: reboot alert NOT sent (Telegram failure). Will retry next check." >&2
        fi
        return 0
    fi

    # Keep the state file fresh (no-op if unchanged)
    echo "$last_boot_time" > "$LAST_BOOT_TIME_FILE"
}






# -------------------------------------------------------------------
# Ping Monitoring (remote hosts / services)
# -------------------------------------------------------------------
        
# ICMP ping check with IPv6 support (IPv6 literals force ping -6).
# Runtime state / defaults for ping monitoring (configured via --PING / --PING-LIST)
EXTERNAL_MONITORING=0
EXTERNAL_NEED_PING=0
EXTERNAL_NEED_TCP=0
PING_LIST_FILE=""
EXTERNAL_TARGETS=()
# CLI-only --PING targets (so we can rebuild EXTERNAL_TARGETS on --RELOAD without duplicating --PING-LIST entries)
EXTERNAL_TARGETS_CLI=()

# Defaults (can be overridden per target via the spec)
EXTERNAL_FAILURE_THRESHOLD=3        # consecutive failures before DOWN alert
EXTERNAL_PING_COUNT=3               # ICMP echo requests per check
EXTERNAL_PING_TIMEOUT=6             # seconds per ping attempt (Linux ping -W)
EXTERNAL_TCP_TIMEOUT=3              # seconds per TCP connect attempt

# Internal key separator for associative arrays (unit separator; unlikely in names/hosts)
EXTERNAL_KEY_SEP=$'\x1f'

# Holds a human-readable reason when parse_external_target_spec() returns non-zero.
EXTERNAL_SPEC_ERROR=""

# Feature monitors (CLI flags). Keep numeric to avoid "integer expression expected" from env garbage.
SSH_LOGIN_MONITORING=0
SFTP_LOGIN_MONITORING=0
REBOOT_MONITORING=0

# Trim leading/trailing whitespace (bash-only; no external deps)
trim_ws() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# Split a host spec into host + optional port suffix.
# Supports:
#   - IPv4 / DNS (optionally with :port)
#   - IPv6 literals (raw, or bracketed [v6], optionally with :port)
# Notes:
#   - Raw IPv6 literals are not split on :port (ambiguous). Use [v6]:port instead.
split_external_host_port() {
    local in
    local -n _out_host="$2"
    local -n _out_port="$3"

    in="$(trim_ws "$1")"
    _out_host=""
    _out_port=""

    [[ -z "$in" ]] && return 0

    # Bracketed IPv6 with optional :port suffix: [2001:db8::1] or [2001:db8::1]:443
    if [[ "$in" =~ ^\[([^]]+)\](:([0-9]{1,5}))?$ ]]; then
        _out_host="${BASH_REMATCH[1]}"
        _out_port="${BASH_REMATCH[3]}"
        return 0
    fi

    # IPv4/DNS with :port suffix (exactly one colon): 1.2.3.4:22 or example.com:443
    if [[ "$in" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
        _out_host="${BASH_REMATCH[1]}"
        _out_port="${BASH_REMATCH[2]}"
        return 0
    fi

    _out_host="$in"
    return 0
}

# Normalize host input for checks (returns host only; strips brackets and any unambiguous :port)
normalize_external_host() {
    local h p
    split_external_host_port "$1" h p
    printf '%s' "$h"
}

# Validate comma-separated TCP ports (empty is OK).
# On failure sets EXTERNAL_SPEC_ERROR and returns 1.
validate_external_ports() {
    local ports raw p
    ports="$(trim_ws "$1")"

    # Empty => OK
    [[ -z "$ports" ]] && return 0

    local -a arr
    IFS=',' read -r -a arr <<< "$ports"

    for raw in "${arr[@]}"; do
        p="$(trim_ws "$raw")"
        [[ -z "$p" ]] && continue  # tolerate extra commas/whitespace

        if ! [[ "$p" =~ ^[0-9]{1,5}$ ]]; then
            EXTERNAL_SPEC_ERROR="Invalid port token '$p' (expected integer 1-65535)"
            return 1
        fi

        p=$((10#$p))
        if (( p < 1 || p > 65535 )); then
            EXTERNAL_SPEC_ERROR="Port '$p' is out of range (expected 1-65535)"
            return 1
        fi
    done

    return 0
}



# Parse a ping target spec.
#
# Supported format (key/value; pairs separated by '|'; order does not matter):
#   Name=router|Host=10.10.10.1|Ping=true|Port=22,80,443|Interval=11|MaxFails=3
#
# Keys (case-insensitive):
#   Name      : display name (defaults to Host)
#   Host      : IPv4 / IPv6 literal (brackets allowed) or DNS name (host:port and [v6]:port supported)
#   Ping      : true/false (default: true). When false, ICMP is skipped (ports only).
#   Port      : comma-separated TCP ports (e.g. 22,80,443) or '-' for none
#   Interval  : seconds between checks (optional; default: PING_CHECK_INTERVAL)
#   MaxFails  : consecutive failures before DOWN alert (optional; default: EXTERNAL_FAILURE_THRESHOLD)
#   Flags     : optional extra flags (comma-separated). Currently supports: noping
#
# Notes:
# - Bare tokens (without '=') are treated as flags; only 'noping' is allowed.
# - A spec that disables ping and has no ports is rejected (it would do nothing).
parse_external_target_spec() {
    local spec="$1"
    local -n _name="$2"
    local -n _host="$3"
    local -n _ports="$4"
    local -n _flags="$5"
    local -n _interval="$6"
    local -n _fails="$7"

    _name=""; _host=""; _ports=""; _flags=""; _interval=""; _fails=""
    EXTERNAL_SPEC_ERROR=""

    spec="$(trim_ws "$spec")"
    if [[ -z "$spec" ]]; then
        EXTERNAL_SPEC_ERROR="Empty ping target spec"
        return 1
    fi

    # Require key/value format (pairs separated by '|')
    if [[ "$spec" != *"="* ]]; then
        EXTERNAL_SPEC_ERROR="Target must use key/value format (e.g. Name=web|Host=example.com|Port=443)"
        return 1
    fi

    local -a parts
    IFS='|' read -r -a parts <<< "$spec"

    local name_val="" host_val="" ports_val="" ping_val="" interval_val="" fails_val="" flags_val=""
    local ping_key_present=0

    local token key val key_lc
    for token in "${parts[@]}"; do
        token="$(trim_ws "$token")"
        [[ -z "$token" ]] && continue

        # Allow bare tokens as flags (only 'noping' supported).
        if [[ "$token" != *"="* ]]; then
            token="${token,,}"
            if [[ "$token" != "noping" ]]; then
                EXTERNAL_SPEC_ERROR="Unknown bare token '$token' (only 'noping' is allowed)"
                return 1
            fi
            if [[ -z "$flags_val" ]]; then
                flags_val="$token"
            else
                flags_val+=",${token}"
            fi
            continue
        fi

        key="${token%%=*}"
        val="${token#*=}"
        key="$(trim_ws "$key")"
        val="$(trim_ws "$val")"
        key_lc="${key,,}"

        case "$key_lc" in
            name)  name_val="$val" ;;
            host)  host_val="$val" ;;
            ping)  ping_val="$val"; ping_key_present=1 ;;
            port|ports) ports_val="$val" ;;
            interval) interval_val="$val" ;;
            maxfails|fails|fail) fails_val="$val" ;;
            flags|flag) flags_val="$val" ;;
            *)
                EXTERNAL_SPEC_ERROR="Unknown key '$key' (allowed: Name, Host, Ping, Port(s), Interval, MaxFails, Flags)"
                return 1
                ;;
        esac
    done

    _name="$(trim_ws "$name_val")"

    local host_port=""
    split_external_host_port "$host_val" _host host_port

    _ports="$(trim_ws "$ports_val")"
    _flags="$(trim_ws "$flags_val")"

    if [[ -z "$_host" ]]; then
        EXTERNAL_SPEC_ERROR="Host is required (Host=...)"
        return 1
    fi
    # Hardening: prevent ping option injection (e.g. Host=-f)
    if [[ "$_host" == -* ]]; then
        EXTERNAL_SPEC_ERROR="Invalid Host '${_host}': must not start with '-'"
        return 1
    fi

    [[ -z "$_name" ]] && _name="$_host"

    # Normalize ports field
    if [[ "$_ports" == "-" ]]; then
        _ports=""
    fi
    case "${_ports,,}" in
        none|null) _ports="" ;;
    esac

    # If Host was provided as host:port and no Port(s) were set, treat it as a single port check.
    if [[ -n "$host_port" && -z "$_ports" ]]; then
        _ports="$host_port"
    fi

    # Fail fast on invalid ports (otherwise they only get skipped at runtime).
    if ! validate_external_ports "$_ports"; then
        # validate_external_ports sets EXTERNAL_SPEC_ERROR
        return 1
    fi

    # Interval / MaxFails (optional)
    if [[ -n "$interval_val" ]]; then
        if ! [[ "$interval_val" =~ ^[0-9]+$ ]]; then
            EXTERNAL_SPEC_ERROR="Interval must be an integer number of seconds (1-86400); got '$interval_val'"
            return 1
        fi
        _interval=$((10#$interval_val))
        if (( _interval < 1 || _interval > 86400 )); then
            EXTERNAL_SPEC_ERROR="Interval is out of range (1-86400); got '${_interval}'"
            return 1
        fi
    fi

    if [[ -n "$fails_val" ]]; then
        if ! [[ "$fails_val" =~ ^[0-9]+$ ]]; then
            EXTERNAL_SPEC_ERROR="MaxFails must be an integer (1-100); got '$fails_val'"
            return 1
        fi
        _fails=$((10#$fails_val))
        if (( _fails < 1 || _fails > 100 )); then
            EXTERNAL_SPEC_ERROR="MaxFails is out of range (1-100); got '${_fails}'"
            return 1
        fi
    fi

    # Normalize flags: split by comma, trim, lowercase, rebuild (and validate)
    if [[ -n "$_flags" ]]; then
        local -a fparts
        IFS=',' read -r -a fparts <<< "$_flags"
        local f cleaned=""
        for f in "${fparts[@]}"; do
            f="$(trim_ws "$f")"
            [[ -z "$f" ]] && continue
            f="${f,,}"
            f="${f//|/}"

            if [[ "$f" != "noping" ]]; then
                EXTERNAL_SPEC_ERROR="Unknown flag '$f' (supported: noping)"
                return 1
            fi

            if [[ -z "$cleaned" ]]; then
                cleaned="$f"
            else
                # avoid duplicating noping
                [[ ",$cleaned," == *",${f},"* ]] || cleaned+=",${f}"
            fi
        done
        _flags="$cleaned"
    fi

    # Ping=true/false implemented via 'noping' flag (Ping overrides flags)
    if (( ping_key_present == 1 )); then
        local ping_enabled=1
        local pv="${ping_val,,}"
        case "$pv" in
            1|true|yes|y|on|enable|enabled)  ping_enabled=1 ;;
            0|false|no|n|off|disable|disabled) ping_enabled=0 ;;
            *)
                EXTERNAL_SPEC_ERROR="Ping must be true/false; got '$ping_val'"
                return 1
                ;;
        esac

        if (( ping_enabled == 0 )); then
            if [[ "$_flags" != *noping* ]]; then
                if [[ -z "$_flags" ]]; then
                    _flags="noping"
                else
                    _flags+=",noping"
                fi
            fi
        else
            # Remove any 'noping' if Ping is explicitly enabled.
            if [[ "$_flags" == *noping* ]]; then
                local -a fparts2
                IFS=',' read -r -a fparts2 <<< "$_flags"
                local f2 cleaned2=""
                for f2 in "${fparts2[@]}"; do
                    f2="$(trim_ws "$f2")"
                    [[ -z "$f2" ]] && continue
                    f2="${f2,,}"
                    [[ "$f2" == "noping" ]] && continue
                    if [[ -z "$cleaned2" ]]; then
                        cleaned2="$f2"
                    else
                        cleaned2+=",${f2}"
                    fi
                done
                _flags="$cleaned2"
            fi
        fi
    fi

    # No-op config guard: ping disabled and no ports
    if [[ "$_flags" == *noping* ]] && [[ -z "$_ports" ]]; then
        EXTERNAL_SPEC_ERROR="No-op target: ping disabled and no tcp ports (set Ping=true or add Port=...)"
        return 1
    fi

    return 0
}

# Load ping targets from --PING-LIST (if set) and decide whether ping is required.
# This runs BEFORE load_secrets/check_required_software so dependency checks can be conditional.
load_external_targets() {
    # Always rebuild the combined target list from scratch (supports --RELOAD without duplicates).
    EXTERNAL_TARGETS=()
    if (( ${#EXTERNAL_TARGETS_CLI[@]} )); then
        EXTERNAL_TARGETS+=("${EXTERNAL_TARGETS_CLI[@]}")
    fi

    # Load from list file (append to any CLI --PING entries)
    if [[ -n "${PING_LIST_FILE:-}" ]]; then
        if [[ ! -f "$PING_LIST_FILE" ]]; then
            echo "Error: --PING-LIST file not found: $PING_LIST_FILE"
            exit 1
        fi

        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%$'\r'}"
            # Strip comments and whitespace
            line="${line%%#*}"
            line="$(trim_ws "$line")"
            [[ -z "$line" ]] && continue
            EXTERNAL_TARGETS+=("$line")
        done < "$PING_LIST_FILE"
    fi

    # Decide whether ping is needed (and ensure monitoring is enabled if targets exist)
    EXTERNAL_NEED_PING=0
    EXTERNAL_NEED_TCP=0

    if [[ ${#EXTERNAL_TARGETS[@]} -gt 0 ]]; then
        EXTERNAL_MONITORING=1

        local spec name host ports flags interval fails
        declare -A seen_target_keys
        local target_key

        for spec in "${EXTERNAL_TARGETS[@]}"; do
            name=""; host=""; ports=""; flags=""; interval=""; fails=""
            if ! parse_external_target_spec "$spec" name host ports flags interval fails; then
                echo "Error: Invalid ping target spec: '$spec'"
                if [[ -n "${EXTERNAL_SPEC_ERROR:-}" ]]; then
                    echo "Reason: ${EXTERNAL_SPEC_ERROR}"
                fi
                echo "Expected: Name=<name>|Host=<host>|Ping=true|Port=22,80,443|Interval=11|MaxFails=3"
                exit 1
            fi
            
            # Reject duplicate Name+Host targets: state/scheduling keys collide.
            target_key="${name}${EXTERNAL_KEY_SEP}${host}"
            if [[ -n "${seen_target_keys["$target_key"]+x}" ]]; then
                echo "Error: Duplicate ping target detected (same Name+Host)."
                echo "Name: '$name'  Host: '$host'"
                echo "First: '${seen_target_keys["$target_key"]}'"
                echo "Dup:   '$spec'"
                echo "Fix: merge ports into one spec, OR give each entry a unique Name (e.g. web-22, web-443)."
                exit 1
            fi
            seen_target_keys["$target_key"]="$spec"

            # Any TCP ports configured => TCP checks are enabled (needs Python)
            if [[ -n "$ports" ]]; then
                EXTERNAL_NEED_TCP=1
            fi

            # Ping is enabled by default unless 'noping' flag is present
            if [[ "$flags" != *noping* ]]; then
                EXTERNAL_NEED_PING=1
            fi

        done
    fi
}

external_ping_host() {
    local host
    host="$(normalize_external_host "$1")"

    # Safety: if ping is missing, fail
    command -v ping >/dev/null 2>&1 || return 2

    local -a base
    base=(-n -c "${EXTERNAL_PING_COUNT}" -W "${EXTERNAL_PING_TIMEOUT}")

    # IPv6 literal: force IPv6 ping (some ping variants won't infer correctly)
    if [[ "$host" == *:* ]]; then
        ping -6 "${base[@]}" "$host" >/dev/null 2>&1
        return $?
    fi

    # Hostname / IPv4 literal:
    # 1) try default ping (lets platform decide)
    # 2) if that fails, try forcing IPv6 (AAAA-only, or v6-preferred environments)
    # 3) if that fails, try forcing IPv4 (v6 broken but v4 works)
    ping "${base[@]}" "$host" >/dev/null 2>&1 && return 0
    ping -6 "${base[@]}" "$host" >/dev/null 2>&1 && return 0
    ping -4 "${base[@]}" "$host" >/dev/null 2>&1
}

# TCP port check (IPv4/IPv6/DNS) using Python sockets (prefers python3, falls back to python).
# Returns 0 if port is reachable (TCP connect succeeds), non-zero otherwise.
external_tcp_port_open() {
    local host port timeout
    host="$(normalize_external_host "$1")"
    port="$2"
    timeout="$3"

    local py=""
    if command -v python3 >/dev/null 2>&1; then
        py="python3"
    elif command -v python >/dev/null 2>&1; then
        py="python"
    else
        # Dependency missing; check_required_software should have caught this when ports are enabled.
        return 2
    fi

    "$py" - "$host" "$port" "$timeout" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])

try:
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
except Exception:
    sys.exit(1)

for af, socktype, proto, canonname, sa in infos:
    s = None
    try:
        s = socket.socket(af, socktype, proto)
        s.settimeout(timeout)
        s.connect(sa)
        s.close()
        sys.exit(0)
    except Exception:
        try:
            if s is not None:
                s.close()
        except Exception:
            pass
        continue

sys.exit(1)
PY
}
            
# -------------------------------------------------------------------
# External alerts: "DOWN while Telegram locked" -> deliver once after unlock
# -------------------------------------------------------------------

_sm_external_safe_token() {
    local s="$1"
    s="${s//[^A-Za-z0-9._-]/_}"
    # Limit length to keep filenames reasonable
    echo "${s:0:160}"
}

_sm_external_pending_path() {
    local kind="$1" key="$2"
    local safe hash
    safe="$(_sm_external_safe_token "$key")"
    hash="$(printf '%s' "$key" | cksum | awk '{print $1}')"
    echo "${EXTERNAL_PENDING_DIR}/${kind}.down.${safe}.${hash}"
}

_sm_external_mark_pending_down() {
    local kind="$1" key="$2" f=""
    [[ -z "${EXTERNAL_PENDING_DIR:-}" ]] && return 0
    [[ -z "${SYSTEM_MONITORING_STATE_DIR:-}" || "$SYSTEM_MONITORING_STATE_DIR" == "/" ]] && return 0

    mkdir -p -- "$EXTERNAL_PENDING_DIR" 2>/dev/null || true
    chmod 700 "$EXTERNAL_PENDING_DIR" 2>/dev/null || true

    f="$(_sm_external_pending_path "$kind" "$key")"
    : > "$f" 2>/dev/null || true
}

_sm_external_clear_pending_down() {
    local kind="$1" key="$2" f=""
    [[ -z "${EXTERNAL_PENDING_DIR:-}" ]] && return 0
    f="$(_sm_external_pending_path "$kind" "$key")"
    rm -f -- "$f" 2>/dev/null || true
}

_sm_external_has_pending_down() {
    local kind="$1" key="$2" f=""
    [[ -z "${EXTERNAL_PENDING_DIR:-}" ]] && return 1
    f="$(_sm_external_pending_path "$kind" "$key")"
    [[ -f "$f" ]]
}

# External monitoring loop: stateful UP/DOWN alerts for ping + TCP ports.
# Interval + failure threshold are per-target (optional in spec).
external_monitor_resources() {
    declare -A host_state host_fail
    declare -A port_state port_fail
    declare -A next_due

    local spec name host ports flags interval fails
    local want_ping host_key fc pfc eff_interval eff_fails
    local now due next_due_ts sleep_until sleep_for display

    # Initialize: run all targets immediately
    now=$(LC_ALL=C date +%s)
    for spec in "${EXTERNAL_TARGETS[@]}"; do
        name=""; host=""; ports=""; flags=""; interval=""; fails=""
        if parse_external_target_spec "$spec" name host ports flags interval fails; then
            host_key="${name}${EXTERNAL_KEY_SEP}${host}"
            next_due[$host_key]="$now"
        fi
    done

    while true; do
        _sm_handle_telegram_lock_transition
        now=$(LC_ALL=C date +%s)
        sleep_until=2147483647  # absolute epoch seconds

        for spec in "${EXTERNAL_TARGETS[@]}"; do
            name=""; host=""; ports=""; flags=""; interval=""; fails=""
            if ! parse_external_target_spec "$spec" name host ports flags interval fails; then
                echo "Error: Invalid ping target spec: '$spec'"
                if [[ -n "${EXTERNAL_SPEC_ERROR:-}" ]]; then
                    echo "Reason: ${EXTERNAL_SPEC_ERROR}"
                fi
                exit 1
            fi

            want_ping=1
            [[ "$flags" == *noping* ]] && want_ping=0

            host_key="${name}${EXTERNAL_KEY_SEP}${host}"

            eff_interval="${interval:-$PING_CHECK_INTERVAL}"
            eff_fails="${fails:-$EXTERNAL_FAILURE_THRESHOLD}"

            # Defensive: ensure sane values even if spec parsing is bypassed
            [[ -z "$eff_interval" ]] && eff_interval="$PING_CHECK_INTERVAL"
            (( eff_interval < 1 )) && eff_interval=1
            (( eff_fails < 1 )) && eff_fails=1

            # Determine when this target is due (absolute time)
            due="${next_due[$host_key]:-$now}"

            if (( now < due )); then
                (( due < sleep_until )) && sleep_until=$due
                continue
            fi
            
            # Display label (used in Telegram/logs):
            # - if name == host or name is empty => host
            # - else                             => "name (host)"
            if [[ -z "$name" || "$name" == "$host" ]]; then
                display="$host"
            else
                display="$name ($host)"
            fi

            # -------------------------------
            # Host reachability (ICMP ping)
            # -------------------------------
             if (( want_ping == 1 )); then

                if external_ping_host "$host"; then
                    # Host is reachable now
                    _sm_external_clear_pending_down "host" "$host_key"

                    if [[ "${host_state[$host_key]:-}" == "down" ]]; then
                        echo "EXTERNAL: Host ${display} ONLINE"
                        send_telegram_alert "EXTERNAL" "║ Host: *${display}*\n║ Status: *ONLINE*"
                    fi

                    host_state[$host_key]="up"
                    host_fail[$host_key]=0
                else
                    # Ping failed; count consecutive failures
                    fc=$(( ${host_fail[$host_key]:-0} + 1 ))
                    host_fail[$host_key]="$fc"

                    if (( fc >= eff_fails )); then
                        if [[ "${host_state[$host_key]:-}" != "down" ]]; then
                            echo "EXTERNAL: Host ${display} OFFLINE"

                            # Clear any stale queued marker (e.g., from an old run) before sending.
                            _sm_external_clear_pending_down "host" "$host_key"

                            send_telegram_alert "EXTERNAL" "║ Host: *${display}*\n║ Status: *OFFLINE*"
                            local _tg_rc=$?
                            if (( _tg_rc == 2 )); then
                                # Telegram locked: queue a one-time OFFLINE alert to be delivered after unlock if still down.
                                _sm_external_mark_pending_down "host" "$host_key"
                            fi

                            host_state[$host_key]="down"
                        else
                            # Already DOWN. If the OFFLINE alert was suppressed due to Telegram lock, send it once after unlock.
                            if should_send_message && _sm_external_has_pending_down "host" "$host_key"; then
                                echo "EXTERNAL: Host ${display} OFFLINE (delayed after unlock)"
                                send_telegram_alert "EXTERNAL" "║ Host: *${display}*\n║ Status: *OFFLINE*"
                                _sm_external_clear_pending_down "host" "$host_key"
                            fi
                        fi
                    fi
                fi
            fi

            # -------------------------------
            # TCP ports (optional)
            # -------------------------------
            # If ping is enabled and the host is considered DOWN, skip port checks to avoid spam.
            if [[ -n "$ports" ]]; then
                if ! (( want_ping == 1 )) || [[ "${host_state[$host_key]:-}" != "down" ]]; then
                    local -a ports_arr
                    IFS=',' read -r -a ports_arr <<< "$ports"

                    local p raw pkey
                    for raw in "${ports_arr[@]}"; do
                        p="$(trim_ws "$raw")"
                        [[ -z "$p" ]] && continue

                        if ! [[ "$p" =~ ^[0-9]{1,5}$ ]]; then
                            echo "Warning: invalid port '$p' for ping target *${display}*; skipping." >&2
                            continue
                        fi

                        p=$((10#$p))
                        if (( p < 1 || p > 65535 )); then
                            echo "Warning: invalid port '$p' for ping target *${display}*; skipping." >&2
                            continue
                        fi

                        pkey="${host_key}${EXTERNAL_KEY_SEP}${p}"

                        if external_tcp_port_open "$host" "$p" "${EXTERNAL_TCP_TIMEOUT}"; then
                            # If this port recovers (even while locked), drop any queued DOWN marker.
                            _sm_external_clear_pending_down "port" "$pkey"

                            if [[ "${port_state[$pkey]:-}" == "down" ]]; then
                                echo "EXTERNAL: Host ${display} port ${p}/tcp UP"
                                send_telegram_alert "EXTERNAL" "║ Host: *${display}*\n║ Port: *$p* (tcp)\n║ Status: *UP*"
                            fi

                            port_state[$pkey]="up"
                            port_fail[$pkey]=0
                        else
                            pfc=$(( ${port_fail[$pkey]:-0} + 1 ))
                            port_fail[$pkey]="$pfc"

                            if (( pfc >= eff_fails )); then
                                if [[ "${port_state[$pkey]:-}" != "down" ]]; then
                                    echo "EXTERNAL: Host ${display} port ${p}/tcp DOWN"

                                    # Clear any stale queued marker (e.g., from an old run) before sending.
                                    _sm_external_clear_pending_down "port" "$pkey"

                                    send_telegram_alert "EXTERNAL" "║ Host: *${display}*\n║ Port: *$p* (tcp)\n║ Status: *DOWN*"
                                    local _tg_rc=$?
                                    if (( _tg_rc == 2 )); then
                                        # Telegram locked: queue a one-time DOWN alert to be delivered after unlock if still down.
                                        _sm_external_mark_pending_down "port" "$pkey"
                                    fi

                                    port_state[$pkey]="down"
                                else
                                    # Already DOWN. If the DOWN alert was suppressed due to Telegram lock, send it once after unlock.
                                    if should_send_message && _sm_external_has_pending_down "port" "$pkey"; then
                                        echo "EXTERNAL: Host ${display} port ${p}/tcp DOWN (delayed after unlock)"
                                        send_telegram_alert "EXTERNAL" "║ Host: *${display}*\n║ Port: *$p* (tcp)\n║ Status: *DOWN*"
                                        _sm_external_clear_pending_down "port" "$pkey"
                                    fi
                                fi
                            fi
                        fi
                    done
                fi
            fi

            # Fixed-rate scheduling:
            # - Compute the next due time based on the *previous due* (not "now") to avoid drift.
            # - If we fell behind (checks took too long), jump forward to the next future slot.
            next_due_ts=$(( due + eff_interval ))
            local after_now
            after_now=$(LC_ALL=C date +%s)

            if (( next_due_ts <= after_now )); then
                local behind steps
                behind=$(( after_now - next_due_ts ))
                steps=$(( behind / eff_interval + 1 ))
                next_due_ts=$(( next_due_ts + steps * eff_interval ))
            fi

            next_due[$host_key]="$next_due_ts"
            (( next_due_ts < sleep_until )) && sleep_until=$next_due_ts
        done

        now=$(LC_ALL=C date +%s)

        if (( sleep_until == 2147483647 )); then
            # Shouldn't happen in normal use; keep a sensible fallback.
            sleep_for=$PING_CHECK_INTERVAL
        else
            sleep_for=$(( sleep_until - now ))
        fi

        (( sleep_for < 1 )) && sleep_for=1
        sleep "$sleep_for"
    done
}


# -------------------------------------------------------------------
# Disk Monitoring (local filesystems; multi-target via --DISK-LIST)
# -------------------------------------------------------------------

# Resolve a user-provided mount point path to a canonical mountpoint, and ensure it is an actual mount point (not just any path).
# On success: sets the output var to the canonical mount point (no trailing slash, except '/').
# On failure: sets DISK_SPEC_ERROR and returns non-zero.
resolve_disk_mountpoint() {
    local in="$1"
    local -n _out="$2"

    _out=""
    DISK_SPEC_ERROR=""

    in="$(trim_ws "$in")"
    [[ -z "$in" ]] && in="/"

    # Use df on the target directly, and extract the mountpoint without relying on $NF (breaks on spaces).
    local resolved_mp
    resolved_mp=$(df -P -- "$in" 2>/dev/null | awk 'NR==2 { $1=$2=$3=$4=$5=""; sub(/^[[:space:]]+/, "", $0); sub(/[[:space:]]+$/, "", $0); print }')
#    resolved_mp=$(df -P "$in" 2>/dev/null | awk 'NR==2 { $1=$2=$3=$4=$5=""; sub(/^[[:space:]]+/, "", $0); sub(/[[:space:]]+$/, "", $0); print }')

    if [[ -z "$resolved_mp" ]]; then
        DISK_SPEC_ERROR="Mount point '$in' does not exist."
        return 1
    fi

    # Enforce that the user provided an actual mount point (not just any path on a filesystem).
    # Normalize both sides to avoid false negatives (trailing slashes, symlinks, ./../).
    local target_norm resolved_norm target_phys resolved_phys
    target_norm="$in"
    resolved_norm="$resolved_mp"

    # Strip trailing slashes (but keep '/' intact)
    while [[ "$target_norm" != "/" && "$target_norm" == */ ]]; do target_norm="${target_norm%/}"; done
    while [[ "$resolved_norm" != "/" && "$resolved_norm" == */ ]]; do resolved_norm="${resolved_norm%/}"; done

    # Resolve to physical paths when possible (handles symlinks)
    target_phys="$(cd -P -- "$target_norm" 2>/dev/null && pwd -P)"
    resolved_phys="$(cd -P -- "$resolved_norm" 2>/dev/null && pwd -P)"
    [[ -z "$target_phys" ]] && target_phys="$target_norm"
    [[ -z "$resolved_phys" ]] && resolved_phys="$resolved_norm"

    if [[ "$resolved_phys" != "$target_phys" ]]; then
        DISK_SPEC_ERROR="'$in' is not a mount point (it resolves to '$resolved_mp')."
        return 1
    fi

    _out="$resolved_norm"
    return 0
}

# Parse a disk target spec from --DISK-LIST.
# Accepted formats:
#   - Key/value (recommended): Mount=/|Threshold=90   (keys are case-insensitive; Mount can be Target/Path; Threshold can be Disk)
#   - Whitespace: /mnt/data 85   OR   85 /mnt/data
#   - Single number: 90   (implies mount '/')
# On failure sets DISK_SPEC_ERROR and returns non-zero.
parse_disk_target_spec() {
    local spec="$1"
    local -n _out_mount="$2"
    local -n _out_thresh="$3"

    _out_mount=""
    _out_thresh=""
    DISK_SPEC_ERROR=""

    spec="$(trim_ws "$spec")"
    if [[ -z "$spec" ]]; then
        DISK_SPEC_ERROR="Empty disk target spec"
        return 1
    fi

    # Key/value format if it contains '='
    if [[ "$spec" == *"="* ]]; then
        local -a parts
        IFS='|' read -r -a parts <<< "$spec"

        local token key val key_lc
        local mount_val=""
        local thresh_val=""

        for token in "${parts[@]}"; do
            token="$(trim_ws "$token")"
            [[ -z "$token" ]] && continue

            if [[ "$token" != *"="* ]]; then
                DISK_SPEC_ERROR="Invalid token '$token' (expected Key=Value)"
                return 1
            fi

            key="${token%%=*}"
            val="${token#*=}"
            key="$(trim_ws "$key")"
            val="$(trim_ws "$val")"

            # Strip optional surrounding quotes
            if [[ "$val" == '"'*'"' && ${#val} -ge 2 ]]; then
                val="${val:1:${#val}-2}"
            elif [[ "$val" == "'"*"'" && ${#val} -ge 2 ]]; then
                val="${val:1:${#val}-2}"
            fi

            key_lc="${key,,}"
            case "$key_lc" in
                mount|target|path|mp) mount_val="$val" ;;
                threshold|disk|pct|percent) thresh_val="$val" ;;
                *)
                    DISK_SPEC_ERROR="Unknown key '$key' (allowed: Mount/Target/Path and Threshold/Disk)"
                    return 1
                    ;;
            esac
        done

        _out_mount="$(trim_ws "$mount_val")"
        _out_thresh="$(trim_ws "$thresh_val")"
        [[ -z "$_out_mount" ]] && _out_mount="/"

    else
        # Whitespace format
        local -a arr
        read -r -a arr <<< "$spec"

        if (( ${#arr[@]} == 1 )); then
            if [[ "${arr[0]}" =~ ^[0-9]+$ ]]; then
                _out_thresh="${arr[0]}"
                _out_mount="/"
            else
                DISK_SPEC_ERROR="Invalid disk spec '$spec' (expected '<threshold>' or '<mount> <threshold>')"
                return 1
            fi
        elif (( ${#arr[@]} == 2 )); then
            local a="${arr[0]}"
            local b="${arr[1]}"

            if [[ "$a" =~ ^[0-9]+$ && ! "$b" =~ ^[0-9]+$ ]]; then
                _out_thresh="$a"
                _out_mount="$b"
            elif [[ "$b" =~ ^[0-9]+$ && ! "$a" =~ ^[0-9]+$ ]]; then
                _out_mount="$a"
                _out_thresh="$b"
            else
                DISK_SPEC_ERROR="Invalid disk spec '$spec' (expected one threshold number and one mount point)"
                return 1
            fi
        else
            DISK_SPEC_ERROR="Invalid disk spec '$spec' (too many fields). If mount has spaces, use key/value format: Mount=...|Threshold=..."
            return 1
        fi
    fi

    if [[ -z "$_out_thresh" ]]; then
        DISK_SPEC_ERROR="Missing disk threshold"
        return 1
    fi

    if ! [[ "$_out_thresh" =~ ^[0-9]+$ ]]; then
        DISK_SPEC_ERROR="Threshold must be an integer 0-100; got '$_out_thresh'"
        return 1
    fi

    local t=$((10#${_out_thresh}))
    if (( t < 0 || t > 100 )); then
        DISK_SPEC_ERROR="Threshold out of range (0-100); got '$t'"
        return 1
    fi
    _out_thresh="$t"

    _out_mount="$(trim_ws "${_out_mount:-/}")"
    [[ -z "$_out_mount" ]] && _out_mount="/"

    return 0
}

# Load disk targets from --DISK-LIST (if set) and/or legacy --DISK/--DISK-TARGET into:
#   DISK_MONITORING, DISK_TARGETS[], DISK_THRESHOLDS[]
# Duplicates are auto-deduped by mount point. If a mount point is repeated, the last definition wins (CLI overrides list).
load_disk_targets() {
    DISK_MONITORING=0
    DISK_TARGETS=()
    DISK_THRESHOLDS=()
    DISK_SPEC_ERROR=""

    # Legacy sanity: don't allow 'target only', which would otherwise do nothing.
    if [[ -n "${DISK_TARGET:-}" && -z "${DISK_THRESHOLD:-}" ]]; then
        echo ""
        echo "Error: --DISK-TARGET must be used with --DISK <threshold>."
        echo ""
        echo "Example:"
        echo "  $0 --DISK 90 --DISK-TARGET /mnt/my_disk"
        echo "  $0 --DISK 90"
        echo ""
        exit 1
    fi

    local -a file_specs=()
    if [[ -n "${DISK_LIST_FILE:-}" ]]; then
        if [[ ! -f "$DISK_LIST_FILE" ]]; then
            echo "Error: --DISK-LIST file not found: $DISK_LIST_FILE"
            exit 1
        fi

        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%$'\r'}"
            line="${line%%#*}"
            line="$(trim_ws "$line")"
            [[ -z "$line" ]] && continue
            file_specs+=("$line")
        done < "$DISK_LIST_FILE"
    fi

    # Guard: user explicitly enabled disk list but file is empty AND no legacy --DISK rule exists.
    if [[ -n "${DISK_LIST_FILE:-}" && ${#file_specs[@]} -eq 0 && -z "${DISK_THRESHOLD:-}" ]]; then
        echo "Error: --DISK-LIST '$DISK_LIST_FILE' contains no disk targets."
        echo "Expected one entry per line. Examples:"
        echo "  Mount=/|Threshold=90"
        echo "  /mnt/data 85"
        echo "  80 /var"
        exit 1
    fi

    declare -A threshold_by_mp
    declare -A source_by_mp
    declare -A seen_order
    local -a order=()

    _disk_add_target() {
        local mp_raw="$1"
        local thr="$2"
        local src="$3"

        local mp
        if ! resolve_disk_mountpoint "$mp_raw" mp; then
            echo ""
            echo "Error: Invalid disk mount point: '$mp_raw'"
            [[ -n "${DISK_SPEC_ERROR:-}" ]] && echo "Reason: $DISK_SPEC_ERROR"
            echo ""
            echo "Available mount points are:"
            df -P | awk 'NR>1 { $1=$2=$3=$4=$5=""; sub(/^[[:space:]]+/, "", $0); sub(/[[:space:]]+$/, "", $0); print }'
            echo ""
            exit 1
        fi

        # Keep stable order: first time we see a mount point, append to the ordered list.
        if [[ -z "${seen_order["$mp"]+x}" ]]; then
            order+=("$mp")
            seen_order["$mp"]=1
        else
            # Duplicate -> last wins (warn so the operator knows what happened)
            local prev_thr="${threshold_by_mp["$mp"]}"
            local prev_src="${source_by_mp["$mp"]}"
            if [[ -n "$prev_thr" && ( "$prev_thr" != "$thr" || "$prev_src" != "$src" ) ]]; then
                echo "Warning: Duplicate disk target '$mp' detected. Replacing ${prev_thr}% (${prev_src}) with ${thr}% (${src})." >&2
            fi
        fi

        threshold_by_mp["$mp"]="$thr"
        source_by_mp["$mp"]="$src"
    }

    # 1) DISK-LIST entries (if any)
    if [[ ${#file_specs[@]} -gt 0 ]]; then
        local spec mp_raw thr idx=0
        for spec in "${file_specs[@]}"; do
            idx=$((idx + 1))
            mp_raw=""; thr=""
            if ! parse_disk_target_spec "$spec" mp_raw thr; then
                echo "Error: Invalid disk spec in --DISK-LIST '$DISK_LIST_FILE' (entry ${idx}): '$spec'"
                [[ -n "${DISK_SPEC_ERROR:-}" ]] && echo "Reason: ${DISK_SPEC_ERROR}"
                echo "Examples:"
                echo "  Mount=/|Threshold=90"
                echo "  /mnt/data 85"
                echo "  80 /var"
                exit 1
            fi
            _disk_add_target "$mp_raw" "$thr" "DISK-LIST:${DISK_LIST_FILE}:${idx}"
        done
    fi

    # 2) Legacy CLI --DISK/--DISK-TARGET (if provided). This is applied last, so CLI overrides list entries for the same mount.
    if [[ -n "${DISK_THRESHOLD:-}" ]]; then
        local cli_thr="$DISK_THRESHOLD"
        local cli_mp_raw
        if [[ -n "${DISK_TARGET:-}" ]]; then
            cli_mp_raw="$DISK_TARGET"
            _disk_add_target "$cli_mp_raw" "$cli_thr" "CLI(--DISK --DISK-TARGET)"

            # Canonicalize DISK_TARGET for footer output and backwards-compatible status text.
            local _cli_mp_resolved
            if resolve_disk_mountpoint "$cli_mp_raw" _cli_mp_resolved; then
                DISK_TARGET="$_cli_mp_resolved"
            fi
        else
            cli_mp_raw="/"
            _disk_add_target "$cli_mp_raw" "$cli_thr" "CLI(--DISK)"
            # Keep DISK_TARGET unset (legacy behavior); we still monitor '/'.
        fi
    fi

    # Build final arrays in stable order.
    local mp
    for mp in "${order[@]}"; do
        DISK_TARGETS+=("$mp")
        DISK_THRESHOLDS+=("${threshold_by_mp["$mp"]}")
    done

    if [[ ${#DISK_TARGETS[@]} -gt 0 ]]; then
        DISK_MONITORING=1
    else
        DISK_MONITORING=0
    fi
}







# -------------------------------------------------------------------
# Main Funcions
# -------------------------------------------------------------------
        
# Function to perform fast resource checks
# This function checks CPU usage, RAM usage, and 1-minute and 5-minute Load Averages.
# These metrics are checked more frequently due to their potential impact on server performance.
fast_monitor_resources() {
    # Run CPU sampling in the background so it never blocks other "fast" checks.
    # We also guard against overlapping CPU samplers.
    local cpu_bg_pid=""

    while true; do
        _sm_handle_telegram_lock_transition
        # Reap finished async CPU check (prevents zombie buildup and allows new sampling).
        if [[ -n "$cpu_bg_pid" ]]; then
            # If pid no longer exists -> clear.
            if ! kill -0 "$cpu_bg_pid" 2>/dev/null; then
                wait "$cpu_bg_pid" 2>/dev/null || true
                cpu_bg_pid=""
            else
                # If it exists but is a zombie -> reap and clear.
                if [[ -r "/proc/${cpu_bg_pid}/stat" ]]; then
                    local _st=""
                    _st="$(awk '{print $3}' "/proc/${cpu_bg_pid}/stat" 2>/dev/null || true)"
                    if [[ "$_st" == "Z" ]]; then
                        wait "$cpu_bg_pid" 2>/dev/null || true
                        cpu_bg_pid=""
                    fi
                fi
            fi
        fi

        # Start CPU check asynchronously so it cannot block other fast checks.
        if [[ -n "$CPU_THRESHOLD" ]]; then
            if [[ -z "$cpu_bg_pid" ]]; then
                check_cpu "$CPU_THRESHOLD" &
                cpu_bg_pid=$!
            fi
        fi

        [[ -n "$RAM_THRESHOLD" ]] && check_ram "$RAM_THRESHOLD"
        [[ -n "$LA1_THRESHOLD" ]] && check_la1 "$LA1_THRESHOLD"
        [[ -n "$LA5_THRESHOLD" ]] && check_la5 "$LA5_THRESHOLD"

        # Reset per-tick snapshot lines (prevents stale output if a monitor is disabled)
        SSH_PUBLIC_LINES=""
        SFTP_PUBLIC_LINES=""

        [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]] && check_sftp_activity
        [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 ]] && check_ssh_activity

        # Update the user-facing combined snapshot file
        [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 || "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]] && write_activity_snapshot_file

        # Auth-log "flash" detection for short-lived sessions
        [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 || "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]] && check_ssh_sftp_flash_from_logs

        sleep "$FAST_CHECK_INTERVAL"
    done
}


slow_monitor_resources() {
    while true; do
        _sm_handle_telegram_lock_transition
        if [[ "${DISK_MONITORING:-0}" -eq 1 ]]; then
            local i
            for i in "${!DISK_TARGETS[@]}"; do
                check_disk "${DISK_THRESHOLDS[$i]}" "${DISK_TARGETS[$i]}"
            done
        fi
        if [[ -n "$TEMP_THRESHOLD" && "${TEMP_MONITORING_DISABLED:-0}" -ne 1 ]]; then
            check_temp "$TEMP_THRESHOLD"
        fi
        [[ -n "$LA15_THRESHOLD" ]] && check_la15 "$LA15_THRESHOLD"
        [[ "${REBOOT_MONITORING:-0}" -eq 1 ]] && check_reboot
        # Sleep for the interval defined by SLOW_CHECK_INTERVAL
        sleep "$SLOW_CHECK_INTERVAL"
    done
}


# `parse_arguments` processes command-line arguments, enabling custom thresholds for system metrics.
# It assigns thresholds for CPU, RAM, Disk, and Temperature. Load Averages default to core-count ratios
# if unspecified, ensuring automatic, hardware-appropriate limits.
parse_arguments() {
    # Loop through all command-line arguments
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --NAME)
                # Check if a server name is provided after --NAME
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --NAME must be followed by a server name."
                    exit 1
                fi
                HOST_NAME="$2"
                shift 2  # Move past the argument and its value
                ;;
            --GROUP-ID)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --GROUP-ID must be followed by a Telegram chat/group id."
                    exit 1
                fi
                CLI_GROUP_ID="$2"
                shift 2
                ;;
            --BOT-TOKEN)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --BOT-TOKEN must be followed by a Telegram bot token."
                    exit 1
                fi
                CLI_BOT_TOKEN="$2"
                shift 2
                ;;
            --CPU|--RAM|--DISK|--TEMP)
                local default_value
                case "$1" in
                    --CPU)  default_value=86 ;;
                    --RAM)  default_value=86 ;;
                    --DISK) default_value=90 ;;
                    --TEMP) default_value=65 ;;
                esac

                local value
                local shift_by=1

                # If the next token is missing or looks like another flag, treat it as "no value".
                if [[ -z "${2:-}" || "${2:-}" == --* ]]; then
                    value="$default_value"
                else
                    # Otherwise, validate the provided value.
                    if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                        echo "Error: $1 threshold must be an integer (got: '$2')."
                        exit 1
                    fi

                    # Normalize as base-10 to avoid octal weirdness (e.g. 08)
                    value=$((10#$2))
                    shift_by=2
                fi

                # Basic sanity checks
                case "$1" in
                    --CPU|--RAM|--DISK)
                        if (( value < 0 || value > 100 )); then
                            echo "Error: $1 threshold must be between 0 and 100 (got: $value)."
                            exit 1
                        fi
                        ;;
                    --TEMP)
                        if (( value < 0 || value > 150 )); then
                            echo "Error: --TEMP threshold must be between 0 and 150°C (got: $value)."
                            exit 1
                        fi
                        ;;
                esac

                declare -n threshold_var="${1#--}_THRESHOLD"
                threshold_var="$value"
                shift "$shift_by"
                ;;
            --DISK-TARGET)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --DISK-TARGET must be followed by a mount point."
                    exit 1
                fi
                DISK_TARGET="$2"
                shift 2
                ;;
            --DISK-LIST)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --DISK-LIST must be followed by a file path."
                    exit 1
                fi
                DISK_LIST_FILE="$2"
                shift 2
                ;;
            --LA1|--LA5|--LA15)
                declare -n threshold_var="${1#--}_THRESHOLD"

                # If the next token is missing or is another option, treat as "use default"
                if [[ -z "${2:-}" || "$2" == --* ]]; then
                    threshold_var="default"
                    shift
                # If a value is provided, it must be numeric
                elif [[ "$2" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                    threshold_var="$2"
                    shift 2
                else
                    echo "Error: $1 must be followed by a numeric threshold (got: '$2')."
                    exit 1
                fi
                ;;
            --SSH|--SSH-LOGIN)
                SSH_LOGIN_MONITORING=1
                shift
                ;;
            --SFTP|--SFTP-MONITOR)
                SFTP_LOGIN_MONITORING=1
                shift
                ;;
            --REBOOT)
                REBOOT_MONITORING=1
                shift
                ;;
            --PING)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --PING must be followed by a target spec."
                    echo "Expected (recommended): Name=<name>|Host=<host>|Ping=true|Port=22,80,443|Interval=11|MaxFails=3"
                    exit 1
                fi
                EXTERNAL_TARGETS_CLI+=("$2")
                EXTERNAL_MONITORING=1
                shift 2
                ;;
            --PING-LIST)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --PING-LIST must be followed by a file path."
                    exit 1
                fi
                PING_LIST_FILE="$2"
                EXTERNAL_MONITORING=1
                shift 2
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                echo "Unknown parameter passed: $1"
                exit 1
                ;;
        esac
    done
}


# The `validate_thresholds` function verifies that at least one monitoring threshold
# or feature is set. It displays the configured settings, applying default values for
# Load Averages if unspecified. If no monitoring conditions are active, it prompts
# the user with a help message and exits to prevent purposeless execution.
validate_thresholds() {
    local enabled=0

    echo ""
    echo "System Monitoring is now running with the following settings:"
    echo ""
    echo "System Monitoring:"

    # Threshold-based monitors
    if [[ -n "$CPU_THRESHOLD" ]]; then
        echo "CPU Threshold: $CPU_THRESHOLD%"
        enabled=1
    fi
    if [[ -n "$RAM_THRESHOLD" ]]; then
        echo "RAM Threshold: $RAM_THRESHOLD%"
        enabled=1
    fi
    
    if [[ -n "$TEMP_THRESHOLD" ]]; then
        echo "CPU Temperature Threshold: $TEMP_THRESHOLD°C"
        enabled=1
    fi

    # Disk monitors (legacy --DISK/--DISK-TARGET OR multi-target --DISK-LIST)
    if [[ "${DISK_MONITORING:-0}" -eq 1 ]]; then
        enabled=1

        # Backwards-compatible single-target output (when configured via --DISK, optionally with --DISK-TARGET)
        if [[ -z "${DISK_LIST_FILE:-}" && ${#DISK_TARGETS[@]} -eq 1 && -n "${DISK_THRESHOLD:-}" ]]; then
            echo "Disk Usage Threshold: ${DISK_THRESHOLDS[0]}%"
            if [[ -n "${DISK_TARGET:-}" ]]; then
                echo "Disk Target Mount Point: ${DISK_TARGETS[0]}"
            fi
        else
            echo "Disk Monitoring Targets:"
            if [[ -n "${DISK_LIST_FILE:-}" ]]; then
                echo "Disk List File: ${DISK_LIST_FILE}"
            fi
            local di
            for di in "${!DISK_TARGETS[@]}"; do
                echo "  [$((di + 1))] ${DISK_TARGETS[$di]} | threshold: ${DISK_THRESHOLDS[$di]}%"
            done
        fi
    fi

    # Feature monitors
    if [[ "${SSH_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        echo "SSH Login Monitoring: Enabled"
        enabled=1
    fi
    if [[ "${SFTP_LOGIN_MONITORING:-0}" -eq 1 ]]; then
        echo "SFTP Login Monitoring: Enabled"
        enabled=1
    fi
    if [[ "${REBOOT_MONITORING:-0}" -eq 1 ]]; then
        echo "Reboot Monitoring: Enabled"
        enabled=1
        check_reboot  # initial check at startup
    fi

    # Load Average monitors (only enabled if user passed --LA1/--LA5/--LA15)
    if [[ -n "$LA1_THRESHOLD" ]]; then
        enabled=1
        if [[ "$LA1_THRESHOLD" == "default" ]]; then
            LA1_THRESHOLD=$(nproc)
            echo "1-minute Load Average Threshold: Using default auto-threshold of $LA1_THRESHOLD (equal to the number of CPU cores)."
        else
            echo "1-minute Load Average Threshold: $LA1_THRESHOLD"
        fi
    fi

    if [[ -n "$LA5_THRESHOLD" ]]; then
        enabled=1
        if [[ "$LA5_THRESHOLD" == "default" ]]; then
            LA5_THRESHOLD=$(echo "$(nproc) * 0.75" | bc)
            echo "5-minute Load Average Threshold: Using default auto-threshold of $LA5_THRESHOLD (75% of CPU cores)."
        else
            echo "5-minute Load Average Threshold: $LA5_THRESHOLD"
        fi
    fi

    if [[ -n "$LA15_THRESHOLD" ]]; then
        enabled=1
        if [[ "$LA15_THRESHOLD" == "default" ]]; then
            LA15_THRESHOLD=$(echo "$(nproc) * 0.5" | bc)
            echo "15-minute Load Average Threshold: Using default auto-threshold of $LA15_THRESHOLD (50% of CPU cores)."
        else
            echo "15-minute Load Average Threshold: $LA15_THRESHOLD"
        fi
    fi

    echo ""
    echo "Ping Monitoring:"
    if [[ "${EXTERNAL_MONITORING:-0}" -eq 1 ]]; then
        if [[ ${#EXTERNAL_TARGETS[@]} -eq 0 ]]; then
            echo "Error: Ping monitoring is enabled, but no targets are configured."
            echo "Use --PING and/or --PING-LIST."
            exit 1
        fi

        enabled=1
        echo "Default Ping Interval: ${PING_CHECK_INTERVAL}s (per target, unless overridden in spec)"
        echo "Default Failure Threshold: ${EXTERNAL_FAILURE_THRESHOLD} consecutive failures (per target, unless overridden in spec)"
        echo "Targets:"

        local i spec name host ports flags interval fails ping_mode ports_disp eff_interval eff_fails
        i=1
        for spec in "${EXTERNAL_TARGETS[@]}"; do
            name=""; host=""; ports=""; flags=""; interval=""; fails=""
            if ! parse_external_target_spec "$spec" name host ports flags interval fails; then
                echo "Error: Invalid ping target spec: '$spec'"
                if [[ -n "${EXTERNAL_SPEC_ERROR:-}" ]]; then
                    echo "Reason: ${EXTERNAL_SPEC_ERROR}"
                fi
                exit 1
            fi

            ping_mode="Enabled"
            [[ "$flags" == *noping* ]] && ping_mode="Disabled"
            ports_disp="${ports:-none}"

            eff_interval="${interval:-$PING_CHECK_INTERVAL}"
            eff_fails="${fails:-$EXTERNAL_FAILURE_THRESHOLD}"

            echo "  [$i] $name | host: $host | ping: $ping_mode | tcp ports: $ports_disp | interval: ${eff_interval}s | fails: ${eff_fails}"
            i=$((i + 1))
        done
    else
        echo "Disabled"
    fi

    echo ""
    echo "Notifications:"
    if should_send_message; then
        echo "Telegram Alerts: Enabled"
    else
        echo "Telegram Alerts: Disabled (lock file '$TELEGRAMM_LOCK_STATE' contains '1')"
        echo "To re-enable: delete '$TELEGRAMM_LOCK_STATE' or set its content to '0'."
    fi

    # If nothing is enabled, exit
    if [[ $enabled -eq 0 ]]; then
        echo "Error: Nothing to monitor (no thresholds or features enabled)."
        exit 1
    fi
}
#                                                                                                                            #
# -------------------------------------------------------------------------------------------------------------------------- #


        
        
        
        
        
        
        
        
# -------------------------------------------------------------------------------------------------------------------------- #
#                                                                                                                            #
#         Main Logic                                                                                                         #
#                                                                                                                            #
#                                                                                                                            #
# If no arguments are passed, print the help message and exit
if [ "$#" -eq 0 ]; then
    print_help
    exit 0
fi

# ------------------------------------------------------------------
# Control actions (must be used alone):
#   --STATUS : show whether monitor is running + PIDs
#   --KILL   : stop the running monitor cleanly (SIGTERM -> SIGKILL)
#   --RELOAD : reload dynamic config in the running monitor (SIGHUP)
# ------------------------------------------------------------------
if [[ "$#" -eq 1 && ( "$1" == "--STATUS" || "$1" == "--KILL" || "$1" == "--RELOAD" ) ]]; then
    # Bypass the single-instance lock for control actions.
    SYSTEM_MONITORING_NOLOCK=1

    SYSTEM_MONITORING_PHASE="require-root(control)"
    require_root

    case "$1" in
        --STATUS)
            _sm_control_status
            exit $?
            ;;
        --KILL)
            _sm_control_kill
            exit $?
            ;;
        --RELOAD)
            _sm_control_reload
            exit $?
            ;;
    esac
fi

# If someone tried to combine a control flag with regular flags, fail fast.
for _a in "$@"; do
    if [[ "$_a" == "--STATUS" || "$_a" == "--KILL" || "$_a" == "--RELOAD" ]]; then
        echo "Error: $_a must be used alone (no other flags)."
        exit 1
    fi
done

# Call the parse_arguments function to process command-line arguments
# (this will also handle -h/--help and exit cleanly without side effects)
SYSTEM_MONITORING_PHASE="parse-arguments"
parse_arguments "$@"

SYSTEM_MONITORING_PHASE="require-root"
require_root

# Early EXIT trap: ensure the main pidfile is removed if startup fails before the later trap block is reached.
# (Keep this below the --STATUS/--KILL/--RELOAD control-action block to avoid side effects.)
trap 'cleanup $?' EXIT

# Write the main PID file AFTER we acquired the single-instance lock.
SYSTEM_MONITORING_PHASE="pidfile"
if ! _sm_write_main_pid_file; then
    echo "Warning: cannot write pid file: ${SYSTEM_MONITORING_MAIN_PID_FILE}" >&2
fi

# Load secrets only after we know we're actually going to run monitoring
SYSTEM_MONITORING_PHASE="load-secrets"
load_secrets

# API endpoint (now BOT_TOKEN is guaranteed to be set)
__xtrace_was_on=
[[ $- == *x* ]] && __xtrace_was_on=1 && set +x

TELEGRAM_API="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"

[[ -n "${__xtrace_was_on:-}" ]] && set -x
unset __xtrace_was_on

# Traps:
# - INT/TERM/EXIT keep the existing cleanup behavior
# - HUP/CONT request a live reload (handled by the supervisor)
trap '_sm_request_reload' HUP
trap '_sm_request_reload' CONT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
trap 'cleanup $?'  EXIT

# Load external monitoring targets (CLI + optional config file) before dependency checks
SYSTEM_MONITORING_PHASE="load-external-targets"
load_external_targets

# Dependency checks (after secrets load so we can notify failures via Telegram)
SYSTEM_MONITORING_PHASE="dependency-check"
check_required_software

# Load disk monitoring targets (CLI + optional --DISK-LIST) after deps are available
SYSTEM_MONITORING_PHASE="load-disk-targets"
load_disk_targets

# Validate that at least one threshold or monitoring feature is set
SYSTEM_MONITORING_PHASE="validate-configuration"
validate_thresholds

SYSTEM_MONITORING_PHASE="running"

# Start the monitoring loops
_sm_start_monitoring_loops

# Supervisor loop (handles reload + prevents script from exiting)
_sm_supervise
#                                                                                                                            #
# -------------------------------------------------------------------------------------------------------------------------- #
