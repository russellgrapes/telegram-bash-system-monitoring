#!/bin/bash

#  _________   _________   _________
# |         | |         | |         |
# |   six   | |    2    | |   one   |
# |_________| |_________| |_________|
#     |||         |||         |||
# -----------------------------------
#    system-monitoring.sh v.3.75
# -----------------------------------

# The system-monitoring.sh script is a dedicated monitoring solution for Unix-like systems that sends alerts to Telegram.
# It monitors CPU, RAM, Disk usage, CPU temperature, and Load Averages across different intervals. Designed to be initiated
# at system startup, it ensures that resource usage is under constant surveillance without the need for scheduled cron jobs.

# To have the script automatically start monitoring when the server boots, add the following line to your crontab:
# @reboot /path/to/system-monitoring.sh --NAME MyServer --CPU 80 --RAM 70 --DISK 90 --LA1 --LA5 --LA15 --SSH-LOGIN

# For icons in Telegram: ☮⚠ https://www.w3schools.com/charsets/ref_utf_symbols.asp

# Author: https://github.com/russellgrapes/









# Telegram Settings

# GROUP_ID should be set to the Telegram group ID where alerts will be sent.
# BOT_TOKEN is the token for the Telegram bot that will send the messages.
GROUP_ID="your_telegram_group_id"  # Replace with your actual Telegram group ID
BOT_TOKEN="your_bot_token"         # Replace with your actual Telegram bot token

# TELEGRAM_API constructs the URL endpoint for sending messages via the Telegram bot API.
TELEGRAM_API="https://api.telegram.org/bot$BOT_TOKEN/sendMessage" # Normally, there's no need to change it.

# TELEGRAMM_LOCK_STATE is the file that controls the sending of alerts.
# A content of '1' in the LOCK file prevents alerts, enabling manual control during maintenance.
TELEGRAMM_LOCK_STATE="/root/telegram_lockfile.state"









# Script Settings

# Default host name if not provided with --NAME key
HOST_NAME="My Host"

# Configuration variables for check intervals
# Frequent checks ensure prompt notifications of for urgent resource checks like CPU, RAM, LA1, etc
FAST_CHECK_INTERVAL=60  # 1 minute in seconds
# This longer interval prevents frequent alerts for persistent conditions like Disk Usage, CPU Temperature, etc
SLOW_CHECK_INTERVAL=1800  # 30 minutes in seconds, for less urgent resource checks

# SSH_ACTIVITY_LOGINS specifies the file path used to keep a record of SSH session logins.
# When the --SSH-LOGIN option is used, the script uses this file to track new SSH logins by
# comparing the currently active sessions against the previously recorded state. It then updates
# the file with the latest login information, providing a log for continuous session monitoring.
SSH_ACTIVITY_LOGINS="/root/ssh_activity_logins.txt"

# SFTP_ACTIVITY_LOGINS specifies the file path used to keep a record of SFTP session details.
SFTP_ACTIVITY_LOGINS="/root/sftp_activity_logins.txt"

# LAST_BOOT_TIME_FILE specifies the file path used to record the last boot time of the server.
# This file is utilized by the --REBOOT option to determine if the server has rebooted since
# the last recorded timestamp. The script writes the current boot time to this file during each
# execution and compares it on subsequent runs to detect a reboot occurrence.
LAST_BOOT_TIME_FILE="/root/last_boot_time.txt"

# SSH_ACTIVITY_EXCLUDED_IPS is an array that holds IP addresses or CIDR ranges that should be
# ignored by the --SSH-LOGIN monitoring feature. When specifying this key, the script will not
# send alerts for SSH logins originating from these IPs. Examples of valid entries include:
# - "192.168.1.1" or "192.168.2.4/32" for individual IP addresses,
# - "192.168.1.0/24" for all IPs in the range 192.168.1.0 to 192.168.1.255,
# - "10.10.0.0/16" for all IPs in the range 10.10.0.0 to 10.10.255.255.
# SSH_ACTIVITY_EXCLUDED_IPS=("10.10.0.0/16" "192.168.1.1" "192.168.2.4/32")
SSH_ACTIVITY_EXCLUDED_IPS=()









# Main Code

# Prints usage instructions
print_help() {
    echo ""
    echo "Usage: $0 [options]"
    echo "Monitors system resources and sends alerts via Telegram if specified thresholds are exceeded."
    echo ""
    echo "Options:"
    echo "  --NAME host_name            Specifies a custom identifier for the host being monitored."
    echo "  --CPU CPU_%                 Sets the CPU usage percentage threshold for generating an alert."
    echo "  --RAM RAM_%                 Sets the RAM usage percentage threshold for generating an alert."
    echo "  --DISK DISK_%               Sets the disk usage percentage threshold for generating an alert."
    echo "  --TEMP TEMP_°C              Sets the CPU temperature threshold for generating an alert (in Celsius)."
    echo "  --LA1 [threshold]           Sets a custom or auto-threshold (equal to CPU cores) for the 1-minute Load Average."
    echo "  --LA5 [threshold]           Sets a custom or 75% CPU cores auto-threshold for the 5-minute Load Average."
    echo "  --LA15 [threshold]          Sets a custom or 50% CPU cores auto-threshold for the 15-minute Load Average."
    echo "  --SSH-LOGIN                 Activates monitoring of SSH logins and sends alerts for logins from non-excluded IPs."
    echo "  --SFTP-MONITOR              Activates monitoring of SFTP sessions and sends alerts for new sessions from non-excluded IPs."
    echo "  --REBOOT                    Sends an alert if the server has been rebooted since the last script execution."
    echo "  -h, --help                  Displays this help message."
    echo ""
    echo "Files:"
    echo "  \$SSH_ACTIVITY_LOGINS       Specifies the path to the file storing current SSH login sessions for monitoring."
    echo "  \$SFTP_ACTIVITY_LOGINS      Specifies the path to the file storing current SFTP session details for monitoring."
    echo "  \$TELEGRAMM_LOCK_STATE      Specifies the path to the file that controls the lock state for Telegram notifications."
    echo "  \$LAST_BOOT_TIME_FILE       Specifies the path to the file that stores the last recorded boot time."
    echo ""
    echo "Variables:"
    echo "  \$GROUP_ID                  Specifies the Telegram group ID for sending alerts."
    echo "  \$BOT_TOKEN                 Specifies the Telegram bot token for authentication."
    echo "  \$FAST_CHECK_INTERVAL       Defines the interval in seconds for urgent resource checks (CPU, RAM, and Load Averages)."
    echo "  \$SLOW_CHECK_INTERVAL       Defines the interval in seconds for less urgent resource checks (Disk Usage, CPU Temperature)."
    echo "  \$SSH_ACTIVITY_EXCLUDED_IPS Lists the array of IP addresses excluded from SSH & SFTP alerts."
    echo ""
    echo "Telegram messages are sent based on the lock state defined by the \$TELEGRAMM_LOCK_STATE variable."
    echo "If the file's content is '1', messages will not be sent."
    echo ""
    echo "The --LA1, --LA5, and --LA15 options enable setting custom Load Average thresholds."
    echo "If no thresholds are specified, the script applies default values based on the CPU core count:"
    echo "  --LA1 defaults to the number of CPU cores."
    echo "  --LA5 defaults to 75% of the CPU core count."
    echo "  --LA15 defaults to 50% of the CPU core count."
    echo "The --REBOOT option will alert on server reboots, using the last recorded boot time for comparison."
    echo ""
    echo "Monitoring intervals can be customized by modifying the \$RESOURCE_CHECK_INTERVAL"
    echo "and \$SSH_CHECK_INTERVAL variables within the script."
    echo ""
    echo "SFTP, SSH login monitoring is governed by the \$SSH_ACTIVITY_EXCLUDED_IPS variable,"
    echo "which defines specific IPs that are exempt from login alerts."
    echo ""
    echo "Examples:"
    echo "  $0 --NAME MyServer --CPU 80 --RAM 70 --DISK 90 --LA1 2 --LA15 --SSH-LOGIN --REBOOT"
    echo "  $0 --NAME MyServer --TEMP 66 --LA15 --SSH-LOGIN --REBOOT"
    echo ""
}









# Telegram functions

# Function to check if messages should be sent based on lock state
should_send_message() {
    # Check if the lock file exists and is not empty
    if [[ ! -f "${TELEGRAMM_LOCK_STATE}" ]] || [[ ! -s "${TELEGRAMM_LOCK_STATE}" ]]; then
        # Lock file doesn't exist or is empty, send message
        return 0
    fi

    # Lock file exists and has content, read the state
    local state=$(cat "${TELEGRAMM_LOCK_STATE}")
    # If state is "1", do not send the message
    [[ "$state" != "1" ]]
}

# The `send_telegram_alert` function formats and sends alert messages to Telegram. It gathers
# current system metrics such as Load Averages, CPU, RAM, and Disk usage, formatting them according
# to the alert type. If the messaging lock is not engaged, it sends the alert with a timestamp
# and hostname to the specified Telegram group.
send_telegram_alert() {
    local alert_type=$1
    local message=$2
    local server_ip=$(get_server_ip)
    local time_stamp=$(LC_ALL=C date "+%H:%M:%S | %b %d")

    # Gather system metrics
    local load1 load5 load15
    read load1 load5 load15 _ <<< $(awk '{print $1, $2, $3}' /proc/loadavg)
    local ram_usage=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')
    local disk_usage=$(df -h | awk '$NF=="/"{printf "%s", $5}')
    local num_cores=$(nproc)
    local cpu_usage=$(awk -v cores="$num_cores" -v load0="$load1" 'BEGIN { printf "%.0f", (load0 * 100) / cores }')
    local uptime_info=$(uptime -p | sed 's/^up //')  # Human-readable uptime information

    # Check if the message should be sent
    if should_send_message; then
        # Format the message based on the type of alert
        local formatted_message
        case $alert_type in
            CPU|RAM|DISK|TEMP)
                formatted_message="*${alert_type}* usage is high: *$message%*\n\nLA1: $load1 | LA5: $load5 | LA15: $load15\n\nCPU: $cpu_usage | RAM: $ram_usage | DISK: $disk_usage"
                ;;
            LA1|LA5|LA15)
                # For Load Average alerts, message is already prepared
                formatted_message="*$message*\nLA1: $load1 | LA5: $load5 | LA15: $load15\n\nCPU: $cpu_usage | RAM: $ram_usage | DISK: $disk_usage"
                ;;
            SSH-LOGIN)
                # For SSH-LOGIN, the message is already formatted
                formatted_message="$message"
                ;;
           SFTP-MONITOR)
                # For SFTP-MONITOR, the message is already formatted
                formatted_message="$message"
                ;;
            REBOOT)
                # For REBOOT, the message is already formatted
                formatted_message="$message"
                ;;
            *)
                echo "Unknown alert type: $alert_type"
                return 1
                ;;
        esac

        # Send the formatted message
        local curl_data=(
            --data parse_mode=Markdown
            --data "text=$(echo -e "\n⚠  *$HOST_NAME* | $time_stamp  ⚠\n----------------------------------------\n$formatted_message\n----------------------------------------\nServer IP: $server_ip\nUptime: $uptime_info")"
            --data "chat_id=$GROUP_ID"
        )

        curl -s "${curl_data[@]}" "$TELEGRAM_API" > /dev/null
    else
        echo "Message sending is locked. No alert sent for $alert_type."
    fi
}









# Functions for helping

# Function to check if an IP is within the specified CIDR ranges or is an exact IP match.
# It supports CIDR notation and exact IPs in the SSH_ACTIVITY_EXCLUDED_IPS array.
# The function uses bitwise operations to convert IP addresses to their numeric equivalent
# for an easier range comparison and leverages `ipcalc` for CIDR calculations.
# Tested with ipcalc -v 0.5

# Usage within the script:
# Call this function with an IP address to check against the SSH_ACTIVITY_EXCLUDED_IPS array.
# It will return "true" if the IP is in the range, "false" otherwise.
check_ip_in_range() {
    # The IP address to check
    local ip_to_check=$1
    # Flag to indicate if a match was found
    local match_found="false"

    # Converts an IP address to its numeric equivalent using bitwise operations.
    ip_to_long() {
        local ip=$1
        local a b c d
        # Read the four octets of the IP address
        IFS='.' read -r a b c d <<< "$ip"
        # Convert the octets to a numeric value
        echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
    }

    # Convert the IP to check into its numeric format
    local ip_long=$(ip_to_long $ip_to_check)

    # Loop through each range in the exclusion array
    for range in "${SSH_ACTIVITY_EXCLUDED_IPS[@]}"; do
        # Handle exact IP addresses or /32 CIDR
        if [[ $range == *"/32" ]] || [[ $range == *.*.*.* && ! $range == *"/"* ]]; then
            local range_ip=${range%/*}  # Remove CIDR notation if present
            local range_long=$(ip_to_long $range_ip)
            # Direct comparison for single IP addresses
            if [[ $ip_long -eq $range_long ]]; then
                match_found="true"
                break
            fi
        else
            # Handle CIDR ranges
            # Calculate the min and max of the CIDR range using ipcalc
            local host_min=$(ipcalc -nb $range | grep 'HostMin' | awk '{print $2}')
            local host_max=$(ipcalc -nb $range | grep 'HostMax' | awk '{print $2}')
            local min_long=$(ip_to_long $host_min)
            local max_long=$(ip_to_long $host_max)
            # Check if the IP falls within the min and max of the range
            if [[ $ip_long -ge $min_long && $ip_long -le $max_long ]]; then
                match_found="true"
                break
            fi
        fi
    done

    # Output true if the IP is within the range, false otherwise
    echo "$match_found"
}


# Function to check for necessary software on the system
check_required_software() {
    local missing_counter=0
    local install_cmd=""

    # Detect package manager
    if command -v apt &> /dev/null; then
        install_cmd="sudo apt install"
    elif command -v yum &> /dev/null; then
        install_cmd="sudo yum install"
    elif command -v dnf &> /dev/null; then
        install_cmd="sudo dnf install"
    else
        echo "Error: No recognized package manager found (apt, yum, dnf)."
        exit 1
    fi

    # List of required commands and their corresponding packages
    declare -A required_commands=(
        ["bc"]="bc"
        ["awk"]="gawk"
        ["curl"]="curl"
        ["free"]="procps"
        ["df"]="coreutils"
        ["uptime"]="procps"
        ["nproc"]="coreutils"
        ["who"]="coreutils"
        ["ipcalc"]="ipcalc"
	["ss"]="iproute2"
    )

    echo "Checking for required software..."

    for cmd in "${!required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo ""
            echo "Error: Required command '$cmd' is not installed."
            echo "To install '$cmd', run: $install_cmd ${required_commands[$cmd]}"
            ((missing_counter++))
        fi
    done

    if [[ missing_counter -ne 0 ]]; then
        echo ""
        echo "Error: $missing_counter required commands are missing."
        echo "Install the missing commands before running this script."
        exit 1
    else
        echo "All required software is installed."
    fi
}

# Function to get the primary IP address of the server
get_server_ip() {
    # This will get the IP address of the server's default route interface
    ip route get 1.2.3.4 | awk '{print $7; exit}'
}












# Monitoring functions

# Function to check for new SSH logins
# This function monitors for new SSH logins by comparing the current sessions against a saved list.
# It checks each session's username, IP, date, and time. If a session is not in the saved list
# and the IP isn't excluded, it sends a Telegram alert with the login details.
# The function updates the saved list after each check.
check_ssh_activity() {
    # Fetch the current SSH sessions
    local current_logins=$(LC_ALL=C who -u | awk '{print $1, $8, $3, $4, $5, $7}') # Extract username, IP, date, time and pid
    local last_logins=$(cat "$SSH_ACTIVITY_LOGINS" 2>/dev/null)

    # Update the saved state with the current SSH sessions
    echo "$current_logins" > "$SSH_ACTIVITY_LOGINS"

    # Loop through the current logins to identify new sessions
    while IFS= read -r current_login; do
        # If the current session is not in the last recorded state, it's new
        if ! grep -Fq "$current_login" <<< "$last_logins"; then
            local user=$(echo "$current_login" | awk '{print $1}')
            local ip=$(echo "$current_login" | awk '{print $2}' | tr -d '()')
            local login_time=$(echo "$current_login" | awk '{print $3, $4, $5}')
            local formatted_time=$(LC_ALL=C date -d "$login_time" +"%H:%M" 2>/dev/null)

            # Check if the IP is within any of the excluded CIDR ranges or exact matches
            if [[ $(check_ip_in_range "$ip") == "false" ]]; then
                # Prepare and send the alert message
                local message="New SSH login: User *[ $user ]* from IP *$ip* at $formatted_time."
                echo "$message"  # Echo the message to the terminal for logging
                send_telegram_alert "SSH-LOGIN" "$message"
            else
                echo "New SSH login: User *[ $user ]* from IP *$ip*. IP excluded, no alerts send."
            fi
        fi
    done <<< "$current_logins"
}


# Function to check for new SFTP sessions
# This function monitors active SFTP sessions by comparing the current sessions against a previously saved list.
# It extracts each session's PID, start time, and associated network connections.
# If a session is not in the saved list and the source IP isn't excluded based on predefined criteria,
# it sends a Telegram alert with detailed connection information.
# After checking, the function updates the saved list with current session details to log new sessions for future comparisons.
# The goal is to monitor and alert on unauthorized or unexpected SFTP activity from non-excluded IP ranges.
check_sftp_activity() {
    # Fetch all PIDs for sftp-server processes along with their start times, parent PIDs, and full command
    local current_sessions=$(LC_ALL=C ps -eo pid,ppid,lstart,cmd | grep [s]ftp-server | awk '{print $1, $2, $3, $4, $5, $6}')

    # Read the last recorded session details from the log file and remove any leading/trailing whitespace
    local last_sessions=$(cat "$SFTP_ACTIVITY_LOGINS" 2>/dev/null | sed 's/^[ \t]*//;s/[ \t]*$//')

    # Loop through each current session to check if it's new
    while IFS= read -r current_session; do
        # Trim spaces from current session string for accurate comparison
        local trimmed_session=$(echo "$current_session" | sed 's/^[ \t]*//;s/[ \t]*$//')

        # Check if this session is already recorded to avoid duplicates
        if ! grep -Fq "$trimmed_session" <<< "$last_sessions"; then
            local pid=$(echo "$trimmed_session" | awk '{print $1}')    # Extract the PID
            local ppid=$(echo "$trimmed_session" | awk '{print $2}')   # Extract the Parent PID
	    local raw_date=$(echo "$current_session" | awk '{print $3, $4, $5, $6}') # Extract the full date string as it appears
            local stime=$(LC_ALL=C date -d "$raw_date" +"%Y-%m-%d %H:%M")  # Format the start time correctly based on extracted raw date
            local htime=$(LC_ALL=C date -d "$raw_date" +"%H:%M")  # Format the start time correctly based on extracted raw date

            # Use 'ss' to fetch network connections associated with the PID or its parent
            local connection_details=$(ss -tnp | grep -E "pid=$pid|pid=$ppid" | awk '{split($4, a, ":"); split($5, b, ":"); if (length(a[1]) > 0 && length(b[1]) > 0) print a[1], "<->", b[1]}')

            # Parse source IP from connection details
            local src_ip=$(echo "$connection_details" | awk '{print $3}')

            # Check if the IP is within any of the excluded ranges
            if [[ $(check_ip_in_range "$src_ip") == "false" ]]; then
                # Check if there are valid network details to report
                if [ -n "$connection_details" ]; then
		    local message="New SFTP session: From IP *${src_ip}* at ${htime}"

                    echo "$message"  # Output the message to terminal for logging
                    send_telegram_alert "SFTP-MONITOR" "$message"  # Send the alert message through Telegram
                    echo "$trimmed_session $stime ${connection_details}" >> "$SFTP_ACTIVITY_LOGINS"
                fi
            else
                echo "New SFTP session from *$src_ip*. IP excluded, no alerts send."
            fi
        fi
    done <<< "$current_sessions"
}


# Function to check CPU usage
check_cpu() {
    local cpu_threshold=$1
    local loadavg=$(awk '{print $1}' /proc/loadavg)  # Get the 1-minute Load Average
    local cores=$(nproc)  # Get the number of processor cores
    local cpu_usage=$(awk -v cores="$cores" -v load0="$loadavg" 'BEGIN { printf "%.0f", (load0 * 100) / cores }')  # Calculate the CPU usage

#    echo "Load Average: $loadavg, Cores: $cores, Calculated CPU Usage: $cpu_usage%"  # Debugging output

    if [[ "$cpu_usage" -ge "$cpu_threshold" ]]; then
        echo "CPU usage is high: $cpu_usage%"
        send_telegram_alert "CPU" "$cpu_usage"
    fi
}


# Function to check RAM usage
check_ram() {
    local ram_threshold=$1
    local ram_usage=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2 }')

    # Compare using awk and interpret the result
    local comparison=$(awk -v usage="$ram_usage" -v threshold="$ram_threshold" 'BEGIN {print (usage >= threshold) ? "1" : "0"}')

    if [ "$comparison" -eq 1 ]; then
        echo "RAM usage is high: $ram_usage%"
        send_telegram_alert "RAM" "$ram_usage"
    fi
}


# Function to check Disk usage
check_disk() {
    local disk_threshold=$1
    local disk_usage=$(df -h | awk '$NF=="/"{printf "%s", $5}' | sed 's/%//')

    if [[ "$disk_usage" -ge "$disk_threshold" ]]; then
        echo "Disk usage is high: $disk_usage%"
        send_telegram_alert "DISK" "$disk_usage"
    fi
}


# Function to check CPU temperature
# Monitors CPU temperature by reading from the sysfs thermal zone files.
# If no temperature data is available, it logs an error.
check_temp() {
    local temp_threshold=$1
    local cpu_temp
    local temp_path

    # Attempt to find a valid temperature file
    for i in /sys/class/thermal/thermal_zone*/temp; do
        if [[ -f "$i" ]]; then
            temp_path="$i"
            break
        fi
    done

    # If a temperature file was found, read the temperature
    if [[ -n "$temp_path" ]]; then
        cpu_temp=$(awk '{print int($1/1000)}' "$temp_path")
    else
        echo "No thermal zone temp file found. Unable to check CPU temperature."
        return 1
    fi

    # Compare the CPU temperature with the threshold
    if [[ "$cpu_temp" -ge "$temp_threshold" ]]; then
        echo "CPU temperature is high: $cpu_temp°C"
        send_telegram_alert "TEMP" "$cpu_temp"
    fi
}


# Function to check 1-minute Load Average against the threshold
check_la1() {
    local la1=$(awk '{print $1}' /proc/loadavg)
    # If LA1_THRESHOLD is not set, default to the number of CPU cores
    local la1_threshold=${LA1_THRESHOLD:-$(nproc)}

    if (( $(echo "$la1 >= $la1_threshold" | bc -l) )); then
        echo "1-minute Load Average is high: $la1"
        send_telegram_alert "LA1" "$la1"
    fi
}


# Function to check 5-minute Load Average against the threshold
check_la5() {
    local la5=$(awk '{print $2}' /proc/loadavg)
    # If LA5_THRESHOLD is not set, default to 75% of the number of CPU cores
    local la5_threshold=${LA5_THRESHOLD:-$(echo "$(nproc) * 0.75" | bc)}

    if (( $(echo "$la5 >= $la5_threshold" | bc -l) )); then
        echo "5-minute Load Average is high: $la5"
        send_telegram_alert "LA5" "$la5"
    fi
}


# Function to check 15-minute Load Average against the threshold
check_la15() {
    local la15=$(awk '{print $3}' /proc/loadavg)
    # If LA15_THRESHOLD is not set, default to 50% of the number of CPU cores
    local la15_threshold=${LA15_THRESHOLD:-$(echo "$(nproc) * 0.5" | bc)}

    if (( $(echo "$la15 >= $la15_threshold" | bc -l) )); then
        echo "15-minute Load Average is high: $la15"
        send_telegram_alert "LA15" "$la15"
    fi
}

# Function to check if the server has been rebooted since the last check
check_reboot() {
    # Get the last boot time using the 'who -b' command and format the output
    local last_boot_time=$(LC_ALL=C who -b | awk '{print $3, $4, $5}')
#    local last_boot_time=$(who -b | awk '{print $3 " " $4}')
#    local last_boot_time=$(LC_ALL=C date -d "$(uptime -s)" "+%b %d %H:%M %Y")

    # Read the last saved boot time from the file
    local last_saved_boot_time=$(cat "$LAST_BOOT_TIME_FILE" 2>/dev/null)

    # Compare the current boot time with the last saved boot time
    if [[ "$last_boot_time" != "$last_saved_boot_time" ]]; then
        # If they differ, save the new boot time to the file
        echo "$last_boot_time" > "$LAST_BOOT_TIME_FILE"

        # Send a Telegram alert indicating the server has rebooted
        send_telegram_alert "REBOOT" "Server rebooted at $last_boot_time"
    fi
}







# Main Funcions

# Function to perform fast resource checks
# This function checks CPU usage, RAM usage, and 1-minute and 5-minute Load Averages.
# These metrics are checked more frequently due to their potential impact on server performance.
fast_monitor_resources() {
    while true; do
        [[ -n "$CPU_THRESHOLD" ]] && check_cpu "$CPU_THRESHOLD"
        [[ -n "$RAM_THRESHOLD" ]] && check_ram "$RAM_THRESHOLD"
        [[ -n "$LA1_THRESHOLD" ]] && check_la1 "$LA1_THRESHOLD"
        [[ -n "$LA5_THRESHOLD" ]] && check_la5 "$LA5_THRESHOLD"
        [[ "$SSH_LOGIN_MONITORING" -eq 1 ]] && check_ssh_activity
	[[ "$SFTP_LOGIN_MONITORING" -eq 1 ]] && check_sftp_activity
        # Sleep for the interval defined by FAST_CHECK_INTERVAL
        sleep "$FAST_CHECK_INTERVAL"
    done
}

# Function to perform slow resource checks
# This function checks Disk usage, CPU temperature, and 15-minute Load Average.
# These metrics are checked less frequently because they are less likely to fluctuate rapidly.
slow_monitor_resources() {
    while true; do
        [[ -n "$DISK_THRESHOLD" ]] && check_disk "$DISK_THRESHOLD"
        [[ -n "$TEMP_THRESHOLD" ]] && check_temp "$TEMP_THRESHOLD"
        [[ -n "$LA15_THRESHOLD" ]] && check_la15 "$LA15_THRESHOLD"
        [[ -n "$REBOOT_MONITORING" ]] && check_reboot
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
            --CPU|--RAM|--DISK|--TEMP)
                # Check if a numeric threshold is provided after the key
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: $1 must be followed by a threshold value."
                    exit 1
                fi
                # Create a reference to the respective threshold variable
                declare -n threshold_var="${1#--}_THRESHOLD"
                threshold_var="$2"
                shift 2  # Move past the argument and its value
                ;;
            --LA1|--LA5|--LA15)
                # Check if a value is provided for Load Average thresholds
                if [[ "$2" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                    declare -n threshold_var="${1#--}_THRESHOLD"
                    threshold_var="$2"
                    shift 2  # Move past the argument and its value
                else
                    # If no value is provided, use a default value
                    declare -n threshold_var="${1#--}_THRESHOLD"
                    threshold_var="default"  # No value provided, use default
                    shift  # Move past the argument
                fi
                ;;
            --SSH-LOGIN)
                # Enable SSH login monitoring
                SSH_LOGIN_MONITORING=1
                shift  # Move past the argument
                ;;
            --SFTP-MONITOR)
                # Enable SSH login monitoring
                SFTP_LOGIN_MONITORING=1
                shift  # Move past the argument
                ;;
            --REBOOT)
                # Enable reboot monitoring
                REBOOT_MONITORING=1
                shift  # Move past the argument
                ;;
            -h|--help)
                # Display help message and exit
                print_help
                exit 0
                ;;
            *)
                # Handle unknown parameters
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
    local default_set=false

    # Inform the user that the monitoring is starting and display the settings being used.
    echo ""
    echo "System Monitoring is now running with the following settings:"

    # Check if a CPU|RAM|DISK|TEMP threshold has been set
    [[ -n "$CPU_THRESHOLD" ]] && echo "CPU Threshold: $CPU_THRESHOLD%"
    [[ -n "$RAM_THRESHOLD" ]] && echo "RAM Threshold: $RAM_THRESHOLD%"
    [[ -n "$DISK_THRESHOLD" ]] && echo "Disk Usage Threshold: $DISK_THRESHOLD%"
    [[ -n "$TEMP_THRESHOLD" ]] && echo "CPU Temperature Threshold: $TEMP_THRESHOLD°C"

    # Check if SSH login monitoring is enabled.
    [[ -n "$SSH_LOGIN_MONITORING" ]] && echo "SSH Login Monitoring: Enabled"

    # Check if SFTP login monitoring is enabled.
    [[ -n "$SFTP_LOGIN_MONITORING" ]] && echo "SFTP Login Monitoring: Enabled"

    # Check if reboot monitoring is enabled and display it.
    if [[ -n "$REBOOT_MONITORING" ]]; then
        echo "Reboot Monitoring: Enabled"
        check_reboot  # Perform an initial check at script startup
    fi

    # Handle Load Average thresholds
    if [[ -n "$LA1_THRESHOLD" && "$LA1_THRESHOLD" != "default" ]]; then
        echo "1-minute Load Average Threshold: $LA1_THRESHOLD"
    elif [[ "$LA1_THRESHOLD" == "default" ]]; then
        LA1_THRESHOLD=$(nproc)  # Set to number of CPU cores by default
        echo "1-minute Load Average Threshold: Using default auto-threshold of $LA1_THRESHOLD (equal to the number of CPU cores)."
    fi

    if [[ -n "$LA5_THRESHOLD" && "$LA5_THRESHOLD" != "default" ]]; then
        echo "5-minute Load Average Threshold: $LA5_THRESHOLD"
    elif [[ "$LA5_THRESHOLD" == "default" ]]; then
        LA5_THRESHOLD=$(echo "$(nproc) * 0.75" | bc)  # Set to 75% of CPU cores by default
        echo "5-minute Load Average Threshold: Using default auto-threshold of $LA5_THRESHOLD (75% of CPU cores)."
    fi

    if [[ -n "$LA15_THRESHOLD" && "$LA15_THRESHOLD" != "default" ]]; then
        echo "15-minute Load Average Threshold: $LA15_THRESHOLD"
    elif [[ "$LA15_THRESHOLD" == "default" ]]; then
        LA15_THRESHOLD=$(echo "$(nproc) * 0.5" | bc)  # Set to 50% of CPU cores by default
        echo "15-minute Load Average Threshold: Using default auto-threshold of $LA15_THRESHOLD (50% of CPU cores)."
    fi

    echo ""
    # Check for required software
    check_required_software

    echo ""
    echo "Notifications: "

    # If no custom thresholds are set and no monitoring features are enabled, exit with an error.
    if [[ -z "$CPU_THRESHOLD" && -z "$RAM_THRESHOLD" && -z "$DISK_THRESHOLD" && -z "$TEMP_THRESHOLD" && ! $default_set && -z "$SSH_LOGIN_MONITORING" && -z "$SFTP_LOGIN_MONITORING" ]]; then
        echo "Error: No custom thresholds set and no monitoring features enabled."
        print_help
        exit 1
    fi
}









# Main code

# If no arguments are passed, print the help message and exit
if [ "$#" -eq 0 ]; then
    print_help
    exit 0
fi

# Call the parse_arguments function to process command-line arguments
parse_arguments "$@"

# Validate that at least one threshold or monitoring feature is set
validate_thresholds

# Start the monitoring functions in the background
fast_monitor_resources &
slow_monitor_resources &

# Wait for background processes to prevent script from exiting
wait
