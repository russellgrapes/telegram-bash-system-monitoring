![alt telegram-bash-system-monitoring](https://github.com/russellgrapes/telegram-bash-system-monitoring/blob/main/placeholder.png)

# Telegram Bash System Monitoring

A single-file, agentless **Linux server monitoring** script that sends **Telegram alerts** for the stuff that actually wakes you up: CPU/RAM/disk/load, temperature, SSH/SFTP logins, reboots, and remote host/service reachability.

Designed to run **once at boot** via `crontab @reboot` and then stay alive as a lightweight supervisor + monitoring loops. No cron spam. No “run every minute” duct tape.

If bash monitoring scripts had a flagship phone — this is the Pro model.

---

## What this is

- **One script**: `system-monitoring.sh`
- **One job**: run it at boot (`@reboot`) and let it monitor continuously
- **One output**: Telegram notifications (with smart cooldowns so you don’t get spammed)

---

## Features

### Local server monitoring (Telegram alerts)
- **CPU usage** alerts with spike filtering (sustained-high logic, not random peaks)
- **RAM usage** alerts
- **Disk usage** alerts (single target or multi-mount via a list file)
- **CPU temperature** alerts with “best sensor wins” auto-detection (thermal zones + hwmon)
- **Load Average** alerts (`LA1`, `LA5`, `LA15`) with sane auto-thresholds based on CPU cores
- **Reboot detection** (alerts when boot-time changes since last run)

### SSH/SFTP activity monitoring (security + ops)
- **SSH login monitoring** with Active/Ended alerts
- **SFTP session monitoring** with Active/Ended alerts (maps processes to sockets; includes IP details)
- **Flash detection** from auth logs/journald for sessions that start/end between polling ticks
- **Noise control**: exclude trusted IPs/CIDRs (IPv4 + IPv6) with correct `ipaddress` matching

### Remote monitoring (Ping + TCP)
- Monitor external hosts/services with:
  - ICMP ping (IPv4/IPv6-aware)
  - TCP port checks (22/80/443/etc.) using Python sockets (more reliable than bash hacks)
- Stateful alerts: **UP/DOWN** only on transitions (and after configurable consecutive failures)
- Smart behavior during maintenance lock:
  - If Telegram alerts are locked, “DOWN” is queued once and delivered after unlock (if still down)

### Operational polish
- **Secure secrets handling**:
  - Stored in `/etc/telegram.secrets` (root-owned, `600`, not a symlink)
  - Parsed as data (not executed)
  - Interactive first-run setup hides the bot token input
- **Maintenance mode** (instant mute): lock file `'/usr/local/bin/telegramm_lock.state'`
- **Single-instance enforcement** (flock lock; PID fallback)
- **Control plane**:
  - `--STATUS` / `--RELOAD` / `--KILL` (must be used alone)
- **Self-checks dependencies** with distro-aware install hints (and can Telegram-notify on startup failures)

---

## Quick start

### 1) Install (one line)
```bash
sudo curl -fsSL https://raw.githubusercontent.com/russellgrapes/telegram-bash-system-monitoring/main/system-monitoring.sh -o /usr/local/bin/system-monitoring.sh \
  && sudo chmod +x /usr/local/bin/system-monitoring.sh
````

### 2) Telegram setup (bot token + group/chat id)

You need two values:

* `BOT_TOKEN` (from BotFather)
* `GROUP_ID` (Telegram chat/group id where alerts go)

Follow the guide below: **Telegram credentials**.

### 3) First run (interactive, creates `/etc/telegram.secrets`)

Run it once in a real terminal (TTY) as root. It will:

* prompt for `GROUP_ID` and `BOT_TOKEN`
* create `/etc/telegram.secrets` securely
* send a Telegram test message

Example (pick what you want to monitor):

```bash
sudo /usr/local/bin/system-monitoring.sh --NAME MyServer --CPU --RAM --DISK --LA1 --LA5 --LA15 --SSH --SFTP --REBOOT
```

Stop it after the test message if you want (Ctrl-C is fine). Then move to `@reboot`.

### 4) Run on every boot (core idea)

Edit root’s crontab:

```bash
sudo crontab -e
```

Add one line (recommended with logs):

```cron
@reboot /usr/local/bin/system-monitoring.sh --NAME MyServer --CPU --RAM --DISK --TEMP --LA1 --LA5 --LA15 --SSH --SFTP --REBOOT >>/var/log/system-monitoring.log 2>&1
```

Or discard output:

```cron
@reboot /usr/local/bin/system-monitoring.sh --NAME MyServer --CPU --RAM --DISK --LA1 --LA5 --LA15 --SSH --SFTP --REBOOT >/dev/null 2>&1
```

---

## Usage

### Common setups

**Classic “server health + security”**

```bash
sudo system-monitoring.sh --NAME prod-api-1 --CPU 85 --RAM 85 --DISK 90 --TEMP 70 --LA1 --LA5 --LA15 --SSH --SFTP --REBOOT
```

**Disk-heavy server with multiple mounts**

```bash
sudo system-monitoring.sh --NAME storage-1 --DISK-LIST /etc/system-monitoring.disk.list --REBOOT
```

**Monitor remote infrastructure (router + DNS + HTTPS)**

```bash
sudo system-monitoring.sh --NAME monitorbox \
  --PING "Name=router|Host=10.10.10.1|Ping=true|Port=22,80,443|Interval=10|MaxFails=3" \
  --PING "Name=cloudflare-dns|Host=1.1.1.1|Ping=true|Port=-|Interval=30|MaxFails=2" \
  --PING "Name=my-site|Host=example.com:443|Ping=false|Interval=15|MaxFails=2"
```

---

## Disk monitoring

### Single target

```bash
sudo system-monitoring.sh --NAME MyServer --DISK 90
```

Or specify a mount point (must be an actual mount point, not just any folder):

```bash
sudo system-monitoring.sh --NAME MyServer --DISK 90 --DISK-TARGET /mnt/data
```

### Multi-target via `--DISK-LIST`

Create `/etc/system-monitoring.disk.list`:

```ini
# One entry per line. '#' comments allowed.
Mount=/|Threshold=90
Mount=/mnt/data|Threshold=85

# OR simple:
/var 70
/mnt/data 85
```

Run:

```bash
sudo system-monitoring.sh --NAME MyServer --DISK-LIST /etc/system-monitoring.disk.list
```

Notes:

* Entries are deduped by mountpoint (last definition wins; CLI overrides file).
* If you pass a path that isn’t a real mount point, the script will reject it (on purpose).

---

## Remote monitoring

### Target spec format (`--PING`)

Recommended key/value format (order doesn’t matter):

```
Name=<name>|Host=<host>|Ping=true|Port=22,80,443|Interval=11|MaxFails=3
```

Rules that matter:

* `Host` supports IPv4, IPv6, DNS
* `Host=example.com:443` is valid (if `Port=` is omitted, it becomes a single port check)
* `Ping=false` skips ICMP and checks only TCP ports
* A config that disables ping and has no ports is rejected (it would do nothing)
* Duplicate `Name+Host` entries are rejected (state keys would collide)

### `--PING-LIST`

Create `/etc/system-monitoring.ping.list`:

```ini
# One spec per line. '#' comments allowed.
Name=router|Host=10.10.10.1|Ping=true|Port=22,80,443|Interval=11|MaxFails=3
Name=dns1|Host=1.1.1.1|Ping=true|Port=-|Interval=30|MaxFails=2
Host=8.8.8.8
Name=v6-web|Host=[2001:db8::10]|Ping=false|Port=443|Interval=11|MaxFails=3
```

Run:

```bash
sudo system-monitoring.sh --NAME MonitorBox --PING-LIST /etc/system-monitoring.ping.list
```

---

## SSH/SFTP monitoring

Enable:

* `--SSH` for SSH logins
* `--SFTP` for SFTP sessions

What you get:

* “Active” and “Ended” notifications (stateful, no spam)
* A snapshot file updated every fast tick:

  * `/usr/local/bin/.system-monitoring/ssh_activity_logins.txt` (safe to tail)

### Excluding trusted IP ranges

Edit the script’s `SSH_ACTIVITY_EXCLUDED_IPS` array (near the top):

```bash
SSH_ACTIVITY_EXCLUDED_IPS=("10.10.0.0/16" "192.168.1.0/24" "2001:db8::/32")
```

CIDR matching is done with Python’s standard `ipaddress` module (correct for IPv4 + IPv6).

### Flash detection (the hidden killer feature)

Some sessions start/end between polls. This script reads auth logs (or journald) and emits “Flash” alerts so you don’t miss them.

If your auth logs are non-standard, you can force the source:

```bash
export SSHD_LOG_SOURCE="/var/log/auth.log"
# or:
export SSHD_LOG_SOURCE="JOURNAL"
```

If sshd’s `LogLevel` is too quiet (e.g. `ERROR`), flash detection can’t see “Accepted …” lines. The script will warn (stderr + Telegram).

---

## Maintenance mode (mute Telegram alerts)

Core switch:

* `/usr/local/bin/telegramm_lock.state`

Mute:

```bash
echo 1 | sudo tee /usr/local/bin/telegramm_lock.state >/dev/null
```

Unmute:

```bash
sudo rm -f /usr/local/bin/telegramm_lock.state
# or:
echo 0 | sudo tee /usr/local/bin/telegramm_lock.state >/dev/null
```

When you unlock, the script resets cooldown state so alerts resume immediately (you don’t miss real issues because of “cooldown time written while muted”).

---

## Managing a running instance

These flags must be used **alone**:

Status:

```bash
sudo system-monitoring.sh --STATUS
```

Reload config (secrets + `--DISK-LIST` + `--PING-LIST`, restarts loops in-place):

```bash
sudo system-monitoring.sh --RELOAD
```

Stop it cleanly:

```bash
sudo system-monitoring.sh --KILL
```

---

## Secrets and security

### Where credentials live

* `/etc/telegram.secrets`
* Must be:

  * owned by `root:root`
  * permissions `600`
  * not a symlink

The script enforces this and refuses to run if the file is unsafe.

Expected file format:

```bash
GROUP_ID="12345678"
BOT_TOKEN="123456:ABC..."
```

### CLI overrides (not recommended)

You *can* run with:

* `--GROUP-ID <chat_id>`
* `--BOT-TOKEN <token>`

But it’s dangerous because CLI args can leak via logs and process lists (`ps`, `top`, etc.). Use the secrets file instead.

---

## Full CLI reference

Run:

```bash
system-monitoring.sh --help
```

Supported flags:

* `--NAME <host_name>`
* `--CPU [percent]` (default 86)
* `--RAM [percent]` (default 86)
* `--DISK [percent]` (default 90)
* `--DISK-TARGET <mount_point>` (must be used with `--DISK`)
* `--DISK-LIST <file>`
* `--TEMP [celsius]` (default 65)
* `--LA1 [threshold]` (omit threshold for auto = CPU cores)
* `--LA5 [threshold]` (omit threshold for auto = 75% of CPU cores)
* `--LA15 [threshold]` (omit threshold for auto = 50% of CPU cores)
* `--SSH`
* `--SFTP`
* `--REBOOT`
* `--PING <spec>` (repeatable)
* `--PING-LIST <file>`
* `--GROUP-ID <chat_id>` (override; unsafe)
* `--BOT-TOKEN <token>` (override; unsafe)
* `--STATUS` (alone)
* `--RELOAD` (alone)
* `--KILL` (alone)

---

## Telegram credentials

#### Creating a Telegram Bot

1. Open the Telegram app and search for "@BotFather", which is the official bot for creating other bots.
2. Send the `/newbot` command to BotFather and follow the instructions. You will be asked to provide a name and a username for your bot.
3. After the bot is created, BotFather will provide a token for your new bot. Keep this token secure as it will be used to control the bot.

#### Getting the Group ID

1. Create a new group in Telegram or use an existing one where you want to receive alerts.
2. Add your newly created bot to the group as a member.
3. Send a dummy message to the group to initialize the chat with the bot (tip: mention the bot or send a command like `/start` so the bot definitely receives an update).
4. Visit `https://api.telegram.org/bot<YourBOTToken>/getUpdates` in your web browser, replacing `<YourBOTToken>` with the token you received from BotFather.
5. Look for a JSON response that contains `"chat":{"id":` followed by a long number. This number is your group ID. Note it down as you will need to enter it into the script's configuration.

Notes:

* Group IDs are often negative numbers (that’s normal). Copy the value exactly as shown.

---

## Contributing

⭐ Star this repo if it helps.

Then fork it and open a pull request, or create an issue tagged **enhancement**.

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Author

I write loops to skip out on life's hoops.

Russell Grapes - [www.grapes.team](https://grapes.team)

Project Link: [https://github.com/russellgrapes/telegram-bash-system-monitoring](https://github.com/russellgrapes/telegram-bash-system-monitoring)
