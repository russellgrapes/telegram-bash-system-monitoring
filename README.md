![alt telegram-bash-system-monitoring](https://github.com/russellgrapes/telegram-bash-system-monitoring/blob/main/placeholder.png)

# Telegram Bash Linux System Monitoring

A versatile bash script to monitor various system resources and alert via Telegram messenger.

## Features

- **Telegram Alerts**: Sends alerts to a specified Telegram group/user.
- **Load Averages**: Allows for user-defined thresholds or auto-generated thresholds based on hardware.
- **Comprehensive Monitoring**: Monitors CPU, RAM, Disk, and CPU temperature with user-defined thresholds.
- **SSH Session Monitoring**: Monitors new SSH login sessions with the ability to exclude IPs or IP ranges.
- **Maintenance Mode**: Utilizes a lock file that can be controlled from other scripts to prevent alerts during maintenance.
- **CLI Feedback**: Provides status and notifications in the command-line interface (CLI).
- **Reboot Detection**: Notifies when the server has been rebooted.

## Usage

The `system-monitoring.sh` script offers various command-line options for monitoring system resources:

- `--NAME [ServerName]`: Assign a custom name to the server to distinguish notifications from different servers.
- `--CPU [threshold]`: Set a CPU usage alert threshold as a percentage (%).
- `--RAM [threshold]`: Set a RAM usage alert threshold as a percentage (%).
- `--DISK [threshold]`: Set a disk usage alert threshold as a percentage (%).
- `--TEMP [threshold]`: Set a CPU temperature alert threshold in degrees Celsius (°C).
- `--LA1 [threshold]`: Set a threshold for 1-minute Load Average. Without a specified threshold, the script uses an auto-threshold based on the hardware.
- `--LA5 [threshold]`: Set a threshold for 5-minute Load Average. If omitted, the script defaults to an auto-threshold of 75% of the CPU cores.
- `--LA15 [threshold]`: Set a threshold for 15-minute Load Average. If omitted, the script defaults to an auto-threshold of 50% of the CPU cores.
- `--SSH-LOGIN`: Enable monitoring of SSH login activity, issuing alerts for any new sessions that do not match the specified excluded IPs or IP ranges.
- `--REBOOT`: Monitor the system for reboots and send a notification upon system restart.
  
*Alerts are sent to Telegram when thresholds are exceeded.

## Configuration

The script can be configured via the following environment variables in the script body:

- `GROUP_ID`: Your unique Telegram group/user ID where alerts will be sent.
- `BOT_TOKEN`: The authentication token for your Telegram bot.
- `TELEGRAM_API`: The API URL for the Telegram bot, constructed using the BOT_TOKEN.
- `TELEGRAMM_LOCK_STATE`: The file path for the lock state file that controls alert messaging.
- `SSH_ACTIVITY_LOGINS`: The file path where the script logs current SSH session logins.
- `SSH_ACTIVITY_EXCLUDED_IPS`: A list of IP addresses or CIDR ranges excluded from SSH login alerts.
- `RESOURCE_CHECK_INTERVAL`: The interval, in seconds, between system resource checks.
- `SSH_CHECK_INTERVAL`: The interval, in seconds, between SSH login checks.
- `LAST_BOOT_TIME_FILE`: The file path for logging the last system boot time, used by the --REBOOT option.
- `HOST_NAME`: An default identifier for the server that also can be set via the --NAME command-line option.

# Telegram System Monitoring Installation

Follow these steps to install and set up the system-monitoring.sh script on your server.

## Install Required Packages

Install the main required packages:

```bash
sudo apt-get install bc ipcalc curl
```

Note: The script will check for any additional required packages during runtime and will notify you if any are missing.

## Download Script

Download the script directly using `curl`:

```bash
curl -O https://raw.githubusercontent.com/russellgrapes/telegram-bash-system-monitoring/main/system-monitoring.sh
```

## Make the Script Executable

Change the script's permissions to make it executable:

```bash
chmod +x system-monitoring.sh
```

## Running the Script

Run the script with the desired thresholds:

```bash
./system-monitoring.sh --LA1 --LA5 --CPU 80 --RAM 70 --DISK 90 --SSH-LOGIN
```

The monitoring script is now ready to use. It will check the specified thresholds and send alerts to your Telegram group when conditions are met. For best practice, consider adding it to your crontab with the reboot option to ensure it runs automatically after each system restart.

## Add Script to Crontab

Edit your crontab file to include the monitoring script:

```bash
crontab -e
```

Add the following line to run the script at reboot:

```bash
@reboot /path/to/system-monitoring.sh --LA15 --CPU 80 --RAM 70 --DISK 90 --SSH-LOGIN --REBOOT
```

Replace `/path/to/system-monitoring.sh` with the actual path to your script.

## Configuration

To configure the script settings, open it with your text editor. For example, using nano:

```bash
nano /path/to/system-monitoring.sh
```

Find the section labeled `# Settings` and set the main settings:

- `GROUP_ID`: Your Telegram group ID where alerts will be sent.
- `BOT_TOKEN`: Your Telegram bot token for authentication.
- `TELEGRAMM_LOCK_STATE`: Path to the lock state file which controls alert messaging.

For instructions on how to obtain your Telegram `GROUP_ID` and `BOT_TOKEN`, see the section below.

### Setting up Telegram Bot and Group

To receive alerts from the monitoring script, you'll need to set up a Telegram bot and determine the group ID where the bot will send notifications.

#### Creating a Telegram Bot

1. Open the Telegram app and search for "@BotFather", which is the official bot for creating other bots.
2. Send the `/newbot` command to BotFather and follow the instructions. You will be asked to provide a name and a username for your bot.
3. After the bot is created, BotFather will provide a token for your new bot. Keep this token secure as it will be used to control the bot.

#### Getting the Group ID

1. Create a new group in Telegram or use an existing one where you want to receive alerts.
2. Add your newly created bot to the group as a member.
3. Send a dummy message to the group to initialize the chat with the bot.
4. Visit `https://api.telegram.org/bot<YourBOTToken>/getUpdates` in your web browser, replacing `<YourBOTToken>` with the token you received from BotFather.
5. Look for a JSON response that contains `"chat":{"id":` followed by a long number. This number is your group ID. Note it down as you will need to enter it into the script's configuration.

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

Don't forget to give the project a star! Thanks again!

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Russell Grapes - [www.grapes.team](https://grapes.team)

Project Link: [https://github.com/russellgrapes/telegram-bash-system-monitoring](https://github.com/russellgrapes/telegram-bash-system-monitoring)
