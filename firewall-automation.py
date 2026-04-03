# Author: Sneaky Celery
# OSINT-based botnet IP blocker using Abuse CH Feodo Tracker

import requests, csv, subprocess, ipaddress, ctypes, sys, logging, time

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not is_admin():
    print("Error: Administrator privileges required.")
    sys.exit(1)

# Simple logging file
logging.basicConfig(
    filename="badip_blocker.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Fetch the known malicious IPs for the day.
for attempt in range(2):
    try:
        response = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            timeout=30      # prevent indefinite stalls with 1 reattempt
        ).text
        break
    except requests.RequestException as e:
        if attempt == 0:
            msg = f"Fetch attempt 1 failed: {e}. \nRetrying in 60 seconds."
            print(msg); logging.warning(msg)
            time.sleep(60)
        else:
            msg = f"Fetch attempt 2 failed: {e}. \nExiting."
            print(msg); logging.error(msg)
            sys.exit(1)

# Parse and validate format/content
mycsv = csv.reader(filter(lambda x: not x.startswith("#"), response.splitlines()))
ip_list = []
for row in mycsv:
    if len(row) > 1 and row[1].count(".") == 3:
        try:
            ip = str(ipaddress.ip_address(row[1]))
            if ip != "dst_ip":
                ip_list.append(ip)
        except ValueError:
            continue

if not ip_list:
    msg = "No valid IPs found in blocklist."
    print(msg); logging.warning(msg)
    sys.exit(1)

# Helper: run PowerShell command and return result
def run_ps(command):
    return subprocess.run(
        ["PowerShell", "-NonInteractive", "-Command", command],
        capture_output=True, text=True
    )

# Delete the old rules
run_ps("Remove-NetFirewallRule -DisplayName 'BadIP' -ErrorAction SilentlyContinue")

# Converts ip_list into a PowerShell array literal: @("1.2.3.4","5.6.7.8",...)
ip_array = "@(" + ",".join(f'"{ip}"' for ip in ip_list) + ")"

'''
Builds and runs two PowerShell commands, one per direction, each passing all IPs at once.
Example of the resolved command for one direction:
New-NetFirewallRule -DisplayName 'BadIP' -Direction Inbound -Action Block -RemoteAddress @("1.2.3.4","5.6.7.8","9.10.11.12") -Enabled True
'''
for direction in ("Inbound", "Outbound"):
    cmd = (
        f"New-NetFirewallRule -DisplayName 'BadIP' -Direction {direction} "
        f"-Action Block -RemoteAddress {ip_array} -Enabled True"
    )
    result = run_ps(cmd)
    if result.returncode != 0:
        msg = f"Failed to create {direction} rule: {result.stderr.strip()}"
        print(msg); logging.error(msg)
        sys.exit(1)

summary = f"Rules updated: {len(ip_list)} IPs blocked (Inbound + Outbound)."
print(summary)
logging.info(summary)
