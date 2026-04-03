# Author: Sneaky Celery
# This script utilizes Open Source Intelligence(OSINT) to block known malicious IPs from
# communicating with your system and vice-versa. This one in particular is protecting against
# botnets.
#
# __ Concepts to add __________________________________________________________
# 1. Try/Except blocks
# 2. Conditionals
# 3. Loops
# 4. Error handling
# 5. Data type conversion
# 6. Logging
# 7. F-strings
# 8. BONUS: Reduce repetition with re-usable helper function. For example: run_ps
#
# ── Features to add ──────────────────────────────────────────────────────────
# 1. Admin privilege check using ctypes -- exit early with clear message if not elevated.
# 2. Minimal logging using logging.basicConfig -- one file, one summary line per run, errors and
#    warnings logged. Log file: badip_blocker.log (append mode, ~365 lines/year).
# 3. requests timeout -- 30 seconds to prevent indefinite stalls.
# 4. Single retry on fetch failure -- 60 second wait between attempts, exit on second failure.
# 5. subprocess error handling -- use -NonInteractive flag, capture output, check returncode
#    and log PowerShell error messages on failure.
# 6. Switch from netsh to New-NetFirewallRule and Remove-NetFirewallRule with
#    -ErrorAction SilentlyContinue so delete step doesn't error on a fresh machine.
# 7. Batch approach -- serialize Python ip_list into a PowerShell array literal @("ip","ip",...)
#    and pass all IPs to New-NetFirewallRule -RemoteAddress at once. Reduces subprocess calls
#    from 2 per IP (~800 for a 400 IP list) down to 2 total (one per direction).
#    Example resolved command:
#    New-NetFirewallRule -DisplayName 'BadIP' -Direction Inbound -Action Block -RemoteAddress @("1.2.3.4","5.6.7.8","9.10.11.12") -Enabled True
# 8. BONUS: Create a helper function to simplify repetitive lines.
# ─────────────────────────────────────────────────────────────────────────────

import requests, csv, subprocess, ipaddress

# Source=Abuse CH
response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").text

# Filter out comments
mycsv = csv.reader(filter(lambda x: not x.startswith("#"), response.splitlines()))

# Verify that the expected IP addresses are found in the csv file before continuing.
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
    print("No valid IP address found. Exiting script.")
    exit(1)

# Delete existing firewall rules
rule = "netsh advfirewall firewall delete rule name='BadIP'"
subprocess.run(["Powershell", "-Command", rule])

# Create new firewall rules for inbound and outbound traffic
for ip in ip_list:
    print("Added Rule to block ", ip)
    rule = "netsh advfirewall firewall add rule name='BadIP' Dir=Out Action=Block RemoteIP=" + ip
    subprocess.run(["Powershell", "-Command", rule])
    rule = "netsh advfirewall firewall add rule name='BadIP' Dir=In Action=Block RemoteIP=" + ip
    subprocess.run(["Powershell", "-Command", rule])
