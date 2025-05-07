import paramiko
import time
import os
from datetime import datetime

# Get user inputs
host = input("MikroTik IP address: ")
username = input("Username: ")

# Authentication method
auth_method = input("SSH authentication method (password/key): ").strip().lower()
if auth_method == "password":
    password = input("Password: ")
    pkey = None
elif auth_method == "key":
    key_path = input("Path to private key file (e.g., /home/user/.ssh/id_rsa): ").strip()
    if not os.path.isfile(key_path):
        print(" Error: Private key file not found.")
        exit()
    try:
        pkey = paramiko.RSAKey.from_private_key_file(key_path)
    except paramiko.PasswordRequiredException:
        key_pass = input("Private key is encrypted. Enter passphrase: ")
        pkey = paramiko.RSAKey.from_private_key_file(key_path, password=key_pass)
    password = None
else:
    print(" Invalid authentication method. Use 'password' or 'key'.")
    exit()

# Application selection for Layer7 blocking
print("Select applications to block (comma separated):")
print("1. YouTube")
print("2. TikTok")
print("3. Instagram")
print("4. Netflix")
print("5. Facebook")
print("6. Twitter")
print("7. Reddit")
print("8. Discord")
print("9. Steam")
print("10. Snapchat")
print("11. Zoom")
print("12. ChatGPT (OpenAI)")
print("13. WhatsApp Web")
print("14. Telegram Web")
print("15. Twitch")
print("16. LinkedIn")
print("17. Pinterest")
print("18. Spotify")
print("Example: 1,3,5,12,14")

selection = input("Enter your choices: ").replace(" ", "")
selected_apps = selection.split(",")

app_patterns = {
    "1": ("youtube", "youtube.com"),
    "2": ("tiktok", "tiktok.com"),
    "3": ("instagram", "instagram.com"),
    "4": ("netflix", "netflix.com"),
    "5": ("facebook", "facebook.com"),
    "6": ("twitter", "twitter.com"),
    "7": ("reddit", "reddit.com"),
    "8": ("discord", "discord.com"),
    "9": ("steam", "steampowered.com"),
    "10": ("snapchat", "snapchat.com"),
    "11": ("zoom", "zoom.us"),
    "12": ("chatgpt", "openai.com"),
    "13": ("whatsapp", "web.whatsapp.com"),
    "14": ("telegram", "web.telegram.org"),
    "15": ("twitch", "twitch.tv"),
    "16": ("linkedin", "linkedin.com"),
    "17": ("pinterest", "pinterest.com"),
    "18": ("spotify", "spotify.com")
}


layer7_commands = []
for app_id in selected_apps:
    if app_id in app_patterns:
        name, pattern = app_patterns[app_id]
        layer7_commands.append(f'/ip firewall layer7-protocol add name={name} regexp="^.+({pattern}).*\\$"')
        layer7_commands.append(f'/ip firewall filter add action=drop chain=forward layer7-protocol={name} comment="Block {name}"')

# Manual TOR/VPN IP blocking
print("\nEnter TOR/VPN IPs to block (comma separated), or leave blank if none:")
tor_input = input("TOR/VPN IPs (e.g., 1.2.3.4, 5.6.7.8): ").strip()
tor_commands = []
if tor_input:
    for ip in tor_input.split(","):
        ip = ip.strip()
        tor_commands.append(f'/ip firewall address-list add list=tor_nodes address={ip}')
    tor_commands.append('/ip firewall filter add chain=input src-address-list=tor_nodes action=drop comment="Block TOR/VPN IPs"')

# Syslog logging configuration
enable_syslog = input("Send firewall logs to syslog server? (yes/no): ").strip().lower()
syslog_commands = []
if enable_syslog == "yes":
    syslog_ip = input("Syslog server IP address: ")
    syslog_port = input("Syslog port (default: 514): ").strip() or "514"
    syslog_commands = [
        f"/system logging action add name=remoteSyslog bsd-syslog=yes remote={syslog_ip} remote-port={syslog_port} target=remote",
        "/system logging add topics=firewall action=remoteSyslog",
        "/system logging add topics=info action=remoteSyslog"
    ]

# IPS firewall rules (with address-list timeout for auto-unblocking)
ips_commands = [

    # SYN Flood protection
    "/ip firewall filter add chain=input protocol=tcp tcp-flags=syn connection-state=new action=add-src-to-address-list address-list=syn_flood address-list-timeout=1d",
    "/ip firewall filter add chain=input src-address-list=syn_flood protocol=tcp tcp-flags=syn action=drop comment=\"Drop SYN Flood\"",

    # ICMP Flood protection
    "/ip firewall filter add chain=input protocol=icmp limit=5,10 action=accept",
    "/ip firewall filter add chain=input protocol=icmp action=drop comment=\"Drop Excessive Ping\"",

    # SSH Brute-force protection
    "/ip firewall filter add chain=input protocol=tcp dst-port=22 src-address-list=ssh_blacklist action=drop comment=\"SSH Blacklist Drop\"",
    "/ip firewall filter add chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=ssh_stage1 action=add-src-to-address-list address-list=ssh_stage2 address-list-timeout=1m",
    "/ip firewall filter add chain=input protocol=tcp dst-port=22 connection-state=new action=add-src-to-address-list address-list=ssh_stage1 address-list-timeout=1m",
    "/ip firewall filter add chain=input protocol=tcp dst-port=22 src-address-list=ssh_stage2 action=add-src-to-address-list address-list=ssh_blacklist address-list-timeout=1d",

    # RDP Brute-force protection
    "/ip firewall filter add chain=input protocol=tcp dst-port=3389 connection-state=new action=add-src-to-address-list address-list=rdp_blacklist address-list-timeout=1d",
    "/ip firewall filter add chain=input src-address-list=rdp_blacklist action=drop comment=\"Drop RDP Brute Force\"",

    # FTP Brute-force protection
    "/ip firewall filter add chain=input protocol=tcp dst-port=21 connection-state=new action=add-src-to-address-list address-list=ftp_blacklist address-list-timeout=1d",
    "/ip firewall filter add chain=input src-address-list=ftp_blacklist action=drop comment=\"Drop FTP Brute Force\"",

    # Telnet blocking
    "/ip firewall filter add chain=input protocol=tcp dst-port=23 action=drop comment=\"Block Telnet\"",

    # Port Scan detection
    "/ip firewall filter add chain=input protocol=tcp psd=21,3s,3,1 action=add-src-to-address-list address-list=port_scanners address-list-timeout=1d",
    "/ip firewall filter add chain=input src-address-list=port_scanners action=drop comment=\"Drop Port Scanners\"",

    # UDP Flood protection
    "/ip firewall filter add chain=input protocol=udp connection-limit=50,32 action=drop comment=\"Drop UDP Flood\"",

    # NTP amplification
    "/ip firewall filter add chain=input protocol=udp dst-port=123 src-address-list=!local action=drop comment=\"Block external NTP (Amplification)\"",

    # DNS amplification
    "/ip firewall filter add chain=input protocol=udp dst-port=53 src-address-list=!local action=drop comment=\"Block external DNS (Amplification)\"",

    "/ip dns set allow-remote-requests=no",

    # Block WAN to LAN DNS/NTP amplification
    "/ip firewall filter add chain=forward protocol=udp dst-port=53 src-address-list=!local action=drop comment=\"Block External DNS to LAN\"",
    "/ip firewall filter add chain=forward protocol=udp dst-port=123 src-address-list=!local action=drop comment=\"Block External NTP to LAN\"",
     
    # Limit all LAN-originated UDP abuse
    "/ip firewall filter add chain=forward protocol=udp dst-port=53,123 connection-limit=20,32 action=drop comment=\"Limit any UDP flood\"",

     # Limit all LAN-originated TCP SYN abuse
    "/ip firewall filter add chain=forward protocol=tcp tcp-flags=syn connection-limit=20,32 action=drop comment=\"Limit any TCP SYN flood\""

    
]

# Automatic configuration backup
now = datetime.now().strftime("%Y%m%d-%H%M%S")
backup_command = f"/system backup save name=pre_ips_backup_{now}"

# Combine all commands
commands = [backup_command] + layer7_commands + ips_commands + tor_commands + syslog_commands

# Execute configuration
def configure_mikrotik():
    print("\n Connecting to MikroTik...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if auth_method == "password":
            ssh.connect(host, username=username, password=password, port=22)
        else:
            ssh.connect(host, username=username, pkey=pkey, port=22)

        shell = ssh.invoke_shell()

        for cmd in commands:
            print(f" Executing: {cmd}")
            shell.send(cmd + '\n')
            time.sleep(0.7)
            while shell.recv_ready():
                output = shell.recv(4096).decode()
                print(output)

        print(f"\n Backup created: pre_ips_backup_{now}.backup")
        print(" IPS configuration completed successfully.")
    except Exception as e:
        print(f"\n Error: {e}")
    finally:
        if 'ssh' in locals():
            ssh.close()

if __name__ == "__main__":
    configure_mikrotik()
