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


#Reference
* Analyze IOT device
https://ceh-practical.cavementech.com/module-18.-iot-and-ot-hacking/2.-capture-and-analyze-iot-traffic
