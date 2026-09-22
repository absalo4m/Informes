# Introduction


This report is the conclusion of **PMAT (Practical Malware Analysis & Triage)** course, which requires to analyze a real malware sample. WannaCry has been chosen as sample for this article, a famous ransomware that caused lots of damages around 2017.

Among the wide variety of ransomware that exists, the two main categories would be: 
- Crypto ransomware: attacks encrypting user's valuable files and makes them unusable.
- Locker ransomware: blocks the access to the computer so it cannot be used.

**WannaCry** is a crypto ransomware with worm capabilities identified for the first time in May 2017. It propagates automatically in Windows systems using the protocol SMB thanks to the vulnerability known as EternalBlue (CVE-2017-0144). It also uses the backdoor DoublePulsar. When it is executed successfully on a vulnerable computer, it encrypts victim's files and shows a ransom note with the intention of extorting the users and oblige them to pay money in Bitcoin in order to restore the access to their files.



# Basic Static Analysis


## 1 - Sample Hashes


- *MD5*: `db349b97c37d22f5ea1d1841e3c89eb4`
    
- *SHA1*: `e889544aff85ffaf8b0d0da705105dee7c97fe26`
    
- *SHA256*: `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c`
    
Searching for these hashes on VirusTotal reveals that the sample has been identified as WannaCry. The platform also provides additional information, including detection names, community analysis, etc:

<img width="639" height="476" alt="imagen" src="https://github.com/user-attachments/assets/f098861f-f83a-4472-a841-03efce541449" />


## 2 - Strings


Several strings related to cryptography can be found in the sample:

```
CryptAcquireContextA
CryptGenRandom
Microsoft Base Cryptographic Provider v1.0
CryptReleaseContext
Microsoft Enhanced RSA and AES Cryptographic Provider
CryptGenKey
CryptDecrypt
CryptEncrypt
CryptDestroyKey
CryptImportKey
CryptAcquireContextA
WanaCrypt0r
```

These strings indicate that the sample makes use of the Windows cryptographic API and that it is going to use related operations, like key generation, encryption, decryption, and key management. This is coherent with the encryption functionalities of WannaCry, but the strings alone are not enough to figure out how the sample uses them.

Also, a suspicious URL can be found:

```
hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com
```

It is known that this URL is related with the kill switch of WannaCry. WannaCry will try to connect to this domain at the beginning of its execution. If the connection is successful, the execution ends.

A wide list of the file extensions that the malware will target for encryption can be observed, as well:

<details>
<summary>List of targeted file extensions</summary>

```text
.der
.pfx
.key
.crt
.csr
.p12
.pem
.odt
.ott
.sxw
.stw
.uot
.3ds
.max
.3dm
.ods
.ots
.sxc
.stc
.dif
.slk
.wb2
.odp
.otp
.sxd
.std
.uop
.odg
.otg
.sxm
.mml
.lay
.lay6
.asc
.sqlite3
.sqlitedb
.sql
.accdb
.mdb
.dbf
.odb
.frm
.myd
.myi
.ibd
.mdf
.ldf
.sln
.suo
.cpp
.pas
.asm
.cmd
.bat
.ps1
.vbs
.dip
.dch
.sch
.brd
.jsp
.php
.asp
.java
.jar
.class
.mp3
.wav
.swf
.fla
.wmv
.mpg
.vob
.mpeg
.asf
.avi
.mov
.mp4
.3gp
.mkv
.3g2
.flv
.wma
.mid
.m3u
.m4u
.djvu
.svg
.psd
.nef
.tiff
.tif
.cgm
.raw
.gif
.png
.bmp
.jpg
.jpeg
.vcd
.iso
.backup
.zip
.rar
.tgz
.tar
.bak
.tbk
.bz2
.PAQ
.ARC
.aes
.gpg
.vmx
.vmdk
.vdi
.sldm
.sldx
.sti
.sxi
.602
.hwp
.snt
.onetoc2
.dwg
.pdf
.wk1
.wks
.123
.rtf
.csv
.txt
.vsdx
.vsd
.edb
.eml
.msg
.ost
.pst
.potm
.potx
.ppam
.ppsx
.ppsm
.pps
.pot
.pptm
.pptx
.ppt
.xltm
.xltx
.xlc
.xlm
.xlt
.xlw
.xlsb
.xlsm
.xlsx
.xls
.dotx
.dotm
.dot
.docm
.docb
.docx
.doc
```
</details>

Strings related to the SMB protocol, and, probably, with the exploitation of EternalBlue:

```
\%s\IPC$
\172.16.99.5\IPC$
\192.168.56.20\IPC$
```

In addition, long alphanumeric strings can be seen. Apparently, these strings could be encoded in Base64, but it is not sure:

<img width="724" height="473" alt="imagen" src="https://github.com/user-attachments/assets/23a9ba11-3414-482c-8ab6-08e8dd3972e7" />

It would be possible to decode the strings, but only one of them ends with `==`, which could indicate that the strings are fragments of a larger encoded sequence. Therefore, it is not possible to decode them without knowing the order, and for now I have no way of knowing it. If activity related to these strings is observed during execution, it might be possible to determine how the sample accesses, combines, or processes them. This would reveal how they are concatenated and could make it possible to decode and analyze their content.


## 3 - PEStudio


### Imports


Analyzing the sample in PEStudio, we can first see that it was compiled with Microsoft Visual C++ v6.0 and is a 32-bit PE executable:

<img width="371" height="151" alt="imagen" src="https://github.com/user-attachments/assets/8459f981-2a64-4db6-be7e-085aa35bbc7f" />

There are 91 imports listed, of which 30 are flagged as potentially dangerous or suspicious:

<img width="356" height="249" alt="imagen" src="https://github.com/user-attachments/assets/f9c415be-38c2-4753-8556-5eed538d7aa9" />

Among them are several that use ordinal import, a technique in which a PE imports functions from a DLL using the function's ordinal number instead of its name. This is also suspicious because it can be a form of light obfuscation when certain APIs are called.

However, this kind of technique is not inherently malicious and could be used by legit software, because it reduces binary's size and the loading speed improves. But it is not common in modern software.

<img width="817" height="234" alt="imagen" src="https://github.com/user-attachments/assets/024f9c65-4261-4ed8-beb8-f1342d731917" />

The names of these imports suggest that they are related to socket operations. It is revealing that the called DLL is WS2_32.dll, Windows Socket Library, what it means, maybe, that those imports are related to the worm behaviour of WannaCry.

MalAPI is a useful website that classifies certain APIs often used by malware, and points what use can be given to them. These are the ones in the sample and identified as suspicious:

<details>
<summary> Flagged imports classified in MalAPI</summary>
	
<img width="2848" height="4683" alt="imagen" src="https://github.com/user-attachments/assets/964e2e2f-e8d4-471d-a302-68708bf6634a" />

</details>

On one hand, APIs related to network communication:
- **GetAdaptersInfo**: commonly used to obtain data about network adapters in the system.
- **InternetOpenA, InternetOpenUrlA, InternetCloseHandle**: used to initialize Internet access, open a URL/resource, and release the associated handles.

On the other hand, related with encryption:
- **CryptAcquireContextA, CryptGenRandom**: cryptographic functions.

Finally, related with persistence:
- **CreateServiceA**
- **StartServiceA**
- **StartServiceCtrlDispatcherA**
- **OpenSCManagerA**


### Second-stage payload


A 32-bit executable can be seen inside the sample, named as resource R:

<img width="724" height="75" alt="imagen" src="https://github.com/user-attachments/assets/8f1fd095-87d7-4215-8bec-725822e4913c" />

This could indicate that WannaCry's first stage would act as a dropper, in other words, it contains an executable inside, which would be its second phase or second stage. Sample's second stage will be analyzed later, in its own section.


# Basic dynamic analysis


## 1 - Network-based indicators


Initially, the sample tries to connect with the following URL, as a kill switch:

`hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com` 

<img width="805" height="154" alt="imagen" src="https://github.com/user-attachments/assets/8f0e555c-e989-4cf3-aea4-b9bee0550773" />

If the connection is successful, the malware stops its execution. That is what allowed to stop the attack back in May 2017, thanks to the researcher Marcus Hutchins, who registered this domain, helping to stop the global propagation of the ransomware.

Then, if the connection is unsuccessful and the payload starts, a lot of network activity is detected, due to the worm functionality that WannaCry has, expanding itself across the network. In the images, both in Wireshark and at the system process level, how the malware tries to connect with any possible system in the net can be observed, scanning through the different IPs on the network. Moreover, the port is always **445**. That is because the SMB protocol uses that port, **445**, and therefore that port should be used to the successful exploitation of **EternalBlue**.

<img width="428" height="272" alt="imagen" src="https://github.com/user-attachments/assets/dc0fc126-9876-4481-a4ad-a79ecd31ad00" />

<img width="910" height="197" alt="imagen" src="https://github.com/user-attachments/assets/576e3455-c496-49dd-8feb-f06be9755146" />

Different connections to localhost can also be noted, involving the processes `taskhsvc.exe` and `@WanaDecryptor@.exe`.

<img width="892" height="78" alt="imagen" src="https://github.com/user-attachments/assets/3d851202-2e68-42f0-bd98-ec2e7e33e159" />

That process establishes the port 9050 in listen mode for all interfaces:

<img width="894" height="66" alt="imagen" src="https://github.com/user-attachments/assets/92bb02bb-2f66-4516-9b83-75ef27875302" />

I tried to connect to that port using netcat, with no success.

After further research, I discovered that 9050 is the default port of the proxy SOCKS of Tor. As my personal assumption, this could be some kind of backdoor that allows the attacker to connect with the system using Tor network.

In order to try to capture the worm behaviour of WannaCry, I added to the virtual network a Windows 7 virtual machine vulnerable to EternalBlue:

<img width="646" height="245" alt="imagen" src="https://github.com/user-attachments/assets/b5b64c0c-98f8-4b48-876b-11a321da8350" />

However, after several attempts, I did not detect the network propagation of the malware. That, probably, due to the low rate of success of EternalBlue. Interestingly, I detected that one of the exploitation tries does not use as path the IP of the vulnerable virtual machine, but 192.168.56.20, which also was observed as an IPC$ path in the identified strings in static analysis:

<img width="563" height="217" alt="imagen" src="https://github.com/user-attachments/assets/636fa03d-b363-40c5-9cec-2f96f92019c0" />

This could suggest that the malware was developed in virtualbox, using his host-only mode, because it is the range of IPs that uses by default: 192.168.56.0/24. But this is just a personal hypothesis.


## 2 - Host-based indicators


Our greatest tool in this section is procmon. First of all, the sample is executed with administrator privileges and the name of the process that the sample has is established as a filter. As we saw in the basic static analysis, this malware's first phase acts as a dropper, so the procmon's filter *Operation is CreateFile* is a must in order to see the name of the file that the second stage will have and where it will be created. A lot of files will be seen with this filter, but that is because the API *CreateFile* is used both to create new files and to access to files in general:

<img width="438" height="184" alt="imagen" src="https://github.com/user-attachments/assets/6c70220e-fb2f-482b-8407-b381448b7288" />

According to the capabilities of the API *CreateFile*, it is reasonable to think that the malware first of all verifies that a file called *tasksche.exe* exists, presumably his second stage, in the path *C:\Windows*. If it is not found, it will create it, as suggested by the two consecutive highlighted operations and their respective results.

<img width="305" height="222" alt="imagen" src="https://github.com/user-attachments/assets/63503066-ff92-4120-a062-20afb4e90c46" />

Having as a new clue the name of the second phase, it will be the next filter and the two previous filters are deleted. An operation involving a strange alphanumeric string can be evidenced:

<img width="426" height="106" alt="imagen" src="https://github.com/user-attachments/assets/f74375df-037c-4bcd-a868-3ba3157467b4" />

Which is a folder created by the payload:

<img width="401" height="178" alt="imagen" src="https://github.com/user-attachments/assets/1080e705-17a5-4a4d-a25c-fd9fb55a17b5" />

This directory contains many files, and among them the file of the second stage itself (`tasksche.exe`):

<img width="325" height="476" alt="imagen" src="https://github.com/user-attachments/assets/bbdbc383-59f3-4457-81c9-c134a4d7e3c6" />

Also 3 files with name 00000000. Analyzing the file with extension .pky it is shown that:

<img width="638" height="232" alt="imagen" src="https://github.com/user-attachments/assets/a52815c9-b827-4657-a006-0c2a4a3acbb0" />

The mention of the RSA cryptographic system and the similarity of the names suggest that these three files are related to the data encryption process.

An interesting outcome is shown with the name of the directory as a filter in procmon:

<img width="486" height="52" alt="imagen" src="https://github.com/user-attachments/assets/795b135c-d004-4b9e-ac8b-4f07928460bf" />

The creation of a new register named as the directory:

<img width="602" height="206" alt="imagen" src="https://github.com/user-attachments/assets/e810bdf1-9433-40db-886e-8848b14e811d" />

Which enables a service with the same name that executes the second stage. This is a persistence mechanism that will execute it every time that the system starts, encrypting the new files created after the initial infection, trying to spread the malware again, etc.

Within services can be seen the persistence service created, which is stopped in the beginning and has an automatic startup. 

<img width="383" height="371" alt="imagen" src="https://github.com/user-attachments/assets/67fdd899-c8d8-4b47-bc9c-c2797c6a5bf6" />

Finally, the most obvious and evident host-indicators: almost all files are encrypted and unavailable. Their file extension becomes `.WNCRY`:

<img width="231" height="237" alt="60" src="https://github.com/user-attachments/assets/274ff6ab-67a1-4b46-bf9a-e3a0bf83c2c6" />

Moreover, the wallpaper has changed for another one with instructions to pay and a red window has poped up with more detailed instructions for the payment:

<img width="1541" height="669" alt="imagen" src="https://github.com/user-attachments/assets/7e546c70-4d88-4908-b2bb-442329d195cd" />

While I was checking events in procmon in order to make this analysis, I realised that the window with instructions, named *Wana Decrypt0r 2.0*, poped up persistently every time it was closed, being very annoying to the user. I found out that *tasksche.exe* always reopens the process. However, if *tasksche.exe* is killed, the window will not open again, as well as if the file *@WanaDecryptor@.exe* is deleted from the created directory by the malware.

Researching in procmon about this executable, I found that executes this command when starts:

<img width="838" height="368" alt="imagen" src="https://github.com/user-attachments/assets/092eeee3-3b90-411a-8cc2-e1df7b3a6eb5" />

```
cmd.exe /c  
vssadmin delete shadows /all /quiet  
& wmic shadowcopy delete  
& bcdedit /set {default} bootstatuspolicy ignoreallfailures  
& bcdedit /set {default} recoveryenabled no  
& wbadmin delete catalog -quiet
```

Looking at the command step by step:

- **vssadmin delete shadows /all /quiet**: deletes all the Volume Shadow Copies (backups of files, folders, or entire volumes) without confirmation
- **wmic shadowcopy delete**: deletes shadow copies through WMI. This provides another mechanism for removing Volume Shadow Copies.
- **bcdedit /set {default} bootstatuspolicy ignoreallfailures**: modifies Boot Configuration Data so that Windows ignores boot errors and does not show options of automatic recovery
- **bcdedit /set {default} recoveryenabled no**: unables Windows recovery environment (WinRE), which disallows automatic repair and the restoration from the recovery environment
- **wbadmin delete catalog -quiet**: deletes backup's catalog of Windows Backup

It is obvious that this executable takes care of the anti-recovery phase of the malware thanks to this command. The malware not only encrypts the data, but also makes it difficult to recover.


# Advanced static analysis


Thanks to advanced analysis, certain internal aspects of the sample can be shown. For example, the killswitch, seen  in the section of network-based indicators:

<img width="637" height="632" alt="imagen" src="https://github.com/user-attachments/assets/1de95c47-3ee0-43b7-967e-c5582f30de49" />

In the red highlighted *1*, the string that contains the URL is provided to the ESI register so it can be used as an argument. The called functions in *2* will connect to the killswitch URL. After that, if there is no response from the website, the program will continue running the instructions in *3* normally. But if the request is answered, the instructions in *4* will be executed and the malware will stop and exit without any encryption of data.

Besides, the second-stage executable can be seen being written on disk thanks to the different calls to APIs that performs in order to do that. First of all, it loads into the register the strings of the API's calls that will do with the goal to create a file and write into it.

<img width="612" height="368" alt="imagen" src="https://github.com/user-attachments/assets/e7c8c192-1186-4167-abd6-a87aeb974a52" />

Then, it uses these APIs to look for the resource, load it and obtain its pointer and size:

<img width="482" height="632" alt="imagen" src="https://github.com/user-attachments/assets/a5154c42-ff2b-42ed-9744-99b5163743a2" />

Finally, it is shown the future name of the file, the path where it will be saved, etc:

<img width="305" height="419" alt="imagen" src="https://github.com/user-attachments/assets/8d894136-c1cf-41a0-bd71-19d379e4f1b7" />


# Advanced dynamic analysis 


I tried to capture the moment of exploitation of EternalBlue and propagation of the malware, manipulating the worm behaviour of WannaCry. Unfortunately, in my previous tests, the exploit always fails and does not infect my vulnerable VM. Therefore, I decided to investigate dynamically where the execution path was failing and determine whether modifying that control flow would allow the subsequent payload-delivery phase to be reached, which I will attempt to capture using wireshark.

As starting point of the research, I will use the attempts of EternalBlue exploitation captured during the basic dynamic analysis section:

<img width="563" height="217" alt="imagen" src="https://github.com/user-attachments/assets/49900272-73df-4360-8867-35137943f419" />

Strings that contain `IPC` have already appeared in the basic static analysis section. I look for them using Cutter to know the memory address where those strings are loaded:

<img width="369" height="73" alt="imagen" src="https://github.com/user-attachments/assets/7f9b2023-9bb4-4024-a7f9-037379cba7c5" />

Cross-references (X-Refs) are useful to show the instruction that loads the string into memory:

<img width="767" height="409" alt="imagen" src="https://github.com/user-attachments/assets/770f5020-d8c5-4f82-a70e-6b5e1799f1c1" />

A good feature of Cutter is that allows to change the name of the functions at will during the analysis. So, I moved up to the upper function and renamed it as `EternalBlue`.

Another strings that I discovered in the static analysis and could be useful are long alphanumeric strings. I had not previously observed these strings being used during the execution flow:

<img width="724" height="473" alt="imagen" src="https://github.com/user-attachments/assets/23a9ba11-3414-482c-8ab6-08e8dd3972e7" />

Under the suspicion of those strings might be related with the spreading of the malware, I redid the same steps in Cutter in order to determine which function would use them. I renamed that function as `Payload`. Moving upward through the call hierarchy, it can be seen that both functions are very close:

<img width="559" height="447" alt="imagen" src="https://github.com/user-attachments/assets/43f66340-bf1d-47f7-9acb-774116a8d7fb" />

The function I named `EternalBlue` (*1*) is very close and before the function I named `Payload` (*2*). This ordering is consistent with my hypothesis that the sample first attempts the exploitation and then sends the payload. So, the conditional jumps in (*3*) and (*4*) are the ones that I need to manipulate. I set a breakpoint in `0x00407582` to control the execution step by step.

However, the breakpoint never activates. When the malware runs, the debugger shows that the debugging ended, but all the other processes already discovered in this analysis were made successfully. Having that in mind, and inspecting more carefully, I realised that after the killswitch check (*1*), the PID of the process changes (*2*):

<img width="651" height="196" alt="imagen" src="https://github.com/user-attachments/assets/287dcae5-821b-48d4-a61a-66ead44b553d" />

<img width="427" height="172" alt="imagen" src="https://github.com/user-attachments/assets/230c7a88-1581-4555-9932-d4a5259e3bd9" />

The details of the event show that the first stage of the malware is executed again with the flag `-m security`. Also the PID of the new process is the same seen in the last picture. However, I lose the control of the debugging process after the killswitch. This explains why the control of the debugging session was lost after the kill-switch check: the execution relevant to the next stage was taking place in a different process.

The solution used was to set a breakpoint in the call to Create Thread, stop the execution in any new thread created and check procmon every time. But the new process will run uncontrolled when started, so the attachment should be quick and the process must be paused. The problem with this solution is that I have no control over the initial moments of the execution of this new process. Nevertheless, I was fast enough to continue the investigation. Shortly after the new process starts, the old one ends:

<img width="260" height="134" alt="imagen" src="https://github.com/user-attachments/assets/8e0c8188-17e8-4294-a84a-a20f6ce13582" />

This time, after attaching to the new process, the malware does stop in the set breakpoint on `EternalBlue`. Doing Step Over over that function, network traffic appears showing the exploitation attempt, with the same result as in the basic dynamic analysis section:

<img width="825" height="215" alt="imagen" src="https://github.com/user-attachments/assets/61e30ccb-7651-41a7-a550-c3345de4285d" />

Keeping on with the execution normally, the malware tries to take the next jump (*3*). I modify the value of Zero Flag (ZF) from 1 to 0 to prevent the jump:

<img width="559" height="447" alt="imagen" src="https://github.com/user-attachments/assets/2a982f09-9259-4caa-a1f0-7ebcdfa54c22" /><br/>

<img width="199" height="82" alt="imagen" src="https://github.com/user-attachments/assets/9a869c4e-81c1-4dc9-90e3-fac68c2b99ec" />

The next jump (*4*) is not taken. After reaching the function `Payload`, and to do Step Over over it, SMB traffic not previously detected to my vulnerable VM can be seen:

<img width="718" height="228" alt="imagen" src="https://github.com/user-attachments/assets/93b34aa2-eeef-4e82-9edf-62e86659661b" />

Alphanumeric strings are sent in multiple SMB packets. The size of the sent data is higher than expected, which is 4096-byte size, in every packet. The following picture shows the symbols `==` at the end of the string in the last sent packet:

<img width="488" height="440" alt="imagen" src="https://github.com/user-attachments/assets/bcb618d3-3add-42ba-b737-2eb8937f19be" />

The presence of the symbols `==` makes reasonable to think that the data is base64-encoded. However, I tried to reconstruct the entire string according to the order of the sent packets, unsuccessfully.

After those strings, the malware sends data again:

<img width="444" height="349" alt="imagen" src="https://github.com/user-attachments/assets/d35124a2-4abb-4ee5-b7fb-fbac922825d2" />

These packets do not contain any string that make sense, it seems only hexadecimal data. As a personal hypothesis it may be shellcode:

<img width="541" height="33" alt="imagen" src="https://github.com/user-attachments/assets/dbab7b05-e5f8-4dfd-ba3a-6dd0629d22c2" />

<img width="490" height="305" alt="imagen" src="https://github.com/user-attachments/assets/62a533bc-26f1-434b-b459-a9bbd800ed1a" />

Doing some research I found that this kind of network activity is related with the use of DoublePulsar, a backdoor, capable of injecting shellcode or running DLLs into memory.

DoublePulsar uses a not too complex XOR obfuscation. Knowing the used formula, which is public, it should be easy to obtain the payload sent. I manage to decrypt it using a PCAP file with the captured network traffic and the following script:

```
https://github.com/WithSecureLabs/doublepulsar-c2-traffic-decryptor/blob/master/decrypt_doublepulsar_traffic.py
```

I easily adapted the script from python 2 to python 3 using ChatGPT.

The output file from the script is a PE executable that I named `payload`:

<img width="460" height="234" alt="imagen" src="https://github.com/user-attachments/assets/2a5ebd5e-899c-45dc-9074-23f93414818a" />

Within this executable, the resource W can be observed. Due to its high entropy, it is highly probable that it could be another executable: 

<img width="933" height="307" alt="imagen" src="https://github.com/user-attachments/assets/7ee68248-68b4-4642-8655-9777fd819607" />

Inside the resource W, I found the resource R, and the resource XIA within R. Whereby, resource W should be the first stage of the malware.

<img width="507" height="466" alt="imagen" src="https://github.com/user-attachments/assets/f137c840-8464-4729-b9d4-bab4b637f0b2" />

The suspicion of resource W being the first phase of the malware seemed reasonable, but making a comparison between both hashes, from file `payload` and from initial sample, it can be seen that they do not match:

<img width="748" height="193" alt="61" src="https://github.com/user-attachments/assets/733cf13b-fd12-4dd4-bfff-4110f3682c3f" />

However, the hash of the resource R within resource W do match with the hash of the file tasksche.exe, extracted from the initial sample:

<img width="658" height="130" alt="62" src="https://github.com/user-attachments/assets/27a3b6f7-26a8-4c06-bfd2-ed75a53baca6" />

Then, the malware achieves to be transmitted across the net, but it seems that does not transmit its first phase identically, because its hash is not the same. What can be said about this new executable obtained after the propagation is that it has the mechanism of kill switch and the capability to spread across the network. As can be seen in the following picture, I obtain the strings of the file `payload` and both the kill switch domain and the SMB communication strings, can be observed:

<img width="480" height="368" alt="63" src="https://github.com/user-attachments/assets/d9e240eb-d5f3-4eba-86c7-2e34d3668a4a" />

These strings can not be observed in the second phase of the malware, as can be seen in this picture:

<img width="418" height="324" alt="64" src="https://github.com/user-attachments/assets/3004b2fb-54c8-4fd1-9b06-b5b9a3d87fd7" />

And because of that, it seems reasonable to declare that this behaviour of the sample belongs just to the first phase and not to the second phase; and despite the hashes of the initial sample and the payload reconstructed from network traffic not matching, the capabilities of the malware are preserved.

In addition, I checked the vulnerable VM and, oddly, it had been infected:

<img width="865" height="639" alt="59" src="https://github.com/user-attachments/assets/32672a26-eae1-4b0f-a2cc-869633c95955" />

The created directory contains the files previously observed in the host-based indicators section of the basic dynamic analysis. However, the alphanumeric directory name differs from the one observed in the original sample:

<img width="823" height="624" alt="65" src="https://github.com/user-attachments/assets/a7ff6b1a-9f22-40a8-b281-fb8322dbbbff" />

The SHA-256 hash of tasksche.exe present on the infected VM matches both the reconstructed executable obtained from the network traffic and the corresponding tasksche.exe extracted from the original sample:

<img width="646" height="66" alt="66" src="https://github.com/user-attachments/assets/21b09bde-5f00-4e92-9965-b6f41ccccd21" />

However, I was not able to specify the conditions that made the propagation possible this time, beyond the alteration of the execution flow.

The combination of static and dynamic analysis allowed me to identify which functions are used by the malware to exploit EternalBlue and to spread the malware across the network, as well as to capture all that traffic with wireshark and to reconstruct the sent payload.


# Second-stage payload


Using PEStudio it can be seen a suspicious resource, called R, which is an executable. It is the second phase of the malware and as we know at this point of the analysis, it will have *tasksche.exe* as its name.

<img width="724" height="75" alt="imagen" src="https://github.com/user-attachments/assets/1e1bd88c-6b93-434b-b34d-949451e3b9ab" />

Thanks to PEStudio, that executable can be saved for analysis. Inspecting it, there is a new resource inside, named XIA, which is a PKZIP compressed file:

<img width="666" height="102" alt="imagen" src="https://github.com/user-attachments/assets/a92b9ebc-cf09-4978-8e06-d147342c4601" />

I extract XIA and change its extension to .7z to unzip it and check what it is inside. However, it is password protected. Given that this compressed file was inside *tasksche.exe*, it is highly probable that the password to unzip it is contained within. The password is found while inspecting it with Cutter:

<img width="487" height="155" alt="imagen" src="https://github.com/user-attachments/assets/87b6ba0f-02e3-4a62-b29a-cf02cf2a87c2" />

The password is: **WNcry@2ol7**

Something interesting can be seen in the same picture:

<img width="477" height="112" alt="imagen" src="https://github.com/user-attachments/assets/5c724bc1-6ace-4f20-856c-bbf834807ea6" />

These commands are posterior actions ran by the malware when the zip is extracted. Both are legit Windows commands, used here with evil purposes:

 1. `attrib +h .`

	- `attrib` it is a command from Windows, usable to change attributes of files or folders.
	- `+h` means "to add the hidden attribute"
	- `.` refers to current directory

This command hides the current directory where the malware dropped the second stage, to avoid that the user could view the files or that malware components could be easily detectable.

 2. `icacls . /grant Everyone:F /T /C /Q`

	- `icacls` manages file and directory permissions in Windows
	- `.`  refers to current directory
	- `/grant Everyone:F`  grants full control permissions to the group “Everyone” (all users)
	- `/T`  applies it recursively to all files and subfolders
	- `/C`  continues even with errors
	- `/Q`  quiet mode

It changes permissions of the entire current directory and its content in order to allow that any user (and process) has full control and can act without restrictions.

Inside the compressed archive, the following files can be found:

<img width="631" height="246" alt="imagen" src="https://github.com/user-attachments/assets/f37d241c-74fc-46ef-8b56-e9012ea6c9df" />

Each file can be checked using the tool detect-it-easy and changing the file extension where necessary:
- **Folder msg**: contains .rtf files with the .wnry extension, which are explanatory notes, in different languages, with all the steps to follow in order to make the payment. Those notes will be used by *Wana Decrypt0r 2.0*: 

<img width="337" height="236" alt="imagen" src="https://github.com/user-attachments/assets/40cf334a-502e-4299-9d7d-ff31d880e26e" />

<img width="569" height="243" alt="imagen" src="https://github.com/user-attachments/assets/d58f3a54-8f35-46e8-904e-40bcb90ce42c" />

As an example, the message in Russian.

- **b.wnry**: wallpaper with instructions to the user.

<img width="779" height="534" alt="imagen" src="https://github.com/user-attachments/assets/a50111fc-7ce5-44e6-a1af-25a75545bc35" />

- **c.wnry**: list of .onion addresses, maybe related with the payment or with command and control functions, although I did not verify its possible uses. There is also a link to download Tor browser, probably in case that it is not previously installed in the system:

<img width="555" height="404" alt="imagen" src="https://github.com/user-attachments/assets/ba22a8df-985b-43c6-b506-67a9c720d1b2" />

<img width="671" height="172" alt="imagen" src="https://github.com/user-attachments/assets/ddd29c74-4401-4f5c-bee2-6e8f04c563e9" />

- **r.wnry**: text file with an explanatory message to the user which says that the user is a victim of a ransomware attack and must pay. 
- **s.wnry**: compressed folder with some .dll files related to Tor.

<img width="201" height="272" alt="imagen" src="https://github.com/user-attachments/assets/331b181e-5cb1-4b7f-b490-aedc3bc29649" />

- **t.wnry**: it is complicated to know the use of this file, because it does not have a common magic number, but the magic number `WANACRY!`:

<img width="645" height="265" alt="imagen" src="https://github.com/user-attachments/assets/fedf4293-011e-4843-83eb-ec360204a9e1" />

Replacing the magic number to `MZ`, I do not observe any new information. Further investigation would be needed.

- **taskdl.exe**: this executable has the following suspicious imports:
	- **FindFirstFileW**
	- **FindNextFileW**
	- **DeleteFileW**

The first two are used to search in directory and the third to delete files, so it is reasonable to think that the use of this executable is the deletion of files, possibly the user's files after their encryption.

- **taskse.exe**: analyzing this executable with PEStudio, or checking its strings, nothing suspicious can be noted. Thanks to dynamic analysis I did realise about its role regarding the other files. It may have more functions, but it is sure that is related to `@WanaDecryptor@.exe`, which opens a window at the end of the encryption. If this window is closed, the active process `tasksche.exe` runs `taskse.exe`, which runs again `@WanaDecryptor@.exe`. This happens every 30 seconds approximately and turns to be something really annoying to the user, unless the main process `@WanaDecryptor@.exe` and the process `tasksche.exe`, are closed.

<img width="244" height="79" alt="imagen" src="https://github.com/user-attachments/assets/9bcba2c4-7fb3-46eb-b9bf-3367d0ac6ba9" /><br/>

<img width="245" height="97" alt="imagen" src="https://github.com/user-attachments/assets/d14c8157-bf6e-425b-91c0-a08149118f88" />

Considering that `taskse.exe` runs only when is needed to run `@WanaDecryptor@.exe` again and closes after that, I would say that `tasksche.exe` checks running processes and executes `@WanaDecryptor@.exe` if `taskse.exe` is not running. But this is just a personal asumption.

- **u.wnry**: executable of **@WanaDecryptor@.exe**:

<img width="811" height="614" alt="imagen" src="https://github.com/user-attachments/assets/cd9a7c09-e309-4ab1-8881-1d62411cacf4" />


# YARA rule


According to the gathered indicators in the whole analysis, a YARA rule for this malware can be written. However, I created this rule only with the first phase of the malware in mind, and that is why not all the indicators are valid, because some of them are into the compressed file. For example, .onion urls will never be triggered by the first stage of the sample and will not be included.

```
rule YaraCry {
    
    meta: 
        last_updated = "2026"
        author = "Me"
        description = "Rule YARA WannaCry First Stage"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = ".wnry"                  ascii
        $string2 = "tasksche.exe"           ascii
        $string3 = "WNcry@2ol7"             ascii
        $string4 = "taskdl.exe"             ascii
        $string5 = "taskse.exe"             ascii

        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii

        $magic_number = "MZ"                ascii


    condition:
        // Fill out the conditions that must be met to identify the binary
        $magic_number at 0 and ($killswitch or 1 of ($string*))
```



# Splunk

Since this is not a formal analysis but a course conclusion, I can allow myself to explore other related approaches. Splunk is one of the leading SIEM tools of the market, and since it allows to collect, analyze and correlate network and systems data in real time, it is interesting to observe the obtained results when the sample is run in the lab. I analyzed system's telemetry using the app "Sysmon app for Splunk" and the logs generated by Sysmon.

Unfortunately, not all the known data, such as the creation of the encrypted files or other events, is collected. That might be due to data encryption, which can prevent logs from being sent, or to a lack of resources allocated to the Splunk server VM, which could cause problems with data ingestion, at least in my experience. However, it is a useful way to list relevant events in a preliminary way.


## Sysmon app for Splunk


To use this app, it is needed to install Sysmon in the target VM (I used the **SwiftOnSecurity** configuration file template) and send the generated log with the relevant events to Splunk through a lightweight agent, known as a forwarder. Once the data has been sent, it can be viewed on different dashboards.

<img width="1630" height="578" alt="imagen" src="https://github.com/user-attachments/assets/8453fa2a-83c5-4809-bef1-aa0eef98e518" />

These dashboards also make it possible to inspect specific events. For example, the DNS request associated with the WannaCry kill switch can be observed directly:

<img width="493" height="331" alt="imagen" src="https://github.com/user-attachments/assets/87e23f1e-6a74-44ed-bae3-0d86b1d836e4" />

Or even some other behaviours that I did not realise about can be seen, like the modification of the creation date on files `taskse.exe`, `tasksdl.exe` and  `tor.exe` by the second stage of the malware. In the picture the modification of `taskse.exe` is shown:

<img width="494" height="466" alt="imagen" src="https://github.com/user-attachments/assets/964d4242-56ac-4e54-90fb-fce1deba6d6e" />

Another interesting section is about registry-related operations. Here I found the register created to run *tasksche.exe* at boot, which I already talked about in the host-based indicators section. Additionally, another new service can be observed:

<img width="489" height="140" alt="imagen" src="https://github.com/user-attachments/assets/cb2f7b9e-a253-4307-9457-2e5ec27ed920" />

The service mssecsvc2.0, which I had not identified previously, is also created by WannaCry. It is configured to execute the first stage of the malware when Windows starts up:

<img width="550" height="215" alt="imagen" src="https://github.com/user-attachments/assets/d2a6fa60-94f9-407a-95d5-bc71a9655949" />

Start means the kind of service startup, while the value 2 means that the service will initiate at Window's boot automatically.

<img width="583" height="305" alt="imagen" src="https://github.com/user-attachments/assets/0933b160-849f-4bd8-b357-1099a0f25250" />

As can be seen, it runs the original file of the malware at boot, which means that this is another persistence mechanism.

This finding is particularly interesting due to it not being identified during the previous stages of the analysis and demonstrates the value of correlating telemetry from different tools.

Overall, using Splunk and Sysmon provided an additional perspective on the behavior of the malware. Although the collected telemetry was not complete, it helped confirm previously identified indicators, such as the kill-switch DNS request and persistence mechanisms, while also revealing additional activity that had not been noticed during the initial static and dynamic analysis.
