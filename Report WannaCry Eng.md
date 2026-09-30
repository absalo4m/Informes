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

<img width="639" height="476" alt="imagen" src="https://github.com/user-attachments/assets/c5deb27f-eee5-4c35-ac41-3b63464a5712" />


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

<img width="724" height="473" alt="imagen" src="https://github.com/user-attachments/assets/86679e6a-2988-4bc4-b2f7-71b141423302" />

It would be possible to decode the strings, but only one of them ends with `==`, which could indicate that the strings are fragments of a larger encoded sequence. Therefore, it is not possible to decode them without knowing the order, and for now I have no way of knowing it. If activity related to these strings is observed during execution, it might be possible to determine how the sample accesses, combines, or processes them. This would reveal how they are concatenated and could make it possible to decode and analyze their content.


## 3 - PEStudio


### Imports


Analyzing the sample in PEStudio, we can first see that it was compiled with Microsoft Visual C++ v6.0 and is a 32-bit PE executable:

<img width="371" height="151" alt="imagen" src="https://github.com/user-attachments/assets/8c441f0e-372f-487a-ab1c-cd3650073382" />

There are 91 imports listed, of which 30 are flagged as potentially dangerous or suspicious:

<img width="356" height="249" alt="imagen" src="https://github.com/user-attachments/assets/e4f93cec-c191-41ca-b560-5b096e68ee05" />

Among them are several that use ordinal import, a technique in which a PE imports functions from a DLL using the function's ordinal number instead of its name. This is also suspicious because it can be a form of light obfuscation when certain APIs are called.

However, this kind of technique is not inherently malicious and could be used by legit software, because it reduces binary's size and the loading speed improves. But it is not common in modern software.

<img width="817" height="234" alt="imagen" src="https://github.com/user-attachments/assets/b79aadb2-23a0-4bc3-8ad8-3f622d3f0953" />

The names of these imports suggest that they are related to socket operations. It is revealing that the called DLL is WS2_32.dll, Windows Socket Library, what it means, maybe, that those imports are related to the worm behaviour of WannaCry.

MalAPI is a useful website that classifies certain APIs often used by malware, and points what use can be given to them. These are the ones in the sample and identified as suspicious:

<details>
<summary> Flagged imports classified in MalAPI</summary>
	
<img width="2848" height="4683" alt="imagen" src="https://github.com/user-attachments/assets/ddc129ab-956d-4532-bd40-95bdabaf196a" />

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

<img width="724" height="75" alt="imagen" src="https://github.com/user-attachments/assets/ed5e8901-faab-44d0-8a2f-0102bf840244" />

This could indicate that WannaCry's first stage would act as a dropper, in other words, it contains an executable inside, which would be its second phase or second stage. Sample's second stage will be analyzed later, in its own section.


# Basic dynamic analysis


## 1 - Network-based indicators


Initially, the sample tries to connect with the following URL, as a kill switch:

`hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com` 

<img width="805" height="154" alt="imagen" src="https://github.com/user-attachments/assets/d3570957-6939-4976-bcde-07b7985bd34e" />

If the connection is successful, the malware stops its execution. That is what allowed to stop the attack back in May 2017, thanks to the researcher Marcus Hutchins, who registered this domain, helping to stop the global propagation of the ransomware.

Then, if the connection is unsuccessful and the payload starts, a lot of network activity is detected, due to the worm functionality that WannaCry has, expanding itself across the network. In the images, both in Wireshark and at the system process level, how the malware tries to connect with any possible system in the net can be observed, scanning through the different IPs on the network. Moreover, the port is always **445**. That is because the SMB protocol uses that port, **445**, and therefore that port should be used to the successful exploitation of **EternalBlue**.

<img width="428" height="272" alt="imagen" src="https://github.com/user-attachments/assets/e55bf3f3-2d95-4c21-9fa2-43252a7b2ae9" />

<br/>

<img width="910" height="197" alt="imagen" src="https://github.com/user-attachments/assets/b1ee1c53-b1eb-4f8a-b112-83898c53bac7" />

Different connections to localhost can also be noted, involving the processes `taskhsvc.exe` and `@WanaDecryptor@.exe`.

<img width="892" height="78" alt="imagen" src="https://github.com/user-attachments/assets/40238524-cd58-4618-9fa2-aa431b8c91bf" />

That process establishes the port 9050 in listen mode for all interfaces:

<img width="894" height="66" alt="imagen" src="https://github.com/user-attachments/assets/0f756faf-376a-491c-a714-eb0ef377f7e2" />

I tried to connect to that port using netcat, with no success.

After further research, I discovered that 9050 is the default port of the proxy SOCKS of Tor. As my personal assumption, this could be some kind of backdoor that allows the attacker to connect with the system using Tor network.

In order to try to capture the worm behaviour of WannaCry, I added to the virtual network a Windows 7 virtual machine vulnerable to EternalBlue:

<img width="646" height="245" alt="imagen" src="https://github.com/user-attachments/assets/5c57d9c6-0684-4671-8bc5-5af386645f4f" />

However, after several attempts, I did not detect the network propagation of the malware. That, probably, due to the low rate of success of EternalBlue. Interestingly, I detected that one of the exploitation tries does not use as path the IP of the vulnerable virtual machine, but 192.168.56.20, which also was observed as an IPC$ path in the identified strings in static analysis:

<img width="563" height="217" alt="imagen" src="https://github.com/user-attachments/assets/ffb2da6a-6b77-44ca-879b-318d782fdefb" />

This could suggest that the malware was developed in virtualbox, using his host-only mode, because it is the range of IPs that uses by default: 192.168.56.0/24. But this is just a personal hypothesis.


## 2 - Host-based indicators


Our greatest tool in this section is procmon. First of all, the sample is executed with administrator privileges and the name of the process that the sample has is established as a filter. As we saw in the basic static analysis, this malware's first phase acts as a dropper, so the procmon's filter *Operation is CreateFile* is a must in order to see the name of the file that the second stage will have and where it will be created. A lot of files will be seen with this filter, but that is because the API *CreateFile* is used both to create new files and to access to files in general:

<img width="438" height="184" alt="imagen" src="https://github.com/user-attachments/assets/f1fe53ef-f654-4fb5-a300-16f5bfbcd8d2" />

According to the capabilities of the API *CreateFile*, it is reasonable to think that the malware first of all verifies that a file called *tasksche.exe* exists, presumably his second stage, in the path *C:\Windows*. If it is not found, it will create it, as suggested by the two consecutive highlighted operations and their respective results.

<img width="305" height="222" alt="imagen" src="https://github.com/user-attachments/assets/21b227c7-0b5a-438d-9433-1a019cdec8aa" />

Having as a new clue the name of the second phase, it will be the next filter and the two previous filters are deleted. An operation involving a strange alphanumeric string can be evidenced:

<img width="426" height="106" alt="imagen" src="https://github.com/user-attachments/assets/2a99ba68-b6f9-4fba-83f1-a653f5ae8d1d" />

Which is a folder created by the payload:

<img width="401" height="178" alt="imagen" src="https://github.com/user-attachments/assets/b0eafd97-0221-48de-abc9-6983c735d3d0" />

This directory contains many files, and among them the file of the second stage itself (`tasksche.exe`):

<img width="325" height="476" alt="imagen" src="https://github.com/user-attachments/assets/362270c1-0f14-49f3-960a-baced8c5f43a" />

Also 3 files with name 00000000. Analyzing the file with extension .pky it is shown that:

<img width="638" height="232" alt="imagen" src="https://github.com/user-attachments/assets/bd74eeca-1ce4-42f4-a5af-38ab5ad995d1" />

The mention of the RSA cryptographic system and the similarity of the names suggest that these three files are related to the data encryption process.

An interesting outcome is shown with the name of the directory as a filter in procmon:

<img width="486" height="52" alt="imagen" src="https://github.com/user-attachments/assets/a05c0516-78e1-4787-88a7-0cd48f511922" />

The creation of a new register named as the directory:

<img width="602" height="206" alt="imagen" src="https://github.com/user-attachments/assets/8cb93714-5f24-45ca-85ab-fda6b0b7f0a1" />

Which enables a service with the same name that executes the second stage. This is a persistence mechanism that will execute it every time that the system starts, encrypting the new files created after the initial infection, trying to spread the malware again, etc.

Within services can be seen the persistence service created, which is stopped in the beginning and has an automatic startup. 

<img width="383" height="371" alt="imagen" src="https://github.com/user-attachments/assets/436bc74e-68dd-4838-9699-0ae6ad196940" />

Finally, the most obvious and evident host-indicators: almost all files are encrypted and unavailable. Their file extension becomes `.WNCRY`:

<img width="231" height="237" alt="imagen" src="https://github.com/user-attachments/assets/20c18de1-ebdd-41d1-937d-600dae0a28ee" />

Moreover, the wallpaper has changed for another one with instructions to pay and a red window has poped up with more detailed instructions for the payment:

<img width="1541" height="669" alt="imagen" src="https://github.com/user-attachments/assets/25d6ed5f-2407-41c0-9d36-f2bb12683d10" />

While I was checking events in procmon in order to make this analysis, I realised that the window with instructions, named *Wana Decrypt0r 2.0*, poped up persistently every time it was closed, being very annoying to the user. I found out that *tasksche.exe* always reopens the process. However, if *tasksche.exe* is killed, the window will not open again, as well as if the file *@WanaDecryptor@.exe* is deleted from the created directory by the malware.

Researching in procmon about this executable, I found that executes this command when starts:

<img width="838" height="368" alt="imagen" src="https://github.com/user-attachments/assets/15a458ce-b730-489e-96c1-7f64cfdecbfc" />

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

<img width="637" height="632" alt="imagen" src="https://github.com/user-attachments/assets/6f339796-2c65-461f-9f6c-19fdac74e576" />

In the red highlighted *1*, the string that contains the URL is provided to the ESI register so it can be used as an argument. The called functions in *2* will connect to the killswitch URL. After that, if there is no response from the website, the program will continue running the instructions in *3* normally. But if the request is answered, the instructions in *4* will be executed and the malware will stop and exit without any encryption of data.

Besides, the second-stage executable can be seen being written on disk thanks to the different calls to APIs that performs in order to do that. First of all, it loads into the register the strings of the API's calls that will do with the goal to create a file and write into it.

<img width="612" height="368" alt="imagen" src="https://github.com/user-attachments/assets/626fb6ab-5010-492c-9028-1a49d5785336" />

Then, it uses these APIs to look for the resource, load it and obtain its pointer and size:

<img width="482" height="632" alt="imagen" src="https://github.com/user-attachments/assets/985a6137-d2f0-4b83-91c6-27f9fb2523f7" />

Finally, it is shown the future name of the file, the path where it will be saved, etc:

<img width="305" height="419" alt="imagen" src="https://github.com/user-attachments/assets/80d5f089-9310-4d06-9716-0fed7e282606" />


# Advanced dynamic analysis 


I tried to capture the moment of exploitation of EternalBlue and propagation of the malware, manipulating the worm behaviour of WannaCry. Unfortunately, in my previous tests, the exploit always fails and does not infect my vulnerable VM. Therefore, I decided to investigate dynamically where the execution path was failing and determine whether modifying that control flow would allow the subsequent payload-delivery phase to be reached, which I will attempt to capture using wireshark.

As starting point of the research, I will use the attempts of EternalBlue exploitation captured during the basic dynamic analysis section:

<img width="563" height="217" alt="imagen" src="https://github.com/user-attachments/assets/1789e303-ed21-4303-8ae0-ec74a0108f3f" />

Strings that contain `IPC` have already appeared in the basic static analysis section. I look for them using Cutter to know the memory address where those strings are loaded:

<img width="369" height="73" alt="imagen" src="https://github.com/user-attachments/assets/d4a31ec8-e9f2-4bbe-b2a0-a0bf73a271ec" />

Cross-references (X-Refs) are useful to show the instruction that loads the string into memory:

<img width="767" height="409" alt="imagen" src="https://github.com/user-attachments/assets/6dce855a-445c-4a84-a868-6f82cc37d452" />

A good feature of Cutter is that allows to change the name of the functions at will during the analysis. So, I moved up to the upper function and renamed it as `EternalBlue`.

Another strings that I discovered in the static analysis and could be useful are long alphanumeric strings. I had not previously observed these strings being used during the execution flow:

<img width="724" height="473" alt="imagen" src="https://github.com/user-attachments/assets/7f684c64-00aa-43fa-9d3c-aaaf7bf9cb54" />

Under the suspicion of those strings might be related with the spreading of the malware, I redid the same steps in Cutter in order to determine which function would use them. I renamed that function as `Payload`. Moving upward through the call hierarchy, it can be seen that both functions are very close:

<img width="559" height="447" alt="imagen" src="https://github.com/user-attachments/assets/727f7eed-648c-4e79-99f8-2ce0e0a117d1" />

The function I named `EternalBlue` (*1*) is very close and before the function I named `Payload` (*2*). This ordering is consistent with my hypothesis that the sample first attempts the exploitation and then sends the payload. So, the conditional jumps in (*3*) and (*4*) are the ones that I need to manipulate. I set a breakpoint in `0x00407582` to control the execution step by step.

However, the breakpoint never activates. When the malware runs, the debugger shows that the debugging ended, but all the other processes already discovered in this analysis were made successfully. Having that in mind, and inspecting more carefully, I realised that after the killswitch check (*1*), the PID of the process changes (*2*):

<img width="651" height="196" alt="imagen" src="https://github.com/user-attachments/assets/89f819e9-07b9-4caf-a1d1-10d47d8f3aed" />

<br/>

<img width="427" height="172" alt="imagen" src="https://github.com/user-attachments/assets/1754ceea-d4d1-4cf7-9558-f253afee749b" />

The details of the event show that the first stage of the malware is executed again with the flag `-m security`. Also the PID of the new process is the same seen in the last picture. However, I lose the control of the debugging process after the killswitch. This explains why the control of the debugging session was lost after the kill-switch check: the execution relevant to the next stage was taking place in a different process.

The solution used was to set a breakpoint in the call to Create Thread, stop the execution in any new thread created and check procmon every time. But the new process will run uncontrolled when started, so the attachment should be quick and the process must be paused. The problem with this solution is that I have no control over the initial moments of the execution of this new process. Nevertheless, I was fast enough to continue the investigation. Shortly after the new process starts, the old one ends:

<img width="260" height="134" alt="imagen" src="https://github.com/user-attachments/assets/b7a3d61d-c059-4a05-8a6a-4bf9bf078324" />

This time, after attaching to the new process, the malware does stop in the set breakpoint on `EternalBlue`. Doing Step Over over that function, network traffic appears showing the exploitation attempt, with the same result as in the basic dynamic analysis section:

<img width="825" height="215" alt="imagen" src="https://github.com/user-attachments/assets/d86071f3-7f7c-49b1-aa95-dcdbc76c5938" />

Keeping on with the execution normally, the malware tries to take the next jump (*3*). I modify the value of Zero Flag (ZF) from 1 to 0 to prevent the jump:

<img width="559" height="447" alt="imagen" src="https://github.com/user-attachments/assets/b941e7ce-63c2-4fa1-aa69-192ae27f2cb5" />

<br/>

<img width="199" height="82" alt="imagen" src="https://github.com/user-attachments/assets/6f539611-7775-4416-9296-65ab52f52684" />

The next jump (*4*) is not taken. After reaching the function `Payload`, and to do Step Over over it, SMB traffic not previously detected to my vulnerable VM can be seen:

<img width="718" height="228" alt="imagen" src="https://github.com/user-attachments/assets/2ef9647b-14af-47b4-b182-30e58ddbad63" />

Alphanumeric strings are sent in multiple SMB packets. The size of the sent data is higher than expected, which is 4096-byte size, in every packet. The following picture shows the symbols `==` at the end of the string in the last sent packet:

<img width="488" height="440" alt="imagen" src="https://github.com/user-attachments/assets/ef28a822-eac6-4ff4-8fd1-e004c18304b8" />

The presence of the symbols `==` makes reasonable to think that the data is base64-encoded. However, I tried to reconstruct the entire string according to the order of the sent packets, unsuccessfully.

After those strings, the malware sends data again:

<img width="444" height="349" alt="imagen" src="https://github.com/user-attachments/assets/3d74d6b6-e1ab-4f74-905e-00b45228d617" />

These packets do not contain any string that make sense, it seems only hexadecimal data. As a personal hypothesis it may be shellcode:

<img width="541" height="33" alt="imagen" src="https://github.com/user-attachments/assets/f72bd713-7181-4c6c-990d-4909efb8fa7f" />

<br/>

<img width="490" height="305" alt="imagen" src="https://github.com/user-attachments/assets/ed76f844-1a0e-492f-a57b-754f58790bce" />

Doing some research I found that this kind of network activity is related with the use of DoublePulsar, a backdoor, capable of injecting shellcode or running DLLs into memory.

DoublePulsar uses a not too complex XOR obfuscation. Knowing the used formula, which is public, it should be easy to obtain the payload sent. I manage to decrypt it using a PCAP file with the captured network traffic and the following script:

```
https://github.com/WithSecureLabs/doublepulsar-c2-traffic-decryptor/blob/master/decrypt_doublepulsar_traffic.py
```

I easily adapted the script from python 2 to python 3 using ChatGPT.

The output file from the script is a PE executable that I named `payload`:

<img width="460" height="234" alt="imagen" src="https://github.com/user-attachments/assets/56b3fde7-0837-4368-8a25-02073f5b6b05" />

Within this executable, the resource W can be observed. Due to its high entropy, it is highly probable that it could be another executable: 

<img width="933" height="307" alt="imagen" src="https://github.com/user-attachments/assets/873d9df5-3830-4132-89b2-5abf3eaa7c1f" />

Inside the resource W, I found the resource R, and the resource XIA within R. Whereby, resource W should be the first stage of the malware.

<img width="507" height="466" alt="imagen" src="https://github.com/user-attachments/assets/6277662e-5815-42da-ab14-28d72c82c02b" />

The suspicion of resource W being the first phase of the malware seemed reasonable, but making a comparison between both hashes, from file `payload` and from initial sample, it can be seen that they do not match:

<img width="748" height="193" alt="imagen" src="https://github.com/user-attachments/assets/4a15b3f5-6a90-4ad5-a52c-39033623bf0a" />

However, the hash of the resource R within resource W do match with the hash of the file tasksche.exe, extracted from the initial sample:

<img width="658" height="130" alt="imagen" src="https://github.com/user-attachments/assets/c4d013a7-7133-4167-9b66-e1d8fc2e2577" />

Then, the malware achieves to be transmitted across the net, but it seems that does not transmit its first phase identically, because its hash is not the same. What can be said about this new executable obtained after the propagation is that it has the mechanism of kill switch and the capability to spread across the network. As can be seen in the following picture, I obtain the strings of the file `payload` and both the kill switch domain and the SMB communication strings, can be observed:

<img width="480" height="368" alt="imagen" src="https://github.com/user-attachments/assets/ee24ac3f-b922-4c97-8eb1-aef76aacdecf" />

These strings can not be observed in the second phase of the malware, as can be seen in this picture:

<img width="418" height="324" alt="imagen" src="https://github.com/user-attachments/assets/492596e1-f4d7-4406-9044-2c00c8cd1b64" />

And because of that, it seems reasonable to declare that this behaviour of the sample belongs just to the first phase and not to the second phase; and despite the hashes of the initial sample and the payload reconstructed from network traffic not matching, the capabilities of the malware are preserved.

In addition, I checked the vulnerable VM and, oddly, it had been infected:

<img width="865" height="639" alt="imagen" src="https://github.com/user-attachments/assets/9c6c4c3e-5624-4ea1-8eba-25e814e8d5e1" />

The created directory contains the files previously observed in the host-based indicators section of the basic dynamic analysis. However, the alphanumeric directory name differs from the one observed in the original sample:

<img width="823" height="624" alt="imagen" src="https://github.com/user-attachments/assets/9227832e-4f30-4ed5-8e7e-f42f96fb8718" />

The SHA-256 hash of tasksche.exe present on the infected VM matches both the reconstructed executable obtained from the network traffic and the corresponding tasksche.exe extracted from the original sample:

<img width="646" height="66" alt="imagen" src="https://github.com/user-attachments/assets/1078acc5-12cc-487c-9cb2-eecd1c7c08a8" />

However, I was not able to specify the conditions that made the propagation possible this time, beyond the alteration of the execution flow.

The combination of static and dynamic analysis allowed me to identify which functions are used by the malware to exploit EternalBlue and to spread the malware across the network, as well as to capture all that traffic with wireshark and to reconstruct the sent payload.


# Second-stage payload


Using PEStudio it can be seen a suspicious resource, called R, which is an executable. It is the second phase of the malware and as we know at this point of the analysis, it will have *tasksche.exe* as its name.

<img width="724" height="75" alt="imagen" src="https://github.com/user-attachments/assets/0c50ebbc-c001-41a3-bae8-ded2efe350d6" />

Thanks to PEStudio, that executable can be saved for analysis. Inspecting it, there is a new resource inside, named XIA, which is a PKZIP compressed file:

<img width="666" height="102" alt="imagen" src="https://github.com/user-attachments/assets/984b4482-1a9a-4ac0-ba6e-a512ddbdba82" />

I extract XIA and change its extension to .7z to unzip it and check what it is inside. However, it is password protected. Given that this compressed file was inside *tasksche.exe*, it is highly probable that the password to unzip it is contained within. The password is found while inspecting it with Cutter:

<img width="487" height="155" alt="imagen" src="https://github.com/user-attachments/assets/a0a962e1-5b13-4419-a3d8-41f53ad1bf8d" />

The password is: **WNcry@2ol7**

Something interesting can be seen in the same picture:

<img width="477" height="112" alt="imagen" src="https://github.com/user-attachments/assets/cabed7e3-f838-4c97-8dd5-1b322154fad7" />

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

<img width="631" height="246" alt="imagen" src="https://github.com/user-attachments/assets/fa40f026-1352-497a-9051-91f2e55cf5c0" />

Each file can be checked using the tool detect-it-easy and changing the file extension where necessary:
- **Folder msg**: contains .rtf files with the .wnry extension, which are explanatory notes, in different languages, with all the steps to follow in order to make the payment. Those notes will be used by *Wana Decrypt0r 2.0*: 

<img width="337" height="236" alt="imagen" src="https://github.com/user-attachments/assets/654d2d82-d9c3-4468-b345-1b275e85bd97" />

<br/>

<img width="569" height="243" alt="imagen" src="https://github.com/user-attachments/assets/b400e140-5faa-492d-8f8a-da6815a21f0b" />

As an example, the message in Russian.

- **b.wnry**: wallpaper with instructions to the user.

<img width="779" height="534" alt="imagen" src="https://github.com/user-attachments/assets/39cc92df-d948-4ca9-a5da-cb18c0f1fe7d" />

- **c.wnry**: list of .onion addresses, maybe related with the payment or with command and control functions, although I did not verify its possible uses. There is also a link to download Tor browser, probably in case that it is not previously installed in the system:

<img width="555" height="404" alt="imagen" src="https://github.com/user-attachments/assets/035dd1f0-2973-434f-a22d-df17c97a701c" />

<br/>

<img width="671" height="172" alt="imagen" src="https://github.com/user-attachments/assets/78623f2b-4b2d-4626-9222-dec12248aa26" />

- **r.wnry**: text file with an explanatory message to the user which says that the user is a victim of a ransomware attack and must pay. 
- **s.wnry**: compressed folder with some .dll files related to Tor.

<img width="201" height="272" alt="imagen" src="https://github.com/user-attachments/assets/9763dd6f-d86c-4b48-bb77-a8a57a5a4c80" />

- **t.wnry**: it is complicated to know the use of this file, because it does not have a common magic number, but the magic number `WANACRY!`:

<img width="645" height="265" alt="imagen" src="https://github.com/user-attachments/assets/4b9b5f28-74f2-4f90-aa6a-b5e6975a3f0c" />

Replacing the magic number to `MZ`, I do not observe any new information. Further investigation would be needed.

- **taskdl.exe**: this executable has the following suspicious imports:
	- **FindFirstFileW**
	- **FindNextFileW**
	- **DeleteFileW**

The first two are used to search in directory and the third to delete files, so it is reasonable to think that the use of this executable is the deletion of files, possibly the user's files after their encryption.

- **taskse.exe**: analyzing this executable with PEStudio, or checking its strings, nothing suspicious can be noted. Thanks to dynamic analysis I did realise about its role regarding the other files. It may have more functions, but it is sure that is related to `@WanaDecryptor@.exe`, which opens a window at the end of the encryption. If this window is closed, the active process `tasksche.exe` runs `taskse.exe`, which runs again `@WanaDecryptor@.exe`. This happens every 30 seconds approximately and turns to be something really annoying to the user, unless the main process `@WanaDecryptor@.exe` and the process `tasksche.exe`, are closed.

<img width="244" height="79" alt="imagen" src="https://github.com/user-attachments/assets/49264c22-8d0e-40d9-985b-ba4c5c3668d9" />

<br/>

<img width="245" height="97" alt="imagen" src="https://github.com/user-attachments/assets/d00c15ed-ff93-49f9-99b1-82c0637b3bfc" />

Considering that `taskse.exe` runs only when is needed to run `@WanaDecryptor@.exe` again and closes after that, I would say that `tasksche.exe` checks running processes and executes `@WanaDecryptor@.exe` if `taskse.exe` is not running. But this is just a personal asumption.

- **u.wnry**: executable of **@WanaDecryptor@.exe**:

<img width="811" height="614" alt="imagen" src="https://github.com/user-attachments/assets/908ddaec-99b1-4571-ac13-21331cd8044c" />


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

<img width="1630" height="578" alt="imagen" src="https://github.com/user-attachments/assets/77fb723f-869b-48c2-944e-619203e23d53" />

These dashboards also make it possible to inspect specific events. For example, the DNS request associated with the WannaCry kill switch can be observed directly:

<img width="493" height="331" alt="imagen" src="https://github.com/user-attachments/assets/c309d2b5-ee88-4bf4-9ef0-749382a7d645" />

Or even some other behaviours that I did not realise about can be seen, like the modification of the creation date on files `taskse.exe`, `tasksdl.exe` and  `tor.exe` by the second stage of the malware. In the picture the modification of `taskse.exe` is shown:

<img width="494" height="466" alt="imagen" src="https://github.com/user-attachments/assets/14479d28-e5ff-4868-8f29-7b20902b0829" />

Another interesting section is about registry-related operations. Here I found the register created to run *tasksche.exe* at boot, which I already talked about in the host-based indicators section. Additionally, another new service can be observed:

<img width="489" height="140" alt="imagen" src="https://github.com/user-attachments/assets/e2089c9d-753e-45fc-b1fd-5a02da51cde2" />

The service mssecsvc2.0, which I had not identified previously, is also created by WannaCry. It is configured to execute the first stage of the malware when Windows starts up:

<img width="550" height="215" alt="imagen" src="https://github.com/user-attachments/assets/b86ce6be-8e83-4954-874f-ab1845489666" />

Start means the kind of service startup, while the value 2 means that the service will initiate at Window's boot automatically.

<img width="583" height="305" alt="imagen" src="https://github.com/user-attachments/assets/74dd950a-195d-4c27-a6e6-76405ea332bb" />

As can be seen, it runs the original file of the malware at boot, which means that this is another persistence mechanism.

This finding is particularly interesting due to it not being identified during the previous stages of the analysis and demonstrates the value of correlating telemetry from different tools.

Overall, using Splunk and Sysmon provided an additional perspective on the behavior of the malware. Although the collected telemetry was not complete, it helped confirm previously identified indicators, such as the kill-switch DNS request and persistence mechanisms, while also revealing additional activity that had not been noticed during the initial static and dynamic analysis.
