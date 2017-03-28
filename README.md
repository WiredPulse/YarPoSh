# YarPoSh
Remoting Capability for Deploying YARA Across an Enterprise 

# About
Deploy-YarPoSh.ps1 provides the following capability:
- Executes YARA and ruleset on a remote system or systems
- Retrieves the data gathered by YARA on remote systems and stores in on the local system (.\YarPoSh_Results)
- Logs systems not accessible, for one reason or another

# Requirements
- YARA (https://www.dropbox.com/sh/umip8ndplytwzj1/AADdLRsrpJL1CM1vPVAxc5JZa?dl=0)
- A suitable YARA ruleset
- PowerShell v2 or above
- RunAs Administrator
- WMI
- C$

# Examples
Running YARA and the 'my_yara_rules.yar' ruleset against c:\windows\system32 on a specific IP.
    PS C:\> .\Deploy-YarPosH.ps1 -ComputerName 172.16.155.201 -Dir c:\windows\system32 -Path C:\users\blue\Desktop\yara32.exe -Rules C:\users\blue\Desktop\my_yara_rules.yar

.EXAMPLE
    .\Deploy-YarPosH.ps1 -ComputerName c:\users\blue\computers.txt -Dir c:\windows\system32 -Path C:\users\blue\Desktop\yara32.exe -Rules C:\users\blue\Desktop\my_yara_rules.yar

    Running YARA and the 'my_yara_rules.yar' ruleset against c:\windows\system32 on the IP or IPs listed in computers.txt.

# Credits
Huge thanks to @psmitty7373 for developing Evil Inject Finder.
