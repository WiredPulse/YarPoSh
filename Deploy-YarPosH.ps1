#Requires -runasadministrator

<#
.SYNOPSIS
    Runs YARA with rules against a remote system or group of system(s). Any hits yielded from YARA are written back on the local machine in .\YARA_Results.
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER Dir
    Specify the directory to run rules against.

.PARAMETER Path
    Specify path to yara executable.

.EXAMPLE
    .\Deploy-YarPosH.ps1 -ComputerName 172.16.155.201 -Dir c:\windows\system32 -Path C:\users\blue\Desktop\yara32.exe -Rules C:\users\blue\Desktop\my_yara_rules.yar

    Running YARA and the 'my_yara_rules.yar' ruleset against c:\windows\system32 on a specific IP.

.EXAMPLE
    .\Deploy-YarPosH.ps1 -ComputerName c:\users\blue\computers.txt -Dir c:\windows\system32 -Path C:\users\blue\Desktop\yara32.exe -Rules C:\users\blue\Desktop\my_yara_rules.yar

    Running YARA and the 'my_yara_rules.yar' ruleset against c:\windows\system32 on the IP or IPs listed in computers.txt.

.OUTPUTS

.NOTES
    Version:        1.0
    Author:         @wiredPulse or @Wired_Pulse
    Creation Date:  March 27, 2017

.LINK
    YARA Project: https://github.com/VirusTotal/yara
    YARA Binaries: https://www.dropbox.com/sh/umip8ndplytwzj1/AADdLRsrpJL1CM1vPVAxc5JZa?dl=0
#>


param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$Dir,
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Rules
     )


$newline = "`r`n"
New-Item .\YarPoSh_Results -ItemType directory -ErrorAction SilentlyContinue | out-null
$ErrorActionPreference = "silentlycontinue"

function CALL
    {
    write-host "Running YARA on specified system(s)..." -ForegroundColor Cyan
    foreach($computer in $cpu)
        {
        if (!(test-path "\\$computer\c$\$exe"))
            {
            if(!(test-path "\\$computer\c$\"))
                {
                "$computer : No connection path" >> .\YarPoSh_Results\_Log.txt
                }
            Copy-item $Path \\$computer\c$\ -force -ErrorAction SilentlyContinue 
            Copy-Item .\ps_yara.ps1 \\$computer\c$\ -force -ErrorAction SilentlyContinue
            Copy-Item $rules \\$computer\c$\ -force -ErrorAction SilentlyContinue
            }
        $proc = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\ps_yara.ps1"
        $my_var = Register-WmiEvent -ComputerName $computer -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $computer -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
            if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$computer : Not accessible via WMI" >> .\YarPoSh_Results\_Log.txt
            }
        }
    write-host "Sleeping for 60 seconds..." -ForegroundColor Cyan
    sleep 60
    }


Function RETRIEVE
    {
    foreach($computer in $cpu)
        {
        # Retrieves the results from the distant machine and saves it locally
        copy-Item \\$computer\c$\*55.txt .\YarPoSh_Results -force -ErrorAction SilentlyContinue 
        rename-item .\YarPoSh_Results\ps_yara_55.txt $computer-ps_yara.txt
        remove-item \\$computer\c$\*55.txt -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\$exe -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\ps_yara.ps1 -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\$my_rules -ErrorAction SilentlyContinue
        }

    write-host "Retrieving YARA hits from distant machine(s)..." -ForegroundColor Cyan
    sleep 15
    remove-item .\ps_yara.ps1
    }


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $exe = $path.split('\') | select -last 1
    $my_rules = $rules.split('\') | select -last 1
    "Get-ChildItem $dir 2> $null |" >> ps_yara.ps1
    "ForEach-Object {c:\$exe -s -m -g -d filename=`$_. c:\$my_rules `$_.FullName 2> `$null } > c:\ps_yara_55.txt" >> ps_yara.ps1
    $cpu = Get-content $computername
    call
    retrieve
    }
elseif($ComputerName -notcontains '.txt')
    {
    $exe = $path.split('\') | select -last 1
    $my_rules = $rules.split('\') | select -last 1
    "Get-ChildItem $dir 2> `$null |" >> ps_yara.ps1
    "ForEach-Object {c:\$exe -s -m -g -d filename=`$_. c:\$my_rules `$_.FullName 2> `$null } > c:\ps_yara_55.txt" >> ps_yara.ps1
    $cpu = $ComputerName
    call
    retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}
