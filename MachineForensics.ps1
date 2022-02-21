#Needs to be run as admin*******otherwise some of the hashing functions in particular will fail
# Usage - .\MachineForensics.ps1 -SaveFolder C:\Temp\Forensics

Param(
    [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the FULL path of the folder you would like to save your results to')]$SaveFolder
)

#set variables and folders
$pc = $env:COMPUTERNAME
#directory must be created beforehand...make sure it is their, if not then create one
if (!(Test-Path $SaveFolder)) {
    Write-Host "Can't find $SaveFolder...Creating it now." -ForegroundColor Red
    mkdir $SaveFolder
    exit
}

#Create all the functions to be used for information gathering
function Get-Startup {
   Get-WmiObject -Class win32_startupcommand | select Location,Caption,Command
}

function Get-Tasks {
  Get-ScheduledTask | Select-Object TaskName,Description,State,Taskpath,URI,Triggers,Author
}

function Get-ProcessHash {
    $processes = Get-Process | Select-Object -ExpandProperty Path
    foreach ($process in $processes){
        CertUtil -Hashfile $process MD5
    }
}

function Get-ServiceHash {
    $services = Get-WmiObject Win32_Service |  Select-Object -ExpandProperty Pathname
    foreach ($service in $services){
        CertUtil -Hashfile $service MD5
    }
}

function Get-SortedServices {
    Get-Service | Sort-Object Status -Descending
}

#process information combining wmi with PS to get usernames and commandline as well
function Get-EnrichedProcesses {
  $ProcInfo1 = Get-WmiObject win32_process | select processname, ProcessId, CommandLine | Sort-Object processname
  foreach ($proc in $ProcInfo1){
   $ProcInfo2 = Get-Process -Id $proc.ProcessId -IncludeUserName | Select-Object UserName
   $FullProcInfo = New-Object -TypeName psobject -Property @{
    PID = $proc.ProcessId
    User = $ProcInfo2.UserName
    ProcessName = $proc.processname
    CommandLine = $proc.CommandLine
    }
   $FullProcInfo
  }
}

function Get-UserAccounts{
  Get-WmiObject Win32_UserAccount | Select-Object Name,SID,Caption,Accounttype,LocalAccount,Description
}

function Get-OSInfo{
  Get-WmiObject -Class win32_computersystem  | select PSComputername, Domain, Model, Manufacturer, EnableDaylightSavingsTime, PartOfDomain, Roles, SystemType, NumberOfProcessors, TotalPhysicalMemory, Username
}

#connection information and correlate it with the processID
function Get-Connections{
  $results = Invoke-Command { netstat -ano } | Select-String -Pattern '::','\]:','Active','Proto','\s+$' -NotMatch
  $results | % {
     $socket = $_
     $pattern = '(^\s+(?<proto>[TCP]{3})\s+(?<LocalAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<LocalPort>[0-9]{1,5})\s+(?<RemoteAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<RemotePort>[0-9]{1,5})\s+(?<State>[\w]+)\s+(?<PID>[0-9]{1,5}))|(\s+(?<proto>[UDP]{3})\s+(?<LocalAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<LocalPort>[0-9]{1,5})\s+\*:\*\s+(?<PID>[0-9]{1,5}))'
       if ($socket -match $pattern)
       {
         New-Object psobject | Select @{N='Protocol';E={$Matches['proto']}},
                                      @{N='LocalAddress';E={$Matches['LocalAddress']}},
                                      @{N='LocalPort';E={$Matches['LocalPort']}},
                                      @{N='RemoteAddress';E={$Matches['RemoteAddress']}},
                                      @{N='RemotePort';E={$Matches['RemotePort']}},
                                      @{N='State';E={$Matches['State']}},
                                      @{N='PID';E={$Matches['PID']}},
                                      @{N='ProcessName';E={[System.Diagnostics.Process]::GetProcessById([int]$Matches['PID']).ProcessName};},
                                      @{N='ProcessBornDate';E={Get-UnixDateTime -DateTime ([System.Diagnostics.Process]::GetProcessById([int]$Matches['PID']).StartTime)};}

        }
    }
}
<# Commented out because this is not necessary in my environment, if it is useful to you, feel free to uncomment
function Get-ImportantEventLogs{
  Get-WmiObject -Class win32_ntlogevent  | Where-Object {$_.EventCode -eq "4672" -or $_.EventCode -eq "4698" -or $_.EventCode -eq "4702" -or $_.EventCode -eq "4697" -or $_.EventCode -eq "7045" -or $_.EventCode -eq "517"-or $_.EventCode -eq "1102" -or $_.EventCode -eq "4610" -or $_.EventCode -eq "4611" -or $_.EventCode -eq "4614" -or $_.EventCode -eq "4622" -or $_.EventCode -eq "4661" -or $_.EventCode -eq "4719" -or $_.EventCode -eq "612" -or $_.EventCode -eq "4728" -or $_.EventCode -eq "4729" -or $_.EventCode -eq "4720" -or $_.EventCode -eq "3065" -or $_.EventCode -eq "3066" -or $_.EventCode -eq "3033" -or $_.EventCode -eq "3063" -or $_.EventCode -eq "4798"} | Select-Object PSComputername, LogFile, EventCode, TimeGenerated, Message, InsertionStrings, Type
}
#>
function Get-NetworkAdapters{
  Get-WmiObject -Class win32_networkadapterconfiguration | select PSComputername, IPAddress, IPSubnet, DefaultIPGateway, DHCPServer, DNSHostname, DNSserversearchorder, MACAddress, description
}

function Get-Drivers{
  Get-WmiObject win32_pnpsigneddriver | Select-Object devicename, deviceid, driverversion, signer, startmode
}

function Get-MappedDrives{
  Get-PSDrive | Select-Object Name, Provider, Root, CurrentLocation
}

function Get-UserGroups{
  Get-WmiObject -Class win32_group |select PSComputername, Caption, Domain, Name, Sid
}

function Get-Shares{
  Get-WmiObject -Class win32_share  |select PSComputername, Name, Path, Description
}

function Get-PSHistory {
    history
}

function Get-DNSCache {
    Get-DnsClientCache -Status Success | Select Name,Data
}

function Get-SMBUserSessions {
    Get-SmbSession
}

function Get-PrefetchFiles {
    Get-ChildItem C:\Windows\Prefetch | Sort Name | Format-Table Name, CreationTime, LastWriteTime, LastAccessTime
}

function Get-UsedDLLs {
   Get-Process | Format-List ProcessName, @{I="Modules";e={_.Modules | Out-String}}
}

function Get-WMIBinders {
    Get-WmiObject -Class __Filtertoconsumerbinding -Namespace root\subscription | Format-Table Consumer,Filter,_SERVER -Wrap
}

function Get-WMIFilters {
    Get-WmiObject -Class __EventFilter -Namespace root\subscription | Format-Table Name,Query,PSComputername -Wrap
}

Function Get-WMIConsumers{
Get-WmiObject -Class __EventConsumer | Format-Table
}

function Get-DefenderExclustions {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclustions'
}

function Get-NamedPipes {
    Get-ChildItem -Path '\\.pipe\' | sort Fullname | Format-Table Fullname,Length,IsreadOnly,Exists,Extension,CreationTime,LastAccessTime
}

function Get-KerberosSessions {
    klist sessions
}

#run functions and output the results to separate csv files
Write-Host "   [*] COLLECTING ARTIFACT'S" -ForegroundColor Green
Write-Host "Collecting Operating System Information" -ForegroundColor Yellow
Get-OSInfo | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.operating_systems.csv")) -NoTypeInformation
Write-Host "Collecting User Accounts" -ForegroundColor Yellow
Get-UserAccounts | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.user_accounts.csv")) -NoTypeInformation
Write-Host "Collecting User Groups" -ForegroundColor Yellow
Get-UserGroups | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.UserGroups.csv")) -NoTypeInformation
Write-Host "Collecting Startup Programs and Locations" -ForegroundColor Yellow
Get-Startup | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.Startup.csv")) -NoTypeInformation
Write-Host "Collecting Process Hashes" -ForegroundColor Yellow
Get-ProcessHash | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.processhases.csv")) -NoTypeInformation
Write-Host "Collecting Service Hashes" -ForegroundColor Yellow
Get-ServiceHash | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.servicehashes.csv")) -NoTypeInformation
Write-Host "Collecting Connection Information" -ForegroundColor Yellow
Get-Connections | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.connections.csv")) -NoTypeInformation
Write-Host "Collecting Scheduled Tasks" -ForegroundColor Yellow
Get-Tasks | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.ScheduledTasks.csv")) -NoTypeInformation
Write-Host "Collecting Process Information" -ForegroundColor Yellow
Get-EnrichedProcesses | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.processes.csv")) -NoTypeInformation
Write-Host "Collecting Services" -ForegroundColor Yellow
Get-SortedServices | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.services.csv")) -NoTypeInformation
Write-Host "Collecting Mapped Drives" -ForegroundColor Yellow
Get-MappedDrives | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.mappeddrives.csv")) -NoTypeInformation
Write-Host "Collecting File Shares" -ForegroundColor Yellow
Get-Shares | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.shares.csv")) -NoTypeInformation
Write-Host "Collecting Powershell History" -ForegroundColor Yellow
Get-PSHistory | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.powershell_history.csv")) -NoTypeInformation
Write-Host "Collecting DNS Cache" -ForegroundColor Yellow
Get-DNSCache | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.dns_cache.csv")) -NoTypeInformation
Write-Host "Collecting SMB Sessions" -ForegroundColor Yellow
Get-SMBUserSessions | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.smb_sessions.csv")) -NoTypeInformation
Write-Host "Collecting Prefetch Files" -ForegroundColor Yellow
Get-PrefetchFiles | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.prefetch.csv")) -NoTypeInformation
Write-Host "Collecting Used DLLs" -ForegroundColor Yellow
Get-UsedDLLs | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.used_dlls.csv")) -NoTypeInformation
Write-Host "Collecting WMI Consumers" -ForegroundColor Yellow
Get-WMIConsumers | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.wmi_consumers.csv")) -NoTypeInformation
Write-Host "Collecting WMI Filters" -ForegroundColor Yellow
Get-WMIFilters | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.wmi_filters.csv")) -NoTypeInformation
Write-Host "Collecting Defender Exclusions" -ForegroundColor Yellow
Get-DefenderExclustions | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.defender_exclusions.csv")) -NoTypeInformation
Write-Host "Collecting Named Pipes" -ForegroundColor Yellow
Get-NamedPipes | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.named_pipes.csv")) -NoTypeInformation
Write-Host "Collecting Kerberos Sessions" -ForegroundColor Yellow
Get-KerberosSessions | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.kerberos_sessions.csv")) -NoTypeInformation
Write-Host "Forensics Collection Complete" -ForegroundColor Green
