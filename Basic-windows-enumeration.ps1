
param($extended)
$lines
 
$lines="------------------------------------------"
function whost($a) {

    Write-Host -ForegroundColor Yellow $lines
    Write-Host -ForegroundColor Yellow " "$a 
    Write-Host -ForegroundColor Yellow $lines
}


whost "
 ******************************************************************
 ******************************************************************
 **                        OSCP Script usage                     **
 **                    Windows Enumeration Script (WSC)          **
 **                    Written by: infosecsanyam                 **    
 **                    Support by absolomb                       **
 **                                                              **
 **                                                              **
 ******************************************************************
 ******************************************************************"


$Access = Get-Date
Write-Output "[***] You ran this script on $Access [***]"

# Determine OS running on target

$ComputerName = $env:computername
$OS = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName | select caption | select-string windows)-split("=", "}", "{")[0] -replace "}"| select-string windows
If ($OS -match "10") {Write-Output "[*] You are running $OS"}

$standard_commands = [ordered]@{


    'Basic System Information Results'                    = 'Start-Process "systeminfo" -NoNewWindow -Wait | ft';
    'Environment Variables Results'                       = 'Get-ChildItem Env: | ft Key,Value';
    'Network Information Results'                         = 'Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address';
    'DNS Servers Results'                                 = 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft';
    'ARP cache Results'                                   = 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State';
    'Routing Table Results'                               = 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex';
    'Network Connections Results'                         = 'Start-Process "netstat" -ArgumentList "-ano" -NoNewWindow -Wait | ft';
    'Connected Drives Results'                            = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft';
    'Firewall Config Results'                             = 'Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | ft';
    'Credential Manager Results'                          = 'start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait | ft'
    'User Autologon Registry Items Results'               = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft';
    'Local Groups Results'                                = 'Get-LocalGroup | ft Name';
    'Local Administrators Results'                        = 'Get-LocalGroupMember Administrators | ft Name, PrincipalSource';
    'User Directories Results'                            = 'Get-ChildItem C:\Users | ft Name';
    'Searching for SAM backup files Results'              = 'Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM';
    'Installed Software Directories Results'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime';
    'Software in Registry Results'                        = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name';
    'Folders with Everyone Permissions Results'           = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | ft';
    'Folders with BUILTIN\User Permissions Results'       = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | ft';
    'Checking registry for AlwaysInstallElevated Results' = 'Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | ft';
    'Unquoted Service Paths Results'                      = 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*''} | select PathName, DisplayName, Name | ft';
    'Scheduled Tasks Results'                             = 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State';
    'Tasks Folder Results'                                = 'Get-ChildItem C:\Windows\Tasks | ft';
    'Startup Commands Results'                            = 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl';
    'Host File content Results'                           = 'Get-content $env:windir\System32\drivers\etc\hosts | out-string';
    'Running Services Results'                            = 'Get-service | Select Name,DisplayName,Status | sort status | Format-Table -Property * -AutoSize | Out-String -Width 4096'
    'Installed Softwares in Computer Results'             = 'Get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096'
    'Installed Patches Results'                           = 'Get-Wmiobject -class Win32_QuickFixEngineering -namespace "root\cimv2" | select HotFixID, InstalledOn| ft -autosize | out-string'
    'Recent Documents Used Results'                       = 'get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent"  -EA SilentlyContinue | select Name | ft -hidetableheaders | out-string'
    'Potentially Interseting files Results'               = 'get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string | ft'
    'Last 10 Modified items Results'                      = 'Get-ChildItem "C:\Users" -recurse -EA SilentlyContinue | Sort {$_.LastWriteTime} |  %{$_.FullName } | select -last 10 | ft -hidetableheaders | out-string'
    'Stored Credentials Results'                          = 'cmdkey /list | out-string'
    'Localgroup Administrators Results'                   = 'net localgroup Administrators'
    'Current User Results'                                = 'Write-Host $env:UserDomain\$env:UserName';
    'User Privileges Results'                             = 'start-process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait | ft';
    'Local Users Results'                                 = 'Get-LocalUser | ft Name,Enabled,LastLogon';
    'Logged in Users Results'                             = 'gcim Win32_LoggedOnUser  | ft';
    'Running Processes Results'                           = 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize';

}


function RunCommands($commands) {
    ForEach ($command in $commands.GetEnumerator()) {
        whost $command.Name
        Invoke-Expression $command.Value
    }
}


RunCommands($standard_commands)



    whost "Script finished!"

Read-Host -Prompt "Press Enter to exit"



