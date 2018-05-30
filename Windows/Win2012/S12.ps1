#Created by Zamanry, 05/2018

#Import firewall
Netsh advfirewall import "S12.wfw"
Write-Host Firewall installed.

#Flush DNS
Ipconfig /flushdns

#Disable & stop services
Write-Host Disabling/stopping services.
$Services = 
'Browser',
'ALG',
'TrkWks',
'fdPHost',
'FDResPub',
'SharedAccess',
'iphlpsvc',
'lltdsvc',
'NetTcpPortSharing',
'napagent',
'PerfHost',
'pla',
'RasAuto',
'RasMan',
'SessionEnv',
'TermService',
'umRdpService',
'RemoteRegistry',
'RemoteAccess',
'seclogon',
'SstpSvc',
'LanmanServer',
'SNMPTRAP',
'SSDPSRV',
'lmhosts',
'TapiSrv',
'upnphost',
'Wecsvc',
'FontCache',
'WinRM',
'WinHttpAutoProxySvc',
'wmiApSrv',
'LanmanWorkstation',
'defragsvc',
'MSiSCSI',
'AeLookupSvc',
'ShellHWDetection',
'SCardSvr',
'SCPolicySvc',
'CertPropSvc',
'wercplsupport',
'Spooler',
'WcsPlugInService',
'WPDBusEnum',
'DeviceAssociationService',
'DeviceInstall',
'DsmSvc',
'NcaSvc',
'PrintNotify',
'sacsvr',
'Audiosrv',
'AudioEndpointBuilder',
#'Dhcp', #Unless DHCP is required
'DPS',
'MozillaMaintenance',
'PlugPlay',
'WSService',
'WerSvc',
'PolicyAgent',
'IKEEXT',
'hidserv',
'WdiSystemHost',
'WdiServiceHost',
'RpcLocator',
'KPSSVC',
'AppMgmt',
'Power'

$Index = 0
$CrntService = $Services[$Index]

do
{
    if (Get-Service $CrntService -ErrorAction SilentlyContinue)
    {        
        Set-Service $CrntService -StartupType Disabled
        Stop-Service $CrntService -Force
    }
    else
    {
        Write-Host "$CrntService not found"
    }

    $Index++
    $CrntService = $Services[$Index]

}
while ($CrntService -ne $NULL)

#Start Windows Update service
Start-Service wuauserv

#Disable unnecessary network components
Write-Host Disabling network components.
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_tcpip6'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_rspndr'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_lltdio'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_implat'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_msclient'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_pacer'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_server'

#Disable IPv6 completely
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "DisabledComponents" -Type DWORD -Value "0xFF" -Force 

#Disable 'Register this connection's addresses in DNS'
$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
$NIC.SetDynamicDNSRegistration($false)

#Disable NetBIOS over TCP/IP
$NIC.SetTcpipNetbios(2)

#Disable LMHosts lookup
$NIC = [wmiclass]'Win32_NetworkAdapterConfiguration'
$NIC.enablewins($false,$false)

#Prevent Server Manager from opening at startup
Set-ItemProperty -Path "HKLM:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Type DWORD -Value "0x1" –Force

#Disables IGMP
Netsh interface ipv4 set global mldlevel = none

#Disable memory dumps
Wmic recoveros set DebugInfoType = 0

#Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1

#Show File Explorer hidden files
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

#Show File Explorer file extensions
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFilExt" -Value 0

#Disable File Explorer Sharing Wizard
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Value 0

#Disables Jump List items in Taskbar Properties
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_JumpListItems" -Value 0

#Disables tracking of recent documents in Taskbar Properties
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0

#Create new Hosts file
$ScriptLocation = Get-Location 
Set-Location ..\..\..\..
$DriveLetter = Get-Location
Move-Item -path $ScriptLocation\hosts -destination $DriveLetter\Windows\system32\drivers\etc\hosts -force
Set-Location $ScriptLocation

#Set UAC level to high
Import-Module .\SwitchUACLevel.psm1
Get-Command -Module SwitchUACLevel
Set-UACLevel 3
Write-Host Set UAC level to High

#Enables custom local security policies
Secedit /configure /db %temp%\temp.sdb /cfg S12.inf

#Cleaning up
Remove-Item -path .\S12.INF
Remove-Item -path .\S12.WFW
Remove-Item -path ..\S12.zip
Remove-Item -path .\SwitchUACLevel.psm1
Remove-Item -path .\hosts

#Removes Windows Features
Write-Host Removing PowerShell ISE
Remove-WindowsFeature -Name PowerShell-ISE

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
