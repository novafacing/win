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
'Power',
'Netman',
'Netlogon',
'MMCSS',
'Eaphost',
'SamSs'

$Index = 0
$CrntService = $Services[$Index]

do {
    if (Get-Service $CrntService -ErrorAction SilentlyContinue) {        
        Set-Service $CrntService -StartupType Disabled
        Stop-Service $CrntService -Force
    }
    else {
        Write-Host "$CrntService not found"
    }
    $Index++
    $CrntService = $Services[$Index]

} while ($CrntService -ne $NULL)

#Sets Windows Update service to automatic
Set-Service wuauserv -StartupType Automatic

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

#Show File Explorer hidden files (WIP)


#Show File Explorer file extensions (WIP)


#Disable File Explorer Sharing Wizard (WIP)


#Disables Jump List items in Taskbar Properties
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_JumpListItems" -Value 0

#Disables tracking of recent documents in Taskbar Properties
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0

function DisableProtocol() {
    if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" == false) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -name "$Protocol" -Type Directory
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Client" -Type Directory
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Server" -Type Directory
    }
    else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" == false) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Client" -Type Directory
    }
    else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" == false) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Server" -Type Directory
    }
    else {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Type DWORD -Name "DisabledByDefault" -Value 1
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Type DWORD -Name "Enabled" -Value 0
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" -Type DWORD -Name "DisabledByDefault" -Value 1
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" -Type DWORD -Name "Enabled" -Value 0
    }
}

#Disable PCT 1.0
$Protocol = "PCT 1.0"
DisableProtocol()

#Disable SSL 2.0
$Protocol = "SSL 2.0"
DisableProtocol()

#Disable SSL 3.0
$Protocol = "SSL 3.0"
DisableProtocol()

#Disable TLS 1.0
$Protocol = "TLS 1.0"
DisableProtocol()

#Disable TLS 1.1
$Protocol = "TLS 1.1"
DisableProtocol()

#Enable TLS 1.2 (No other SSL or TLS versions are enabled)
$Protocol = "TLS 1.2"
if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" == false) {
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -name "$Protocol" -Type Directory
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Client" -Type Directory
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Server" -Type Directory
}
else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" == false) {
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Client" -Type Directory
}
else if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" == false) {
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol" -name "Server" -Type Directory
}
else {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocol\$Protocol\Client" -Type DWORD -Name "DisabledByDefault" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocol\$Protocol\Client" -Type DWORD -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocol\$Protocol\Server" -Type DWORD -Name "DisabledByDefault" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocol\$Protocol\Server" -Type DWORD -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type DWORD -Name "DefaultSecureProtocols" -Value 0x00000800
    
    #Force .NET Framework 4.0 to use TLS 1.2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1
}

#Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled

#Disable SMBv2 & SMBv3
Set-SmbServerConfiguration -EnableSMB2Protocol $false
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi
sc.exe config mrxsmb20 start= disabled

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

#Install .MSI Mozilla Firefox, Wireshark, MalwareBytes, CCleaner (WIP)


#Extract SysInternals (WIP)


#Cleaning up
Remove-Item -path .\S12.INF
Remove-Item -path .\S12.WFW
Remove-Item -path ..\S12.zip
Remove-Item -path .\SwitchUACLevel.psm1
Remove-Item -path .\hosts

#Disable features
Write-Host Removing uneccessary programs 
dism /online /Disable-Feature /FeatureName: WindowsServerBackupSnapin
dism /online /Disable-Feature /FeatureName: Printing-Client
dism /online /Disable-Feature /FeatureName: Printing-Client-Gui
dism /online /Disable-Feature /FeatureName: Internet-Explorer-Optional-amd64
dism /online /Disable-Feature /FeatureName: Printing-XPSServices-Features
dism /online /Disable-Feature /FeatureName: SmbDirect

#Removes Windows Features
Remove-WindowsFeature -Name PowerShell-ISE

#New standard user
Write-Warning "Enter password for new user account below."
$Password = Read-Host -AsSecureString
Net User Milton $Password /Add /Y

#Clear PowerShell command history
Clear-History

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
