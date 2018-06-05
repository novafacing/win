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
        Write-Host "$CrntService not found."
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

#Disable Remote Desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1

#Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWORD –Value 0

#Show File Explorer hidden files (WIP)


#Show File Explorer file extensions (WIP)


#Disable File Explorer Sharing Wizard (WIP)


#Disables Jump List items in Taskbar Properties
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_JumpListItems" -Value 0

#Disables tracking of recent documents in Taskbar Properties
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0

#Disable outdated protocols
$Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
function DisableProtocol {
	New-Item -Path "$Path" -name "$Protocol" -Type Directory -ErrorAction SilentlyContinue
	$Path = "$Path\$Protocol"
	New-Item -Path "$Path" -name "Client" -Type Directory -ErrorAction SilentlyContinue
	New-Item -Path "$Path" -name "Server" -Type Directory -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "$Path\Client" -Type DWORD -Name "DisabledByDefault" -Value 1 -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "$Path\Client" -Type DWORD -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "$Path\Server" -Type DWORD -Name "DisabledByDefault" -Value 1 -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "$Path\Server" -Type DWORD -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
}

$Protocols = 'PCT 1.0', 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1'
$Index = 0
$Protocol = $Protocols[$Index]

do {
	DisableProtocol
	$Index++
	$Protocol = $Protocols[$Index]
} while ($Protocol -ne $NULL)

#Enable TLS 1.2 (No other SSL or TLS versions are enabled)
$Protocol = "TLS 1.2"
New-Item -Path "$Path" -name "$Protocol" -Type Directory -ErrorAction SilentlyContinue
New-Item -Path "$Path" -name "Client" -Type Directory -ErrorAction SilentlyContinue
New-Item -Path "$Path" -name "Server" -Type Directory -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Client" -Type DWORD -Name "DisabledByDefault" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Client" -Type DWORD -Name "Enabled" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Server" -Type DWORD -Name "DisabledByDefault" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Server" -Type DWORD -Name "Enabled" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type DWORD -Name "DefaultSecureProtocols" -Value 0x800  -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type DWORD -Name "DefaultSecureProtocols" -Value 0x800 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Type DWORD -Name "SecureProtocols" -Value 0x800 -ErrorAction SilentlyContinue

#Force .NET Framework 4.0 to use TLS 1.2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Type DWORD -Name "chUseStrongCrypto" -Value 1 -ErrorAction SilentlyContinue

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
$Passverb = Read-Host -AsSecureString
Net User Milton $Passverb /Add /Y
$Passverb = $NULL

#Clear PowerShell command history
Clear-History

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
