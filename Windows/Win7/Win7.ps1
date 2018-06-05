#Created by Zamanry, 06/2018

#Import firewall
Netsh advfirewall import "Win7.wfw"
Write-Host Firewall installed.

#Flush DNS
Ipconfig /flushdns

#Flush Netsh caches
Netsh interface ipv4 delete arpcache
Netsh interface ipv4 delete desinationcache
Netsh interface ipv4 delete neighbors
Netsh interface ipv4 delete winsservers

#Disable & stop services
Write-Host Disabling/stopping services.
$Services = 
'SensrSvc',
'AeLookupSvc',
'ALG',
'AppMgmt',
'aspnet_state',
'BDESVC',
'wbengine',
'bthserv',
'PeerDistSvc',
'CertPropSvc',
'Browser',
'Dhcp',
'DPS',
'WdiServiceHost',
'WdiSystemHost',
'DiagTrack',
'defragsvc',
'TrkWks',
'MSDTC',
'EFS',
'EapHost',
'Fax',
'FDResPub',
'fdPHost',
'hkmsvc',
'HomeGroupListener',
'HomeGroupProvider',
'hidserv',
'SharedAccess',
'IEEtwCollectorService',
'iphlpsvc',
'PolicyAgent',
'lltdsvc',
'Mcx2Svc',
'clr_optimization_v2.0.50727_32',
'clr_optimization_v4.0.30319_32',
'MSiSCSI',
'swprv',
'MMCSS',
'NetMsmqActivator',
'NetPipeActivator',
'NetTcpActivator',
'NetTcpPortSharing',
'Netlogon',
'napagent',
'CscService',
'WPCSvc',
'PNRPsvc',
'p2psvc',
'p2pimsvc',
'pla',
'IPBusEnum',
'PNRPAutoReg',
'WPDBusEnum',
'Spooler',
'wercplsupport',
'PcaSvc',
'QWAVE',
'RasAuto',
'RasMan',
'SessionEnv',
'TermService',
'UmRdpService',
'RpcLocator',
'RemoteRegistry',
'RemoteAccess',
'seclogon',
'SstpSvc',
'LanmanServer',
'ShellHWDetection',
'SCardSvr',
'SCPolicySvc',
'SNMPTRAP',
'sppsvc',
'sppuinotify',
'SSDPSRV',
'StorSvc',
'TabletInputService',
'lmhosts',
'tapiSrv',
'upnphost',
'VSS',
'WebClient',
'WatAdminSvc',
'AudioSrv',
'AudioEndpointBuilder',
'SDRSVC',
'WbioSrvc',
'idsvc',
'WcsPlugInService',
'wcncsvc',
'WinDefend',
'WerSvc',
'Wecsvc',
'FontCache',
'stisvc',
'ehRecvr',
'ehSched',
'WMPNetworkSvc',
'FontCache3.0.0.0',
'WinRM',
'WinHttpAutoProxySvc',
'Wlansvc',
'wmiApSrv',
'LanmanWorkstation',
'WwanSvc',
'PerfHost'

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

#Sets Windows Update service and dependencies to automatic
Set-Service wuauserv -StartupType Automatic
Set-Service BITS -StartupType Automatic
Set-Service TrustedInstaller -StartupType Automatic

#Disable all network components except IPv4
ncpa.cpl

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

#Disables IGMP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Type DWORD -Value "0" -Force 

#Disable memory dumps
Get-WmiObject -Class Win32_OSRecoveryConfiguration -EnableAllPrivileges | >> Set-WmiInstance -Arguments @{DebugInfoType = 0}

#Disable Remote Desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1

#Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWORD –Value 0

#Internet Options:
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\CACHE" -Type DWORD -Name "Persistent" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main" -Type DWORD -Name "Enable Browser Extensions" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main" -Type DWORD -Name "DoNotTrack" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Type DWORD -Name "WarnonZoneCrossing" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Type DWORD -Name "WarnonBadCertRecving" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\PhishingFilter" -Type DWORD -Name "Enable" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Type DWORD -Name "iexplore.exe" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "" -Type DWORD -Name "" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "" -Type DWORD -Name "" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "" -Type DWORD -Name "" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "" -Type DWORD -Name "" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "" -Type DWORD -Name "" -Value 1 -ErrorAction SilentlyContinue

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
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type DWORD -Name "DefaultSecureProtocols" -Value 0x800 -ErrorAction SilentlyContinue
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

#Set UAC level to High
Import-Module .\SwitchUACLevel.psm1
Get-Command -Module SwitchUACLevel
Set-UACLevel 3
Write-Host Set UAC level to High

#Enables custom local security policies
Secedit /configure /db %temp%\temp.sdb /cfg Win7.inf

#Install .MSI Mozilla Firefox, Wireshark, MalwareBytes, CCleaner (WIP)


#Extract SysInternals (WIP)


#Cleaning up
Remove-Item -path .\Win7.INF
Remove-Item -path .\Win7.WFW
Remove-Item -path ..\Win7.zip
Remove-Item -path .\SwitchUACLevel.psm1

#Disable features
dism /online /Disable-Feature /FeatureName: Internet-Explorer-Optional-amd64
dism /online /Disable-Feature /FeatureName: MSRDC-Infrastructure
dism /online /Disable-Feature /FeatureName: Printing-XPSServices-Features
dism /online /Disable-Feature /FeatureName: Xps-Foundation-Xps-Viewer
dism /online /Disable-Feature /FeatureName: FaxServicesClientPackage
dism /online /Disable-Feature /FeatureName: Printing-Foundation-InternetPrinting-Client
dism /online /Disable-Feature /FeatureName: Printing-Foundation-Features
dism /online /Disable-Feature /FeatureName: TabletPCOG
dism /online /Disable-Feature /FeatureName: MediaCenter
dism /online /Disable-Feature /FeatureName: WindowsMediaPlayer
dism /online /Disable-Feature /FeatureName: MediaPlayback
dism /online /Disable-Feature /FeatureName: OpticalMediaDisc
dism /online /Disable-Feature /FeatureName: WindowsGadgetPlatform

#New standard user
Write-Warning "Enter password for new user account below."
$Passverb = Read-Host -AsSecureString
Net User Charles $Passverb /Add /Y
$Passverb = $NULL

#Clear PowerShell command history
Clear-History

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
