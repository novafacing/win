#Created by Zamanry, 06/2018.
#Fully functioning as of 06/12/18.

#Import Windows Firewall
Write-Host "Installing firewall."
Netsh advfirewall import "Win7.wfw"

Write-Warning "Uncheck all items except IPv4."
Ncpa.cpl

#Disable & stop services
Write-Host "Disabling & stopping services."
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
		Set-Service $CrntService -StartupType "Disabled"
		Stop-Service $CrntService -Force
	}
	else {
		Write-Host "$CrntService not found."
	}
	$Index++
	$CrntService = $Services[$Index]
} while ($CrntService -ne $NULL)

#Sets Windows Update service and dependencies to automatic
Write-Host "Enabling Windows Update."
Set-Service "wuauserv" -StartupType "Automatic"
Set-Service "BITS" -StartupType "Automatic"
Set-Service "TrustedInstaller" -StartupType "Automatic"

#Disable unneccessary network connections:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "DisabledComponents" -Type "DWORD" -Value "0xFF" #Disable IPv6 completely
$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'" #Disable 'Register this connection's addresses in DNS'
$NIC.SetDynamicDNSRegistration($false)
$NIC.SetTcpipNetbios(2) #Disable NetBIOS over TCP/IP
$NIC = [wmiclass]'Win32_NetworkAdapterConfiguration' #Disable LMHosts lookup
$NIC.enablewins($false,$false)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Type "DWORD" -Value "0" #Disable IGMP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1 #Disable Remote Desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type "DWORD" –Value 0 #Disable Remote Assistance

#Flush caches (DNS, ARP, NetBIOS, routes, hosts):
Ipconfig /flushdns
Netsh interface ipv4 delete arpcache
Netsh interface ipv4 delete destinationcache
Netsh interface ipv4 delete neighbors
Netsh interface ipv4 delete winsservers "Local Area Connection" all
Push-Location
Set-Location "..\..\..\.."
$DriveLetter = Get-Location
Pop-Location
Move-Item -path ".\hosts" -destination "$DriveLetter\Windows\system32\drivers\etc\hosts" -force

#Misc.
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control" -Name "CrashControl" -Type "DWORD" -Value "0x0" #Disable memory dumps

#Enable/Disable File Explorer Folder Options:
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type "DWORD" -Value 1
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type "DWORD" -Value 0
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Type "DWORD" -Value 0

#Enable/Disable Internet Options:
Write-Host "Enabling/Disabling Internet Options."
$Path = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$Path1 = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer"
Set-ItemProperty -Path "$Path1\Main" -Name "Start Page" -Type "String" -Value "https://start.duckduckgo.com/"
New-Item -Path "$Path1" -Name "Privacy" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path1\Privacy" -Name "ClearBrowsingHistoryOnExit" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path" -Name "SyncMode5" -Type "DWORD" -Value 3
New-Item -Path "$Path" -Name "Url History" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Url History" -Name "DaysToKeep" -Type "DWORD" -Value 0
New-Item -Path "$Path1" -Name "BrowserStorage" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path1\BrowserStorage" -Name "IndexedDB" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path1\BrowserStorage\IndexedDB" -Name "AllowWebsiteDatabases" -Type "DWORD" -Value 0
New-Item -Path "$Path1\BrowserStorage" -Name "AppCache" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path1\BrowserStorage\AppCache" -Name "AllowWebsiteCaches" -Type "DWORD" -Value 0
Set-ItemProperty -Path "$Path1\TabbedBrowsing" -Name "WarnOnClose" -Type "DWORD" -Value 0
Set-ItemProperty -Path "$Path1\TabbedBrowsing" -Name "NetTabPageShow" -Type "DWORD" -Value 1
#Privacy Tab
Set-ItemProperty -Path "$Path1\New Windows" -Name "PopupMgr" -Type "DWORD" -Value 1
#Programs Tab
New-Item -Path "$Path" -Name "Activities" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path\Activities" -Name "Email" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path\Activities\Email" -Name "live.com" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Activities\Email\live.com" -Name "Enabled" -Type "DWORD" -Value 0
New-Item -Path "$Path\Activities" -Name "Map" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path\Activities\Map" -Name "bing.com" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Activities\Map\bing.com" -Name "Enabled" -Type "DWORD" -Value 0
New-Item -Path "$Path\Activities" -Name "Translate" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path\Activities\Translate" -Name "microsofttranslator.com" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Activities\Translate\microsofttranslator.com" -Name "Enabled" -Type "DWORD" -Value 0
#Advanced tab
Set-ItemProperty -Path "$Path1\Main" -Name "DisableScriptDebuggerIE" -Type "String" -Value "yes"
Set-ItemProperty -Path "$Path1\Main" -Name "Disable Script Debugger" -Type "String" -Value "yes"
Set-ItemProperty -Path "$Path1\Recovery" -Name "AutoRecover" -Type "DWORD" -Value 2
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\FTP" -Name "Use Web Based FTP" -Type "String" -Value "yes"
Set-ItemProperty -Path "$Path1\Main" -Name "Enable Browser Extensions" -Type "DWORD" -Value 0
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\FTP" -Name "Use PASV" -Type "String" -Value "no"
Set-ItemProperty -Path "$Path" -Name "EnableHttp1_1" -Type "DWORD" -Value 1
New-Item -Path "$Path1\Main" -Name "FeatureControl" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path1\Main\FeatureControl" -Name "FEATURE_LOCALMACHINE_LOCKDOWN" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Name "iexplore.exe" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path1\Download" -Name "RunInvalid" -Type "DWORD" -Value 0
Set-ItemProperty -Path "$Path" -Name "CertificateRevocation" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path1\Download" -Name "CheckExeSignatures" -Type "String" -Value "yes"
Set-ItemProperty -Path "$Path\CACHE" -Name "Persistent" -Type "DWORD" -Value 0
Set-ItemProperty -Path "$Path1\Main" -Name "DOMStorage" -Type "DWORD" -Value 0
Set-ItemProperty -Path "$Path1\PhishingFilter" -Name "Enable" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path" -Name "EnforceP3PValidity" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path1\Main" -Name "DoNotTrack" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path" -Name "WarnonBadCertRecving" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path" -Name "WarnonZoneCrossing" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path" -Name "WarnOnPostRedirect" -Type "DWORD" -Value 1
$Path1 = $NULL

#Disable features
OptionalFeatures

#Disable outdated protocols:
Write-Host "Disabling PCT/SSL/TLS outdated protocols."
$Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
function DisableProtocol {
	New-Item -Path "$Path" -Name "$Protocol" -Type Directory -ErrorAction SilentlyContinue
	$Path = "$Path\$Protocol"
	New-Item -Path "$Path" -Name "Client" -Type "Directory" -ErrorAction SilentlyContinue
	New-Item -Path "$Path" -Name "Server" -Type "Directory" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "$Path\Client" -Type "DWORD" -Name "DisabledByDefault" -Value 1
	Set-ItemProperty -Path "$Path\Client" -Type "DWORD" -Name "Enabled" -Value 0
	Set-ItemProperty -Path "$Path\Server" -Type "DWORD" -Name "DisabledByDefault" -Value 1
	Set-ItemProperty -Path "$Path\Server" -Type "DWORD" -Name "Enabled" -Value 0
}

$Protocols = 'PCT 1.0', 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1'
$Index = 0
$Protocol = $Protocols[$Index]
do {
	DisableProtocol
	$Index++
	$Protocol = $Protocols[$Index]
} while ($Protocol -ne $NULL)

#Enable TLS 1.2
$Protocol = "TLS 1.2"
New-Item -Path "$Path" -Name "$Protocol" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path" -Name "Client" -Type "Directory" -ErrorAction SilentlyContinue
New-Item -Path "$Path" -Name "Server" -Type "Directory" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "$Path\Client" -Type "DWORD" -Name "DisabledByDefault" -Value 0
Set-ItemProperty -Path "$Path\Client" -Type "DWORD" -Name "Enabled" -Value 1
Set-ItemProperty -Path "$Path\Server" -Type "DWORD" -Name "DisabledByDefault" -Value 0
Set-ItemProperty -Path "$Path\Server" -Type "DWORD" -Name "Enabled" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type "DWORD" -Name "DefaultSecureProtocols" -Type "DWORD" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type "DWORD" -Name "DefaultSecureProtocols" -Type "DWORD" -Value "0x800"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Type "DWORD" -Name "SecureProtocols" -Type "DWORD" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Type "DWORD" -Name "chUseStrongCrypto" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Type "DWORD" -Name "chUseStrongCrypto" -Value 1
$Path = $NULL

#Disable features continued
Write-Warning "Please uncheck all items except .NET, and Windows Search."

#Disable SMBv1, v2, and v3 (Unnecessary without domain)
Write-Host "Disabling all SMB versions."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Type "DWORD" -Name "SMB1" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Type "DWORD" -Name "SMB2" -Value 0
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi
sc.exe config mrxsmb20 start= disabled

#Set UAC level to High
Write-Host "Setting UAC level to High."
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Type "DWORD" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Type "DWORD" -Name "PromptOnSecureDesktop" -Value 1

#Enable a custom local security policy
Write-Host "Setting custom local security policy."
Secedit /import /cfg Win7.inf /db Win7.sdb
Secedit /configure /db Win7.sdb

#Install .MSI Mozilla Firefox, Wireshark, MalwareBytes, CCleaner (WIP)

#Disable .MSI service
Set-Service "msiserver" -StartupType "Disabled"
Stop-Service "msiserver" -Force

#Cleaning up files
Write-Host "Cleaning up files."
Remove-Item -path ".\Win7.INF" -ErrorAction SilentlyContinue
Remove-Item -path ".\Win7.SDB" -ErrorAction SilentlyContinue
Remove-Item -path ".\Win7.WFW" -ErrorAction SilentlyContinue
Remove-Item -path "..\Win7.ZIP" -ErrorAction SilentlyContinue

#Create a standard user
Write-Warning "Creating a new user. DO NOT name them Admin, Guest, Root, etc."
$Userverb = Read-Host -Prompt "Enter a new username"
$ctr = 0
do {
	if ($ctr -gt 0) {
		Write-Host " "
		Write-Warning "Passwords did not match."
	}
	$Passverb1 = Read-Host -Prompt "Enter password"-AsSecureString
	$Passverb2 = Read-Host -Prompt "Re-enter password" -AsSecureString
	$ctr++
	If (([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passverb1))) -eq ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passverb2)))) {
		$Matched = $True
	}
} while ($Matched -ne $True)
Net User $Userverb $Passverb1 /Add /Y
$Userverb, $Passverb1, $Passverb2 = $NULL

Write-Warning "Please restart PC once all optional features have been removed."

#Clear PowerShell command history
Clear-History

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
