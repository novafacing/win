#Created by Zamanry, 05/2018
#Fully functioning as of 06/12/18.

#Import firewall
Write-Host "Installing firewall."
Netsh advfirewall import "S12.wfw"

#Disable & stop services
Write-Host "Disabling & stopping services."
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
'DPS',
'MozillaMaintenance',
'PlugPlay',
'WerSvc',
'PolicyAgent',
'IKEEXT',
'hidserv',
'WdiSystemHost',
'WdiServiceHost',
'RpcLocator',
'KPSSVC',
'AppMgmt',
'Netlogon',
'MMCSS',
'Eaphost'

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

#Sets Windows Update service to automatic
Write-Host "Enabling Windows Update."
Set-Service "wuauserv" -StartupType "Automatic"
Set-Service "BITS" -StartupType "Automatic"

#Disable unnecessary network connections:
Write-Host "Disabling network components."
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_tcpip6'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_rspndr'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_lltdio'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_implat'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_msclient'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_pacer'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_server'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "DisabledComponents" -Type "DWORD" -Value "0xFF" #Disable IPv6 completely
$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'" #Disable 'Register this connection's addresses in DNS'
$NIC.SetDynamicDNSRegistration($false)
$NIC.SetTcpipNetbios(2) #Disable NetBIOS over TCP/IP
$NIC = [wmiclass]'Win32_NetworkAdapterConfiguration' #Disable LMHosts lookup
$NIC.enablewins($false,$false)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Type "DWORD" -Value 0 #Disable IGMP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type "DWORD" –Value 1 #Disable Remote Desktop
New-Item -Path "HKLM:\System\CurrentControlSet\Control" -Name "Remote Assistance" -Type "Directory"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type "DWORD" –Value 0 #Disable Remote Assistance

#Flush caches (DNS, ARP, NetBIOS, routes, hosts):
Ipconfig /flushdns
Netsh interface ipv4 delete arpcache
Netsh interface ipv4 delete destinationcache
Netsh interface ipv4 delete neighbors
Netsh interface ipv4 delete winsservers "Ethernet" all
Push-Location
Set-Location "..\..\..\.."
$DriveLetter = Get-Location
Pop-Location
Move-Item -Path ".\hosts" -destination "$DriveLetter\Windows\system32\drivers\etc\hosts" -Force

#Misc.
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control" -Name "CrashControl"-Type "DWORD" -Value "0x0" #Disable memory dumps
Set-ItemProperty -Path "HKLM:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon"-Type "DWORD" -Value "0x1" #Prevent Server Manager from opening at startup

#Enable/Disable File Explorer options:
$Path = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path "$Path" -Name "Hidden" -Type "DWORD" -Value 1 #Enable hidden files
Set-ItemProperty -Path "$Path" -Name "HideFileExt" -Type "DWORD" -Value 0 #Enable file extensions
Set-ItemProperty -Path "$Path" -Name "SharingWizardOn" -Type "DWORD" -Value 0 #Disable Sharing Wizard
Set-ItemProperty -Path "$Path" -Name "Start_TrackProgs" -Type "DWORD" -Value 0 #Disable Jump List items
Set-ItemProperty -Path "$Path" -Name "Start_TrackDocs" -Type "DWORD" -Value 0 #Disable recent documents

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

#Disable outdated protocols:
Write-Host "Disabling PCT/SSL/TLS outdated protocols."
$Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
function DisableProtocol {
    New-Item -Path "$Path" -Name "$Protocol" -Type "Directory" -ErrorAction SilentlyContinue
    $Path = "$Path\$Protocol"
    New-Item -Path "$Path" -Name "Client" -Type "Directory" -ErrorAction SilentlyContinue
    New-Item -Path "$Path" -Name "Server" -Type "Directory" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "$Path\Client" -Name "DisabledByDefault" -Type "DWORD" -Value 1
    Set-ItemProperty -Path "$Path\Client" -Name "Enabled" -Type "DWORD" -Value 0
    Set-ItemProperty -Path "$Path\Server" -Name "DisabledByDefault" -Type "DWORD" -Value 1
    Set-ItemProperty -Path "$Path\Server" -Name "Enabled" -Type "DWORD" -Value 0
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
Set-ItemProperty -Path "$Path\Client" -Name "DisabledByDefault" -Type "DWORD" -Value 0
Set-ItemProperty -Path "$Path\Client" -Name "Enabled" -Type "DWORD" -Value 1
Set-ItemProperty -Path "$Path\Server" -Name "DisabledByDefault" -Type "DWORD" -Value 0
Set-ItemProperty -Path "$Path\Server" -Name "Enabled" -Type "DWORD" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols"-Type "DWORD" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols" -Type "DWORD" -Value "0x800"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SecureProtocols" -Type "DWORD" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "chUseStrongCrypto" -Type "DWORD" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "chUseStrongCrypto" -Type "DWORD" -Value 1
$Path = $NULL

#Disable SMBv1, v2, and v3 (Unnecessary without domain)
Write-Host "Disabling all SMB versions."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
Sc.exe config mrxsmb10 start= disabled
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
Sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi
Sc.exe config mrxsmb20 start= disabled

#Set UAC level to High.
Write-Host "Setting UAC level to High."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type "DWORD" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type "DWORD" -Value 1

#Enable a custom local security policy
Write-Host "Setting custom local security policy."
Secedit /import /cfg S12.inf /db S12.sdb
Secedit /configure /db S12.sdb

#Install .MSI Mozilla Firefox, Wireshark, MalwareBytes, CCleaner (WIP)

#Cleaning up files
Write-Host "Cleaning up files."
Remove-Item -Path ".\S12.INF" -ErrorAction SilentlyContinue
Remove-Item -Path ".\S12.SDB" -ErrorAction SilentlyContinue
Remove-Item -Path ".\S12.WFW" -ErrorAction SilentlyContinue
Remove-Item -Path "..\S12.ZIP" -ErrorAction SilentlyContinue

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

#Disable features
Write-Host Removing uneccessary features.
Dism /Online /Disable-Feature /FeatureName:SmbDirect /NoRestart
Dism /Online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64 /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-Client /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-Client-Gui /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-XPSServices-Features /NoRestart
Dism /Online /Disable-Feature /FeatureName:WindowsServerBackupSnapin /NoRestart
Remove-WindowsFeature -Name PowerShell-ISE

Write-Warning "Restarting in 10 seconds..."
Shutdown /r

#Clear PowerShell command history
Clear-History

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
