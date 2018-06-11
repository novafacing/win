#Created by Zamanry, 05/2018

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
'Dhcp',
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
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "DisabledComponents" -Value "0xFF" -Force #Disable IPv6 completely
$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'" #Disable 'Register this connection's addresses in DNS'
$NIC.SetDynamicDNSRegistration($false)
$NIC.SetTcpipNetbios(2) #Disable NetBIOS over TCP/IP
$NIC = [wmiclass]'Win32_NetworkAdapterConfiguration' #Disable LMHosts lookup
$NIC.enablewins($false,$false)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Value "0" #Disable IGMP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1 #Disable Remote Desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" –Value 0 #Disable Remote Assistance

#Flush caches (DNS, ARP, NetBIOS, routes, hosts):
Ipconfig /flushdns
Netsh interface ipv4 delete arpcache
Netsh interface ipv4 delete desinationcache
Netsh interface ipv4 delete neighbors
Netsh interface ipv4 delete winsservers "Local Area Connection" all
Push-Location
Set-Location "..\..\..\.."
$DriveLetter = Get-Location
Pop-Location
Move-Item -path ".\hosts" -destination "$DriveLetter\Windows\system32\drivers\etc\hosts" -force

#Misc.
Wmic recoveros set DebugInfoType = 0 #Disable memory dumps
Set-ItemProperty -Path "HKLM:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Value "0x1" –Force #Prevent Server Manager from opening at startup

#Enable/Disable File Explorer Folder Options:
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Advanced" -Name "Hidden" -Value 1 #Enable hidden files
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Advanced" -Name "HideFileExt" -Value 0 #Enable file extensions
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Advanced" -Name "SharingWizardOn" -Value 0 #Disable Sharing Wizard

#Disable Taskbar Properties:
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 #Disable Jump List items
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 #Disabl recent documents

#Disable outdated protocols:
Write-Host "Disabling PCT/SSL/TLS outdated protocols."
$Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
function DisableProtocol {
    New-Item -Path "$Path" -name "$Protocol" -Type Directory
    $Path = "$Path\$Protocol"
    New-Item -Path "$Path" -name "Client" -Type "Directory"
    New-Item -Path "$Path" -name "Server" -Type "Directory"
    Set-ItemProperty -Path "$Path\Client" -Name "DisabledByDefault" -Value 1
    Set-ItemProperty -Path "$Path\Client" -Name "Enabled" -Value 0
    Set-ItemProperty -Path "$Path\Server" -Name "DisabledByDefault" -Value 1
    Set-ItemProperty -Path "$Path\Server" -Name "Enabled" -Value 0
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
New-Item -Path "$Path" -name "$Protocol" -Type "Directory"
New-Item -Path "$Path" -name "Client" -Type "Directory"
New-Item -Path "$Path" -name "Server" -Type "Directory"
Set-ItemProperty -Path "$Path\Client" -Name "DisabledByDefault" -Value 0
Set-ItemProperty -Path "$Path\Client" -Name "Enabled" -Value 1
Set-ItemProperty -Path "$Path\Server" -Name "DisabledByDefault" -Value 0
Set-ItemProperty -Path "$Path\Server" -Name "Enabled" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DefaultSecureProtocols" -Value "0x800"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SecureProtocols" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "chUseStrongCrypto" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "chUseStrongCrypto" -Value 1
$Path = $NULL

#Disable SMBv1, v2, and v3 (Unnecessary without domain)
Write-Host "Disabling all SMB versions."
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
Sc.exe config mrxsmb10 start= disabled
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi
Sc.exe config mrxsmb20 start= disabled

#Set UAC level to High.
Write-Host "Setting UAC level to High."
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Type DWORD -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Type DWORD -Name "PromptOnSecureDesktop" -Value 1

#Enable a custom local security policy
Write-Host "Setting custom local security policy."
Secedit /import /cfg S12.inf /db S12.sdb
Secedit /configure /db S12.sdb

#Install .MSI Mozilla Firefox, Wireshark, MalwareBytes, CCleaner (WIP)

#Disable .MSI service
Set-Service "msiserver" -StartupType "Disabled"
Stop-Service "msiserver" -Force

#Cleaning up files
Write-Host "Cleaning up files."
Remove-Item -path ".\S12.INF" -ErrorAction SilentlyContinue
Remove-Item -path ".\S12.SDB" -ErrorAction SilentlyContinue
Remove-Item -path ".\S12.WFW" -ErrorAction SilentlyContinue
Remove-Item -path "..\S12.ZIP" -ErrorAction SilentlyContinue

#Disable features
Write-Host Removing uneccessary features.
dism /online /Disable-Feature /FeatureName: SmbDirect
dism /online /Disable-Feature /FeatureName: Internet-Explorer-Optional-amd64
dism /online /Disable-Feature /FeatureName: Printing-Client
dism /online /Disable-Feature /FeatureName: Printing-Client-Gui
dism /online /Disable-Feature /FeatureName: Printing-XPSServices-Features
dism /online /Disable-Feature /FeatureName: WindowsServerBackupSnapin
Remove-WindowsFeature -Name PowerShell-ISE

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

Write-Warning "Please restart once all features have been removed."

#Clear PowerShell command history
Clear-History

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
