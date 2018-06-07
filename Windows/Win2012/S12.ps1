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
Set-Service "RpcSs" -StartupType "Automatic"

#Disable unnecessary network connections:
Write-Host "Disabling network components."
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_tcpip6'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_rspndr'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_lltdio'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_implat'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_msclient'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_pacer'
Disable-NetAdapterBinding -Name "*" -ComponentID 'ms_server'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "DisabledComponents" -Type "REG_DWORD" -Value "0xFF" -Force #Disable IPv6 completely
$NIC = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'" #Disable 'Register this connection's addresses in DNS'
$NIC.SetDynamicDNSRegistration($false)
$NIC.SetTcpipNetbios(2) #Disable NetBIOS over TCP/IP
$NIC = [wmiclass]'Win32_NetworkAdapterConfiguration' #Disable LMHosts lookup
$NIC.enablewins($false,$false)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Type "REG_DWORD" -Value "0" #Disable IGMP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1 #Disable Remote Desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type "REG_DWORD" –Value 0 #Disable Remote Assistance
$NIC = $NULL

#Flush caches (DNS, ARP, NetBIOS, routes, hosts):
Ipconfig /flushdns
Netsh interface ipv4 delete arpcache
Netsh interface ipv4 delete desinationcache
Netsh interface ipv4 delete neighbors
Netsh interface ipv4 delete winsservers
$Path = Get-Location
Set-Location "..\..\..\.."
$DriveLetter = Get-Location
Move-Item -path "$Path\hosts" -destination "$DriveLetter\Windows\system32\drivers\etc\hosts" -force
Set-Location $Path
$DriveLetter = $NULL

Wmic recoveros set DebugInfoType = 0 #Disable memory dumps
Set-ItemProperty -Path "HKLM:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Type "REG_DWORD" -Value "0x1" –Force #Prevent Server Manager from opening at startup
 
#Enable/Disable File Explorer Folder Options:
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Advanced" -Type "REG_DWORD" -Name "Hidden" -Value 1
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Advanced" -Type "REG_DWORD" -Name "HideFileExt" -Value 0
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Advanced" -Type "REG_DWORD" -Name "SharingWizardOn" -Value 0

#Disable Taskbar Properties:
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 #Disable Jump List items
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 #Disabl recent documents

#Disable outdated protocols:
Write-Host "Disabling PCT/SSL/TLS outdated protocols."
$Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
function DisableProtocol {
    New-Item -Path "$Path" -name "$Protocol" -Type Directory
    $Path = "$Path\$Protocol"
    New-Item -Path "$Path" -name "Client" -Type "Directory"
    New-Item -Path "$Path" -name "Server" -Type "Directory"
    Set-ItemProperty -Path "$Path\Client" -Type "REG_DWORD" -Name "DisabledByDefault" -Value 1
    Set-ItemProperty -Path "$Path\Client" -Type "REG_DWORD" -Name "Enabled" -Value 0
    Set-ItemProperty -Path "$Path\Server" -Type "REG_DWORD" -Name "DisabledByDefault" -Value 1
    Set-ItemProperty -Path "$Path\Server" -Type "REG_DWORD" -Name "Enabled" -Value 0
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
Set-ItemProperty -Path "$Path\Client" -Type "REG_DWORD" -Name "DisabledByDefault" -Value 0
Set-ItemProperty -Path "$Path\Client" -Type "REG_DWORD" -Name "Enabled" -Value 1
Set-ItemProperty -Path "$Path\Server" -Type "REG_DWORD" -Name "DisabledByDefault" -Value 0
Set-ItemProperty -Path "$Path\Server" -Type "REG_DWORD" -Name "Enabled" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type "REG_DWORD" -Name "DefaultSecureProtocols" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Type "REG_DWORD" -Name "DefaultSecureProtocols" -Value "0x800"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Type "REG_DWORD" -Name "SecureProtocols" -Value "0x800"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Type "REG_DWORD" -Name "chUseStrongCrypto" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Type "REG_DWORD" -Name "chUseStrongCrypto" -Value 1
$Path = $NULL

#Disable SMBv1, v2, and v3 (Unnecessary without domain)
Write-Host "Disabling all SMB versions."
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Sc.exe config lanmanworkstation depend = bowser/mrxsmb20/nsi
Sc.exe config mrxsmb10 start = disabled
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Sc.exe config lanmanworkstation depend = bowser/mrxsmb10/nsi
Sc.exe config mrxsmb20 start = disabled

#Set UAC level to High.
Write-Host "Setting UAC level to High."
Import-Module ".\SwitchUACLevel.psm1"
Get-Command -Module "SwitchUACLevel"
Set-UACLevel 3

#Enable a custom local security policy
Write-Host "Setting custom local security policy."
Secedit /configure /db %temp%\temp.sdb /cfg S12.inf

#Install .MSI Mozilla Firefox, Wireshark, MalwareBytes, CCleaner (WIP)

#Disable .MSI service
Set-Service "msiserver" -StartupType "Disabled"
Stop-Service "msiserver" -Force

#Cleaning up files
Write-Host "Cleaning up files."
Remove-Item -path ".\S12.INF"
Remove-Item -path ".\S12.WFW"
Remove-Item -path "..\S12.zip"
Remove-Item -path ".\SwitchUACLevel.psm1"

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
Write-Warning "Creating a standard user. Enter a username that is not Admin, Guest, Root, etc."
$Userverb = Read-Host
Write-Warning "Enter a secure password for the account below. Don't worry, it's encrypted."
$Passverb = Read-Host -AsSecureString
Net User $Userverb $Passverb /Add /Y
$Userverb, $Passverb = $NULL

#Clear PowerShell command history
Clear-History

Write-Warning "Please restart once all features have been removed."

#Restricts PowerShell scripts
Set-ExecutionPolicy restricted
