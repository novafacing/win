#Based off the 08/18/2018 version of https://github.com/asbtho/Powershell-Scripts/blob/master/GetProfilesModifiedWithin.ps1
#This script checks the last time a file was written too.

$Hours = 8
$Path = (get-location).Drive.Name
$Path = "${Path}:\"
$Output = ".\Log.txt"
Clear-Content $Output -ErrorAction SilentlyContinue
$ParentDir = Get-ChildItem -Path $Path -Directory -Force -ErrorAction SilentlyContinue
Write-Warning "Scanning files..."

Foreach ($Dir in $ParentDir) {
  $ChildList = Get-ChildItem -Path $Path$Dir -Recurse -File -ErrorAction SilentlyContinue
  Foreach ($Child in $ChildList) {
    If ($Child.LastWriteTime -GT (Get-Date).AddHours(-$Hours)) {
      $CurrentTime = Get-Date
      $PathOutput = $Child.FullName
      $TimeOutput = $CurrentTime - $Child.LastWriteTime
      $OutputString = "$PathOutput`t`t| Last write: $TimeOutput"
      Out-File -Append -Filepath $Output -InputObject $OutputString
      Break
    }
  }
}
