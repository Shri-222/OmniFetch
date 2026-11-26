# OmniFetch Windows Shortcut Generator
$targetExe = "C:\Users\shrey\Desktop\OmniFetch\dist\OmniFetch\OmniFetch.exe"
$workingDir = "C:\Users\shrey\Desktop\OmniFetch\dist\OmniFetch"
$iconPath = "C:\Users\shrey\Desktop\OmniFetch\app\assets\omnifetch.ico"

$WshShell = New-Object -ComObject WScript.Shell

# 1. Desktop Shortcut
$desktopPath = [Environment]::GetFolderPath("Desktop")
$desktopLnk = Join-Path $desktopPath "OmniFetch.lnk"
$shortcut1 = $WshShell.CreateShortcut($desktopLnk)
$shortcut1.TargetPath = $targetExe
$shortcut1.WorkingDirectory = $workingDir
$shortcut1.IconLocation = "$iconPath,0"
$shortcut1.Description = "OmniFetch Native Download Manager"
$shortcut1.Save()
Write-Host "Created Desktop shortcut: $desktopLnk"

# 2. Start Menu Shortcut
$programsPath = [Environment]::GetFolderPath("Programs")
$startMenuLnk = Join-Path $programsPath "OmniFetch.lnk"
$shortcut2 = $WshShell.CreateShortcut($startMenuLnk)
$shortcut2.TargetPath = $targetExe
$shortcut2.WorkingDirectory = $workingDir
$shortcut2.IconLocation = "$iconPath,0"
$shortcut2.Description = "OmniFetch Native Download Manager"
$shortcut2.Save()
Write-Host "Created Start Menu shortcut: $startMenuLnk"
