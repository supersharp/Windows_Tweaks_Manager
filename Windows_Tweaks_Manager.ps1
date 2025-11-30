<#
.SYNOPSIS
    Master Script: Admin Terminal + UI Tweaks + Xbox + Startup Task + Shortcuts + Secure DNS.
    
.DESCRIPTION
#>

# Force Console to use UTF-8 to display ASCII art correctly
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ==============================================================================
# 1. AUTO-ELEVATE
# ==============================================================================
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# ==============================================================================
# 2. CONFIGURATION
# ==============================================================================
$ScriptPath = $PSScriptRoot
$ResourcePath = Join-Path $ScriptPath "Resources"
$XboxDepPath = Join-Path $ScriptPath "xbox_app_dependencies"
$Ver = "0.0.1"

# Set Window Title
$host.ui.RawUI.WindowTitle = "Windows Tweaks Manager $Ver"

# Assets
$IconSource = Join-Path $ResourcePath "terminal.ico"
$IconDest = "C:\Windows\terminal.ico"

# System Paths
$StartMenuPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"

# Registry Paths for Terminal
$RegPath_PS1 = "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.ps1\shell\RunInWTAdmin"
$RegPath_BAT = "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.bat\shell\RunInWTAdmin"
$RegPath_CMD = "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.cmd\shell\RunInWTAdmin"
$RegPath_Folder = "Registry::HKEY_CLASSES_ROOT\Directory\shell\OpenElevatedWT"
$RegPath_Bg = "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\OpenElevatedWT"

# Terminal Commands
$Cmd_Folder = 'powershell.exe -WindowStyle Hidden -Command "Start-Process wt.exe -ArgumentList ''-d \""%V\""'' -Verb RunAs"'
$Cmd_PS1 = 'powershell.exe -WindowStyle Hidden -Command "Start-Process wt.exe -ArgumentList ''-p \""Windows PowerShell\"" powershell.exe -ExecutionPolicy Bypass -NoExit -File \"\"\""%1\"\"\""'' -Verb RunAs"'
$Cmd_Batch = 'powershell.exe -WindowStyle Hidden -Command "Start-Process wt.exe -ArgumentList ''-p \""Command Prompt\"" cmd.exe /k \"\"\""%1\"\"\""'' -Verb RunAs"'

# ==============================================================================
# 3. HELPER FUNCTIONS
# ==============================================================================
function Pause-And-Return {
    Write-Host "`n------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Operation Complete." -ForegroundColor Green
    Write-Host "Press [Enter] to return to Main Menu, or [X] to Exit..." -ForegroundColor Yellow
    
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($key.Character -eq 'x' -or $key.Character -eq 'X') {
        $host.ui.RawUI.WindowTitle = "Administrator: Windows PowerShell"; Clear-Host; Exit
    }
}



# ==============================================================================
# 4. FUNCTIONS: TERMINAL CONTEXT MENU
# ==============================================================================
function Install-TerminalMenu {
    Write-Host "`n[Installing Terminal Menu...]" -ForegroundColor Cyan
    
    if (Test-Path $IconSource) {
        Copy-Item -Path $IconSource -Destination $IconDest -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Warning "terminal.ico not found in Resources folder. Menu will work without icon."
    }

    # 1. PowerShell (.ps1)
    New-Item -Path $RegPath_PS1 -Force | Out-Null
    New-ItemProperty -Path $RegPath_PS1 -Name "(default)" -Value "Run in Terminal (Admin)" -Force | Out-Null
    New-ItemProperty -Path $RegPath_PS1 -Name "Icon" -Value $IconDest -Force | Out-Null
    New-Item -Path "$RegPath_PS1\command" -Force | Out-Null
    New-ItemProperty -Path "$RegPath_PS1\command" -Name "(default)" -Value $Cmd_PS1 -Force | Out-Null
    Write-Host " + Added to .ps1 files" -ForegroundColor Green

    # 2. Batch (.bat and .cmd)
    foreach ($path in @($RegPath_BAT, $RegPath_CMD)) {
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -Path $path -Name "(default)" -Value "Run in Terminal (Admin)" -Force | Out-Null
        New-ItemProperty -Path $path -Name "Icon" -Value $IconDest -Force | Out-Null
        New-Item -Path "$path\command" -Force | Out-Null
        New-ItemProperty -Path "$path\command" -Name "(default)" -Value $Cmd_Batch -Force | Out-Null
    }
    Write-Host " + Added to .bat and .cmd files" -ForegroundColor Green

    # 3. Folder & Background
    foreach ($path in @($RegPath_Folder, $RegPath_Bg)) {
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -Path $path -Name "(default)" -Value "Open in Terminal (Admin)" -Force | Out-Null
        New-ItemProperty -Path $path -Name "Icon" -Value $IconDest -Force | Out-Null
        New-Item -Path "$path\command" -Force | Out-Null
        New-ItemProperty -Path "$path\command" -Name "(default)" -Value $Cmd_Folder -Force | Out-Null
    }
    Write-Host " + Added to Folders and Background" -ForegroundColor Green
}

function Uninstall-TerminalMenu {
    Write-Host "`n[Removing Terminal Menu...]" -ForegroundColor Cyan
    
    # Remove Registry Keys
    Remove-Item -Path $RegPath_PS1 -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path $RegPath_BAT -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path $RegPath_CMD -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path $RegPath_Folder -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path $RegPath_Bg -Recurse -ErrorAction SilentlyContinue
    
    # Cleanup old method if present
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\RunInWTAdmin" -Recurse -ErrorAction SilentlyContinue
    
    Write-Host " + Terminal Context Menus Removed" -ForegroundColor Green
}

# ==============================================================================
# 5. FUNCTIONS: SYSTEM TWEAKS (DEBLOAT & TASKS)
# ==============================================================================
function Install-SystemTweaks {
    Write-Host "`n[Applying System Tweaks...]" -ForegroundColor Cyan
    Write-Host "Note: Explorer will restart automatically at the end." -ForegroundColor Gray

    # --- 1. SCHEDULED TASK: Low Audio Latency ---
    $TaskName = "LowAudioLatency_Startup"
    $TaskExe = Join-Path $ResourcePath "low_audio_latency.exe"

    if (Test-Path $TaskExe) {
        Write-Host " + Configuring Startup Task: $TaskName" -ForegroundColor Yellow
        $Action = New-ScheduledTaskAction -Execute $TaskExe
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Principal = New-ScheduledTaskPrincipal -UserId "System" -RunLevel Highest
        $Settings = New-ScheduledTaskSettingsSet -WakeToRun -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
        
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
        Write-Host "   Done." -ForegroundColor Green
    }
    else {
        Write-Warning "   File 'low_audio_latency.exe' not found in Resources folder. Task skipped."
    }

    # --- 2. DEPLOY SHORTCUTS ---
    Write-Host " + Deploying Start Menu Shortcuts..." -ForegroundColor Yellow
    $UserShortcuts = @("Microsoft Store.lnk", "Windows Update.url", "Realtek Audio Console.lnk")
    
    foreach ($lnk in $UserShortcuts) {
        $SourceLnk = Join-Path $ResourcePath $lnk
        if (Test-Path $SourceLnk) {
            Copy-Item -Path $SourceLnk -Destination $StartMenuPath -Force
            Write-Host "   + Copied: $lnk" -ForegroundColor Green
        }
    }

    # --- 3. SECURE DNS (DoH + IPv4/IPv6 Assignment) ---
    Write-Host " + Configuring DNS (Cloudflare+Google) with DoH & Fallback..." -ForegroundColor Yellow
    try {
        # Cloudflare
        Set-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $True -AutoUpgrade $True -ErrorAction SilentlyContinue
        Set-DnsClientDohServerAddress -ServerAddress '1.0.0.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $True -AutoUpgrade $True -ErrorAction SilentlyContinue
        Set-DnsClientDohServerAddress -ServerAddress '2606:4700:4700::1111' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $True -AutoUpgrade $True -ErrorAction SilentlyContinue
        
        # Google
        Set-DnsClientDohServerAddress -ServerAddress '8.8.8.8' -DohTemplate 'https://dns.google/dns-query' -AllowFallbackToUdp $True -AutoUpgrade $True -ErrorAction SilentlyContinue
        Set-DnsClientDohServerAddress -ServerAddress '8.8.4.4' -DohTemplate 'https://dns.google/dns-query' -AllowFallbackToUdp $True -AutoUpgrade $True -ErrorAction SilentlyContinue
        Set-DnsClientDohServerAddress -ServerAddress '2001:4860:4860::8888' -DohTemplate 'https://dns.google/dns-query' -AllowFallbackToUdp $True -AutoUpgrade $True -ErrorAction SilentlyContinue

        # Apply IPs
        $ActiveAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        if ($ActiveAdapters) {
            foreach ($adapter in $ActiveAdapters) {
                Write-Host "   Applying DNS to adapter: $($adapter.Name)" -NoNewline
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888") -ErrorAction SilentlyContinue
                Write-Host " [OK]" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Warning "   DNS configuration failed."
    }

    # --- 4. REGISTRY TWEAKS ---
    
    # Restore Classic Context Menu (HKCU)
    $Key = "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InProcServer32"
    if (!(Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
    New-ItemProperty -Path $Key -Name "(default)" -Value "" -Force | Out-Null
    Write-Host " + Classic Context Menu Enabled" -ForegroundColor Green

    # Disable Copilot, Recall, Edge Bar, Search Suggestions
    New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HubsSidebarEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -PropertyType DWord -Force | Out-Null
    try { DISM /Online /Disable-Feature /FeatureName:"Recall" /NoRestart | Out-Null } catch {}
    Write-Host " + Copilot, Recall, Edge Bar, Search Suggestions Disabled" -ForegroundColor Green

    # --- REMOVING XBOX APPS ---
    Write-Host " + Removing All Xbox Related Apps..." -ForegroundColor Yellow
    
    $OldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    
    Get-AppxPackage *Xbox* | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage *GamingApp* | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage *XboxGamingOverlay* | Remove-AppxPackage -ErrorAction SilentlyContinue

    $ProgressPreference = $OldProgress
    Write-Host "   Done." -ForegroundColor Green
    
    # Disable Game DVR (Registry)
    $GameDVRPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
    $GameConfigPath = "HKCU:\System\GameConfigStore"
    if (!(Test-Path $GameDVRPath)) { New-Item -Path $GameDVRPath -Force | Out-Null }
    if (!(Test-Path $GameConfigPath)) { New-Item -Path $GameConfigPath -Force | Out-Null }
    Set-ItemProperty -Path $GameDVRPath -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force | Out-Null
    Set-ItemProperty -Path $GameConfigPath -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force | Out-Null
    Write-Host " + Game DVR Disabled" -ForegroundColor Green

    # Remove Home, Gallery, Previous Versions
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_36354489\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Recurse -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value "hide:home" -Force | Out-Null
    
    $PrevVerGUID = "{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\$PrevVerGUID" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\$PrevVerGUID" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\$PrevVerGUID" -Recurse -ErrorAction SilentlyContinue
    Write-Host " + Home, Gallery, Previous Versions Removed" -ForegroundColor Green

    # Remove Compatibility, ShellNew
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\.lnk\ShellNew" -Recurse -ErrorAction SilentlyContinue
    $BlockKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
    if (!(Test-Path $BlockKey)) { New-Item -Path $BlockKey -Force | Out-Null }
    New-ItemProperty -Path $BlockKey -Name "{1d27f844-3a1f-4410-85ac-14651078412d}" -Value "" -Force | Out-Null

    # Hide "Pin to Quick Access" and "Add to Favorites"
    $PinKeys = @(
        "Registry::HKEY_CLASSES_ROOT\Folder\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\Drive\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\*\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\*\shell\pintohomefile"
    )
    foreach ($key in $PinKeys) { 
        if (Test-Path -LiteralPath $key) { 
            # New-ItemProperty supports LiteralPath in PS 5.1
            New-ItemProperty -LiteralPath $key -Name "ProgrammaticAccessOnly" -Value "" -Force | Out-Null 
        } 
    }
    Write-Host " + UI Cleanup (ShellNew, Compatibility, Pin/Favs)" -ForegroundColor Green

    # --- 5. TAKE OWNERSHIP CONTEXT MENU (Safe .NET Method) ---
    Write-Host " + Adding 'Take Ownership' Context Menu..." -ForegroundColor Yellow
    
    # File Command (Files, DLLs)
    $CmdFile = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l & pause'
    # Folder/Drive Command (Recursive) 
    $CmdDir = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q & pause'

    $Targets = @{
        "*"         = $CmdFile
        "dllfile"   = $CmdFile
        "Directory" = $CmdDir
        "Drive"     = $CmdDir
    }

    $HKCR = [Microsoft.Win32.Registry]::ClassesRoot

    foreach ($Target in $Targets.Keys) {
        $CommandString = $Targets[$Target]
        $SubKeyPath = "$Target\shell\runas"
        
        Remove-Item -LiteralPath "Registry::HKEY_CLASSES_ROOT\$SubKeyPath" -Recurse -ErrorAction SilentlyContinue

        try {
            $ShellKey = $HKCR.CreateSubKey($SubKeyPath, $true)
            $ShellKey.SetValue("", "Take Ownership")
            $ShellKey.SetValue("HasLUAShield", "")
            $ShellKey.SetValue("NoWorkingDirectory", "")
            $ShellKey.SetValue("Position", "middle")
            
            $CommandKey = $ShellKey.CreateSubKey("command", $true)
            $CommandKey.SetValue("", $CommandString)
            $CommandKey.SetValue("IsolatedCommand", $CommandString)
            
            $CommandKey.Close()
            $ShellKey.Close()
        }
        catch {
            Write-Warning "   Failed to create key for $Target : $_"
        }
    }

    # Reset exefile
    $ExePath = "Registry::HKEY_CLASSES_ROOT\exefile\shell\runas"
    Remove-Item -LiteralPath $ExePath -Recurse -ErrorAction SilentlyContinue
    $HKCR.CreateSubKey("exefile\shell\runas").SetValue("HasLUAShield", "")
    $CmdKey = $HKCR.CreateSubKey("exefile\shell\runas\command")
    $CmdKey.SetValue("", "`"%1`" %*")
    $CmdKey.SetValue("IsolatedCommand", "`"%1`" %*")
    $CmdKey.Close()
    
    Write-Host "   Done." -ForegroundColor Green

    # Restart Explorer
    Stop-Process -Name explorer -Force
}

function Uninstall-SystemTweaks {
    Write-Host "`n[Reverting Windows 11 UI Tweaks...]" -ForegroundColor Cyan
    
    # 1. Remove Startup Task & Shortcuts
    Unregister-ScheduledTask -TaskName "LowAudioLatency_Startup" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item "$StartMenuPath\Windows Update.lnk" -ErrorAction SilentlyContinue
    Remove-Item "$StartMenuPath\Windows Update.url" -ErrorAction SilentlyContinue
    Remove-Item "$StartMenuPath\Microsoft Store.lnk" -ErrorAction SilentlyContinue
    Remove-Item "$StartMenuPath\Realtek Audio Console.lnk" -ErrorAction SilentlyContinue

    # 2. Revert Registry Tweaks
    Remove-Item -Path "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -ErrorAction SilentlyContinue
    
    # Restore Home & Gallery
    $HomeGUID = "{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
    $GalleryGUID = "{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}"
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\$HomeGUID" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\$GalleryGUID" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_36354489\$HomeGUID" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Value 0 -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -ErrorAction SilentlyContinue

    # Restore "Pin to Quick Access"
    $PinKeys = @(
        "Registry::HKEY_CLASSES_ROOT\Folder\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\Drive\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\*\shell\pintohome",
        "Registry::HKEY_CLASSES_ROOT\*\shell\pintohomefile"
    )
    foreach ($key in $PinKeys) { if (Test-Path -LiteralPath $key) { Remove-ItemProperty -LiteralPath $key -Name "ProgrammaticAccessOnly" -ErrorAction SilentlyContinue } }

    # 3. Remove Take Ownership Keys
    $TakeOwnTargets = @(
        "Registry::HKEY_CLASSES_ROOT\*\shell\runas",
        "Registry::HKEY_CLASSES_ROOT\Directory\shell\runas",
        "Registry::HKEY_CLASSES_ROOT\dllfile\shell\runas",
        "Registry::HKEY_CLASSES_ROOT\Drive\shell\runas"
    )
    foreach ($path in $TakeOwnTargets) { Remove-Item -LiteralPath $path -Recurse -ErrorAction SilentlyContinue }
    
    # Reset DNS DoH settings
    try { Reset-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -ErrorAction SilentlyContinue } catch {}
    try { Reset-DnsClientDohServerAddress -ServerAddress '8.8.8.8' -ErrorAction SilentlyContinue } catch {}

    Write-Host " + Tweaks Reverted. Restarting Explorer..." -ForegroundColor Green
    Stop-Process -Name explorer -Force
}

# ==============================================================================
# 6. FUNCTION: INSTALL XBOX DEPENDENCIES (WINGET)
# ==============================================================================
function Install-XboxDependencies {
    Write-Host "`n[Re-installing Xbox/Store Dependencies via Winget...]" -ForegroundColor Cyan
    
    $XboxApps = @(
        @{Name = "Microsoft Store"; Id = "9WZDNCRFHWJK" },
        @{Name = "Xbox App"; Id = "9MV0B5HZVK9Z" },
        @{Name = "Xbox Game Bar"; Id = "9NZKPSTSNW4P" },
        @{Name = "Xbox Identity Provider"; Id = "9WZDNCRD1HKW" },
        @{Name = "Gaming Services"; Id = "9MWPM2CQNLHN" },
        @{Name = "Microsoft UI Xaml 2.8"; Id = "9P487G5J2301" } 
    )

    # 1. Install via Winget
    foreach ($App in $XboxApps) {
        Write-Host "Installing $($App.Name)..." -NoNewline
        winget install --id $App.Id --source msstore --accept-package-agreements --accept-source-agreements --silent
        Write-Host " [Request Sent]" -ForegroundColor Green
    }

    # 2. Re-register via PowerShell (Fixes broken/hidden apps & Frameworks)
    Write-Host "`nEnsuring Apps & Frameworks are Registered..." -ForegroundColor Yellow
    
    # Register Xbox Apps
    Get-AppxPackage -AllUsers *Xbox* | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }
    Get-AppxPackage -AllUsers *GamingServices* | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }
    # Register Microsoft Store
    Get-AppxPackage -AllUsers *WindowsStore* | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }
    
    # IMPORTANT: Re-register Frameworks (VCLibs, .NET Native, UI Xaml) to ensure dependencies are active
    Get-AppxPackage -AllUsers | Where-Object { $_.IsFramework -eq $true } | Foreach { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }

    # 3. Restore GameDVR Registry Keys
    Write-Host "Restoring GameDVR Registry Keys..." -ForegroundColor Yellow
    $GameDVRPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
    $GameConfigPath = "HKCU:\System\GameConfigStore"
    
    if (!(Test-Path $GameDVRPath)) { New-Item -Path $GameDVRPath -Force | Out-Null }
    if (!(Test-Path $GameConfigPath)) { New-Item -Path $GameConfigPath -Force | Out-Null }
    
    Set-ItemProperty -Path $GameDVRPath -Name "AppCaptureEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GameConfigPath -Name "GameDVR_Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    Write-Host "GameDVR Settings Restored." -ForegroundColor Green
    
    Pause-And-Return
}

# ==============================================================================
# 7. MAIN MENU LOOP
# ==============================================================================

$asciiart = @"
██╗    ██╗██╗███╗   ██╗██████╗  ██████╗ ██╗    ██╗███████╗    ████████╗██╗    ██╗███████╗ █████╗ ██╗  ██╗███████╗ 
██║    ██║██║████╗  ██║██╔══██╗██╔═══██╗██║    ██║██╔════╝    ╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║ ██╔╝██╔════╝
██║ █╗ ██║██║██╔██╗ ██║██║  ██║██║   ██║██║ █╗ ██║███████╗       ██║   ██║ █╗ ██║█████╗  ███████║█████╔╝ ███████╗
██║███╗██║██║██║╚██╗██║██║  ██║██║   ██║██║███╗██║╚════██║       ██║   ██║███╗██║██╔══╝  ██╔══██║██╔═██╗ ╚════██║
╚███╔███╔╝██║██║ ╚████║██████╔╝╚██████╔╝╚███╔███╔╝███████║       ██║   ╚███╔███╔╝███████╗██║  ██║██║  ██╗███████║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗                                                     
████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗                                                    
██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝                                                    
██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗                                                    
██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║                                                    
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝  © Tahir - $Ver                                    
"@                                                                                                                    

$ShowMenu = $true

while ($ShowMenu) {
    Clear-Host
    Write-Host $asciiart -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Install 'Open Terminal (Admin)' Context Menu"
    Write-Host "  [2] Apply System Tweaks"
    Write-Host ""
    Write-Host "  [3] Revert 'Open Terminal (Admin)' Context Menu"
    Write-Host "  [4] Revert System Tweaks"
    Write-Host ""
    Write-Host "  [5] Re-install Xbox & Microsoft Store Dependencies"
    Write-Host ""
    Write-Host "  [Q] Quit"

    $choice = Read-Host "`nSelect an option"
    switch ($choice) {
        '1' { Clear-Host; Install-TerminalMenu; Pause-And-Return }
        '2' { Clear-Host; Install-SystemTweaks; Pause-And-Return }
        '3' { Clear-Host; Uninstall-TerminalMenu; Pause-And-Return }
        '4' { Clear-Host; Uninstall-SystemTweaks; Pause-And-Return }
        '5' { Clear-Host; Install-XboxDependencies }
        'Q' { $host.ui.RawUI.WindowTitle = "Administrator: Windows PowerShell"; Clear-Host; $ShowMenu = $false }
        'q' { $host.ui.RawUI.WindowTitle = "Administrator: Windows PowerShell"; Clear-Host; $ShowMenu = $false }
        Default { Write-Host "Invalid selection."; Start-Sleep -Seconds 1 }
    }
}