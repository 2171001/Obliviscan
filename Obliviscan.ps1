# Obliviscan - Comprehensive Malware Scanner, Malware Removal, and System Hardening Script for Windows

# Initialize a flag to control the exit prompt
$promptForExit = $false

# Check if running as administrator; if not, re-run script with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges. Relaunching with elevated permissions..." -ForegroundColor Yellow
    $promptForExit = $true  # Set the flag before relaunching
    Start-Process powershell.exe -ArgumentList ("-File `"" + $PSCommandPath + "`"") -Verb RunAs
    Exit
}

# Start transcript to log all output to a file once running with admin privileges
$logFile = "$PSScriptRoot\Obliviscan_Log.txt"  # This will save the log file in the script's directory
Start-Transcript -Path $logFile -Append

# Function to unlock BitLocker-encrypted drives
function Unlock-BitLockerVolumes {
    Write-Host "Checking for BitLocker-encrypted drives..." -ForegroundColor Yellow
    $bitlockerVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq 'Locked' }

    if ($bitlockerVolumes) {
        foreach ($volume in $bitlockerVolumes) {
            Write-Host "Found locked BitLocker volume: $($volume.MountPoint)"
            $recoveryPassword = Read-Host -Prompt "Enter BitLocker recovery password for $($volume.MountPoint)"

            Try {
                Unlock-BitLocker -MountPoint $volume.MountPoint -RecoveryPassword $recoveryPassword
                Write-Host "Unlocked BitLocker volume at $($volume.MountPoint)" -ForegroundColor Green
            } Catch {
                Write-Host "Failed to unlock $($volume.MountPoint). Please check the recovery password." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No locked BitLocker volumes found." -ForegroundColor Green
    }
}

# Function to initiate a quick Windows Defender scan on key folders
function Start-QuickDefenderScan {
    $scanStatus = Get-MpComputerStatus
    if ($scanStatus.AntivirusScanRunning) {
        Write-Host "A scan is already in progress. Skipping quick scan." -ForegroundColor Yellow
    } else {
        Write-Host "Starting quick Windows Defender scan on specific folders..." -ForegroundColor Green
        Start-MpScan -ScanPath "C:\Windows"
        Start-MpScan -ScanPath "C:\Users"
        Start-MpScan -ScanPath "C:\Program Files"
    }
}

# Function to remove detected malware threats
function Remove-DetectedThreats {
    Write-Host "Checking for detected threats to remove..." -ForegroundColor Yellow
    $threats = Get-MpThreatDetection
    if ($threats) {
        $threats | ForEach-Object {
            Try {
                Remove-MpThreat -ThreatID $_.ThreatID
                Write-Host "Removed detected threat: $($_.ThreatName)" -ForegroundColor Green
            } Catch {
                Write-Host "Failed to remove threat: $($_.ThreatName)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No active threats detected." -ForegroundColor Green
    }
}

# Function to clean up temporary files and Windows Update cache with -Recurse to avoid prompts
function Cleanup-System {
    Write-Host "Cleaning up unnecessary files and optimizing the system..." -ForegroundColor Yellow

    # Clean temporary files with error handling and retry logic
    Get-ChildItem "C:\Windows\Temp\*" -Recurse | ForEach-Object {
        Try {
            Remove-Item $_.FullName -Recurse -Force
            Write-Host "Deleted: $($_.FullName)"
        } Catch [System.IO.IOException] {
            Start-Sleep -Seconds 2  # Wait and retry
            Try {
                Remove-Item $_.FullName -Recurse -Force
                Write-Host "Deleted after retry: $($_.FullName)"
            } Catch {
                Write-Host "Could not delete: $($_.FullName) - File in use" -ForegroundColor Yellow
            }
        }
    }

    # Clean user temp files with error handling and retry logic
    Get-ChildItem "C:\Users\*\AppData\Local\Temp\*" -Recurse | ForEach-Object {
        Try {
            Remove-Item $_.FullName -Recurse -Force
            Write-Host "Deleted: $($_.FullName)"
        } Catch [System.IO.IOException] {
            Start-Sleep -Seconds 2  # Wait and retry
            Try {
                Remove-Item $_.FullName -Recurse -Force
                Write-Host "Deleted after retry: $($_.FullName)"
            } Catch {
                Write-Host "Could not delete: $($_.FullName) - File in use" -ForegroundColor Yellow
            }
        }
    }
    Write-Host "Temporary files cleaned."

    # Clean up Windows Update files with error handling and retry logic
    Write-Host "Cleaning up Windows Update cache..."
    Stop-Service -Name wuauserv
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse | ForEach-Object {
        Try {
            Remove-Item $_.FullName -Recurse -Force
            Write-Host "Deleted: $($_.FullName)"
        } Catch [System.IO.IOException] {
            Start-Sleep -Seconds 2  # Wait and retry
            Try {
                Remove-Item $_.FullName -Recurse -Force
                Write-Host "Deleted after retry: $($_.FullName)"
            } Catch {
                Write-Host "Could not delete: $($_.FullName) - File in use" -ForegroundColor Yellow
            }
        }
    }
    Start-Service -Name wuauserv
    Write-Host "Windows Update cache cleaned."

    Write-Host "System cleanup completed."
}

# Function to apply advanced security hardening
function Advanced-SecurityHardening {
    Write-Host "Applying advanced security hardening..." -ForegroundColor Cyan

    # System-wide Exploit Mitigations
    Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages, BottomUp, HighEntropy, StrictHandleChecks, CallerChecks, CFG

    # Enable Credential Guard
    Enable-WindowsOptionalFeature -Online -FeatureName "IsolatedUserMode" -NoRestart
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

    # Enable Secure Boot and Virtualization-Based Security (VBS)
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot" /v "SecureBoot" /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVSM" /t REG_DWORD /d 1 /f

    # Enable Memory Integrity (HVCI)
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f

    # Enforce ASR Rules (Attack Surface Reduction)
    powershell -Command "& {(New-Object -ComObject Microsoft.Windows.Security.Mitigation.AuditConfiguration).EnableAll}"

    # Harden SMB Protocols (Disable SMBv1)
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

    # Enable Ransomware Protection
    Set-MpPreference -EnableControlledFolderAccess Enabled

    # Disable Remote Desktop
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1

    # Block PowerShell Script Execution by Untrusted Scripts
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

    # Apply Windows Firewall Rules
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

    # Enable Defender Tamper Protection
    Set-MpPreference -EnableTamperProtection Enabled

    # Restrict LLMNR and NetBIOS
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLmhosts" /t REG_DWORD /d 0 /f

    # Ensure Windows Updates are Set to Automatic
    Set-Service -Name wuauserv -StartupType Automatic

    # Harden UAC (User Account Control)
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f

    Write-Host "Advanced security hardening applied."
}

# Start all scans, repairs, and security hardening
Write-Host "Initiating comprehensive malware scan, system repair, and security hardening..." -ForegroundColor Cyan
Unlock-BitLockerVolumes
Start-QuickDefenderScan
Cleanup-System
Advanced-SecurityHardening
Remove-DetectedThreats

Write-Host "All scans, repairs, and security hardening completed. Please review the respective logs for detailed results." -ForegroundColor Cyan

# Stop transcript to end logging
Stop-Transcript
Write-Host "Logs saved to $logFile"

# Conditional prompt for exit if the script was elevated
if ($promptForExit) {
    Read-Host -Prompt "Press ENTER to close the elevated PowerShell window"
}
