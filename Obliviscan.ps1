# Obliviscan - Comprehensive Malware Scanner and System Hardening Script

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

# Function to clean up temporary files and Windows Update cache with -Recurse to avoid prompts
function Cleanup-System {
    Write-Host "Cleaning up unnecessary files and optimizing the system..." -ForegroundColor Yellow

    # Clean temporary files with error handling
    Get-ChildItem "C:\Windows\Temp\*" -Recurse | ForEach-Object {
        Try {
            Remove-Item $_.FullName -Recurse -Force
            Write-Host "Deleted: $($_.FullName)"
        } Catch {
            Write-Host "Could not delete: $($_.FullName)" -ForegroundColor Yellow
        }
    }

    Get-ChildItem "C:\Users\*\AppData\Local\Temp\*" -Recurse | ForEach-Object {
        Try {
            Remove-Item $_.FullName -Recurse -Force
            Write-Host "Deleted: $($_.FullName)"
        } Catch {
            Write-Host "Could not delete: $($_.FullName)" -ForegroundColor Yellow
        }
    }
    Write-Host "Temporary files cleaned."

    # Clean up Windows Update files with error handling
    Write-Host "Cleaning up Windows Update cache..."
    Stop-Service -Name wuauserv
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse | ForEach-Object {
        Try {
            Remove-Item $_.FullName -Recurse -Force
            Write-Host "Deleted: $($_.FullName)"
        } Catch {
            Write-Host "Could not delete: $($_.FullName)" -ForegroundColor Yellow
        }
    }
    Start-Service -Name wuauserv
    Write-Host "Windows Update cache cleaned."

    Write-Host "System cleanup completed."
}

# Function to enable additional security settings (e.g., enable firewall, exploit protection, etc.)
function Secure-System {
    Write-Host "Applying system security settings..." -ForegroundColor Yellow

    # Enable Windows Firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "Windows Firewall enabled."

    # Enable Secure Boot
    Confirm-SecureBootUEFI | ForEach-Object {
        if ($_ -eq $true) {
            Write-Host "Secure Boot is already enabled." -ForegroundColor Green
        } else {
            Write-Host "Please enable Secure Boot in BIOS/UEFI for additional protection." -ForegroundColor Red
        }
    }

    # Enable Exploit Protection
    Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages, BottomUp, HighEntropy
    Write-Host "Exploit protection enabled."

    Write-Host "System secured with additional protection settings."
}

# Start all scans, repairs, and security hardening
Write-Host "Initiating comprehensive malware scan, system repair, and security hardening..." -ForegroundColor Cyan
Start-QuickDefenderScan
Cleanup-System
Secure-System

Write-Host "All scans, repairs, and security hardening completed. Please review the respective logs for detailed results." -ForegroundColor Cyan
