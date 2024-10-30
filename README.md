# Obliviscan
Advanced PowerShell toolkit for Windows system scanning, malware removal, repair, and security hardening—bringing threats into oblivion.

# Comprehensive Malware Scanner and System Hardening Script
This PowerShell script provides a robust solution for scanning your Windows system for malware, repairing file integrity, cleaning up unnecessary files, and applying essential security hardening. It combines features such as rootkit scanning, Windows Defender antivirus checks, and system cleanup with enhanced security measures, including Windows Firewall and exploit protection.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Detailed Functionality](#detailed-functionality)
- [Notes and Considerations](#notes-and-considerations)

---

## Features
- **Malware Scanning**: Initiates Windows Defender scans on key directories and uses Sysinternals RootkitRevealer to detect hidden malware.
- **File Integrity Repair**: Runs SFC (System File Checker) and DISM (Deployment Image Servicing and Management) to repair corrupted system files.
- **System Cleanup**: Removes unnecessary files, temporary files, and Windows Update cache with error handling.
- **System Security Hardening**:
  - Enables Windows Firewall for all network profiles.
  - Checks for Secure Boot and recommends enabling it if disabled.
  - Enables exploit protection features (DEP, SEHOP, ASLR).

## Requirements
- **Windows 10/11** with **PowerShell 5.1** or higher.
- **Windows Defender** enabled and up-to-date.
- **Sysinternals RootkitRevealer** tool downloaded and available on your system.

> **Note**: The script must be run with administrative privileges for full functionality.

## Setup
1. **Download the Script**: Save the `Obliviscan.ps1` file to a directory on your Windows machine.
2. **Download RootkitRevealer**:
   - Visit the [Sysinternals website](https://learn.microsoft.com/en-us/sysinternals/downloads/rootkit-revealer) to download **RootkitRevealer**.
   - Place `RootkitRevealer.exe` in a folder, e.g., `C:\Tools\RootkitRevealer\`.
3. **Edit the Script**: Update the path to RootkitRevealer in the script:
   ```powershell
   $rootkitRevealerPath = "C:\Tools\RootkitRevealer\RootkitRevealer.exe"
   ```

## Usage
1. Run PowerShell as Administrator:
   - Open PowerShell and navigate to the directory containing `Obliviscan.ps1`.
   - Set the execution policy to allow the script to run (if not set):
     ```powershell
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
     ```
2. Execute the Script:
   ```powershell
   .\Obliviscan.ps1
   ```

## Detailed Functionality
1. Quick Windows Defender Scan
   - Scans specified system folders (`C:\Windows`, `C:\Users`, `C:\Programs Files`) to check for common malware locations.
   - Uses Windows Defender's Quick Scan for faster completion
2. Rootkit Detection
   - Leverages **Sysinternals RootkitRevealer** to detect rootkits that may be hiding in the system.
     Output is logged in `rootkit_scan_results.log`.
3. System File Integrity Repair
   - System File Checker (SFC): Scans for and attempts to repair any corrupted system files.
   - DISM: Ensures the system image's integrity and applies any necessary repairs.
4. System Cleanup
   - Deletes temporary files and Windows Update cache files, including error handling for files in use.
   - Reduces clutter and frees up disk space by targetting:
     - `C:\Windows\Temp`
     - `C:\Users\<User>\AppData\Local\Temp`
     - `C:\Windows\SoftwareDistribution`
5. System Security Hardening
   - Windows Firewall: Enables the firewall for Domain, Public, and Private network profiles.
   - Secure Boot Check: Detects if Secure Boot is enabled and provides guidance if it’s off.
   - Exploit Protection: Enables Data Execution Prevention (DEP), Structured Exception Handler Overwrite Protection (SEHOP), and Address Space Layout Randomization (ASLR) for increased system resilience.

## Notes and Considerations
- Administrative Privileges: The script requires administrative privileges to perform repairs and make system-level changes.
- Tamper Protection: If Windows Defender Tamper Protection is enabled, certain actions (e.g., stopping Defender service) may be restricted.
- Resource Usage: The script performs several intensive tasks and may take some time to complete. It’s recommended to run it during off-hours to avoid interruptions.