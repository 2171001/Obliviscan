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
