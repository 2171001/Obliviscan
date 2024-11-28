# Obliviscan
**Obliviscan** is a comprehensive PowerShell-based malware scanning, removal, and system-hardening script designed to secure Windows systems. It utilizes Windows Defender for scanning, flags and removes detected threats, unlocks BitLocker-encrypted drives for full scanning access, cleans up unnecessary files, and applies additional security measures.

# Comprehensive Malware Scanner and System Hardening Script
This PowerShell script provides a robust solution for scanning your Windows system for malware, repairing file integrity, cleaning up unnecessary files, and applying essential security hardening. It combines features such as rootkit scanning, Windows Defender antivirus checks, and system cleanup with enhanced security measures, including Windows Firewall and exploit protection.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Detailed Functionality](#detailed-functionality)
- [Notes and Considerations](#notes-and-considerations)
- [Resources](#resources)

---

## Features
- **Administrator Check and Auto-Relaunch**: Ensures the script runs with administrator privileges by auto-relaunching with elevated permissions if necessary.
- **Malware Detection and Removal**: Uses Windows Defender to scan for and remove various types of malware, including:
  - Boot sector virus
  - Macro virus
  - Program virus
  - Multipartite virus
  - Encrypted virus
  - Polymorphic virus
  - Metamorphic virus
  - Stealth virus
  - Armored virus
  - Hoax virus
- **BitLocker Support**: Detects and unlocks BitLocker-encrypted drives to ensure they are scanned.
- **System Cleanup**: Cleans temporary files, user temp files, and Windows Update cache, with retry logic for files actively in use.
- **System Security Hardening**: Applies key security settings, including:
  - Enabling Windows Firewall
  - Enabling Secure Boot (if supported by hardware)
  - Applying exploit protections (DEP, SEHOP, ASLR, and more)
- **Conditional Admin Prompt**: Automatically prompts for administrator privileges only if the script is initially run without them. The script relaunches with elevated permissions, and the PowerShell window remains open for review after completion.
- **Advanced Exploit Mitigations**: Enables system-wide protections such as DEP, SEHOP, CFG, and more to safeguard against memory-based attacks.
- **Credential Guard and VBS**: Protects sensitive credentials and strengthens system security using virtualization-based security.
- **Memory Integrity (HVCI)**: Prevents malicious kernel-mode drivers from loading.
- **Attack Surface Reduction (ASR)**: Enforces rules to block common exploit techniques (requires Microsoft Defender).
- **Ransomware Protection**: Enables Controlled Folder Access to protect critical directories from unauthorized changes.
- **Firewall and Protocol Hardening**: Configures Windows Firewall rules and disables legacy protocols like SMBv1, LLMNR, and NetBIOS.
- **Tamper Protection**: Prevents unauthorized changes to Windows Defender settings.
- **UAC Hardening**: Enhances User Account Control for stricter elevation prompts.

## Requirements
- **Windows 10/11** with **PowerShell 5.1** or higher.
- **Administrator Privileges**: Script automatically prompts for administrator privileges if not already running as administrator.
- **Windows Defender** Enabled and up-to-date.
- **Sysinternals RootkitRevealer** (optional for rootkit detection)

> **Note**: Certain advanced malware types, such as polymorphic viruses or boot sector threats, may require additional specialized tools for complete removal.

## Setup
1. **Download the Script**: Save the `Obliviscan.ps1` file to a directory on your Windows machine.
2. **BitLocker Preparation**: Ensure you have your BitLocker recovery key handy, as the script will prompt for it to unlock any encrypted volumes.
3. **Download RootkitRevealer**:
   - Visit the [Sysinternals website](https://learn.microsoft.com/en-us/sysinternals/downloads/rootkit-revealer) to download **RootkitRevealer**.
   - Place `RootkitRevealer.exe` in a folder, e.g., `C:\Tools\RootkitRevealer\`.
4. **Edit the Script**: Update the path to RootkitRevealer in the script:
   ```powershell
   $rootkitRevealerPath = "C:\Tools\RootkitRevealer\RootkitRevealer.exe"
   ```

## Usage
1. **Run PowerShell as Administrator** *(Optional)*:
   - The script automatically checks and prompts for administrator privileges if not initially run with them.
   - Open PowerShell, navigate to the directory containing `Obliviscan.ps1`.
   - **Set Execution Policy** to allow the script to run (if not already set):
     ```powershell
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
     ```
2. **Execute the Script**:
   ```powershell
   .\Obliviscan.ps1
   ```
3. **Administrator Privileges**: The script automatically checks for administrator privileges and re-launches with elevated permissions if necessary.
4. **Advanced Security Features**: Certain features, such as Credential Guard, Memory Integrity, and Attack Surface Reduction, require a system reboot or hardware support (e.g., Secure Boot and virtualization).
5. **Compatibility Note**: Some advanced mitigations (e.g., SMBv1 disable, Memory Integrity) may cause compatibility issues with older applications or devices. Review system requirements before execution.

* If the script detects that it is not running with administrator privileges, it will prompt for elevation automatically.

## Detailed Functionality
1. **Administrator Privilege Check**
   - The script verifies if it is running as administrator. If not, it restarts itself with elevated permissions to ensure it has full access to system-level functions.
2. **Quick Malware Detection and Removal**
   - Uses Windows Defender to perform quick scans on essential directories (`C:\Windows`, `C:\Users`, `C:\Program Files`).
   - Scans for a wide range of malware types and removes detected threats automatically.
3. **BitLocker Volume Unlocking**
   - Detects locked BitLocker-encrypted volumes and prompts for the recovery key to unlock them for scanning.
   - Ensures full disk access, even for encrypted drives.
4. **System Cleanup**
   - Removes unnecessary files from:
     - `C:\Windows\Temp`
     - `C:\Users\<User>\AppData\Local\Temp`
     - `C:\Windows\SoftwareDistribution` (Windows Update Cache)
   - Uses retry logic to handle files in use by other processes.
5. **Security Hardening**
   - **Windows Firewall**: Ensures the firewall is enabled across all network profiles.
   - **Secure Boot Check**: Detects if Secure Boot is enabled and recommends enabling it if not.
   - **Exploit Protection**: Enables various exploit protections (DEP, SEHOP, ASLR) to harden system defenses.

## Notes and Considerations
- **Administrative Privileges**: Required for the script’s full functionality, including malware removal and system-hardening tasks.
- **Advanced Malware**: For highly advanced threats (e.g., polymorphic viruses, rootkits), consider pairing this tool with additional specialized software.
- **Resource Usage**: The script runs multiple intensive tasks, so it’s recommended to execute it during off-hours to avoid interruptions.

## Resources
- [Windows Defender Antivirus Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/windows-defender-antivirus-in-windows-10) 👉Learn about Windows Defender Antivirus, its scanning abilities, and threat protection features in Windows 10 and 11.
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1) 👉 Microsoft PowerShell documentation provides details on scripting and commands.
- [Microsoft BitLocker Documentation](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview) 👉 BitLocker is Microsoft’s encryption feature for protecting drives in Windows.
- [Microsoft Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/) 👉 A suite of advanced Windows diagnostic tools, including RootkitRevealer for malware troubleshooting.
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines) 👉 Microsoft recommends settings for security baselines to harden Windows systems against threats.
- [Credential Guard Overview](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard) 👉 Credential Guard uses virtualization-based security to protect sensitive data.
- [Attack Surface Reduction Rules](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules) 👉 Attack Surface Reduction rules help minimize exposure to security threats by blocking risky behaviors.
- [Windows Exploit Protection](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/exploit-protection-exploit-guard) 👉 Windows Exploit Protection mitigates vulnerabilities by applying security settings to apps and system processes.
- [Memory Integrity (HVCI)](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard)) 👉 Memory Integrity (HVCI) uses virtualization to protect critical system processes from attacks.
