# 🔒 Windows Update Disabler

[![PowerShell Version](https://img.shields.io/badge/powershell-%3E=5.0-blue)](https://learn.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A **safe and complete PowerShell script** that permanently disables **Windows Update** and related services, without affecting network or other system components.

---

## ✨ Features

- **Stops and disables** all Windows Update services (e.g., `wuauserv`, `bits`, `WaaSMedicSvc`).
- **Disables scheduled tasks** related to Windows Update and Update Orchestrator.
- **Clears update cache folders** (e.g., `SoftwareDistribution`, `catroot2`).
- **Applies registry policies** to prevent automatic updates from restarting.
- **Blocks executables** (e.g., `wuaueng.dll`, `usoclient.exe`).
- **Generates a clear summary** of successes, warnings, and errors.
- **Safe execution** – affects only Windows Update.

---

## ⚡ Requirements

- Windows 10 / 11 (Admin privileges required).
- PowerShell 5.0 or newer.

---

## 📥 Installation & Usage

1. **Download** the script `Disable-WindowsUpdate.ps1`.
2. **Run as Administrator**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File Disable-WindowsUpdate.ps1
   ```
3. Observe a **detailed summary report**:
   - ✅ Commands executed successfully.
   - ⚠️ Commands with warnings or errors.

---

## 📋 Example Output

```
Stopping Windows Update Services...
OK: net stop wuauserv
OK: net stop bits
...
Errors or Warnings:
ERROR: File not found: wuaueng.dll

Have a nice no-updating day!
```

---

## 🧱 Script Structure

```
Disable-WindowsUpdate.ps1     // Main script
```

---

## ⚠️ Disclaimer

This script is designed for users who **do not want Windows Update to run automatically**.  
**Use at your own risk.** Ensure you manually install security updates when needed.

---

## 📄 License

MIT – Free to use and modify.

---

> **Have a nice no-updating day!**
tested on win11 24h2
