# KILL WINDOWS UPDATE - FINAL VERSION
# Run as Administrator!
# Compatible: Windows 11 24H2
# Method: Service disable + Registry lock + ACL ownership + Task disable + WSUS redirect + Rename protection

Write-Host "designed by" -ForegroundColor White
Write-Host @"

   | | ___  __ _  ___  _ __  _ _  ___ 
 / _`` |/ _ \/ _`` |/ _ \| '_ \| '_|/ _ \
 \__,_|\___/\__, |\___/| .__/|_|  \___/
            |___/      |_|  
                          
"@ -ForegroundColor Blue

$Host.UI.RawUI.ForegroundColor = "Gray"

$ErrorActionPreference = "SilentlyContinue"
$script:results = @()
$script:errors  = @()

# ─────────────────────────────────────────────
# HELPER: Run a native command (uses $LASTEXITCODE)
# acceptableCodes: exit codes that should be treated as OK, not errors
# ─────────────────────────────────────────────
function Run-Native {
    param(
        [string]$cmd,
        [int[]]$acceptableCodes = @()
    )
    try {
        Invoke-Expression $cmd 2>&1 | Out-Null
        $code = $LASTEXITCODE
        if ($code -eq 0 -or $null -eq $code -or $acceptableCodes -contains $code) {
            $script:results += "OK: $cmd"
        } else {
            $script:errors += "FAILED [$code]: $cmd"
        }
    } catch {
        $script:errors += "ERROR: $cmd -> $($_.Exception.Message)"
    }
}

# ─────────────────────────────────────────────
# HELPER: Run a PowerShell cmdlet (uses $?)
# ─────────────────────────────────────────────
function Run-Cmdlet {
    param([string]$label, [scriptblock]$block)
    try {
        & $block 2>&1 | Out-Null
        if ($?) {
            $script:results += "OK: $label"
        } else {
            $script:errors += "FAILED: $label"
        }
    } catch {
        $script:errors += "ERROR: $label -> $($_.Exception.Message)"
    }
}

# ─────────────────────────────────────────────
# HELPER: Take full ownership of a registry key
# and grant Administrators full control so we
# can write to protected service entries like
# WaaSMedicSvc and dosvc.
# ─────────────────────────────────────────────
function Set-RegistryOwnerAndWrite {
    param(
        [string]$KeyPath,   # e.g. "SYSTEM\CurrentControlSet\Services\WaaSMedicSvc"
        [string]$ValueName,
        [int]$ValueData
    )

    $label = "Registry own+write: $KeyPath\$ValueName"

    try {
        # Load required types for token manipulation
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class TokenPriv {
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr h, bool d,
        ref TOKEN_PRIVILEGES newState, int len, IntPtr prev, IntPtr rLen);

    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr token);

    [DllImport("advapi32.dll", SetLastError=true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long luid);

    [StructLayout(LayoutKind.Sequential, Pack=1)]
    internal struct TOKEN_PRIVILEGES {
        public int Count;
        public long Luid;
        public int Attr;
    }

    internal const int SE_PRIVILEGE_ENABLED   = 0x00000002;
    internal const int TOKEN_QUERY            = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static void EnablePrivilege(string privilege) {
        IntPtr token = IntPtr.Zero;
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { Count = 1, Attr = SE_PRIVILEGE_ENABLED };
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
                         TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref token);
        LookupPrivilegeValue(null, privilege, ref tp.Luid);
        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@ -ErrorAction SilentlyContinue

        # Enable SeTakeOwnershipPrivilege and SeRestorePrivilege
        [TokenPriv]::EnablePrivilege("SeTakeOwnershipPrivilege") | Out-Null
        [TokenPriv]::EnablePrivilege("SeRestorePrivilege")        | Out-Null

        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $KeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )

        if ($null -eq $regKey) {
            $script:errors += "FAILED (cannot open): $label"
            return
        }

        # Take ownership -> Administrators
        $acl = $regKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $acl.SetOwner($adminSid)
        $regKey.SetAccessControl($acl)

        # Re-open with FullControl rights
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $KeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::FullControl
        )

        # Grant Administrators FullControl
        $acl  = $regKey.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $adminSid,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.SetAccessRule($rule)
        $regKey.SetAccessControl($acl)

        # Now write the value
        $regKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWord)
        $regKey.Close()

        $script:results += "OK: $label = $ValueData"

    } catch {
        $script:errors += "ERROR: $label -> $($_.Exception.Message)"
    }
}

# ─────────────────────────────────────────────
# HELPER: Rename a file by taking ownership first
# ─────────────────────────────────────────────
function Rename-Protected {
    param([string]$FullPath, [string]$NewName)
    $label = "Rename: $FullPath -> $NewName"
    try {
        Run-Native "takeown /f `"$FullPath`" /a"
        Run-Native "icacls `"$FullPath`" /grant *S-1-5-32-544:F"
        $dest = Join-Path (Split-Path $FullPath) $NewName
        if (-not (Test-Path $dest)) {
            Rename-Item -Path $FullPath -NewName $NewName -Force -ErrorAction Stop
            $script:results += "OK: $label"
        } else {
            $script:results += "SKIP (already renamed): $label"
        }
    } catch {
        $script:errors += "ERROR: $label -> $($_.Exception.Message)"
    }
}

# ════════════════════════════════════════════════
# 1. STOP SERVICES
# ════════════════════════════════════════════════
Write-Host "`nStopping Windows Update services..." -ForegroundColor Cyan

$servicesToStop = @("wuauserv","bits","dosvc","WaaSMedicSvc","cryptsvc","usosvc")
foreach ($svc in $servicesToStop) {
    # Exit code 2 = service not running (already stopped) — not a real failure
    Run-Native "net stop $svc /y" -acceptableCodes @(2)
}

# ════════════════════════════════════════════════
# 2. DISABLE SERVICES VIA SC (standard services)
# ════════════════════════════════════════════════
Write-Host "`nDisabling services via sc config..." -ForegroundColor Cyan

$servicesToDisable = @("wuauserv","bits","cryptsvc","usosvc")
foreach ($svc in $servicesToDisable) {
    Run-Native "sc.exe config $svc start= disabled"
}

# ════════════════════════════════════════════════
# 3. DISABLE PROTECTED SERVICES VIA REGISTRY OWN
#    WaaSMedicSvc and dosvc resist sc config on 24H2
#    because their registry keys are ACL-locked by
#    TrustedInstaller. We take ownership first.
# ════════════════════════════════════════════════
Write-Host "`nTaking ownership of protected service registry keys..." -ForegroundColor Cyan

Set-RegistryOwnerAndWrite -KeyPath "SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" `
    -ValueName "Start" -ValueData 4

Set-RegistryOwnerAndWrite -KeyPath "SYSTEM\CurrentControlSet\Services\dosvc" `
    -ValueName "Start" -ValueData 4

# Also disable UsoSvc via registry for belt-and-suspenders
Set-RegistryOwnerAndWrite -KeyPath "SYSTEM\CurrentControlSet\Services\UsoSvc" `
    -ValueName "Start" -ValueData 4

# ════════════════════════════════════════════════
# 4. BLOCK NETWORK CALLS — WSUS REDIRECT
#    Points Windows Update to a dummy local WSUS
#    server so it cannot phone home even if a
#    service somehow restarts.
# ════════════════════════════════════════════════
Write-Host "`nRedirecting Windows Update to dummy WSUS server..." -ForegroundColor Cyan

$wuBase  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$wuAU    = "$wuBase\AU"

Run-Cmdlet "Create WindowsUpdate policy key" {
    if (-not (Test-Path $wuBase)) { New-Item -Path $wuBase -Force }
}
Run-Cmdlet "Create WindowsUpdate\AU policy key" {
    if (-not (Test-Path $wuAU))  { New-Item -Path $wuAU  -Force }
}

Run-Cmdlet "Set WUServer (dummy WSUS)" {
    Set-ItemProperty -Path $wuBase -Name "WUServer"         -Value "http://localhost:8530" -Type String -Force
}
Run-Cmdlet "Set WUStatusServer (dummy WSUS)" {
    Set-ItemProperty -Path $wuBase -Name "WUStatusServer"   -Value "http://localhost:8530" -Type String -Force
}
Run-Cmdlet "Set UseWUServer = 1" {
    Set-ItemProperty -Path $wuAU   -Name "UseWUServer"       -Value 1 -Type DWord -Force
}

# ════════════════════════════════════════════════
# 5. REGISTRY POLICIES — BLOCK UPDATES
# ════════════════════════════════════════════════
Write-Host "`nApplying registry policies to block updates..." -ForegroundColor Cyan

Run-Native "reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`" /v NoAutoUpdate /t REG_DWORD /d 1 /f"
Run-Native "reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`" /v AUOptions /t REG_DWORD /d 1 /f"
Run-Native "reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`" /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f"
Run-Native "reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`" /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f"
Run-Native "reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f"

# ════════════════════════════════════════════════
# 6. DISABLE SCHEDULED TASKS
#    Full list including WaaSMedic tasks that
#    can re-enable services behind the scenes.
# ════════════════════════════════════════════════
Write-Host "`nDisabling scheduled tasks..." -ForegroundColor Cyan

$schedTasks = @(
    "Microsoft\Windows\WindowsUpdate\Scheduled Start",
    "Microsoft\Windows\WindowsUpdate\Scheduled Start With Network",
    "Microsoft\Windows\WindowsUpdate\Automatic App Update",
    "Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
    "Microsoft\Windows\UpdateOrchestrator\Report policies",
    "Microsoft\Windows\UpdateOrchestrator\StartInstall",
    "Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
    "Microsoft\Windows\UpdateOrchestrator\UpdateAssistant",
    "Microsoft\Windows\UpdateOrchestrator\UpdateAssistantAllUsersRun",
    "Microsoft\Windows\UpdateOrchestrator\UpdateAssistantCalendarRun",
    "Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
    "Microsoft\Windows\WaaSMedic\PerformRemediation"
)
foreach ($task in $schedTasks) {
    # Exit code 1 = task not found on this Windows build — warn, don't error
    Run-Native "schtasks /Change /TN `"$task`" /Disable" -acceptableCodes @(1)
}

# ════════════════════════════════════════════════
# 7. RENAME UPDATE EXECUTABLES
#    More durable and reversible than ACL denies.
#    Windows Resource Protection cannot restore a
#    renamed file without SFC /scannow, which the
#    user controls.
# ════════════════════════════════════════════════
Write-Host "`nRenaming Windows Update executables..." -ForegroundColor Cyan

if (Test-Path "C:\Windows\System32\wuaueng.dll") {
    Rename-Protected "C:\Windows\System32\wuaueng.dll" "wuaueng.dll.bak"
}
if (Test-Path "C:\Windows\System32\usoclient.exe") {
    Rename-Protected "C:\Windows\System32\usoclient.exe" "usoclient.exe.bak"
}

# ════════════════════════════════════════════════
# 8. RENAME SCHEDULED TASK FOLDERS
# ════════════════════════════════════════════════
Write-Host "`nRenaming task folders..." -ForegroundColor Cyan

$taskFolders = @(
    "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator",
    "C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate",
    "C:\Windows\System32\Tasks\Microsoft\Windows\WaaSMedic"
)
foreach ($folder in $taskFolders) {
    $oldName = Split-Path $folder -Leaf
    $dest    = Join-Path (Split-Path $folder) "$oldName.old"
    if (Test-Path $dest) {
        $script:results += "SKIP (already renamed): $folder"
    } elseif (Test-Path $folder) {
        Run-Native "ren `"$folder`" `"$oldName.old`""
    }
}

# ════════════════════════════════════════════════
# 9. CLEAR WINDOWS UPDATE CACHE
# ════════════════════════════════════════════════
Write-Host "`nClearing Windows Update cache folders..." -ForegroundColor Cyan

$cacheFolders = @(
    "C:\Windows\SoftwareDistribution",
    "C:\Windows\System32\catroot2"
)
foreach ($folder in $cacheFolders) {
    if (Test-Path $folder) {
        Run-Native "takeown /f `"$folder`" /r /d y"
        Run-Native "icacls `"$folder`" /grant *S-1-5-32-544:F /t"
        # rd is aliased to Remove-Item in PowerShell — must call via cmd.exe
        Run-Native "cmd.exe /c rd /s /q `"$folder`""
        if (-not (Test-Path $folder)) {
            $script:results += "OK: Deleted $folder"
        } else {
            $script:errors  += "PARTIAL: Could not fully delete $folder (files may be in use)"
        }
    } else {
        $script:results += "SKIP (not found): $folder"
    }
}

# ════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════
Write-Host "`n=============================" -ForegroundColor Yellow
Write-Host "  WINDOWS UPDATE DISABLED!  "  -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Yellow

Write-Host "`nCompleted actions:" -ForegroundColor Cyan
$script:results | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }

if ($script:errors.Count -gt 0) {
    Write-Host "`nErrors / Warnings:" -ForegroundColor Red
    $script:errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

Write-Host "`nHave a nice no-updating day!" -ForegroundColor Magenta
Write-Host "`nPress any key to exit..."
[void][System.Console]::ReadKey($true)
