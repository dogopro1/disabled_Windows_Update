# KILL WINDOWS UPDATE - FINAL VERSION
# Run as Administrator!

Write-Host "designed by" -ForegroundColor White
Write-Host @"

   | | ___  __ _  ___  _ __  _ _  ___ 
 / _` |/ _ \/ _` |/ _ \| '_ \| '_|/ _ \
 \__,_|\___/\__, |\___/| .__/|_|  \___/
            |___/      |_|  
                          
"@ -ForegroundColor Blue

# Reset color to default
$Host.UI.RawUI.ForegroundColor = "Gray"

$ErrorActionPreference = "SilentlyContinue"
$results = @()
$errors = @()

function Run-Command {
    param([string]$cmd)
    try {
        Invoke-Expression $cmd
        if ($LASTEXITCODE -eq 0) {
            $results += "OK: $cmd"
        } else {
            $errors += "FAILED: $cmd (ExitCode: $LASTEXITCODE)"
        }
    } catch {
        $errors += "ERROR: $cmd - $($_.Exception.Message)"
    }
}

Write-Host "Stopping Windows Update Services..." -ForegroundColor Cyan
Run-Command "net stop wuauserv"
Run-Command "net stop bits"
Run-Command "net stop dosvc"
Run-Command "net stop WaaSMedicSvc"
Run-Command "net stop cryptsvc"
Run-Command "net stop usosvc"

Write-Host "Disabling Windows Update Services..." -ForegroundColor Cyan
Run-Command "sc config wuauserv start= disabled"
Run-Command "sc config bits start= disabled"
Run-Command "sc config dosvc start= disabled"
Run-Command "sc config WaaSMedicSvc start= disabled"
Run-Command "sc config usosvc start= disabled"

Write-Host "Modifying registry to disable update services..." -ForegroundColor Cyan
Run-Command "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\dosvc' -Name 'Start' -Value 4"
Run-Command "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc' -Name 'Start' -Value 4"
Run-Command "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\usosvc' -Name 'Start' -Value 4"

Write-Host "Clearing Windows Update cache folders..." -ForegroundColor Cyan
if (Test-Path C:\\Windows\\SoftwareDistribution) {
    Run-Command "takeown /f C:\\Windows\\SoftwareDistribution /r /d y"
    Run-Command "icacls C:\\Windows\\SoftwareDistribution /grant *S-1-5-32-544:F /t"
    Run-Command "rd /s /q C:\\Windows\\SoftwareDistribution"
} else {
    $errors += "Folder not found: C:\\Windows\\SoftwareDistribution"
}
if (Test-Path C:\\Windows\\System32\\catroot2) {
    Run-Command "takeown /f C:\\Windows\\System32\\catroot2 /r /d y"
    Run-Command "icacls C:\\Windows\\System32\\catroot2 /grant *S-1-5-32-544:F /t"
    Run-Command "rd /s /q C:\\Windows\\System32\\catroot2"
} else {
    $errors += "Folder not found: C:\\Windows\\System32\\catroot2"
}

Write-Host "Applying registry policies to block updates..." -ForegroundColor Cyan
Run-Command "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v NoAutoUpdate /t REG_DWORD /d 1 /f"
Run-Command "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f"
Run-Command "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f"

Write-Host "Disabling scheduled tasks for updates..." -ForegroundColor Cyan
$schedTasks = @(
    "Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
    "Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
    "Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker",
    "Microsoft\\Windows\\WindowsUpdate\\Automatic App Update",
    "Microsoft\\Windows\\WindowsUpdate\\Scheduled Start With Network"
)
foreach ($task in $schedTasks) {
    Run-Command "schtasks /Change /TN \"$task\" /Disable"
}

Write-Host "Blocking Windows Update executables..." -ForegroundColor Cyan
if (Test-Path C:\\Windows\\System32\\wuaueng.dll) {
    Run-Command "takeown /f C:\\Windows\\System32\\wuaueng.dll"
    Run-Command "icacls C:\\Windows\\System32\\wuaueng.dll /deny SYSTEM:F"
} else {
    $errors += "File not found: wuaueng.dll"
}
if (Test-Path C:\\Windows\\System32\\usoclient.exe) {
    Run-Command "takeown /f C:\\Windows\\System32\\usoclient.exe"
    Run-Command "icacls C:\\Windows\\System32\\usoclient.exe /deny SYSTEM:F"
} else {
    $errors += "File not found: usoclient.exe"
}

Write-Host "Renaming Windows Update task folders..." -ForegroundColor Cyan
if (Test-Path C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator) {
    Run-Command "ren C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator UpdateOrchestrator.old"
}
if (Test-Path C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\WindowsUpdate) {
    Run-Command "ren C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\WindowsUpdate WindowsUpdate.old"
}

Write-Host "=============================" -ForegroundColor Yellow
Write-Host "  WINDOWS UPDATE DISABLED! " -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Yellow

Write-Host "Summary of executed commands:" -ForegroundColor Cyan
$results | ForEach-Object { Write-Host $_ -ForegroundColor Green }

if ($errors.Count -gt 0) {
    Write-Host "\nErrors or Warnings:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host $_ -ForegroundColor Red }
}

Write-Host "\nHave a nice no-updating day!" -ForegroundColor Magenta
Write-Host "\nPress any key to exit..."
[void][System.Console]::ReadKey($true)
