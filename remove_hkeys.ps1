# =====================================================
# AUTO-ELEVATION (RUN AS ADMIN)
# =====================================================
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Start-Process powershell.exe `
        -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
        -Verb RunAs
    exit
}

Set-ExecutionPolicy Bypass -Scope Process -Force
Write-Host "Running as Administrator..."

# =====================================================
# VARIABLES
# =====================================================
$ServiceName  = "WazuhSvc"
$InstallPath = "C:\Program Files (x86)\ossec-agent"
$configPath  = "$InstallPath\ossec.conf"
$internalOptions = "$InstallPath\local_internal_options.conf"

# =====================================================
# VALIDATE AGENT EXISTS
# =====================================================
if (-not (Test-Path $InstallPath)) {
    Write-Error "Wazuh agent not found at $InstallPath"
    exit 1
}

# =====================================================
# PART 3: OSSEC.CONF CLEANUP
# =====================================================
Write-Host "`nCleaning ossec.conf..."

if (-not (Test-Path $configPath)) {
    Write-Error "ossec.conf not found"
    exit 1
}

$backupPath = "$configPath.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item $configPath $backupPath -Force
Write-Host "Backup created: $backupPath"

$content = Get-Content $configPath -Raw

$content = $content -replace '(?s)\s*<!-- Default files to be monitored\. -->', ''
$content = $content -replace '(?s)\s*<directories.*?</directories>', ''
$content = $content -replace '(?s)\s*<windows_registry.*?</windows_registry>', ''
$content = $content -replace '(?s)\s*<registry_ignore.*?</registry_ignore>', ''

$content = $content -replace '\n{3,}', "`n`n"

Set-Content -Path $configPath -Value $content -NoNewline
Write-Host "ossec.conf cleaned successfully"

# =====================================================
# PART 4: ENABLE SCA + REMOTE COMMANDS
# =====================================================
Write-Host "`nEnabling SCA + remote commands..."

if (-not (Test-Path $internalOptions)) {
    New-Item -Path $internalOptions -ItemType File -Force | Out-Null
}

Copy-Item $internalOptions "$internalOptions.bak" -Force
Write-Host "Backup created: $internalOptions.bak"

$lines = Get-Content $internalOptions -ErrorAction SilentlyContinue |
    Where-Object {
        $_ -notmatch '^wazuh_command\.remote_commands=1' -and
        $_ -notmatch '^sca\.remote_commands=1'
    }

$lines += 'wazuh_command.remote_commands=1'
$lines += 'sca.remote_commands=1'

Set-Content -Path $internalOptions -Value $lines
Write-Host "SCA + remote commands enabled"

# =====================================================
# RESTART AGENT
# =====================================================
Restart-Service $ServiceName -Force
Get-Service $ServiceName

Write-Host "`nConfiguration update completed successfully."
