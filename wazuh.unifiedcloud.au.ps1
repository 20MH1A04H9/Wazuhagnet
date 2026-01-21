# ============================================================
# WAZUH AGENT INSTALL + OSSEC CLEANUP + SCA ENABLE (WINDOWS)
# ============================================================

# ------------------------------
# RUN AS ADMINISTRATOR CHECK
# ------------------------------
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole] "Administrator")) {

    Write-Warning "This script must be run as Administrator!"
    Start-Process powershell `
        "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
        -Verb RunAs
    exit
}

# ------------------------------
# EXECUTION POLICY (SESSION ONLY)
# ------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Write-Host "ExecutionPolicy set to Bypass for this session"

# ============================================================
# PART 1: INSTALL WAZUH AGENT
# ============================================================

$WazuhManager = "wazuh.unifiedcloud.au"
$AgentName    = $env:COMPUTERNAME
$Version      = "4.14.1"
$MsiPath      = "$env:TEMP\wazuh-agent.msi"
$LogPath      = "$env:TEMP\wazuh-agent-install.log"

Write-Host "Downloading Wazuh agent..."
Invoke-WebRequest `
    -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi" `
    -OutFile $MsiPath

Write-Host "Installing Wazuh agent..."
Start-Process msiexec `
    -ArgumentList "/i `"$MsiPath`" /qn /l*v `"$LogPath`" WAZUH_MANAGER=`"$WazuhManager`" WAZUH_AGENT_NAME=`"$AgentName`"" `
    -Wait

if (-not (Get-Service -Name Wazuh -ErrorAction SilentlyContinue)) {
    Write-Error "Wazuh agent installation FAILED. Check log: $LogPath"
    exit 1
}

Write-Host "Wazuh agent installed successfully"

# ============================================================
# PART 2: OSSEC.CONF CLEANUP
# ============================================================

$configPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

if (-Not (Test-Path $configPath)) {
    Write-Error "OSSEC config file not found at: $configPath"
    exit 1
}

$backupPath = "$configPath.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item $configPath $backupPath -Force
Write-Host "Backup created: $backupPath"

$content = Get-Content $configPath -Raw

$content = $content -replace '(?s)\s*<!-- Default files to be monitored\. -->', ''
$content = $content -replace '(?s)\s*<directories recursion_level="0".*?</directories>', ''
$content = $content -replace '(?s)\s*<windows_registry.*?</windows_registry>', ''
$content = $content -replace '(?s)\s*<registry_ignore.*?</registry_ignore>', ''

$content = $content -replace '(?m)^\s*$\n', ''
$content = $content -replace '\n{3,}', "`n`n"

Set-Content -Path $configPath -Value $content -NoNewline
Write-Host "OSSEC configuration cleaned successfully"

# ============================================================
# PART 3: ENABLE SCA + REMOTE COMMANDS
# ============================================================

$internalOptions = "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

if (-not (Test-Path $internalOptions)) {
    New-Item -Path $internalOptions -ItemType File -Force | Out-Null
}

Copy-Item $internalOptions "$internalOptions.bak" -Force
Write-Host "Backup created: $internalOptions.bak"

# Read existing content
$lines = Get-Content $internalOptions -ErrorAction SilentlyContinue
    
# Remove existing entries
$lines = $lines | Where-Object {
    $_ -notmatch '^wazuh_command\.remote_commands=1' -and
    $_ -notmatch '^sca\.remote_commands=1'
}

# Add required settings
$lines += 'wazuh_command.remote_commands=1'
$lines += 'sca.remote_commands=1'

Set-Content -Path $internalOptions -Value $lines
Write-Host "SCA and remote commands enabled"

# ============================================================
# PART 4: RESTART WAZUH AGENT
# ============================================================

Restart-Service Wazuh -Force
Get-Service Wazuh

Write-Host "Wazuh agent restarted successfully"
Write-Host "Installation + SCA configuration completed"
