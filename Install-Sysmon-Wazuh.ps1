# Continue on error
$ErrorActionPreference = 'Continue'

# Require elevation for script run
#Requires -RunAsAdministrator

# Set the script location to the script root
$scriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
Set-Location -Path $scriptRoot

# Function to refresh environment variables
function RefreshEnv {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# Check if Sysmon.exe exists, install it if not
$sysmonPath = Get-Command -Name "Sysmon.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source

if (-not $sysmonPath) {
    Write-Host "Sysmon.exe does not exist, installing..." -ForegroundColor Yellow
    
    # Check if Chocolatey is already installed
    $chocoInstalled = Get-Command -Name "choco" -ErrorAction SilentlyContinue
    
    if (-not $chocoInstalled) {
        # Install Chocolatey and upgrade all packages
        Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
        Start-Job -Name "Install and Configure Chocolatey" -ScriptBlock {
            Write-Host "Installing Chocolatey"
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            choco feature enable -n=allowGlobalConfirmation
            choco feature enable -n=useFipsCompliantChecksums
            choco feature enable -n=useEnhancedExitCodes
            choco config set commandExecutionTimeoutSeconds 14400
            choco config set --name="'cacheLocation'" --value="'C:\temp\chococache'"
            choco config set --name="'proxyBypassOnLocal'" --value="'true'"
            choco upgrade all
        }
        
        Write-Host "Sleeping for 60 seconds while Chocolatey is installed..." -ForegroundColor Yellow
        Start-Sleep -Seconds 60
        RefreshEnv
    }
    else {
        Write-Host "Chocolatey is already installed." -ForegroundColor Green
    }
    
    # Install Sysmon
    Write-Host "Installing Sysmon via Chocolatey..." -ForegroundColor Cyan
    choco install sysmon -y
    
    # Refresh Environment to Call Sysmon.exe Natively
    RefreshEnv
    
    # Re-check for Sysmon after installation
    $sysmonPath = Get-Command -Name "Sysmon.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    
    if (-not $sysmonPath) {
        Write-Host "ERROR: Sysmon installation failed. Please install manually." -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "Sysmon.exe exists at: $sysmonPath" -ForegroundColor Green
}

# Download Wazuh Sysmon Configuration
$sysmonConfigUrl = 'https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml'
$sysmonConfigLocalPath = Join-Path -Path $scriptRoot -ChildPath 'Files/sysmonconfig.xml'

# Ensure the Files directory exists
$filesDir = Join-Path -Path $scriptRoot -ChildPath 'Files'
if (-not (Test-Path -Path $filesDir)) {
    Write-Host "Creating Files directory..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $filesDir -Force | Out-Null
}

try {
    Write-Host "Checking Wazuh repo accessibility..." -ForegroundColor Cyan
    $webRequest = [System.Net.WebRequest]::Create($sysmonConfigUrl)
    $webRequest.Timeout = 10000  # 10 second timeout
    $webResponse = $webRequest.GetResponse()
    $statusCode = $webResponse.StatusCode
    
    if ($statusCode -eq 'OK') {
        Write-Host "Repo access is available. Downloading latest Wazuh Sysmon config..." -ForegroundColor Green
        Invoke-WebRequest -Uri $sysmonConfigUrl -OutFile $sysmonConfigLocalPath -UseBasicParsing
        Write-Host "Configuration file downloaded successfully to: $sysmonConfigLocalPath" -ForegroundColor Green
    }
    else {
        Write-Host "Unexpected response code: $statusCode. Checking for local copy..." -ForegroundColor Yellow
        if (-not (Test-Path -Path $sysmonConfigLocalPath)) {
            Write-Host "ERROR: Local configuration file not found at: $sysmonConfigLocalPath" -ForegroundColor Red
            Write-Host "Please download the configuration manually from: $sysmonConfigUrl" -ForegroundColor Yellow
            exit 1
        }
    }
}
catch {
    Write-Host "Error accessing the repo: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Checking for local copy..." -ForegroundColor Yellow
    
    if (-not (Test-Path -Path $sysmonConfigLocalPath)) {
        Write-Host "ERROR: Local configuration file not found at: $sysmonConfigLocalPath" -ForegroundColor Red
        Write-Host "Please download the configuration manually from: $sysmonConfigUrl" -ForegroundColor Yellow
        exit 1
    }
    else {
        Write-Host "Using local configuration file." -ForegroundColor Green
    }
}
finally {
    if ($webResponse) {
        $webResponse.Close()
    }
}

# Verify the configuration file exists before proceeding
if (-not (Test-Path -Path $sysmonConfigLocalPath)) {
    Write-Host "ERROR: Configuration file not available. Cannot proceed with Sysmon installation." -ForegroundColor Red
    exit 1
}

# Uninstall any existing Sysmon instance
Write-Host "Uninstalling any existing Sysmon instance..." -ForegroundColor Cyan
& $sysmonPath -u force 2>&1 | Out-Null

# Install Sysmon with the Wazuh configuration
Write-Host "Installing Sysmon with Wazuh configuration..." -ForegroundColor Cyan
$installResult = & $sysmonPath -accepteula -i $sysmonConfigLocalPath 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "Sysmon installed successfully with Wazuh configuration!" -ForegroundColor Green
    Write-Host "Configuration file: $sysmonConfigLocalPath" -ForegroundColor Green
}
else {
    Write-Host "WARNING: Sysmon installation may have encountered issues." -ForegroundColor Yellow
    Write-Host "Exit Code: $LASTEXITCODE" -ForegroundColor Yellow
    Write-Host "Output: $installResult" -ForegroundColor Yellow
}

# Verify Sysmon service is running
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if ($sysmonService) {
    if ($sysmonService.Status -eq 'Running') {
        Write-Host "Sysmon service is running successfully!" -ForegroundColor Green
    }
    else {
        Write-Host "WARNING: Sysmon service exists but is not running. Status: $($sysmonService.Status)" -ForegroundColor Yellow
        Write-Host "Attempting to start the service..." -ForegroundColor Cyan
        Start-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        
        $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        if ($sysmonService.Status -eq 'Running') {
            Write-Host "Sysmon service started successfully!" -ForegroundColor Green
        }
        else {
            Write-Host "ERROR: Failed to start Sysmon service." -ForegroundColor Red
        }
    }
}
else {
    Write-Host "WARNING: Sysmon service not found. Installation may have failed." -ForegroundColor Yellow
}

Write-Host "`nSysmon installation and configuration complete!" -ForegroundColor Green
Write-Host "Configuration URL: $sysmonConfigUrl" -ForegroundColor Cyan
Write-Host "Local Configuration: $sysmonConfigLocalPath" -ForegroundColor Cyan
