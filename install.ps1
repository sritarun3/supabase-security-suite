# Supabase Security Suite - Windows Installation Script
# This script installs all dependencies and sets up the environment on Windows

param(
    [switch]$SkipDocker,
    [switch]$SkipTests,
    [switch]$Force
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    White = "White"
}

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Colors.Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Colors.Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Colors.Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Colors.Red
}

# Banner
Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║           SUPABASE SECURITY SUITE - INSTALLER            ║
║                                                           ║
║  🔒 Enterprise-Grade Security Scanning for Supabase      ║
║  🚀 AI-Powered Recommendations & Compliance Mapping      ║
║  📊 Advanced Dashboard with Real-time Monitoring         ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor $Colors.Blue

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ($isAdmin) {
    Write-Warning "Running as Administrator. Consider running as a regular user for security."
    if (-not $Force) {
        $response = Read-Host "Continue anyway? (y/N)"
        if ($response -notmatch "^[Yy]$") {
            exit 1
        }
    }
}

# Check Python installation
Write-Status "Checking Python installation..."
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    
    $versionMatch = $pythonVersion -match "Python (\d+)\.(\d+)"
    if ($versionMatch) {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]
        
        if ($major -eq 3 -and $minor -ge 9) {
            Write-Success "Python $($matches[1]).$($matches[2]) found (✓ Python 3.9+ required)"
        } else {
            throw "Python $($matches[1]).$($matches[2]) found, but Python 3.9+ is required"
        }
    } else {
        throw "Could not determine Python version"
    }
} catch {
    Write-Error "Python 3.9+ is required but not found. Please install Python from https://python.org"
    exit 1
}

# Check pip
try {
    pip --version | Out-Null
    Write-Success "pip found"
} catch {
    Write-Error "pip is not installed"
    exit 1
}

# Install Chocolatey if not present (for package management)
Write-Status "Checking package manager..."
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Status "Installing Chocolatey package manager..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    
    # Refresh environment
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Install system dependencies
Write-Status "Installing system dependencies..."

# Install Git if not present
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Status "Installing Git..."
    choco install git -y
}

# Install Docker Desktop if not present and not skipped
if (-not $SkipDocker) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Status "Installing Docker Desktop..."
        choco install docker-desktop -y
        Write-Warning "Docker Desktop installed. Please restart your computer and start Docker Desktop before using volume scanning features."
    } else {
        Write-Success "Docker found"
    }
} else {
    Write-Warning "Docker installation skipped. Volume scanning features will be limited."
}

# Install nmap if not present (optional)
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Status "Installing nmap for enhanced port scanning..."
    choco install nmap -y
} else {
    Write-Success "nmap found (enhanced port scanning available)"
}

# Create virtual environment
Write-Status "Creating Python virtual environment..."
if (Test-Path "venv") {
    if ($Force) {
        Write-Status "Removing existing virtual environment..."
        Remove-Item -Recurse -Force venv
    } else {
        Write-Warning "Virtual environment already exists. Use -Force to recreate."
        exit 1
    }
}

python -m venv venv
Write-Success "Virtual environment created"

# Activate virtual environment and install dependencies
Write-Status "Installing Python dependencies..."

# Activate virtual environment
& ".\venv\Scripts\Activate.ps1"

# Upgrade pip
python -m pip install --upgrade pip

# Install requirements
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
    Write-Success "Python dependencies installed"
} else {
    Write-Error "requirements.txt not found"
    exit 1
}

# Create configuration file if it doesn't exist
if (-not (Test-Path "config.json")) {
    if (Test-Path "config.example.json") {
        Copy-Item config.example.json config.json
        Write-Success "Configuration file created from example"
    } else {
        Write-Warning "No configuration example found"
    }
}

# Set up permissions
Write-Status "Setting up file permissions..."
# Make scripts executable (Unix-style permissions don't apply on Windows, but we can set attributes)
Get-ChildItem -Path "*.py" | ForEach-Object { $_.Attributes = "Normal" }
Get-ChildItem -Path "*.sh" | ForEach-Object { $_.Attributes = "Normal" }

Write-Success "File permissions set"

# Create reports directory
if (-not (Test-Path "supabase_security_reports")) {
    New-Item -ItemType Directory -Name "supabase_security_reports"
}
Write-Success "Reports directory created"

# Run basic tests
if (-not $SkipTests) {
    Write-Status "Running basic tests..."
    try {
        python test_suite.py --quick
        Write-Success "Basic tests passed"
    } catch {
        Write-Warning "Some tests failed, but installation completed"
    }
}

# Create Windows batch files for easy execution
Write-Status "Creating Windows batch files..."

# Create start_dashboard.bat
@"
@echo off
cd /d "%~dp0"
call venv\Scripts\activate.bat
python dashboard_server.py
pause
"@ | Out-File -FilePath "start_dashboard.bat" -Encoding ASCII

# Create run_scanner.bat
@"
@echo off
cd /d "%~dp0"
call venv\Scripts\activate.bat
python final.py %*
pause
"@ | Out-File -FilePath "run_scanner.bat" -Encoding ASCII

Write-Success "Windows batch files created"

# Final instructions
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║                INSTALLATION COMPLETE!                    ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor $Colors.Green

Write-Host "`nQuick Start:" -ForegroundColor $Colors.Blue
Write-Host "1. Start dashboard: Double-click start_dashboard.bat" -ForegroundColor $Colors.White
Write-Host "2. Open browser: http://localhost:8080" -ForegroundColor $Colors.White
Write-Host "3. CLI usage: Double-click run_scanner.bat" -ForegroundColor $Colors.White

Write-Host "`nAlternative (PowerShell):" -ForegroundColor $Colors.Blue
Write-Host "1. Activate environment: .\venv\Scripts\Activate.ps1" -ForegroundColor $Colors.White
Write-Host "2. Start dashboard: python dashboard_server.py" -ForegroundColor $Colors.White
Write-Host "3. CLI usage: python final.py --help" -ForegroundColor $Colors.White

Write-Host "`nConfiguration:" -ForegroundColor $Colors.Blue
Write-Host "- Edit config.json to customize settings" -ForegroundColor $Colors.White
Write-Host "- Add API keys for AI recommendations (optional)" -ForegroundColor $Colors.White
Write-Host "- Configure Jira integration (optional)" -ForegroundColor $Colors.White

Write-Host "`nDocumentation:" -ForegroundColor $Colors.Blue
Write-Host "- README.md - Complete documentation" -ForegroundColor $Colors.White
Write-Host "- DASHBOARD_GUIDE.md - Dashboard usage guide" -ForegroundColor $Colors.White
Write-Host "- CONTRIBUTING.md - Development guidelines" -ForegroundColor $Colors.White

Write-Host "`nSupport:" -ForegroundColor $Colors.Blue
Write-Host "- Run tests: python test_suite.py" -ForegroundColor $Colors.White
Write-Host "- CLI help: python final.py --help" -ForegroundColor $Colors.White
Write-Host "- Dashboard: http://localhost:8080" -ForegroundColor $Colors.White

Write-Success "Supabase Security Suite is ready to use! 🚀"
