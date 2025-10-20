#!/bin/bash

# Supabase Security Suite - Installation Script
# This script installs all dependencies and sets up the environment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║           SUPABASE SECURITY SUITE - INSTALLER            ║
║                                                           ║
║  🔒 Enterprise-Grade Security Scanning for Supabase      ║
║  🚀 AI-Powered Recommendations & Compliance Mapping      ║
║  📊 Advanced Dashboard with Real-time Monitoring         ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. Consider running as a regular user for security."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

print_status "Detected OS: $OS"

# Check Python version
print_status "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 9 ]]; then
        print_success "Python $PYTHON_VERSION found (✓ Python 3.9+ required)"
    else
        print_error "Python $PYTHON_VERSION found, but Python 3.9+ is required"
        exit 1
    fi
else
    print_error "Python 3 is not installed"
    exit 1
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed"
    exit 1
fi

print_success "pip3 found"

# Install system dependencies
print_status "Installing system dependencies..."

if [[ $OS == "linux" ]]; then
    # Detect Linux distribution
    if command -v apt-get &> /dev/null; then
        print_status "Installing packages via apt-get..."
        sudo apt-get update
        sudo apt-get install -y python3-venv python3-dev build-essential curl git
        if ! command -v docker &> /dev/null; then
            print_status "Installing Docker..."
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo usermod -aG docker $USER
            print_warning "Docker installed. You may need to log out and back in for Docker permissions."
        fi
    elif command -v yum &> /dev/null; then
        print_status "Installing packages via yum..."
        sudo yum update -y
        sudo yum install -y python3-devel gcc git curl
        if ! command -v docker &> /dev/null; then
            print_status "Installing Docker..."
            sudo yum install -y docker
            sudo systemctl start docker
            sudo systemctl enable docker
            sudo usermod -aG docker $USER
        fi
    else
        print_warning "Package manager not detected. Please install: python3-dev, build-essential, git, docker"
    fi
elif [[ $OS == "macos" ]]; then
    if command -v brew &> /dev/null; then
        print_status "Installing packages via Homebrew..."
        brew install python git docker
    else
        print_warning "Homebrew not found. Please install: Python 3.9+, git, docker"
    fi
fi

# Check for Docker
if command -v docker &> /dev/null; then
    print_success "Docker found"
    if docker info &> /dev/null; then
        print_success "Docker daemon is running"
    else
        print_warning "Docker daemon is not running. Please start Docker before using volume scanning features."
    fi
else
    print_warning "Docker not found. Volume scanning features will be limited."
fi

# Check for nmap (optional)
if command -v nmap &> /dev/null; then
    print_success "nmap found (enhanced port scanning available)"
else
    print_warning "nmap not found. Basic port scanning will be used."
fi

# Create virtual environment
print_status "Creating Python virtual environment..."
if [[ -d "venv" ]]; then
    print_warning "Virtual environment already exists. Removing..."
    rm -rf venv
fi

python3 -m venv venv
print_success "Virtual environment created"

# Activate virtual environment and install dependencies
print_status "Installing Python dependencies..."
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
if [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt
    print_success "Python dependencies installed"
else
    print_error "requirements.txt not found"
    exit 1
fi

# Create configuration file if it doesn't exist
if [[ ! -f "config.json" ]]; then
    if [[ -f "config.example.json" ]]; then
        cp config.example.json config.json
        print_success "Configuration file created from example"
    else
        print_warning "No configuration example found"
    fi
fi

# Set up permissions
print_status "Setting up permissions..."
chmod +x final.py
chmod +x dashboard_server.py
chmod +x cli_dashboard.py
chmod +x start_dashboard.sh
chmod +x test_suite.py

print_success "File permissions set"

# Create reports directory
mkdir -p supabase_security_reports
chmod 755 supabase_security_reports

print_success "Reports directory created"

# Run basic tests
print_status "Running basic tests..."
if python test_suite.py --quick; then
    print_success "Basic tests passed"
else
    print_warning "Some tests failed, but installation completed"
fi

# Final instructions
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                INSTALLATION COMPLETE!                    ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}Quick Start:${NC}"
echo -e "1. ${YELLOW}Activate virtual environment:${NC} source venv/bin/activate"
echo -e "2. ${YELLOW}Start dashboard:${NC} ./start_dashboard.sh"
echo -e "3. ${YELLOW}Open browser:${NC} http://localhost:8080"
echo -e "4. ${YELLOW}CLI usage:${NC} python final.py --help"

echo -e "\n${BLUE}Configuration:${NC}"
echo -e "- Edit ${YELLOW}config.json${NC} to customize settings"
echo -e "- Add API keys for AI recommendations (optional)"
echo -e "- Configure Jira integration (optional)"

echo -e "\n${BLUE}Documentation:${NC}"
echo -e "- ${YELLOW}README.md${NC} - Complete documentation"
echo -e "- ${YELLOW}DASHBOARD_GUIDE.md${NC} - Dashboard usage guide"
echo -e "- ${YELLOW}CONTRIBUTING.md${NC} - Development guidelines"

echo -e "\n${BLUE}Support:${NC}"
echo -e "- Run tests: ${YELLOW}python test_suite.py${NC}"
echo -e "- CLI help: ${YELLOW}python final.py --help${NC}"
echo -e "- Dashboard: ${YELLOW}http://localhost:8080${NC}"

print_success "Supabase Security Suite is ready to use! 🚀"
