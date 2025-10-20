#!/bin/bash
#
# Supabase Security Dashboard - Startup Script
# Enterprise Production Ready
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPORTS_DIR="$SCRIPT_DIR/supabase_security_reports"
DASHBOARD_PORT=8080

# Functions
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║   SUPABASE SECURITY DASHBOARD - Enterprise Edition       ║
║   Production-Ready Security Analysis & Monitoring        ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ Python 3 not found${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Python 3 found${NC}"
    
    # Check required Python packages
    if ! python3 -c "import flask" 2>/dev/null; then
        echo -e "${YELLOW}⚠ Flask not installed. Installing dependencies...${NC}"
        pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
    fi
    echo -e "${GREEN}✓ Python packages installed${NC}"
    
    # Check nmap (optional)
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}✓ nmap found (enhanced port scanning enabled)${NC}"
    else
        echo -e "${YELLOW}⚠ nmap not found (will use socket fallback for port scanning)${NC}"
        echo -e "${YELLOW}  Install with: sudo apt-get install nmap${NC}"
    fi
    
    echo ""
}

check_port() {
    if lsof -Pi :$DASHBOARD_PORT -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        echo -e "${YELLOW}⚠ Port $DASHBOARD_PORT is already in use${NC}"
        echo -e "${YELLOW}  Kill existing process? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            lsof -ti:$DASHBOARD_PORT | xargs kill -9 2>/dev/null || true
            sleep 1
            echo -e "${GREEN}✓ Port $DASHBOARD_PORT cleared${NC}"
        else
            echo -e "${RED}✗ Cannot start dashboard on port $DASHBOARD_PORT${NC}"
            exit 1
        fi
    fi
}

start_web_dashboard() {
    echo -e "${BLUE}Starting Web Dashboard...${NC}"
    
    cd "$SCRIPT_DIR"
    nohup python3 dashboard_server.py > "$SCRIPT_DIR/dashboard.log" 2>&1 &
    
    DASH_PID=$!
    echo $DASH_PID > "$SCRIPT_DIR/dashboard.pid"
    
    sleep 2
    
    if ps -p $DASH_PID > /dev/null; then
        echo -e "${GREEN}✓ Web Dashboard started (PID: $DASH_PID)${NC}"
        echo -e "${GREEN}  URL: http://localhost:$DASHBOARD_PORT${NC}"
        echo -e "${GREEN}  Logs: $SCRIPT_DIR/dashboard.log${NC}"
    else
        echo -e "${RED}✗ Failed to start dashboard${NC}"
        echo -e "${RED}  Check logs: tail -f $SCRIPT_DIR/dashboard.log${NC}"
        exit 1
    fi
}

start_cli_dashboard() {
    echo -e "${BLUE}Starting CLI Dashboard...${NC}"
    cd "$SCRIPT_DIR"
    python3 cli_dashboard.py --watch
}

show_status() {
    echo -e "${CYAN}Dashboard Status:${NC}"
    
    if [ -f "$SCRIPT_DIR/dashboard.pid" ]; then
        PID=$(cat "$SCRIPT_DIR/dashboard.pid")
        if ps -p $PID > /dev/null; then
            echo -e "${GREEN}✓ Web Dashboard running (PID: $PID)${NC}"
            echo -e "  URL: http://localhost:$DASHBOARD_PORT"
        else
            echo -e "${RED}✗ Web Dashboard not running${NC}"
        fi
    else
        echo -e "${RED}✗ Web Dashboard not started${NC}"
    fi
    
    # Check for reports
    if [ -d "$REPORTS_DIR" ]; then
        REPORT_COUNT=$(find "$REPORTS_DIR" -name "report*.json" | wc -l)
        echo -e "${BLUE}Reports available: $REPORT_COUNT${NC}"
    fi
}

stop_dashboard() {
    echo -e "${BLUE}Stopping dashboard...${NC}"
    
    if [ -f "$SCRIPT_DIR/dashboard.pid" ]; then
        PID=$(cat "$SCRIPT_DIR/dashboard.pid")
        if ps -p $PID > /dev/null; then
            kill $PID
            rm "$SCRIPT_DIR/dashboard.pid"
            echo -e "${GREEN}✓ Dashboard stopped${NC}"
        else
            echo -e "${YELLOW}⚠ Dashboard not running${NC}"
            rm "$SCRIPT_DIR/dashboard.pid"
        fi
    else
        echo -e "${YELLOW}⚠ No PID file found${NC}"
    fi
}

run_scan() {
    echo -e "${BLUE}Running security scan...${NC}"
    
    SCAN_PATH="${1:-/home/debian/supabase}"
    SUPABASE_URL="${2:-}"
    DB_URL="${3:-}"
    
    cd "$SCRIPT_DIR"
    
    CMD="python3 final.py --path $SCAN_PATH --fancy --out $REPORTS_DIR"
    
    if [ -n "$SUPABASE_URL" ]; then
        CMD="$CMD --supabase-url $SUPABASE_URL --allow-external"
    fi
    
    if [ -n "$DB_URL" ]; then
        CMD="$CMD --db-url \"$DB_URL\""
    fi
    
    echo -e "${CYAN}Running: $CMD${NC}"
    eval $CMD
    
    echo -e "${GREEN}✓ Scan complete${NC}"
    echo -e "${GREEN}  Reports: $REPORTS_DIR/${NC}"
}

show_help() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
    start           Start web dashboard (default)
    start-cli       Start CLI dashboard with live updates
    stop            Stop web dashboard
    status          Show dashboard status
    scan            Run security scan
    restart         Restart web dashboard
    logs            Show dashboard logs
    help            Show this help message

Examples:
    # Start web dashboard
    $0 start

    # Start CLI dashboard
    $0 start-cli

    # Run security scan
    $0 scan /path/to/supabase http://host:54321 "postgresql://..."

    # View logs
    $0 logs

    # Check status
    $0 status

EOF
}

# Main
print_banner

case "${1:-start}" in
    start)
        check_dependencies
        check_port
        start_web_dashboard
        echo ""
        echo -e "${CYAN}Next steps:${NC}"
        echo -e "  1. Open browser: ${GREEN}http://localhost:$DASHBOARD_PORT${NC}"
        echo -e "  2. View logs: ${BLUE}tail -f $SCRIPT_DIR/dashboard.log${NC}"
        echo -e "  3. Run scan: ${BLUE}$0 scan${NC}"
        echo ""
        ;;
    
    start-cli)
        check_dependencies
        start_cli_dashboard
        ;;
    
    stop)
        stop_dashboard
        ;;
    
    status)
        show_status
        ;;
    
    scan)
        check_dependencies
        run_scan "${2:-}" "${3:-}" "${4:-}"
        ;;
    
    restart)
        stop_dashboard
        sleep 2
        check_port
        start_web_dashboard
        ;;
    
    logs)
        if [ -f "$SCRIPT_DIR/dashboard.log" ]; then
            tail -f "$SCRIPT_DIR/dashboard.log"
        else
            echo -e "${RED}No log file found${NC}"
        fi
        ;;
    
    help)
        show_help
        ;;
    
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac

