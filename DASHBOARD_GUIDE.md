# Supabase Security Dashboard - Enterprise Production Guide

## 🚀 Complete Security Suite

This enterprise-grade security solution includes:

1. **Core Security Scanner** (`final.py`) - With nmap integration
2. **Web Dashboard** (`dashboard_server.py`) - GUI on port 6666
3. **CLI Dashboard** (`cli_dashboard.py`) - Terminal-based real-time monitoring

---

## 📦 Installation

### 1. Install Dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Install nmap (optional but recommended for better port scanning)
# Ubuntu/Debian:
sudo apt-get install -y nmap

# macOS:
brew install nmap

# Windows:
# Download from https://nmap.org/download.html
```

### 2. Verify Installation

```bash
# Check if all components are ready
python3 -c "import flask, rich; print('✅ All dependencies installed')"
nmap --version  # Should show nmap version
```

---

## 🔍 Core Security Scanner

### Basic Usage

```bash
# Scan local Supabase project
python3 final.py --path /path/to/supabase/project --fancy

# Full scan with external access
python3 final.py \
  --path /home/debian/supabase \
  --supabase-url http://144.217.163.132:54321 \
  --db-url "postgresql://postgres:postgres@144.217.163.132:54322/postgres" \
  --allow-external \
  --fancy \
  --out ./security_reports
```

### With AI Recommendations

```bash
export OPENAI_API_KEY="sk-your-api-key"

python3 final.py \
  --path /home/debian/supabase \
  --supabase-url http://144.217.163.132:54321 \
  --db-url "postgresql://postgres:postgres@144.217.163.132:54322/postgres" \
  --allow-external \
  --fancy \
  --openai-api-key "$OPENAI_API_KEY"
```

### Features

- ✅ **Static Code Analysis** - Scans for secrets, weak configs
- ✅ **Semgrep Integration** - Advanced pattern matching
- ✅ **Runtime Probes** - Live endpoint testing
- ✅ **Database Checks** - RLS, SECURITY DEFINER, search_path
- ✅ **nmap Port Scanning** - With socket fallback
- ✅ **AI Recommendations** - OpenAI-powered advice (optional)
- ✅ **Compliance Mapping** - SOC2, HIPAA, ISO27001

---

## 🌐 Web Dashboard (GUI)

### Start the Dashboard

```bash
python3 dashboard_server.py
```

### Access

- **Dashboard URL**: http://localhost:6666
- **API Endpoint**: http://localhost:6666/api/reports

### Features

- 📊 **Real-time Charts** - Severity & source distribution
- 🚨 **Critical Alerts** - Highlighted high-risk findings
- ⚖️ **Compliance View** - Standard violations
- 🔄 **Auto-refresh** - Live updates
- 📥 **Export** - JSON/Markdown reports
- 🎨 **Modern UI** - Responsive design

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/reports` | GET | List all reports |
| `/api/report/<filename>` | GET | Get specific report |
| `/api/findings/critical` | GET | Get critical findings only |
| `/api/scan/status` | GET | Get scan status |
| `/api/scan/start` | POST | Trigger new scan |
| `/api/export/<format>/<filename>` | GET | Export report |

### Running in Background

```bash
# Using nohup
nohup python3 dashboard_server.py > dashboard.log 2>&1 &

# Using screen
screen -dmS dashboard python3 dashboard_server.py

# Using systemd (production)
sudo systemctl start supabase-dashboard
```

---

## 💻 CLI Dashboard

### Basic Usage

```bash
# Static view
python3 cli_dashboard.py

# Live updates (refreshes every 5 seconds)
python3 cli_dashboard.py --watch

# Custom reports directory
python3 cli_dashboard.py --reports-dir /path/to/reports
```

### Features

- 📊 **Real-time Statistics** - Live severity & source counts
- 🚨 **Top Findings** - Critical/High priority issues
- ⚖️ **Compliance Summary** - Violations by standard
- 💡 **Action Items** - Top recommendations
- 🔄 **Auto-refresh** - Watch mode for live monitoring
- 🎨 **Rich UI** - Beautiful terminal formatting

---

## 🔧 Production Deployment

### 1. Systemd Service (Web Dashboard)

Create `/etc/systemd/system/supabase-dashboard.service`:

```ini
[Unit]
Description=Supabase Security Dashboard
After=network.target

[Service]
Type=simple
User=debian
WorkingDirectory=/home/debian/script
ExecStart=/usr/bin/python3 /home/debian/script/dashboard_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable supabase-dashboard
sudo systemctl start supabase-dashboard
sudo systemctl status supabase-dashboard
```

### 2. Nginx Reverse Proxy

Add to Nginx config:

```nginx
server {
    listen 80;
    server_name security-dashboard.yourdomain.com;

    location / {
        proxy_pass http://localhost:6666;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. SSL/TLS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d security-dashboard.yourdomain.com
```

### 4. Firewall Configuration

```bash
# Allow dashboard port
sudo ufw allow 6666/tcp

# Or restrict to specific IPs
sudo ufw allow from 192.168.1.0/24 to any port 6666
```

---

## 📊 Scheduled Scans

### Using Cron

```bash
# Edit crontab
crontab -e

# Add daily scan at 2 AM
0 2 * * * cd /home/debian/script && python3 final.py --path /home/debian/supabase --supabase-url http://144.217.163.132:54321 --db-url "postgresql://postgres:postgres@144.217.163.132:54322/postgres" --allow-external --fancy --out ./supabase_security_reports >> /var/log/security-scan.log 2>&1
```

### Using Systemd Timer

Create `/etc/systemd/system/security-scan.service`:

```ini
[Unit]
Description=Supabase Security Scan

[Service]
Type=oneshot
User=debian
WorkingDirectory=/home/debian/script
ExecStart=/usr/bin/python3 /home/debian/script/final.py --path /home/debian/supabase --allow-external --fancy
```

Create `/etc/systemd/system/security-scan.timer`:

```ini
[Unit]
Description=Daily Security Scan Timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl enable security-scan.timer
sudo systemctl start security-scan.timer
```

---

## 🔔 Alerting & Notifications

### Slack Webhook (Example)

```python
# Add to final.py after scan completion
import requests

def send_slack_alert(score, critical_count):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    
    message = {
        "text": f"🚨 Security Scan Complete",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Security Score:* {score}/100\n*Critical Issues:* {critical_count}"
                }
            }
        ]
    }
    
    requests.post(webhook_url, json=message)
```

### Email Alerts (Example)

```python
import smtplib
from email.mime.text import MIMEText

def send_email_alert(score, report_path):
    msg = MIMEText(f"Security scan completed. Score: {score}/100")
    msg['Subject'] = 'Supabase Security Scan Alert'
    msg['From'] = 'security@yourdomain.com'
    msg['To'] = 'admin@yourdomain.com'
    
    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)
```

---

## 📈 Monitoring & Metrics

### Prometheus Metrics (Optional)

```python
from prometheus_client import start_http_server, Gauge

security_score = Gauge('supabase_security_score', 'Current security score')
critical_findings = Gauge('supabase_critical_findings', 'Number of critical findings')

# Update metrics after scan
security_score.set(result.score)
critical_findings.set(len([f for f in result.findings if f.severity == 'CRITICAL']))

# Start metrics server
start_http_server(9090)
```

---

## 🛡️ Security Best Practices

### 1. Dashboard Access Control

```python
# Add authentication to dashboard_server.py
from functools import wraps
from flask import request, abort

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if auth != 'Bearer YOUR_SECRET_TOKEN':
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route('/api/reports')
@require_auth
def get_reports():
    # ...
```

### 2. Rate Limiting

```bash
pip install flask-limiter
```

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/scan/start', methods=['POST'])
@limiter.limit("5 per hour")
def start_scan():
    # ...
```

### 3. HTTPS Only

```python
from flask_talisman import Talisman

Talisman(app, force_https=True)
```

---

## 📝 Quick Start Commands

### Complete Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt
sudo apt-get install -y nmap

# 2. Run initial scan
python3 final.py --path /home/debian/supabase --fancy

# 3. Start web dashboard (background)
nohup python3 dashboard_server.py > dashboard.log 2>&1 &

# 4. View in browser
open http://localhost:6666

# 5. Monitor in terminal
python3 cli_dashboard.py --watch
```

### Troubleshooting

```bash
# Check if dashboard is running
ps aux | grep dashboard_server

# View dashboard logs
tail -f dashboard.log

# Test API
curl http://localhost:6666/api/reports

# Check port availability
netstat -tuln | grep 6666
```

---

## 📚 Additional Resources

- **Main Scanner**: `final.py`
- **Web Dashboard**: `dashboard_server.py`
- **CLI Dashboard**: `cli_dashboard.py`
- **Reports Directory**: `./supabase_security_reports/`
- **API Documentation**: http://localhost:6666/api/reports

---

## 🆘 Support

For issues or questions:
1. Check logs: `tail -f dashboard.log`
2. Verify dependencies: `pip list`
3. Test nmap: `nmap --version`
4. Review reports: `ls -lah supabase_security_reports/`

---

**Version**: 3.5.1 Enterprise Edition  
**Last Updated**: October 2025


