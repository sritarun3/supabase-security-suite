#!/usr/bin/env python3
"""
Supabase Security Dashboard - Enterprise Production Ready
Web-based GUI for viewing security scan results with real-time updates
"""

from flask import Flask, render_template, jsonify, request, send_from_directory, Response, make_response
from flask_cors import CORS
import json
import os
from pathlib import Path
from datetime import datetime
from collections import Counter
import threading
import time
import csv
import io
import requests
import base64

# Import few-shot prompting for AI validation
try:
    from supabase_security_suite.integrations.ai_examples import build_few_shot_prompt
except ImportError:
    # Fallback if module not available
    build_few_shot_prompt = None


def create_app(reports_dir=None):
    """Create and configure the Flask application."""
    
    # Get the directory where this file is located
    dashboard_dir = Path(__file__).parent
    template_folder = dashboard_dir / 'templates'
    static_folder = dashboard_dir / 'static'
    
    app = Flask(__name__,
                template_folder=str(template_folder),
                static_folder=str(static_folder))
    CORS(app)
    
    # Configuration
    if reports_dir is None:
        reports_dir = Path.cwd() / "supabase_security_reports"
    else:
        reports_dir = Path(reports_dir)
    
    REPORTS_DIR = reports_dir
    SCAN_STATUS = {"running": False, "progress": 0, "message": ""}
    AI_VALIDATION_STATUS = {
        "running": False, 
        "progress": 0, 
        "current": 0, 
        "total": 0, 
        "message": ""
    }
    JIRA_CONFIG = {
        "enabled": False,
        "url": "",
        "username": "",
        "api_token": "",
        "project_key": ""
    }
    
    AI_CONFIG = {
        "provider": "none",  # "openai", "openrouter", "none"
        "openai_api_key": "",
        "openrouter_api_key": "",
        "openrouter_model": "anthropic/claude-3-haiku",
        "enabled": False
    }
    
    # Global variables
    reports = []
    current_scan_process = None
    
    @app.route('/')
    def index():
        response = make_response(render_template('dashboard.html'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    @app.route('/api/reports')
    def get_reports():
        """Get list of all available reports"""
        reports = []
        if REPORTS_DIR.exists():
            for json_file in REPORTS_DIR.glob("report*.json"):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                        reports.append({
                            "filename": json_file.name,
                            "timestamp": json_file.stat().st_mtime,
                            "score": data.get("score", 0),
                            "findings_count": len(data.get("findings", []))
                        })
                except Exception as e:
                    print(f"Error reading {json_file}: {e}")
        
        return jsonify(sorted(reports, key=lambda x: x['timestamp'], reverse=True))
    
    @app.route('/api/report/<filename>')
    def get_report(filename):
        """Get specific report details"""
        try:
            report_path = REPORTS_DIR / filename
            if not report_path.exists():
                return jsonify({"error": "Report not found"}), 404
            
            with open(report_path) as f:
                data = json.load(f)
            
            # Calculate statistics
            findings = data.get("findings", [])
            severities = Counter(f['severity'] for f in findings)
            sources = Counter(f['source'] for f in findings)
            compliance_issues = {}
            
            for finding in findings:
                for standard, controls in finding.get('compliance', {}).items():
                    if standard not in compliance_issues:
                        compliance_issues[standard] = set()
                    compliance_issues[standard].update(controls)
            
            # Convert sets to lists for JSON serialization
            compliance_issues = {k: list(v) for k, v in compliance_issues.items()}
            
            return jsonify({
                "score": data.get("score", 0),
                "metadata": data.get("metadata", {}),
                "findings": findings,
                "statistics": {
                    "total": len(findings),
                    "by_severity": dict(severities),
                    "by_source": dict(sources),
                    "compliance_issues": compliance_issues
                }
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/findings/critical')
    def get_critical_findings():
        """Get only critical/high severity findings"""
        try:
            latest_report = max(REPORTS_DIR.glob("report*.json"), key=lambda x: x.stat().st_mtime)
            with open(latest_report) as f:
                data = json.load(f)
            
            critical = [f for f in data.get("findings", []) 
                       if f['severity'] in ['CRITICAL', 'HIGH']]
            
            return jsonify({
                "count": len(critical),
                "findings": critical
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/scan/status')
    def scan_status():
        """Get current scan status"""
        return jsonify(SCAN_STATUS)
    
    @app.route('/api/scan/start', methods=['POST'])
    def start_scan():
        """Trigger a new security scan"""
        nonlocal SCAN_STATUS
        
        if SCAN_STATUS['running']:
            return jsonify({"error": "Scan already running"}), 400
        
        params = request.json or {}
        
        def run_scan():
            nonlocal SCAN_STATUS
            SCAN_STATUS = {"running": True, "progress": 0, "message": "Initializing..."}
            
            try:
                import subprocess
                
                cmd = [
                    "python3", "final.py",
                    "--path", params.get("path", "/path/to/supabase/project"),
                    "--out", str(REPORTS_DIR),
                    "--fancy"
                ]
                
                if params.get("supabase_url"):
                    cmd.extend(["--supabase-url", params["supabase_url"]])
                if params.get("db_url"):
                    cmd.extend(["--db-url", params["db_url"]])
                if params.get("allow_external"):
                    cmd.append("--allow-external")
                if params.get("openai_api_key"):
                    cmd.extend(["--openai-api-key", params["openai_api_key"]])
                if params.get("volume_scan"):
                    cmd.append("--volume-scan")
                if params.get("dashboard_auth"):
                    cmd.append("--dashboard-auth")
                
                SCAN_STATUS['message'] = "Running scan..."
                SCAN_STATUS['progress'] = 30
                
                # Simulate progress updates
                for i in range(30, 90, 10):
                    SCAN_STATUS['progress'] = i
                    SCAN_STATUS['message'] = f"Scanning... {i}% complete"
                    time.sleep(1)
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    SCAN_STATUS['progress'] = 100
                    SCAN_STATUS['message'] = "Scan completed successfully"
                else:
                    SCAN_STATUS['message'] = f"Scan failed: {result.stderr}"
                
                time.sleep(2)
                
            except Exception as e:
                SCAN_STATUS['message'] = f"Error: {str(e)}"
            finally:
                SCAN_STATUS['running'] = False
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
        return jsonify({"status": "Scan started"})
    
    @app.route('/api/scan/progress')
    def scan_progress():
        """Get detailed scan progress with WebSocket-like updates"""
        return jsonify(SCAN_STATUS)
    
    @app.route('/api/export/<format>/<filename>')
    def export_report(format, filename):
        """Export report in different formats"""
        try:
            report_path = REPORTS_DIR / filename
            if not report_path.exists():
                return jsonify({"error": "Report not found"}), 404
            
            with open(report_path) as f:
                data = json.load(f)
            
            if format == 'json':
                return send_from_directory(REPORTS_DIR, filename, as_attachment=True, download_name=filename)
            
            elif format == 'csv':
                findings = data.get("findings", [])
                output = io.StringIO()
                writer = csv.writer(output)
                
                # CSV headers - Added AI validation columns
                writer.writerow([
                    'ID', 'Title', 'Severity', 'Source', 'File', 'Line', 
                    'Description', 'Impact', 'Recommendation', 'Compliance',
                    'AI Verdict', 'AI Confidence', 'AI Reason', 'AI Validated At'
                ])
                
                # CSV data
                for finding in findings:
                    compliance_str = ', '.join([
                        f"{std}: {', '.join(controls)}" 
                        for std, controls in finding.get('compliance', {}).items()
                    ])
                    
                    # Extract AI validation data if present
                    ai_validation = finding.get('ai_validation', {})
                    ai_verdict = ai_validation.get('verdict', '')
                    ai_confidence = ai_validation.get('confidence', '')
                    ai_reason = ai_validation.get('reason', '')
                    ai_validated_at = ai_validation.get('validated_at', '')
                    
                    writer.writerow([
                        finding.get('id', ''),
                        finding.get('title', ''),
                        finding.get('severity', ''),
                        finding.get('source', ''),
                        finding.get('file', ''),
                        finding.get('line', ''),
                        finding.get('description', ''),
                        finding.get('impact', ''),
                        finding.get('recommendation', ''),
                        compliance_str,
                        ai_verdict,
                        ai_confidence,
                        ai_reason,
                        ai_validated_at
                    ])
                
                output.seek(0)
                csv_filename = filename.replace('.json', '.csv')
                
                return Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={csv_filename}'}
                )
            
            elif format == 'pdf':
                # Generate PDF report (simplified version)
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib import colors
                from reportlab.lib.units import inch
                
                buffer = io.BytesIO()
                doc = SimpleDocTemplate(buffer, pagesize=letter)
                styles = getSampleStyleSheet()
                story = []
                
                # Title
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=18,
                    spaceAfter=30,
                    alignment=1  # Center alignment
                )
                story.append(Paragraph("Supabase Security Report", title_style))
                story.append(Spacer(1, 12))
                
                # Summary
                score = data.get("score", 0)
                findings_count = len(data.get("findings", []))
                story.append(Paragraph(f"<b>Security Score:</b> {score}/100", styles['Normal']))
                story.append(Paragraph(f"<b>Total Findings:</b> {findings_count}", styles['Normal']))
                
                # AI Validation Summary (if available)
                validation_summary = data.get("validation_summary", {})
                if validation_summary:
                    story.append(Spacer(1, 12))
                    story.append(Paragraph("<b>AI Validation Summary:</b>", styles['Normal']))
                    story.append(Paragraph(f"  • Total Validated: {validation_summary.get('total_validated', 0)}", styles['Normal']))
                    story.append(Paragraph(f"  • True Positives: {validation_summary.get('true_positives', 0)} (confirmed issues)", styles['Normal']))
                    story.append(Paragraph(f"  • False Positives: {validation_summary.get('false_positives', 0)} (can be ignored)", styles['Normal']))
                    story.append(Paragraph(f"  • Needs Review: {validation_summary.get('needs_review', 0)} (manual check)", styles['Normal']))
                    val_date = validation_summary.get('validation_date', '')
                    if val_date:
                        story.append(Paragraph(f"  • Validation Date: {val_date[:10]}", styles['Normal']))
                
                story.append(Spacer(1, 20))
                
                # Findings table
                findings = data.get("findings", [])
                if findings:
                    story.append(Paragraph("Security Findings", styles['Heading2']))
                    story.append(Spacer(1, 12))
                    
                    # Table data with AI validation
                    table_data = [['Severity', 'Title', 'Source', 'AI Verdict', 'File']]
                    for finding in findings[:50]:  # Limit to first 50 findings
                        ai_validation = finding.get('ai_validation', {})
                        ai_verdict = ai_validation.get('verdict', 'N/A')
                        # Shorten verdict names for table
                        verdict_short = {
                            'TRUE_POSITIVE': '🚨 True',
                            'FALSE_POSITIVE': '✓ False',
                            'NEEDS_REVIEW': '⚠ Review',
                            'N/A': '-'
                        }.get(ai_verdict, ai_verdict)
                        
                        table_data.append([
                            finding.get('severity', ''),
                            finding.get('title', '')[:40] + '...' if len(finding.get('title', '')) > 40 else finding.get('title', ''),
                            finding.get('source', ''),
                            verdict_short,
                            finding.get('file', '')[:25] + '...' if len(finding.get('file', '')) > 25 else finding.get('file', '')
                        ])
                    
                    table = Table(table_data)
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    story.append(table)
                
                doc.build(story)
                buffer.seek(0)
                pdf_filename = filename.replace('.json', '.pdf')
                
                return Response(
                    buffer.getvalue(),
                    mimetype='application/pdf',
                    headers={'Content-Disposition': f'attachment; filename={pdf_filename}'}
                )
            
            elif format == 'markdown':
                md_file = filename.replace('.json', '.md')
                return send_from_directory(REPORTS_DIR, md_file)
            
            else:
                return jsonify({"error": "Invalid format"}), 400
                
        except Exception as e:
            return jsonify({"error": f"Export failed: {str(e)}"}), 500
    
    @app.route('/api/jira/config', methods=['GET', 'POST'])
    def jira_config():
        """Get or update Jira configuration"""
        nonlocal JIRA_CONFIG
        
        if request.method == 'POST':
            config = request.json
            JIRA_CONFIG.update({
                "enabled": config.get("enabled", False),
                "url": config.get("url", ""),
                "username": config.get("username", ""),
                "api_token": config.get("api_token", ""),
                "project_key": config.get("project_key", "")
            })
            return jsonify({"status": "Configuration updated"})
        
        return jsonify(JIRA_CONFIG)
    
    @app.route('/api/jira/test', methods=['POST'])
    def test_jira_connection():
        """Test Jira connection"""
        config = request.json or JIRA_CONFIG
        
        if not all([config.get("url"), config.get("username"), config.get("api_token")]):
            return jsonify({"error": "Missing Jira configuration"}), 400
        
        try:
            auth_string = f"{config['username']}:{config['api_token']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/json'
            }
            
            # Test connection by getting user info
            response = requests.get(
                f"{config['url']}/rest/api/3/myself",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                user_data = response.json()
                return jsonify({
                    "status": "success",
                    "message": f"Connected as {user_data.get('displayName', 'Unknown')}",
                    "user": user_data
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": f"Connection failed: {response.status_code}"
                }), 400
                
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Connection error: {str(e)}"
            }), 500
    
    @app.route('/api/jira/create-tickets', methods=['POST'])
    def create_jira_tickets():
        """Create Jira tickets for security findings"""
        nonlocal JIRA_CONFIG
        
        if not JIRA_CONFIG.get("enabled"):
            return jsonify({"error": "Jira integration not configured"}), 400
        
        data = request.json
        findings = data.get("findings", [])
        project_key = data.get("project_key", JIRA_CONFIG.get("project_key"))
        
        if not project_key:
            return jsonify({"error": "Project key required"}), 400
        
        created_tickets = []
        failed_tickets = []
        
        try:
            auth_string = f"{JIRA_CONFIG['username']}:{JIRA_CONFIG['api_token']}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/json'
            }
            
            for finding in findings:
                try:
                    # Create ticket payload
                    ticket_data = {
                        "fields": {
                            "project": {"key": project_key},
                            "summary": f"Security Issue: {finding.get('title', 'Unknown')}",
                            "description": {
                                "type": "doc",
                                "version": 1,
                                "content": [
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": f"**Severity:** {finding.get('severity', 'Unknown')}\n\n"
                                            },
                                            {
                                                "type": "text",
                                                "text": f"**Description:** {finding.get('description', 'No description')}\n\n"
                                            },
                                            {
                                                "type": "text",
                                                "text": f"**Impact:** {finding.get('impact', 'No impact details')}\n\n"
                                            },
                                            {
                                                "type": "text",
                                                "text": f"**Recommendation:** {finding.get('recommendation', 'No recommendation')}\n\n"
                                            },
                                            {
                                                "type": "text",
                                                "text": f"**File:** {finding.get('file', 'N/A')}\n\n"
                                            },
                                            {
                                                "type": "text",
                                                "text": f"**Line:** {finding.get('line', 'N/A')}"
                                            }
                                        ]
                                    }
                                ]
                            },
                            "issuetype": {"name": "Bug"},
                            "priority": {
                                "name": "High" if finding.get('severity') in ['CRITICAL', 'HIGH'] else "Medium"
                            },
                            "labels": [
                                "security",
                                "supabase",
                                finding.get('severity', '').lower(),
                                finding.get('source', '').lower()
                            ]
                        }
                    }
                    
                    response = requests.post(
                        f"{JIRA_CONFIG['url']}/rest/api/3/issue",
                        headers=headers,
                        json=ticket_data,
                        timeout=10
                    )
                    
                    if response.status_code == 201:
                        ticket = response.json()
                        created_tickets.append({
                            "finding_id": finding.get('id'),
                            "ticket_key": ticket['key'],
                            "ticket_url": f"{JIRA_CONFIG['url']}/browse/{ticket['key']}"
                        })
                    else:
                        failed_tickets.append({
                            "finding_id": finding.get('id'),
                            "error": response.text
                        })
                        
                except Exception as e:
                    failed_tickets.append({
                        "finding_id": finding.get('id'),
                        "error": str(e)
                    })
            
            return jsonify({
                "created": len(created_tickets),
                "failed": len(failed_tickets),
                "tickets": created_tickets,
                "failures": failed_tickets
            })
            
        except Exception as e:
            return jsonify({"error": f"Jira integration failed: {str(e)}"}), 500
    
    @app.route('/api/ai/config', methods=['GET', 'POST'])
    def ai_config():
        """Get or update AI configuration"""
        nonlocal AI_CONFIG
        
        if request.method == 'POST':
            config = request.json
            AI_CONFIG.update({
                "provider": config.get("provider", "none"),
                "openai_api_key": config.get("openai_api_key", ""),
                "openrouter_api_key": config.get("openrouter_api_key", ""),
                "openrouter_model": config.get("openrouter_model", "anthropic/claude-3-haiku"),
                "enabled": config.get("enabled", False)
            })
            return jsonify({"status": "AI configuration updated"})
        
        return jsonify(AI_CONFIG)
    
    @app.route('/api/ai/test', methods=['POST'])
    def test_ai_connection():
        """Test AI provider connection"""
        nonlocal AI_CONFIG
        
        config = request.json or AI_CONFIG
        provider = config.get("provider", "none")
        
        if provider == "none":
            return jsonify({"error": "No AI provider selected"}), 400
        
        try:
            if provider == "openai":
                api_key = config.get("openai_api_key")
                if not api_key:
                    return jsonify({"error": "OpenAI API key required"}), 400
                
                try:
                    from openai import OpenAI
                    client = OpenAI(api_key=api_key)
                    response = client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": "Test connection"}],
                        max_tokens=10
                    )
                    return jsonify({
                        "status": "success",
                        "message": "OpenAI connection successful",
                        "provider": "openai"
                    })
                except Exception as e:
                    return jsonify({
                        "status": "error",
                        "message": f"OpenAI connection failed: {str(e)}"
                    }), 400
            
            elif provider == "openrouter":
                api_key = config.get("openrouter_api_key")
                if not api_key:
                    return jsonify({"error": "OpenRouter API key required"}), 400
                
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
                
                # Test with a simple request
                test_data = {
                    "model": config.get("openrouter_model", "anthropic/claude-3-haiku"),
                    "messages": [{"role": "user", "content": "Test connection"}],
                    "max_tokens": 10
                }
                
                response = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=test_data,
                    timeout=10
                )
                
                if response.status_code == 200:
                    return jsonify({
                        "status": "success",
                        "message": "OpenRouter connection successful",
                        "provider": "openrouter"
                    })
                else:
                    return jsonify({
                        "status": "error",
                        "message": f"OpenRouter connection failed: {response.status_code} - {response.text}"
                    }), 400
            
            elif provider == "anthropic":
                api_key = config.get("anthropic_api_key")
                if not api_key:
                    return jsonify({"error": "Anthropic API key required"}), 400
                
                try:
                    # Test Anthropic API connection
                    headers = {
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    }
                    
                    test_data = {
                        "model": config.get("anthropic_model", "claude-sonnet-4-20250514"),
                        "messages": [{"role": "user", "content": "Test connection"}],
                        "max_tokens": 10
                    }
                    
                    response = requests.post(
                        "https://api.anthropic.com/v1/messages",
                        headers=headers,
                        json=test_data,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        return jsonify({
                            "status": "success",
                            "message": "Anthropic (Claude) connection successful",
                            "provider": "anthropic"
                        })
                    else:
                        return jsonify({
                            "status": "error",
                            "message": f"Anthropic connection failed: {response.status_code} - {response.text}"
                        }), 400
                except Exception as e:
                    return jsonify({
                        "status": "error",
                        "message": f"Anthropic connection failed: {str(e)}"
                    }), 400
            
            else:
                return jsonify({"error": "Invalid AI provider"}), 400
                
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Connection test failed: {str(e)}"
            }), 500
    
    @app.route('/api/ai/validation-progress')
    def get_validation_progress():
        """Get current AI validation progress"""
        nonlocal AI_VALIDATION_STATUS
        return jsonify(AI_VALIDATION_STATUS)
    
    @app.route('/api/ai/validate-findings', methods=['POST'])
    def validate_findings_with_ai():
        """Validate findings and identify false positives using AI"""
        nonlocal AI_CONFIG, AI_VALIDATION_STATUS
        
        if not AI_CONFIG.get("enabled") or AI_CONFIG.get("provider") == "none":
            return jsonify({"error": "AI validation not enabled"}), 400
        
        data = request.json
        findings = data.get("findings", [])
        
        if not findings:
            return jsonify({"error": "Findings data required"}), 400
        
        def get_file_snippet(file_path: str, line: int, context_lines: int = 5) -> str:
            """Read file content around the specified line"""
            try:
                from pathlib import Path
                file = Path(file_path)
                if not file.exists():
                    return "[File not accessible]"
                
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                start = max(0, line - context_lines - 1)
                end = min(len(lines), line + context_lines)
                
                snippet_lines = []
                for i in range(start, end):
                    marker = ">>>" if i == line - 1 else "   "
                    snippet_lines.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")
                
                return "\n".join(snippet_lines)
            except Exception as e:
                return f"[Error reading file: {str(e)}]"
        
        def get_db_context(finding: dict) -> str:
            """Get database context for DB-related findings"""
            try:
                import re
                import psycopg
                from pathlib import Path
                
                # Check if it's a DB-related finding
                title = finding.get('title', '').lower()
                description = finding.get('description', '').lower()
                
                if not any(keyword in title or keyword in description 
                          for keyword in ['rls', 'table', 'sql', 'injection', 'policy', 'schema']):
                    return None
                
                # Try to extract table name from finding
                table_match = re.search(r'table[:\s]+[\'"`]?([a-zA-Z0-9_\.]+)', description)
                if not table_match:
                    # Try alternate patterns
                    table_match = re.search(r'`([a-zA-Z0-9_\.]+)`', description)
                
                if not table_match:
                    return None
                
                table_name = table_match.group(1)
                schema_name = 'public'
                
                if '.' in table_name:
                    schema_name, table_name = table_name.split('.', 1)
                
                # Look for Supabase connection in environment or config
                db_url = None
                
                # Check multiple potential .env file locations
                env_locations = [
                    Path.home() / 'supabase' / '.env',
                    Path.home() / 'supabase' / 'supabase-external.env',
                    Path.home() / 'supabase' / 'supabase-security-demo.env',
                    Path('/home/debian/supabase/.env'),
                    Path('/home/debian/supabase/supabase-external.env'),
                ]
                
                for env_path in env_locations:
                    if env_path.exists():
                        try:
                            with open(env_path, 'r') as f:
                                for line in f:
                                    if 'DATABASE_URL' in line and not line.strip().startswith('#'):
                                        parts = line.split('=', 1)
                                        if len(parts) == 2:
                                            db_url = parts[1].strip().strip('"\'')
                                            break
                            if db_url:
                                break
                        except Exception:
                            continue
                
                if not db_url:
                    return None  # Silently skip if no DB access
                
                # Connect to database
                with psycopg.connect(db_url, connect_timeout=5) as conn:
                    with conn.cursor() as cur:
                        db_info = []
                        
                        # Get table info
                        cur.execute("""
                            SELECT 
                                c.relname AS table_name,
                                c.relrowsecurity AS rls_enabled,
                                c.relforcerowsecurity AS rls_forced
                            FROM pg_class c
                            JOIN pg_namespace n ON n.oid = c.relnamespace
                            WHERE n.nspname = %s AND c.relname = %s AND c.relkind = 'r'
                        """, (schema_name, table_name))
                        
                        table_info = cur.fetchone()
                        if table_info:
                            db_info.append(f"Table: {schema_name}.{table_name}")
                            db_info.append(f"RLS Enabled: {table_info[1]}")
                            db_info.append(f"RLS Forced: {table_info[2]}")
                        else:
                            return f"[Table {schema_name}.{table_name} not found]"
                        
                        # Get RLS policies
                        cur.execute("""
                            SELECT 
                                polname,
                                polcmd,
                                polroles::regrole[],
                                polqual,
                                polwithcheck
                            FROM pg_policy
                            WHERE polrelid = %s::regclass
                        """, (f"{schema_name}.{table_name}",))
                        
                        policies = cur.fetchall()
                        if policies:
                            db_info.append(f"\nRLS Policies ({len(policies)}):")
                            for policy in policies[:3]:  # Limit to 3 policies
                                db_info.append(f"  - {policy[0]} ({policy[1]})")
                        else:
                            db_info.append("\nRLS Policies: None")
                        
                        # Get columns
                        cur.execute("""
                            SELECT column_name, data_type, is_nullable
                            FROM information_schema.columns
                            WHERE table_schema = %s AND table_name = %s
                            ORDER BY ordinal_position
                            LIMIT 10
                        """, (schema_name, table_name))
                        
                        columns = cur.fetchall()
                        if columns:
                            db_info.append(f"\nColumns ({len(columns)}):")
                            for col in columns[:5]:  # Limit to 5 columns
                                db_info.append(f"  - {col[0]} ({col[1]})")
                        
                        return "\n".join(db_info)
                
            except Exception as e:
                return f"[DB query error: {str(e)}]"
        
        try:
            validated_findings = []
            errors = []
            total_findings = len(findings)
            
            # Initialize progress tracking
            AI_VALIDATION_STATUS['running'] = True
            AI_VALIDATION_STATUS['total'] = total_findings
            AI_VALIDATION_STATUS['current'] = 0
            AI_VALIDATION_STATUS['progress'] = 0
            AI_VALIDATION_STATUS['message'] = 'Starting validation...'
            
            # Process all findings (not just 20)
            for idx, finding in enumerate(findings, 1):
                # Update progress
                AI_VALIDATION_STATUS['current'] = idx
                AI_VALIDATION_STATUS['progress'] = int((idx / total_findings) * 100)
                AI_VALIDATION_STATUS['message'] = f'Processing finding {idx}/{total_findings}...'
                
                try:
                    # Extract metadata
                    file_path = finding.get('file', 'N/A')
                    line_num = finding.get('line') or 0  # Handle None
                    source_type = finding.get('source', 'unknown')
                    severity = finding.get('severity', 'UNKNOWN')
                    
                    # Get code snippet if file and line are available
                    code_snippet = ""
                    if file_path != 'N/A' and line_num and line_num > 0:
                        code_snippet = get_file_snippet(file_path, line_num)
                    
                    # Get database context for DB-related findings
                    db_context = get_db_context(finding)
                except Exception as e:
                    errors.append(f"Error processing finding {finding.get('id', 'unknown')}: {str(e)}")
                    continue
                
                try:
                    # Build enhanced prompt
                    context_sections = []
                    
                    if code_snippet:
                        context_sections.append(f"Code Context:\n```\n{code_snippet}\n```")
                    
                    if db_context:
                        context_sections.append(f"Database Context:\n{db_context}")
                    
                    additional_context = "\n\n".join(context_sections) if context_sections else "[No additional context available]"
                except Exception as e:
                    errors.append(f"Error building context for {finding.get('id', 'unknown')}: {str(e)}")
                    continue
                
                try:
                    if AI_CONFIG["provider"] == "openai":
                        api_key = AI_CONFIG.get("openai_api_key")
                        if not api_key:
                            return jsonify({"error": "OpenAI API key not configured"}), 400
                        
                        from openai import OpenAI
                        client = OpenAI(api_key=api_key)
                        
                        # Use few-shot prompting if available, otherwise fall back to original
                        if build_few_shot_prompt:
                            finding_dict = {
                                'title': finding.get('title', 'N/A'),
                                'file': file_path,
                                'line': line_num,
                                'severity': severity,
                                'description': finding.get('description', 'N/A'),
                                'impact': finding.get('impact', 'N/A'),
                            }
                            prompt = build_few_shot_prompt(finding_dict)
                            # Add additional context to prompt
                            if additional_context and additional_context != "[No additional context available]":
                                prompt += f"\n\nADDITIONAL CONTEXT:\n{additional_context}"
                        else:
                            # Fallback to original prompt
                            prompt = f"""Analyze if this security finding is a FALSE POSITIVE or TRUE POSITIVE.

FINDING DETAILS:
Title: {finding.get('title', 'N/A')}
Severity: {severity}
File: {file_path} (line {line_num})
Source: {source_type}
Description: {finding.get('description', 'N/A')}
Impact: {finding.get('impact', 'N/A')}

{additional_context}

ANALYSIS CRITERIA:
✅ FALSE POSITIVE if:
- In documentation/README/example/test files
- Mock/example credentials (e.g., "your-api-key", "example.com")
- System/internal tables (_realtime, vault, net, supabase_functions, pg_*, information_schema)
- HTTP URLs in docs (not actual API endpoints)
- Comments or example code blocks

🚨 TRUE POSITIVE if:
- Real credentials in production code
- Missing RLS on user data tables (users, profiles, posts, etc.)
- Actual SQL injection vulnerabilities
- Real security misconfigurations

⚠️ NEEDS REVIEW if:
- Context-dependent (could be acceptable in some cases)
- Insufficient information to determine
- Requires domain knowledge

Respond with ONLY:
VERDICT: [FALSE_POSITIVE|TRUE_POSITIVE|NEEDS_REVIEW]
REASON: [One sentence explanation]
CONFIDENCE: [HIGH|MEDIUM|LOW]"""
                        
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": prompt}],
                            temperature=0.3,
                            max_tokens=200
                        )
                        
                        ai_response = response.choices[0].message.content.strip()
                        
                        # Parse AI response
                        verdict = "NEEDS_REVIEW"
                        reason = "Unable to determine"
                        confidence = "LOW"
                        
                        for line in ai_response.split('\n'):
                            if line.startswith('VERDICT:'):
                                verdict = line.split(':', 1)[1].strip()
                            elif line.startswith('REASON:'):
                                reason = line.split(':', 1)[1].strip()
                            elif line.startswith('CONFIDENCE:'):
                                confidence = line.split(':', 1)[1].strip()
                        
                        validated_findings.append({
                            "finding": finding,
                            "verdict": verdict,
                            "reason": reason,
                            "confidence": confidence
                        })
                        
                    elif AI_CONFIG["provider"] == "openrouter":
                        api_key = AI_CONFIG.get("openrouter_api_key")
                        model = AI_CONFIG.get("openrouter_model", "anthropic/claude-3-haiku")
                        
                        if not api_key:
                            return jsonify({"error": "OpenRouter API key not configured"}), 400
                        
                        # Use few-shot prompting if available, otherwise fall back to original
                        if build_few_shot_prompt:
                            finding_dict = {
                                'title': finding.get('title', 'N/A'),
                                'file': file_path,
                                'line': line_num,
                                'severity': severity,
                                'description': finding.get('description', 'N/A'),
                                'impact': finding.get('impact', 'N/A'),
                            }
                            prompt = build_few_shot_prompt(finding_dict)
                            # Add additional context to prompt
                            if additional_context and additional_context != "[No additional context available]":
                                prompt += f"\n\nADDITIONAL CONTEXT:\n{additional_context}"
                        else:
                            # Fallback to original prompt
                            prompt = f"""Analyze if this security finding is a FALSE POSITIVE or TRUE POSITIVE.

FINDING DETAILS:
Title: {finding.get('title', 'N/A')}
Severity: {severity}
File: {file_path} (line {line_num})
Source: {source_type}
Description: {finding.get('description', 'N/A')}
Impact: {finding.get('impact', 'N/A')}

{additional_context}

ANALYSIS CRITERIA:
✅ FALSE POSITIVE if:
- In documentation/README/example/test files
- Mock/example credentials (e.g., "your-api-key", "example.com")
- System/internal tables (_realtime, vault, net, supabase_functions, pg_*, information_schema)
- HTTP URLs in docs (not actual API endpoints)
- Comments or example code blocks

🚨 TRUE POSITIVE if:
- Real credentials in production code
- Missing RLS on user data tables (users, profiles, posts, etc.)
- Actual SQL injection vulnerabilities
- Real security misconfigurations

⚠️ NEEDS REVIEW if:
- Context-dependent (could be acceptable in some cases)
- Insufficient information to determine
- Requires domain knowledge

Respond with ONLY:
VERDICT: [FALSE_POSITIVE|TRUE_POSITIVE|NEEDS_REVIEW]
REASON: [One sentence explanation]
CONFIDENCE: [HIGH|MEDIUM|LOW]"""
                        
                        response = requests.post(
                            "https://openrouter.ai/api/v1/chat/completions",
                            headers={
                                "Authorization": f"Bearer {api_key}",
                                "Content-Type": "application/json",
                                "HTTP-Referer": request.host_url,
                            },
                            json={
                                "model": model,
                                "messages": [{"role": "user", "content": prompt}],
                                "temperature": 0.3,
                                "max_tokens": 200
                            }
                        )
                        
                        if response.status_code == 200:
                            ai_response = response.json()['choices'][0]['message']['content'].strip()
                            
                            # Parse AI response
                            verdict = "NEEDS_REVIEW"
                            reason = "Unable to determine"
                            confidence = "LOW"
                            
                            for line in ai_response.split('\n'):
                                if line.startswith('VERDICT:'):
                                    verdict = line.split(':', 1)[1].strip()
                                elif line.startswith('REASON:'):
                                    reason = line.split(':', 1)[1].strip()
                                elif line.startswith('CONFIDENCE:'):
                                    confidence = line.split(':', 1)[1].strip()
                            
                            validated_findings.append({
                                "finding": finding,
                                "verdict": verdict,
                                "reason": reason,
                                "confidence": confidence
                            })
                        else:
                            # Skip this finding on API error
                            errors.append(f"OpenRouter API error for {finding.get('id', 'unknown')}: {response.status_code}")
                            continue
                    
                    elif AI_CONFIG["provider"] == "anthropic":
                        api_key = AI_CONFIG.get("anthropic_api_key")
                        model = AI_CONFIG.get("anthropic_model", "claude-sonnet-4-20250514")
                        
                        if not api_key:
                            return jsonify({"error": "Anthropic API key not configured"}), 400
                        
                        # Use few-shot prompting if available, otherwise fall back to original
                        if build_few_shot_prompt:
                            finding_dict = {
                                'title': finding.get('title', 'N/A'),
                                'file': file_path,
                                'line': line_num,
                                'severity': severity,
                                'description': finding.get('description', 'N/A'),
                                'impact': finding.get('impact', 'N/A'),
                            }
                            prompt = build_few_shot_prompt(finding_dict)
                            # Add additional context to prompt
                            if additional_context and additional_context != "[No additional context available]":
                                prompt += f"\n\nADDITIONAL CONTEXT:\n{additional_context}"
                        else:
                            # Fallback to original prompt
                            prompt = f"""Analyze if this security finding is a FALSE POSITIVE or TRUE POSITIVE.

FINDING DETAILS:
Title: {finding.get('title', 'N/A')}
Severity: {severity}
File: {file_path} (line {line_num})
Source: {source_type}
Description: {finding.get('description', 'N/A')}
Impact: {finding.get('impact', 'N/A')}

{additional_context}

ANALYSIS CRITERIA:
✅ FALSE POSITIVE if:
- In documentation/README/example/test files
- Mock/example credentials (e.g., "your-api-key", "example.com")
- System/internal tables (_realtime, vault, net, supabase_functions, pg_*, information_schema)
- HTTP URLs in docs (not actual API endpoints)
- Comments or example code blocks

🚨 TRUE POSITIVE if:
- Real credentials in production code
- Missing RLS on user data tables (users, profiles, posts, etc.)
- Actual SQL injection vulnerabilities
- Real security misconfigurations

⚠️ NEEDS REVIEW if:
- Context-dependent (could be acceptable in some cases)
- Insufficient information to determine
- Requires domain knowledge

Respond with ONLY:
VERDICT: [FALSE_POSITIVE|TRUE_POSITIVE|NEEDS_REVIEW]
REASON: [One sentence explanation]
CONFIDENCE: [HIGH|MEDIUM|LOW]"""
                        
                        response = requests.post(
                            "https://api.anthropic.com/v1/messages",
                            headers={
                                "x-api-key": api_key,
                                "anthropic-version": "2023-06-01",
                                "content-type": "application/json"
                            },
                            json={
                                "model": model,
                                "messages": [{"role": "user", "content": prompt}],
                                "temperature": 0.3,
                                "max_tokens": 200
                            }
                        )
                        
                        if response.status_code == 200:
                            ai_response = response.json()['content'][0]['text'].strip()
                            
                            # Parse AI response
                            verdict = "NEEDS_REVIEW"
                            reason = "Unable to determine"
                            confidence = "LOW"
                            
                            for line in ai_response.split('\n'):
                                if line.startswith('VERDICT:'):
                                    verdict = line.split(':', 1)[1].strip()
                                elif line.startswith('REASON:'):
                                    reason = line.split(':', 1)[1].strip()
                                elif line.startswith('CONFIDENCE:'):
                                    confidence = line.split(':', 1)[1].strip()
                            
                            validated_findings.append({
                                "finding": finding,
                                "verdict": verdict,
                                "reason": reason,
                                "confidence": confidence
                            })
                        else:
                            # Skip this finding on API error
                            errors.append(f"Anthropic API error for {finding.get('id', 'unknown')}: {response.status_code}")
                            continue
                            
                except Exception as e:
                    errors.append(f"AI API error for {finding.get('id', 'unknown')}: {str(e)}")
                    continue
            
            # Calculate statistics
            true_positives = sum(1 for r in validated_findings if r['verdict'] == 'TRUE_POSITIVE')
            false_positives = sum(1 for r in validated_findings if r['verdict'] == 'FALSE_POSITIVE')
            needs_review = sum(1 for r in validated_findings if r['verdict'] == 'NEEDS_REVIEW')
            
            # Mark validation as complete
            AI_VALIDATION_STATUS['running'] = False
            AI_VALIDATION_STATUS['progress'] = 100
            AI_VALIDATION_STATUS['message'] = 'Validation complete'
            
            return jsonify({
                "status": "success",
                "total_findings": total_findings,
                "validated_count": len(validated_findings),
                "skipped_count": total_findings - len(validated_findings),
                "statistics": {
                    "true_positives": true_positives,
                    "false_positives": false_positives,
                    "needs_review": needs_review
                },
                "errors": errors if errors else None,
                "results": validated_findings
            })
            
        except Exception as e:
            # Reset status on error
            AI_VALIDATION_STATUS['running'] = False
            AI_VALIDATION_STATUS['message'] = f'Validation failed: {str(e)}'
            
            return jsonify({
                "status": "error",
                "message": f"AI validation failed: {str(e)}"
            }), 500
    
    @app.route('/api/report/save-validation', methods=['POST'])
    def save_validation_to_report():
        """Save AI validation results to the report file"""
        try:
            data = request.json
            filename = data.get('filename')
            validation_results = data.get('validation_results', [])
            
            if not filename:
                return jsonify({"error": "Filename required"}), 400
            
            report_path = REPORTS_DIR / filename
            if not report_path.exists():
                return jsonify({"error": "Report not found"}), 404
            
            # Read the current report
            with open(report_path, 'r') as f:
                report_data = json.load(f)
            
            # Create a mapping of finding ID to validation result
            validation_map = {}
            for result in validation_results:
                finding_id = result.get('finding', {}).get('id')
                if finding_id:
                    validation_map[finding_id] = {
                        'verdict': result.get('verdict'),
                        'reason': result.get('reason'),
                        'confidence': result.get('confidence'),
                        'validated_at': datetime.now().isoformat()
                    }
            
            # Update findings with validation data
            updated_count = 0
            for finding in report_data.get('findings', []):
                finding_id = finding.get('id')
                if finding_id in validation_map:
                    finding['ai_validation'] = validation_map[finding_id]
                    updated_count += 1
            
            # Add validation summary to report metadata
            if validation_results:
                true_positives = sum(1 for r in validation_results if r.get('verdict') == 'TRUE_POSITIVE')
                false_positives = sum(1 for r in validation_results if r.get('verdict') == 'FALSE_POSITIVE')
                needs_review = sum(1 for r in validation_results if r.get('verdict') == 'NEEDS_REVIEW')
                
                report_data['validation_summary'] = {
                    'total_validated': len(validation_results),
                    'true_positives': true_positives,
                    'false_positives': false_positives,
                    'needs_review': needs_review,
                    'validation_date': datetime.now().isoformat()
                }
            
            # Save the updated report
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            return jsonify({
                "status": "success",
                "updated_findings": updated_count,
                "message": f"Saved validation for {updated_count} findings"
            })
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to save validation: {str(e)}"
            }), 500
    
    @app.route('/api/ai/generate-recommendation', methods=['POST'])
    def generate_ai_recommendation():
        """Generate AI recommendation for a specific finding"""
        nonlocal AI_CONFIG
        
        if not AI_CONFIG.get("enabled") or AI_CONFIG.get("provider") == "none":
            return jsonify({"error": "AI recommendations not enabled"}), 400
        
        data = request.json
        finding = data.get("finding", {})
        
        if not finding:
            return jsonify({"error": "Finding data required"}), 400
        
        try:
            if AI_CONFIG["provider"] == "openai":
                api_key = AI_CONFIG.get("openai_api_key")
                if not api_key:
                    return jsonify({"error": "OpenAI API key not configured"}), 400
                
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
                
                prompt = f"""You are a security expert. Provide a concise, actionable recommendation (2-3 sentences max) for this security finding:

Title: {finding.get('title', 'N/A')}
Severity: {finding.get('severity', 'N/A')}
Description: {finding.get('description', 'N/A')}
Impact: {finding.get('impact', 'N/A')}
File: {finding.get('file', 'N/A')}
Line: {finding.get('line', 'N/A')}

Focus on:
1. Immediate action to fix the issue
2. Best practices specific to Supabase/PostgreSQL if relevant
3. Tools or commands that can help

Keep it concise and actionable."""

                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a security expert specializing in Supabase and PostgreSQL security."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=200,
                    temperature=0.3
                )
                
                recommendation = response.choices[0].message.content.strip()
                
            elif AI_CONFIG["provider"] == "openrouter":
                api_key = AI_CONFIG.get("openrouter_api_key")
                if not api_key:
                    return jsonify({"error": "OpenRouter API key not configured"}), 400
                
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
                
                prompt = f"""You are a security expert. Provide a concise, actionable recommendation (2-3 sentences max) for this security finding:

Title: {finding.get('title', 'N/A')}
Severity: {finding.get('severity', 'N/A')}
Description: {finding.get('description', 'N/A')}
Impact: {finding.get('impact', 'N/A')}
File: {finding.get('file', 'N/A')}
Line: {finding.get('line', 'N/A')}

Focus on:
1. Immediate action to fix the issue
2. Best practices specific to Supabase/PostgreSQL if relevant
3. Tools or commands that can help

Keep it concise and actionable."""

                request_data = {
                    "model": AI_CONFIG.get("openrouter_model", "anthropic/claude-3-haiku"),
                    "messages": [
                        {"role": "system", "content": "You are a security expert specializing in Supabase and PostgreSQL security."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 200,
                    "temperature": 0.3
                }
                
                response = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=request_data,
                    timeout=30
                )
                
                if response.status_code != 200:
                    return jsonify({
                        "error": f"OpenRouter API error: {response.status_code} - {response.text}"
                    }), 500
                
                result = response.json()
                recommendation = result["choices"][0]["message"]["content"].strip()
            
            else:
                return jsonify({"error": "Invalid AI provider"}), 400
            
            return jsonify({
                "recommendation": recommendation,
                "provider": AI_CONFIG["provider"],
                "model": AI_CONFIG.get("openrouter_model") if AI_CONFIG["provider"] == "openrouter" else "gpt-4o-mini"
            })
            
        except Exception as e:
            return jsonify({
                "error": f"AI recommendation generation failed: {str(e)}"
            }), 500
    
    @app.route('/api/auth/privilege', methods=['POST'])
    def privilege_elevation():
        """Handle dashboard-based privilege elevation requests"""
        try:
            data = request.json
            token = data.get("token", "")
            action = data.get("action", "")
            
            if not token or not action:
                return jsonify({"error": "Missing token or action"}), 400
            
            # For demo purposes, we'll approve all requests
            # In production, this should check admin permissions, rate limiting, etc.
            
            # Log the privilege request
            print(f"[PRIVILEGE] Token: {token}, Action: {action}, IP: {request.remote_addr}")
            
            # Simulate admin approval (in real implementation, this would check user permissions)
            approved = True  # This should be replaced with actual permission checking
            
            if approved:
                return jsonify({
                    "approved": True,
                    "token": token,
                    "action": action,
                    "message": "Privilege elevation approved",
                    "expires": int(time.time()) + 300  # 5 minutes
                })
            else:
                return jsonify({
                    "approved": False,
                    "message": "Privilege elevation denied"
                }), 403
                
        except Exception as e:
            return jsonify({
                "error": f"Privilege elevation failed: {str(e)}"
            }), 500
    
    @app.route('/api/reports/clear', methods=['POST'])
    def clear_reports():
        """Clear all reports and reset dashboard."""
        try:
            nonlocal reports, current_scan_process
            
            # Stop any running scan
            try:
                if current_scan_process and current_scan_process.poll() is None:
                    current_scan_process.terminate()
                    current_scan_process = None
            except:
                pass
            
            # Clear reports
            reports.clear()
            
            # Remove report files
            if os.path.exists('report.json'):
                os.remove('report.json')
            if REPORTS_DIR.exists():
                for report_file in REPORTS_DIR.glob("report*.json"):
                    try:
                        os.remove(report_file)
                    except:
                        pass
            
            return jsonify({
                'status': 'success',
                'message': 'Reports cleared successfully'
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    
    return app


def main():
    """Main entry point for the dashboard server."""
    import sys
    
    # Parse command-line arguments
    host = '0.0.0.0'
    port = 8080
    reports_dir = None
    
    for i, arg in enumerate(sys.argv):
        if arg == '--host' and i + 1 < len(sys.argv):
            host = sys.argv[i + 1]
        elif arg == '--port' and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
        elif arg == '--reports-dir' and i + 1 < len(sys.argv):
            reports_dir = sys.argv[i + 1]
    
    # Create and run the app
    app = create_app(reports_dir=reports_dir)
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   SUPABASE SECURITY DASHBOARD - Enterprise Edition       ║
    ║                                                           ║
    ║   🌐 Dashboard: http://{}:{}                     ║
    ║   📊 API: http://{}:{}/api/reports               ║
    ║                                                           ║
    ║   Press Ctrl+C to stop                                    ║
    ╚═══════════════════════════════════════════════════════════╝
    """.format(host, port, host, port))
    
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == '__main__':
    main()

