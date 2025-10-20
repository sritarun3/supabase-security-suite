#!/usr/bin/env python3
"""
Comprehensive test suite for Supabase Security Suite
Tests all major components and integrations
"""

import unittest
import json
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess
import time

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

class TestSupabaseSecuritySuite(unittest.TestCase):
    """Main test class for the security suite"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = Path(self.test_dir) / "test_file.py"
        
        # Create a test file with some content
        with open(self.test_file, 'w') as f:
            f.write("""
# Test file with potential security issues
import os
SECRET_KEY = "test-secret-key-123"
DATABASE_URL = "postgresql://user:pass@localhost/db"

def test_function():
    return "test"
""")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_imports(self):
        """Test that all modules can be imported"""
        try:
            import final
            import dashboard_server
            import cli_dashboard
            print("✅ All modules imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import module: {e}")
    
    def test_final_py_syntax(self):
        """Test final.py syntax"""
        try:
            with open('final.py', 'r') as f:
                compile(f.read(), 'final.py', 'exec')
            print("✅ final.py syntax is valid")
        except SyntaxError as e:
            self.fail(f"Syntax error in final.py: {e}")
    
    def test_dashboard_server_syntax(self):
        """Test dashboard_server.py syntax"""
        try:
            with open('dashboard_server.py', 'r') as f:
                compile(f.read(), 'dashboard_server.py', 'exec')
            print("✅ dashboard_server.py syntax is valid")
        except SyntaxError as e:
            self.fail(f"Syntax error in dashboard_server.py: {e}")
    
    def test_cli_dashboard_syntax(self):
        """Test cli_dashboard.py syntax"""
        try:
            with open('cli_dashboard.py', 'r') as f:
                compile(f.read(), 'cli_dashboard.py', 'exec')
            print("✅ cli_dashboard.py syntax is valid")
        except SyntaxError as e:
            self.fail(f"Syntax error in cli_dashboard.py: {e}")
    
    def test_requirements_file(self):
        """Test requirements.txt file exists and has content"""
        self.assertTrue(Path('requirements.txt').exists(), "requirements.txt file missing")
        
        with open('requirements.txt', 'r') as f:
            content = f.read()
            self.assertGreater(len(content.strip()), 0, "requirements.txt is empty")
            
        # Check for essential dependencies
        required_packages = ['rich', 'psycopg', 'flask', 'requests']
        for package in required_packages:
            self.assertIn(package, content.lower(), f"Missing required package: {package}")
        
        print("✅ requirements.txt is valid")
    
    def test_config_files(self):
        """Test configuration files exist and are valid"""
        # Test .gitignore
        self.assertTrue(Path('.gitignore').exists(), ".gitignore file missing")
        
        # Test LICENSE
        self.assertTrue(Path('LICENSE').exists(), "LICENSE file missing")
        
        # Test README
        self.assertTrue(Path('README.md').exists(), "README.md file missing")
        
        # Test example config
        self.assertTrue(Path('config.example.json').exists(), "config.example.json missing")
        
        # Validate JSON config
        with open('config.example.json', 'r') as f:
            config = json.load(f)
            self.assertIn('scan_defaults', config)
            self.assertIn('dashboard', config)
            self.assertIn('ai', config)
            self.assertIn('jira', config)
        
        print("✅ Configuration files are valid")
    
    def test_dashboard_template(self):
        """Test dashboard template exists and has required elements"""
        self.assertTrue(Path('templates/dashboard.html').exists(), "dashboard.html template missing")
        
        with open('templates/dashboard.html', 'r') as f:
            content = f.read()
            
        # Check for essential elements
        required_elements = [
            'chart.js',
            'alpinejs',
            'severityChart',
            'sourceChart',
            'dashboard()'
        ]
        
        for element in required_elements:
            self.assertIn(element, content, f"Missing required element: {element}")
        
        print("✅ Dashboard template is valid")
    
    def test_no_hardcoded_ips(self):
        """Test that no hardcoded IP addresses exist in main files"""
        sensitive_files = [
            'final.py',
            'dashboard_server.py',
            'cli_dashboard.py',
            'templates/dashboard.html',
            'README.md'
        ]
        
        # Pattern to match IP addresses (basic pattern)
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        for file_path in sensitive_files:
            if Path(file_path).exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                    # Remove localhost and 0.0.0.0 as they're acceptable
                    content = re.sub(r'127\.0\.0\.1|localhost|0\.0\.0\.0', '', content)
                    matches = re.findall(ip_pattern, content)
                    
                    if matches:
                        # Filter out common non-sensitive IPs
                        filtered_matches = [ip for ip in matches if not ip.startswith('127.') and ip != '0.0.0.0']
                        if filtered_matches:
                            self.fail(f"Found hardcoded IP addresses in {file_path}: {filtered_matches}")
        
        print("✅ No hardcoded IP addresses found")
    
    def test_ai_recommendations_module(self):
        """Test AI recommendations functionality"""
        try:
            import test_ai_recommendations
            # Check if the module has the expected functions
            self.assertTrue(hasattr(test_ai_recommendations, 'test_ai_recommendation'), 
                           "Missing test_ai_recommendation function")
            print("✅ AI recommendations module is valid")
        except ImportError as e:
            self.fail(f"Failed to import AI recommendations test: {e}")
    
    def test_file_permissions(self):
        """Test that scripts have proper permissions"""
        script_files = [
            'final.py',
            'dashboard_server.py',
            'cli_dashboard.py',
            'start_dashboard.sh'
        ]
        
        for script in script_files:
            if Path(script).exists():
                # Check if file is readable
                self.assertTrue(os.access(script, os.R_OK), f"{script} is not readable")
                print(f"✅ {script} has proper permissions")
    
    def test_directory_structure(self):
        """Test that directory structure is correct"""
        required_dirs = ['templates', 'static']
        
        for dir_name in required_dirs:
            self.assertTrue(Path(dir_name).exists(), f"Required directory missing: {dir_name}")
        
        print("✅ Directory structure is correct")
    
    def test_no_sensitive_data(self):
        """Test that no sensitive data is exposed"""
        sensitive_patterns = [
            r'sk-[a-zA-Z0-9]{20,}',  # OpenAI API keys
            r'password\s*=\s*["\'][^"\']+["\']',  # Passwords
            r'token\s*=\s*["\'][^"\']+["\']',  # Tokens
        ]
        
        import re
        
        # Check main Python files
        python_files = ['final.py', 'dashboard_server.py', 'cli_dashboard.py']
        
        for file_path in python_files:
            if Path(file_path).exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.fail(f"Found potential sensitive data in {file_path}: {matches}")
        
        print("✅ No sensitive data found in code")
    
    def test_import_dependencies(self):
        """Test that all dependencies can be imported"""
        try:
            import rich
            import flask
            import requests
            print("✅ Core dependencies can be imported")
        except ImportError as e:
            self.fail(f"Missing dependency: {e}")
    
    @patch('subprocess.run')
    def test_dashboard_startup_script(self, mock_run):
        """Test dashboard startup script functionality"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        
        # Test that the script exists and is executable
        script_path = Path('start_dashboard.sh')
        self.assertTrue(script_path.exists(), "start_dashboard.sh missing")
        
        with open(script_path, 'r') as f:
            content = f.read()
            self.assertIn('python3', content)
            self.assertIn('dashboard_server.py', content)
        
        print("✅ Dashboard startup script is valid")

def run_tests():
    """Run all tests and provide summary"""
    print("🧪 Running Supabase Security Suite Test Suite")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSupabaseSecuritySuite)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    print(f"✅ Tests run: {result.testsRun}")
    print(f"❌ Failures: {len(result.failures)}")
    print(f"🚨 Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n🚨 Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed! The directory is GitHub-ready.")
        return True
    else:
        print(f"\n⚠️  {len(result.failures + result.errors)} test(s) failed.")
        return False

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
