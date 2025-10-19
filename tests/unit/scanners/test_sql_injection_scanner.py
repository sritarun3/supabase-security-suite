"""
Unit tests for scanners.sql_injection_scanner module.
"""

import pytest
from pathlib import Path

from supabase_security_suite.scanners.sql_injection_scanner import SQLInjectionScanner
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.reporting.models import Severity, FindingCategory


class TestSQLInjectionScanner:
    """Tests for SQLInjectionScanner."""
    
    def test_scanner_initialization(self, scan_context):
        """Test SQL Injection scanner initialization."""
        scanner = SQLInjectionScanner(scan_context)
        
        assert scanner.name == "sql_injection_scanner"
        assert "sql" in scanner.description.lower() or "injection" in scanner.description.lower()
        assert scanner.category == "sql_injection"
    
    @pytest.mark.asyncio
    async def test_scan_no_code(self, scan_context, tmp_path):
        """Test scanning directory with no code files."""
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should return empty
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_string_concatenation(self, scan_context, tmp_path):
        """Test detecting SQL string concatenation."""
        code_file = tmp_path / "app.py"
        code_file.write_text("""
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect string concatenation
        concat_findings = [f for f in findings if "concatenat" in f.description.lower() or "string" in f.description.lower()]
        assert len(concat_findings) > 0
        
        if concat_findings:
            assert concat_findings[0].severity in [Severity.CRITICAL, Severity.HIGH]
            assert concat_findings[0].category == FindingCategory.SQL_INJECTION
    
    @pytest.mark.asyncio
    async def test_scan_format_strings(self, scan_context, tmp_path):
        """Test detecting SQL with format strings."""
        code_file = tmp_path / "queries.py"
        code_file.write_text("""
def search_users(name):
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    return db.execute(query)
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect format string injection
        format_findings = [f for f in findings if "format" in f.description.lower() or "f-string" in f.description.lower()]
        assert len(format_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_percent_formatting(self, scan_context, tmp_path):
        """Test detecting SQL with % formatting."""
        code_file = tmp_path / "database.py"
        code_file.write_text("""
def get_posts(author_id):
    query = "SELECT * FROM posts WHERE author_id = %s" % (author_id,)
    cursor.execute(query)
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect % formatting
        percent_findings = [f for f in findings if "%" in f.description or "format" in f.description.lower()]
        assert len(percent_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_safe_parameterized(self, scan_context, tmp_path):
        """Test that parameterized queries are safe."""
        code_file = tmp_path / "safe_queries.py"
        code_file.write_text("""
def get_user_safe(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def search_posts_safe(keyword):
    query = "SELECT * FROM posts WHERE title ILIKE %s"
    cursor.execute(query, (f"%{keyword}%",))
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should not flag properly parameterized queries
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
    
    @pytest.mark.asyncio
    async def test_scan_execute_with_params(self, scan_context, tmp_path):
        """Test detecting execute() without parameters."""
        code_file = tmp_path / "unsafe.py"
        code_file.write_text("""
def search(term):
    # Unsafe - concatenated
    query = "SELECT * FROM items WHERE name = '" + term + "'"
    conn.execute(query)
    
    # Safe - parameterized
    query2 = "SELECT * FROM items WHERE id = %s"
    conn.execute(query2, (item_id,))
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect unsafe query
        unsafe_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(unsafe_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_raw_sql(self, scan_context, tmp_path):
        """Test detecting raw SQL execution."""
        code_file = tmp_path / "raw.py"
        code_file.write_text("""
def admin_query(table_name):
    # Very dangerous - table name from user input
    query = f"SELECT * FROM {table_name}"
    return db.raw(query)
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect raw SQL with user input
        raw_findings = [f for f in findings if "raw" in f.description.lower() or "table" in f.description.lower()]
        assert len(raw_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_javascript_sql(self, scan_context, tmp_path):
        """Test detecting SQL injection in JavaScript/TypeScript."""
        js_file = tmp_path / "api.js"
        js_file.write_text("""
async function getUser(userId) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return await db.query(query);
}

async function searchPosts(keyword) {
  const query = "SELECT * FROM posts WHERE title LIKE '%" + keyword + "%'";
  return db.execute(query);
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect JavaScript SQL injection
        js_findings = [f for f in findings if f.location and ".js" in f.location.file]
        assert len(js_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_orm_raw_queries(self, scan_context, tmp_path):
        """Test detecting ORM raw queries."""
        code_file = tmp_path / "models.py"
        code_file.write_text("""
from sqlalchemy import text

def get_filtered_users(filter_value):
    # Unsafe - concatenated into raw query
    query = text(f"SELECT * FROM users WHERE status = '{filter_value}'")
    return session.execute(query)

def get_user_safe(user_id):
    # Safe - using ORM
    return session.query(User).filter(User.id == user_id).first()
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect unsafe ORM raw query
        orm_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(orm_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_supabase_rpc(self, scan_context, tmp_path):
        """Test scanning Supabase RPC functions."""
        sql_file = tmp_path / "functions.sql"
        sql_file.write_text("""
CREATE OR REPLACE FUNCTION search_users(search_term text)
RETURNS TABLE (id uuid, name text, email text)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY EXECUTE 'SELECT id, name, email FROM users WHERE name LIKE ' || quote_literal('%' || search_term || '%');
END;
$$;
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should analyze SQL functions
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_multiple_languages(self, scan_context, tmp_path):
        """Test scanning multiple programming languages."""
        # Python file
        py_file = tmp_path / "app.py"
        py_file.write_text('query = "SELECT * FROM users WHERE id = " + user_id')
        
        # JavaScript file
        js_file = tmp_path / "api.js"
        js_file.write_text('const query = `SELECT * FROM posts WHERE id = ${postId}`;')
        
        # SQL file
        sql_file = tmp_path / "migrations.sql"
        sql_file.write_text('SELECT * FROM users;')
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should scan multiple languages
        assert len(findings) > 0
        file_types = {f.location.file.split('.')[-1] for f in findings if f.location}
        assert len(file_types) >= 2
    
    @pytest.mark.asyncio
    async def test_scan_dynamic_table_names(self, scan_context, tmp_path):
        """Test detecting dynamic table names."""
        code_file = tmp_path / "admin.py"
        code_file.write_text("""
def get_table_data(table_name):
    # Very dangerous - table name from user
    query = f"SELECT * FROM {table_name}"
    return execute(query)
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        # Should flag dynamic table names
        table_findings = [f for f in findings if "table" in f.description.lower()]
        assert len(table_findings) > 0
        if table_findings:
            assert table_findings[0].severity == Severity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_finding_details(self, scan_context, tmp_path):
        """Test that findings have all required details."""
        code_file = tmp_path / "vulnerable.py"
        code_file.write_text("""
def unsafe_query(user_input):
    query = "SELECT * FROM data WHERE value = " + user_input
    execute(query)
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        finding = findings[0]
        
        # Check all required fields
        assert finding.id is not None
        assert finding.title is not None
        assert finding.description is not None
        assert finding.severity is not None
        assert finding.category == FindingCategory.SQL_INJECTION
        assert finding.recommendation is not None
        
        # Should include location
        if finding.location:
            assert finding.location.file is not None
            assert finding.location.line is not None
    
    @pytest.mark.asyncio
    async def test_recommendations_provided(self, scan_context, tmp_path):
        """Test that recommendations are provided."""
        code_file = tmp_path / "bad.py"
        code_file.write_text("""
query = "SELECT * FROM users WHERE id = " + user_id
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SQLInjectionScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        for finding in findings:
            # Each finding should have a recommendation
            assert finding.recommendation is not None
            assert len(finding.recommendation) > 0
            # Should mention parameterized queries
            assert "parameter" in finding.recommendation.lower() or "prepared" in finding.recommendation.lower()

