"""
AI Few-Shot Examples for False Positive Detection

Provides curated examples to improve AI accuracy in identifying false positives.
"""

from typing import Dict, List

# Curated few-shot examples for AI validation
FEW_SHOT_EXAMPLES: List[Dict] = [
    {
        "finding": {
            "title": "Supabase service_role key leak",
            "file": "README.md",
            "line": 45,
            "severity": "CRITICAL",
            "description": "JWT token found in file",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "Documentation file with example credentials for demonstration purposes",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "Supabase service_role key leak",
            "file": "src/api/auth.py",
            "line": 12,
            "severity": "CRITICAL",
            "description": "JWT token found in production code",
        },
        "verdict": "TRUE_POSITIVE",
        "reason": "Real credential hardcoded in production source code",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "RLS disabled on vault.secrets",
            "file": None,
            "severity": "HIGH",
            "description": "Table does not have RLS enabled",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "Internal Supabase system table (vault schema), not user-facing",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "RLS disabled on users",
            "file": None,
            "severity": "CRITICAL",
            "description": "Table does not have RLS enabled",
        },
        "verdict": "TRUE_POSITIVE",
        "reason": "User-facing table without RLS exposes sensitive data",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "HTTP endpoint present",
            "file": "README.md",
            "line": 23,
            "severity": "MEDIUM",
            "description": "http://localhost:54321 in documentation",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "localhost URL in documentation for development setup",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "HTTP endpoint present",
            "file": ".env.production",
            "line": 5,
            "severity": "MEDIUM",
            "description": "http://api.example.com in production config",
        },
        "verdict": "TRUE_POSITIVE",
        "reason": "Production environment using HTTP instead of HTTPS",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "Weak JWT Secret",
            "file": "config-example.toml",
            "line": 12,
            "severity": "HIGH",
            "description": "JWT secret is only 16 characters",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "Example configuration file, not actual production config",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "Weak JWT Secret",
            "file": ".env",
            "line": 8,
            "severity": "HIGH",
            "description": "JWT secret is only 16 characters",
        },
        "verdict": "TRUE_POSITIVE",
        "reason": "Production environment file with weak secret",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "Supabase service_role key leak",
            "file": "tests/test_auth.py",
            "line": 15,
            "severity": "CRITICAL",
            "description": "JWT token in test file",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "Test file with mock credentials for testing",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "SQL Injection vulnerability",
            "file": "src/database/queries.py",
            "line": 45,
            "severity": "CRITICAL",
            "description": "String concatenation in SQL query",
        },
        "verdict": "TRUE_POSITIVE",
        "reason": "Real SQL injection vulnerability in production code",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "RLS disabled on pg_stat_statements",
            "file": None,
            "severity": "HIGH",
            "description": "PostgreSQL system table without RLS",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "PostgreSQL internal table (pg_* prefix), not application data",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "Dangerous eval() usage detected",
            "file": "examples/demo.py",
            "line": 23,
            "severity": "HIGH",
            "description": "eval() found in code",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "Example/demo file demonstrating bad practices",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "Dangerous eval() usage detected",
            "file": "src/parser.py",
            "line": 89,
            "severity": "HIGH",
            "description": "eval() found in production code",
        },
        "verdict": "TRUE_POSITIVE",
        "reason": "Dangerous eval() in production parser code",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "RLS disabled on net.http_request_queue",
            "file": None,
            "severity": "HIGH",
            "description": "Supabase net schema table without RLS",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "Supabase internal net schema for HTTP extensions, not user data",
        "confidence": "HIGH",
    },
    {
        "finding": {
            "title": "API key exposed",
            "file": "supabase-demo.env",
            "line": 7,
            "severity": "CRITICAL",
            "description": "API key found in demo file",
        },
        "verdict": "FALSE_POSITIVE",
        "reason": "Demo environment file with example API key",
        "confidence": "HIGH",
    },
]


def build_few_shot_prompt(finding: dict, num_examples: int = 5) -> str:
    """
    Build a prompt with few-shot examples for better AI classification.

    Args:
        finding: The finding to classify (dict with title, file, line, etc.)
        num_examples: Number of examples to include (default: 5)

    Returns:
        Formatted prompt string with examples
    """
    # Select relevant examples (first N for now, could be smarter with similarity)
    selected_examples = FEW_SHOT_EXAMPLES[:num_examples]

    # Format examples
    examples_text = "\n\n".join(
        [
            f"Example {i+1}:\n"
            f"Finding: {ex['finding']['title']}\n"
            f"File: {ex['finding'].get('file', 'N/A')}\n"
            f"Severity: {ex['finding'].get('severity', 'N/A')}\n"
            f"Verdict: {ex['verdict']}\n"
            f"Reason: {ex['reason']}\n"
            f"Confidence: {ex['confidence']}"
            for i, ex in enumerate(selected_examples)
        ]
    )

    # Build prompt
    prompt = f"""You are a security expert analyzing potential security findings.
Learn from these examples of TRUE vs FALSE positives:

{examples_text}

Now analyze this finding:
Title: {finding.get('title', 'N/A')}
File: {finding.get('file', 'N/A')}
Line: {finding.get('line', 'N/A')}
Severity: {finding.get('severity', 'N/A')}
Description: {finding.get('description', 'N/A')}
Impact: {finding.get('impact', 'N/A')}

ANALYSIS CRITERIA:
✅ FALSE POSITIVE if:
- In documentation/README/example/test files
- Mock/example credentials (e.g., "your-api-key", "example.com")
- System/internal tables (vault.*, net.*, pg_*, information_schema, _realtime.*)
- HTTP URLs in docs or localhost
- Comments or code examples

🚨 TRUE POSITIVE if:
- Real credentials in production code
- Missing RLS on user data tables
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

    return prompt


def get_example_count() -> int:
    """Get the total number of curated examples."""
    return len(FEW_SHOT_EXAMPLES)


def get_examples_by_verdict(verdict: str) -> List[Dict]:
    """
    Get examples filtered by verdict.

    Args:
        verdict: "TRUE_POSITIVE" or "FALSE_POSITIVE" or "NEEDS_REVIEW"

    Returns:
        List of examples matching the verdict
    """
    return [ex for ex in FEW_SHOT_EXAMPLES if ex["verdict"] == verdict]

