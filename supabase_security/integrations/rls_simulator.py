"""
RLS Policy Simulator and Coverage Checker for Supabase.
"""

import re
import json
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
import sqlparse
from sqlparse.sql import Statement, Token, TokenList


@dataclass
class RLSPolicy:
    """Represents an RLS policy."""
    
    name: str
    table: str
    operation: str  # SELECT, INSERT, UPDATE, DELETE, ALL
    using_clause: str
    with_check_clause: str
    is_permissive: bool = False
    coverage_score: float = 0.0
    complexity_score: float = 0.0


@dataclass
class TableInfo:
    """Information about a database table."""
    
    name: str
    schema: str = "public"
    columns: List[str] = None
    rls_enabled: bool = False
    policies: List[RLSPolicy] = None
    
    def __post_init__(self):
        if self.columns is None:
            self.columns = []
        if self.policies is None:
            self.policies = []


@dataclass
class RLSCoverageReport:
    """RLS coverage analysis report."""
    
    total_tables: int
    tables_with_rls: int
    tables_with_policies: int
    uncovered_tables: List[str]
    weak_policies: List[RLSPolicy]
    coverage_percentage: float
    recommendations: List[str]


class RLSSimulator:
    """Simulates RLS policy behavior and checks coverage."""
    
    def __init__(self):
        self.policies: List[RLSPolicy] = []
        self.tables: List[TableInfo] = []
        self.test_scenarios: List[Dict[str, Any]] = []
    
    def load_policies_from_sql(self, sql_content: str) -> List[RLSPolicy]:
        """Parse RLS policies from SQL content."""
        policies = []
        
        # Parse SQL content
        parsed = sqlparse.parse(sql_content)
        
        for statement in parsed:
            if self._is_create_policy_statement(statement):
                policy = self._extract_policy_from_statement(statement)
                if policy:
                    policies.append(policy)
        
        self.policies.extend(policies)
        return policies
    
    def _is_create_policy_statement(self, statement: Statement) -> bool:
        """Check if statement is a CREATE POLICY statement."""
        tokens = [token for token in statement.flatten() if not token.is_whitespace]
        if len(tokens) < 3:
            return False
        
        return (tokens[0].ttype is sqlparse.tokens.Keyword and tokens[0].value.upper() == 'CREATE' and
                tokens[1].ttype is sqlparse.tokens.Keyword and tokens[1].value.upper() == 'POLICY')
    
    def _extract_policy_from_statement(self, statement: Statement) -> Optional[RLSPolicy]:
        """Extract policy information from CREATE POLICY statement."""
        try:
            # Convert to string and use regex for more reliable parsing
            sql_str = str(statement)
            
            # Pattern to match CREATE POLICY statements
            pattern = r"CREATE\s+POLICY\s+(\w+)\s+ON\s+(\w+\.?\w*)\s+FOR\s+(\w+)\s*(?:USING\s*\(([^)]+)\))?\s*(?:WITH\s+CHECK\s*\(([^)]+)\))?"
            
            match = re.search(pattern, sql_str, re.IGNORECASE | re.MULTILINE)
            if not match:
                return None
            
            policy_name = match.group(1)
            table_name = match.group(2)
            operation = match.group(3).upper()
            using_clause = match.group(4) or ""
            with_check_clause = match.group(5) or ""
            
            # Check if policy is permissive
            is_permissive = "true" in using_clause.lower() if using_clause else False
            
            policy = RLSPolicy(
                name=policy_name,
                table=table_name,
                operation=operation,
                using_clause=using_clause,
                with_check_clause=with_check_clause,
                is_permissive=is_permissive
            )
            
            # Calculate complexity and coverage scores
            policy.complexity_score = self._calculate_policy_complexity(policy)
            policy.coverage_score = self._calculate_policy_coverage(policy)
            
            return policy
            
        except Exception as e:
            print(f"Error parsing policy statement: {e}")
            return None
    
    def _calculate_policy_complexity(self, policy: RLSPolicy) -> float:
        """Calculate policy complexity score (0-1, higher is more complex)."""
        score = 0.0
        
        # Base complexity from clause length
        using_length = len(policy.using_clause)
        check_length = len(policy.with_check_clause)
        
        score += min(using_length / 100, 0.3)  # Max 0.3 for using clause
        score += min(check_length / 100, 0.3)  # Max 0.3 for check clause
        
        # Complexity from operators
        complex_operators = ['EXISTS', 'IN', 'ANY', 'ALL', 'CASE', 'COALESCE']
        for op in complex_operators:
            if op in policy.using_clause.upper():
                score += 0.1
            if op in policy.with_check_clause.upper():
                score += 0.1
        
        # Complexity from subqueries
        subquery_count = policy.using_clause.count('(') + policy.with_check_clause.count('(')
        score += min(subquery_count * 0.05, 0.2)
        
        return min(score, 1.0)
    
    def _calculate_policy_coverage(self, policy: RLSPolicy) -> float:
        """Calculate policy coverage score (0-1, higher is better coverage)."""
        score = 0.0
        
        # Penalty for permissive policies
        if policy.is_permissive:
            return 0.1
        
        # Score based on specific conditions
        using_clause = policy.using_clause.lower()
        
        # Good coverage indicators
        if 'auth.uid()' in using_clause:
            score += 0.3
        if 'auth.role()' in using_clause:
            score += 0.2
        if 'user_id' in using_clause or 'owner_id' in using_clause:
            score += 0.2
        if 'organization_id' in using_clause or 'tenant_id' in using_clause:
            score += 0.2
        if 'status' in using_clause or 'active' in using_clause:
            score += 0.1
        
        # Penalty for overly broad conditions
        if 'is not null' in using_clause:
            score -= 0.1
        if 'created_at' in using_clause and '>' in using_clause:
            score += 0.1  # Time-based access is good
        
        return max(0.0, min(score, 1.0))
    
    def add_table(self, table: TableInfo) -> None:
        """Add table information."""
        self.tables.append(table)
    
    def simulate_policy_evaluation(self, policy: RLSPolicy, context: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate policy evaluation with given context."""
        result = {
            "policy_name": policy.name,
            "table": policy.table,
            "operation": policy.operation,
            "allowed": False,
            "reason": "",
            "confidence": 0.0
        }
        
        try:
            # Simple simulation based on common patterns
            using_clause = policy.using_clause.lower()
            
            if policy.is_permissive:
                result["allowed"] = True
                result["reason"] = "Permissive policy (always allows)"
                result["confidence"] = 1.0
                return result
            
            # Check for authentication requirements
            if 'auth.uid()' in using_clause:
                if context.get("user_id"):
                    result["allowed"] = True
                    result["reason"] = "User authenticated and matches policy"
                    result["confidence"] = 0.8
                else:
                    result["allowed"] = False
                    result["reason"] = "User not authenticated"
                    result["confidence"] = 0.9
            elif 'auth.role()' in using_clause:
                user_role = context.get("user_role", "anon")
                if "authenticated" in using_clause and user_role == "authenticated":
                    result["allowed"] = True
                    result["reason"] = "User has authenticated role"
                    result["confidence"] = 0.8
                else:
                    result["allowed"] = False
                    result["reason"] = "User role does not match policy"
                    result["confidence"] = 0.7
            else:
                # Generic policy - assume it works but with low confidence
                result["allowed"] = True
                result["reason"] = "Policy condition not fully analyzable"
                result["confidence"] = 0.3
            
        except Exception as e:
            result["reason"] = f"Error simulating policy: {e}"
            result["confidence"] = 0.0
        
        return result
    
    def generate_test_scenarios(self) -> List[Dict[str, Any]]:
        """Generate test scenarios for RLS policies."""
        scenarios = []
        
        # Common test scenarios
        base_scenarios = [
            {
                "name": "Anonymous User",
                "context": {"user_id": None, "user_role": "anon"},
                "description": "Test access for unauthenticated users"
            },
            {
                "name": "Authenticated User",
                "context": {"user_id": "user123", "user_role": "authenticated"},
                "description": "Test access for authenticated users"
            },
            {
                "name": "Service Role",
                "context": {"user_id": None, "user_role": "service_role"},
                "description": "Test access for service role (bypasses RLS)"
            },
            {
                "name": "Owner Access",
                "context": {"user_id": "user123", "user_role": "authenticated", "is_owner": True},
                "description": "Test access for resource owner"
            },
            {
                "name": "Cross-User Access",
                "context": {"user_id": "user456", "user_role": "authenticated", "is_owner": False},
                "description": "Test access for different user"
            }
        ]
        
        # Generate scenarios for each policy
        for policy in self.policies:
            for scenario in base_scenarios:
                simulation_result = self.simulate_policy_evaluation(policy, scenario["context"])
                
                scenarios.append({
                    "policy_name": policy.name,
                    "table": policy.table,
                    "operation": policy.operation,
                    "scenario": scenario["name"],
                    "context": scenario["context"],
                    "result": simulation_result,
                    "description": scenario["description"]
                })
        
        self.test_scenarios = scenarios
        return scenarios
    
    def analyze_coverage(self) -> RLSCoverageReport:
        """Analyze RLS coverage across all tables."""
        total_tables = len(self.tables)
        tables_with_rls = len([t for t in self.tables if t.rls_enabled])
        tables_with_policies = len([t for t in self.tables if any(p.table == t.name for p in self.policies)])
        
        uncovered_tables = []
        for table in self.tables:
            if table.rls_enabled and not any(p.table == table.name for p in self.policies):
                uncovered_tables.append(table.name)
        
        # Find weak policies
        weak_policies = [p for p in self.policies if p.coverage_score < 0.5 or p.is_permissive]
        
        # Calculate coverage percentage
        if total_tables > 0:
            coverage_percentage = (tables_with_policies / total_tables) * 100
        else:
            coverage_percentage = 0.0
        
        # Generate recommendations
        recommendations = []
        
        if uncovered_tables:
            recommendations.append(f"Add RLS policies for tables: {', '.join(uncovered_tables)}")
        
        if weak_policies:
            recommendations.append(f"Review and strengthen {len(weak_policies)} weak policies")
        
        if tables_with_rls < total_tables:
            recommendations.append(f"Consider enabling RLS on {total_tables - tables_with_rls} tables without RLS")
        
        if coverage_percentage < 80:
            recommendations.append("Overall RLS coverage is below 80% - consider comprehensive policy review")
        
        return RLSCoverageReport(
            total_tables=total_tables,
            tables_with_rls=tables_with_rls,
            tables_with_policies=tables_with_policies,
            uncovered_tables=uncovered_tables,
            weak_policies=weak_policies,
            coverage_percentage=coverage_percentage,
            recommendations=recommendations
        )
    
    def export_analysis(self, output_path: str) -> None:
        """Export RLS analysis to JSON file."""
        coverage_report = self.analyze_coverage()
        test_scenarios = self.generate_test_scenarios()
        
        analysis_data = {
            "policies": [
                {
                    "name": p.name,
                    "table": p.table,
                    "operation": p.operation,
                    "using_clause": p.using_clause,
                    "with_check_clause": p.with_check_clause,
                    "is_permissive": p.is_permissive,
                    "complexity_score": p.complexity_score,
                    "coverage_score": p.coverage_score
                }
                for p in self.policies
            ],
            "tables": [
                {
                    "name": t.name,
                    "schema": t.schema,
                    "rls_enabled": t.rls_enabled,
                    "policy_count": len([p for p in self.policies if p.table == t.name])
                }
                for t in self.tables
            ],
            "coverage_report": {
                "total_tables": coverage_report.total_tables,
                "tables_with_rls": coverage_report.tables_with_rls,
                "tables_with_policies": coverage_report.tables_with_policies,
                "uncovered_tables": coverage_report.uncovered_tables,
                "weak_policies_count": len(coverage_report.weak_policies),
                "coverage_percentage": coverage_report.coverage_percentage,
                "recommendations": coverage_report.recommendations
            },
            "test_scenarios": test_scenarios
        }
        
        with open(output_path, 'w') as f:
            json.dump(analysis_data, f, indent=2)
    
    def get_security_findings(self) -> List[Dict[str, Any]]:
        """Generate security findings from RLS analysis."""
        findings = []
        coverage_report = self.analyze_coverage()
        
        # Finding for uncovered tables
        if coverage_report.uncovered_tables:
            findings.append({
                "id": "rls:uncovered_tables",
                "title": "Tables with RLS enabled but no policies",
                "severity": "HIGH",
                "description": f"Tables {', '.join(coverage_report.uncovered_tables)} have RLS enabled but no policies defined",
                "impact": "RLS is enabled but provides no protection without policies",
                "recommendation": "Add appropriate RLS policies for all tables with RLS enabled",
                "source": "rls_simulator",
                "metadata": {
                    "uncovered_tables": coverage_report.uncovered_tables,
                    "coverage_percentage": coverage_report.coverage_percentage
                }
            })
        
        # Finding for weak policies
        if coverage_report.weak_policies:
            permissive_policies = [p for p in coverage_report.weak_policies if p.is_permissive]
            if permissive_policies:
                findings.append({
                    "id": "rls:permissive_policies",
                    "title": "Permissive RLS policies detected",
                    "severity": "HIGH",
                    "description": f"Found {len(permissive_policies)} policies with 'true' conditions",
                    "impact": "Permissive policies allow all access, defeating RLS purpose",
                    "recommendation": "Replace permissive policies with specific conditions",
                    "source": "rls_simulator",
                    "metadata": {
                        "permissive_policies": [p.name for p in permissive_policies],
                        "policy_count": len(permissive_policies)
                    }
                })
        
        # Finding for low coverage
        if coverage_report.coverage_percentage < 50:
            findings.append({
                "id": "rls:low_coverage",
                "title": "Low RLS policy coverage",
                "severity": "MEDIUM",
                "description": f"Only {coverage_report.coverage_percentage:.1f}% of tables have RLS policies",
                "impact": "Insufficient RLS coverage may leave data unprotected",
                "recommendation": "Implement comprehensive RLS policies across all tables",
                "source": "rls_simulator",
                "metadata": {
                    "coverage_percentage": coverage_report.coverage_percentage,
                    "total_tables": coverage_report.total_tables,
                    "tables_with_policies": coverage_report.tables_with_policies
                }
            })
        
        return findings
