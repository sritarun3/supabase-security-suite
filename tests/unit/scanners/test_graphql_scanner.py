"""
Unit tests for scanners.graphql_scanner module.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from supabase_security_suite.scanners.graphql_scanner import GraphQLScanner
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.reporting.models import Severity, FindingCategory


class TestGraphQLScanner:
    """Tests for GraphQLScanner."""
    
    def test_scanner_initialization(self, scan_context):
        """Test GraphQL scanner initialization."""
        scanner = GraphQLScanner(scan_context)
        
        assert scanner.name == "graphql_scanner"
        assert "graphql" in scanner.description.lower()
        assert scanner.category == "graphql"
    
    @pytest.mark.asyncio
    async def test_scan_no_graphql(self, scan_context, tmp_path):
        """Test scanning directory with no GraphQL configuration."""
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should return empty or informational
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_introspection_enabled(self, scan_context, tmp_path):
        """Test detecting introspection enabled."""
        scan_context.config.scanners.graphql.check_introspection = True
        
        # Create a GraphQL config file
        config_file = tmp_path / "hasura-metadata.json"
        config_file.write_text("""
{
  "version": 3,
  "sources": [{
    "name": "default",
    "configuration": {
      "introspection": {
        "enabled": true
      }
    }
  }]
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect introspection enabled
        introspection_findings = [f for f in findings if "introspection" in f.description.lower()]
        assert len(introspection_findings) > 0
        
        if introspection_findings:
            assert introspection_findings[0].severity in [Severity.MEDIUM, Severity.HIGH]
            assert introspection_findings[0].category == FindingCategory.GRAPHQL
    
    @pytest.mark.asyncio
    async def test_scan_depth_limiting(self, scan_context, tmp_path):
        """Test detecting missing depth limiting."""
        config_file = tmp_path / ".graphqlrc.yml"
        config_file.write_text("""
schema: schema.graphql
documents: '**/*.graphql'
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should warn about missing depth limiting
        depth_findings = [f for f in findings if "depth" in f.description.lower() or "limit" in f.description.lower()]
        assert len(depth_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_rate_limiting(self, scan_context, tmp_path):
        """Test detecting missing rate limiting."""
        config_file = tmp_path / "apollo.config.js"
        config_file.write_text("""
module.exports = {
  client: {
    service: 'my-service'
  }
};
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should recommend rate limiting
        rate_findings = [f for f in findings if "rate" in f.description.lower() or "throttle" in f.description.lower()]
        assert len(rate_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_public_queries(self, scan_context, tmp_path):
        """Test detecting potentially public queries."""
        schema_file = tmp_path / "schema.graphql"
        schema_file.write_text("""
type Query {
  users: [User!]!
  user(id: ID!): User
  allPosts: [Post!]!
}

type User {
  id: ID!
  email: String!
  password: String!
}

type Post {
  id: ID!
  title: String!
  content: String!
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect exposed sensitive fields
        sensitive_findings = [f for f in findings if "password" in f.description.lower() or "sensitive" in f.description.lower()]
        assert len(sensitive_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_authentication(self, scan_context, tmp_path):
        """Test detecting missing authentication."""
        schema_file = tmp_path / "schema.graphql"
        schema_file.write_text("""
type Query {
  sensitiveData: String!
}

type Mutation {
  updateUser(id: ID!, data: UserInput!): User!
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should warn about authentication
        auth_findings = [f for f in findings if "auth" in f.description.lower() or "permission" in f.description.lower()]
        assert len(auth_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_hasura_permissions(self, scan_context, tmp_path):
        """Test checking Hasura permissions."""
        metadata_file = tmp_path / "metadata.json"
        metadata_file.write_text("""
{
  "version": 3,
  "sources": [{
    "name": "default",
    "tables": [{
      "table": {"schema": "public", "name": "users"},
      "select_permissions": [],
      "insert_permissions": []
    }]
  }]
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect missing permissions
        perm_findings = [f for f in findings if "permission" in f.description.lower()]
        assert len(perm_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_complexity_analysis(self, scan_context, tmp_path):
        """Test detecting missing complexity analysis."""
        schema_file = tmp_path / "schema.graphql"
        schema_file.write_text("""
type Query {
  posts: [Post!]!
}

type Post {
  id: ID!
  author: User!
  comments: [Comment!]!
}

type Comment {
  id: ID!
  author: User!
  replies: [Comment!]!
}

type User {
  id: ID!
  posts: [Post!]!
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should warn about complex nested queries
        complexity_findings = [f for f in findings if "complex" in f.description.lower() or "nested" in f.description.lower()]
        assert len(complexity_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_batch_attacks(self, scan_context, tmp_path):
        """Test detecting vulnerability to batch attacks."""
        config_file = tmp_path / "apollo-server.js"
        config_file.write_text("""
const { ApolloServer } = require('apollo-server');

const server = new ApolloServer({
  typeDefs,
  resolvers,
});
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should recommend batch protection
        batch_findings = [f for f in findings if "batch" in f.description.lower()]
        assert len(batch_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_cors_config(self, scan_context, tmp_path):
        """Test checking CORS configuration."""
        config_file = tmp_path / "server.js"
        config_file.write_text("""
const server = new ApolloServer({
  typeDefs,
  resolvers,
  cors: {
    origin: '*',
    credentials: true
  }
});
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should flag permissive CORS
        cors_findings = [f for f in findings if "cors" in f.description.lower()]
        assert len(cors_findings) > 0
        if cors_findings:
            assert cors_findings[0].severity in [Severity.HIGH, Severity.MEDIUM]
    
    @pytest.mark.asyncio
    async def test_scan_good_config(self, scan_context, tmp_path):
        """Test scanning well-configured GraphQL setup."""
        config_file = tmp_path / "hasura-metadata.json"
        config_file.write_text("""
{
  "version": 3,
  "sources": [{
    "name": "default",
    "configuration": {
      "introspection": {
        "enabled": false
      },
      "rate_limiting": {
        "enabled": true,
        "max_queries_per_minute": 100
      }
    },
    "tables": [{
      "table": {"schema": "public", "name": "users"},
      "select_permissions": [{
        "role": "user",
        "permission": {
          "filter": {"id": {"_eq": "X-Hasura-User-Id"}},
          "columns": ["id", "name", "email"]
        }
      }]
    }]
  }]
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        # Should have fewer critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
    
    @pytest.mark.asyncio
    async def test_finding_details(self, scan_context, tmp_path):
        """Test that findings have all required details."""
        schema_file = tmp_path / "schema.graphql"
        schema_file.write_text("""
type Query {
  users: [User!]!
}

type User {
  password: String!
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        finding = findings[0]
        
        # Check all required fields
        assert finding.id is not None
        assert finding.title is not None
        assert finding.description is not None
        assert finding.severity is not None
        assert finding.category == FindingCategory.GRAPHQL
        assert finding.recommendation is not None
    
    @pytest.mark.asyncio
    async def test_recommendations_provided(self, scan_context, tmp_path):
        """Test that recommendations are provided."""
        schema_file = tmp_path / "schema.graphql"
        schema_file.write_text("""
type Query {
  allData: String!
}
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = GraphQLScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        for finding in findings:
            # Each finding should have a recommendation
            assert finding.recommendation is not None
            assert len(finding.recommendation) > 0

