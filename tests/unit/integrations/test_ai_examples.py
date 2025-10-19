"""
Tests for AI few-shot examples module.
"""

import pytest
from supabase_security_suite.integrations.ai_examples import (
    build_few_shot_prompt,
    get_example_count,
    get_examples_by_verdict,
    FEW_SHOT_EXAMPLES,
)


def test_few_shot_examples_structure():
    """Test that few-shot examples have correct structure."""
    assert len(FEW_SHOT_EXAMPLES) > 0
    
    for example in FEW_SHOT_EXAMPLES:
        # Check required keys
        assert "finding" in example
        assert "verdict" in example
        assert "reason" in example
        assert "confidence" in example
        
        # Check finding structure
        finding = example["finding"]
        assert "title" in finding
        assert "severity" in finding
        
        # Check verdict values
        assert example["verdict"] in ["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"]
        
        # Check confidence values
        assert example["confidence"] in ["HIGH", "MEDIUM", "LOW"]


def test_get_example_count():
    """Test getting total example count."""
    count = get_example_count()
    assert count > 0
    assert count == len(FEW_SHOT_EXAMPLES)


def test_get_examples_by_verdict():
    """Test filtering examples by verdict."""
    false_positives = get_examples_by_verdict("FALSE_POSITIVE")
    true_positives = get_examples_by_verdict("TRUE_POSITIVE")
    
    assert len(false_positives) > 0
    assert len(true_positives) > 0
    
    # Verify all returned examples have correct verdict
    for ex in false_positives:
        assert ex["verdict"] == "FALSE_POSITIVE"
    
    for ex in true_positives:
        assert ex["verdict"] == "TRUE_POSITIVE"


def test_build_few_shot_prompt_basic():
    """Test building basic few-shot prompt."""
    finding = {
        "title": "Test Finding",
        "file": "app.py",
        "line": 42,
        "severity": "HIGH",
        "description": "Test description",
    }
    
    prompt = build_few_shot_prompt(finding)
    
    # Check prompt contains key elements
    assert "Test Finding" in prompt
    assert "app.py" in prompt
    assert "42" in prompt
    assert "Example" in prompt
    assert "VERDICT:" in prompt
    assert "REASON:" in prompt
    assert "CONFIDENCE:" in prompt


def test_build_few_shot_prompt_with_examples():
    """Test that prompt includes examples."""
    finding = {
        "title": "API Key Leak",
        "file": "config.py",
        "line": 10,
        "severity": "CRITICAL",
        "description": "API key found",
    }
    
    prompt = build_few_shot_prompt(finding, num_examples=3)
    
    # Should contain multiple examples
    assert "Example 1:" in prompt
    assert "Example 2:" in prompt
    assert "Example 3:" in prompt


def test_build_few_shot_prompt_custom_example_count():
    """Test custom number of examples."""
    finding = {
        "title": "Test",
        "file": "test.py",
        "line": 1,
        "severity": "LOW",
        "description": "Test",
    }
    
    prompt_3 = build_few_shot_prompt(finding, num_examples=3)
    prompt_5 = build_few_shot_prompt(finding, num_examples=5)
    
    # More examples should result in longer prompt
    assert len(prompt_5) > len(prompt_3)


def test_build_few_shot_prompt_analysis_criteria():
    """Test that prompt includes analysis criteria."""
    finding = {
        "title": "Test",
        "file": "test.py",
    }
    
    prompt = build_few_shot_prompt(finding)
    
    # Check for analysis criteria
    assert "FALSE POSITIVE" in prompt
    assert "TRUE POSITIVE" in prompt
    assert "NEEDS REVIEW" in prompt
    assert "documentation" in prompt.lower() or "README" in prompt


def test_build_few_shot_prompt_with_missing_fields():
    """Test prompt building with missing finding fields."""
    finding = {
        "title": "Incomplete Finding",
        # Missing file, line, etc.
    }
    
    prompt = build_few_shot_prompt(finding)
    
    # Should handle missing fields gracefully
    assert "Incomplete Finding" in prompt
    assert "N/A" in prompt  # Should show N/A for missing fields


def test_examples_cover_common_false_positives():
    """Test that examples cover common false positive scenarios."""
    false_positives = get_examples_by_verdict("FALSE_POSITIVE")
    
    # Check for common false positive patterns
    scenarios = {
        "documentation": False,
        "test": False,
        "example": False,
        "system_table": False,
    }
    
    for ex in false_positives:
        reason = ex["reason"].lower()
        finding = ex["finding"]
        file_name = finding.get("file", "").lower() if finding.get("file") else ""
        
        if "documentation" in reason or "readme" in file_name:
            scenarios["documentation"] = True
        if "test" in reason or "test" in file_name:
            scenarios["test"] = True
        if "example" in reason or "demo" in reason:
            scenarios["example"] = True
        if "system" in reason or "internal" in reason:
            scenarios["system_table"] = True
    
    # Should cover at least 3 of 4 common scenarios
    assert sum(scenarios.values()) >= 3


def test_examples_have_good_diversity():
    """Test that examples have diverse finding types."""
    titles = set()
    severities = set()
    
    for ex in FEW_SHOT_EXAMPLES:
        titles.add(ex["finding"]["title"])
        severities.add(ex["finding"].get("severity", ""))
    
    # Should have multiple different finding types
    assert len(titles) > 5
    
    # Should have multiple severity levels
    assert len(severities) >= 2

