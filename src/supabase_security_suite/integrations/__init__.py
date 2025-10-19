"""
Integrations module for external services and AI.
"""

from .ai_examples import build_few_shot_prompt, get_example_count, get_examples_by_verdict

__all__ = [
    "build_few_shot_prompt",
    "get_example_count",
    "get_examples_by_verdict",
]
