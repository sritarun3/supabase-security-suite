"""
Deduplication logic for security findings.

Merges duplicate findings by (title + file) and aggregates line numbers.
"""

from collections import defaultdict
from typing import Dict, List, Tuple

from .models import Finding


class FindingDeduplicator:
    """Deduplicate findings by title and file, aggregating line numbers."""

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Merge findings with same title + file.
        Aggregate line numbers into metadata.

        Args:
            findings: List of findings to deduplicate

        Returns:
            Deduplicated list of findings
        """
        if not findings:
            return []

        # Group findings by (title, file)
        groups: Dict[Tuple[str, str], List[Finding]] = defaultdict(list)

        for finding in findings:
            # Use file path from location if available, otherwise use "N/A"
            file_key = finding.location.file if finding.location and finding.location.file else "N/A"
            key = (finding.title, file_key)
            groups[key].append(finding)

        # Merge duplicates
        deduplicated = []
        for (title, file), group in groups.items():
            if len(group) == 1:
                # No duplicates, keep as-is
                deduplicated.append(group[0])
            else:
                # Merge: keep first finding, add metadata about duplicates
                primary = group[0]

                # Collect all line numbers
                lines = []
                for f in group:
                    if f.location and f.location.line:
                        lines.append(f.location.line)

                # Update metadata
                if lines:
                    primary.metadata = primary.metadata or {}
                    primary.metadata["all_lines"] = sorted(set(lines))
                    primary.metadata["occurrence_count"] = len(group)

                    # Update description to indicate multiple locations
                    if len(lines) > 1:
                        primary.description = (
                            f"{primary.description} "
                            f"(Found at {len(lines)} locations: lines {', '.join(map(str, sorted(set(lines))))})"
                        )

                deduplicated.append(primary)

        return deduplicated

    def get_deduplication_stats(
        self, original: List[Finding], deduplicated: List[Finding]
    ) -> Dict[str, int]:
        """
        Get statistics about deduplication.

        Args:
            original: Original findings list
            deduplicated: Deduplicated findings list

        Returns:
            Dictionary with stats (original_count, deduplicated_count, removed_count, reduction_pct)
        """
        original_count = len(original)
        deduplicated_count = len(deduplicated)
        removed_count = original_count - deduplicated_count
        reduction_pct = int((removed_count / original_count) * 100) if original_count > 0 else 0

        return {
            "original_count": original_count,
            "deduplicated_count": deduplicated_count,
            "removed_count": removed_count,
            "reduction_pct": reduction_pct,
        }

