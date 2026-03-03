"""YARA rule service."""

import os
from pathlib import Path
from typing import List

YARA_RULES_PATH = os.environ.get("YARA_RULES_PATH", "/data/extracted/yara")


def get_available_rules() -> List[dict]:
    """List available YARA rule files."""
    rules_dir = Path(YARA_RULES_PATH)
    if not rules_dir.exists():
        return []

    rules = []
    for rule_file in rules_dir.glob("**/*.yar"):
        try:
            stat = rule_file.stat()
            rules.append({
                "name": rule_file.name,
                "path": str(rule_file.relative_to(rules_dir)),
                "size": stat.st_size,
            })
        except Exception:
            pass

    for rule_file in rules_dir.glob("**/*.yara"):
        try:
            stat = rule_file.stat()
            rules.append({
                "name": rule_file.name,
                "path": str(rule_file.relative_to(rules_dir)),
                "size": stat.st_size,
            })
        except Exception:
            pass

    return rules
