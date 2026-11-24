from pathlib import Path

import pytest
import yaml

RULES_DIR = Path(__file__).resolve().parents[3] / "data" / "scanners" / "rules"
REQUIRED_KEYS = ("id", "message", "severity", "languages")


@pytest.mark.parametrize("name", ["dart.yaml", "javascript.yaml"])
def test_rules_load_and_have_required_fields(name):
    document = yaml.safe_load((RULES_DIR / name).read_text())
    assert document["rules"]
    for rule in document["rules"]:
        for key in REQUIRED_KEYS:
            assert rule[key]
        assert rule["metadata"]["category"]
        assert rule["metadata"]["severity"]
