"""Shared fixtures for ted_tools tests."""
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_ted_xml() -> Path:
    """Path to the small hand-crafted Junos TED XML fixture."""
    return FIXTURES_DIR / "sample_ted.xml"


@pytest.fixture
def sample_db_json() -> Path:
    """Path to the small adjacency-DB JSON fixture."""
    return FIXTURES_DIR / "sample_db.json"


@pytest.fixture
def sample_db_v2_json() -> Path:
    """Path to the variant adjacency-DB JSON for diff/merge tests.

    Diff vs sample_db.json:
    - node-A→node-B: IGP Metric changed from 10000 to 12000 (one changed link)
    - node-A→node-C: NEW link via plane3 admin group (one added link, intentionally
      one-sided — no reciprocal node-C→node-A entry — to surface a clean
      'added' signal in diff tests without bidirectional matching noise)
    - node-B and node-C entries: unchanged from sample_db.json
    """
    return FIXTURES_DIR / "sample_db_v2.json"
