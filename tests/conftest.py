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
    """Path to the variant adjacency-DB JSON for diff/merge tests."""
    return FIXTURES_DIR / "sample_db_v2.json"
