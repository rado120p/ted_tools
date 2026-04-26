"""Security boundary regression tests for ted_tools."""
from pathlib import Path

import lxml.etree as etree
import pytest

from ted_tools.db_handler import _SAFE_XML_PARSER
from ted_tools.ted_handler import UnsupportedDbFormatError, validate_db_format


def test_safe_xml_parser_blocks_xxe(tmp_path):
    """XXE entity does NOT resolve through the safe parser (regression for SEC-002)."""
    xxe = tmp_path / "xxe.xml"
    xxe.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
        '<root><data>&xxe;</data></root>\n'
    )
    tree = etree.parse(str(xxe), parser=_SAFE_XML_PARSER)
    text = tree.find("data").text or ""
    assert "root:" not in text, f"XXE leaked /etc/passwd: {text!r}"


def test_no_pickle_imports_in_src():
    """Regression for SEC-001: no pickle import survives anywhere in src/."""
    src = Path(__file__).resolve().parent.parent / "src" / "ted_tools"
    for py in src.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        # Look for the literal import statement (not just the word in a comment)
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("import pickle") or stripped.startswith("from pickle"):
                pytest.fail(f"pickle import survives at {py}: {line!r}")


def test_unsupported_db_format_message_no_pickle(tmp_path):
    """Error message for unsupported DB suffix does NOT mention pickle (regression for SEC-001)."""
    bad = tmp_path / "bad.txt"
    bad.write_text("anything")
    with pytest.raises(UnsupportedDbFormatError) as exc_info:
        validate_db_format(str(bad))
    msg = str(exc_info.value)
    assert "pickle" not in msg.lower()
    assert ".json" in msg
