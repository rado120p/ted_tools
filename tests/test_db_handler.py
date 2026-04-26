"""Tests for ted_tools.db_handler — XML→DB parsing + JSON roundtrip."""
import json

import pytest

from ted_tools.db_handler import (
    FileOperationError,
    load_json_db,
    parse_xml,
    save_json_db,
)
from ted_tools.ted_handler import gather_node_data


def test_parse_xml_basic(sample_ted_xml):
    """parse_xml + gather_node_data on the fixture yields the expected adjacency-DB shape."""
    parsed = parse_xml(str(sample_ted_xml))
    db = gather_node_data(parsed)
    assert sorted(db.keys()) == ["node-A", "node-B", "node-C"]
    # node-B has links to both node-A and node-C
    neighbors_b = sorted(r["Neighbor"] for r in db["node-B"])
    assert neighbors_b == ["node-A", "node-C"]


def test_parse_xml_with_admin_groups(sample_ted_xml):
    """Admin Groups are parsed correctly per link."""
    parsed = parse_xml(str(sample_ted_xml))
    db = gather_node_data(parsed)
    a_to_b = next(r for r in db["node-A"] if r["Neighbor"] == "node-B")
    assert a_to_b["Admin Groups"] == ["plane1"]
    b_to_c = next(r for r in db["node-B"] if r["Neighbor"] == "node-C")
    assert b_to_c["Admin Groups"] == ["plane2"]


def test_parse_xml_bandwidth_strings(sample_ted_xml):
    """Bandwidth strings like '400Gbps' parse to bps integers (regression for 8fc69da)."""
    parsed = parse_xml(str(sample_ted_xml))
    db = gather_node_data(parsed)
    a_to_b = next(r for r in db["node-A"] if r["Neighbor"] == "node-B")
    assert a_to_b["Static Bandwidth"] == 400_000_000_000
    assert a_to_b["Reservable Bandwidth"] == 400_000_000_000
    b_to_c = next(r for r in db["node-B"] if r["Neighbor"] == "node-C")
    assert b_to_c["Static Bandwidth"] == 100_000_000_000


def test_save_load_json_db_roundtrip(tmp_path):
    """save_json_db + load_json_db roundtrip preserves the dict."""
    src = {"node-X": [{"Neighbor": "node-Y", "IGP Metric": 1, "TE Metric": 10, "Local IP": "1.1.1.1", "Remote IP": "1.1.1.2", "Static Bandwidth": 100, "Reservable Bandwidth": 100, "Admin Groups": []}]}
    target = tmp_path / "out.json"
    save_json_db(str(target), src)
    loaded = load_json_db(str(target))
    assert loaded == src


def test_load_json_db_invalid_format_raises(tmp_path):
    """Loading a JSON file that's not a dict at top level raises FileOperationError."""
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(["not", "a", "dict"]))
    with pytest.raises(FileOperationError):
        load_json_db(str(bad))
