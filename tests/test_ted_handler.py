"""Tests for ted_tools.ted_handler — DB loading, diff/merge, trace path."""
import pytest

from ted_tools.ted_handler import (
    UnsupportedDbFormatError,
    compare_dbs,
    merge_dbs,
    trace_path_by_ips_from_db,
    validate_db_format,
)


def test_validate_db_format_accepts_json(sample_db_json):
    db = validate_db_format(str(sample_db_json))
    assert isinstance(db, dict)
    assert "node-A" in db


def test_validate_db_format_rejects_pickle(tmp_path):
    """Regression for SEC-001: .pickle is no longer a supported suffix."""
    fake = tmp_path / "fake.pickle"
    fake.write_text("anything")
    with pytest.raises(UnsupportedDbFormatError):
        validate_db_format(str(fake))


def test_validate_db_format_rejects_other_suffix(tmp_path):
    fake = tmp_path / "fake.txt"
    fake.write_text("anything")
    with pytest.raises(UnsupportedDbFormatError):
        validate_db_format(str(fake))


def test_compare_dbs_no_diff(sample_db_json):
    diff = compare_dbs(str(sample_db_json), str(sample_db_json))
    # Identical DBs → no changes anywhere
    assert all(
        not (entry.added or entry.removed or entry.changed)
        for entry in diff.values()
    ) or len(diff) == 0


def test_compare_dbs_added_link(sample_db_json, sample_db_v2_json):
    """v2 adds node-A→node-C; diff should surface that as 'added' under node-A."""
    diff = compare_dbs(str(sample_db_json), str(sample_db_v2_json))
    assert "node-A" in diff
    added_neighbors = [r.get("Neighbor") for r in diff["node-A"].added]
    assert "node-C" in added_neighbors


def test_compare_dbs_changed_metric(sample_db_json, sample_db_v2_json):
    """v2 changes the IGP metric on node-A→node-B from 10000 to 12000."""
    diff = compare_dbs(str(sample_db_json), str(sample_db_v2_json))
    changed = diff["node-A"].changed
    assert any(c.record_old.get("IGP Metric") == 10000 and c.record_new.get("IGP Metric") == 12000 for c in changed)


def test_merge_dbs_no_changes(sample_db_json, tmp_path):
    """Merging a DB with itself + no accepted changes → output equals source."""
    out = tmp_path / "merged.json"
    result_path = merge_dbs(str(sample_db_json), str(sample_db_json), accepted_changes=[], output_json=str(out))
    a = validate_db_format(str(sample_db_json))
    b = validate_db_format(str(result_path))
    assert a == b


def test_trace_path_by_ips_resolves(sample_db_json):
    """Feeding a known Remote IP from the fixture resolves to the expected ingress node."""
    # node-B has Remote IP 10.0.0.1 (back to node-A) — trace input is the remote-side IP
    hops = trace_path_by_ips_from_db(str(sample_db_json), ["10.0.0.1"])
    assert len(hops) == 1
    assert hops[0].found is True
    assert hops[0].ingress_node == "node-B"


def test_trace_path_by_ips_unknown_hop(sample_db_json):
    """A bogus IP yields a hop with found=False."""
    hops = trace_path_by_ips_from_db(str(sample_db_json), ["1.2.3.4"])
    assert len(hops) == 1
    assert hops[0].found is False
