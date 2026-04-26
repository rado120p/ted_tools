"""Tests for ted_tools.ted_graph — graph build + path analysis."""
import pytest

from ted_tools.ted_graph import (
    TedGraphError,
    build_graph_from_adjacency,
    path_analysis,
    shortest_path_and_total,
)
from ted_tools.ted_handler import validate_db_format


def _load_graph(path):
    db = validate_db_format(str(path))
    return build_graph_from_adjacency(db)


def test_build_graph_from_db(sample_db_json):
    g = _load_graph(sample_db_json)
    assert sorted(g.nodes()) == ["node-A", "node-B", "node-C"]
    # Bidirectional A↔B (2 directed edges) + B↔C (2) = 4 edges total
    assert g.number_of_edges() == 4


def test_shortest_path_igp_metric(sample_db_json):
    g = _load_graph(sample_db_json)
    res = shortest_path_and_total(g, src="node-A", dst="node-C", metric_attr="IGP Metric")
    assert res.path == ["node-A", "node-B", "node-C"]
    assert res.total == 15000  # 10000 (A→B) + 5000 (B→C)


def test_shortest_path_te_metric(sample_db_json):
    g = _load_graph(sample_db_json)
    res = shortest_path_and_total(g, src="node-A", dst="node-C", metric_attr="TE Metric")
    assert res.path == ["node-A", "node-B", "node-C"]
    assert res.total == 150000  # 100000 + 50000


def test_shortest_path_no_route_raises(sample_db_json):
    g = _load_graph(sample_db_json)
    with pytest.raises(TedGraphError):
        shortest_path_and_total(g, src="node-A", dst="node-NONEXISTENT")


def test_path_analysis_primary(sample_db_json):
    g = _load_graph(sample_db_json)
    res = path_analysis(g, src="node-A", dst="node-C", analysis_type="primary")
    assert res.path == ["node-A", "node-B", "node-C"]


def test_path_analysis_admin_group_exclude(sample_db_json):
    """Excluding plane2 removes the B→C link, no path from A to C remains."""
    g = _load_graph(sample_db_json)
    with pytest.raises(TedGraphError):
        path_analysis(g, src="node-A", dst="node-C", analysis_type="primary", exclude_groups=["plane2"])


def test_path_analysis_admin_group_include_any(sample_db_json):
    """Including only plane1 limits path to A↔B; A→C unreachable via plane1 only."""
    g = _load_graph(sample_db_json)
    with pytest.raises(TedGraphError):
        path_analysis(g, src="node-A", dst="node-C", analysis_type="primary", include_groups=["plane1"], include_type="include-any")


def test_path_analysis_min_reservable_bw_prunes(sample_db_json):
    """B↔C is 100Gbps; setting min above that prunes those links → no A→C path."""
    g = _load_graph(sample_db_json)
    with pytest.raises(TedGraphError):
        path_analysis(g, src="node-A", dst="node-C", analysis_type="primary", min_reservable_bw=200_000_000_000)
