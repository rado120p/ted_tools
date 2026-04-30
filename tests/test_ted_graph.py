"""Tests for ted_tools.ted_graph — graph build + path analysis."""
import networkx as nx
import pytest

from ted_tools.ted_graph import (
    TedGraphError,
    build_graph_from_adjacency,
    path_analysis,
    path_hop_details,
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


def _two_hop_with_parallels():
    """Build A→B→C where A↔B has 3 parallel edges (two tied at IGP 500, one at 800)."""
    g = nx.MultiDiGraph()
    for n in ("A", "B", "C"):
        g.add_node(n)
    g.add_edge("A", "B", **{"IGP Metric": 500, "TE Metric": 5000, "Remote IP": "10.0.0.1",
                            "Admin Groups": ["core"], "Static Bandwidth": 100, "Reservable Bandwidth": 100})
    g.add_edge("A", "B", **{"IGP Metric": 500, "TE Metric": 5000, "Remote IP": "10.0.0.2",
                            "Admin Groups": ["core"], "Static Bandwidth": 100, "Reservable Bandwidth": 100})
    g.add_edge("A", "B", **{"IGP Metric": 800, "TE Metric": 8000, "Remote IP": "10.0.0.3",
                            "Admin Groups": ["core"], "Static Bandwidth": 100, "Reservable Bandwidth": 100})
    g.add_edge("B", "C", **{"IGP Metric": 1000, "TE Metric": 10000, "Remote IP": "10.0.0.4",
                            "Admin Groups": ["plane2"], "Static Bandwidth": 100, "Reservable Bandwidth": 100})
    return g


def test_path_hop_details_emits_tied_parallel_edges():
    """Hop with two tied-min parallel edges emits both; higher-metric one is excluded."""
    g = _two_hop_with_parallels()
    hops = path_hop_details(g, ["A", "B", "C"], metric_attr="IGP Metric")
    assert len(hops) == 2
    assert len(hops[0]["edges"]) == 2  # two tied at 500, the 800 one is dropped
    ips = sorted(e["neighbor_ip"] for e in hops[0]["edges"])
    assert ips == ["10.0.0.1", "10.0.0.2"]
    assert all(e["igp_metric"] == 500 for e in hops[0]["edges"])
    assert len(hops[1]["edges"]) == 1
    assert hops[1]["edges"][0]["neighbor_ip"] == "10.0.0.4"


def test_path_hop_details_single_edge_per_hop_when_no_parallels(sample_db_json):
    """No parallel edges in sample_db; each hop has exactly one edge entry."""
    g = _load_graph(sample_db_json)
    hops = path_hop_details(g, ["node-A", "node-B", "node-C"], metric_attr="IGP Metric")
    assert [len(h["edges"]) for h in hops] == [1, 1]
    assert hops[0]["edges"][0]["igp_metric"] == 10000
    assert hops[1]["edges"][0]["igp_metric"] == 5000
