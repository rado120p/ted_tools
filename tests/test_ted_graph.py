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


def _ecmp_diamond_graph():
    """A→B→D and A→C→D, both cost 2 (one hop of metric 1 + one hop of metric 1).
    Two equal-cost paths from A to D."""
    g = nx.MultiDiGraph()
    for n in ("A", "B", "C", "D"):
        g.add_node(n)
    for u, v in [("A", "B"), ("B", "D"), ("A", "C"), ("C", "D")]:
        g.add_edge(u, v, **{"IGP Metric": 1, "TE Metric": 1, "Remote IP": f"10.{ord(u)}.{ord(v)}.0",
                            "Admin Groups": [], "Static Bandwidth": 100, "Reservable Bandwidth": 100})
    return g


def test_path_analysis_primary_detects_ecmp():
    """Primary SPF returns chosen path + the alternate equal-cost path in ecmp_paths."""
    g = _ecmp_diamond_graph()
    res = path_analysis(g, src="A", dst="D", analysis_type="primary")
    assert res.path[0] == "A" and res.path[-1] == "D"
    assert len(res.ecmp_paths) == 1  # one alternative besides the chosen
    alt = res.ecmp_paths[0]
    assert alt[0] == "A" and alt[-1] == "D"
    # The alternative is the OTHER equal-cost path
    all_paths_set = {tuple(res.path), alt}
    assert all_paths_set == {("A", "B", "D"), ("A", "C", "D")}


def test_path_analysis_no_ecmp_when_unique_path():
    """When only one shortest path exists, ecmp_paths is empty."""
    g = nx.MultiDiGraph()
    for n in ("A", "B", "C"):
        g.add_node(n)
    g.add_edge("A", "B", **{"IGP Metric": 1})
    g.add_edge("B", "C", **{"IGP Metric": 1})
    res = path_analysis(g, src="A", dst="C", analysis_type="primary")
    assert res.path == ["A", "B", "C"]
    assert res.ecmp_paths == ()


def test_path_analysis_backup_omits_ecmp():
    """ECMP detection is primary-only; backup analysis types leave it empty."""
    g = _ecmp_diamond_graph()
    res = path_analysis(g, src="A", dst="D", analysis_type="link_disjoint")
    assert res.ecmp_paths == ()


def test_build_graph_propagates_sim_tags():
    g = nx.MultiDiGraph()
    db = {
        "A": [{"Neighbor": "B", "IGP Metric": 1, "TE Metric": 1,
               "Local IP": "10.0.0.1", "Remote IP": "10.0.0.2",
               "Admin Groups": [], "Sim Tags": ["plane3-link"]}],
        "B": [{"Neighbor": "A", "IGP Metric": 1, "TE Metric": 1,
               "Local IP": "10.0.0.2", "Remote IP": "10.0.0.1",
               "Admin Groups": []}],
    }
    g = build_graph_from_adjacency(db)
    ab_data = list(g["A"]["B"].values())[0]
    assert ab_data.get("Sim Tags") == ["plane3-link"]
    ba_data = list(g["B"]["A"].values())[0]
    assert ba_data.get("Sim Tags", []) == []


def _two_node_with_sim_link():
    g = nx.MultiDiGraph()
    g.add_node("A"); g.add_node("B")
    # untagged baseline edge
    g.add_edge("A", "B", **{"IGP Metric": 10, "TE Metric": 10, "Remote IP": "10.0.0.1",
                            "Admin Groups": [], "Sim Tags": []})
    g.add_edge("B", "A", **{"IGP Metric": 10, "TE Metric": 10, "Remote IP": "10.0.0.2",
                            "Admin Groups": [], "Sim Tags": []})
    # cheap sim-tagged edge — only present when "plane3-link" is active
    g.add_edge("A", "B", **{"IGP Metric": 1, "TE Metric": 1, "Remote IP": "10.0.0.3",
                            "Admin Groups": [], "Sim Tags": ["plane3-link"]})
    g.add_edge("B", "A", **{"IGP Metric": 1, "TE Metric": 1, "Remote IP": "10.0.0.4",
                            "Admin Groups": [], "Sim Tags": ["plane3-link"]})
    return g


def test_path_analysis_keeps_sim_tagged_link_by_default():
    g = _two_node_with_sim_link()
    res = path_analysis(g, src="A", dst="B", analysis_type="primary",
                        exclude_sim_tags=None)
    assert res.path == ["A", "B"]
    assert res.total == 1  # cheap sim-tagged edge wins (no exclusion)


def test_path_analysis_drops_sim_tagged_link_when_excluded():
    g = _two_node_with_sim_link()
    res = path_analysis(g, src="A", dst="B", analysis_type="primary",
                        exclude_sim_tags=["plane3-link"])
    assert res.path == ["A", "B"]
    assert res.total == 10  # baseline edge survives, sim edge dropped


def test_path_analysis_untagged_link_unaffected_by_sim_tags():
    g = nx.MultiDiGraph()
    g.add_node("A"); g.add_node("B")
    g.add_edge("A", "B", **{"IGP Metric": 5, "Admin Groups": [], "Sim Tags": []})
    g.add_edge("B", "A", **{"IGP Metric": 5, "Admin Groups": [], "Sim Tags": []})
    # exclude_sim_tags has no effect on untagged links
    res = path_analysis(g, src="A", dst="B", analysis_type="primary",
                        exclude_sim_tags=["irrelevant"])
    assert res.total == 5
