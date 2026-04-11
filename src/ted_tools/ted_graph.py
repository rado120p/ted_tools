"""
ted_graph.py — Build and export NetworkX graphs from a TED adjacency database (web-ready)

Web-integration goals:
- No argparse / CLI main
- No sys.exit()
- Functions return values / raise exceptions
- Uses configurable workspace paths via ted_tools.config (EXPORT_DIR)
- Can load adjacency DB from:
    - a .pickle file (created by ted_handler)
    - an in-memory adjacency dict (node -> list of neighbor records)

Adjacency DB schema:
{
  "<NODE>": [
      {
        "Neighbor": "<NEI>",
        "Local IP": "...",
        "Remote IP": "...",
        "TE Metric": "700",
        "IGP Metric": "700",
        "Local Interface": "...",        # optional
        "Remote Interface": "...",       # optional
      },
      ...
  ],
  ...
}
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json
from collections import Counter

import networkx as nx
from pyvis.network import Network

from ted_tools.config import EXPORT_DIR, LAYOUT_DIR
from ted_tools.db_handler import load_json_db, load_pickle_db

NeighborRecord = Dict[str, Any]
AdjacencyDB = Dict[str, List[NeighborRecord]]


# -----------------------------
# Exceptions (web-friendly)
# -----------------------------

class TedGraphError(Exception):
    """Base exception for ted_graph."""


class InvalidAdjacencyDbError(TedGraphError):
    """Raised when adjacency DB schema is invalid."""


# -----------------------------
# Load / Validate
# -----------------------------

def load_adjacency_db(path: str) -> AdjacencyDB:
    db_path = Path(path)
    suffix = db_path.suffix.lower()

    if suffix == ".json":
        data = load_json_db(str(db_path))
        return _ensure_adjacency_db_schema(data)

    if suffix == ".pickle":
        data = load_pickle_db(str(db_path))
        return _ensure_adjacency_db_schema(data)

    raise InvalidAdjacencyDbError("Supported graph DB types are .json and .pickle.")

def load_pickle_adjacency_db(path: str) -> AdjacencyDB:
    return load_adjacency_db(path)

def _ensure_adjacency_db_schema(db: Any) -> AdjacencyDB:
    if not isinstance(db, dict):
        raise InvalidAdjacencyDbError("Expected a dict keyed by node -> list of neighbor dicts.")

    for node_name, neighbor_list in db.items():
        if not isinstance(node_name, str):
            raise InvalidAdjacencyDbError("DB keys must be strings (node names).")
        if not isinstance(neighbor_list, list):
            raise InvalidAdjacencyDbError("DB values must be lists (neighbor records).")
        for neighbor_record in neighbor_list:
            if not isinstance(neighbor_record, dict):
                raise InvalidAdjacencyDbError("Each neighbor record must be a dict.")
    return db  # type: ignore[return-value]


# -----------------------------
# Build helpers
# -----------------------------

def _to_int(value: Any, default: int = 1) -> int:
    try:
        return int(float(str(value)))
    except Exception:
        return default

def _format_metric(value: Any) -> str:
    try:
        return str(int(value))
    except Exception:
        return str(value) if value is not None else "—"

def make_edge_label(edge_attributes: Dict[str, Any]) -> str:
    """Build a compact edge label showing IGP/TE metrics."""
    igp = _format_metric(edge_attributes.get("IGP Metric"))
    te = _format_metric(edge_attributes.get("TE Metric"))
    return f"IGP: {igp} | TE: {te}"


def build_graph_from_adjacency(
    adjacency_db: Union[AdjacencyDB, Dict[str, list]],
    *,
    directed: bool = False,      # visualization hint only — does not affect graph structure
    prefer_metric: str = "IGP Metric",  # kept for call-site compatibility
) -> nx.MultiDiGraph:
    """
    Build a directed NetworkX multigraph from an adjacency-style TED DB.

    MultiDiGraph is used so that parallel links between the same node pair are
    preserved as distinct edges (each with their own metrics and interface IPs).
    Each edge A→B carries the metrics as advertised by node A, preserving
    asymmetric metric values.

    ``directed`` only controls whether PyVis renders arrows; it no longer
    changes the graph type.
    """
    db = _ensure_adjacency_db_schema(adjacency_db)

    graph = nx.MultiDiGraph()

    for node_name in db.keys():
        graph.add_node(node_name, label=node_name)

    for node_name, neighbor_list in db.items():
        if not isinstance(neighbor_list, list):
            continue

        for neighbor_record in neighbor_list:
            neighbor_name = neighbor_record.get("Neighbor")
            if not neighbor_name:
                continue

            igp_metric = _to_int(neighbor_record.get("IGP Metric"), 1.0)
            te_metric  = _to_int(neighbor_record.get("TE Metric"),  1.0)

            edge_attributes = {
                "local_ip":   neighbor_record.get("Local IP"),
                "remote_ip":  neighbor_record.get("Remote IP"),
                "IGP Metric": igp_metric,
                "TE Metric":  te_metric,
                "local_ifl":  neighbor_record.get("Local Interface"),
                "remote_ifl": neighbor_record.get("Remote Interface"),
            }

            graph.add_node(neighbor_name, label=neighbor_name)
            label = make_edge_label(edge_attributes)
            graph.add_edge(node_name, neighbor_name, label=label, **edge_attributes)

    return graph


def gexf_sanitize_graph(graph: nx.Graph) -> None:
    """
    NetworkX GEXF cannot serialize attributes with None; remove them.
    """
    # Graph attributes
    for key in list(graph.graph.keys()):
        if graph.graph[key] is None:
            del graph.graph[key]

    # Node attributes
    for _, node_attrs in graph.nodes(data=True):
        for key in list(node_attrs.keys()):
            if node_attrs[key] is None:
                del node_attrs[key]

    # Edge attributes
    for _, _, edge_attrs in graph.edges(data=True):
        for key in list(edge_attrs.keys()):
            if edge_attrs[key] is None:
                del edge_attrs[key]


def build_path_subgraph(
    graph: nx.Graph,
    path: list[str],
) -> nx.Graph:
    """
    Build a subgraph containing only the nodes and hop-to-hop edges in a path,
    with source/destination/path highlighting metadata.
    """
    subgraph = nx.MultiDiGraph()

    if not path:
        return subgraph

    source_node = path[0]
    destination_node = path[-1]

    for node in path:
        if node not in graph:
            continue

        node_attrs = dict(graph.nodes[node])

        if node == source_node:
            node_attrs["path_role"] = "source"
            node_attrs["color"] = "#16a34a"
            node_attrs["size"] = 28
        elif node == destination_node:
            node_attrs["path_role"] = "destination"
            node_attrs["color"] = "#dc2626"
            node_attrs["size"] = 28
        else:
            node_attrs["path_role"] = "transit"
            node_attrs["color"] = "#2563eb"
            node_attrs["size"] = 22

        subgraph.add_node(node, **node_attrs)

    for node_a, node_b in zip(path[:-1], path[1:]):
        for a, b in ((node_a, node_b), (node_b, node_a)):  # color both directions for vis.js undirected mode
            if not graph.has_edge(a, b):
                continue
            for edge_data in graph[a][b].values():
                attrs = dict(edge_data)
                attrs["color"] = "#f59e0b"
                attrs["width"] = 4
                attrs["path_edge"] = True
                subgraph.add_edge(a, b, **attrs)

    return subgraph

# -----------------------------
# Shortest path
# -----------------------------

@dataclass(frozen=True)
class ShortestPathResult:
    path: List[str]
    total: int


@dataclass(frozen=True)
class PathAnalysisResult:
    analysis_type: str
    path: List[str]
    total: int
    hops: int


SOURCE_COLOR = "#7c3aed"   # violet
DEST_COLOR   = "#dc2626"   # red

# One color per analysis type — also used as the path-card border color in the UI.
ANALYSIS_TYPES: Dict[str, str] = {
    "primary":            "Primary SPF",
    "link_disjoint":      "Link-disjoint backup",
    "node_disjoint":      "Node-disjoint backup",
    "first_link_failure": "First next-hop link failure",
    "first_node_failure": "First next-hop node failure",
}

ANALYSIS_COLORS: Dict[str, str] = {
    "primary":            "#2563eb",  # blue
    "link_disjoint":      "#1AFF1A",  # green
    "node_disjoint":      "#FFC20A",  # orange
    "first_link_failure": "#D35FB7",  # pink
    "first_node_failure": "#FF6B6B",  # coral
}


def path_analysis(
    graph: nx.Graph,
    *,
    src: str,
    dst: str,
    metric_attr: str = "IGP Metric",
    analysis_type: str = "primary",
    exclude_nodes: Optional[List[str]] = None,
    exclude_links: Optional[List[tuple]] = None,
) -> PathAnalysisResult:
    """
    Run one of five path analyses and return the result.

    analysis_type values (see ANALYSIS_TYPES):
      primary            — best SPF path as the IGP computes it
      link_disjoint      — best path after removing all primary-path edges
      node_disjoint      — best path after removing all primary transit nodes
      first_link_failure — best path after removing the first next-hop link (src→first_hop)
      first_node_failure — best path after removing the first next-hop node

    Raises TedGraphError when no path exists or nodes are missing.
    """
    if analysis_type not in ANALYSIS_TYPES:
        raise TedGraphError(f"Unknown analysis type: {analysis_type!r}")

    # Apply user-requested exclusions before any SPF runs.
    graph = _apply_exclusions(graph, exclude_nodes, exclude_links)

    def _spf(g: nx.Graph) -> tuple:
        try:
            p = nx.shortest_path(g, src, dst, weight=metric_attr)
            t = sum(
                min(_to_int(data.get(metric_attr), 1) for data in g[u][v].values())
                for u, v in zip(p[:-1], p[1:])
            )
            return p, t
        except (nx.NetworkXNoPath, nx.NodeNotFound) as exc:
            raise TedGraphError(str(exc)) from exc

    if analysis_type == "primary":
        path, total = _spf(graph)
        return PathAnalysisResult(analysis_type=analysis_type, path=path, total=total, hops=len(path) - 1)

    # All non-primary types require the primary path first.
    primary_path, _ = _spf(graph)

    if analysis_type == "link_disjoint":
        g2 = graph.copy()
        for u, v in zip(primary_path[:-1], primary_path[1:]):
            if g2.has_edge(u, v):
                g2.remove_edge(u, v)

    elif analysis_type == "node_disjoint":
        g2 = graph.copy()
        for node in primary_path[1:-1]:
            if node in g2:
                g2.remove_node(node)

    elif analysis_type == "first_link_failure":
        if len(primary_path) < 2:
            raise TedGraphError("Primary path has no links to remove.")
        g2 = graph.copy()
        g2.remove_edge(primary_path[0], primary_path[1])

    elif analysis_type == "first_node_failure":
        if len(primary_path) < 3:
            raise TedGraphError(
                "Source is directly connected to destination — no intermediate node to remove."
            )
        g2 = graph.copy()
        g2.remove_node(primary_path[1])

    path, total = _spf(g2)
    return PathAnalysisResult(analysis_type=analysis_type, path=path, total=total, hops=len(path) - 1)


def build_path_overlay_graph(
    base_graph: nx.Graph,
    path: List[str],
    *,
    path_color: str,
) -> nx.Graph:
    """
    Copy the full topology and highlight the given path in path_color.
    Source = SOURCE_COLOR, destination = DEST_COLOR, transit nodes and edges = path_color.
    """
    graph = base_graph.copy()

    if not path:
        return graph

    src = path[0]
    dst = path[-1]

    for node in path:
        if node not in graph:
            continue
        if node == src:
            graph.nodes[node]["color"] = SOURCE_COLOR
            graph.nodes[node]["size"] = 28
        elif node == dst:
            graph.nodes[node]["color"] = DEST_COLOR
            graph.nodes[node]["size"] = 28
        else:
            graph.nodes[node]["color"] = path_color
            graph.nodes[node]["size"] = 22

    for u, v in zip(path[:-1], path[1:]):
        for a, b in ((u, v), (v, u)):  # color both directions so vis.js shows it regardless of arrow mode
            if graph.has_edge(a, b):
                for edge_data in graph[a][b].values():
                    edge_data["color"] = path_color
                    edge_data["width"] = 4

    return graph


def path_hop_details(
    graph: nx.Graph,
    path: List[str],
    metric_attr: str = "IGP Metric",
) -> List[dict]:
    """
    Return per-hop detail dicts for a computed path, matching the trace-path format:
      ingress_node, neighbor, te_metric, igp_metric, neighbor_ip (remote_ip of edge).
    Picks the lowest-metric parallel edge for each hop, consistent with SPF.
    """
    hops = []
    for u, v in zip(path[:-1], path[1:]):
        if graph.has_edge(u, v):
            best = min(
                graph[u][v].values(),
                key=lambda d: _to_int(d.get(metric_attr), 1),
            )
            hops.append({
                "ingress_node": u,
                "neighbor":     v,
                "te_metric":    _to_int(best.get("TE Metric"), 0),
                "igp_metric":   _to_int(best.get("IGP Metric"), 0),
                "neighbor_ip":  best.get("remote_ip") or "—",
            })
        else:
            hops.append({
                "ingress_node": u,
                "neighbor":     v,
                "te_metric":    None,
                "igp_metric":   None,
                "neighbor_ip":  "—",
            })
    return hops


def _apply_exclusions(
    graph: nx.Graph,
    exclude_nodes: Optional[List[str]] = None,
    exclude_links: Optional[List[tuple]] = None,
) -> nx.Graph:
    """Return a copy of *graph* with specified nodes and/or links removed."""
    g = graph.copy()
    for node in (exclude_nodes or []):
        if node in g:
            g.remove_node(node)
    for a, b in (exclude_links or []):
        for u, v in ((a, b), (b, a)):
            if g.has_edge(u, v):
                # Remove all parallel edges between u→v
                keys = list(g[u][v].keys())
                for k in keys:
                    g.remove_edge(u, v, key=k)
    return g


def shortest_path_and_total(
    graph: nx.Graph,
    *,
    src: str,
    dst: str,
    metric_attr: str = "IGP Metric",
    exclude_nodes: Optional[List[str]] = None,
    exclude_links: Optional[List[tuple]] = None,
) -> ShortestPathResult:
    """
    Compute weighted shortest path and total weight.
    Optionally exclude specific nodes or links from the calculation.
    """
    g = _apply_exclusions(graph, exclude_nodes, exclude_links)
    try:
        path = nx.shortest_path(g, src, dst, weight=metric_attr)
    except (nx.NetworkXNoPath, nx.NodeNotFound) as exc:
        raise TedGraphError(str(exc)) from exc
    total = sum(
        min(_to_int(data.get(metric_attr), 1) for data in g[u][v].values())
        for u, v in zip(path[:-1], path[1:])
    )
    return ShortestPathResult(path=path, total=total)


# -----------------------------
# Export (web-friendly defaults)
# -----------------------------

def export_graph(
    graph: nx.Graph,
    *,
    graphml_path: Optional[str] = None,
    gexf_path: Optional[str] = None,
) -> None:
    """
    Export to GraphML and/or GEXF at explicit paths.
    """
    if graphml_path or gexf_path:
        gexf_sanitize_graph(graph)

    if graphml_path:
        nx.write_graphml(graph, graphml_path)

    if gexf_path:
        nx.write_gexf(graph, gexf_path)


from datetime import datetime

def export_graph_to_workspace(
    graph: nx.Graph,
    *,
    base_name: str = "ted_graph",
    write_graphml: bool = True,
    write_gexf: bool = True,
    output_dir: Path = EXPORT_DIR,
) -> Dict[str, str]:
    """
    Convenience helper for the web app:
    - writes exports to EXPORT_DIR (or provided output_dir)
    - returns dict of produced file paths
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    produced: Dict[str, str] = {}

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_base_name = base_name.replace(" ", "_")

    if write_graphml or write_gexf:
        gexf_sanitize_graph(graph)

    if write_graphml:
        graphml = output_dir / f"{safe_base_name}_{stamp}.graphml"
        nx.write_graphml(graph, str(graphml))
        produced["graphml"] = str(graphml)

    if write_gexf:
        gexf = output_dir / f"{safe_base_name}_{stamp}.gexf"
        nx.write_gexf(graph, str(gexf))
        produced["gexf"] = str(gexf)

    return produced

def export_graph_to_html(
    graph: nx.Graph,
    *,
    output_html: Optional[str] = None,
    output_dir: Path = EXPORT_DIR,
    base_name: str = "ted_graph",
    height: str = "95vh",
    width: str = "100vw",
    directed: bool = False,
    node_positions: Optional[dict] = None
) -> str:
    """
    Export a NetworkX graph as an interactive HTML visualization using PyVis.
    Returns the HTML file path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if output_html:
        html_path = Path(output_html)
    else:
        html_path = output_dir / f"{base_name}.html"

    net = Network(
        height=height,
        width=width,
        directed=directed,
        notebook=False,
        cdn_resources="in_line",
    )

    for node_name, node_attrs in graph.nodes(data=True):
        kwargs = {
            "label": str(node_name),
            "title": str(node_name),
            "size": node_attrs.get("size", 18),
        }

        if "color" in node_attrs:
            kwargs["color"] = node_attrs["color"]

        if node_positions and node_name in node_positions:
            kwargs["x"] = node_positions[node_name]["x"]
            kwargs["y"] = node_positions[node_name]["y"]
            kwargs["physics"] = False

        net.add_node(node_name, **kwargs)

    # For undirected rendering, only process the canonical direction (a <= b)
    # to avoid doubling up A→B and B→A from the MultiDiGraph.
    canonical_edges = [
        (src, tgt, attrs)
        for src, tgt, attrs in graph.edges(data=True)
        if src <= tgt
    ]
    edge_counts: Counter = Counter((src, tgt) for src, tgt, _ in canonical_edges)
    edge_pair_index: Counter = Counter()

    for edge_id, (source, target, edge_attrs) in enumerate(canonical_edges):
        title = "<br>".join([
            f"IGP: {edge_attrs.get('IGP Metric', '')}",
            f"TE: {edge_attrs.get('TE Metric', '')}",
        ])

        edge_dict: dict = {
            "id": edge_id,
            "from": source,
            "to": target,
            "label": "",
            "title": title,
        }

        if "color" in edge_attrs:
            edge_dict["color"] = edge_attrs["color"]

        if "width" in edge_attrs:
            edge_dict["width"] = edge_attrs["width"]

        pair = (source, target)
        if edge_counts[pair] > 1:
            idx = edge_pair_index[pair]
            edge_pair_index[pair] += 1
            smooth_type = "curvedCW" if idx % 2 == 0 else "curvedCCW"
            edge_dict["smooth"] = {"enabled": True, "type": smooth_type, "roundness": 0.3}

        # Append directly to bypass PyVis's undirected dedup check
        net.edges.append(edge_dict)
        
    if node_positions:
        net.set_options("""
        var options = {
        "physics": {
            "enabled": false
        },
        "interaction": {
            "hover": true,
            "navigationButtons": true,
            "keyboard": true,
            "dragNodes": true,
            "dragView": true,
            "zoomView": true
        },
        "edges": {
            "smooth": false,
            "color": {
            "inherit": false
            },
            "font": {
            "size": 10
            }
        },
        "nodes": {
            "font": {
            "size": 14
            }
        }
        }
        """)
    else:
        net.set_options("""
        var options = {
        "physics": {
            "enabled": true,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
            "gravitationalConstant": -80,
            "centralGravity": 0.01,
            "springLength": 180,
            "springConstant": 0.08
            },
            "stabilization": {
            "enabled": true,
            "iterations": 500,
            "updateInterval": 25
            }
        },
        "interaction": {
            "hover": true,
            "navigationButtons": true,
            "keyboard": true,
            "dragNodes": true,
            "dragView": true,
            "zoomView": true
        },
        "edges": {
            "smooth": false,
            "color": {
            "inherit": false
            },
            "font": {
            "size": 10
            }
        },
        "nodes": {
            "font": {
            "size": 14
            }
        }
        }
        """)

    net.write_html(str(html_path))

    html = html_path.read_text()
    html = html.replace(
        "network = new vis.Network(container, data, options);",
        """network = new vis.Network(container, data, options);
network.once("stabilizationIterationsDone", function () {
    network.setOptions({ physics: false });
});"""
    )
    html_path.write_text(html)

    return str(html_path)


def save_graph_layout(layout_name: str, positions: dict) -> str:
    path = LAYOUT_DIR / f"{layout_name}.json"
    with open(path, "w") as f:
        json.dump(positions, f, indent=2)
    return str(path)


def load_graph_layout(layout_name: str) -> dict:
    path = LAYOUT_DIR / f"{layout_name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Layout '{layout_name}' does not exist.")
    with open(path, "r") as f:
        return json.load(f)


def list_graph_layouts() -> list[str]:
    return [p.stem for p in LAYOUT_DIR.glob("*.json")]