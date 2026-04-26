# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (editable)
pip install -e .
pip install -e ".[dev]"   # includes pytest, ruff, mypy

# Lint
ruff check src/

# Type check
mypy src/

# Tests (smoke/import only — no live devices needed)
pytest
pytest tests/test_smoke_imports.py  # run single file
```

## Architecture

**TED Tools** is a Python library (no CLI) for fetching, parsing, and analyzing Juniper Traffic Engineering Database (TED) adjacency data from network devices via NETCONF/PyEZ.

### Module responsibilities

| Module | Role |
|--------|------|
| `config.py` | Workspace path setup via `TED_BASE_DIR` env var; creates `xml/`, `db/`, `exports/`, `layouts/` dirs |
| `exception_handler.py` | Decorator-based wrapping of PyEZ/Netmiko exceptions into typed app exceptions |
| `db_handler.py` | Low-level file I/O: XML parsing (`jxmlease`), JSON serialization |
| `get_ted.py` | NETCONF device connection; fetches TED RPC; parallel node verification via `ThreadPoolExecutor` |
| `ted_handler.py` | Parses TED XML into an adjacency DB (`{node: [neighbor_records]}`); CRUD operations on nodes/links; serializes to JSON |
| `ted_graph.py` | Builds `nx.MultiDiGraph` from adjacency DB; path analysis (primary, link-disjoint, node-disjoint, failure scenarios); PyVis HTML export |

### Data flow

```
Device (NETCONF/RPC)
  → get_ted.py          → XML files (workspace/xml/)
  → ted_handler.py      → adjacency DB (workspace/db/, JSON)
  → ted_graph.py        → graph analysis + HTML export (workspace/exports/)
```

### Key design decisions

- **Pure library API**: no `argparse`, `input()`, `getpass()`, or `sys.exit()`. All functions return typed dataclasses or raise typed exceptions — suitable for web backend integration.
- **`nx.MultiDiGraph`**: preserves parallel links and asymmetric TE/IGP metrics between the same node pair.
- **Adjacency DB format**: `dict[str, list[dict]]` — JSON-serializable, human-readable.
- **Node name normalization**: Junos names like `r1.0` are stripped to `r1` (optionally uppercased).
- **Admin groups**: asymmetric per-direction per-edge; used as path constraints in `path_analysis()`.
- **Device verification**: compares IS-IS config snapshots (not live TED) to distinguish transient vs. confirmed topology changes.

### Path analysis types

`ted_graph.path_analysis(graph, src, dst, analysis_type)` supports:
- `"primary"` — standard shortest path
- `"link_disjoint"` — backup avoiding shared links
- `"node_disjoint"` — backup avoiding shared nodes
- `"first_link_failure"` — path after primary's first link fails
- `"first_node_failure"` — path after primary's first node fails

Optional BW constraint: `min_reservable_bw` (bps int) prunes edges before SPF — every hop must have sufficient reservable bandwidth.

### DB diff / merge

`ted_handler.compare_dbs()` detects added/removed/changed links. `_DIFF_EXCLUDE` in `ted_handler` lists fields excluded from change detection (currently `Reservable Bandwidth` — dynamic, not config-driven).

`merge_dbs()` accepts change IDs in `TYPE|NODE|NEIGHBOR|LOCAL_IP` format.

### Device verification (`get_ted.py`)

`verify_changed_nodes()` fetches IS-IS config + interface IPs + RSVP bandwidth via NETCONF and compares against two DB snapshots to classify changes as transient vs. confirmed. All three config fetches (`_fetch_isis_config_metrics`, `_fetch_interface_ips`, `_fetch_rsvp_bandwidth`) use lxml XML parsing for consistency.

## Tests

Run from the repo root:

```bash
pytest -q
```

Tests cover XML→DB parsing, DB diff/merge, graph algorithms, and security regressions (SEC-001 unused-serialisation removal, SEC-002 XXE hardening). No live NETCONF — `get_ted.py` network code is exercised only at the parser-output level via fixture XML in `tests/fixtures/`.

Fixtures: `tests/fixtures/sample_ted.xml` (3-node hand-crafted Junos TED) + `tests/fixtures/sample_db.json` and `sample_db_v2.json` (corresponding adjacency-DB JSONs for diff/merge tests).
