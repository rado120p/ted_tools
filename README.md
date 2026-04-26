# ted-tools

Python library for parsing Junos TED (Traffic Engineering Database) XML and
computing graph paths over the resulting topology.

## What this is

`ted_tools` ingests TED XML pulled from Junos routers via NETCONF, builds an
adjacency-DB JSON representation, and exposes:

- DB diff and merge (`compare_dbs`, `merge_dbs`)
- Path analysis with admin-group + bandwidth constraints (`path_analysis`)
- Shortest-path queries (`shortest_path_and_total`)
- IP-list trace resolution (`trace_path_by_ips_from_db`)
- Live NETCONF fetch (`fetch_ted_link_information`)

Used by [`ted_webapp_ide`](../ted_webapp_ide) as the FastAPI IDE backend.

## Install

```bash
pip install -e .
```

## Quick example

```python
from ted_tools.ted_handler import build_db_from_xml, validate_db_format
from ted_tools.ted_graph import build_graph_from_adjacency, shortest_path_and_total

# XML → adjacency DB JSON
db_path = build_db_from_xml("ted.xml", output_json="ted.json")

# JSON → NetworkX graph → SPF
db = validate_db_format(db_path)
graph = build_graph_from_adjacency(db)
result = shortest_path_and_total(graph, src="A", dst="B", metric_attr="IGP Metric")
print(result.path, result.total)
```

## Tests

```bash
pytest -q
```

## License

MIT.
