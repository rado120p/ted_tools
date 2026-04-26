"""
ted_handler.py — TED-Link adjacency DB builder/maintainer (web-ready, clearer naming)

Web-integration goals:
- No interactive input()
- No sys.exit() in core logic
- Uses configurable workspace paths via ted_tools.config (DB_DIR, EXPORT_DIR)
- Functions return values / raise exceptions (so web layer can handle errors)

Adjacency DB schema:
{
  "NODEA": [
    {
      "Neighbor": "NODEB",
      "Local IP": "x.x.x.x",
      "Remote IP": "y.y.y.y",
      "TE Metric": 700,
      "IGP Metric": 700,
      "Admin Groups": ["core", "plane1"],   # 0 or more; per-direction (asymmetric allowed)
      "Static Bandwidth": 1000000000,       # bps; per-direction (asymmetric allowed); None if absent
      "Reservable Bandwidth": 800000000,    # bps; per-direction (asymmetric allowed); None if absent
      "Local Interface": "...",
      "Remote Interface": "...",
      "Description": "..."
    },
    ...
  ],
  ...
}
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ted_tools.config import DB_DIR, EXPORT_DIR
from ted_tools.db_handler import (
    csv_to_list,
    load_json_db,
    parse_xml,
    save_json_db,
    validate_key,
)

NeighborRecord = Dict[str, Any]
AdjacencyDB = Dict[str, List[NeighborRecord]]


# -----------------------------
# Exceptions (web-friendly)
# -----------------------------

class TedHandlerError(Exception):
    """Base exception for ted_handler."""


class EmptyTedDataError(TedHandlerError):
    """Raised when parsed TED XML contains no ted-link entries."""


class UnsupportedDbFormatError(TedHandlerError):
    """Raised when a DB path is not .xml or .json."""


class NodeNotFoundError(TedHandlerError):
    """Raised when requested node is not in DB."""


class DuplicateLinkError(TedHandlerError):
    """Raised when attempting to add a duplicate link without overwrite."""


class InvalidActionError(TedHandlerError):
    """Raised when an invalid action is provided."""


# -----------------------------
# Small helpers
# -----------------------------

def _normalize_node_name(node_name: Optional[str], *, to_upper: bool = False) -> Optional[str]:
    """
    Normalize Junos-style node names like 'r1.0' -> 'r1' (optionally uppercased).
    """
    if not isinstance(node_name, str):
        return None
    normalized = node_name.split(".0")[0]
    return normalized.upper() if to_upper else normalized


def _now_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _default_json_output_path(prefix: str = "ted_dict") -> Path:
    return DB_DIR / f"{prefix}_{_now_timestamp()}.json"

def _default_csv_output_path(prefix: str = "ted_db") -> Path:
    return EXPORT_DIR / f"{prefix}_{_now_timestamp()}.csv"


def _parse_metric(value: Any, default: int = 1) -> int:
    """Convert a raw metric value (str, XMLDictNode, int, float) to int."""
    try:
        return int(float(str(value)))
    except Exception:
        return default


def _parse_optional_int(value: Any) -> Optional[int]:
    """Parse a raw value to int; return None if value is None or unparseable."""
    if value is None:
        return None
    try:
        return int(float(str(value)))
    except Exception:
        return None


def _parse_bandwidth_bps(value: Any) -> Optional[int]:
    """
    Parse a Junos bandwidth value to bps int.
    Handles strings like '400Gbps', '100Mbps', '10Kbps', '1000000000', or raw int.
    Returns None if value is None or unparseable.
    """
    if value is None:
        return None
    s = str(value).strip().lower().replace("bps", "").replace("b/s", "")
    try:
        if s.endswith("g"):
            return int(float(s[:-1]) * 1_000_000_000)
        elif s.endswith("m"):
            return int(float(s[:-1]) * 1_000_000)
        elif s.endswith("k"):
            return int(float(s[:-1]) * 1_000)
        else:
            return int(float(s))
    except (ValueError, TypeError):
        return None


def _is_zero_ipv4(ip_str: Optional[str]) -> bool:
    return ip_str == "0.0.0.0" or ip_str is None


def _extract_admin_groups(link_entry: dict) -> List[str]:
    """
    Extract admin-group-name values from a parsed ted-link entry.

    XML structure (jxmlease-parsed):
      admin-groups:
        admin-group-name: "core"          # string  — single group
        admin-group-name: ["core","x"]    # list    — multiple groups (rare but possible)

    Returns a sorted, deduplicated list of group name strings.
    """
    admin_groups_raw = link_entry.get("admin-groups")
    if not isinstance(admin_groups_raw, dict):
        return []
    names = admin_groups_raw.get("admin-group-name")
    if names is None:
        return []
    if isinstance(names, list):
        return sorted({str(n) for n in names})
    return [str(names)]


def _ensure_adjacency_db_schema(node_db: Any) -> AdjacencyDB:
    """
    Lightweight schema check to catch obvious wrong-types early.
    """
    if not isinstance(node_db, dict):
        raise ValueError("DB is not a dict (expected dict[str, list[dict]]).")

    for node_name, neighbor_list in node_db.items():
        if not isinstance(node_name, str):
            raise ValueError("DB keys must be strings (node names).")
        if not isinstance(neighbor_list, list):
            raise ValueError("DB values must be lists (neighbor records).")
        for neighbor_record in neighbor_list:
            if not isinstance(neighbor_record, dict):
                raise ValueError("Each neighbor record must be a dict.")

    return node_db  # type: ignore[return-value]


def _find_neighbor_record_index(
    node_db: AdjacencyDB,
    *,
    node_name: str,
    neighbor_name: str,
    local_ip: str,
) -> Optional[int]:
    """
    Return the index of the first record matching (Neighbor, Local IP).

    Remote IP is intentionally excluded: jxmlease may return XMLDictNode objects
    that compare unequal to plain strings even with the same value, causing false
    negatives and duplicate record creation.  (Neighbor, Local IP) is sufficient
    to uniquely identify a directed link from node_name's perspective.
    """
    for index, neighbor_record in enumerate(node_db.get(node_name, [])):
        if (
            neighbor_record.get("Neighbor") == neighbor_name
            and str(neighbor_record.get("Local IP", "")) == local_ip
        ):
            return index
    return None


# -----------------------------
# Core: build/parse/validate
# -----------------------------

def gather_node_data(parsed_database: dict, *, normalize_nodes_upper: bool = False) -> AdjacencyDB:
    """
    Extract adjacency/link records from parsed TED XML content (from parse_xml()).

    Raises:
        EmptyTedDataError: if no ted-link entries exist or nothing survives filtering.
        ValueError: if parsed structure is unexpected.
    """
    try:
        ted_info = parsed_database["ted-link-information"]
    except Exception as exc:
        raise ValueError("Parsed database missing 'ted-link-information'.") from exc

    ted_links = ted_info.get("ted-link")
    if not ted_links:
        raise EmptyTedDataError("Parsed database is empty - no TED information found.")

    # jxmlease can represent singletons as dicts; normalize to list.
    if isinstance(ted_links, dict):
        ted_links = [ted_links]

    if not isinstance(ted_links, list):
        raise ValueError("Unexpected format for 'ted-link' entries (expected list or dict).")

    adjacency_db: AdjacencyDB = {}

    field_keys = [
        "ted-link-local-address",
        "ted-link-remote-address",
        "ted-link-from",
        "ted-link-to",
        "ted-link-metric",
        "ted-link-igp-metric",
    ]

    for link_entry in ted_links:
        if not isinstance(link_entry, dict):
            continue

        local_ip, remote_ip, raw_node_a, raw_node_b, raw_te_metric, raw_igp_metric = (
            validate_key(link_entry, key_name) for key_name in field_keys
        )

        node_a = _normalize_node_name(raw_node_a, to_upper=normalize_nodes_upper)
        node_b = _normalize_node_name(raw_node_b, to_upper=normalize_nodes_upper)

        if _is_zero_ipv4(local_ip) or _is_zero_ipv4(remote_ip) or not node_a or not node_b:
            continue

        te_metric = _parse_metric(raw_te_metric)
        igp_metric = _parse_metric(raw_igp_metric)

        static_bandwidth: Optional[int] = _parse_bandwidth_bps(validate_key(link_entry, "ted-link-static-bandwidth"))
        reservable_bandwidth: Optional[int] = _parse_bandwidth_bps(validate_key(link_entry, "ted-link-reservable-bandwidth"))

        # Only store the forward record (node_a's own perspective).
        # The reverse direction (node_b → node_a) is a separate TED link entry
        # advertised by node_b with its own metric values.  Creating a synthetic
        # reverse here would assign node_a's metrics to node_b's direction, which
        # is incorrect for asymmetric topologies.
        admin_groups = _extract_admin_groups(link_entry)
        forward_record: NeighborRecord = {
            "Neighbor": node_b,
            "Local IP": local_ip,
            "Remote IP": remote_ip,
            "TE Metric": te_metric,
            "IGP Metric": igp_metric,
            "Admin Groups": admin_groups,
            "Static Bandwidth": static_bandwidth,
            "Reservable Bandwidth": reservable_bandwidth,
        }

        if forward_record not in adjacency_db.get(node_a, []):
            adjacency_db.setdefault(node_a, []).append(forward_record)

    if not adjacency_db:
        raise EmptyTedDataError("No valid TED links were found after filtering.")

    return adjacency_db


def validate_db_format(db_path: str) -> AdjacencyDB:
    path = Path(db_path)
    suffix = path.suffix.lower()

    if suffix == ".xml":
        parsed_db = parse_xml(str(path))
        adjacency_db = gather_node_data(parsed_db)
        return _ensure_adjacency_db_schema(adjacency_db)

    if suffix == ".json":
        adjacency_db = load_json_db(str(path))
        return _ensure_adjacency_db_schema(adjacency_db)

    raise UnsupportedDbFormatError("Unsupported DB type. Must be '.xml' or '.json'.")


def save_db(
    adjacency_db: AdjacencyDB,
    output_json: Optional[str] = None,
) -> str:
    _ensure_adjacency_db_schema(adjacency_db)

    json_path = Path(output_json) if output_json else _default_json_output_path()
    save_json_db(str(json_path), adjacency_db)

    return str(json_path)


def build_db_from_xml(
    xml_path: str,
    output_json: Optional[str] = None,
    output_name: Optional[str] = None,
) -> str:
    parsed_database = parse_xml(xml_path)
    adjacency_db = gather_node_data(parsed_database)
    if output_json is None and output_name:
        stem = Path(output_name).stem or output_name
        output_json = str(DB_DIR / f"{stem}.json")
    return save_db(
        adjacency_db,
        output_json=output_json,
    )


# -----------------------------
# Query helpers (web UI)
# -----------------------------

def list_nodes(db_path: str) -> List[str]:
    adjacency_db = validate_db_format(db_path)
    return sorted(adjacency_db.keys())


def get_node_records(db_path: str, node_name: str, *, normalize_upper: bool = False) -> List[NeighborRecord]:
    adjacency_db = validate_db_format(db_path)
    normalized_node = node_name.upper() if normalize_upper else node_name

    if normalized_node not in adjacency_db:
        raise NodeNotFoundError(f"{normalized_node} is not in the database.")

    return adjacency_db[normalized_node]


@dataclass(frozen=True)
class DbStats:
    nodes: int
    directed_links: int
    unique_undirected_links: int


def db_stats(db_path: str) -> DbStats:
    """
    Basic stats for UI display.
    """
    adjacency_db = validate_db_format(db_path)

    node_count = len(adjacency_db)
    directed_link_count = sum(len(neighbors) for neighbors in adjacency_db.values())

    # Approximate unique undirected links by canonicalizing endpoints and IP pair.
    seen_undirected = set()
    for node_name, neighbors in adjacency_db.items():
        for neighbor_record in neighbors:
            neighbor_name = str(neighbor_record.get("Neighbor", ""))
            local_ip = str(neighbor_record.get("Local IP", ""))
            remote_ip = str(neighbor_record.get("Remote IP", ""))

            endpoint_key = tuple(sorted([node_name, neighbor_name]))
            ip_key = tuple(sorted([local_ip, remote_ip]))
            seen_undirected.add(endpoint_key + ip_key)

    return DbStats(
        nodes=node_count,
        directed_links=directed_link_count,
        unique_undirected_links=len(seen_undirected),
    )


# -----------------------------
# Link operations (web-ready)
# -----------------------------

def add_or_remove_link_in_db_file(
    db_path: str,
    *,
    action: str,
    nodeA: str,
    nodeB: str,
    localIP: str,
    remoteIP: str,
    teMetricAB: int,
    igpMetricAB: int,
    teMetricBA: int,
    igpMetricBA: int,
    adminGroupsAB: Optional[List[str]] = None,
    adminGroupsBA: Optional[List[str]] = None,
    staticBandwidthAB: Optional[int] = None,
    staticBandwidthBA: Optional[int] = None,
    reservableBandwidthAB: Optional[int] = None,
    reservableBandwidthBA: Optional[int] = None,
    overwrite: bool = False,
    output_json: Optional[str] = None,
    normalize_nodes_upper: bool = False,
) -> str:
    adjacency_db = validate_db_format(db_path)
    add_or_remove_link_in_memory(
        adjacency_db,
        action=action,
        nodeA=nodeA,
        nodeB=nodeB,
        localIP=localIP,
        remoteIP=remoteIP,
        teMetricAB=teMetricAB,
        igpMetricAB=igpMetricAB,
        teMetricBA=teMetricBA,
        igpMetricBA=igpMetricBA,
        adminGroupsAB=adminGroupsAB,
        adminGroupsBA=adminGroupsBA,
        staticBandwidthAB=staticBandwidthAB,
        staticBandwidthBA=staticBandwidthBA,
        reservableBandwidthAB=reservableBandwidthAB,
        reservableBandwidthBA=reservableBandwidthBA,
        overwrite=overwrite,
        normalize_nodes_upper=normalize_nodes_upper,
    )
    return save_db(
        adjacency_db,
        output_json=output_json,
    )


def add_or_remove_link_in_memory(
    adjacency_db: AdjacencyDB,
    *,
    action: str,
    nodeA: str,
    nodeB: str,
    localIP: str,
    remoteIP: str,
    teMetricAB: int,
    igpMetricAB: int,
    teMetricBA: int,
    igpMetricBA: int,
    adminGroupsAB: Optional[List[str]] = None,
    adminGroupsBA: Optional[List[str]] = None,
    staticBandwidthAB: Optional[int] = None,
    staticBandwidthBA: Optional[int] = None,
    reservableBandwidthAB: Optional[int] = None,
    reservableBandwidthBA: Optional[int] = None,
    overwrite: bool = False,
    normalize_nodes_upper: bool = False,
) -> None:
    """
    Mutate adjacency DB in-memory: add/remove bidirectional link.

    Metrics, admin groups, and bandwidths are per-direction (each router's own perspective):
      - *AB params: nodeA → nodeB (stored under nodeA)
      - *BA params: nodeB → nodeA (stored under nodeB)

    Admin groups and bandwidths can be asymmetric. Bandwidth values are in bps; pass None
    if not applicable.

    Raises:
        InvalidActionError
        DuplicateLinkError (if adding duplicate and overwrite=False)
    """
    _ensure_adjacency_db_schema(adjacency_db)

    normalized_action = action.lower().strip()
    if normalized_action not in {"add", "remove"}:
        raise InvalidActionError("Action must be 'add' or 'remove'.")

    node_a = _normalize_node_name(nodeA, to_upper=normalize_nodes_upper) or nodeA
    node_b = _normalize_node_name(nodeB, to_upper=normalize_nodes_upper) or nodeB

    forward_record: NeighborRecord = {
        "Neighbor": node_b,
        "Local IP": localIP,
        "Remote IP": remoteIP,
        "TE Metric": teMetricAB,
        "IGP Metric": igpMetricAB,
        "Admin Groups": sorted(adminGroupsAB) if adminGroupsAB else [],
        "Static Bandwidth": staticBandwidthAB,
        "Reservable Bandwidth": reservableBandwidthAB,
    }
    reverse_record: NeighborRecord = {
        "Neighbor": node_a,
        "Local IP": remoteIP,
        "Remote IP": localIP,
        "TE Metric": teMetricBA,
        "IGP Metric": igpMetricBA,
        "Admin Groups": sorted(adminGroupsBA) if adminGroupsBA else [],
        "Static Bandwidth": staticBandwidthBA,
        "Reservable Bandwidth": reservableBandwidthBA,
    }

    if normalized_action == "add":
        _add_link_one_direction(
            adjacency_db,
            node_name=node_a,
            neighbor_name=node_b,
            neighbor_record=forward_record,
            overwrite=overwrite,
        )
        _add_link_one_direction(
            adjacency_db,
            node_name=node_b,
            neighbor_name=node_a,
            neighbor_record=reverse_record,
            overwrite=overwrite,
        )
        return

    # remove
    _remove_link_one_direction(
        adjacency_db,
        node_name=node_a,
        neighbor_name=node_b,
        local_ip=localIP,
        remote_ip=remoteIP,
    )
    _remove_link_one_direction(
        adjacency_db,
        node_name=node_b,
        neighbor_name=node_a,
        local_ip=remoteIP,
        remote_ip=localIP,
    )


def _add_link_one_direction(
    adjacency_db: AdjacencyDB,
    *,
    node_name: str,
    neighbor_name: str,
    neighbor_record: NeighborRecord,
    overwrite: bool,
) -> None:
    existing_index = _find_neighbor_record_index(
        adjacency_db,
        node_name=node_name,
        neighbor_name=neighbor_name,
        local_ip=str(neighbor_record.get("Local IP", "")),
    )

    if existing_index is None:
        adjacency_db.setdefault(node_name, []).append(neighbor_record)
        return

    if not overwrite:
        raise DuplicateLinkError(
            f"Link already exists for {node_name}->{neighbor_name} "
            f"({neighbor_record.get('Local IP')} -> {neighbor_record.get('Remote IP')})."
        )

    adjacency_db[node_name][existing_index] = neighbor_record


def _remove_link_one_direction(
    adjacency_db: AdjacencyDB,
    *,
    node_name: str,
    neighbor_name: str,
    local_ip: str,
    remote_ip: str,
) -> None:
    if node_name not in adjacency_db:
        return

    adjacency_db[node_name] = [
        neighbor_record
        for neighbor_record in adjacency_db[node_name]
        if not (
            neighbor_record.get("Neighbor") == neighbor_name
            and neighbor_record.get("Local IP") == local_ip
            and neighbor_record.get("Remote IP") == remote_ip
        )
    ]


def add_node_in_db_file(
    db_path: str,
    *,
    node_name: str,
    output_json: Optional[str] = None,
    normalize_nodes_upper: bool = False,
) -> str:
    adjacency_db = validate_db_format(db_path)
    add_node_in_memory(
        adjacency_db,
        node_name=node_name,
        normalize_nodes_upper=normalize_nodes_upper,
    )
    return save_db(
        adjacency_db,
        output_json=output_json,
    )


def remove_node_in_db_file(
    db_path: str,
    *,
    node_name: str,
    output_json: Optional[str] = None,
    normalize_nodes_upper: bool = False,
) -> str:
    adjacency_db = validate_db_format(db_path)
    remove_node_in_memory(
        adjacency_db,
        node_name=node_name,
        normalize_nodes_upper=normalize_nodes_upper,
    )
    return save_db(
        adjacency_db,
        output_json=output_json,
    )

def add_node_in_memory(
    adjacency_db: AdjacencyDB,
    *,
    node_name: str,
    normalize_nodes_upper: bool = False,
) -> None:
    _ensure_adjacency_db_schema(adjacency_db)

    normalized_node = _normalize_node_name(node_name, to_upper=normalize_nodes_upper) or node_name

    if normalized_node in adjacency_db:
        raise ValueError(f"Node {normalized_node} already exists.")

    adjacency_db[normalized_node] = []


def remove_node_in_memory(
    adjacency_db: AdjacencyDB,
    *,
    node_name: str,
    normalize_nodes_upper: bool = False,
) -> None:
    _ensure_adjacency_db_schema(adjacency_db)

    normalized_node = _normalize_node_name(node_name, to_upper=normalize_nodes_upper) or node_name

    if normalized_node not in adjacency_db:
        raise NodeNotFoundError(f"{normalized_node} is not in the database.")

    # Remove the node itself
    del adjacency_db[normalized_node]

    # Remove all links pointing to it
    for existing_node, neighbor_list in adjacency_db.items():
        adjacency_db[existing_node] = [
            neighbor_record
            for neighbor_record in neighbor_list
            if neighbor_record.get("Neighbor") != normalized_node
        ]

# -----------------------------
# Interface metadata operations
# -----------------------------

def add_interface_metadata_in_memory(
    adjacency_db: AdjacencyDB,
    *,
    nodeA: str,
    localIP: str,
    interface: str,
    description: str,
    normalize_nodes_upper: bool = False,
) -> None:
    """
    Add interface + description metadata to both sides of a link.

    Updates:
      - nodeA record where Local IP == localIP: sets "Local Interface" and "Description"
      - neighbor reverse record where Remote IP == localIP: sets "Remote Interface"
    """
    _ensure_adjacency_db_schema(adjacency_db)

    node_a = _normalize_node_name(nodeA, to_upper=normalize_nodes_upper) or nodeA
    if node_a not in adjacency_db:
        raise NodeNotFoundError(f"{node_a} is not in the database.")

    any_updated = False

    for neighbor_record in adjacency_db[node_a]:
        if neighbor_record.get("Local IP") != localIP:
            continue

        neighbor_record["Local Interface"] = interface
        neighbor_record["Description"] = description

        neighbor_node = neighbor_record.get("Neighbor")
        if isinstance(neighbor_node, str) and neighbor_node in adjacency_db:
            for reverse_record in adjacency_db[neighbor_node]:
                if reverse_record.get("Remote IP") == localIP:
                    reverse_record["Remote Interface"] = interface
                    break

        any_updated = True

    if not any_updated:
        raise ValueError(f"No adjacency record matched node={node_a}, localIP={localIP}.")


@dataclass(frozen=True)
class BulkInterfaceResult:
    processed_rows: int
    updated_rows: int
    skipped_missing_node: int
    skipped_invalid_row: int


def add_interfaces_bulk_from_csv(
    db_path: str,
    csv_path: str,
    *,
    output_json: Optional[str] = None,
    normalize_nodes_upper: bool = False,
) -> Tuple[str, BulkInterfaceResult]:
    rows = csv_to_list(csv_path)
    adjacency_db = validate_db_format(db_path)

    summary = add_interfaces_bulk_in_memory(
        adjacency_db,
        rows=rows,
        normalize_nodes_upper=normalize_nodes_upper,
    )

    output_path = save_db(
        adjacency_db,
        output_json=output_json,
    )
    return output_path, summary


def add_interfaces_bulk_in_memory(
    adjacency_db: AdjacencyDB,
    *,
    rows: List[List[str]],
    normalize_nodes_upper: bool = False,
) -> BulkInterfaceResult:
    _ensure_adjacency_db_schema(adjacency_db)

    processed_rows = 0
    updated_rows = 0
    skipped_missing_node = 0
    skipped_invalid_row = 0

    for row in rows:
        processed_rows += 1

        if not row or len(row) < 4:
            skipped_invalid_row += 1
            continue

        nodeA, localIP, interface, description = row[:4]
        node_a = _normalize_node_name(nodeA, to_upper=normalize_nodes_upper) or nodeA

        if node_a not in adjacency_db:
            skipped_missing_node += 1
            continue

        try:
            add_interface_metadata_in_memory(
                adjacency_db,
                nodeA=node_a,
                localIP=localIP,
                interface=interface,
                description=description,
                normalize_nodes_upper=normalize_nodes_upper,
            )
            updated_rows += 1
        except ValueError:
            # localIP not found for this node in this DB
            skipped_invalid_row += 1

    return BulkInterfaceResult(
        processed_rows=processed_rows,
        updated_rows=updated_rows,
        skipped_missing_node=skipped_missing_node,
        skipped_invalid_row=skipped_invalid_row,
    )


# -----------------------------
# Trace path by IP list
# -----------------------------

@dataclass(frozen=True)
class PathHop:
    ip: str
    found: bool
    ingress_node: str
    te_metric: int
    igp_metric: int
    neighbor: str
    neighbor_ip: str
    admin_groups: List[str] = None

    def __post_init__(self):
        # dataclass frozen=True requires object.__setattr__ for defaults
        if self.admin_groups is None:
            object.__setattr__(self, "admin_groups", [])


def trace_path_by_ips(
    adjacency_db: AdjacencyDB,
    ip_list: List[str],
) -> List[PathHop]:
    """
    Map a list of ERO hop IP addresses to TED DB records.

    Each ERO hop IP is the ingress interface of the next router, which corresponds
    to the "Remote IP" field in the advertising node's adjacency record.

    IPs not found in the DB are returned as UNKNOWN HOPs.
    Returns a list of PathHop entries in the same order as ip_list.
    """
    # Build lookup: remote_ip (str) -> (node_name, record)
    remote_ip_index: Dict[str, Tuple[str, NeighborRecord]] = {}
    for node_name, neighbors in adjacency_db.items():
        for record in neighbors:
            remote_ip = record.get("Remote IP")
            if remote_ip:
                remote_ip_index[str(remote_ip)] = (node_name, record)

    hops: List[PathHop] = []
    for raw_ip in ip_list:
        ip = raw_ip.strip()
        if not ip:
            continue
        if ip in remote_ip_index:
            node_name, record = remote_ip_index[ip]
            hops.append(PathHop(
                ip=ip,
                found=True,
                ingress_node=node_name,
                te_metric=_parse_metric(record.get("TE Metric"), default=0),
                igp_metric=_parse_metric(record.get("IGP Metric"), default=0),
                neighbor=str(record.get("Neighbor", "-")),
                neighbor_ip=str(record.get("Remote IP", "-")),
                admin_groups=record.get("Admin Groups") or [],
            ))
        else:
            hops.append(PathHop(
                ip=ip,
                found=False,
                ingress_node=f"UNKNOWN HOP ({ip})",
                te_metric="-",
                igp_metric="-",
                neighbor="-",
                neighbor_ip="-",
            ))
    return hops


def trace_path_by_ips_from_db(
    db_path: str,
    ip_list: List[str],
) -> List[PathHop]:
    """Load DB and trace path — convenience wrapper for the web layer."""
    adjacency_db = validate_db_format(db_path)
    return trace_path_by_ips(adjacency_db, ip_list)


# -----------------------------
# Compare + Export
# -----------------------------

@dataclass(frozen=True)
class LinkChange:
    """A link that exists in both DBs but whose metric values differ."""
    record_old: NeighborRecord
    record_new: NeighborRecord


@dataclass(frozen=True)
class DbDiff:
    removed: List[NeighborRecord]   # links in DB1 but not DB2
    added: List[NeighborRecord]     # links in DB2 but not DB1
    changed: List[LinkChange]       # same link (Neighbor + Local IP), different metrics


_DIFF_EXCLUDE = {"Reservable Bandwidth"}


def _link_key(record: NeighborRecord) -> tuple:
    """Identity key for a directed link: (Neighbor, Local IP)."""
    return (str(record.get("Neighbor", "")), str(record.get("Local IP", "")))


def _link_values(record: NeighborRecord) -> dict:
    """Record fields used for change detection (excludes dynamic attributes)."""
    return {k: v for k, v in record.items() if k not in _DIFF_EXCLUDE}


def compare_dbs(db_path_1: str, db_path_2: str) -> Dict[str, DbDiff]:
    """
    Compare two DB files and return structured differences per node.

    Three categories per node:
      removed  — link present in DB1 but absent in DB2
      added    — link present in DB2 but absent in DB1
      changed  — same (Neighbor, Local IP) in both DBs but metric values differ
    """
    db1 = validate_db_format(db_path_1)
    db2 = validate_db_format(db_path_2)

    differences: Dict[str, DbDiff] = {}

    all_nodes = set(db1) | set(db2)

    for node_name in all_nodes:
        neighbors_1 = db1.get(node_name, [])
        neighbors_2 = db2.get(node_name, [])

        idx1 = {_link_key(r): r for r in neighbors_1}
        idx2 = {_link_key(r): r for r in neighbors_2}

        removed  = [r for k, r in idx1.items() if k not in idx2]
        added    = [r for k, r in idx2.items() if k not in idx1]
        changed  = [
            LinkChange(record_old=idx1[k], record_new=idx2[k])
            for k in idx1
            if k in idx2 and _link_values(idx1[k]) != _link_values(idx2[k])
        ]

        if removed or added or changed:
            differences[node_name] = DbDiff(removed=removed, added=added, changed=changed)

    return differences


def merge_dbs(
    db_path_1: str,
    db_path_2: str,
    *,
    accepted_changes: List[str],
    output_json: Optional[str] = None,
) -> str:
    """
    Merge DB1 with a user-selected subset of changes from DB2.

    accepted_changes: list of change identifiers, each formatted as
      "TYPE|NODE|NEIGHBOR|LOCAL_IP"
      where TYPE is one of: "removed", "added", "changed"

    Logic:
      - Starts from a deep copy of DB1 as the base.
      - removed: the link is deleted from the merged DB (accepting DB2's absence).
      - added:   the link is copied from DB2 into the merged DB.
      - changed: the link in the merged DB is replaced with DB2's version.

    Raises ValueError for malformed change IDs (skips silently) and
    KeyError / NodeNotFoundError if referenced nodes/links don't exist.
    """
    import copy

    db1 = validate_db_format(db_path_1)
    db2 = validate_db_format(db_path_2)
    merged: AdjacencyDB = copy.deepcopy(db1)

    for change_id in accepted_changes:
        parts = change_id.split("|", 3)
        if len(parts) != 4:
            continue
        change_type, node, neighbor, local_ip = parts

        if change_type == "removed":
            if node in merged:
                merged[node] = [
                    r for r in merged[node]
                    if not (str(r.get("Neighbor")) == neighbor
                            and str(r.get("Local IP")) == local_ip)
                ]
                if not merged[node]:
                    del merged[node]

        elif change_type == "added":
            node_records_2 = db2.get(node, [])
            record = next(
                (r for r in node_records_2
                 if str(r.get("Neighbor")) == neighbor
                 and str(r.get("Local IP")) == local_ip),
                None,
            )
            if record is not None:
                merged.setdefault(node, []).append(record)

        elif change_type == "changed":
            node_records_2 = db2.get(node, [])
            new_record = next(
                (r for r in node_records_2
                 if str(r.get("Neighbor")) == neighbor
                 and str(r.get("Local IP")) == local_ip),
                None,
            )
            if new_record is not None and node in merged:
                for i, r in enumerate(merged[node]):
                    if (str(r.get("Neighbor")) == neighbor
                            and str(r.get("Local IP")) == local_ip):
                        merged[node][i] = new_record
                        break

    return save_db(merged, output_json=output_json)


def export_db_to_csv(db_path: str, output_csv: Optional[str] = None) -> str:
    """
    Export adjacency DB to CSV (one directed record per line).
    Returns the CSV path.
    """
    adjacency_db = validate_db_format(db_path)
    output_path = Path(output_csv) if output_csv else _default_csv_output_path()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as file_handle:
        for node_name, neighbors in adjacency_db.items():
            for neighbor_record in neighbors:
                line = (
                    f"{node_name},"
                    f"{neighbor_record.get('TE Metric','')},"
                    f"{neighbor_record.get('IGP Metric','')},"
                    f"{neighbor_record.get('Neighbor','')},"
                    f"{neighbor_record.get('Local IP','')}"
                )
                file_handle.write(line + "\n")

    return str(output_path)