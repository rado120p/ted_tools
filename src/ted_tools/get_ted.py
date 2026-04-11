"""
get_ted.py — TED (Traffic Engineering Database) collection (web-ready)

Web-integration goals:
- No argparse / CLI main
- No interactive getpass() inside core functions (web layer supplies credentials)
- No sys.exit()
- Uses configurable workspace paths via ted_tools.config (XML_DIR)
- Functions return values / raise exceptions

Security note:
- Do NOT log passwords
- Keep credentials ephemeral (pass them in, don’t store them)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from lxml import etree
from jnpr.junos import Device

from ted_tools.config import XML_DIR
from ted_tools.exception_handler import ExceptionHandler


# -----------------------------
# Exceptions (web-friendly)
# -----------------------------

class GetTedError(Exception):
    """Base exception for get_ted."""


# -----------------------------
# Public API (web-ready)
# -----------------------------

@dataclass(frozen=True)
class TedFetchResult:
    target: str
    username: str
    xml_path: str


@ExceptionHandler.junos_exceptions(exit_on_error=False)
def get_ted_rpc(
    *,
    username: str,
    target: str,
    password: str,
    port: int = 830,
    timeout: int = 30,
    normalize: bool = True,
):
    """
    Connect to a Juniper device and retrieve TED link information via RPC.

    Args:
        username: Login username
        target: Hostname / IP
        password: Login password (supplied by caller)
        port: NETCONF port (default 830)
        timeout: connection timeout seconds
        normalize: PyEZ normalize flag

    Returns:
        lxml.etree._Element: XML element containing TED link information.

    Raises:
        Wrapped by ExceptionHandler; with exit_on_error=False it will raise RuntimeError
        (or propagate unexpected exceptions).
    """
    with Device(
        host=target,
        user=username,
        passwd=password,
        port=port,
        timeout=timeout,
        normalize=normalize,
    ) as dev:
        ted_rpc = dev.rpc.get_ted_link_information(detail=True)

    return ted_rpc


# -----------------------------
# Node verification
# -----------------------------

@dataclass
class NodeVerifyResult:
    node: str
    host: str
    status: str          # "matches_db1" | "matches_db2" | "matches_neither" | "unreachable" | "error"
    detail: str = ""     # human-readable summary shown in the UI
    error: Optional[str] = None


def _safe_int(value) -> Optional[int]:
    """Parse metric value to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def _fetch_isis_config_metrics(dev) -> dict:
    """
    Fetch IS-IS interface configuration from the device.
    Returns {interface_name: {"igp": int_or_None, "te": int_or_None}}.

    Tries level-2 metric first, falls back to flat <metric> element.
    TE metric is taken from <te-metric> or traffic-engineering/metric.
    """
    from lxml import etree

    filter_xml = etree.fromstring(
        "<configuration>"
        "  <protocols><isis><interface/></isis></protocols>"
        "</configuration>"
    )
    isis_cfg = dev.rpc.get_config(filter_xml=filter_xml)

    metrics: dict = {}
    for iface in isis_cfg.findall(".//{http://xml.juniper.net/xnm/1.1/xnm}interface") or \
                  isis_cfg.findall(".//interface"):
        name_el = iface.find("name") or iface.find(
            "{http://xml.juniper.net/xnm/1.1/xnm}name"
        )
        if name_el is None:
            continue
        name = name_el.text.strip()

        # IGP metric — prefer level-2 explicit config, fall back to flat <metric>
        igp: Optional[int] = None
        for level in iface.findall("level") or iface.findall(
            "{http://xml.juniper.net/xnm/1.1/xnm}level"
        ):
            lvl_name = level.find("name") or level.find(
                "{http://xml.juniper.net/xnm/1.1/xnm}name"
            )
            if lvl_name is not None and lvl_name.text.strip() == "2":
                m = level.find("metric") or level.find(
                    "{http://xml.juniper.net/xnm/1.1/xnm}metric"
                )
                if m is not None:
                    igp = _safe_int(m.text)
                break
        if igp is None:
            m = iface.find("metric") or iface.find(
                "{http://xml.juniper.net/xnm/1.1/xnm}metric"
            )
            if m is not None:
                igp = _safe_int(m.text)

        # TE metric — <te-metric> or traffic-engineering/metric
        te: Optional[int] = None
        te_el = iface.find("te-metric") or iface.find(
            "{http://xml.juniper.net/xnm/1.1/xnm}te-metric"
        )
        if te_el is not None:
            te = _safe_int(te_el.text)
        else:
            te_m = iface.find(".//traffic-engineering/metric") or iface.find(
                ".//{http://xml.juniper.net/xnm/1.1/xnm}traffic-engineering"
                "/{http://xml.juniper.net/xnm/1.1/xnm}metric"
            )
            if te_m is not None:
                te = _safe_int(te_m.text)

        metrics[name] = {"igp": igp, "te": te}

    return metrics


def _fetch_interface_ips(dev) -> dict:
    """
    Fetch interface IP addresses from configuration.
    Returns {full_interface_name: [ip, ...]}  e.g. {"ge-0/0/0.0": ["10.0.0.1"]}.
    """
    from lxml import etree

    filter_xml = etree.fromstring(
        "<configuration><interfaces/></configuration>"
    )
    iface_cfg = dev.rpc.get_config(filter_xml=filter_xml)

    ns = "{http://xml.juniper.net/xnm/1.1/xnm}"
    ip_map: dict = {}

    def _find(el, tag):
        return el.find(tag) or el.find(ns + tag)

    def _findall(el, tag):
        return el.findall(tag) or el.findall(ns + tag)

    for iface in _findall(iface_cfg, ".//interface"):
        iface_name_el = _find(iface, "name")
        if iface_name_el is None:
            continue
        iface_name = iface_name_el.text.strip()

        for unit in _findall(iface, "unit"):
            unit_name_el = _find(unit, "name")
            unit_name = unit_name_el.text.strip() if unit_name_el is not None else "0"
            full_name = f"{iface_name}.{unit_name}"

            ips = []
            for addr_el in unit.findall(".//address") + unit.findall(
                f".//{ns}address"
            ):
                addr_name = _find(addr_el, "name")
                if addr_name is not None:
                    ip = addr_name.text.strip().split("/")[0]
                    ips.append(ip)

            if ips:
                ip_map[full_name] = ips

    return ip_map


def _build_config_metric_map(isis_metrics: dict, iface_ips: dict) -> dict:
    """
    Join IS-IS interface metrics with interface IP addresses.
    Returns {local_ip: {"IGP Metric": int_or_None, "TE Metric": int_or_None}}.
    """
    result: dict = {}
    for iface_name, metrics in isis_metrics.items():
        for ip in iface_ips.get(iface_name, []):
            result[ip] = {
                "IGP Metric": metrics["igp"],
                "TE Metric": metrics["te"],
            }
    return result


def _config_matches_db(config_map: dict, db_records: list) -> bool:
    """
    True when the IS-IS config metric map matches the DB record set for a node.

    Comparison is based on Local IP → (IGP Metric, TE Metric).  Neighbor names
    are TED-derived and not available from config, so they are intentionally
    excluded from the comparison.

    Both the set of Local IPs and their metric values must agree for a match.
    """
    db_map = {
        str(r.get("Local IP", "")): {
            "IGP Metric": _safe_int(r.get("IGP Metric")),
            "TE Metric": _safe_int(r.get("TE Metric")),
        }
        for r in db_records
        if r.get("Local IP")
    }

    if set(config_map.keys()) != set(db_map.keys()):
        return False

    for ip, cfg_metrics in config_map.items():
        if cfg_metrics != db_map.get(ip):
            return False

    return True


def _verify_one_node(
    *,
    node: str,
    host: str,
    username: str,
    password: str,
    db1_records: list,
    db2_records: list,
    port: int,
    timeout: int,
) -> NodeVerifyResult:
    """
    Connect to *host*, fetch IS-IS interface **configuration** (not TED), and
    compare configured metrics with DB snapshots.

    Configuration is the source of truth: metrics only change when an
    administrator manually reconfigures them, so transient link failures do not
    affect the result.
    """
    try:
        with Device(
            host=host,
            user=username,
            passwd=password,
            port=port,
            timeout=timeout,
            normalize=True,
        ) as dev:
            isis_metrics = _fetch_isis_config_metrics(dev)
            iface_ips    = _fetch_interface_ips(dev)
    except Exception as exc:
        return NodeVerifyResult(
            node=node, host=host, status="unreachable",
            detail="Could not reach device — manual verification required.",
            error=str(exc),
        )

    try:
        config_map = _build_config_metric_map(isis_metrics, iface_ips)
    except Exception as exc:
        return NodeVerifyResult(
            node=node, host=host, status="error",
            detail="Connected but config parsing failed.",
            error=str(exc),
        )

    n_cfg = len(config_map)
    if _config_matches_db(config_map, db1_records):
        return NodeVerifyResult(
            node=node, host=host, status="matches_db1",
            detail=(
                f"{n_cfg} IS-IS interface(s) configured — "
                "metrics match snapshot A (change appears transient)."
            ),
        )
    if _config_matches_db(config_map, db2_records):
        return NodeVerifyResult(
            node=node, host=host, status="matches_db2",
            detail=(
                f"{n_cfg} IS-IS interface(s) configured — "
                "metrics match snapshot B (change confirmed in configuration)."
            ),
        )
    return NodeVerifyResult(
        node=node, host=host, status="matches_neither",
        detail=(
            f"{n_cfg} IS-IS interface(s) configured — "
            "metrics match neither snapshot (device is in a third state)."
        ),
    )


def verify_changed_nodes(
    *,
    nodes: List[str],
    host_map: Dict[str, str],
    username: str,
    password: str,
    db_path_1: str,
    db_path_2: str,
    port: int = 830,
    timeout: int = 30,
    max_workers: int = 10,
) -> Dict[str, NodeVerifyResult]:
    """
    Query each changed node in parallel via PyEZ and determine whether its
    current TED records match snapshot A (transient change), snapshot B
    (confirmed change), neither, or are unreachable.

    host_map: {node_name: management_hostname_or_ip}
    Nodes absent from host_map fall back to using the node name as the host.
    """
    from ted_tools.ted_handler import validate_db_format

    db1 = validate_db_format(db_path_1)
    db2 = validate_db_format(db_path_2)

    results: Dict[str, NodeVerifyResult] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _verify_one_node,
                node=node,
                host=host_map.get(node, node),
                username=username,
                password=password,
                db1_records=db1.get(node, []),
                db2_records=db2.get(node, []),
                port=port,
                timeout=timeout,
            ): node
            for node in nodes
        }
        for future in as_completed(futures):
            node = futures[future]
            try:
                results[node] = future.result()
            except Exception as exc:
                results[node] = NodeVerifyResult(
                    node=node, host=host_map.get(node, node),
                    status="error", detail="Unexpected error.", error=str(exc),
                )

    return results


def save_ted_rpc_to_file(
    ted_rpc,
    *,
    output_dir: Path = XML_DIR,
    filename: Optional[str] = None,
) -> str:
    """
    Save TED RPC XML data to a file (pretty-printed).
    Returns the full path as string.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if filename is None:
        filename = datetime.now().strftime("%Y%m%d_%H%M%S") + ".xml"

    full_path = output_dir / filename

    # Write bytes directly
    payload = etree.tostring(ted_rpc, pretty_print=True)

    with open(full_path, "wb") as f:
        f.write(payload)

    return str(full_path)


def fetch_and_save_ted(
    *,
    username: str,
    target: str,
    password: str,
    output_dir: Path = XML_DIR,
    filename: Optional[str] = None,
    port: int = 830,
    timeout: int = 30,
    normalize: bool = True,
) -> TedFetchResult:
    """
    High-level helper for web use:
    - fetch TED via RPC
    - save to XML_DIR (or provided output_dir)
    - return metadata for UI
    """
    ted_rpc = get_ted_rpc(
        username=username,
        target=target,
        password=password,
        port=port,
        timeout=timeout,
        normalize=normalize,
    )
    xml_path = save_ted_rpc_to_file(
        ted_rpc,
        output_dir=output_dir,
        filename=filename,
    )
    return TedFetchResult(target=target, username=username, xml_path=xml_path)