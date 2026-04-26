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

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from lxml import etree
from jnpr.junos import Device

log = logging.getLogger(__name__)

from ted_tools.config import XML_DIR
from ted_tools.exception_handler import ExceptionHandler


# Hardened XML parser. Prevents:
# - XXE: external entity expansion (e.g. <!ENTITY xxe SYSTEM "file:///etc/passwd">)
# - Billion-laughs: recursive entity expansion DoS
# - SSRF via DTD external references with no_network=True
# - Memory exhaustion on deeply nested trees with huge_tree=False
_SAFE_XML_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    huge_tree=False,
)


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
    config_map: Optional[dict] = None   # {local_ip: {"IGP Metric": ..., "TE Metric": ...}}
    db1_records: Optional[list] = None  # raw records from snapshot A for this node
    db2_records: Optional[list] = None  # raw records from snapshot B for this node
    rsvp_bw: Optional[dict] = None     # {interface_name: bps} from live device
    iface_map: Optional[dict] = None   # {interface_name: [ip, ...]} from live device


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
    TE metric is taken from level/<te-metric> or level/traffic-engineering/metric.
    """
    filter_xml = etree.fromstring(
        "<configuration>"
        "  <protocols><isis><interface/></isis></protocols>"
        "</configuration>",
        parser=_SAFE_XML_PARSER,
    )
    isis_cfg = dev.rpc.get_config(filter_xml=filter_xml)
    log.debug("IS-IS config XML:\n%s", etree.tostring(isis_cfg, pretty_print=True).decode())

    metrics: dict = {}
    for iface in isis_cfg.findall(".//interface"):
        name_el = iface.find("name")
        if name_el is None:
            continue
        name = name_el.text.strip()

        # Skip passive interfaces — they don't appear as TED transit links
        if iface.find("passive") is not None:
            log.debug("IS-IS interface %s is passive — skipped", name)
            continue

        igp: Optional[int] = None
        te: Optional[int] = None

        # Prefer level-2 config; fall back to flat <metric>/<te-metric>
        for level in iface.findall("level"):
            lvl_name = level.find("name")
            if lvl_name is not None and lvl_name.text.strip() == "2":
                m = level.find("metric")
                if m is not None:
                    igp = _safe_int(m.text)
                te_el = level.find("te-metric")
                if te_el is not None:
                    te = _safe_int(te_el.text)
                else:
                    te_m = level.find("traffic-engineering/metric")
                    if te_m is not None:
                        te = _safe_int(te_m.text)
                break

        if igp is None:
            m = iface.find("metric")
            if m is not None:
                igp = _safe_int(m.text)
        if te is None:
            te_el = iface.find("te-metric")
            if te_el is not None:
                te = _safe_int(te_el.text)

        metrics[name] = {"igp": igp, "te": te}
        log.debug("IS-IS interface parsed: %s → igp=%s te=%s", name, igp, te)

    log.debug("IS-IS metrics total: %d interface(s)", len(metrics))
    return metrics


def _fetch_rsvp_bandwidth(dev) -> dict:
    """
    Fetch RSVP interface bandwidth from device config.
    Returns dict: { interface_name: static_bw_bps } using RSVP interface config.
    Falls back to empty dict if RSVP is not configured.
    """
    try:
        filter_xml = etree.fromstring(
            "<configuration>"
            "  <protocols><rsvp><interface/></rsvp></protocols>"
            "</configuration>",
            parser=_SAFE_XML_PARSER,
        )
        config = dev.rpc.get_config(filter_xml=filter_xml)
        log.debug("RSVP config XML:\n%s", etree.tostring(config, pretty_print=True).decode())
        result = {}
        for iface in config.findall(".//rsvp/interface"):
            name_el = iface.find("name")
            bw_el = iface.find("bandwidth")
            if name_el is not None and bw_el is not None:
                result[name_el.text.strip()] = _parse_bandwidth_string(bw_el.text)
        return result
    except Exception:
        log.debug("EXCEPTION occurred for RSVP config XML retrieval")
        return {}


def _parse_bandwidth_string(s: str) -> Optional[int]:
    """Parse Junos bandwidth strings like '1g', '100m', '1000000' to bps int."""
    if s is None:
        return None
    s = str(s).strip().lower()
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


def _fetch_interface_ips(dev) -> dict:
    """
    Fetch interface IP addresses from configuration.
    Returns {full_interface_name: [ip, ...]}  e.g. {"ge-0/0/0.0": ["10.0.0.1"]}.
    """
    filter_xml = etree.fromstring(
        "<configuration><interfaces/></configuration>",
        parser=_SAFE_XML_PARSER,
    )
    iface_cfg = dev.rpc.get_config(filter_xml=filter_xml)
    log.debug("Interface config XML:\n%s", etree.tostring(iface_cfg, pretty_print=True).decode())

    ip_map: dict = {}

    for iface in iface_cfg.findall(".//interface"):
        iface_name_el = iface.find("name")
        if iface_name_el is None:
            continue
        iface_name = iface_name_el.text.strip()

        for unit in iface.findall("unit"):
            unit_name_el = unit.find("name")
            unit_name = unit_name_el.text.strip() if unit_name_el is not None else "0"
            full_name = f"{iface_name}.{unit_name}"

            ips = []
            for addr_el in unit.findall("family/inet/address"):
                addr_name = addr_el.find("name")
                if addr_name is not None:
                    ip = addr_name.text.strip().split("/")[0]
                    ips.append(ip)

            if ips:
                ip_map[full_name] = ips
                log.debug("Interface IPs: %s → %s", full_name, ips)

    log.debug("Interface IP map total: %d interface(s) with addresses", len(ip_map))
    return ip_map


def _build_config_metric_map(isis_metrics: dict, iface_ips: dict) -> dict:
    """
    Join IS-IS interface metrics with interface IP addresses.
    Returns {local_ip: {"IGP Metric": int_or_None, "TE Metric": int_or_None}}.
    """
    result: dict = {}
    for iface_name, metrics in isis_metrics.items():
        ips = iface_ips.get(iface_name, [])
        if not ips:
            log.debug("No IP found for IS-IS interface %s — skipped", iface_name)
        for ip in ips:
            result[ip] = {
                "IGP Metric": metrics["igp"],
                "TE Metric": metrics["te"],
            }
            log.debug("Config metric map: %s → IGP=%s TE=%s", ip, metrics["igp"], metrics["te"])

    log.debug("Config metric map total: %d IP(s)", len(result))
    return result


def _config_matches_db(
    config_map: dict,
    db_records: list,
    rsvp_bw: dict = None,
    iface_map: dict = None,
) -> bool:
    """
    True when the IS-IS config metric map matches the DB record set for a node.

    Comparison is based on Local IP → (IGP Metric, TE Metric).  Neighbor names
    are TED-derived and not available from config, so they are intentionally
    excluded from the comparison.

    Both the set of Local IPs and their metric values must agree for a match.

    If rsvp_bw and iface_map are provided, also compares Static Bandwidth for
    interfaces where RSVP bandwidth is configured. Only fails if RSVP BW is
    present AND differs from the DB value.
    """
    db_map = {
        str(r.get("Local IP", "")): {
            "IGP Metric": _safe_int(r.get("IGP Metric")),
            "TE Metric": _safe_int(r.get("TE Metric")),
            "Static Bandwidth": r.get("Static Bandwidth"),
        }
        for r in db_records
        if r.get("Local IP")
    }

    cfg_ips = set(config_map.keys())
    db_ips  = set(db_map.keys())
    if cfg_ips != db_ips:
        log.debug(
            "IP set mismatch — config only: %s  db only: %s",
            cfg_ips - db_ips, db_ips - cfg_ips,
        )
        return False

    for ip, cfg_metrics in config_map.items():
        db_entry = db_map.get(ip)
        db_metrics = {"IGP Metric": db_entry["IGP Metric"], "TE Metric": db_entry["TE Metric"]}
        if cfg_metrics != db_metrics:
            log.debug("Metric mismatch for %s — config: %s  db: %s", ip, cfg_metrics, db_metrics)
            return False

    # Bandwidth comparison (only when RSVP data available)
    if rsvp_bw and iface_map:
        # Build reverse map: ip -> interface_name
        ip_to_iface: dict = {}
        for iface_name, ips in iface_map.items():
            for ip in ips:
                ip_to_iface[ip] = iface_name

        for ip, db_entry in db_map.items():
            iface_name = ip_to_iface.get(ip)
            if iface_name is None:
                continue
            rsvp_bw_val = rsvp_bw.get(iface_name)
            if rsvp_bw_val is None:
                # RSVP BW not configured for this interface — skip check
                continue
            db_bw = db_entry.get("Static Bandwidth")
            if db_bw != rsvp_bw_val:
                log.debug(
                    "Bandwidth mismatch for %s (%s) — rsvp: %s  db: %s",
                    ip, iface_name, rsvp_bw_val, db_bw,
                )
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
    Connect to *host*, fetch IS-IS and RSVP interface config, and
    compare configured metrics/bw with DB snapshots.

    Configuration is the source of truth: metrics/static_bw only change when an
    administrator manually reconfigures them, so transient link failures do not
    affect the result.
    """
    log.debug("verify_one_node: node=%s host=%s", node, host)
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
            rsvp_bw      = _fetch_rsvp_bandwidth(dev)
    except Exception as exc:
        log.debug("verify_one_node: unreachable — %s", exc)
        return NodeVerifyResult(
            node=node, host=host, status="unreachable",
            detail="Could not reach device — manual verification required.",
            error=str(exc),
        )

    try:
        config_map = _build_config_metric_map(isis_metrics, iface_ips)
    except Exception as exc:
        log.debug("verify_one_node: config parse error — %s", exc)
        return NodeVerifyResult(
            node=node, host=host, status="error",
            detail="Connected but config parsing failed.",
            error=str(exc),
        )

    log.debug(
        "verify_one_node: config_map=%s  db1_ips=%s  db2_ips=%s",
        list(config_map.keys()),
        [r.get("Local IP") for r in db1_records],
        [r.get("Local IP") for r in db2_records],
    )
    n_cfg = len(config_map)
    if _config_matches_db(config_map, db1_records, rsvp_bw=rsvp_bw, iface_map=iface_ips):
        return NodeVerifyResult(
            node=node, host=host, status="matches_db1",
            detail=(
                f"{n_cfg} IS-IS interface(s) configured — "
                "metrics match snapshot A (change appears transient)."
            ),
            config_map=config_map,
            db1_records=db1_records,
            db2_records=db2_records,
            rsvp_bw=rsvp_bw,
            iface_map=iface_ips,
        )
    if _config_matches_db(config_map, db2_records, rsvp_bw=rsvp_bw, iface_map=iface_ips):
        return NodeVerifyResult(
            node=node, host=host, status="matches_db2",
            detail=(
                f"{n_cfg} IS-IS interface(s) configured — "
                "metrics match snapshot B (change confirmed in configuration)."
            ),
            config_map=config_map,
            db1_records=db1_records,
            db2_records=db2_records,
            rsvp_bw=rsvp_bw,
            iface_map=iface_ips,
        )
    return NodeVerifyResult(
        node=node, host=host, status="matches_neither",
        detail=(
            f"{n_cfg} IS-IS interface(s) configured — "
            "metrics match neither snapshot (device is in a third state)."
        ),
        config_map=config_map,
        db1_records=db1_records,
        db2_records=db2_records,
        rsvp_bw=rsvp_bw,
        iface_map=iface_ips,
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