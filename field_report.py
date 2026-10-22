"""Validate a Sightline field report before adding it to a desktop project."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re


def normalise_field_report(payload: dict) -> dict:
    if not isinstance(payload, dict) or payload.get("schema") != "sightline-field-report/v1":
        raise ValueError("unsupported Sightline field report")
    mission_id = payload.get("mission_id")
    if not isinstance(mission_id, str) or not re.fullmatch(r"[0-9a-f]{16}", mission_id):
        raise ValueError("invalid mission id")
    summary = payload.get("summary_text")
    if not isinstance(summary, str) or not summary or len(summary.encode()) > 512 * 1024:
        raise ValueError("field summary is missing or too large")
    digest = hashlib.sha256(summary.encode()).hexdigest()
    if digest != payload.get("summary_sha256"):
        raise ValueError("field summary hash does not match")
    scope = ipaddress.ip_network(payload.get("scope", ""), strict=True)
    if scope.version != 4 or scope.prefixlen < 24:
        raise ValueError("field scope must be IPv4 /24 or smaller")
    source_ip = ipaddress.ip_address(payload.get("source_ip", ""))
    if source_ip.version != 4 or source_ip not in scope:
        raise ValueError("source IP is outside the reported scope")
    interface = payload.get("interface")
    profile = payload.get("profile")
    outcome = payload.get("outcome")
    if interface not in ("eth0", "wlan0") or profile not in ("balanced", "deep") or outcome not in (
            "complete", "partial", "stopped", "interrupted"):
        raise ValueError("invalid field run metadata")
    context = payload.get("context")
    if not isinstance(context, dict) or any(not isinstance(context.get(key), str) or
            not 1 <= len(context[key]) <= 48 for key in ("project_id", "engagement_id", "operator_id")):
        raise ValueError("invalid field engagement metadata")
    hosts = payload.get("hosts")
    if not isinstance(hosts, list) or len(hosts) > 256:
        raise ValueError("invalid field host list")
    clean_hosts = []
    seen = set()
    for host in hosts:
        if not isinstance(host, dict) or not isinstance(host.get("open_ports"), list):
            raise ValueError("invalid field host")
        address = ipaddress.ip_address(host.get("address", ""))
        if address not in scope or str(address) in seen:
            raise ValueError("field host lies outside scope or is duplicated")
        seen.add(str(address))
        ports = host["open_ports"]
        if len(ports) > 65535 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("invalid field port list")
        coverage = host.get("tcp_coverage")
        if coverage not in ("all-65535", "top-1000-at-most", "top-100-at-most"):
            raise ValueError("invalid field coverage")
        clean_hosts.append({"address": str(address), "open_ports": sorted(set(ports)),
                            "tcp_coverage": coverage})
    files = payload.get("files")
    if not isinstance(files, list) or len(files) > 1024:
        raise ValueError("invalid evidence inventory")
    clean_files = []
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("invalid evidence inventory item")
        name = item.get("name")
        size = item.get("size")
        sha256 = item.get("sha256")
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", name) or
                name.startswith(".") or type(size) is not int or not 0 <= size <= 128 * 1024 * 1024 or
                not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256)):
            raise ValueError("invalid evidence inventory item")
        clean_files.append({"name": name, "size": size, "sha256": sha256})
    metrics = payload.get("metrics", {})
    if not isinstance(metrics, dict) or len(metrics) > 32:
        raise ValueError("invalid field metrics")
    clean_metrics = {key: value for key, value in metrics.items() if isinstance(key, str) and len(key) <= 48
                     and (type(value) is int and 0 <= value <= 16777216 or
                          isinstance(value, str) and len(value) <= 48)}
    finished_at = payload.get("finished_at", 0)
    if type(finished_at) is not int or (finished_at != 0 and not 946684800 <= finished_at <= 4102444800):
        raise ValueError("invalid field completion time")
    return {"mission_id": mission_id, "scope": str(scope), "interface": interface, "source_ip": str(source_ip),
            "profile": profile, "outcome": outcome, "context": {key: context[key] for key in
            ("project_id", "engagement_id", "operator_id")}, "summary_text": summary,
            "summary_sha256": digest, "hosts": clean_hosts, "files": clean_files, "metrics": clean_metrics,
            "finished_at": finished_at}


def import_field_report(workspace, project_id: str, payload: dict) -> dict:
    report = normalise_field_report(payload)
    hosts = report["hosts"]
    record = workspace.add_evidence({
        "id": "sightline-" + report["mission_id"], "project_id": project_id,
        "job_id": report["mission_id"], "kind": "sightline-field-report",
        "title": f"Sightline {report['profile']} assessment · {report['scope']}",
        "summary": (f"{report['outcome']} · {sum(bool(host['open_ports']) for host in hosts)} "
                    "hosts with open TCP · "
                    f"{report['metrics'].get('deep_hosts_checked', 0)} full-TCP hosts · "
                    "operator-imported; device origin unverified"),
        "captured_at_ms": report["finished_at"] * 1000 if report["finished_at"] > 0 else 0,
        "data": {"hosts": hosts, "scope": report["scope"], "interface": report["interface"],
                 "source_ip": report["source_ip"], "profile": report["profile"],
                 "outcome": report["outcome"], "metrics": report["metrics"],
                 "device_context": report["context"], "summary_text": report["summary_text"],
                 "summary_sha256": report["summary_sha256"], "file_inventory": report["files"],
                 "origin_verified": False}})
    workspace.add_audit_event({"project_id": project_id, "action": "sightline.report.imported",
                               "subject_id": report["mission_id"], "outcome": "accepted"})
    return record
