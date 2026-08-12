#!/usr/bin/env python3
import argparse
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path

STAGES = {
    "recon", "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "credential_use", "discovery",
    "lateral_movement", "collection", "exfiltration", "impact"
}
ACTIONS = {
    "scan", "exploit_public_service", "webshell_upload", "command_execution",
    "host_discovery", "network_discovery", "domain_discovery", "database_discovery",
    "devops_discovery", "cloud_discovery", "credential_dump", "credential_use",
    "lateral_movement", "data_collection", "cloud_collection", "data_staging",
    "ci_pipeline_execution", "command_and_control", "cleanup", "exfiltration"
}
EVIDENCE_FIELDS = ["evidence_id", "event_id", "stage"]
TIMELINE_FIELDS = ["step", "stage", "time_start", "time_end", "evidence_ids"]
IOC_FIELDS = ["type", "value", "first_seen", "last_seen", "related_asset", "evidence_ids"]
NODE_TYPES = {"ip", "host", "account", "bucket", "cluster", "database", "domain", "file", "network", "process", "service", "token"}
IOC_TYPES = {"ip", "domain", "file", "account", "token", "command"}

def scan_event_ids(logs_dir, artifacts_dir=None):
    ids = set()
    for path in logs_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    event_id = row.get("event_id")
                    if event_id:
                        ids.add(event_id)
        elif path.suffix == ".jsonl":
            with path.open("r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise SystemExit(f"{path}:{line_no} JSON parse error: {exc}") from exc
                    event_id = obj.get("event_id")
                    if event_id:
                        ids.add(event_id)
        elif path.suffix == ".log":
            pattern = re.compile(r"\bevent_id=([^\s]+)")
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    m = pattern.search(line)
                    if m:
                        ids.add(m.group(1))
    if artifacts_dir:
        index_path = Path(artifacts_dir) / "artifact_event_index.csv"
        if index_path.exists():
            with index_path.open("r", encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    event_id = row.get("event_id")
                    if event_id:
                        ids.add(event_id)
    return ids

def read_csv(path):
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return list(reader.fieldnames or []), rows

def parse_evidence_ids(value):
    if not value:
        return []
    return [x.strip() for x in re.split(r"[;,]", value) if x.strip()]

def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def main():
    parser = argparse.ArgumentParser(description="Validate enterprise trace build submission format.")
    parser.add_argument("submission", help="submission directory, not zip")
    parser.add_argument("--logs", required=True, help="logs directory from challenge package")
    parser.add_argument("--artifacts", help="artifacts directory from challenge package; defaults to sibling of logs")
    args = parser.parse_args()

    sub = Path(args.submission)
    logs = Path(args.logs)
    artifacts = Path(args.artifacts) if args.artifacts else logs.parent / "artifacts"
    required = ["manifest.json", "evidence.csv", "timeline.csv", "attack_graph.json", "ioc.csv"]
    missing = [name for name in required if not (sub / name).exists()]
    if missing:
        raise SystemExit(f"missing files: {', '.join(missing)}")

    try:
        manifest = json.loads((sub / "manifest.json").read_text(encoding="utf-8"))
        graph = json.loads((sub / "attack_graph.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"json parse error: {exc}") from exc

    known_event_ids = scan_event_ids(logs, artifacts)
    evidence_headers, evidence_rows = read_csv(sub / "evidence.csv")
    timeline_headers, timeline_rows = read_csv(sub / "timeline.csv")
    ioc_headers, ioc_rows = read_csv(sub / "ioc.csv")
    evidence_ids = set()
    event_ids = set()
    errors = []
    if not isinstance(manifest, dict):
        errors.append("manifest.json must be an object")
    else:
        required_manifest = {"team_id", "schema_version", "created_at"}
        if set(manifest) != required_manifest:
            errors.append("manifest.json fields must be exactly: team_id,schema_version,created_at")
        if not str(manifest.get("team_id") or "").strip():
            errors.append("manifest.json empty team_id")
        if manifest.get("schema_version") != "1.0":
            errors.append("manifest.json schema_version must be 1.0")
        created_at = parse_time(str(manifest.get("created_at") or ""))
        if created_at is None or created_at.utcoffset() is None:
            errors.append("manifest.json created_at must be timezone-aware ISO 8601")
    if evidence_headers != EVIDENCE_FIELDS:
        errors.append("evidence.csv invalid header")
    if not evidence_rows:
        errors.append("evidence.csv must contain at least one row")
    if timeline_headers != TIMELINE_FIELDS:
        errors.append("timeline.csv invalid header")
    if not timeline_rows:
        errors.append("timeline.csv must contain at least one row")
    if ioc_headers != IOC_FIELDS:
        errors.append("ioc.csv invalid header")
    if not ioc_rows:
        errors.append("ioc.csv must contain at least one row")
    for idx, row in enumerate(evidence_rows, 2):
        eid = (row.get("evidence_id") or "").strip()
        event_id = (row.get("event_id") or "").strip()
        stage = (row.get("stage") or "").strip()
        if not eid:
            errors.append(f"evidence.csv:{idx} empty evidence_id")
        if eid in evidence_ids:
            errors.append(f"evidence.csv:{idx} duplicate evidence_id {eid}")
        evidence_ids.add(eid)
        if not event_id:
            errors.append(f"evidence.csv:{idx} empty event_id")
        elif event_id in event_ids:
            errors.append(f"evidence.csv:{idx} duplicate event_id {event_id}")
        elif event_id not in known_event_ids:
            errors.append(f"evidence.csv:{idx} unknown event_id {event_id}")
        event_ids.add(event_id)
        if not stage or stage not in STAGES:
            errors.append(f"evidence.csv:{idx} invalid stage {stage}")

    timeline_steps = set()
    timeline_order = []
    for idx, row in enumerate(timeline_rows, 2):
        try:
            step = int(row.get("step", ""))
            if step <= 0 or step in timeline_steps:
                raise ValueError
            timeline_steps.add(step)
        except ValueError:
            errors.append(f"timeline.csv:{idx} invalid or duplicate step")
            step = 0
        if row.get("stage") not in STAGES:
            errors.append(f"timeline.csv:{idx} invalid stage")
        start = parse_time(row.get("time_start", ""))
        end = parse_time(row.get("time_end", ""))
        if start is None or start.utcoffset() is None:
            errors.append(f"timeline.csv:{idx} invalid time_start")
        if end is None or end.utcoffset() is None:
            errors.append(f"timeline.csv:{idx} invalid time_end")
        if start and end and start > end:
            errors.append(f"timeline.csv:{idx} time_start after time_end")
        if step and start:
            timeline_order.append((step, start))
        refs = parse_evidence_ids(row.get("evidence_ids", ""))
        if not refs or len(refs) != len(set(refs)):
            errors.append(f"timeline.csv:{idx} evidence_ids must be non-empty and unique")
        for evidence_id in refs:
            if evidence_id not in evidence_ids:
                errors.append(f"timeline.csv:{idx} references unknown evidence_id {evidence_id}")
    if timeline_steps and timeline_steps != set(range(1, len(timeline_steps) + 1)):
        errors.append("timeline.csv steps must be continuous from 1")
    ordered_times = [ts for _, ts in sorted(timeline_order)]
    if any(cur < prev for prev, cur in zip(ordered_times, ordered_times[1:])):
        errors.append("timeline.csv time must be non-decreasing by step")

    if not isinstance(graph, dict):
        errors.append("attack_graph.json must be an object")
        graph = {}
    elif set(graph) != {"schema_version", "incident_id", "nodes", "edges"}:
        errors.append("attack_graph.json top-level fields are invalid")
    if graph.get("schema_version") != "1.0" or not str(graph.get("incident_id") or "").strip():
        errors.append("attack_graph.json invalid schema_version or incident_id")
    nodes = graph.get("nodes", []) if isinstance(graph.get("nodes"), list) else []
    edges = graph.get("edges", []) if isinstance(graph.get("edges"), list) else []
    if not nodes:
        errors.append("attack_graph.json nodes must contain at least one node")
    if not edges:
        errors.append("attack_graph.json edges must contain at least one edge")
    node_ids = set()
    for idx, node in enumerate(nodes, 1):
        if not isinstance(node, dict):
            errors.append(f"attack_graph.json nodes[{idx}] is not an object")
            continue
        if set(node) != {"id", "type", "label"}:
            errors.append(f"attack_graph.json nodes[{idx}] invalid fields")
        node_id = str(node.get("id") or "")
        node_type = str(node.get("type") or "")
        if not node_id or node_id in node_ids:
            errors.append(f"attack_graph.json invalid or duplicate node id {node_id}")
        node_ids.add(node_id)
        if node_type not in NODE_TYPES or ":" not in node_id or node_id.split(":", 1)[0] != node_type or not node_id.split(":", 1)[1]:
            errors.append(f"attack_graph.json node {node_id} invalid type")
        if not str(node.get("label") or "").strip():
            errors.append(f"attack_graph.json node {node_id} empty label")
    edge_ids = set()
    for idx, edge in enumerate(edges, 1):
        if not isinstance(edge, dict):
            errors.append(f"attack_graph.json edges[{idx}] is not an object")
            continue
        required_edge = {"id", "from", "to", "action", "stage", "time_start", "time_end", "evidence_ids"}
        if set(edge) != required_edge:
            errors.append(f"attack_graph.json edges[{idx}] invalid fields")
        edge_id = str(edge.get("id") or "")
        if not edge_id or edge_id in edge_ids:
            errors.append(f"attack_graph.json duplicate edge id {edge_id}")
        edge_ids.add(edge_id)
        if edge.get("from") not in node_ids:
            errors.append(f"attack_graph.json edge {edge_id} references unknown from node")
        if edge.get("to") not in node_ids:
            errors.append(f"attack_graph.json edge {edge_id} references unknown to node")
        if edge.get("stage") not in STAGES:
            errors.append(f"attack_graph.json edge {edge_id} invalid stage")
        if edge.get("action") not in ACTIONS:
            errors.append(f"attack_graph.json edge {edge_id} invalid action")
        start = parse_time(str(edge.get("time_start") or ""))
        end = parse_time(str(edge.get("time_end") or ""))
        if start is None or end is None or start.utcoffset() is None or end.utcoffset() is None or start > end:
            errors.append(f"attack_graph.json edge {edge_id} invalid time window")
        refs = edge.get("evidence_ids", [])
        if not isinstance(refs, list) or not refs:
            errors.append(f"attack_graph.json edge {edge_id} evidence_ids must be non-empty and unique")
            refs = []
        elif any(not isinstance(value, str) or not value.strip() for value in refs):
            errors.append(f"attack_graph.json edge {edge_id} evidence_ids must contain non-empty strings")
            refs = []
        elif len(refs) != len(set(refs)):
            errors.append(f"attack_graph.json edge {edge_id} evidence_ids must be non-empty and unique")
        for evidence_id in refs:
            if evidence_id not in evidence_ids:
                errors.append(f"attack_graph.json edge {edge_id} references unknown evidence_id {evidence_id}")

    ioc_pairs = set()
    for idx, row in enumerate(ioc_rows, 2):
        ioc_type = (row.get("type") or "").strip().lower()
        value = (row.get("value") or "").strip().lower()
        if ioc_type not in IOC_TYPES or not value:
            errors.append(f"ioc.csv:{idx} invalid type or value")
        pair = (ioc_type, value)
        if pair in ioc_pairs:
            errors.append(f"ioc.csv:{idx} duplicate IOC")
        ioc_pairs.add(pair)
        first_seen = parse_time(row.get("first_seen", ""))
        last_seen = parse_time(row.get("last_seen", ""))
        if first_seen is None or last_seen is None or first_seen.utcoffset() is None or last_seen.utcoffset() is None or first_seen > last_seen:
            errors.append(f"ioc.csv:{idx} invalid time range")
        if not str(row.get("related_asset") or "").strip():
            errors.append(f"ioc.csv:{idx} empty related_asset")
        refs = parse_evidence_ids(row.get("evidence_ids", ""))
        if not refs or len(refs) != len(set(refs)):
            errors.append(f"ioc.csv:{idx} evidence_ids must be non-empty and unique")
        for evidence_id in refs:
            if evidence_id not in evidence_ids:
                errors.append(f"ioc.csv:{idx} references unknown evidence_id {evidence_id}")

    if errors:
        print("INVALID")
        for err in errors[:50]:
            print(f"- {err}")
        if len(errors) > 50:
            print(f"... {len(errors) - 50} more")
        return 1
    print("VALID")
    print(f"events scanned: {len(known_event_ids)}")
    print(f"evidence rows: {len(evidence_rows)}")
    print(f"graph nodes: {len(node_ids)}")
    print(f"graph edges: {len(edge_ids)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
