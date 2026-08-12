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
NODE_TYPES = {"ip", "host", "account", "bucket", "cluster", "database", "domain", "file", "network", "process", "service", "token"}
ACTIONS = {
    "scan", "exploit_public_service", "webshell_upload", "command_execution",
    "host_discovery", "network_discovery", "domain_discovery", "database_discovery",
    "devops_discovery", "cloud_discovery", "credential_dump", "credential_use",
    "lateral_movement", "data_collection", "cloud_collection", "data_staging",
    "ci_pipeline_execution", "command_and_control", "cleanup", "exfiltration"
}

def read_csv(path):
    with Path(path).open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return list(reader.fieldnames or []), rows

def parse_list(value):
    if not value:
        return []
    return [item.strip() for item in re.split(r"[;,]", value) if item.strip()]

def parse_time(value):
    try:
        parsed = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None

def main():
    parser = argparse.ArgumentParser(description="Build attack_graph.json from graph_nodes.csv and graph_edges.csv.")
    parser.add_argument("nodes_csv")
    parser.add_argument("edges_csv")
    parser.add_argument("output_json")
    parser.add_argument("--incident-id", default="build-final-2026")
    args = parser.parse_args()

    node_headers, node_rows = read_csv(args.nodes_csv)
    edge_headers, edge_rows = read_csv(args.edges_csv)
    errors = []
    if node_headers != ["node_id", "type", "label"]:
        errors.append("graph_nodes.csv header must be: node_id,type,label")
    if edge_headers != ["edge_id", "from", "to", "action", "stage", "time_start", "time_end", "evidence_ids"]:
        errors.append("graph_edges.csv header must be: edge_id,from,to,action,stage,time_start,time_end,evidence_ids")
    nodes = []
    node_ids = set()

    for idx, row in enumerate(node_rows, 2):
        node_id = (row.get("node_id") or "").strip()
        node_type = (row.get("type") or "").strip()
        label = (row.get("label") or node_id).strip()
        if not node_id:
            errors.append(f"{args.nodes_csv}:{idx} empty node_id")
            continue
        if node_id in node_ids:
            errors.append(f"{args.nodes_csv}:{idx} duplicate node_id {node_id}")
            continue
        if node_type not in NODE_TYPES:
            errors.append(f"{args.nodes_csv}:{idx} invalid type for {node_id}")
        if ":" not in node_id or node_id.split(":", 1)[0] != node_type or not node_id.split(":", 1)[1]:
            errors.append(f"{args.nodes_csv}:{idx} node_id must use type:value")
        if not label:
            errors.append(f"{args.nodes_csv}:{idx} empty label for {node_id}")
        node = {"id": node_id, "type": node_type, "label": label}
        nodes.append(node)
        node_ids.add(node_id)

    edges = []
    edge_ids = set()
    for idx, row in enumerate(edge_rows, 2):
        edge_id = (row.get("edge_id") or f"EDGE{idx-1:03d}").strip()
        src = (row.get("from") or "").strip()
        dst = (row.get("to") or "").strip()
        stage = (row.get("stage") or "").strip()
        action = (row.get("action") or "").strip()
        if edge_id in edge_ids:
            errors.append(f"{args.edges_csv}:{idx} duplicate edge_id {edge_id}")
        edge_ids.add(edge_id)
        if src not in node_ids:
            errors.append(f"{args.edges_csv}:{idx} edge {edge_id} references unknown from node {src}")
        if dst not in node_ids:
            errors.append(f"{args.edges_csv}:{idx} edge {edge_id} references unknown to node {dst}")
        if stage not in STAGES:
            errors.append(f"{args.edges_csv}:{idx} edge {edge_id} invalid stage {stage}")
        if action not in ACTIONS:
            errors.append(f"{args.edges_csv}:{idx} edge {edge_id} invalid action {action}")
        start = parse_time(row.get("time_start"))
        end = parse_time(row.get("time_end"))
        if start is None or end is None or start > end:
            errors.append(f"{args.edges_csv}:{idx} edge {edge_id} invalid time window")
        refs = parse_list(row.get("evidence_ids", ""))
        if not refs or len(refs) != len(set(refs)):
            errors.append(f"{args.edges_csv}:{idx} edge {edge_id} evidence_ids must be non-empty and unique")
        edge = {
            "id": edge_id,
            "from": src,
            "to": dst,
            "action": action,
            "stage": stage,
            "time_start": (row.get("time_start") or "").strip(),
            "time_end": (row.get("time_end") or "").strip(),
            "evidence_ids": refs,
        }
        edges.append(edge)

    if errors:
        print("INVALID GRAPH CSV")
        for err in errors[:50]:
            print(f"- {err}")
        if len(errors) > 50:
            print(f"... {len(errors) - 50} more")
        return 1

    graph = {
        "schema_version": "1.0",
        "incident_id": args.incident_id,
        "nodes": nodes,
        "edges": edges,
    }
    Path(args.output_json).write_text(json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output_json}")
    print(f"nodes: {len(nodes)}")
    print(f"edges: {len(edges)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
