#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

def safe_label(value):
    return str(value).replace('"', "'")

def safe_id(value):
    return re.sub(r"[^A-Za-z0-9_]", "_", value)

def main():
    parser = argparse.ArgumentParser(description="Render attack_graph.json to Mermaid flowchart.")
    parser.add_argument("graph")
    parser.add_argument("output")
    args = parser.parse_args()
    graph = json.loads(Path(args.graph).read_text(encoding="utf-8"))
    lines = ["flowchart LR"]
    for node in graph.get("nodes", []):
        nid = safe_id(node.get("id", "node"))
        label = safe_label(node.get("label") or node.get("id"))
        lines.append(f'  {nid}["{label}"]')
    for edge in graph.get("edges", []):
        src = safe_id(edge.get("from", ""))
        dst = safe_id(edge.get("to", ""))
        label = safe_label(edge.get("action", ""))
        lines.append(f'  {src} -->|"{label}"| {dst}')
    Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")

if __name__ == "__main__":
    main()
