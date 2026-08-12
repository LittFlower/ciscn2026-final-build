#!/usr/bin/env python3
"""Score submission correctness against source-derived attack facts.

Unlike score_submission.py, this module never reads reference/high_confidence.json.
Its oracle is independently tied to raw event IDs, source fields, and exact source
timestamps.  It intentionally favors atomic timeline steps and evidence closure.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from score_submission import (
    CHALLENGE_ROOT,
    canonical_ioc_key,
    collect_submission,
    maximum_weight_matching,
    parse_time,
    run_public_validator,
)
from source_integrity import (
    DEFAULT_SOURCE_MANIFEST,
    DEFAULT_SOURCE_ORACLE_LOCK,
    DEFAULT_SOURCE_PROVENANCE,
    read_source_oracle_lock,
    read_source_manifest,
    read_source_provenance,
    verify_artifact_sources,
    verify_environment_nodes,
    verify_source_oracle_lock,
    verify_source_manifest,
    verify_source_provenance,
)


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ORACLE = SCRIPT_DIR / "source_oracle.json"
WEIGHTS = {
    "format": 10,
    "evidence": 25,
    "stage": 10,
    "timeline": 15,
    "nodes": 10,
    "edges": 20,
    "ioc": 10,
}


@dataclass(frozen=True)
class SourceRange:
    start: datetime
    end: datetime


def source_integrity_issues(oracle: dict[str, Any]) -> list[str]:
    """Verify the reviewed raw corpus and its primary artifact records."""
    manifest = read_source_manifest(DEFAULT_SOURCE_MANIFEST)
    issues = verify_source_manifest(CHALLENGE_ROOT, manifest)
    try:
        oracle_lock = read_source_oracle_lock(DEFAULT_SOURCE_ORACLE_LOCK)
        issues.extend(verify_source_oracle_lock(oracle, oracle_lock))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        issues.append(f"source oracle lock invalid: {exc}")
    artifact_ids = {
        event_id for event_id in source_event_ids(oracle) if event_id.startswith("artifact-")
    }
    artifact_assertions = {
        item["event_id"]: item["fields"]
        for item in oracle.get("artifact_assertions", [])
    }
    issues.extend(
        verify_artifact_sources(CHALLENGE_ROOT, artifact_ids, artifact_assertions)
    )
    issues.extend(verify_environment_nodes(CHALLENGE_ROOT, oracle["nodes"]))
    try:
        records = load_source_records(source_event_ids(oracle))
        provenance = read_source_provenance(DEFAULT_SOURCE_PROVENANCE)
        issues.extend(
            verify_source_provenance(records, source_event_ids(oracle), provenance)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        issues.append(f"source provenance invalid: {exc}")
    return issues


def parse_refs(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if not isinstance(value, str):
        return []
    return [item.strip() for item in re.split(r"[;,]", value) if item.strip()]


def read_oracle(path: Path) -> dict[str, Any]:
    oracle = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "oracle_version",
        "timeline_steps",
        "nodes",
        "edges",
        "iocs",
        "source_assertions",
    }
    missing = required.difference(oracle)
    if missing:
        raise ValueError(f"oracle missing fields: {', '.join(sorted(missing))}")
    if sum(WEIGHTS.values()) != 100:
        raise AssertionError("component weights must total 100")
    for collection_name in ("timeline_steps", "nodes", "edges", "iocs", "source_assertions"):
        if not isinstance(oracle[collection_name], list):
            raise ValueError(f"oracle {collection_name} must be a list")

    for step in oracle["timeline_steps"]:
        if not isinstance(step, dict):
            raise ValueError("oracle timeline steps must be objects")
        if not isinstance(step.get("stage"), str) or not step["stage"]:
            raise ValueError(f"oracle timeline step {step.get('id')} needs a stage")
        if not isinstance(step.get("event_ids"), list) or not step["event_ids"]:
            raise ValueError(f"oracle timeline step {step.get('id')} needs event_ids")
    timeline_ids = [item.get("id") for item in oracle["timeline_steps"]]
    if (
        not timeline_ids
        or any(not isinstance(step_id, str) or not step_id for step_id in timeline_ids)
        or len(timeline_ids) != len(set(timeline_ids))
    ):
        raise ValueError("oracle timeline step IDs must be present and unique")
    source_events = [event_id for item in oracle["timeline_steps"] for event_id in item["event_ids"]]
    duplicates = sorted(event_id for event_id, count in Counter(source_events).items() if count > 1)
    if duplicates:
        raise ValueError(f"oracle assigns events to multiple timeline steps: {', '.join(duplicates)}")
    if not source_events:
        raise ValueError("oracle has no source events")
    canonical = set(source_events)
    negative = set(oracle.get("negative_events", []))
    overlap = canonical.intersection(negative)
    if overlap:
        raise ValueError(
            "oracle event cannot be both canonical and negative: "
            + ", ".join(sorted(overlap))
        )
    node_ids = []
    for node in oracle["nodes"]:
        if not isinstance(node, dict):
            raise ValueError("oracle nodes must be objects")
        node_id = node.get("id")
        node_type = node.get("type")
        if not isinstance(node_id, str) or not node_id or not isinstance(node_type, str) or not node_type:
            raise ValueError("oracle nodes need nonempty id and type")
        node_ids.append(node_id)
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("oracle node IDs must be unique")
    node_id_set = set(node_ids)
    edge_ids: list[str] = []
    edge_keys: list[tuple[str, str, str, str]] = []
    for collection_name in ("edges", "iocs"):
        for item in oracle[collection_name]:
            if not isinstance(item, dict):
                raise ValueError(f"oracle {collection_name} items must be objects")
            event_ids = item.get("event_ids")
            if not isinstance(event_ids, list) or not event_ids:
                raise ValueError(
                    f"oracle {collection_name} item {item.get('id') or item.get('value')} "
                    "must contain event_ids"
                )
            unknown = set(event_ids).difference(canonical)
            if unknown:
                raise ValueError(
                    f"oracle {collection_name} item {item.get('id') or item.get('value')} "
                    f"references noncanonical events: {', '.join(sorted(unknown))}"
                )
            if collection_name == "edges":
                edge_id = item.get("id")
                required_edge_fields = ("from", "to", "action", "stage")
                if not isinstance(edge_id, str) or not edge_id:
                    raise ValueError("oracle edges need nonempty IDs")
                if any(not isinstance(item.get(field), str) or not item[field] for field in required_edge_fields):
                    raise ValueError(f"oracle edge {edge_id} has an empty semantic field")
                if item["from"] not in node_id_set or item["to"] not in node_id_set:
                    raise ValueError(f"oracle edge {edge_id} references an unknown node")
                edge_ids.append(edge_id)
                edge_keys.append(
                    (item["from"], item["to"], item["action"], item["stage"])
                )
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("oracle edge IDs must be unique")
    if len(edge_keys) != len(set(edge_keys)):
        raise ValueError("oracle edge semantic keys must be unique")
    ioc_keys = [
        canonical_ioc_key(item.get("type"), item.get("value"))
        for item in oracle["iocs"]
    ]
    if any(not ioc_type or not value for ioc_type, value in ioc_keys):
        raise ValueError("oracle contains an empty IOC type or value")
    if len(ioc_keys) != len(set(ioc_keys)):
        raise ValueError("oracle contains duplicate canonical IOC values")
    source_assertion_ids: set[str] = set()
    for assertion in oracle["source_assertions"]:
        if not isinstance(assertion, dict):
            raise ValueError("source assertions must be objects")
        event_id = assertion.get("event_id")
        fields = assertion.get("fields")
        if event_id not in canonical.union(negative):
            raise ValueError(f"source assertion references unknown event: {event_id}")
        if not isinstance(fields, dict) or not fields:
            raise ValueError(f"source assertion for {event_id} must contain fields")
        if event_id in source_assertion_ids:
            raise ValueError(f"duplicate source assertion: {event_id}")
        source_assertion_ids.add(event_id)
    negative_assertion_ids: set[str] = set()
    for assertion in oracle.get("negative_assertions", []):
        event_id = assertion.get("event_id")
        fields = assertion.get("fields", {})
        raw_contains = assertion.get("raw_contains")
        if event_id not in negative:
            raise ValueError(f"negative assertion references non-negative event: {event_id}")
        if event_id in negative_assertion_ids:
            raise ValueError(f"duplicate negative assertion: {event_id}")
        negative_assertion_ids.add(event_id)
        if not isinstance(fields, dict):
            raise ValueError(f"negative assertion fields for {event_id} must be an object")
        if raw_contains is not None and not isinstance(raw_contains, str):
            raise ValueError(f"negative assertion raw_contains for {event_id} must be a string")
        if not fields and not raw_contains:
            raise ValueError(
                f"negative assertion for {event_id} needs fields or raw_contains"
            )
    missing_negative_assertions = negative.difference(negative_assertion_ids)
    if missing_negative_assertions:
        raise ValueError(
            "negative events lack semantic assertions: "
            + ", ".join(sorted(missing_negative_assertions))
        )
    artifact_assertion_ids: set[str] = set()
    for assertion in oracle.get("artifact_assertions", []):
        event_id = assertion.get("event_id")
        fields = assertion.get("fields")
        if event_id not in canonical or not str(event_id).startswith("artifact-"):
            raise ValueError(f"artifact assertion references noncanonical artifact: {event_id}")
        if event_id in artifact_assertion_ids:
            raise ValueError(f"duplicate artifact assertion: {event_id}")
        artifact_assertion_ids.add(event_id)
        if not isinstance(fields, dict) or not fields:
            raise ValueError(f"artifact assertion for {event_id} must contain fields")
    caveats = oracle.get("claim_caveats", [])
    if not isinstance(caveats, list):
        raise ValueError("oracle claim_caveats must be a list")
    caveat_ids: set[str] = set()
    valid_caveat_classes = {"direct", "corroborative", "inferred", "alias"}
    for caveat in caveats:
        if not isinstance(caveat, dict) or not all(
            str(caveat.get(field) or "").strip()
            for field in ("id", "scope", "classification", "reason")
        ):
            raise ValueError("each oracle claim caveat needs id, scope, classification, and reason")
        if caveat["id"] in caveat_ids:
            raise ValueError(f"duplicate oracle claim caveat: {caveat['id']}")
        if caveat["classification"] not in valid_caveat_classes:
            raise ValueError(
                f"invalid oracle claim caveat classification: {caveat['classification']}"
            )
        caveat_ids.add(caveat["id"])
    return oracle


def source_event_ids(oracle: dict[str, Any]) -> set[str]:
    ids = {event_id for step in oracle["timeline_steps"] for event_id in step["event_ids"]}
    ids.update(oracle.get("negative_events", []))
    ids.update(assertion["event_id"] for assertion in oracle["source_assertions"])
    ids.update(
        assertion["event_id"] for assertion in oracle.get("negative_assertions", [])
    )
    ids.update(
        assertion["event_id"] for assertion in oracle.get("artifact_assertions", [])
    )
    return ids


def load_source_records(
    required_ids: set[str], challenge_root: Path = CHALLENGE_ROOT
) -> dict[str, dict[str, Any]]:
    """Index oracle-related raw records and fail closed on duplicate IDs."""
    records: dict[str, dict[str, Any]] = {}
    origins: dict[str, str] = {}

    def add_record(event_id: str, row: dict[str, Any], origin: str) -> None:
        if event_id in records:
            raise ValueError(
                f"duplicate source event {event_id}: {origins[event_id]} and {origin}"
            )
        record = dict(row)
        record["__source_origin"] = origin
        records[event_id] = record
        origins[event_id] = origin

    artifact_index = challenge_root / "artifacts" / "artifact_event_index.csv"
    if artifact_index.exists():
        with artifact_index.open("r", encoding="utf-8", newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), 2):
                event_id = row.get("event_id")
                if event_id in required_ids:
                    add_record(
                        event_id,
                        dict(row),
                        f"{artifact_index.relative_to(challenge_root)}:{row_number}",
                    )

    logs = challenge_root / "logs"
    for path in (logs.rglob("*") if logs.exists() else []):
        if not path.is_file():
            continue
        if path.suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as handle:
                for row_number, row in enumerate(csv.DictReader(handle), 2):
                    event_id = row.get("event_id")
                    if event_id in required_ids:
                        add_record(
                            event_id,
                            dict(row),
                            f"{path.relative_to(challenge_root)}:{row_number}",
                        )
        elif path.suffix == ".jsonl":
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    event_id = row.get("event_id")
                    if event_id in required_ids:
                        add_record(
                            event_id,
                            row,
                            f"{path.relative_to(challenge_root)}:{line_number}",
                        )
        elif path.suffix == ".log":
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    event_match = re.search(r"\bevent_id=([^\s]+)", line)
                    time_match = re.search(r"\b(?:time|timestamp)=([^\s]+)", line)
                    if event_match is None or time_match is None:
                        continue
                    event_id = event_match.group(1)
                    if event_id in required_ids:
                        add_record(
                            event_id,
                            {
                                "event_id": event_id,
                                "timestamp": time_match.group(1),
                                "raw_line": line.strip(),
                            },
                            f"{path.relative_to(challenge_root)}:{line_number}",
                        )
    return records


def source_timestamp(record: dict[str, Any]) -> datetime | None:
    return parse_time(record.get("timestamp") or record.get("time"))


def build_source_ranges(
    oracle: dict[str, Any], records: dict[str, dict[str, Any]]
) -> tuple[dict[str, SourceRange], list[str]]:
    issues: list[str] = []
    ranges: dict[str, SourceRange] = {}
    for event_id in source_event_ids(oracle):
        record = records.get(event_id)
        timestamp = source_timestamp(record or {})
        if timestamp is None:
            issues.append(f"missing source record or timestamp: {event_id}")
            continue
        ranges[event_id] = SourceRange(timestamp, timestamp)

    def check_assertions(items: list[dict[str, Any]], kind: str) -> None:
        for assertion in items:
            event_id = assertion["event_id"]
            record = records.get(event_id, {})
            for field, expected in assertion.get("fields", {}).items():
                actual = str(record.get(field, ""))
                if actual != str(expected):
                    issues.append(
                        f"{kind} assertion failed for {event_id}.{field}: "
                        f"expected {expected!r}, found {actual!r}"
                    )
            raw_contains = assertion.get("raw_contains")
            if raw_contains and raw_contains not in str(record.get("raw_line", "")):
                issues.append(
                    f"{kind} assertion failed for {event_id}.raw_contains: "
                    f"missing {raw_contains!r}"
                )

    check_assertions(oracle["source_assertions"], "source")
    check_assertions(oracle.get("negative_assertions", []), "negative")
    previous_step_id: str | None = None
    previous_start: datetime | None = None
    for step in oracle["timeline_steps"]:
        if any(event_id not in ranges for event_id in step["event_ids"]):
            continue
        step_range = event_range(step["event_ids"], ranges)
        if previous_start is not None and step_range.start < previous_start:
            issues.append(
                f"timeline step {step['id']} starts before prior declared step "
                f"{previous_step_id}"
            )
        previous_step_id = step["id"]
        previous_start = step_range.start
    return ranges, issues


def event_range(event_ids: list[str], source_ranges: dict[str, SourceRange]) -> SourceRange:
    points = [source_ranges[event_id].start for event_id in event_ids]
    return SourceRange(min(points), max(points))


def canonical_events(oracle: dict[str, Any]) -> set[str]:
    return {event_id for step in oracle["timeline_steps"] for event_id in step["event_ids"]}


def canonical_stages(oracle: dict[str, Any]) -> dict[str, str]:
    return {
        event_id: step["stage"]
        for step in oracle["timeline_steps"]
        for event_id in step["event_ids"]
    }


def event_id_to_candidate_evidence(candidate: dict[str, Any]) -> dict[str, str]:
    return {
        event_id: item["evidence_id"]
        for event_id, item in candidate["event_to_evidence"].items()
    }


def f1(expected: set[str], actual: set[str]) -> float:
    if not expected and not actual:
        return 1.0
    if not expected or not actual:
        return 0.0
    overlap = len(expected.intersection(actual))
    precision = overlap / len(actual)
    recall = overlap / len(expected)
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def range_score(actual_start: datetime | None, actual_end: datetime | None, expected: SourceRange) -> float:
    if actual_start is None or actual_end is None:
        return 0.0
    return 1.0 if actual_start == expected.start and actual_end == expected.end else 0.0


def row_events(row: dict[str, Any]) -> set[str]:
    return set(row.get("evidence_event_ids", set()))


def score_timeline(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    source_ranges: dict[str, SourceRange],
) -> tuple[float, list[str], list[str]]:
    expected_steps = oracle["timeline_steps"]
    candidate_rows = candidate["timeline"]
    matched: list[str] = []
    issues: list[str] = []

    event_to_step = {
        event_id: step["id"]
        for step in expected_steps
        for event_id in step["event_ids"]
    }
    cited_events = set().union(*(row_events(row) for row in candidate_rows)) if candidate_rows else set()
    uncited = canonical_events(oracle).difference(cited_events)
    if uncited:
        issues.append(f"timeline leaves {len(uncited)} canonical events uncited: {', '.join(sorted(uncited))}")

    for row in candidate_rows:
        step_ids = {event_to_step[event_id] for event_id in row_events(row) if event_id in event_to_step}
        if len(step_ids) > 1:
            issues.append(
                f"timeline row {row['step']} mixes atomic source steps: {', '.join(sorted(step_ids))}"
            )

    scores: list[list[float]] = []
    for step in expected_steps:
        expected_events = set(step["event_ids"])
        expected_range = event_range(step["event_ids"], source_ranges)
        row_scores: list[float] = []
        for row in candidate_rows:
            evidence_score = f1(expected_events, row_events(row))
            stage_score = 1.0 if row["stage"] == step["stage"] else 0.0
            time_component = range_score(row["start"], row["end"], expected_range)
            row_scores.append(0.50 * evidence_score + 0.25 * stage_score + 0.25 * time_component)
        scores.append(row_scores)
    assignments = {
        step_index: (row_index, score)
        for step_index, row_index, score in maximum_weight_matching(scores)
    }
    total = 0.0
    for index, step in enumerate(expected_steps):
        assignment = assignments.get(index)
        score = assignment[1] if assignment else 0.0
        total += score
        if score < 1.0:
            issues.append(f"missing or non-atomic timeline step {step['id']}")
        else:
            matched.append(step["id"])

    closure = 1.0 - len(uncited) / len(canonical_events(oracle))
    complete_rows = {
        assignment[0]
        for assignment in assignments.values()
        if assignment[1] == 1.0
    }
    noncanonical_rows = [
        str(row["step"])
        for index, row in enumerate(candidate_rows)
        if index not in complete_rows
    ]
    if noncanonical_rows:
        issues.append(
            "timeline has noncanonical or duplicate rows: "
            + ", ".join(noncanonical_rows)
        )
    precision = len(complete_rows) / len(candidate_rows) if candidate_rows else 0.0
    coverage = (total / len(expected_steps) if expected_steps else 0.0) * closure
    return coverage * precision, matched, issues


def score_nodes(
    oracle: dict[str, Any], candidate: dict[str, Any]
) -> tuple[float, list[str], list[str]]:
    expected = {node["id"]: node["type"] for node in oracle["nodes"]}
    actual = {
        str(node.get("id") or ""): str(node.get("type") or "")
        for node in candidate["nodes"]
        if str(node.get("id") or "")
    }
    matching = {node_id for node_id, node_type in expected.items() if actual.get(node_id) == node_type}
    missing = sorted(set(expected).difference(matching))
    extra = sorted(set(actual).difference(expected))
    recall = len(matching) / len(expected) if expected else 0.0
    precision = len(matching) / len(actual) if actual else 0.0
    issues = []
    if missing:
        issues.append(f"missing canonical nodes: {', '.join(missing)}")
    if extra:
        issues.append(f"unsupported extra nodes: {', '.join(extra)}")
    return recall * precision, sorted(matching), issues


def edge_key(edge: dict[str, Any]) -> tuple[str, str, str, str]:
    return (edge["from"], edge["to"], edge["action"], edge["stage"])


def score_edges(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    source_ranges: dict[str, SourceRange],
) -> tuple[float, list[str], list[str]]:
    expected_edges = oracle["edges"]
    candidate_edges = candidate["edges"]
    matched: list[str] = []
    issues: list[str] = []
    canonical_keys = {edge_key(edge) for edge in expected_edges}

    scores: list[list[float]] = []
    for edge in expected_edges:
        expected_events = set(edge["event_ids"])
        expected_range = event_range(edge["event_ids"], source_ranges)
        row_scores: list[float] = []
        for candidate_edge in candidate_edges:
            if edge_key(candidate_edge) != edge_key(edge):
                row_scores.append(0.0)
                continue
            evidence_score = f1(expected_events, row_events(candidate_edge))
            time_component = range_score(
                candidate_edge["start"], candidate_edge["end"], expected_range
            )
            row_scores.append(0.70 * evidence_score + 0.30 * time_component)
        scores.append(row_scores)
    assignments = {
        edge_index: (candidate_index, score)
        for edge_index, candidate_index, score in maximum_weight_matching(scores)
    }
    total = 0.0
    for index, edge in enumerate(expected_edges):
        assignment = assignments.get(index)
        score = assignment[1] if assignment else 0.0
        total += score
        if score < 1.0:
            issues.append(f"missing or unsupported graph edge {edge['id']}")
        else:
            matched.append(edge["id"])

    extras = [
        edge["id"] or f"row-{edge['row']}"
        for edge in candidate_edges
        if edge_key(edge) not in canonical_keys
    ]
    if extras:
        issues.append(f"unsupported graph edges: {', '.join(extras)}")
    recall = total / len(expected_edges) if expected_edges else 0.0
    complete_edges = {
        assignment[0]
        for assignment in assignments.values()
        if assignment[1] == 1.0
    }
    incomplete = [
        edge["id"] or f"row-{edge['row']}"
        for index, edge in enumerate(candidate_edges)
        if index not in complete_edges
    ]
    if incomplete:
        issues.append(
            "incomplete, duplicate, or unsupported graph edges: "
            + ", ".join(incomplete)
        )
    precision = len(complete_edges) / len(candidate_edges) if candidate_edges else 0.0
    return recall * precision, matched, issues


def source_ioc_range(
    item: dict[str, Any], source_ranges: dict[str, SourceRange]
) -> SourceRange:
    return event_range(item["event_ids"], source_ranges)


def score_iocs(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    source_ranges: dict[str, SourceRange],
) -> tuple[float, list[str], list[str]]:
    expected_iocs = oracle["iocs"]
    candidate_iocs = candidate["iocs"]
    scores: list[list[float]] = []
    for item in expected_iocs:
        expected_key = canonical_ioc_key(item["type"], item["value"])
        expected_range = source_ioc_range(item, source_ranges)
        expected_events = set(item["event_ids"])
        expected_assets = set(item["related_assets"])
        row_scores: list[float] = []
        for actual in candidate_iocs:
            if canonical_ioc_key(actual["type"], actual["value"]) != expected_key:
                row_scores.append(0.0)
                continue
            evidence_score = f1(expected_events, row_events(actual))
            time_component = range_score(actual["start"], actual["end"], expected_range)
            asset_score = f1(expected_assets, actual["assets"])
            row_scores.append(
                0.45 * evidence_score + 0.30 * time_component + 0.25 * asset_score
            )
        scores.append(row_scores)
    assignments = {
        expected_index: (candidate_index, score)
        for expected_index, candidate_index, score in maximum_weight_matching(scores)
    }
    total = 0.0
    matched: list[str] = []
    issues: list[str] = []
    for index, item in enumerate(expected_iocs):
        assignment = assignments.get(index)
        score = assignment[1] if assignment else 0.0
        total += score
        if assignment is None:
            issues.append(f"missing IOC {item['type']}:{item['value']}")
            continue
        if score < 1.0:
            issues.append(f"incomplete IOC {item['type']}:{item['value']}")
        else:
            matched.append(f"{item['type']}:{item['value']}")

    complete_candidate_indices = {
        assignment[0]
        for assignment in assignments.values()
        if assignment[1] == 1.0
    }
    noncanonical_candidates = [
        f"{item['type']}:{item['value']}"
        for index, item in enumerate(candidate_iocs)
        if index not in complete_candidate_indices
    ]
    if noncanonical_candidates:
        issues.append(
            "incomplete, duplicate, or unsupported IOCs: "
            + ", ".join(noncanonical_candidates)
        )
    recall = total / len(expected_iocs) if expected_iocs else 0.0
    precision = (
        len(complete_candidate_indices) / len(candidate_iocs)
        if candidate_iocs
        else 0.0
    )
    return recall * precision, matched, issues


def score_correctness(submission: Path, oracle: dict[str, Any]) -> dict[str, Any]:
    integrity_issues = source_integrity_issues(oracle)
    if integrity_issues:
        raise ValueError("source integrity invalid: " + "; ".join(integrity_issues))
    records = load_source_records(source_event_ids(oracle))
    source_ranges, oracle_issues = build_source_ranges(oracle, records)
    if oracle_issues:
        raise ValueError("source oracle invalid: " + "; ".join(oracle_issues))

    validator_passed, validator_output = run_public_validator(submission)
    candidate, parse_errors = collect_submission(submission)
    expected_events = canonical_events(oracle)
    expected_stages = canonical_stages(oracle)
    candidate_events = set(candidate["event_to_evidence"])
    matched_events = candidate_events.intersection(expected_events)
    extra_events = candidate_events.difference(expected_events)
    negative_events = candidate_events.intersection(set(oracle.get("negative_events", [])))
    correct_stages = {
        event_id
        for event_id in matched_events
        if candidate["event_to_evidence"][event_id]["stage"] == expected_stages[event_id]
    }

    evidence_recall = len(matched_events) / len(expected_events)
    evidence_precision = len(matched_events) / len(candidate_events) if candidate_events else 0.0
    stage_recall = len(correct_stages) / len(expected_events)
    timeline_ratio, timeline_matched, timeline_issues = score_timeline(
        oracle, candidate, source_ranges
    )
    node_ratio, node_matched, node_issues = score_nodes(oracle, candidate)
    edge_ratio, edge_matched, edge_issues = score_edges(oracle, candidate, source_ranges)
    ioc_ratio, ioc_matched, ioc_issues = score_iocs(oracle, candidate, source_ranges)

    components = {
        "format": {
            "max": WEIGHTS["format"],
            "score": float(WEIGHTS["format"]) if validator_passed else 0.0,
        },
        "evidence": {
            "max": WEIGHTS["evidence"],
            "score": WEIGHTS["evidence"] * evidence_recall * evidence_precision,
            "coverage": evidence_recall,
            "precision": evidence_precision,
        },
        "stage": {
            "max": WEIGHTS["stage"],
            "score": WEIGHTS["stage"] * stage_recall,
            "coverage": stage_recall,
        },
        "timeline": {
            "max": WEIGHTS["timeline"],
            "score": WEIGHTS["timeline"] * timeline_ratio,
            "coverage": timeline_ratio,
        },
        "nodes": {
            "max": WEIGHTS["nodes"],
            "score": WEIGHTS["nodes"] * node_ratio,
            "coverage": node_ratio,
        },
        "edges": {
            "max": WEIGHTS["edges"],
            "score": WEIGHTS["edges"] * edge_ratio,
            "coverage": edge_ratio,
        },
        "ioc": {
            "max": WEIGHTS["ioc"],
            "score": WEIGHTS["ioc"] * ioc_ratio,
            "coverage": ioc_ratio,
        },
    }
    semantic_score = sum(component["score"] for component in components.values())
    return {
        "oracle_version": oracle["oracle_version"],
        "submission": str(submission),
        "validator": {"passed": validator_passed, "output": validator_output},
        "source_records": {
            "expected_events": len(expected_events),
            "resolved_events": len(source_ranges),
            "assertions": len(oracle["source_assertions"])
            + len(oracle.get("negative_assertions", []))
            + len(oracle.get("artifact_assertions", [])),
            "source_manifest": "verified",
            "source_oracle_lock": "verified",
            "source_provenance_records": len(source_event_ids(oracle)),
            "verified_artifact_records": sum(
                event_id.startswith("artifact-") for event_id in source_event_ids(oracle)
            ),
        },
        "score": semantic_score if validator_passed else 0.0,
        "diagnostic_semantic_score": semantic_score,
        "components": components,
        "counts": {
            "candidate_evidence": len(candidate_events),
            "matched_evidence": len(matched_events),
            "correct_stage_evidence": len(correct_stages),
            "extra_evidence": len(extra_events),
            "negative_evidence": len(negative_events),
            "canonical_timeline_steps": len(oracle["timeline_steps"]),
            "candidate_timeline_steps": len(candidate["timeline"]),
            "canonical_edges": len(oracle["edges"]),
            "candidate_edges": len(candidate["edges"]),
            "canonical_iocs": len(oracle["iocs"]),
            "candidate_iocs": len(candidate["iocs"]),
        },
        "issues": {
            "parse": parse_errors,
            "evidence": [
                f"wrong source-derived stage: {event_id} "
                f"expected {expected_stages[event_id]}, found "
                f"{candidate['event_to_evidence'][event_id]['stage']}"
                for event_id in sorted(matched_events.difference(correct_stages))
            ]
            + ([f"unexpected evidence: {', '.join(sorted(extra_events))}"] if extra_events else [])
            + (
                [f"known-negative evidence: {', '.join(sorted(negative_events))}"]
                if negative_events
                else []
            ),
            "timeline": timeline_issues,
            "nodes": node_issues,
            "edges": edge_issues,
            "iocs": ioc_issues,
        },
        "matched": {
            "timeline": timeline_matched,
            "nodes": node_matched,
            "edges": edge_matched,
            "iocs": ioc_matched,
        },
        "source_caveats": oracle.get("claim_caveats", []),
    }


def write_oracle_submission(
    oracle: dict[str, Any],
    source_ranges: dict[str, SourceRange],
    output: Path,
    force: bool,
) -> None:
    required = ["manifest.json", "evidence.csv", "timeline.csv", "attack_graph.json", "ioc.csv"]
    output.mkdir(parents=True, exist_ok=True)
    existing = [name for name in required if (output / name).exists()]
    if existing and not force:
        raise ValueError(f"target already contains {', '.join(existing)}")

    stages = canonical_stages(oracle)
    ordered_events = [
        event_id for step in oracle["timeline_steps"] for event_id in step["event_ids"]
    ]
    evidence_ids = {
        event_id: f"E{index:03d}" for index, event_id in enumerate(ordered_events, 1)
    }
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "team_id": "oracle-test",
                "schema_version": "1.0",
                "created_at": "2026-08-12T16:00:00+08:00",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    def write_csv(name: str, fields: list[str], rows: list[dict[str, str]]) -> None:
        with (output / name).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    write_csv(
        "evidence.csv",
        ["evidence_id", "event_id", "stage"],
        [
            {
                "evidence_id": evidence_ids[event_id],
                "event_id": event_id,
                "stage": stages[event_id],
            }
            for event_id in ordered_events
        ],
    )
    timeline_rows = []
    for index, step in enumerate(oracle["timeline_steps"], 1):
        span = event_range(step["event_ids"], source_ranges)
        timeline_rows.append(
            {
                "step": str(index),
                "stage": step["stage"],
                "time_start": span.start.isoformat(),
                "time_end": span.end.isoformat(),
                "evidence_ids": ";".join(evidence_ids[event_id] for event_id in step["event_ids"]),
            }
        )
    write_csv(
        "timeline.csv",
        ["step", "stage", "time_start", "time_end", "evidence_ids"],
        timeline_rows,
    )
    graph = {
        "schema_version": "1.0",
        "incident_id": "source-oracle-test",
        "nodes": oracle["nodes"],
        "edges": [
            {
                "id": edge["id"],
                "from": edge["from"],
                "to": edge["to"],
                "action": edge["action"],
                "stage": edge["stage"],
                "time_start": event_range(edge["event_ids"], source_ranges).start.isoformat(),
                "time_end": event_range(edge["event_ids"], source_ranges).end.isoformat(),
                "evidence_ids": [evidence_ids[event_id] for event_id in edge["event_ids"]],
            }
            for edge in oracle["edges"]
        ],
    }
    (output / "attack_graph.json").write_text(
        json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(
        "ioc.csv",
        ["type", "value", "first_seen", "last_seen", "related_asset", "evidence_ids"],
        [
            {
                "type": item["type"],
                "value": item["value"],
                "first_seen": source_ioc_range(item, source_ranges).start.isoformat(),
                "last_seen": source_ioc_range(item, source_ranges).end.isoformat(),
                "related_asset": ";".join(item["related_assets"]),
                "evidence_ids": ";".join(evidence_ids[event_id] for event_id in item["event_ids"]),
            }
            for item in oracle["iocs"]
        ],
    )


def compact(values: list[str], limit: int = 5) -> str:
    if not values:
        return "none"
    shown = ", ".join(values[:limit])
    return shown if len(values) <= limit else f"{shown} … (+{len(values) - limit})"


def print_report(report: dict[str, Any]) -> None:
    print(f"Source correctness benchmark v{report['oracle_version']} — {report['submission']}")
    print(f"Public format validator: {'PASS' if report['validator']['passed'] else 'FAIL'}")
    source_records = report["source_records"]
    print(
        "Raw source/oracle/provenance locks: VERIFIED "
        f"({source_records['source_provenance_records']} records bound; "
        f"{source_records['verified_artifact_records']} primary artifact records reconciled)"
    )
    for name in ("format", "evidence", "stage", "timeline", "nodes", "edges", "ioc"):
        component = report["components"][name]
        coverage = component.get("coverage")
        suffix = f" coverage={coverage:.1%}" if coverage is not None else ""
        print(f"  {name:<9} {component['score']:6.2f} / {component['max']:>2}{suffix}")
    print(f"Source correctness score: {report['score']:.2f} / 100.00")
    counts = report["counts"]
    print(
        f"Evidence: {counts['correct_stage_evidence']}/{counts['matched_evidence']} "
        f"correct source-derived stages; {counts['extra_evidence']} extra."
    )
    if report["source_caveats"]:
        print(
            "Source-correlation caveats: "
            + ", ".join(
                f"{item['scope']} ({item['classification']})"
                for item in report["source_caveats"]
            )
        )
    for category in ("evidence", "timeline", "nodes", "edges", "iocs"):
        issues = report["issues"][category]
        if issues:
            print(f"{category} issues: {compact(issues)}")
    if not report["validator"]["passed"]:
        print(f"Validator output: {report['validator']['output']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Score submission correctness against source-derived raw-event facts."
    )
    parser.add_argument("submission", nargs="?", type=Path, help="submission directory")
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--json", dest="json_report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write-oracle-submission", type=Path, metavar="DIR")
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        oracle = read_oracle(args.oracle)
        integrity_issues = source_integrity_issues(oracle)
        records = load_source_records(source_event_ids(oracle))
        source_ranges, oracle_issues = build_source_ranges(oracle, records)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load source oracle: {exc}") from exc
    if oracle_issues:
        print("SOURCE ORACLE INVALID")
        for issue in oracle_issues:
            print(f"- {issue}")
        return 1
    if integrity_issues:
        print("SOURCE INTEGRITY INVALID")
        for issue in integrity_issues:
            print(f"- {issue}")
        return 1

    if args.write_oracle_submission:
        try:
            write_oracle_submission(oracle, source_ranges, args.write_oracle_submission, args.force)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"cannot write oracle submission: {exc}") from exc
        print(f"Wrote source-oracle submission to {args.write_oracle_submission}")

    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="source-oracle-") as temp_dir:
            submission = Path(temp_dir)
            write_oracle_submission(oracle, source_ranges, submission, force=False)
            report = score_correctness(submission, oracle)
        print_report(report)
        return 0 if report["validator"]["passed"] and abs(report["score"] - 100.0) < 0.001 else 1

    if args.submission is None:
        return 0 if args.write_oracle_submission else 2
    try:
        report = score_correctness(args.submission, oracle)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot score submission: {exc}") from exc
    print_report(report)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote detailed report to {args.json_report}")
    return 0 if report["validator"]["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
