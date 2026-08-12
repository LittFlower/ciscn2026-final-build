#!/usr/bin/env python3
"""Score a Build submission.

The CLI defaults to a remote-platform score estimate.  Source-derived
correctness and the former curated reference comparison remain available as
explicit audit modes.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
CHALLENGE_ROOT = SCRIPT_DIR.parent
DEFAULT_REFERENCE = SCRIPT_DIR / "reference" / "high_confidence.json"
DEFAULT_ORACLE = SCRIPT_DIR / "source_oracle.json"
DEFAULT_REMOTE_PROFILE = SCRIPT_DIR / "remote_profile.json"
REQUIRED_FILES = (
    "manifest.json",
    "evidence.csv",
    "timeline.csv",
    "attack_graph.json",
    "ioc.csv",
)


def parse_time(value: object) -> datetime | None:
    """Return an aware ISO-8601 timestamp, or None for invalid input."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None


def parse_refs(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if not isinstance(value, str):
        return []
    return [item.strip() for item in value.replace(",", ";").split(";") if item.strip()]


def normalized_ioc_type(value: object) -> str:
    return str(value or "").strip().casefold()


def normalized_ioc_value(ioc_type: object, value: object) -> str:
    """Normalize only type-specific presentation differences safe for IOC identity."""
    text = str(value or "").strip()
    normalized_type = normalized_ioc_type(ioc_type)
    if normalized_type in {"ip", "domain"}:
        return text.casefold()
    if normalized_type == "file" and (
        re.match(r"^[A-Za-z]:[\\/]", text) is not None or text.startswith("\\\\")
    ):
        text = text.replace("\\", "/").casefold()
    return text


def canonical_ioc_key(ioc_type: object, value: object) -> tuple[str, str]:
    normalized_type = normalized_ioc_type(ioc_type)
    return normalized_type, normalized_ioc_value(normalized_type, value)


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_reference(path: Path) -> dict[str, Any]:
    reference = load_json(path)
    required = {"weights", "evidence", "timeline", "nodes", "edges", "iocs"}
    missing = required.difference(reference)
    if missing:
        raise ValueError(f"reference missing fields: {', '.join(sorted(missing))}")

    event_ids = [item.get("event_id") for item in reference["evidence"]]
    if any(not isinstance(event_id, str) or not event_id for event_id in event_ids):
        raise ValueError("reference contains an empty event_id")
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("reference contains duplicate event_id values")
    ioc_keys = [canonical_ioc_key(item.get("type"), item.get("value")) for item in reference["iocs"]]
    if any(not ioc_type or not value for ioc_type, value in ioc_keys):
        raise ValueError("reference contains an empty IOC type or value")
    if len(ioc_keys) != len(set(ioc_keys)):
        raise ValueError("reference contains duplicate canonical IOC values")
    if sum(reference["weights"].values()) != 100:
        raise ValueError("reference component weights must total 100")
    return reference


def run_public_validator(submission: Path) -> tuple[bool, str]:
    """Run the supplied schema validator with the challenge's data sources."""
    validator = CHALLENGE_ROOT / "tools" / "validator.py"
    command = [
        sys.executable,
        str(validator),
        str(submission),
        "--logs",
        str(CHALLENGE_ROOT / "logs"),
        "--artifacts",
        str(CHALLENGE_ROOT / "artifacts"),
    ]
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"could not run public validator: {exc}"
    return completed.returncode == 0, completed.stdout.strip()


def reference_source_time_issues(
    reference: dict[str, Any], tolerance_seconds: int
) -> list[str]:
    """Verify reference anchors exist in source data and fit all stated time windows."""
    reference_events = {item["event_id"] for item in reference["evidence"]}
    negative_events = {
        item["event_id"] for item in reference.get("negative_evidence", [])
    }
    known_source_events = reference_events.union(negative_events)
    timestamps: dict[str, datetime] = {}

    index_path = CHALLENGE_ROOT / "artifacts" / "artifact_event_index.csv"
    with index_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            event_id = row.get("event_id")
            timestamp = parse_time(row.get("timestamp"))
            if event_id in known_source_events and timestamp is not None:
                timestamps[event_id] = timestamp

    remaining = known_source_events.difference(timestamps)
    for path in (CHALLENGE_ROOT / "logs").rglob("*"):
        if not remaining or not path.is_file():
            continue
        if path.suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as handle:
                for row in csv.DictReader(handle):
                    event_id = row.get("event_id")
                    timestamp = parse_time(row.get("timestamp") or row.get("time"))
                    if event_id in remaining and timestamp is not None:
                        timestamps[event_id] = timestamp
                        remaining.remove(event_id)
        elif path.suffix == ".jsonl":
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    event_id = row.get("event_id")
                    timestamp = parse_time(row.get("timestamp") or row.get("time"))
                    if event_id in remaining and timestamp is not None:
                        timestamps[event_id] = timestamp
                        remaining.remove(event_id)
        elif path.suffix == ".log":
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    event_id_match = re.search(r"\bevent_id=([^\s]+)", line)
                    timestamp_match = re.search(r"\b(?:timestamp|time)=([^\s]+)", line)
                    if event_id_match is None or timestamp_match is None:
                        continue
                    event_id = event_id_match.group(1)
                    timestamp = parse_time(timestamp_match.group(1))
                    if event_id in remaining and timestamp is not None:
                        timestamps[event_id] = timestamp
                        remaining.remove(event_id)

    issues = [
        f"no source timestamp for {'negative' if event_id in negative_events else 'reference'} "
        f"event {event_id}"
        for event_id in sorted(remaining)
    ]
    known_events = set(reference_events)
    tolerance = timedelta(seconds=tolerance_seconds)

    def check_windows(
        items: list[dict[str, Any]],
        start_key: str,
        end_key: str,
        description: str,
    ) -> None:
        for item in items:
            item_id = item.get("id") or item.get("type", "IOC") + ":" + item.get("value", "")
            start = parse_time(item.get(start_key))
            end = parse_time(item.get(end_key))
            if start is None or end is None or start > end:
                issues.append(f"{description} {item_id} has an invalid time window")
                continue
            for event_id in item.get("evidence_event_ids", []):
                if event_id not in known_events:
                    issues.append(f"{description} {item_id} references non-reference event {event_id}")
                    continue
                timestamp = timestamps.get(event_id)
                if timestamp is None:
                    continue
                if timestamp < start - tolerance or timestamp > end + tolerance:
                    issues.append(
                        f"{description} {item_id} time window excludes {event_id} at "
                        f"{timestamp.isoformat()}"
                    )

    check_windows(reference["timeline"], "time_start", "time_end", "timeline")
    check_windows(reference["edges"], "time_start", "time_end", "edge")
    check_windows(reference["iocs"], "first_seen", "last_seen", "IOC")
    return issues


def collect_submission(submission: Path) -> tuple[dict[str, Any], list[str]]:
    """Load candidate files defensively so a malformed draft still gets diagnostics."""
    errors: list[str] = []
    data: dict[str, Any] = {
        "evidence": [],
        "event_to_evidence": {},
        "timeline": [],
        "nodes": [],
        "edges": [],
        "iocs": [],
        "canonical_ioc_duplicates": [],
    }

    for name in REQUIRED_FILES:
        if not (submission / name).is_file():
            errors.append(f"missing {name}")
    if errors:
        return data, errors

    try:
        _, evidence_rows = read_csv(submission / "evidence.csv")
    except (OSError, csv.Error, UnicodeError) as exc:
        errors.append(f"cannot read evidence.csv: {exc}")
        evidence_rows = []

    evidence_ids: dict[str, str] = {}
    event_to_evidence: dict[str, dict[str, str]] = {}
    for row_number, row in enumerate(evidence_rows, 2):
        evidence_id = (row.get("evidence_id") or "").strip()
        event_id = (row.get("event_id") or "").strip()
        stage = (row.get("stage") or "").strip()
        if not evidence_id or not event_id:
            errors.append(f"evidence.csv:{row_number} has an empty ID")
            continue
        if evidence_id in evidence_ids:
            errors.append(f"evidence.csv:{row_number} duplicate evidence_id {evidence_id}")
            continue
        if event_id in event_to_evidence:
            errors.append(f"evidence.csv:{row_number} duplicate event_id {event_id}")
            continue
        normalized = {
            "evidence_id": evidence_id,
            "event_id": event_id,
            "stage": stage,
        }
        evidence_ids[evidence_id] = event_id
        event_to_evidence[event_id] = normalized
        data["evidence"].append(normalized)
    data["event_to_evidence"] = event_to_evidence

    try:
        _, timeline_rows = read_csv(submission / "timeline.csv")
    except (OSError, csv.Error, UnicodeError) as exc:
        errors.append(f"cannot read timeline.csv: {exc}")
        timeline_rows = []
    for row_number, row in enumerate(timeline_rows, 2):
        evidence_event_ids = {
            evidence_ids[evidence_id]
            for evidence_id in parse_refs(row.get("evidence_ids"))
            if evidence_id in evidence_ids
        }
        data["timeline"].append(
            {
                "row": row_number,
                "step": row.get("step", ""),
                "stage": (row.get("stage") or "").strip(),
                "start": parse_time(row.get("time_start")),
                "end": parse_time(row.get("time_end")),
                "evidence_event_ids": evidence_event_ids,
            }
        )

    try:
        graph = load_json(submission / "attack_graph.json")
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        errors.append(f"cannot read attack_graph.json: {exc}")
        graph = {}
    if not isinstance(graph, dict):
        errors.append("attack_graph.json is not an object")
        graph = {}
    nodes = graph.get("nodes", [])
    if not isinstance(nodes, list):
        errors.append("attack_graph.json nodes is not a list")
        nodes = []
    data["nodes"] = [node for node in nodes if isinstance(node, dict)]
    edges = graph.get("edges", [])
    if not isinstance(edges, list):
        errors.append("attack_graph.json edges is not a list")
        edges = []
    for edge_number, edge in enumerate(edges, 1):
        if not isinstance(edge, dict):
            continue
        evidence_event_ids = {
            evidence_ids[evidence_id]
            for evidence_id in parse_refs(edge.get("evidence_ids"))
            if evidence_id in evidence_ids
        }
        data["edges"].append(
            {
                "row": edge_number,
                "id": str(edge.get("id") or ""),
                "from": str(edge.get("from") or ""),
                "to": str(edge.get("to") or ""),
                "action": str(edge.get("action") or ""),
                "stage": str(edge.get("stage") or ""),
                "start": parse_time(edge.get("time_start")),
                "end": parse_time(edge.get("time_end")),
                "evidence_event_ids": evidence_event_ids,
            }
        )

    try:
        _, ioc_rows = read_csv(submission / "ioc.csv")
    except (OSError, csv.Error, UnicodeError) as exc:
        errors.append(f"cannot read ioc.csv: {exc}")
        ioc_rows = []
    seen_ioc_keys: set[tuple[str, str]] = set()
    for row_number, row in enumerate(ioc_rows, 2):
        ioc_type = normalized_ioc_type(row.get("type"))
        ioc_value = normalized_ioc_value(ioc_type, row.get("value"))
        ioc_key = (ioc_type, ioc_value)
        if ioc_type and ioc_value and ioc_key in seen_ioc_keys:
            errors.append(
                f"ioc.csv:{row_number} duplicate canonical IOC {ioc_type}:{ioc_value}"
            )
            data["canonical_ioc_duplicates"].append(ioc_key)
        seen_ioc_keys.add(ioc_key)
        evidence_event_ids = {
            evidence_ids[evidence_id]
            for evidence_id in parse_refs(row.get("evidence_ids"))
            if evidence_id in evidence_ids
        }
        data["iocs"].append(
            {
                "row": row_number,
                "type": ioc_type,
                "value": ioc_value,
                "start": parse_time(row.get("first_seen")),
                "end": parse_time(row.get("last_seen")),
                "assets": set(parse_refs(row.get("related_asset"))),
                "evidence_event_ids": evidence_event_ids,
            }
        )
    return data, errors


def endpoint_time_score(
    candidate_start: datetime | None,
    candidate_end: datetime | None,
    reference_start: datetime | None,
    reference_end: datetime | None,
    tolerance: timedelta,
) -> float:
    """Score an interval, allowing small source-clock and granularity differences."""
    if not all((candidate_start, candidate_end, reference_start, reference_end)):
        return 0.0
    assert candidate_start and candidate_end and reference_start and reference_end
    if (
        abs(candidate_start - reference_start) <= tolerance
        and abs(candidate_end - reference_end) <= tolerance
    ):
        return 1.0
    if candidate_start <= reference_end + tolerance and candidate_end >= reference_start - tolerance:
        return 0.5
    return 0.0


def evidence_f1(expected: set[str], actual: set[str]) -> float:
    """Score cited evidence without rewarding a single weak intersection."""
    if not expected and not actual:
        return 1.0
    if not expected or not actual:
        return 0.0
    overlap = len(expected.intersection(actual))
    precision = overlap / len(actual)
    recall = overlap / len(expected)
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def maximum_weight_matching(scores: list[list[float]]) -> list[tuple[int, int, float]]:
    """Return a deterministic maximum-weight one-to-one assignment.

    Greedy matching can either reuse a partial candidate row or consume it for
    the wrong expected item.  This implementation uses the Hungarian algorithm
    on a zero-padded square matrix, so unmatched rows/columns remain legal.
    """
    row_count = len(scores)
    column_count = max((len(row) for row in scores), default=0)
    if row_count == 0 or column_count == 0:
        return []

    size = max(row_count, column_count)
    weights = [[0.0] * size for _ in range(size)]
    for row_index, row in enumerate(scores):
        for column_index, value in enumerate(row[:column_count]):
            try:
                weights[row_index][column_index] = max(0.0, float(value))
            except (TypeError, ValueError):
                continue
    maximum = max((value for row in weights for value in row), default=0.0)
    costs = [[maximum - value for value in row] for row in weights]

    # Standard Hungarian minimization implementation, 1-indexed internally.
    potential_row = [0.0] * (size + 1)
    potential_column = [0.0] * (size + 1)
    matched_column = [0] * (size + 1)
    predecessor = [0] * (size + 1)
    for row in range(1, size + 1):
        matched_column[0] = row
        column0 = 0
        minimum = [float("inf")] * (size + 1)
        used = [False] * (size + 1)
        while True:
            used[column0] = True
            row0 = matched_column[column0]
            delta = float("inf")
            column1 = 0
            for column in range(1, size + 1):
                if used[column]:
                    continue
                reduced_cost = (
                    costs[row0 - 1][column - 1]
                    - potential_row[row0]
                    - potential_column[column]
                )
                if reduced_cost < minimum[column]:
                    minimum[column] = reduced_cost
                    predecessor[column] = column0
                if minimum[column] < delta:
                    delta = minimum[column]
                    column1 = column
            for column in range(size + 1):
                if used[column]:
                    potential_row[matched_column[column]] += delta
                    potential_column[column] -= delta
                else:
                    minimum[column] -= delta
            column0 = column1
            if matched_column[column0] == 0:
                break
        while True:
            column1 = predecessor[column0]
            matched_column[column0] = matched_column[column1]
            column0 = column1
            if column0 == 0:
                break

    assignment = [-1] * size
    for column in range(1, size + 1):
        if matched_column[column]:
            assignment[matched_column[column] - 1] = column - 1
    return [
        (row, column, weights[row][column])
        for row, column in enumerate(assignment[:row_count])
        if 0 <= column < column_count and weights[row][column] > 0.0
    ]


def score_timeline(
    expected: list[dict[str, Any]],
    candidate: list[dict[str, Any]],
    tolerance: timedelta,
    strict_extras: bool = False,
) -> tuple[float, list[str]]:
    scores: list[list[float]] = []
    for item in expected:
        expected_events = set(item["evidence_event_ids"])
        row_scores: list[float] = []
        for row in candidate:
            if row["stage"] != item["stage"]:
                row_scores.append(0.0)
                continue
            time_score = endpoint_time_score(
                row["start"],
                row["end"],
                parse_time(item["time_start"]),
                parse_time(item["time_end"]),
                tolerance,
            )
            evidence_score = evidence_f1(expected_events, row["evidence_event_ids"])
            if evidence_score == 0.0:
                row_scores.append(0.0)
                continue
            row_scores.append(0.35 * time_score + 0.65 * evidence_score)
        scores.append(row_scores)
    assignments = {
        expected_index: (candidate_index, score)
        for expected_index, candidate_index, score in maximum_weight_matching(scores)
    }
    matches: list[str] = []
    total = 0.0
    for index, item in enumerate(expected):
        candidate_match = assignments.get(index)
        score = candidate_match[1] if candidate_match else 0.0
        total += score
        if candidate_match:
            matches.append(f"{item['id']}:{score:.1f}")
    coverage = total / len(expected) if expected else 0.0
    precision = len(assignments) / len(candidate) if candidate else 0.0
    return coverage * precision if strict_extras else coverage, matches


def score_edges(
    expected: list[dict[str, Any]],
    candidate: list[dict[str, Any]],
    tolerance: timedelta,
    strict_extras: bool = False,
) -> tuple[float, list[str]]:
    scores: list[list[float]] = []
    for item in expected:
        semantic_key = (item["from"], item["to"], item["action"], item["stage"])
        expected_events = set(item["evidence_event_ids"])
        row_scores: list[float] = []
        for edge in candidate:
            candidate_key = (edge["from"], edge["to"], edge["action"], edge["stage"])
            if candidate_key != semantic_key:
                row_scores.append(0.0)
                continue
            time_score = endpoint_time_score(
                edge["start"],
                edge["end"],
                parse_time(item["time_start"]),
                parse_time(item["time_end"]),
                tolerance,
            )
            evidence_score = evidence_f1(expected_events, edge["evidence_event_ids"])
            if evidence_score == 0.0:
                row_scores.append(0.0)
                continue
            row_scores.append(0.10 + 0.25 * time_score + 0.65 * evidence_score)
        scores.append(row_scores)
    assignments = {
        expected_index: (candidate_index, score)
        for expected_index, candidate_index, score in maximum_weight_matching(scores)
    }
    matches: list[str] = []
    total = 0.0
    for index, item in enumerate(expected):
        candidate_match = assignments.get(index)
        score = candidate_match[1] if candidate_match else 0.0
        total += score
        if candidate_match:
            matches.append(f"{item['id']}:{score:.1f}")
    coverage = total / len(expected) if expected else 0.0
    precision = len(assignments) / len(candidate) if candidate else 0.0
    return coverage * precision if strict_extras else coverage, matches


def score_iocs(
    expected: list[dict[str, Any]],
    candidate: list[dict[str, Any]],
    tolerance: timedelta,
) -> tuple[float, list[str]]:
    scores: list[list[float]] = []
    for item in expected:
        expected_key = canonical_ioc_key(item.get("type"), item.get("value"))
        expected_assets = set(item.get("related_assets", []))
        expected_events = set(item.get("evidence_event_ids", []))
        row_scores: list[float] = []
        for candidate_item in candidate:
            candidate_key = canonical_ioc_key(
                candidate_item.get("type"), candidate_item.get("value")
            )
            if not expected_key[0] or candidate_key != expected_key:
                row_scores.append(0.0)
                continue
            time_score = endpoint_time_score(
                candidate_item["start"],
                candidate_item["end"],
                parse_time(item["first_seen"]),
                parse_time(item["last_seen"]),
                tolerance,
            )
            asset_score = evidence_f1(expected_assets, candidate_item["assets"])
            evidence_score = evidence_f1(
                expected_events, candidate_item["evidence_event_ids"]
            )
            # Identity alone is not corroboration.  At least the cited evidence
            # or temporal window must support an otherwise exact IOC value.
            if time_score == 0.0 and evidence_score == 0.0:
                row_scores.append(0.0)
                continue
            row_scores.append(
                0.20 + 0.30 * time_score + 0.25 * asset_score + 0.25 * evidence_score
            )
        scores.append(row_scores)
    assignments = {
        expected_index: (candidate_index, score)
        for expected_index, candidate_index, score in maximum_weight_matching(scores)
    }
    total = 0.0
    matches: list[str] = []
    supported_candidate_indices: set[int] = set()
    for index, item in enumerate(expected):
        assignment = assignments.get(index)
        score = assignment[1] if assignment else 0.0
        total += score
        if assignment:
            supported_candidate_indices.add(assignment[0])
            matches.append(f"{item['type']}:{item['value']}:{score:.2f}")
    coverage = total / len(expected) if expected else 0.0
    precision = (
        len(supported_candidate_indices) / len(candidate) if candidate else 0.0
    )
    return coverage * precision, matches


def score_submission(
    submission: Path,
    reference: dict[str, Any],
    strict_extras: bool,
    skip_validator: bool,
    tolerance_seconds: int,
) -> dict[str, Any]:
    if not submission.is_dir():
        raise ValueError(f"submission directory does not exist: {submission}")

    validator_passed, validator_output = (
        (True, "Skipped by --skip-validator.")
        if skip_validator
        else run_public_validator(submission)
    )
    candidate, read_errors = collect_submission(submission)
    weights = reference["weights"]
    expected_evidence = {item["event_id"]: item for item in reference["evidence"]}
    known_negative = {
        item["event_id"]: item.get("reason", "")
        for item in reference.get("negative_evidence", [])
    }
    candidate_events = set(candidate["event_to_evidence"])
    matched_events = candidate_events.intersection(expected_evidence)
    negative_events = candidate_events.intersection(known_negative)
    unreviewed_events = candidate_events.difference(expected_evidence).difference(known_negative)
    reference_event_weight = sum(float(item.get("weight", 1.0)) for item in expected_evidence.values())
    matched_event_weight = sum(
        float(expected_evidence[event_id].get("weight", 1.0))
        for event_id in matched_events
    )
    coverage = matched_event_weight / reference_event_weight if reference_event_weight else 0.0
    precision_denominator = len(matched_events) + 2 * len(negative_events)
    if strict_extras:
        precision_denominator += len(unreviewed_events)
    precision_guard = len(matched_events) / precision_denominator if precision_denominator else 0.0

    correct_stage_events = {
        event_id
        for event_id in matched_events
        if candidate["event_to_evidence"][event_id]["stage"] == expected_evidence[event_id]["stage"]
    }
    stage_coverage = (
        sum(float(expected_evidence[event_id].get("weight", 1.0)) for event_id in correct_stage_events)
        / reference_event_weight
        if reference_event_weight
        else 0.0
    )
    tolerance = timedelta(seconds=tolerance_seconds)
    timeline_coverage, timeline_matches = score_timeline(
        reference["timeline"],
        candidate["timeline"],
        tolerance,
        strict_extras=strict_extras,
    )

    expected_nodes = {item["id"]: item["type"] for item in reference["nodes"]}
    candidate_nodes = {
        str(item.get("id") or ""): str(item.get("type") or "")
        for item in candidate["nodes"]
        if str(item.get("id") or "")
    }
    matching_nodes = {
        node_id
        for node_id, node_type in expected_nodes.items()
        if candidate_nodes.get(node_id) == node_type
    }
    node_coverage = len(matching_nodes) / len(expected_nodes) if expected_nodes else 0.0

    edge_coverage, edge_matches = score_edges(
        reference["edges"],
        candidate["edges"],
        tolerance,
        strict_extras=strict_extras,
    )
    ioc_coverage, ioc_matches = score_iocs(reference["iocs"], candidate["iocs"], tolerance)

    components = {
        "format": {
            "max": weights["format"],
            "score": float(weights["format"]) if validator_passed else 0.0,
            "note": "public validator passed" if validator_passed else "public validator failed",
        },
        "evidence": {
            "max": weights["evidence"],
            "score": float(weights["evidence"]) * coverage * precision_guard,
            "coverage": coverage,
            "precision_guard": precision_guard,
        },
        "stage": {
            "max": weights["stage"],
            "score": float(weights["stage"]) * stage_coverage,
            "coverage": stage_coverage,
        },
        "timeline": {
            "max": weights["timeline"],
            "score": float(weights["timeline"]) * timeline_coverage,
            "coverage": timeline_coverage,
        },
        "nodes": {
            "max": weights["nodes"],
            "score": float(weights["nodes"]) * node_coverage,
            "coverage": node_coverage,
        },
        "edges": {
            "max": weights["edges"],
            "score": float(weights["edges"]) * edge_coverage,
            "coverage": edge_coverage,
        },
        "ioc": {
            "max": weights["ioc"],
            "score": float(weights["ioc"]) * ioc_coverage,
            "coverage": ioc_coverage,
        },
    }
    semantic_total = sum(component["score"] for component in components.values())
    # A schema-invalid directory cannot be submitted, so the primary score is zero.
    score = semantic_total if validator_passed else 0.0
    return {
        "reference_version": reference.get("reference_version"),
        "submission": str(submission),
        "validator": {
            "passed": validator_passed,
            "output": validator_output,
        },
        "read_errors": read_errors,
        "strict_extras": strict_extras,
        "score": score,
        "diagnostic_semantic_score": semantic_total,
        "components": components,
        "counts": {
            "reference_evidence": len(expected_evidence),
            "candidate_evidence": len(candidate_events),
            "matched_evidence": len(matched_events),
            "correct_stage_evidence": len(correct_stage_events),
            "known_negative_evidence": len(negative_events),
            "unreviewed_evidence": len(unreviewed_events),
            "reference_timeline_steps": len(reference["timeline"]),
            "candidate_timeline_steps": len(candidate["timeline"]),
            "reference_nodes": len(expected_nodes),
            "candidate_nodes": len(candidate_nodes),
            "reference_edges": len(reference["edges"]),
            "candidate_edges": len(candidate["edges"]),
            "reference_iocs": len(reference["iocs"]),
            "candidate_iocs": len(candidate["iocs"]),
        },
        "matched": {
            "events": sorted(matched_events),
            "timeline": timeline_matches,
            "nodes": sorted(matching_nodes),
            "edges": edge_matches,
            "iocs": ioc_matches,
        },
        "missing": {
            "events": sorted(set(expected_evidence).difference(candidate_events)),
            "nodes": sorted(set(expected_nodes).difference(matching_nodes)),
        },
        "known_negative": [
            {"event_id": event_id, "reason": known_negative[event_id]}
            for event_id in sorted(negative_events)
        ],
        "unreviewed_evidence": sorted(unreviewed_events),
    }


def write_reference_submission(reference: dict[str, Any], output: Path, force: bool) -> None:
    """Generate a validator-compliant local reference draft for regression checks."""
    output.mkdir(parents=True, exist_ok=True)
    existing = [name for name in REQUIRED_FILES if (output / name).exists()]
    if existing and not force:
        raise ValueError(
            f"{output} already contains {', '.join(existing)}; use --force to replace them"
        )

    event_to_evidence = {
        item["event_id"]: f"E{index:03d}"
        for index, item in enumerate(reference["evidence"], 1)
    }
    manifest = {
        "team_id": "benchmark",
        "schema_version": "1.0",
        "created_at": "2026-07-06T12:00:00+08:00",
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
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
                "evidence_id": event_to_evidence[item["event_id"]],
                "event_id": item["event_id"],
                "stage": item["stage"],
            }
            for item in reference["evidence"]
        ],
    )
    write_csv(
        "timeline.csv",
        ["step", "stage", "time_start", "time_end", "evidence_ids"],
        [
            {
                "step": str(index),
                "stage": item["stage"],
                "time_start": item["time_start"],
                "time_end": item["time_end"],
                "evidence_ids": ";".join(
                    event_to_evidence[event_id] for event_id in item["evidence_event_ids"]
                ),
            }
            for index, item in enumerate(reference["timeline"], 1)
        ],
    )
    graph = {
        "schema_version": "1.0",
        "incident_id": "build-final-2026-local-benchmark",
        "nodes": reference["nodes"],
        "edges": [
            {
                "id": item["id"],
                "from": item["from"],
                "to": item["to"],
                "action": item["action"],
                "stage": item["stage"],
                "time_start": item["time_start"],
                "time_end": item["time_end"],
                "evidence_ids": [
                    event_to_evidence[event_id] for event_id in item["evidence_event_ids"]
                ],
            }
            for item in reference["edges"]
        ],
    }
    (output / "attack_graph.json").write_text(
        json.dumps(graph, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_csv(
        "ioc.csv",
        ["type", "value", "first_seen", "last_seen", "related_asset", "evidence_ids"],
        [
            {
                "type": item["type"],
                "value": item["value"],
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
                "related_asset": ";".join(item["related_assets"]),
                "evidence_ids": ";".join(
                    event_to_evidence[event_id] for event_id in item["evidence_event_ids"]
                ),
            }
            for item in reference["iocs"]
        ],
    )


def compact_list(values: list[str], limit: int = 12) -> str:
    if not values:
        return "none"
    shown = ", ".join(values[:limit])
    return f"{shown} … (+{len(values) - limit})" if len(values) > limit else shown


def print_report(report: dict[str, Any]) -> None:
    print(f"Local benchmark v{report['reference_version']} — {report['submission']}")
    validator = report["validator"]
    print(f"Public format validator: {'PASS' if validator['passed'] else 'FAIL'}")
    for name in ("format", "evidence", "stage", "timeline", "nodes", "edges", "ioc"):
        component = report["components"][name]
        coverage = component.get("coverage")
        suffix = f"  coverage={coverage:.1%}" if coverage is not None else ""
        print(
            f"  {name:<9} {component['score']:6.2f} / {component['max']:>2}{suffix}"
        )
    print(f"Benchmark score: {report['score']:.2f} / 100.00")
    if not validator["passed"]:
        print(
            f"Diagnostic semantic score (not submit-eligible): "
            f"{report['diagnostic_semantic_score']:.2f} / 100.00"
        )
        if validator["output"]:
            print(f"Validator output: {validator['output']}")
    if report["read_errors"]:
        print(f"Local parsing warnings: {'; '.join(report['read_errors'])}")

    counts = report["counts"]
    print(
        "Evidence anchors: "
        f"{counts['matched_evidence']}/{counts['reference_evidence']} matched; "
        f"{counts['correct_stage_evidence']} correct stage; "
        f"{counts['unreviewed_evidence']} unreviewed extra; "
        f"{counts['known_negative_evidence']} confirmed negative."
    )
    if report["known_negative"]:
        print("Confirmed-negative evidence: " + ", ".join(
            item["event_id"] for item in report["known_negative"]
        ))
    print("Missing high-confidence events: " + compact_list(report["missing"]["events"]))
    print("Missing topology nodes: " + compact_list(report["missing"]["nodes"]))
    if report["strict_extras"]:
        print(
            "Strict-extras mode is active: unreviewed evidence and unmatched "
            "timeline/edge rows lower their component scores."
        )
    else:
        print(
            "Unreviewed evidence IDs are reported but not penalized; "
            "enable --strict-extras only after reviewing them."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Score a candidate submission; remote-platform estimation is the default mode."
    )
    parser.add_argument("submission", nargs="?", type=Path, help="submission directory to score")
    parser.add_argument(
        "--mode",
        choices=("remote", "correctness", "reference"),
        default="remote",
        help="use remote-score estimation (default), strict source correctness, or legacy reference comparison",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=DEFAULT_REMOTE_PROFILE,
        help="observed remote-platform profile used by remote mode",
    )
    parser.add_argument(
        "--oracle",
        type=Path,
        help="source oracle JSON; remote mode otherwise uses the profile's oracle",
    )
    parser.add_argument(
        "--zip",
        dest="archive",
        type=Path,
        metavar="FILE",
        help="actual ZIP payload required by remote mode",
    )
    parser.add_argument(
        "--team-id",
        help="expected authenticated team ID for remote manifest binding",
    )
    parser.add_argument(
        "--reference",
        type=Path,
        default=DEFAULT_REFERENCE,
        help="reference JSON (default: benchmark/reference/high_confidence.json)",
    )
    parser.add_argument(
        "--json",
        dest="json_report",
        type=Path,
        help="write the detailed report to this JSON file",
    )
    parser.add_argument(
        "--strict-extras",
        action="store_true",
        help="treat unreviewed evidence and unmatched timeline/edge rows as precision penalties",
    )
    parser.add_argument(
        "--skip-validator",
        action="store_true",
        help="skip the supplied schema validator (only for fast local debugging)",
    )
    parser.add_argument(
        "--time-tolerance-seconds",
        type=int,
        help="timestamp tolerance; remote mode otherwise uses the profile value (90 in reference mode)",
    )
    parser.add_argument(
        "--write-reference",
        type=Path,
        metavar="DIR",
        help="generate a validator-compliant reference submission in DIR",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow --write-reference to replace existing core files",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="generate and score the reference submission; exits non-zero unless it is 100",
    )
    return parser


def run_remote_estimate(args: argparse.Namespace) -> int:
    """Forward compatible arguments to the observed remote-platform estimator."""
    if args.write_reference or args.strict_extras or args.skip_validator or args.force:
        raise SystemExit(
            "--write-reference, --strict-extras, --skip-validator, and --force "
            "are unavailable in --mode remote"
        )

    # Import lazily: the estimator reuses scoring helpers from this module.
    from score_remote import main as remote_main

    forwarded = ["--profile", str(args.profile)]
    if args.oracle is not None:
        forwarded.extend(["--oracle", str(args.oracle)])
    if args.time_tolerance_seconds is not None:
        forwarded.extend(["--time-tolerance-seconds", str(args.time_tolerance_seconds)])
    if args.submission is not None and args.archive is None:
        forwarded.insert(0, str(args.submission))
    if args.archive is not None:
        forwarded.extend(["--zip", str(args.archive)])
    if args.team_id:
        forwarded.extend(["--team-id", args.team_id])
    if args.json_report is not None:
        forwarded.extend(["--json", str(args.json_report)])
    if args.self_test:
        forwarded.append("--self-test")
    return remote_main(forwarded)


def run_source_correctness(args: argparse.Namespace) -> int:
    """Forward the compatible CLI subset to the independent correctness scorer."""
    if args.write_reference or args.archive is not None:
        raise SystemExit(
            "--write-reference and --zip are unavailable in --mode correctness"
        )
    if (
        args.strict_extras
        or args.skip_validator
        or args.time_tolerance_seconds is not None
        or args.force
    ):
        raise SystemExit(
            "--strict-extras, --skip-validator, and --time-tolerance-seconds "
            "are available only with --mode reference; --force is unavailable here"
        )

    # Import lazily: score_correctness imports parsing helpers from this module.
    from score_correctness import main as source_correctness_main

    forwarded = ["--oracle", str(args.oracle or DEFAULT_ORACLE)]
    if args.submission is not None:
        forwarded.insert(0, str(args.submission))
    if args.json_report is not None:
        forwarded.extend(["--json", str(args.json_report)])
    if args.self_test:
        forwarded.append("--self-test")
    if args.force:
        forwarded.append("--force")
    return source_correctness_main(forwarded)


def main() -> int:
    args = build_parser().parse_args()
    if args.mode == "remote":
        return run_remote_estimate(args)
    if args.mode == "correctness":
        return run_source_correctness(args)
    tolerance_seconds = args.time_tolerance_seconds if args.time_tolerance_seconds is not None else 90
    if tolerance_seconds < 0:
        raise SystemExit("--time-tolerance-seconds must be non-negative")
    try:
        reference = load_reference(args.reference)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load reference: {exc}") from exc

    if args.write_reference:
        try:
            write_reference_submission(reference, args.write_reference, args.force)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"cannot write reference submission: {exc}") from exc
        print(f"Wrote reference submission to {args.write_reference}")

    if args.self_test:
        source_time_issues = reference_source_time_issues(
            reference, tolerance_seconds
        )
        if source_time_issues:
            print("Reference source-time audit: FAIL")
            for issue in source_time_issues[:20]:
                print(f"  - {issue}")
            if len(source_time_issues) > 20:
                print(f"  ... {len(source_time_issues) - 20} more")
            return 1
        print(
            "Reference source-time audit: PASS "
            f"({len(reference['evidence'])} anchors and "
            f"{len(reference.get('negative_evidence', []))} negative controls checked)"
        )
        with tempfile.TemporaryDirectory(prefix="build-benchmark-") as temp_dir:
            submission = Path(temp_dir)
            write_reference_submission(reference, submission, force=False)
            report = score_submission(
                submission,
                reference,
                strict_extras=False,
                skip_validator=False,
                tolerance_seconds=tolerance_seconds,
            )
        print_report(report)
        if not report["validator"]["passed"] or abs(report["score"] - 100.0) > 0.001:
            return 1
        return 0

    if args.submission is None:
        if args.write_reference:
            return 0
        raise SystemExit("provide SUBMISSION, --write-reference DIR, or --self-test")
    try:
        report = score_submission(
            args.submission,
            reference,
            strict_extras=args.strict_extras,
            skip_validator=args.skip_validator,
            tolerance_seconds=tolerance_seconds,
        )
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
    raise SystemExit(main())
