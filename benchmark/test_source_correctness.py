#!/usr/bin/env python3
"""Regression tests proving source-derived checks catch semantic mutations."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import score_correctness
from source_integrity import (
    build_source_manifest,
    read_source_provenance,
    read_source_manifest,
    verify_artifact_sources,
    verify_environment_nodes,
    verify_source_provenance,
    verify_source_manifest,
)


class SourceCorrectnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.oracle = score_correctness.read_oracle(score_correctness.DEFAULT_ORACLE)
        records = score_correctness.load_source_records(
            score_correctness.source_event_ids(cls.oracle)
        )
        cls.ranges, issues = score_correctness.build_source_ranges(cls.oracle, records)
        if issues:
            raise AssertionError(issues)

    def make_submission(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory(prefix="source-correctness-test-")
        score_correctness.write_oracle_submission(
            self.oracle, self.ranges, Path(temp_dir.name), force=False
        )
        return temp_dir

    @staticmethod
    def rewrite_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return list(reader.fieldnames or []), list(reader)

    @staticmethod
    def event_evidence_id(directory: Path, event_id: str) -> str:
        with (directory / "evidence.csv").open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if row["event_id"] == event_id:
                    return row["evidence_id"]
        raise AssertionError(f"event not found: {event_id}")

    def score(self, directory: Path) -> dict:
        return score_correctness.score_correctness(directory, self.oracle)

    def test_source_oracle_submission_scores_100(self) -> None:
        with self.make_submission() as temp_dir:
            report = self.score(Path(temp_dir))
        self.assertTrue(report["validator"]["passed"])
        self.assertEqual(100.0, report["score"])

    def test_raw_source_manifest_and_primary_artifacts_verify(self) -> None:
        self.assertEqual([], score_correctness.source_integrity_issues(self.oracle))

    def test_source_oracle_semantic_lock_detects_stage_drift(self) -> None:
        mutated = json.loads(json.dumps(self.oracle))
        original_stage = mutated["timeline_steps"][0]["stage"]
        mutated["timeline_steps"][0]["stage"] = (
            "impact" if original_stage != "impact" else "recon"
        )
        issues = score_correctness.source_integrity_issues(mutated)
        self.assertTrue(any("semantic hash mismatch" in issue for issue in issues))

    def test_source_provenance_binds_all_scored_records(self) -> None:
        event_ids = score_correctness.source_event_ids(self.oracle)
        records = score_correctness.load_source_records(event_ids)
        provenance = read_source_provenance()
        self.assertEqual([], verify_source_provenance(records, event_ids, provenance))
        mutated = {event_id: dict(record) for event_id, record in records.items()}
        event_id = next(
            event for event in sorted(mutated) if not event.startswith("artifact-")
        )
        mutated[event_id]["event_id"] = "semantic-drift"
        issues = verify_source_provenance(mutated, event_ids, provenance)
        self.assertTrue(
            any("record hash mismatch" in issue and event_id in issue for issue in issues)
        )

    def test_raw_source_manifest_detects_tampered_lock(self) -> None:
        manifest = json.loads(json.dumps(read_source_manifest()))
        manifest["files"][0]["sha256"] = "0" * 64
        issues = verify_source_manifest(score_correctness.CHALLENGE_ROOT, manifest)
        self.assertTrue(any("hash mismatch" in issue for issue in issues))

    def test_raw_source_manifest_detects_same_size_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source-lock-") as temp_dir:
            root = Path(temp_dir)
            path = root / "logs" / "example.log"
            path.parent.mkdir(parents=True)
            path.write_text("event_id=sample time=2026-07-06T10:00:00+08:00\n", encoding="utf-8")
            manifest = build_source_manifest(root)
            path.write_text("event_id=sample time=2026-07-06T10:00:01+08:00\n", encoding="utf-8")
            issues = verify_source_manifest(root, manifest)
        self.assertTrue(any("hash mismatch" in issue for issue in issues))

    def test_duplicate_required_source_event_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="duplicate-source-") as temp_dir:
            root = Path(temp_dir)
            logs = root / "logs"
            logs.mkdir()
            for name, timestamp in (("a.csv", "10:00:00"), ("b.csv", "10:00:01")):
                (logs / name).write_text(
                    "event_id,timestamp\n"
                    f"duplicate-event,2026-07-06T{timestamp}+08:00\n",
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(ValueError, "duplicate source event"):
                score_correctness.load_source_records({"duplicate-event"}, root)

    def test_declared_timeline_order_rejects_backward_source_time(self) -> None:
        later = datetime.fromisoformat("2026-07-06T10:01:00+08:00")
        earlier = datetime.fromisoformat("2026-07-06T10:00:00+08:00")
        oracle = {
            "timeline_steps": [
                {"id": "S01", "stage": "execution", "event_ids": ["event-later"]},
                {"id": "S02", "stage": "execution", "event_ids": ["event-earlier"]},
            ],
            "source_assertions": [],
            "negative_assertions": [],
        }
        records = {
            "event-later": {"timestamp": later.isoformat()},
            "event-earlier": {"timestamp": earlier.isoformat()},
        }
        _, issues = score_correctness.build_source_ranges(oracle, records)
        self.assertTrue(any("starts before prior declared step" in issue for issue in issues))

    def test_scoring_aborts_when_raw_source_lock_fails(self) -> None:
        with self.make_submission() as temp_dir:
            with patch.object(
                score_correctness,
                "source_integrity_issues",
                return_value=["simulated source drift"],
            ):
                with self.assertRaisesRegex(ValueError, "source integrity invalid"):
                    self.score(Path(temp_dir))

    def test_primary_artifact_field_assertion_detects_wrong_pcap_content(self) -> None:
        issues = verify_artifact_sources(
            score_correctness.CHALLENGE_ROOT,
            {"artifact-pcap-20260706-072073"},
            {"artifact-pcap-20260706-072073": {"http_host": "wrong.example"}},
        )
        self.assertTrue(any("PCAP assertion failed" in issue for issue in issues))

    def test_artifact_index_duplicate_event_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="duplicate-artifact-index-") as temp_dir:
            root = Path(temp_dir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "artifact_event_index.csv").write_text(
                "event_id\nartifact-duplicate\nartifact-duplicate\n",
                encoding="utf-8",
            )
            issues = verify_artifact_sources(root, {"artifact-duplicate"})
        self.assertTrue(any("duplicate artifact index event" in issue for issue in issues))

    def test_environment_backed_nodes_require_inventory_entries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="environment-node-") as temp_dir:
            root = Path(temp_dir)
            environment = root / "env"
            environment.mkdir()
            (environment / "asset_inventory.csv").write_text(
                "hostname\nknown-host\n", encoding="utf-8"
            )
            issues = verify_environment_nodes(
                root,
                [
                    {"id": "host:known-host", "type": "host"},
                    {"id": "database:missing-db", "type": "database"},
                ],
            )
        self.assertTrue(any("missing-db" in issue for issue in issues))

    def test_oracle_rejects_noncanonical_graph_evidence(self) -> None:
        corrupt = json.loads(json.dumps(self.oracle))
        corrupt["edges"][0]["event_ids"].append("not-a-canonical-event")
        with tempfile.TemporaryDirectory(prefix="corrupt-oracle-") as temp_dir:
            path = Path(temp_dir) / "oracle.json"
            path.write_text(json.dumps(corrupt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "noncanonical events"):
                score_correctness.read_oracle(path)

    def test_oracle_rejects_edge_to_unknown_node(self) -> None:
        corrupt = json.loads(json.dumps(self.oracle))
        corrupt["edges"][0]["to"] = "host:unreviewed"
        with tempfile.TemporaryDirectory(prefix="invalid-oracle-edge-") as temp_dir:
            path = Path(temp_dir) / "oracle.json"
            path.write_text(json.dumps(corrupt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown node"):
                score_correctness.read_oracle(path)

    def test_wrong_token_review_stage_is_detected(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            fields, rows = self.read_csv(directory / "evidence.csv")
            for row in rows:
                if row["event_id"] == "k8s-20260706-018130":
                    row["stage"] = "discovery"
            self.rewrite_csv(directory / "evidence.csv", fields, rows)
            report = self.score(directory)
        self.assertLess(report["components"]["stage"]["score"], 10.0)
        self.assertTrue(
            any("k8s-20260706-018130" in issue for issue in report["issues"]["evidence"])
        )

    def test_merged_token_steps_reduce_timeline_score(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            fields, rows = self.read_csv(directory / "timeline.csv")
            token_read = self.event_evidence_id(directory, "audit-ci-20260706-000002")
            token_use = self.event_evidence_id(directory, "k8s-20260706-018130")
            read_row = next(row for row in rows if token_read in row["evidence_ids"].split(";"))
            use_row = next(row for row in rows if token_use in row["evidence_ids"].split(";"))
            read_row["evidence_ids"] += f";{token_use}"
            read_row["time_end"] = use_row["time_end"]
            use_row["evidence_ids"] = self.event_evidence_id(
                directory, "k8s-20260706-018131"
            )
            use_row["stage"] = "discovery"
            use_row["time_start"] = "2026-07-06T10:34:00+08:00"
            use_row["time_end"] = "2026-07-06T10:34:00+08:00"
            self.rewrite_csv(directory / "timeline.csv", fields, rows)
            report = self.score(directory)
        self.assertLess(report["components"]["timeline"]["score"], 15.0)
        self.assertTrue(
            any("mixes atomic source steps" in issue for issue in report["issues"]["timeline"])
        )

    def test_wrong_role_edge_is_detected(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            graph = json.loads((directory / "attack_graph.json").read_text(encoding="utf-8"))
            edge = next(edge for edge in graph["edges"] if edge["id"] == "G29")
            edge["from"] = "cluster:k8s-master-01"
            (directory / "attack_graph.json").write_text(
                json.dumps(graph, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            report = self.score(directory)
        self.assertLess(report["components"]["edges"]["score"], 20.0)
        self.assertIn(
            "missing or unsupported graph edge G29", report["issues"]["edges"]
        )

    def test_partial_timeline_row_cannot_score_multiple_atomic_steps(self) -> None:
        first = datetime.fromisoformat("2026-07-06T10:00:00+08:00")
        second = datetime.fromisoformat("2026-07-06T10:01:00+08:00")
        oracle = {
            "timeline_steps": [
                {"id": "A", "stage": "execution", "event_ids": ["event-a"]},
                {"id": "B", "stage": "execution", "event_ids": ["event-b"]},
            ]
        }
        candidate = {
            "timeline": [
                {
                    "step": "1",
                    "stage": "execution",
                    "start": first,
                    "end": second,
                    "evidence_event_ids": {"event-a", "event-b"},
                }
            ]
        }
        ranges = {
            "event-a": score_correctness.SourceRange(first, first),
            "event-b": score_correctness.SourceRange(second, second),
        }
        ratio, matched, issues = score_correctness.score_timeline(
            oracle, candidate, ranges
        )
        # One merged row has F1=2/3 and no exact time match for either source
        # step. It can receive partial assignment only once, but strict mode
        # also applies zero precision because no submitted row is canonical.
        self.assertEqual(0.0, ratio)
        self.assertEqual([], matched)
        self.assertEqual(2, sum("missing or non-atomic" in issue for issue in issues))
        self.assertTrue(
            any("noncanonical or duplicate rows" in issue for issue in issues)
        )

    def test_duplicate_timeline_row_lowers_strict_precision(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            fields, rows = self.read_csv(directory / "timeline.csv")
            duplicate = dict(rows[0])
            duplicate["step"] = str(len(rows) + 1)
            duplicate["time_start"] = "2026-07-06T12:00:00+08:00"
            duplicate["time_end"] = "2026-07-06T12:00:00+08:00"
            rows.append(duplicate)
            self.rewrite_csv(directory / "timeline.csv", fields, rows)
            report = self.score(directory)
        self.assertTrue(report["validator"]["passed"])
        self.assertLess(report["components"]["timeline"]["score"], 15.0)
        self.assertTrue(
            any("noncanonical or duplicate rows" in issue for issue in report["issues"]["timeline"])
        )

    def test_duplicate_graph_edge_lowers_strict_precision(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            graph = json.loads((directory / "attack_graph.json").read_text(encoding="utf-8"))
            duplicate = dict(graph["edges"][0])
            duplicate["id"] = "G999"
            graph["edges"].append(duplicate)
            (directory / "attack_graph.json").write_text(
                json.dumps(graph, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            report = self.score(directory)
        self.assertTrue(report["validator"]["passed"])
        self.assertLess(report["components"]["edges"]["score"], 20.0)
        self.assertTrue(
            any(
                "incomplete, duplicate, or unsupported graph edges" in issue
                for issue in report["issues"]["edges"]
            )
        )

    def test_canonical_duplicate_ioc_lowers_strict_precision(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            fields, rows = self.read_csv(directory / "ioc.csv")
            file_row = next(row for row in rows if row["type"] == "file")
            duplicate = dict(file_row)
            duplicate["value"] = file_row["value"].replace("\\", "/")
            rows.append(duplicate)
            self.rewrite_csv(directory / "ioc.csv", fields, rows)
            report = self.score(directory)
        self.assertFalse(report["validator"]["passed"])
        self.assertLess(report["components"]["ioc"]["score"], 10.0)
        self.assertTrue(
            any("duplicate canonical IOC" in error for error in report["issues"]["parse"])
        )
        self.assertTrue(
            any("incomplete, duplicate, or unsupported IOCs" in issue for issue in report["issues"]["iocs"])
        )


if __name__ == "__main__":
    unittest.main()
