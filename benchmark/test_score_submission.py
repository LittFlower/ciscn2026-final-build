#!/usr/bin/env python3
"""Regression tests for the local benchmark's important scoring guarantees."""

from __future__ import annotations

import csv
import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from itertools import product
from pathlib import Path

import score_submission


class BenchmarkScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = score_submission.load_reference(score_submission.DEFAULT_REFERENCE)

    def make_reference_submission(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory(prefix="build-benchmark-test-")
        score_submission.write_reference_submission(
            self.reference, Path(temp_dir.name), force=False
        )
        return temp_dir

    @staticmethod
    def append_evidence(directory: Path, evidence_id: str, event_id: str, stage: str) -> None:
        with (directory / "evidence.csv").open("a", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerow([evidence_id, event_id, stage])

    def score(self, directory: Path, *, strict_extras: bool = False) -> dict:
        return score_submission.score_submission(
            directory,
            self.reference,
            strict_extras=strict_extras,
            skip_validator=True,
            tolerance_seconds=90,
        )

    def test_reference_is_a_full_score(self) -> None:
        with self.make_reference_submission() as temp_dir:
            report = self.score(Path(temp_dir))
        self.assertEqual(100.0, report["score"])

    def test_confirmed_negative_lowers_evidence_score(self) -> None:
        with self.make_reference_submission() as temp_dir:
            directory = Path(temp_dir)
            self.append_evidence(
                directory,
                "E900",
                "waf-20260706-096001",
                "recon",
            )
            report = self.score(directory)
        self.assertEqual(1, report["counts"]["known_negative_evidence"])
        self.assertLess(report["components"]["evidence"]["score"], 25.0)
        self.assertLess(report["score"], 100.0)

    def test_unreviewed_evidence_is_only_penalized_in_strict_mode(self) -> None:
        with self.make_reference_submission() as temp_dir:
            directory = Path(temp_dir)
            self.append_evidence(
                directory,
                "E901",
                "waf-20260706-096002",
                "recon",
            )
            relaxed = self.score(directory)
            strict = self.score(directory, strict_extras=True)
        self.assertEqual(1, relaxed["counts"]["unreviewed_evidence"])
        self.assertEqual(100.0, relaxed["score"])
        self.assertLess(strict["score"], relaxed["score"])

    def test_schema_invalid_submission_has_no_submit_eligible_score(self) -> None:
        with self.make_reference_submission() as temp_dir:
            directory = Path(temp_dir)
            (directory / "manifest.json").write_text("{}", encoding="utf-8")
            report = score_submission.score_submission(
                directory,
                self.reference,
                strict_extras=False,
                skip_validator=False,
                tolerance_seconds=90,
            )
        self.assertFalse(report["validator"]["passed"])
        self.assertEqual(0.0, report["score"])
        self.assertGreater(report["diagnostic_semantic_score"], 0.0)

    def test_partial_matches_use_global_one_to_one_assignment(self) -> None:
        # A greedy scorer would take (0, 0)=1.0, then leave row 1 unmatched.
        # The maximum valid one-to-one assignment is (0, 1)+(1, 0)=1.8.
        matches = score_submission.maximum_weight_matching(
            [[1.0, 0.9], [0.9, 0.0]]
        )
        self.assertEqual({0, 1}, {row for row, _, _ in matches})
        self.assertEqual({0, 1}, {column for _, column, _ in matches})
        self.assertAlmostEqual(1.8, sum(score for _, _, score in matches))

    def test_assignment_matches_bruteforce_optimum_on_small_matrices(self) -> None:
        matrices = [
            [[0.0, 0.8], [0.7, 0.1]],
            [[1.0, 0.2, 0.0], [0.4, 0.9, 0.3]],
            [[0.2, 0.7], [0.8, 0.1], [0.6, 0.5]],
            [[0.4, 0.0, 0.9], [0.7, 0.6, 0.2], [0.3, 0.8, 0.5]],
        ]

        def brute_force(matrix: list[list[float]]) -> float:
            rows = len(matrix)
            columns = len(matrix[0])
            best = 0.0
            for choices in product(range(-1, columns), repeat=rows):
                selected = [column for column in choices if column >= 0]
                if len(selected) != len(set(selected)):
                    continue
                best = max(
                    best,
                    sum(
                        matrix[row][column]
                        for row, column in enumerate(choices)
                        if column >= 0
                    ),
                )
            return best

        for matrix in matrices:
            matches = score_submission.maximum_weight_matching(matrix)
            self.assertAlmostEqual(
                brute_force(matrix),
                sum(score for _, _, score in matches),
            )

    def test_timeline_partial_evidence_cannot_receive_full_credit(self) -> None:
        timestamp = datetime(2026, 7, 6, 10, tzinfo=timezone.utc)
        expected = [
            {
                "id": "T1",
                "stage": "execution",
                "time_start": timestamp.isoformat(),
                "time_end": timestamp.isoformat(),
                "evidence_event_ids": ["E1", "E2", "E3", "E4"],
            }
        ]
        candidate = [
            {
                "stage": "execution",
                "start": timestamp,
                "end": timestamp,
                "evidence_event_ids": {"E1"},
            }
        ]
        ratio, _ = score_submission.score_timeline(
            expected, candidate, timedelta(seconds=0)
        )
        self.assertAlmostEqual(0.61, ratio)
        self.assertLess(ratio, 1.0)

    def test_edge_without_cited_evidence_receives_no_credit(self) -> None:
        timestamp = datetime(2026, 7, 6, 10, tzinfo=timezone.utc)
        expected = [
            {
                "id": "G1",
                "from": "host:a",
                "to": "host:b",
                "action": "remote_service",
                "stage": "lateral_movement",
                "time_start": timestamp.isoformat(),
                "time_end": timestamp.isoformat(),
                "evidence_event_ids": ["E1"],
            }
        ]
        candidate = [
            {
                "from": "host:a",
                "to": "host:b",
                "action": "remote_service",
                "stage": "lateral_movement",
                "start": timestamp,
                "end": timestamp,
                "evidence_event_ids": set(),
            }
        ]
        ratio, _ = score_submission.score_edges(
            expected, candidate, timedelta(seconds=0)
        )
        self.assertEqual(0.0, ratio)

    def test_strict_extras_penalize_unmatched_timeline_and_edge_rows(self) -> None:
        timestamp = datetime(2026, 7, 6, 10, tzinfo=timezone.utc)
        timeline_expected = [
            {
                "id": "T1",
                "stage": "execution",
                "time_start": timestamp.isoformat(),
                "time_end": timestamp.isoformat(),
                "evidence_event_ids": ["E1"],
            }
        ]
        timeline_candidate = [
            {
                "stage": "execution",
                "start": timestamp,
                "end": timestamp,
                "evidence_event_ids": {"E1"},
            },
            {
                "stage": "execution",
                "start": timestamp,
                "end": timestamp,
                "evidence_event_ids": {"E1"},
            },
        ]
        edge_expected = [
            {
                "id": "G1",
                "from": "host:a",
                "to": "host:b",
                "action": "remote_service",
                "stage": "lateral_movement",
                "time_start": timestamp.isoformat(),
                "time_end": timestamp.isoformat(),
                "evidence_event_ids": ["E1"],
            }
        ]
        edge_candidate = [
            {
                "from": "host:a",
                "to": "host:b",
                "action": "remote_service",
                "stage": "lateral_movement",
                "start": timestamp,
                "end": timestamp,
                "evidence_event_ids": {"E1"},
            },
            {
                "from": "host:a",
                "to": "host:b",
                "action": "remote_service",
                "stage": "lateral_movement",
                "start": timestamp,
                "end": timestamp,
                "evidence_event_ids": {"E1"},
            },
        ]
        timeline_ratio, _ = score_submission.score_timeline(
            timeline_expected,
            timeline_candidate,
            timedelta(seconds=0),
            strict_extras=True,
        )
        edge_ratio, _ = score_submission.score_edges(
            edge_expected,
            edge_candidate,
            timedelta(seconds=0),
            strict_extras=True,
        )
        self.assertEqual(0.5, timeline_ratio)
        self.assertEqual(0.5, edge_ratio)

    def test_ioc_identity_without_time_or_evidence_receives_no_credit(self) -> None:
        timestamp = datetime(2026, 7, 6, 10, tzinfo=timezone.utc)
        expected = [
            {
                "type": "ip",
                "value": "203.0.113.77",
                "first_seen": timestamp.isoformat(),
                "last_seen": timestamp.isoformat(),
                "related_assets": ["host:a"],
                "evidence_event_ids": ["E1"],
            }
        ]
        candidate = [
            {
                "type": "IP",
                "value": "203.0.113.77",
                "start": timestamp + timedelta(days=1),
                "end": timestamp + timedelta(days=1),
                "assets": {"host:b"},
                "evidence_event_ids": set(),
            }
        ]
        ratio, _ = score_submission.score_iocs(expected, candidate, timedelta(seconds=0))
        self.assertEqual(0.0, ratio)

    def test_ioc_type_is_case_insensitive_and_one_candidate_is_not_reused(self) -> None:
        timestamp = datetime(2026, 7, 6, 10, tzinfo=timezone.utc)
        expected = {
            "type": "ip",
            "value": "203.0.113.77",
            "first_seen": timestamp.isoformat(),
            "last_seen": timestamp.isoformat(),
            "related_assets": ["host:a"],
            "evidence_event_ids": ["E1"],
        }
        candidate = {
            "type": "IP",
            "value": "203.0.113.77",
            "start": timestamp,
            "end": timestamp,
            "assets": {"host:a"},
            "evidence_event_ids": {"E1"},
        }
        single_ratio, _ = score_submission.score_iocs(
            [expected], [candidate], timedelta(seconds=0)
        )
        duplicate_ratio, _ = score_submission.score_iocs(
            [expected, copy.deepcopy(expected)], [candidate], timedelta(seconds=0)
        )
        self.assertEqual(1.0, single_ratio)
        self.assertEqual(0.5, duplicate_ratio)

    def test_ioc_value_normalization_preserves_posix_and_command_case(self) -> None:
        self.assertNotEqual(
            score_submission.canonical_ioc_key(
                "file", "/var/www/oa/public/.CACHE.php"
            ),
            score_submission.canonical_ioc_key(
                "file", "/var/www/oa/public/.cache.php"
            ),
        )
        self.assertNotEqual(
            score_submission.canonical_ioc_key("command", "PowerShell -File a.ps1"),
            score_submission.canonical_ioc_key("command", "powershell -file a.ps1"),
        )
        self.assertEqual(
            score_submission.canonical_ioc_key("file", "C:\\Temp\\PAYLOAD.EXE"),
            score_submission.canonical_ioc_key("file", "c:/temp/payload.exe"),
        )

    def test_reference_rejects_duplicate_canonical_iocs(self) -> None:
        reference = copy.deepcopy(self.reference)
        reference["iocs"].append(copy.deepcopy(reference["iocs"][0]))
        with tempfile.TemporaryDirectory(prefix="duplicate-reference-ioc-") as temp_dir:
            path = Path(temp_dir) / "reference.json"
            path.write_text(json.dumps(reference), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate canonical IOC"):
                score_submission.load_reference(path)

    def test_slash_equivalent_file_iocs_are_detected_as_duplicates(self) -> None:
        with self.make_reference_submission() as temp_dir:
            directory = Path(temp_dir)
            with (directory / "ioc.csv").open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            file_row = next(row for row in rows if row["type"] == "file")
            duplicate = dict(file_row)
            duplicate["value"] = file_row["value"].replace("\\", "/")
            rows.append(duplicate)
            with (directory / "ioc.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(file_row))
                writer.writeheader()
                writer.writerows(rows)
            _, errors = score_submission.collect_submission(directory)
        self.assertTrue(any("duplicate canonical IOC" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
