"""Tests for :mod:`tools.coverage_analyze`.

These tests exercise the analyzer without ever reading the real
``coverage.json`` committed to the project root: every test materializes
its own minimal payload via :func:`_write_coverage_json` so the test
suite is fully hermetic.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from coverage_analyze import (
    EXIT_BAD_JSON,
    EXIT_NO_COVERAGE,
    EXIT_OK,
    FileSummary,
    TotalSummary,
    compute_diff,
    compute_todo,
    fetch_latest,
    load_coverage,
    main,
    record_to_db,
    render_markdown,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _file_block(
    *,
    percent: float,
    statements: int,
    missing_lines: list[int],
    branches: int = 0,
    missing_branches: int = 0,
    percent_stmt: float | None = None,
) -> dict[str, Any]:
    """Build a minimal coverage.json entry for one file."""

    if percent_stmt is None:
        percent_stmt = percent
    covered_lines = max(statements - len(missing_lines), 0)
    return {
        "executed_lines": list(range(1, statements + 1)),
        "summary": {
            "covered_lines": covered_lines,
            "num_statements": statements,
            "percent_covered": percent,
            "percent_covered_display": str(round(percent)),
            "missing_lines": len(missing_lines),
            "excluded_lines": 0,
            "percent_statements_covered": percent_stmt,
            "percent_statements_covered_display": str(round(percent_stmt)),
            "num_branches": branches,
            "num_partial_branches": max(missing_branches, 0),
            "covered_branches": max(branches - missing_branches, 0),
            "missing_branches": missing_branches,
            "percent_branches_covered": 100.0
            if branches == 0
            else 100.0 * (branches - missing_branches) / branches,
            "percent_branches_covered_display": "100",
        },
        "missing_lines": list(missing_lines),
        "excluded_lines": [],
        "executed_branches": [],
        "missing_branches": [],
    }


def _write_coverage_json(
    path: Path,
    files: dict[str, dict[str, Any]],
    totals: dict[str, Any] | None = None,
) -> Path:
    """Serialize a minimal coverage.json payload and return the path."""

    if totals is None:
        total_stmts = sum(b["summary"]["num_statements"] for b in files.values())
        total_covered = sum(b["summary"]["covered_lines"] for b in files.values())
        total_branches = sum(b["summary"]["num_branches"] for b in files.values())
        total_missing_branches = sum(
            b["summary"]["missing_branches"] for b in files.values()
        )
        total_missing_lines = sum(len(b["missing_lines"]) for b in files.values())
        totals = {
            "covered_lines": total_covered,
            "num_statements": total_stmts,
            "percent_covered": 100.0 if total_stmts == 0 else total_covered * 100.0 / total_stmts,
            "missing_lines": total_missing_lines,
            "num_branches": total_branches,
            "missing_branches": total_missing_branches,
            "percent_branches_covered": 100.0
            if total_branches == 0
            else (total_branches - total_missing_branches) * 100.0 / total_branches,
        }
    payload = {
        "meta": {
            "format": 3,
            "version": "7.0.0",
            "timestamp": "2026-01-01T00:00:00",
            "branch_coverage": True,
            "show_contexts": False,
        },
        "files": files,
        "totals": totals,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# load_coverage
# ---------------------------------------------------------------------------


class TestLoadCoverage:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "no.json"
        with pytest.raises(FileNotFoundError):
            load_coverage(missing)

    def test_corrupt_json_raises_value_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        with pytest.raises(ValueError):
            load_coverage(bad)

    def test_payload_missing_files_block_raises(
        self, tmp_path: Path
    ) -> None:
        bad = tmp_path / "wrong.json"
        bad.write_text(json.dumps({"totals": {}}), encoding="utf-8")
        with pytest.raises(ValueError):
            load_coverage(bad)

    def test_normalizes_windows_paths(self, tmp_path: Path) -> None:
        path = _write_coverage_json(
            tmp_path / "cov.json",
            {
                "shredder_encryptor\\foo.py": _file_block(
                    percent=80.0,
                    statements=10,
                    missing_lines=[],
                ),
            },
        )
        files, _ = load_coverage(path)
        assert "shredder_encryptor/foo.py" in files
        info = files["shredder_encryptor/foo.py"]
        assert info.percent == 80.0
        assert info.statements == 10
        # Derived missing_statements should match percent_statements_covered
        assert info.missing_statements == 2

    def test_derives_missing_statements(self, tmp_path: Path) -> None:
        path = _write_coverage_json(
            tmp_path / "cov.json",
            {
                "a.py": _file_block(
                    percent=50.0,
                    percent_stmt=40.0,
                    statements=10,
                    missing_lines=[1, 2, 3, 4, 5, 6],
                ),
            },
        )
        files, _ = load_coverage(path)
        assert files["a.py"].missing_statements == 6

# ---------------------------------------------------------------------------
# compute_todo / compute_diff
# ---------------------------------------------------------------------------


class TestComputeTodo:
    def test_filters_below_threshold(self) -> None:
        files = {
            "high.py": FileSummary(
                filename="high.py",
                percent=95.0,
                statements=100,
                missing_statements=5,
                branches=0,
                missing_branches=0,
                covered_lines=95,
            ),
            "low.py": FileSummary(
                filename="low.py",
                percent=42.0,
                statements=10,
                missing_statements=6,
                branches=2,
                missing_branches=2,
                covered_lines=4,
                missing_lines=[1, 2, 3, 4, 5, 6],
            ),
        }
        todo = compute_todo(files, threshold=80.0)
        assert [entry["file"] for entry in todo] == ["low.py"]
        entry = todo[0]
        assert entry["cover"] == 42.0
        assert entry["branch_cover"] == 0.0
        assert entry["missing_lines"] == [1, 2, 3, 4, 5, 6]
        assert entry["missing_statements"] == 6

    def test_threshold_inclusive(self) -> None:
        files = {
            "edge.py": FileSummary(
                filename="edge.py",
                percent=80.0,
                statements=10,
                missing_statements=2,
                branches=0,
                missing_branches=0,
                covered_lines=8,
            ),
        }
        assert compute_todo(files, threshold=80.0) == []

    def test_sorted_by_filename(self) -> None:
        files = {
            "zeta.py": FileSummary(
                filename="zeta.py",
                percent=10.0,
                statements=10,
                missing_statements=9,
                branches=0,
                missing_branches=0,
                covered_lines=1,
            ),
            "alpha.py": FileSummary(
                filename="alpha.py",
                percent=20.0,
                statements=10,
                missing_statements=8,
                branches=0,
                missing_branches=0,
                covered_lines=2,
            ),
        }
        todo = compute_todo(files, threshold=80.0)
        assert [e["file"] for e in todo] == ["alpha.py", "zeta.py"]


class TestComputeDiff:
    def _make(self, percent: float, name: str = "f.py") -> FileSummary:
        return FileSummary(
            filename=name,
            percent=percent,
            statements=100,
            missing_statements=int(100 - percent),
            branches=0,
            missing_branches=0,
            covered_lines=int(percent),
        )

    def test_added_and_removed(self) -> None:
        current = {"a.py": self._make(50.0, "a.py")}
        previous = {"b.py": self._make(60.0, "b.py")}
        diff = compute_diff(current, previous)
        assert diff["added"] == [{"file": "a.py", "cover": 50.0}]
        assert diff["removed"] == [{"file": "b.py", "cover": 60.0}]
        assert diff["improved"] == []
        assert diff["regressed"] == []

    def test_improved_and_regressed(self) -> None:
        current = {
            "up.py": self._make(90.0, "up.py"),
            "down.py": self._make(40.0, "down.py"),
        }
        previous = {
            "up.py": self._make(70.0, "up.py"),
            "down.py": self._make(80.0, "down.py"),
        }
        diff = compute_diff(current, previous)
        assert diff["improved"] == [
            {"file": "up.py", "from": 70.0, "to": 90.0}
        ]
        assert diff["regressed"] == [
            {"file": "down.py", "from": 80.0, "to": 40.0}
        ]
        assert diff["added"] == []
        assert diff["removed"] == []

    def test_ignores_small_deltas(self) -> None:
        # 0.05% threshold keeps infinitesimal changes out of the buckets.
        current = {"f.py": self._make(80.05, "f.py")}
        previous = {"f.py": self._make(80.0, "f.py")}
        diff = compute_diff(current, previous)
        assert diff["improved"] == []
        assert diff["regressed"] == []

# ---------------------------------------------------------------------------
# record_to_db / fetch_latest
# ---------------------------------------------------------------------------


class TestStorage:
    def test_record_creates_schema(self, tmp_path: Path) -> None:
        db = tmp_path / "history.db"
        info = [
            FileSummary(
                filename="a.py",
                percent=50.0,
                statements=10,
                missing_statements=5,
                branches=0,
                missing_branches=0,
                covered_lines=5,
            ),
        ]
        n = record_to_db(db, info)
        assert n == 1
        assert db.exists()
        with sqlite3.connect(str(db)) as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        assert ("file_cov",) in tables

    def test_record_appends_rows(self, tmp_path: Path) -> None:
        db = tmp_path / "history.db"
        record_to_db(
            db,
            [
                FileSummary(
                    filename="a.py",
                    percent=50.0,
                    statements=10,
                    missing_statements=5,
                    branches=0,
                    missing_branches=0,
                    covered_lines=5,
                ),
                FileSummary(
                    filename="b.py",
                    percent=80.0,
                    statements=10,
                    missing_statements=2,
                    branches=0,
                    missing_branches=0,
                    covered_lines=8,
                ),
            ],
        )
        record_to_db(
            db,
            [
                FileSummary(
                    filename="a.py",
                    percent=60.0,
                    statements=10,
                    missing_statements=4,
                    branches=0,
                    missing_branches=0,
                    covered_lines=6,
                ),
            ],
        )
        with sqlite3.connect(str(db)) as conn:
            rows = conn.execute(
                "SELECT filename, pct FROM file_cov ORDER BY id"
            ).fetchall()
        assert rows == [("a.py", 50.0), ("b.py", 80.0), ("a.py", 60.0)]

    def test_fetch_latest_returns_most_recent(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "history.db"
        record_to_db(
            db,
            [
                FileSummary(
                    filename="a.py",
                    percent=50.0,
                    statements=10,
                    missing_statements=5,
                    branches=0,
                    missing_branches=0,
                    covered_lines=5,
                ),
            ],
        )
        record_to_db(
            db,
            [
                FileSummary(
                    filename="a.py",
                    percent=70.0,
                    statements=10,
                    missing_statements=3,
                    branches=0,
                    missing_branches=0,
                    covered_lines=7,
                ),
            ],
        )
        latest = fetch_latest(db, ["a.py"])
        assert "a.py" in latest
        assert latest["a.py"].percent == 70.0
        assert latest["a.py"].missing_statements == 3

    def test_fetch_latest_returns_empty_for_missing_files(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "history.db"
        latest = fetch_latest(db, ["unknown.py"])
        assert latest == {}

# ---------------------------------------------------------------------------
# render_markdown
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def _build(self) -> tuple[dict[str, FileSummary], TotalSummary]:
        files = {
            "a.py": FileSummary(
                filename="a.py",
                percent=42.0,
                statements=10,
                missing_statements=6,
                branches=4,
                missing_branches=2,
                covered_lines=4,
                missing_lines=[1, 2, 3, 4, 5, 6],
            ),
            "b.py": FileSummary(
                filename="b.py",
                percent=90.0,
                statements=10,
                missing_statements=1,
                branches=0,
                missing_branches=0,
                covered_lines=9,
            ),
        }
        totals = TotalSummary(
            covered_lines=13,
            num_statements=20,
            percent_covered=65.0,
            missing_lines=7,
            num_branches=4,
            missing_branches=2,
            percent_branches_covered=50.0,
        )
        return files, totals

    def test_includes_threshold_and_totals(self) -> None:
        files, totals = self._build()
        todo = compute_todo(files, threshold=80.0)
        out = render_markdown(files, totals, todo, threshold=80.0)
        assert "Threshold: **80.0%**" in out
        assert "Total: **65.0%** lines" in out
        assert "branches **50.0%**" in out

    def test_low_coverage_table_present(self) -> None:
        files, totals = self._build()
        todo = compute_todo(files, threshold=80.0)
        out = render_markdown(files, totals, todo, threshold=80.0)
        assert "## Low-coverage modules" in out
        assert "| `a.py` | 42.0%" in out
        assert "## All files" in out

    def test_no_low_coverage_message(self) -> None:
        files, totals = self._build()
        out = render_markdown(files, totals, [], threshold=0.0)
        assert "None - every file is at or above the threshold." in out

# ---------------------------------------------------------------------------
# main() end-to-end
# ---------------------------------------------------------------------------


class TestMain:
    def test_missing_json_returns_exit_code(self, tmp_path: Path) -> None:
        code = main(
            [
                "--coverage-json",
                str(tmp_path / "missing.json"),
                "--coverage-db",
                str(tmp_path / "history.db"),
                "--todo-json",
                str(tmp_path / "todo.json"),
                "--quiet",
            ]
        )
        assert code == EXIT_NO_COVERAGE

    def test_corrupt_json_returns_exit_code(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        code = main(
            [
                "--coverage-json",
                str(bad),
                "--coverage-db",
                str(tmp_path / "history.db"),
                "--todo-json",
                str(tmp_path / "todo.json"),
                "--quiet",
            ]
        )
        assert code == EXIT_BAD_JSON

    def test_full_run_writes_artifacts(self, tmp_path: Path) -> None:
        cov_path = _write_coverage_json(
            tmp_path / "cov.json",
            {
                "good.py": _file_block(
                    percent=100.0,
                    statements=4,
                    missing_lines=[],
                ),
                "bad.py": _file_block(
                    percent=20.0,
                    statements=10,
                    missing_lines=[1, 2, 3, 4, 5, 6, 7, 8],
                ),
            },
        )
        db_path = tmp_path / "history.db"
        todo_path = tmp_path / "todo.json"
        md_path = tmp_path / "report.md"
        code = main(
            [
                "--coverage-json",
                str(cov_path),
                "--coverage-db",
                str(db_path),
                "--todo-json",
                str(todo_path),
                "--markdown-report",
                str(md_path),
                "--threshold",
                "50.0",
                "--quiet",
            ]
        )
        assert code == EXIT_OK
        todo = json.loads(todo_path.read_text(encoding="utf-8"))
        assert [entry["file"] for entry in todo] == ["bad.py"]
        assert todo[0]["missing_statements"] == 8
        report = md_path.read_text(encoding="utf-8")
        assert "# Coverage report" in report
        assert "| `bad.py` | 20.0%" in report
        assert db_path.exists()
        with sqlite3.connect(str(db_path)) as conn:
            row_count = conn.execute(
                "SELECT COUNT(*) FROM file_cov"
            ).fetchone()[0]
        assert row_count == 2

    def test_diff_includes_prev_run(self, tmp_path: Path) -> None:
        # First run: only one covered file.
        cov_path = _write_coverage_json(
            tmp_path / "cov.json",
            {
                "a.py": _file_block(
                    percent=50.0,
                    statements=10,
                    missing_lines=[1, 2, 3, 4, 5],
                ),
            },
        )
        db_path = tmp_path / "history.db"
        todo_path = tmp_path / "todo.json"
        md_path = tmp_path / "report.md"
        main(
            [
                "--coverage-json",
                str(cov_path),
                "--coverage-db",
                str(db_path),
                "--todo-json",
                str(todo_path),
                "--markdown-report",
                str(md_path),
                "--quiet",
            ]
        )
        # Second run: a.py improved, b.py added.
        cov_path = _write_coverage_json(
            tmp_path / "cov.json",
            {
                "a.py": _file_block(
                    percent=90.0,
                    statements=10,
                    missing_lines=[1],
                ),
                "b.py": _file_block(
                    percent=10.0,
                    statements=10,
                    missing_lines=[1, 2, 3, 4, 5, 6, 7, 8, 9],
                ),
            },
        )
        code = main(
            [
                "--coverage-json",
                str(cov_path),
                "--coverage-db",
                str(db_path),
                "--todo-json",
                str(todo_path),
                "--markdown-report",
                str(md_path),
                "--diff",
                "--quiet",
            ]
        )
        assert code == EXIT_OK
        report = md_path.read_text(encoding="utf-8")
        assert "Diff vs previous run" in report
        assert "1 improved" in report
        assert "1 added" in report

