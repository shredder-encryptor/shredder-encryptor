# tools/coverage_analyze.py
# Post-process the coverage.json artifact produced by pytest-cov.
#
# The default invocation reads coverage.json (created by
# `pytest --cov=shredder_encryptor --cov-report=json tests/`), appends a
# row per source file to a SQLite history database, and writes a
# test_todo.json artifact listing every file whose coverage is below
# the configured threshold.  An optional Markdown report can also be
# produced for CI summaries.
#
# The script deliberately keeps zero third-party dependencies so it can
# run inside the same minimal environment as the rest of the project.

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_NO_COVERAGE = 1
EXIT_BAD_JSON = 2
EXIT_DB_ERROR = 3
EXIT_IO_ERROR = 4

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileSummary:
    # A flattened view of one entry in coverage.json's files map.
    filename: str
    percent: float
    statements: int
    missing_statements: int
    branches: int
    missing_branches: int
    covered_lines: int
    missing_lines: list[int] = field(default_factory=list)

    @property
    def pct_display(self) -> str:
        return f"{self.percent:.1f}%"

    @property
    def branch_pct(self) -> float:
        if self.branches <= 0:
            return 100.0
        covered = max(self.branches - self.missing_branches, 0)
        return covered * 100.0 / self.branches


@dataclass(frozen=True)
class TotalSummary:
    # The top-level totals block of coverage.json.
    covered_lines: int
    num_statements: int
    percent_covered: float
    missing_lines: int
    num_branches: int
    missing_branches: int
    percent_branches_covered: float

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "TotalSummary":
        return cls(
            covered_lines=int(raw.get("covered_lines", 0)),
            num_statements=int(raw.get("num_statements", 0)),
            percent_covered=float(raw.get("percent_covered", 0.0)),
            missing_lines=int(raw.get("missing_lines", 0)),
            num_branches=int(raw.get("num_branches", 0)),
            missing_branches=int(raw.get("missing_branches", 0)),
            percent_branches_covered=float(raw.get("percent_branches_covered", 100.0)),
        )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _normalize_filename(raw: str) -> str:
    # Normalize a path entry from coverage.json.
    # coverage.json uses backslashes on Windows and forward slashes on
    # Linux/macOS.  Build a forward-slash, relative path so the resulting
    # history database is portable across CI runners.
    return raw.replace("\\", "/").lstrip("./")


def load_coverage(json_path: Path) -> tuple[dict[str, FileSummary], TotalSummary]:
    # Read coverage.json and return (files, totals).
    # Raises FileNotFoundError if the path is missing and ValueError if
    # the payload is malformed.
    if not json_path.exists():
        raise FileNotFoundError(f"coverage JSON not found: {json_path}")

    try:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse {json_path}: {exc}") from exc

    if not isinstance(payload, Mapping) or "files" not in payload:
        raise ValueError(f"{json_path} is not a coverage.json payload")

    files: dict[str, FileSummary] = {}
    for raw_name, info in payload.get("files", {}).items():
        summary = info.get("summary", {}) if isinstance(info, Mapping) else {}
        # coverage.py 7.x does not include missing_statements in the
        # summary block (it only emits missing_lines).  Derive a
        # faithful count from num_statements and
        # percent_statements_covered so downstream fields stay useful.
        num_statements = int(summary.get("num_statements", 0))
        pct_stmt = float(summary.get("percent_statements_covered", 0.0))
        covered_statements = round(num_statements * pct_stmt / 100.0)
        missing_statements = max(num_statements - covered_statements, 0)
        files[_normalize_filename(raw_name)] = FileSummary(
            filename=_normalize_filename(raw_name),
            percent=float(summary.get("percent_covered", 0.0)),
            statements=num_statements,
            missing_statements=missing_statements,
            branches=int(summary.get("num_branches", 0)),
            missing_branches=int(summary.get("missing_branches", 0)),
            covered_lines=int(summary.get("covered_lines", 0)),
            missing_lines=[int(x) for x in info.get("missing_lines", [])]
            if isinstance(info, Mapping)
            else [],
        )

    totals_raw = payload.get("totals", {}) if isinstance(payload, Mapping) else {}
    totals = TotalSummary.from_json(
        totals_raw if isinstance(totals_raw, Mapping) else {}
    )

    return files, totals


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


SCHEMA = """
CREATE TABLE IF NOT EXISTS file_cov (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    statements INTEGER NOT NULL,
    missing INTEGER NOT NULL,
    branches INTEGER NOT NULL,
    missing_branches INTEGER NOT NULL,
    pct REAL NOT NULL,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

CREATE_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_file_cov_filename_ts ON file_cov (filename, ts)"
)


def _ensure_schema(cur: sqlite3.Cursor) -> None:
    cur.execute(SCHEMA)
    cur.execute(CREATE_INDEX)


def record_to_db(db_path: Path, files: Iterable[FileSummary]) -> int:
    # Insert every file's summary into file_cov and return the row count.
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        db = sqlite3.connect(str(db_path))
    except sqlite3.Error as exc:
        raise RuntimeError(f"cannot open sqlite db {db_path}: {exc}") from exc

    try:
        cur = db.cursor()
        _ensure_schema(cur)
        rows = [
            (
                f.filename,
                f.statements,
                f.missing_statements,
                f.branches,
                f.missing_branches,
                f.percent,
            )
            for f in files
        ]
        cur.executemany(
            "INSERT INTO file_cov "
            "(filename, statements, missing, branches, missing_branches, pct) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        db.commit()
        return len(rows)
    finally:
        db.close()


def fetch_latest(db_path: Path, filenames: Iterable[str]) -> dict[str, FileSummary]:
    # Return the most recent FileSummary for every given filename.
    # Used by compute_diff to compare the current run against the previous
    # SQLite snapshot.  Filenames that have no history are omitted from
    # the returned mapping.
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(db_path))
    try:
        cur = db.cursor()
        # Make sure the schema exists so the lookup below is safe even
        # when the caller has never written to the database yet.
        _ensure_schema(cur)
        result: dict[str, FileSummary] = {}
        for fname in filenames:
            cur.execute(
                "SELECT filename, statements, missing, branches, "
                "missing_branches, pct FROM file_cov "
                "WHERE filename = ? ORDER BY ts DESC, id DESC LIMIT 1",
                (fname,),
            )
            row = cur.fetchone()
            if row is None:
                continue
            (h_name, h_stmts, h_miss, h_br, h_mbr, h_pct) = row
            result[h_name] = FileSummary(
                filename=h_name,
                percent=float(h_pct),
                statements=int(h_stmts),
                missing_statements=int(h_miss),
                branches=int(h_br),
                missing_branches=int(h_mbr),
                covered_lines=int(h_stmts) - int(h_miss),
                missing_lines=[],
            )
        return result
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def compute_todo(
    files: Mapping[str, FileSummary], threshold: float
) -> list[dict[str, Any]]:
    # Return the list of low-coverage modules below threshold.
    out: list[dict[str, Any]] = []
    for fname in sorted(files):
        info = files[fname]
        if info.percent < threshold:
            out.append(
                {
                    "file": fname,
                    "cover": round(info.percent, 2),
                    "branch_cover": round(info.branch_pct, 2),
                    "missing_lines": info.missing_lines,
                    "missing_statements": info.missing_statements,
                }
            )
    return out


def compute_diff(
    current: Mapping[str, FileSummary],
    previous: Mapping[str, FileSummary],
) -> dict[str, list[dict[str, Any]]]:
    # Compare current against previous and bucket the deltas.
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    improved: list[dict[str, Any]] = []
    regressed: list[dict[str, Any]] = []

    for fname, info in current.items():
        if fname not in previous:
            added.append({"file": fname, "cover": round(info.percent, 2)})
            continue
        delta = info.percent - previous[fname].percent
        if delta > 0.05:
            improved.append(
                {
                    "file": fname,
                    "from": round(previous[fname].percent, 2),
                    "to": round(info.percent, 2),
                }
            )
        elif delta < -0.05:
            regressed.append(
                {
                    "file": fname,
                    "from": round(previous[fname].percent, 2),
                    "to": round(info.percent, 2),
                }
            )

    for fname, info in previous.items():
        if fname not in current:
            removed.append({"file": fname, "cover": round(info.percent, 2)})

    return {
        "added": added,
        "removed": removed,
        "improved": improved,
        "regressed": regressed,
    }


def render_markdown(
    files: Mapping[str, FileSummary],
    totals: TotalSummary,
    todo: list[dict[str, Any]],
    threshold: float,
    diff: Mapping[str, list[dict[str, Any]]] | None = None,
) -> str:
    # Build a Markdown summary suitable for CI artifacts.
    lines: list[str] = []
    lines.append("# Coverage report")
    lines.append("")
    lines.append(
        f"_Threshold: **{threshold:.1f}%** - "
        f"Total: **{totals.percent_covered:.1f}%** lines "
        f"({totals.covered_lines}/{totals.num_statements} statements), "
        f"branches **{totals.percent_branches_covered:.1f}%** "
        f"({totals.num_branches - totals.missing_branches}/"
        f"{totals.num_branches})._"
    )
    lines.append("")

    if diff:
        counts = {k: len(v) for k, v in diff.items()}
        lines.append(
            "Diff vs previous run: "
            f"{counts['improved']} improved, "
            f"{counts['regressed']} regressed, "
            f"{counts['added']} added, "
            f"{counts['removed']} removed."
        )
        lines.append("")

    lines.append("## Low-coverage modules")
    lines.append("")
    if not todo:
        lines.append("_None - every file is at or above the threshold._")
    else:
        lines.append(
            "| File | Line % | Branch % | Missing statements | Missing lines |"
        )
        lines.append("|---|---:|---:|---:|---|")
        for entry in todo:
            miss_lines = ", ".join(str(x) for x in entry["missing_lines"][:20])
            if len(entry["missing_lines"]) > 20:
                miss_lines += ", ..."
            lines.append(
                f"| `{entry['file']}` "
                f"| {entry['cover']:.1f}% "
                f"| {entry['branch_cover']:.1f}% "
                f"| {entry['missing_statements']} "
                f"| {miss_lines or '-'} |"
            )
    lines.append("")

    lines.append("## All files")
    lines.append("")
    lines.append("| File | Line % | Branch % | Statements | Covered |")
    lines.append("|---|---:|---:|---:|---:|")
    for fname in sorted(files):
        info = files[fname]
        covered = info.statements - info.missing_statements
        lines.append(
            f"| `{fname}` | {info.percent:.1f}% | {info.branch_pct:.1f}% "
            f"| {info.statements} | {covered} |"
        )
    lines.append("")
    return "\n".join(lines)


def print_summary(
    files: Mapping[str, FileSummary],
    totals: TotalSummary,
    todo: list[dict[str, Any]],
    threshold: float,
) -> None:
    # Print a short human-readable summary to stdout.
    print("Coverage summary")
    print(f"  total line coverage:   {totals.percent_covered:.1f}%")
    print(f"  total branch coverage: {totals.percent_branches_covered:.1f}%")
    print(f"  files tracked:         {len(files)}")
    print(f"  threshold:             {threshold:.1f}%")
    print(f"  low-coverage modules:  {len(todo)}")
    for entry in todo:
        print(f"   - {entry['file']}  {entry['cover']:.1f}%")


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze a coverage.json artifact, record history in SQLite, "
            "and emit a low-coverage TODO list for CI."
        )
    )
    parser.add_argument(
        "--coverage-json",
        type=Path,
        default=Path("coverage.json"),
        help="Path to the coverage.json file (default: ./coverage.json)",
    )
    parser.add_argument(
        "--coverage-db",
        type=Path,
        default=Path("coverage_history.db"),
        help="Path to the SQLite history database (default: ./coverage_history.db)",
    )
    parser.add_argument(
        "--todo-json",
        type=Path,
        default=Path("test_todo.json"),
        help="Path to the JSON TODO artifact (default: ./test_todo.json)",
    )
    parser.add_argument(
        "--markdown-report",
        type=Path,
        default=None,
        help="Optional path to emit a Markdown report",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=80.0,
        help="Coverage percentage below which a file is added to the TODO "
        "(default: 80.0)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Compare against the previous SQLite snapshot and include "
        "a diff section in the Markdown report",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print the summary but skip writing the TODO JSON / Markdown "
        "report.  Useful for local sanity checks.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg)

    # 1. Load coverage.json
    try:
        files, totals = load_coverage(args.coverage_json)
    except FileNotFoundError:
        print(
            f"Error: coverage JSON not found at {args.coverage_json}. "
            "Run `pytest --cov=shredder_encryptor "
            "--cov-report=json tests/` first.",
            file=sys.stderr,
        )
        return EXIT_NO_COVERAGE
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_BAD_JSON

    # 2. Optionally diff against previous run before inserting the new one
    diff: dict[str, list[dict[str, Any]]] | None = None
    if args.diff and args.coverage_db.exists():
        try:
            previous = fetch_latest(args.coverage_db, files.keys())
        except sqlite3.Error as exc:
            print(f"Error reading history db: {exc}", file=sys.stderr)
            return EXIT_DB_ERROR
        diff = compute_diff(files, previous)

    # 3. Append to the history database
    try:
        inserted = record_to_db(args.coverage_db, files.values())
    except sqlite3.Error as exc:
        print(f"Error writing history db: {exc}", file=sys.stderr)
        return EXIT_DB_ERROR
    log(f"Recorded {inserted} rows in {args.coverage_db}")

    # 4. Compute and (optionally) emit the TODO list
    todo = compute_todo(files, threshold=args.threshold)

    if not args.summary_only:
        try:
            args.todo_json.parent.mkdir(parents=True, exist_ok=True)
            args.todo_json.write_text(
                json.dumps(todo, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"Error writing {args.todo_json}: {exc}", file=sys.stderr)
            return EXIT_IO_ERROR
        log(f"Wrote {len(todo)} low-coverage modules to {args.todo_json}")

        if args.markdown_report is not None:
            try:
                args.markdown_report.parent.mkdir(parents=True, exist_ok=True)
                args.markdown_report.write_text(
                    render_markdown(files, totals, todo, args.threshold, diff=diff),
                    encoding="utf-8",
                )
            except OSError as exc:
                print(
                    f"Error writing {args.markdown_report}: {exc}",
                    file=sys.stderr,
                )
                return EXIT_IO_ERROR
            log(f"Wrote Markdown report to {args.markdown_report}")

    print_summary(files, totals, todo, args.threshold)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
