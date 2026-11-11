"""Command line: python -m sealed explain <alerts.json> | demo

Exit codes: 0 every alert explained (or a replay duplicate), 1 input rejected
or unreadable, 2 usage error, 3 at least one alert rejected.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from .contract import MAX_INPUT_BYTES
from .explain import explain
from .narrate import OllamaNarrator, TemplateNarrator
from .quarantine import escape
from .render import render

SAMPLES = Path(__file__).with_name("samples")


def _read(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    with open(path, "rb") as handle:
        return handle.read(MAX_INPUT_BYTES + 1)


def _status(report: dict) -> int:
    if report["input"]["status"] != "ok":
        return 1
    return 3 if any(r["status"] == "rejected" for r in report["results"]) else 0


def _print_report(report: dict, fmt: str, out: TextIO) -> None:
    if fmt in ("text", "both"):
        out.write(render(report))
    if fmt == "both":
        out.write("\n--- JSON ---\n")
    if fmt in ("json", "both"):
        out.write(json.dumps(report, ensure_ascii=True, indent=2) + "\n")


def cmd_explain(args: argparse.Namespace, out: TextIO) -> int:
    try:
        data = _read(args.path)
    except OSError as err:
        sys.stderr.write(f"cannot read {args.path}: {err.strerror or type(err).__name__}\n")
        return 1
    narrator = TemplateNarrator()
    if args.narrator == "ollama":
        try:
            narrator = OllamaNarrator(args.model, base_url=args.ollama_url, cache_dir=args.cache_dir,
                                      offline=args.offline)
        except ValueError as err:  # bad --model or a non-loopback --ollama-url
            sys.stderr.write(f"error: {err}\n")
            return 2
    report = explain(data, narrator=narrator)
    _print_report(report, args.format, out)
    return _status(report)


def _why(result: dict) -> str:
    if result["status"] == "rejected":
        return ", ".join(e["code"] for e in result["errors"])
    if result["status"] == "duplicate":
        return f"replay of [{result['duplicate_of'] + 1}]"
    notes = [reason["rule"] for reason in result["uncertainty"]["reasons"]]
    if result["recommendation"]["escalated_by_injection_evidence"]:
        notes.append("escalated by injection evidence")
    return ", ".join(notes) or "-"


def cmd_demo(args: argparse.Namespace, out: TextIO) -> int:
    clean = explain((SAMPLES / "track_example.json").read_bytes())
    attacked = explain((SAMPLES / "attacked_username.json").read_bytes())
    edge = explain((SAMPLES / "edge_cases.json").read_bytes())

    out.write("=== 1. The organiser's Track 4 example ===\n")
    out.write(render(clean))
    out.write("\n=== 2. The same alert with an attack written into the username ===\n")
    out.write(render(attacked))

    before = clean["results"][0]["model_input"]["sha256"]
    after = attacked["results"][0]["model_input"]["sha256"]
    out.write("\n=== Seal check ===\n")
    out.write(f"clean alert     model input SHA-256 {before}\n")
    out.write(f"attacked alert  model input SHA-256 {after}\n")
    out.write("identical: yes. The narrator receives the same bytes whatever the username says.\n"
              if before == after else "identical: NO. This is a bug.\n")

    out.write("\n=== 3. Edge cases (detail: python -m sealed explain sealed/samples/edge_cases.json) ===\n")
    out.write(f"{'#':>3}  {'id':<28} {'status':<10} {'action':<9} {'uncertainty':<12} why\n")
    for r in edge["results"]:
        shown = escape(r["alert_id"], 26)[0] if r["alert_id"] is not None else "(no valid id)"
        action = r["recommendation"]["action"] if r["status"] == "explained" else "-"
        level = r["uncertainty"]["level"] if r["status"] == "explained" else "-"
        out.write(f"{r['index'] + 1:>3}  {shown:<28} {r['status']:<10} {action:<9} {level:<12} {_why(r)}\n")
    out.write("\nOffline run: no model, no network, no downloads. Every action is a mock recommendation.\n")
    return 0 if before == after else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m sealed",
                                     description="Explain security alerts without letting a model read attacker text.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("explain", help="explain the alerts in a Track 4 JSON file ('-' reads standard input)")
    p.add_argument("path")
    p.add_argument("--format", choices=["both", "text", "json"], default="both")
    p.add_argument("--narrator", choices=["template", "ollama"], default="template",
                   help="template (default, no model) or a local Ollama model")
    p.add_argument("--model", default="qwen2.5:7b-instruct", help="Ollama model name (with --narrator ollama)")
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="loopback addresses only")
    p.add_argument("--cache-dir", default="cache/narrations", help="narration cache, keyed by model-input hash")
    p.add_argument("--offline", action="store_true", help="replay cached narrations only; never call Ollama")
    p.set_defaults(handler=cmd_explain)

    p = sub.add_parser("demo", help="run on the bundled sample alerts (offline, template narrator)")
    p.set_defaults(handler=cmd_demo)
    return parser


def main(argv: list[str] | None = None, out: TextIO | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # never crash on a console that lacks a glyph
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    return args.handler(args, out or sys.stdout)
