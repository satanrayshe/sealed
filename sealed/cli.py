"""Command line: python -m sealed explain <alerts.json> | demo | app | evaluate | generate

Exit codes: 0 every alert explained (or a replay duplicate), 1 input rejected
or unreadable, 2 usage error, 3 at least one alert rejected, 4 internal error
(reported by type only, never with a traceback that could quote input).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import TextIO

from .contract import MAX_INPUT_BYTES
from .explain import explain
from .generate import write_data
from .template_eval import write_results
from .narrate import OllamaNarrator, TemplateNarrator
from .render import render, short_id

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
    detector = None
    if args.detector == "learned":
        from .learned import LearnedDetector
        detector = LearnedDetector()
    report = explain(data, narrator=narrator, detector=detector)
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
        shown = short_id(r["alert_id"], 26)
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
    p.add_argument("--detector", choices=["keyword", "learned"], default="keyword",
                   help="injection detector: the keyword baseline (default) or the learned n-gram model")
    p.set_defaults(handler=cmd_explain)

    p = sub.add_parser("demo", help="run on the bundled sample alerts (offline, template narrator)")
    p.set_defaults(handler=cmd_demo)

    p = sub.add_parser("app", help="local two-pane app on http://127.0.0.1 (this machine only)")
    p.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default 8765)")
    p.set_defaults(handler=cmd_app)

    p = sub.add_parser("evaluate", help="run an evaluation arm and write or print its results")
    p.add_argument("--arm", choices=["template", "models", "detectors"], default="template",
                   help="template: offline, no model; models: the three model arms for one local model; "
                        "detectors: train and compare the learned detector (needs --corpora)")
    p.add_argument("--corpora", default=None, help="directory made by tools/fetch_corpora.py (for --arm detectors)")
    p.add_argument("--out", default="results", help="output directory for the template arm (default: results)")
    p.add_argument("--model", default=None,
                   help="--arm models: one model tag (prints its summary); default: all three, written to --out")
    p.add_argument("--limit", type=int, default=None,
                   help="--arm models: the first N class-interleaved triples (default: the plan's number per model)")
    p.add_argument("--run", action="store_true",
                   help="ask the local server for replies not yet cached (otherwise summarise the cache offline)")
    p.add_argument("--base-url", default="http://127.0.0.1:11434", help="local /api/chat server (loopback only)")
    p.add_argument("--cache-dir", default=None, help="reply cache (default: cache/model_arms in the repository)")
    p.set_defaults(handler=cmd_evaluate)

    p = sub.add_parser("generate", help="rewrite the seeded synthetic data files")
    p.add_argument("--out", default="data", help="output directory (default: data)")
    p.set_defaults(handler=cmd_generate)
    return parser


def cmd_app(args: argparse.Namespace, out: TextIO) -> int:
    if not 0 < args.port < 65536:
        sys.stderr.write("error: --port must be between 1 and 65535" + chr(10))
        return 2
    from .app import serve  # imported here so the other commands never load http.server
    serve(args.port)
    return 0


def cmd_models(args: argparse.Namespace, out: TextIO) -> int:
    from . import model_eval
    models = [args.model] if args.model else list(model_eval.MODELS)
    if any(m not in model_eval.MODELS for m in models) or (args.limit is not None and not 0 < args.limit <= 1200):
        sys.stderr.write(f"error: --model must be one of {', '.join(model_eval.MODELS)} and --limit 1 to 1200" + chr(10))
        return 2
    if args.run and not args.model:
        sys.stderr.write("error: --run asks one model at a time; add --model" + chr(10))
        return 2
    cache = args.cache_dir or model_eval.DEFAULT_CACHE
    summaries, limits = [], {}
    for model in models:
        limits[model] = args.limit or model_eval.PLAN_LIMITS[model]
        triples = model_eval.interleaved_triples()[:limits[model]]
        if args.run:
            def progress(p: dict) -> None:
                out.write(f"{p['model']} {p['done']}/{p['total']} {p['arm']} mean {p['mean_seconds']}s "
                          f"remaining about {p['remaining_seconds'] // 60} min" + chr(10))
                out.flush()
            model_eval.run(model, triples, base_url=args.base_url, cache_dir=cache, progress=progress)
        summaries.append(model_eval.summarise(model, triples, cache_dir=cache))
    if args.model:
        out.write(json.dumps(summaries[0], indent=2) + chr(10))
    incomplete = [s for s in summaries if not s["complete"]]
    for s in incomplete:
        c = s["coverage"]
        sys.stderr.write(f"warning: {s['model']}: {c['triples_complete']} of {c['triples_planned']} triples complete "
                         f"in every arm, {c['clean_alerts_complete']} of {c['clean_alerts_planned']} clean alerts; "
                         "no results written" + chr(10))
    if incomplete:
        return 1
    if args.model:
        return 0
    result = model_eval.results(summaries, limits)
    out.write(model_eval.readme_block(result) + chr(10))
    for path in model_eval.write_results(result, args.out).values():
        out.write(f"wrote {path.as_posix()}" + chr(10))
    return 0


def cmd_detectors(args: argparse.Namespace, out: TextIO) -> int:
    from . import detector_eval
    if not args.corpora or not Path(args.corpora).is_dir():
        sys.stderr.write("error: --corpora must name the directory made by tools/fetch_corpora.py" + chr(10))
        return 2
    paths = detector_eval.write_results(detector_eval.run(Path(args.corpora)), Path(args.out))
    for path in paths.values():
        out.write(f"wrote {path.as_posix()}" + chr(10))
    return 0


def cmd_evaluate(args: argparse.Namespace, out: TextIO) -> int:
    if args.arm == "models":
        return cmd_models(args, out)
    if args.arm == "detectors":
        return cmd_detectors(args, out)
    paths = write_results(args.out)
    result = json.loads(paths["template_arm.json"].read_text(encoding="utf-8"))
    for label, metric in [("M1 seal invariance", result["seal_invariance"]),
                          ("M2 action stability", result["action_stability"]),
                          ("M3 uncertainty never lowered", result["uncertainty_never_lowered"]),
                          ("M4 detector recall (test)", result["test"]["recall"]),
                          ("M5 false flags (test)", result["test"]["false_flags"]),
                          ("M6 escalation fired", result["escalation_rate"])]:
        low, high = metric["wilson95"]
        out.write(f"{label:30s} {metric['k']:>5} / {metric['n']:<5} {100 * metric['rate']:5.1f}%  "
                  f"[{100 * low:.1f}%, {100 * high:.1f}%]\n")
    for path in paths.values():
        out.write(f"wrote {path.as_posix()}\n")
    return 0


def cmd_generate(args: argparse.Namespace, out: TextIO) -> int:
    for name, path in write_data(args.out).items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        out.write(f"{digest}  {path.as_posix()}\n")
    return 0


def main(argv: list[str] | None = None, out: TextIO | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # never crash on a console that lacks a glyph
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args, out or sys.stdout)
    except Exception as err:  # no traceback: it could quote input values
        sys.stderr.write(f"internal error ({type(err).__name__}); no input content is shown\n")
        return 4
