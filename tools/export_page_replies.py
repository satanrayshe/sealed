"""Export the recorded baseline replies that the public page shows for its presets.

After the model run, this reads the run's reply cache offline (no model, no
network) and writes docs/page/replies.json: for every preset in
docs/page/presets.json, every model and both baseline arms, the reply about
the attacked alert and the reply about its twin (the same alert with "x" in
the attacked field), each with its decision as the evaluation parses it.
While any of those replies is missing it writes nothing and exits 1.

    python tools/export_page_replies.py                 the real file, from cache/model_arms
    python tools/export_page_replies.py --dry-run       a DRY RUN document on stdout

The dry run reads no cache and asks no model. Every row in it is synthetic:
its "decision" is the policy's action for that alert (what the template arm
computes) and its "content" says DRY RUN. It is marked "dry_run": true, it is
never written under docs/, and the page refuses to show it.

Exit codes: 0 written (or printed), 1 replies missing or the presets file is
out of date, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sealed.evaluate import parse_decision  # noqa: E402  (stdlib-only package)
from sealed.explain import explain  # noqa: E402
from sealed.model_eval import BASELINES, DEFAULT_CACHE, MODELS, Client, _parsed, json_object  # noqa: E402
from sealed.page import REPLIES_SCHEMA, presets_document  # noqa: E402

DOCS = ROOT / "docs"
PRESETS = DOCS / "page" / "presets.json"
OUT = DOCS / "page" / "replies.json"
GENERATED_BY = "python tools/export_page_replies.py"
SOURCE = "the reply cache of the evaluation's model run, read offline"
DRY_SOURCE = ("DRY RUN: synthetic rows, not model replies. Each decision is the policy's action for that alert "
              "(the template arm); no cache was read and no model was asked.")
DRY_MODEL = "dry-run:template-arm"


def _row(content: str, request_sha256: str | None) -> dict:
    return {"decision": parse_decision(content), "valid_json": json_object(content) is not None,
            "content": content, "request_sha256": request_sha256}


def _dry_row(alert: dict) -> dict:
    action = explain(json.dumps({"alerts": [alert]}))["results"][0]["recommendation"]["action"]
    content = json.dumps({"action": action, "explanation": "DRY RUN synthetic row: the policy's action, not a "
                                                           "model reply."})
    return _row(content, None)


def build(presets: list[dict], *, dry_run: bool, cache_dir: Path = DEFAULT_CACHE,
          models: tuple[str, ...] = MODELS) -> tuple[dict, list[str]]:
    """The replies document and a list of what is missing (empty when complete)."""
    missing: list[str] = []
    out = {"schema": REPLIES_SCHEMA, "generated_by": GENERATED_BY + (" --dry-run" if dry_run else ""),
           "dry_run": dry_run, "source": DRY_SOURCE if dry_run else SOURCE,
           "models": [DRY_MODEL] if dry_run else list(models), "presets": {}}
    for preset in presets:
        variants = {"twin": preset["twin"], "attacked": preset["alert"]}
        replies: dict[str, dict] = {}
        if dry_run:
            replies[DRY_MODEL] = {arm: {name: _dry_row(alert) for name, alert in variants.items()} for arm in BASELINES}
        for model in () if dry_run else models:
            client = Client(model, cache_dir=cache_dir, transport=lambda *a: b"", offline=True)
            replies[model] = {}
            for arm in BASELINES:
                replies[model][arm] = {}
                for name, alert in variants.items():
                    record = client.cached(client.body(arm, alert, _parsed(alert)))
                    if record is None:
                        missing.append(f"{preset['id']} {model} {arm} {name}")
                        continue
                    replies[model][arm][name] = _row(record["content"], record["request_sha256"])
        out["presets"][preset["id"]] = {"triple": preset["triple"], "prompt_sha256": preset["prompt_sha256"],
                                        "replies": replies}
    return out, missing


def to_text(doc: dict) -> str:
    text = json.dumps(doc, ensure_ascii=True, indent=1)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") + "\n"


def _inside(path: Path, folder: Path) -> bool:
    try:
        path.resolve().relative_to(folder.resolve())
    except ValueError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python tools/export_page_replies.py", description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="synthetic rows, printed; reads no cache")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE), help="the model run's reply cache")
    parser.add_argument("--out", default=None, help=f"where to write (default {OUT.relative_to(ROOT).as_posix()}; "
                                                    "the dry run prints unless given a path outside docs/)")
    args = parser.parse_args(argv)
    if args.dry_run and args.out is not None and _inside(Path(args.out), DOCS):
        sys.stderr.write("error: a dry run is never written under docs/, where the page would publish it\n")
        return 2
    document = presets_document()
    if not args.dry_run:
        shipped = json.loads(PRESETS.read_text(encoding="utf-8")) if PRESETS.is_file() else None
        if shipped != json.loads(json.dumps(document)):
            sys.stderr.write("error: docs/page/presets.json is missing or out of date; run python tools/build_page.py\n")
            return 1
    doc, missing = build(document["presets"], dry_run=args.dry_run, cache_dir=Path(args.cache_dir))
    if missing:
        sys.stderr.write(f"{len(missing)} replies are missing from the cache; nothing written. First: {missing[0]}\n")
        return 1
    text = to_text(doc)
    if args.dry_run and args.out is None:
        sys.stdout.write("# DRY RUN: synthetic rows, not model replies; not for publication\n")
        sys.stdout.write(text)
        return 0
    path = Path(args.out) if args.out is not None else OUT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {path} ({len(doc['presets'])} presets, {'DRY RUN' if args.dry_run else 'recorded replies'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
