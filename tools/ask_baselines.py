"""Ask the two baseline arms about your own alert, with a live local model.

The public page has no model, so it cannot show how the raw-prompt and
hardened explainers answer text you typed. This sends them the same requests
the evaluation sends (sealed/model_eval.py, Client.body: same prompts, JSON
format, temperature 0, seed 0) and prints each reply next to Sealed's own
decision. It talks only to a model server on this machine and writes nothing,
not even to the evaluation's reply cache.

    <python with torch> tools/local_model_server.py --model qwen3-1.7b:bf16      (or Ollama)
    python tools/ask_baselines.py alert.json --model qwen3-1.7b:bf16 [--url http://127.0.0.1:11434]

Exit codes: 0 replies printed, 1 the input has no alert to ask about or the
server could not be reached, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, TextIO

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sealed.contract import MAX_INPUT_BYTES, Alert, parse_document  # noqa: E402  (stdlib-only package)
from sealed.evaluate import parse_decision  # noqa: E402
from sealed.explain import explain  # noqa: E402
from sealed.model_eval import BASELINES, Client  # noqa: E402
from sealed.narrate import urllib_transport  # noqa: E402

MAX_ALERTS = 5


def ask(data: bytes, model: str, url: str, *, transport: Callable = urllib_transport, timeout: float = 900.0,
        out: TextIO = sys.stdout) -> int:
    client = Client(model, base_url=url, transport=transport, offline=True)  # offline: never touches a cache
    report = explain(data)
    if report["input"]["status"] != "ok":
        out.write("The input was rejected, so there is no alert to ask about: "
                  + ", ".join(issue["code"] for issue in report["input"]["issues"]) + "\n")
        return 1
    alerts = json.loads(data.decode("utf-8-sig"))["alerts"]
    parsed = [item for item in parse_document(data).items if isinstance(item, Alert)]
    if not parsed:
        out.write("No alert in the input was explained, so there is nothing to ask about.\n")
        return 1
    results = {r["index"]: r for r in report["results"]}
    for item in parsed[:MAX_ALERTS]:
        sealed = results[item.index]["recommendation"]["action"]
        out.write(f"=== alert {item.index + 1}: Sealed's decision (policy, no model): {sealed}\n")
        for arm in BASELINES:
            body = client.body(arm, alerts[item.index], item)
            try:
                raw = transport(client.url, body, timeout)
                content = json.loads(raw.decode("utf-8"))["message"]["content"]
            except OSError as error:
                out.write(f"--- {arm}: the server at {url} did not answer ({type(error).__name__})\n")
                return 1
            except (UnicodeDecodeError, ValueError, KeyError, TypeError, RecursionError):
                out.write(f"--- {arm}: the server's reply is not an /api/chat response\n")
                return 1
            out.write(f"--- {arm} ({model}): decision {parse_decision(str(content))}\n{content}\n")
    if len(parsed) > MAX_ALERTS:
        out.write(f"Asked about the first {MAX_ALERTS} of {len(parsed)} alerts.\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python tools/ask_baselines.py", description=__doc__.splitlines()[0])
    parser.add_argument("path", help="an alert document in the Track 4 format ('-' reads stdin)")
    parser.add_argument("--model", required=True, help="the model name the local server answers to")
    parser.add_argument("--url", default="http://127.0.0.1:11434", help="a loopback address only")
    args = parser.parse_args(argv)
    try:
        if args.path == "-":
            data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            with open(args.path, "rb") as handle:
                data = handle.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        sys.stderr.write(f"cannot read {args.path}: {error.strerror or type(error).__name__}\n")
        return 1
    try:
        return ask(data, args.model, args.url)
    except ValueError as error:  # a bad model name or a non-loopback URL
        sys.stderr.write(f"error: {error}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
