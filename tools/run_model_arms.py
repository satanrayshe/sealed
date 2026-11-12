"""Run the model arms for several local models, one after another. Resumable and safe to kill.

For each model in the plan it starts tools/local_model_server.py with a
Python that has torch and transformers, waits until the model is loaded,
asks every request that is not yet in the hash-keyed cache, and stops the
server again. It only ever stops the server process it started itself.
Progress goes to <log-dir>/run.log and <log-dir>/status.json.

    python tools/run_model_arms.py --plan qwen3-1.7b:bf16=1200,granite-4.0-micro:nf4=400 \
        --server-python C:/path/to/venv/Scripts/python.exe

A model whose server refuses to load (not enough free GPU memory) is retried
after a wait; a CUDA out-of-memory error stops the whole run.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sealed import model_eval  # noqa: E402  (the stdlib-only package; never imports the server)

REFUSED, OUT_OF_MEMORY = 3, 4


def log(log_dir: Path, message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(log_dir / "run.log", "a", encoding="utf-8") as handle:
        handle.write(f"{stamp} {message}\n")


def write_status(log_dir: Path, status: dict) -> None:
    status = dict(status, updated=time.strftime("%Y-%m-%d %H:%M:%S"))
    temp = log_dir / "status.json.tmp"
    temp.write_text(json.dumps(status, indent=1), encoding="utf-8")
    os.replace(temp, log_dir / "status.json")


def server_ready(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/tags", timeout=5) as response:
            return response.status == 200
    except OSError:
        return False


def start_server(python: str, model: str, port: int, log_dir: Path) -> subprocess.Popen:
    # Offline, and no bytecode files written into the server's Python environment.
    env = dict(os.environ, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", PYTHONUNBUFFERED="1",
               PYTHONDONTWRITEBYTECODE="1")
    handle = open(log_dir / f"server-{model.replace(':', '_')}.log", "a", encoding="utf-8")
    return subprocess.Popen([python, str(ROOT / "tools" / "local_model_server.py"), "--model", model,
                             "--port", str(port)], stdout=handle, stderr=subprocess.STDOUT, env=env,
                            cwd=str(ROOT))


def stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=60)


def run_one(args, model: str, limit: int, log_dir: Path) -> int:
    triples = model_eval.interleaved_triples()[:limit]
    for attempt in range(args.retries + 1):
        process = start_server(args.server_python, model, args.port, log_dir)
        log(log_dir, f"{model}: server pid {process.pid} starting (attempt {attempt + 1})")
        deadline = time.time() + args.load_minutes * 60
        while time.time() < deadline and process.poll() is None and not server_ready(args.port):
            time.sleep(5)
        if process.poll() is not None:
            code = process.returncode
            log(log_dir, f"{model}: server exited with code {code} before it was ready")
            if code == REFUSED and attempt < args.retries:
                log(log_dir, f"{model}: not enough free GPU memory; waiting {args.retry_minutes} min")
                time.sleep(args.retry_minutes * 60)
                continue
            return code or 1
        if not server_ready(args.port):
            log(log_dir, f"{model}: server not ready after {args.load_minutes} min; stopping it")
            stop_server(process)
            return 1
        log(log_dir, f"{model}: ready; {len(triples)} triples")
        last = [0.0]

        def progress(p: dict) -> None:
            write_status(log_dir, {"state": "running", **p})
            if time.time() - last[0] > 60 or p["done"] == p["total"]:
                last[0] = time.time()
                log(log_dir, f"{p['model']} {p['done']}/{p['total']} fresh {p['fresh']} mean {p['mean_seconds']}s "
                             f"remaining about {p['remaining_seconds'] // 60} min")

        try:
            result = model_eval.run(model, triples, base_url=f"http://127.0.0.1:{args.port}",
                                    cache_dir=args.cache_dir, progress=progress)
        except Exception as error:  # the server died or the network layer failed: stop, keep what is cached
            log(log_dir, f"{model}: stopped by {type(error).__name__}: {error}")
            stop_server(process)
            return OUT_OF_MEMORY if process.returncode == OUT_OF_MEMORY else 1
        stop_server(process)
        log(log_dir, f"{model}: done, {result['requests']} requests, {result['fresh']} new")
        return 0
    return REFUSED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the model arms model by model; resumable.")
    parser.add_argument("--plan", required=True, help="comma list of model=triples, e.g. qwen3-1.7b:bf16=1200")
    parser.add_argument("--server-python", required=True, help="a Python with torch, transformers and bitsandbytes")
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--cache-dir", default=str(model_eval.DEFAULT_CACHE))
    parser.add_argument("--log-dir", default=str(ROOT / "logs"))
    parser.add_argument("--load-minutes", type=float, default=20)
    parser.add_argument("--retries", type=int, default=6)
    parser.add_argument("--retry-minutes", type=float, default=10)
    args = parser.parse_args(argv)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    plan = []
    for item in args.plan.split(","):
        model, _, limit = item.partition("=")
        if model not in model_eval.MODELS or not limit.isdigit() or not 0 < int(limit) <= 1200:
            parser.error(f"bad plan item {item!r}")
        plan.append((model, int(limit)))
    log(log_dir, f"run started, pid {os.getpid()}, plan {args.plan}")
    for model, limit in plan:
        code = run_one(args, model, limit, log_dir)
        if code:
            write_status(log_dir, {"state": "stopped", "model": model, "exit_code": code})
            log(log_dir, f"run stopped at {model} with code {code}; re-run the same command to resume")
            return code
    write_status(log_dir, {"state": "finished", "plan": args.plan})
    log(log_dir, "run finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
