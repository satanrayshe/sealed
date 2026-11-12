"""Run the model arms for several local models, one after another. Resumable and safe to kill.

For each model in the plan it starts tools/local_model_server.py with a
Python that has torch and transformers, waits until that server (and no
other) answers with the right model, asks every request that is not yet in
the hash-keyed cache (the triples, then the clean alerts), and stops the
server again. Each new reply is stored with the server file's SHA-256, the
snapshot revision and the decoding settings. Progress goes to
<log-dir>/run.log and <log-dir>/status.json.

    python tools/run_model_arms.py --plan qwen3-1.7b:bf16=1200,granite-4.0-micro:nf4=400 \
        --server-python C:/path/to/venv/Scripts/python.exe

The GPU is shared with whatever else runs on the machine. When the server
runs out of GPU memory, or refuses to load because too little is free, the
driver stops that server, polls free memory (nvidia-smi, at most every 30 s)
until the model's need plus the margin is free, then starts the same model
again and resumes from the cache. It gives up after 6 such stops in a row
(a stop after at least 25 new replies starts the count again) or after 45
minutes without enough free memory. It never stops, pauses or reprioritises
any process except the server it started; the server also stops by itself
when this driver ends.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sealed import model_eval  # noqa: E402  (the stdlib-only package; never imports the server)
from sealed.narrate import LOCAL_OPENER  # noqa: E402  (no proxy, no redirects)

SERVER = ROOT / "tools" / "local_model_server.py"
REFUSED, OUT_OF_MEMORY, PORT_BUSY = 3, 4, 5
POLL_SECONDS = 30      # free GPU memory is read at most this often
WAIT_MINUTES = 45      # give up after this long without enough free memory
MAX_STOPS = 6          # give up after this many out-of-memory stops or refusals in a row
PROGRESS_RESET = 25    # a stop after at least this many new replies starts the count again
GIB = 1024 ** 3


def _retry(action: Callable[[], None], attempts: int = 5, pause: float = 0.05) -> None:
    for attempt in range(attempts):
        try:
            action()
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(pause)


def log(log_dir: Path, message: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n"

    def append() -> None:
        with open(log_dir / "run.log", "a", encoding="utf-8") as handle:
            handle.write(line)
    try:
        _retry(append)
    except OSError:
        sys.stderr.write(line)


def write_status(log_dir: Path, status: dict) -> None:
    """Advisory only. On Windows a reader holding status.json open makes os.replace fail: retry briefly, then
    skip this update. Never lets the error reach the run."""
    status = dict(status, updated=time.strftime("%Y-%m-%d %H:%M:%S"))
    temp = log_dir / "status.json.tmp"

    def replace() -> None:
        temp.write_text(json.dumps(status, indent=1), encoding="utf-8")
        os.replace(temp, log_dir / "status.json")
    try:
        _retry(replace)
    except OSError as error:
        log(log_dir, f"status.json not updated ({type(error).__name__}); the run goes on")


def server_settings():
    """The server file's constants (standard library only at module level; no model is loaded)."""
    spec = importlib.util.spec_from_file_location("local_model_server_settings", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tags(port: int) -> dict | None:
    """What the server on the port reports about itself, or None if nothing usable answers."""
    try:
        with LOCAL_OPENER.open(f"http://127.0.0.1:{port}/api/tags", timeout=5) as response:
            if response.status != 200:
                return None
            model = json.loads(response.read(100_000))["models"][0]
    except (OSError, ValueError, KeyError, IndexError, TypeError, RecursionError):
        return None
    return model if isinstance(model, dict) else None


def server_ready(port: int, model: str | None = None, instance: str | None = None) -> bool:
    """Ready: the server on the port holds `model` and carries this driver's `instance` token (when given)."""
    found = tags(port)
    if found is None:
        return False
    if model is not None and found.get("name") != model:
        return False
    return instance is None or found.get("instance") == instance


def generation_meta(model: str, port: int) -> dict:
    """What produced the replies, stored with each new cache record: the server file, the loaded snapshot
    (as the server reports it) and the decoding settings."""
    source = SERVER.read_bytes()
    server = server_settings()
    details = tags(port) or {}
    return {"server_sha256": hashlib.sha256(source).hexdigest(), "tag": details.get("name"),
            **{k: details.get("details", {}).get(k) for k in ("repo", "revision", "precision")},
            "max_new_tokens": server.MAX_NEW_TOKENS, "do_sample": False, "seed": server.SEED,
            "template_kwargs": server.MODELS[model]["template_kwargs"]}


def free_gpu_bytes() -> int | None:
    """Free memory on GPU 0 as nvidia-smi reports it (a read-only query), or None if unavailable."""
    try:
        done = subprocess.run(["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits", "-i", "0"],
                              capture_output=True, text=True, timeout=60, check=True)
        return int(done.stdout.strip().splitlines()[0]) * 1024 * 1024
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None


def wait_for_memory(need: int, log_dir: Path, model: str, *, free: Callable[[], int | None] = free_gpu_bytes,
                    sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                    poll_seconds: float = POLL_SECONDS, minutes: float = WAIT_MINUTES) -> bool:
    """Wait until `need` bytes are free. False after `minutes` without enough. Polls at most every 30 s."""
    pause = max(poll_seconds, POLL_SECONDS)
    deadline = clock() + minutes * 60
    waited = False
    while True:
        available = free()
        if available is None:
            log(log_dir, f"{model}: free GPU memory unknown (nvidia-smi unavailable); the server checks it itself")
            return True
        if available >= need:
            if waited:
                log(log_dir, f"{model}: backoff over, {available / GIB:.2f} GiB free")
            return True
        if clock() >= deadline:
            log(log_dir, f"{model}: gave up after {minutes:.0f} min: {available / GIB:.2f} GiB free, "
                         f"{need / GIB:.2f} GiB needed")
            return False
        if not waited:
            log(log_dir, f"{model}: backoff: {available / GIB:.2f} GiB free, {need / GIB:.2f} GiB needed "
                         f"(model plus margin); polling every {pause:.0f} s for up to {minutes:.0f} min")
            waited = True
        sleep(pause)


def start_server(python: str, model: str, port: int, log_dir: Path, instance: str) -> subprocess.Popen:
    # Offline, no bytecode files written into the server's Python environment, and tied to this driver.
    env = dict(os.environ, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", PYTHONUNBUFFERED="1",
               PYTHONDONTWRITEBYTECODE="1", SEALED_SERVER_INSTANCE=instance)
    handle = open(log_dir / f"server-{model.replace(':', '_')}.log", "a", encoding="utf-8")
    return subprocess.Popen([python, str(SERVER), "--model", model, "--port", str(port),
                             "--parent-pid", str(os.getpid())], stdout=handle, stderr=subprocess.STDOUT, env=env,
                            cwd=str(ROOT))


def stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=60)


def serve_and_run(args, model: str, triples: list[dict], log_dir: Path, process: subprocess.Popen,
                  instance: str) -> tuple[str | int, int]:
    """One server lifetime. Returns ("done" | "oom" | "refused" | exit code, new replies)."""
    deadline = time.time() + args.load_minutes * 60
    while time.time() < deadline and process.poll() is None and not server_ready(args.port, model, instance):
        time.sleep(5)
    if process.poll() is not None:
        code = process.returncode
        log(log_dir, f"{model}: server exited with code {code} before it was ready")
        return {REFUSED: "refused", OUT_OF_MEMORY: "oom"}.get(code, code or 1), 0
    if not server_ready(args.port, model, instance):
        log(log_dir, f"{model}: server not ready after {args.load_minutes} min")
        return 1, 0
    meta = generation_meta(model, args.port)
    log(log_dir, f"{model}: ready; {len(triples)} triples; {meta['repo']} at {meta['revision']}, {meta['precision']}")
    last, fresh = [0.0], [0]

    def progress(p: dict) -> None:
        fresh[0] = p["fresh"]
        write_status(log_dir, {"state": "running", **p})
        if time.time() - last[0] > 60 or p["done"] == p["total"]:
            last[0] = time.time()
            log(log_dir, f"{p['model']} {p['done']}/{p['total']} fresh {p['fresh']} mean {p['mean_seconds']}s "
                         f"remaining about {p['remaining_seconds'] // 60} min")

    try:
        result = model_eval.run(model, triples, base_url=f"http://127.0.0.1:{args.port}",
                                cache_dir=args.cache_dir, progress=progress, record_meta=meta)
    except Exception as error:  # the server died or the network layer failed: keep what is cached
        try:
            process.wait(timeout=30)  # after an out-of-memory error the server exits by itself with code 4
        except subprocess.TimeoutExpired:
            pass
        oom = process.returncode == OUT_OF_MEMORY or (isinstance(error, urllib.error.HTTPError) and error.code == 503)
        log(log_dir, f"{model}: stopped by {type(error).__name__}: {error}" + ("; out of GPU memory" if oom else ""))
        return ("oom" if oom else 1), fresh[0]
    log(log_dir, f"{model}: done, {result['requests']} requests, {result['fresh']} new")
    return "done", result["fresh"]


def run_one(args, model: str, limit: int, log_dir: Path) -> int:
    triples = model_eval.interleaved_triples()[:limit]
    settings = server_settings()
    need = settings.needed_bytes(settings.MODELS[model])
    stops = 0
    while True:
        busy = tags(args.port)
        for _ in range(6):  # a server that was just stopped may need a moment to release the port
            if busy is None:
                break
            time.sleep(5)
            busy = tags(args.port)
        if busy is not None:
            log(log_dir, f"port {args.port} is already answered by a server holding {busy.get('name')!r} "
                         f"(pid {busy.get('pid')}); not starting another. Stop that one, then re-run.")
            return PORT_BUSY
        if not wait_for_memory(need, log_dir, model, minutes=args.wait_minutes):
            return REFUSED
        instance = secrets.token_hex(16)
        process = start_server(args.server_python, model, args.port, log_dir, instance)
        log(log_dir, f"{model}: server pid {process.pid} starting")
        try:
            outcome, fresh = serve_and_run(args, model, triples, log_dir, process, instance)
        finally:
            stop_server(process)  # also on KeyboardInterrupt: never leave our own server behind
        if outcome == "done":
            return 0
        if outcome not in ("oom", "refused"):
            return outcome
        stops = 1 if fresh >= PROGRESS_RESET else stops + 1
        what = "out of GPU memory" if outcome == "oom" else "the server refused to load (too little free memory)"
        if stops >= args.max_stops:
            log(log_dir, f"{model}: {what}; {stops} stops in a row, giving up")
            return OUT_OF_MEMORY if outcome == "oom" else REFUSED
        log(log_dir, f"{model}: {what} after {fresh} new replies; stop {stops} of {args.max_stops}; backing off")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the model arms model by model; resumable.")
    parser.add_argument("--plan", required=True, help="comma list of model=triples, e.g. qwen3-1.7b:bf16=1200")
    parser.add_argument("--server-python", required=True, help="a Python with torch, transformers and bitsandbytes")
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--cache-dir", default=str(model_eval.DEFAULT_CACHE))
    parser.add_argument("--log-dir", default=str(ROOT / "logs"))
    parser.add_argument("--load-minutes", type=float, default=20)
    parser.add_argument("--wait-minutes", type=float, default=WAIT_MINUTES,
                        help="give up after this long without enough free GPU memory")
    parser.add_argument("--max-stops", type=int, default=MAX_STOPS,
                        help="give up after this many out-of-memory stops or refusals in a row")
    args = parser.parse_args(argv)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    plan = []
    for item in args.plan.split(","):
        model, _, limit = item.partition("=")
        if model not in model_eval.MODELS or not (limit.isascii() and limit.isdigit()) or not 0 < int(limit) <= 1200:
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
