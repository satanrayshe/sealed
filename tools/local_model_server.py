"""Optional local model server for Sealed's model arms. Not part of the `sealed` package.

It needs a Python environment with torch, transformers and bitsandbytes; the
`sealed` package never imports this file and needs none of them. It serves,
on 127.0.0.1 only, the part of the Ollama HTTP API that `sealed/narrate.py`
and `sealed/model_eval.py` call:

    POST /api/chat   non-streaming chat completion
    GET  /api/tags   the one loaded model

so the request bytes and the hash-keyed caches stay exactly as designed.
It runs fully offline (HF_HUB_OFFLINE=1, local files only) from snapshots
pinned by revision, decodes greedily, refuses to load a model when the GPU's
free memory is below the estimated need plus a margin, and stops cleanly on
a CUDA out-of-memory error. It never touches other processes.

    <python with torch> tools/local_model_server.py --model qwen3-1.7b:bf16 [--port 11434]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Protocol

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")

MAX_NEW_TOKENS = 384
SEED = 0
MAX_BODY_BYTES = 5_000_000
OVERHEAD_GIB = 1.5  # CUDA context, activations and the KV cache for prompts of a few thousand tokens
MARGIN_GIB = 1.0
GIB = 1024 ** 3

# Pinned by snapshot revision (docs/EVAL-PLAN.md, deviation of 2026-11-12 09:10).
MODELS: dict[str, dict] = {
    "qwen3-1.7b:bf16": {
        "repo": "Qwen/Qwen3-1.7B", "revision": "70d244cc86ccca08cf5af4e1e306ecf908b1ad5e",
        "precision": "bf16", "params": 2.03e9, "embedding_params": 0.31e9,
        "template_kwargs": {"enable_thinking": False}, "licence": "Apache-2.0",
    },
    "qwen3-4b-instruct-2507:nf4": {
        "repo": "Qwen/Qwen3-4B-Instruct-2507", "revision": "cdbee75f17c01a7cc42f958dc650907174af0554",
        "precision": "nf4", "params": 4.02e9, "embedding_params": 0.39e9,
        "template_kwargs": {}, "licence": "Apache-2.0",
    },
    "granite-4.0-micro:nf4": {
        "repo": "ibm-granite/granite-4.0-micro", "revision": "56111ae135df9c53a78c99028e7bc24035a9e979",
        "precision": "nf4", "params": 3.40e9, "embedding_params": 0.26e9,
        "template_kwargs": {}, "licence": "Apache-2.0",
    },
}


def needed_bytes(spec: dict) -> int:
    """Estimated GPU memory for weights plus overhead and margin."""
    if spec["precision"] == "bf16":
        weights = spec["params"] * 2
    else:  # NF4: linear layers at about half a byte per weight, embeddings kept in bf16
        weights = (spec["params"] - spec["embedding_params"]) * 0.5 + spec["embedding_params"] * 2
    return int(weights + (OVERHEAD_GIB + MARGIN_GIB) * GIB)


def memory_refusal(free_bytes: int, spec: dict) -> str | None:
    need = needed_bytes(spec)
    if free_bytes < need:
        return (f"refusing to load: the GPU has {free_bytes / GIB:.2f} GiB free and this model needs about "
                f"{need / GIB:.2f} GiB including a {MARGIN_GIB:.0f} GiB margin")
    return None


def snapshot_dir(spec: dict, hub: Path) -> Path:
    path = hub / ("models--" + spec["repo"].replace("/", "--")) / "snapshots" / spec["revision"]
    if not (path / "config.json").is_file():
        raise FileNotFoundError(f"pinned snapshot not found: {path}")
    return path


def is_out_of_memory(error: BaseException) -> bool:
    return type(error).__name__ == "OutOfMemoryError" or "out of memory" in str(error).lower()


class Backend(Protocol):
    tag: str

    def generate(self, messages: list[dict]) -> dict:
        """Return {"content", "prompt_tokens", "completion_tokens", "done_reason"}."""
        ...


class TransformersBackend:
    """Loads one pinned model on the GPU. torch and transformers are imported here, not at module level."""

    def __init__(self, tag: str, hub: Path) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, GenerationConfig

        self.tag, self.spec, self.torch = tag, MODELS[tag], torch
        path = snapshot_dir(self.spec, hub)
        if not torch.cuda.is_available():
            raise RuntimeError("no CUDA device")
        free, _total = torch.cuda.mem_get_info()
        refusal = memory_refusal(free, self.spec)
        if refusal:
            raise MemoryError(refusal)
        kwargs = {"dtype": torch.bfloat16, "device_map": "cuda:0", "local_files_only": True}
        if self.spec["precision"] == "nf4":
            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=False)
        self.tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
        self.model = AutoModelForCausalLM.from_pretrained(path, **kwargs)
        self.model.eval()
        eos = self.model.generation_config.eos_token_id
        pad = self.tokenizer.pad_token_id if self.tokenizer.pad_token_id is not None else (
            eos[0] if isinstance(eos, list) else eos)
        self.generation = GenerationConfig(max_new_tokens=MAX_NEW_TOKENS, do_sample=False, eos_token_id=eos,
                                           pad_token_id=pad)

    def generate(self, messages: list[dict]) -> dict:
        torch = self.torch
        inputs = self.tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, tokenize=True, return_dict=True, return_tensors="pt",
            **self.spec["template_kwargs"]).to("cuda:0")
        prompt_tokens = int(inputs["input_ids"].shape[1])
        torch.manual_seed(SEED)
        with torch.inference_mode():
            output = self.model.generate(**inputs, generation_config=self.generation)
        new = output[0, prompt_tokens:]
        completion_tokens = int(new.shape[0])
        return {
            "content": self.tokenizer.decode(new, skip_special_tokens=True),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "done_reason": "length" if completion_tokens >= MAX_NEW_TOKENS else "stop",
        }


def chat(backend: Backend, payload: object) -> tuple[int, dict]:
    """Answer one /api/chat payload. Returns (HTTP status, JSON body)."""
    if not isinstance(payload, dict):
        return 400, {"error": "the request body must be a JSON object"}
    if payload.get("model") != backend.tag:
        return 404, {"error": f"model {payload.get('model')!r} not found; this server holds {backend.tag!r}"}
    if payload.get("stream", True) is not False:
        return 400, {"error": "streaming is not supported; send \"stream\": false"}
    messages = payload.get("messages")
    if (not isinstance(messages, list) or not messages
            or not all(isinstance(m, dict) and m.get("role") in ("system", "user", "assistant")
                       and isinstance(m.get("content"), str) and set(m) <= {"role", "content"} for m in messages)):
        return 400, {"error": "messages must be a non-empty list of {role, content} with string content"}
    started = time.perf_counter()
    result = backend.generate([{"role": m["role"], "content": m["content"]} for m in messages])
    elapsed = time.perf_counter() - started
    return 200, {
        "model": backend.tag,
        "message": {"role": "assistant", "content": result["content"]},
        "done": True,
        "done_reason": result["done_reason"],
        "prompt_eval_count": result["prompt_tokens"],
        "eval_count": result["completion_tokens"],
        "total_duration": int(elapsed * 1e9),
    }


def make_handler(backend: Backend, on_fatal):
    class Handler(BaseHTTPRequestHandler):
        server_version = "sealed-local-model"
        sys_version = ""

        def _send(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=True).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            port = self.server.server_address[1]
            return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._send(403, {"error": "local requests only"})
            if self.path == "/api/tags":
                spec = MODELS.get(backend.tag, {})
                return self._send(200, {"models": [{"name": backend.tag, "model": backend.tag,
                                                    "details": {"repo": spec.get("repo"),
                                                                "revision": spec.get("revision"),
                                                                "precision": spec.get("precision")}}]})
            return self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._send(403, {"error": "local requests only"})
            if self.path != "/api/chat":
                return self._send(404, {"error": "not found"})
            length = self.headers.get("Content-Length", "")
            if not length.isdigit() or int(length) > MAX_BODY_BYTES:
                self.close_connection = True
                return self._send(413 if length.isdigit() else 411, {"error": "bad or missing Content-Length"})
            try:
                payload = json.loads(self.rfile.read(int(length)).decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return self._send(400, {"error": "the request body is not JSON"})
            try:
                status, body = chat(backend, payload)
            except Exception as error:  # report, never crash silently
                if is_out_of_memory(error):
                    self._send(503, {"error": "CUDA out of memory; the server stops"})
                    on_fatal("CUDA out of memory during generation")
                    return
                return self._send(500, {"error": f"generation failed ({type(error).__name__})"})
            self._send(status, body)

        def log_message(self, format: str, *args) -> None:
            return

    return Handler


def serve(backend: Backend, port: int) -> int:
    """Serve until interrupted. Returns 0, or 4 after a CUDA out-of-memory error."""
    state = {"code": 0}
    server: HTTPServer

    def on_fatal(reason: str) -> None:
        state["code"] = 4
        sys.stderr.write(f"stopping: {reason}\n")
        threading.Thread(target=server.shutdown, daemon=True).start()

    server = HTTPServer(("127.0.0.1", port), make_handler(backend, on_fatal))
    print(f"serving {backend.tag} on http://127.0.0.1:{server.server_address[1]}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return state["code"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", required=True, choices=sorted(MODELS))
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--hub", default=os.environ.get("HF_HUB_CACHE",
                                                        str(Path.home() / ".cache" / "huggingface" / "hub")))
    args = parser.parse_args(argv)
    try:
        backend = TransformersBackend(args.model, Path(args.hub))
    except MemoryError as error:
        sys.stderr.write(f"{error}\n")
        return 3
    except Exception as error:
        if is_out_of_memory(error):
            sys.stderr.write("CUDA out of memory while loading; nothing else was touched\n")
            return 4
        raise
    return serve(backend, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
