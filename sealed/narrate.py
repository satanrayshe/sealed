"""Narrators turn a sealed view into cited sentences. They decide nothing.

TemplateNarrator needs no model. It is the default offline path and the
test oracle: its sentences are what a perfect narrator would say.

OllamaNarrator asks a local Ollama server (http://127.0.0.1:11434 by
default, loopback only). The single user message is exactly the sealed
model input, so the hash shown to the analyst is the hash of what the model
read. Temperature is 0, the seed is fixed and the reply must match a JSON
schema. Replies are cached on disk under the model-input hash, so runs can
be replayed offline. Tests use a fake transport; nothing here is called
against a real server in the test suite.

Whatever a narrator returns goes through verify.py before anyone sees it.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from .view import PROMPT_VERSION, SealedView
from .vocabulary import SIGNALS, UNRECOGNISED

MAX_REPLY_BYTES = 200_000
MAX_SENTENCES = 50
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "sentences": {
            "type": "array",
            "maxItems": MAX_SENTENCES,
            "items": {"type": "string", "maxLength": 400},
        }
    },
    "required": ["sentences"],
    "additionalProperties": False,
}

Transport = Callable[[str, bytes, float], bytes]


class NarratorError(RuntimeError):
    """The narrator could not produce usable output. Callers fall back to the template."""


class CacheMiss(NarratorError):
    """Offline mode and no cached reply for this model input."""


class TemplateNarrator:
    name = "template"

    def narrate(self, view: SealedView) -> list[str]:
        sentences = []
        for item in view.evidence:
            signal = UNRECOGNISED if item.signal == UNRECOGNISED.code else SIGNALS[item.signal]
            sentences.append(f"{signal.sentence(item.count)} [{item.id}].")
        return sentences


def urllib_transport(url: str, body: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # loopback only, checked in __init__
        return response.read(MAX_REPLY_BYTES + 1)


def parse_reply(raw: bytes) -> list[str]:
    """Extract the sentence list from an Ollama /api/chat reply."""
    if len(raw) > MAX_REPLY_BYTES:
        raise NarratorError("reply is too large")
    try:
        outer = json.loads(raw.decode("utf-8"))
        inner = json.loads(outer["message"]["content"])
        sentences = inner["sentences"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as err:
        raise NarratorError("reply is not the expected JSON") from err
    if not isinstance(sentences, list) or not all(isinstance(s, str) for s in sentences):
        raise NarratorError("sentences must be a list of strings")
    return sentences[:MAX_SENTENCES]


_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,120}")


class OllamaNarrator:
    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://127.0.0.1:11434",
        cache_dir: str | Path | None = None,
        offline: bool = False,
        transport: Transport | None = None,
        timeout: float = 120.0,
        seed: int = 0,
    ) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or parts.hostname not in _LOOPBACK:
            raise ValueError("the Ollama narrator only talks to this machine (127.0.0.1, ::1 or localhost)")
        if not isinstance(model, str) or not _MODEL_NAME.fullmatch(model):
            raise ValueError("model must be an Ollama model name such as qwen2.5:7b-instruct")
        self.model = model
        self.name = f"ollama:{model}"
        self.url = base_url.rstrip("/") + "/api/chat"
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self.offline = offline
        self.transport = transport or urllib_transport
        self.timeout = timeout
        self.seed = seed

    def request_body(self, view: SealedView) -> bytes:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": view.model_input_text}],
            "stream": False,
            "format": OUTPUT_SCHEMA,
            "options": {"temperature": 0, "seed": self.seed},
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def cache_path(self, view: SealedView) -> Path | None:
        if self.cache_dir is None:
            return None
        slug = re.sub(r"[^a-z0-9.]+", "_", self.model.lower())
        return self.cache_dir / slug / f"{view.sha256}.json"

    def narrate(self, view: SealedView) -> list[str]:
        body = self.request_body(view)
        cached = self._read_cache(view, body)
        if cached is not None:
            return cached
        if self.offline:
            raise CacheMiss("no cached narration for this model input")
        try:
            raw = self.transport(self.url, body, self.timeout)
        except (OSError, http.client.HTTPException, ValueError) as err:
            raise NarratorError(f"Ollama request failed ({type(err).__name__})") from err
        sentences = parse_reply(raw)
        self._write_cache(view, body, sentences)
        return sentences

    def _read_cache(self, view: SealedView, body: bytes) -> list[str] | None:
        path = self.cache_path(view)
        if path is None or not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["request_sha256"] != hashlib.sha256(body).hexdigest():
                return None  # same input, different model or settings
            sentences = data["sentences"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if not isinstance(sentences, list) or not all(isinstance(s, str) for s in sentences):
            return None
        return sentences[:MAX_SENTENCES]

    def _write_cache(self, view: SealedView, body: bytes, sentences: list[str]) -> None:
        path = self.cache_path(view)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "model": self.model,
            "model_input_sha256": view.sha256,
            "prompt_version": PROMPT_VERSION,
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "sentences": sentences,
        }
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(record, ensure_ascii=True, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
        os.replace(temp, path)
