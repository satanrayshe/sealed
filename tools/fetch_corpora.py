"""Fetch the three public prompt-injection corpora used to train and test the learned detector.

The data is never committed. Each corpus goes into its own directory under
--dest (outside the repository), every file is checked against the SHA-256
recorded below, and the result is converted to one JSON Lines file of
{"text", "label"} records (label 1 = injection) that the standard-library
detector reads. Parquet files are converted by a separate Python that has
pyarrow, run isolated (-I -B) from a neutral directory with the file paths as
arguments; nothing in the downloaded files is executed.

Corpora (pinned revisions, licences from the dataset cards):
    deepset/prompt-injections                 Apache-2.0 and CC-BY-4.0 (the card states both)
    Lakera/gandalf_ignore_instructions        MIT   (all rows are injection attempts; cite arXiv:2501.07927)
    reshabhs/SPML_Chatbot_Prompt_Injection    MIT   (user prompts, labelled; cite arXiv:2402.11755)

Every file's size is pinned as well as its hash: a download whose
Content-Length differs is refused before anything is written, and a stream
that runs past the pinned size is cut off.

    python tools/fetch_corpora.py --dest "../external-data" --parquet-python C:/path/to/python-with-pyarrow.exe
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

CORPORA = {
    "deepset-prompt-injections": {
        "repo": "deepset/prompt-injections",
        "revision": "4f61ecb038e9c3fb77e21034b22511b523772cdd",
        "licence": "Apache-2.0 / CC-BY-4.0", "records": 662,
        "files": {
            "data/train-00000-of-00001-9564e8b05b4757ab.parquet":
                "2e10bc7ab30f542c97e4e83e2a5683000b5057d25ec10908784c631d44124c04",
            "data/test-00000-of-00001-701d16158af87368.parquet":
                "39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e",
        },
        "sizes": {"data/train-00000-of-00001-9564e8b05b4757ab.parquet": 40323,
                  "data/test-00000-of-00001-701d16158af87368.parquet": 10892},
    },
    "lakera-gandalf-ignore-instructions": {
        "repo": "Lakera/gandalf_ignore_instructions",
        "revision": "04737b65e90a6794ec227012e4a255a7def6344b",
        "licence": "MIT", "records": 1000,
        "files": {
            "data/train-00000-of-00001-ded53be747ff55cd.parquet":
                "5b6acf3e5a5998d21f8e1222bb45bbdec25a14408747b1cd63bebef4a75fa439",
            "data/validation-00000-of-00001-94481a2a09ff2fff.parquet":
                "f51ab3e3407a368845b0f57932cc745c09280429416d7507bd178a16326a79f6",
            "data/test-00000-of-00001-bc92128b9288a6d1.parquet":
                "56b646d133335ebc535266bd55dbe1b5bee7caa4b95bf49d040684b9b5dd9972",
        },
        "sizes": {"data/train-00000-of-00001-ded53be747ff55cd.parquet": 36715,
                  "data/validation-00000-of-00001-94481a2a09ff2fff.parquet": 7464,
                  "data/test-00000-of-00001-bc92128b9288a6d1.parquet": 7336},
    },
    "spml-chatbot-prompt-injection": {
        "repo": "reshabhs/SPML_Chatbot_Prompt_Injection",
        "revision": "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
        "licence": "MIT", "records": 16012,
        "files": {"spml_prompt_injection.csv":
                "4ca6590cd8ec10832fcebee5e243acb32be5c3e79b7a260f8638eed738c784f8"},
        "sizes": {"spml_prompt_injection.csv": 29051327},
    },
}
MAX_TOTAL_BYTES = 300_000_000
USER_AGENT = "sealed-fetch/1.0"

# Reads parquet with pyarrow and writes {"text", "label"} lines. The column names are checked, not trusted.
PARQUET_TO_JSONL = r"""
import json, sys
import pyarrow.parquet as pq
out_path, label_column = sys.argv[1], sys.argv[2]
with open(out_path, "w", encoding="utf-8", newline="\n") as out:
    for path in sys.argv[3:]:
        table = pq.read_table(path)
        names = table.column_names
        if "text" not in names:
            raise SystemExit("no text column in " + path)
        texts = table.column("text").to_pylist()
        labels = table.column(label_column).to_pylist() if label_column in names else [1] * len(texts)
        for text, label in zip(texts, labels):
            if isinstance(text, str) and label in (0, 1):
                out.write(json.dumps({"text": text, "label": int(label)}, ensure_ascii=True) + "\n")
"""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(repo: str, revision: str, name: str, target: Path, size: int | None) -> None:
    """Fetch one file. With a pinned size, a different Content-Length is refused before anything is written,
    and the stream is never read past the pinned size (without one, past MAX_TOTAL_BYTES)."""
    url = f"https://huggingface.co/datasets/{repo}/resolve/{revision}/{name}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    limit = size if size else MAX_TOTAL_BYTES
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(request, timeout=120) as response:
        declared = response.headers.get("Content-Length", "")
        if size and declared and declared != str(size):
            raise SystemExit(f"{repo}/{name}: the server announces {declared!r} bytes, the pin is {size}")
        if declared.isascii() and declared.isdigit() and int(declared) > limit:
            raise SystemExit(f"{repo}/{name}: {declared} bytes is over the limit")
        received = 0
        with open(target, "wb") as out:
            while True:
                block = response.read(1 << 20)
                if not block:
                    break
                received += len(block)
                if received > limit:
                    out.close()
                    target.unlink()
                    raise SystemExit(f"{repo}/{name}: more than {limit} bytes; download stopped")
                out.write(block)


def spml_to_jsonl(csv_path: Path, out_path: Path) -> None:
    csv.field_size_limit(10_000_000)
    with open(csv_path, encoding="utf-8", newline="") as handle, open(out_path, "w", encoding="utf-8", newline="\n") as out:
        for row in csv.DictReader(handle):
            text, label = row.get("User Prompt"), row.get("Prompt injection")
            if isinstance(text, str) and label in ("0", "1"):
                out.write(json.dumps({"text": text, "label": int(label)}, ensure_ascii=True) + "\n")


def fetch(dest: Path, parquet_python: str, record: bool = False) -> dict:
    results = {}
    for key, corpus in CORPORA.items():
        folder = dest / key
        raw = folder / "raw"
        if folder.exists() and any(folder.iterdir()) and not raw.exists():
            raise SystemExit(f"{folder} exists and is not one of ours; refusing to write into it")
        hashes = {}
        for name, expected in corpus["files"].items():
            target = raw / name
            if not (target.is_file() and expected and sha256_of(target) == expected):
                download(corpus["repo"], corpus["revision"], name, target,
                         None if record else corpus.get("sizes", {}).get(name))
            digest = sha256_of(target)
            if expected and digest != expected and not record:
                raise SystemExit(f"SHA-256 mismatch for {key}/{name}: got {digest}")
            hashes[name] = digest
        total = sum((raw / name).stat().st_size for name in corpus["files"])
        if total > MAX_TOTAL_BYTES:
            raise SystemExit(f"{key} is {total} bytes, over the cap")
        jsonl = folder / "records.jsonl"
        if key.startswith("spml"):
            spml_to_jsonl(raw / "spml_prompt_injection.csv", jsonl)
        else:
            files = [str(raw / name) for name in corpus["files"]]
            with tempfile.TemporaryDirectory() as neutral:  # no file from the download sits next to the interpreter
                subprocess.run([parquet_python, "-I", "-B", "-c", PARQUET_TO_JSONL, str(jsonl), "label", *files],
                               check=True, cwd=neutral)
        lines = sum(1 for _ in open(jsonl, encoding="utf-8"))
        results[key] = {"repo": corpus["repo"], "revision": corpus["revision"], "licence": corpus["licence"],
                        "bytes": total, "sha256": hashes, "records": lines, "records_sha256": sha256_of(jsonl)}
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch and convert the three prompt-injection corpora.")
    parser.add_argument("--dest", required=True, help="directory outside the repository")
    parser.add_argument("--parquet-python", required=True, help="a Python with pyarrow, used only to read parquet")
    parser.add_argument("--record", action="store_true", help="print hashes instead of enforcing them")
    args = parser.parse_args(argv)
    dest = Path(args.dest).resolve()
    repo = Path(__file__).resolve().parent.parent
    if dest == repo or repo in dest.parents:
        raise SystemExit("--dest must be outside the repository")
    results = fetch(dest, args.parquet_python, record=args.record)
    print(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
