"""Detector evaluation (docs/EVAL-PLAN.md): the learned detector against the keyword baseline.

1. Leave one corpus out: train on two of the three public corpora, test on the
   third; report average precision (when the test corpus has both classes),
   recall on injections and the false-positive rate on benign prompts at the
   policy threshold.
2. Train once on all three corpora, save the weights, and evaluate once on the
   held-out test halves of the project's own attack and benign sets (and, for
   reference, the dev halves). Nothing is tuned on those sets.

`python -m sealed evaluate --arm detectors --corpora <dir>` writes
results/detectors.json and results/detectors.md. The corpora live outside the
repository (tools/fetch_corpora.py); the second part needs only the weights.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .attackset import attack_set, benign_set
from .detect import KeywordDetector
from .evaluate import wilson
from .learned import (
    BUCKETS, EPOCHS, MAX_CHARS, SEED, LearnedDetector, Model, average_precision, load, read_corpus, save, train,
)
from .policy import POLICY
from .template_eval import ascii_preview, texts_of

CORPORA = ("deepset-prompt-injections", "lakera-gandalf-ignore-instructions", "spml-chatbot-prompt-injection")
ATTRIBUTION = ("Trained on deepset/prompt-injections (Apache-2.0), Lakera/gandalf_ignore_instructions (MIT) and "
               "reshabhs/SPML_Chatbot_Prompt_Injection (MIT).")


def _p(k: int, n: int) -> dict:
    if n == 0:
        return {"k": 0, "n": 0, "rate": None, "wilson95": None}
    low, high = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4), "wilson95": [round(low, 4), round(high, 4)]}


def _scored(detector, records: list[tuple[str, int]]) -> list[tuple[float, int]]:
    return [(detector.score(text), label) for text, label in records]


def _corpus_row(scored: list[tuple[float, int]], threshold: float) -> dict:
    positives = [s for s, label in scored if label]
    negatives = [s for s, label in scored if not label]
    ap = average_precision(scored)
    return {"records": len(scored), "injections": len(positives), "benign": len(negatives),
            "average_precision": None if ap is None else round(ap, 4),
            "recall": _p(sum(s >= threshold for s in positives), len(positives)),
            "false_positive_rate": _p(sum(s >= threshold for s in negatives), len(negatives))}


def leave_one_corpus_out(corpora: dict[str, list[tuple[str, int]]], threshold: float) -> dict:
    keyword = KeywordDetector()
    out = {}
    for held_out in CORPORA:
        training = [r for name in CORPORA if name != held_out for r in corpora[name]]
        learned = LearnedDetector(train(training))
        out[held_out] = {"learned": _corpus_row(_scored(learned, corpora[held_out]), threshold),
                         "keyword": _corpus_row(_scored(keyword, corpora[held_out]), threshold),
                         "trained_on": [name for name in CORPORA if name != held_out]}
    return out


def on_our_sets(detector, threshold: float) -> dict:
    """Recall on our attack strings and false flags on our benign values, by split."""
    attacks, benign = attack_set(), benign_set()
    flagged = {a["id"]: any(detector.score(t) >= threshold for t in texts_of(a)) for a in attacks}
    false_flag = [detector.score(b["value"]) >= threshold for b in benign]
    result = {}
    for split in ("test", "dev"):
        items = [a for a in attacks if a["split"] == split]
        groups = {key: defaultdict(list) for key in ("class", "encoding", "language")}
        for a in items:
            for key in groups:
                groups[key][a[key]].append(flagged[a["id"]])
        values = [(b, hit) for b, hit in zip(benign, false_flag) if b["split"] == split]
        result[split] = {
            "recall": _p(sum(flagged[a["id"]] for a in items), len(items)),
            **{f"recall_by_{key}": {g: _p(sum(v), len(v)) for g, v in sorted(groups[key].items())} for key in groups},
            "false_flags": _p(sum(hit for _, hit in values), len(values)),
            "missed": [a["id"] for a in items if not flagged[a["id"]]],
            "flagged_benign": [ascii_preview(b["value"], 80) for b, hit in values if hit],
        }
    return result


def run(corpora_dir: Path, weights_path: Path | None = None, meta_path: Path | None = None) -> dict:
    threshold = POLICY.threshold
    corpora = {name: read_corpus(corpora_dir / name / "records.jsonl") for name in CORPORA}
    loco = leave_one_corpus_out(corpora, threshold)
    final = train([r for name in CORPORA for r in corpora[name]])
    meta = {"name": LearnedDetector.name, "attribution": ATTRIBUTION, "epochs": EPOCHS, "seed": SEED,
            "max_chars": MAX_CHARS, "features": "char 3-5-grams and word unigrams, CRC-32 hashed",
            "training_records": {name: len(corpora[name]) for name in CORPORA}}
    kwargs = {k: v for k, v in (("weights_path", weights_path), ("meta_path", meta_path)) if v is not None}
    save(final, meta, **kwargs)
    saved = load(**kwargs)  # evaluate exactly what was written (float32), not the in-memory model
    return {"generated_by": "python -m sealed evaluate --arm detectors", "threshold": threshold,
            "buckets": BUCKETS, "leave_one_corpus_out": loco, "ours": ours(saved)}


def ours(model: Model | None = None) -> dict:
    """Part 2: needs only the saved weights."""
    threshold = POLICY.threshold
    return {"learned": on_our_sets(LearnedDetector(model), threshold),
            "keyword": on_our_sets(KeywordDetector(), threshold)}


def _cell(p: dict | None) -> str:
    if not p or p["n"] == 0:
        return "- | -"
    low, high = p["wilson95"]
    return f"{p['k']} / {p['n']} ({100 * p['rate']:.1f}%) | {100 * low:.1f}% to {100 * high:.1f}%"


def render_markdown(r: dict) -> str:
    lines = ["# Detector evaluation", "",
             f"Generated by `{r['generated_by']}`. Do not edit by hand. Threshold {r['threshold']} (the policy's). "
             "Intervals are Wilson 95%.", "", ATTRIBUTION, "",
             "## Leave one corpus out", "",
             "| Held-out corpus | Detector | Average precision | Recall on injections | 95% | False positives on benign | 95% |",
             "|---|---|---|---|---|---|---|"]
    for corpus, rows in r["leave_one_corpus_out"].items():
        for name in ("learned", "keyword"):
            row = rows[name]
            ap = "n/a (one class)" if row["average_precision"] is None else f"{row['average_precision']:.3f}"
            lines.append(f"| {corpus} | {name} | {ap} | {_cell(row['recall'])} | {_cell(row['false_positive_rate'])} |")
    for split in ("test", "dev"):
        title = "held-out test half" if split == "test" else "dev half (the keyword detector was written on these)"
        lines += ["", f"## Our sets, {title}", "",
                  "| Measure | Learned | 95% | Keyword | 95% |", "|---|---|---|---|---|",
                  f"| recall on attack strings | {_cell(r['ours']['learned'][split]['recall'])} | "
                  f"{_cell(r['ours']['keyword'][split]['recall'])} |",
                  f"| false flags on benign values | {_cell(r['ours']['learned'][split]['false_flags'])} | "
                  f"{_cell(r['ours']['keyword'][split]['false_flags'])} |"]
        for key in ("class", "encoding", "language"):
            groups = sorted(set(r["ours"]["learned"][split][f"recall_by_{key}"]))
            for g in groups:
                lines.append(f"| recall, {key} {g} | {_cell(r['ours']['learned'][split][f'recall_by_{key}'][g])} | "
                             f"{_cell(r['ours']['keyword'][split][f'recall_by_{key}'][g])} |")
        flagged = r["ours"]["learned"][split]["flagged_benign"]
        lines += ["", f"Benign values the learned detector flags ({len(flagged)}):", ""]
        lines += [f"- `{text}`" for text in flagged] or ["- none"]
    lines.append("")
    return "\n".join(lines)


def write_results(r: dict, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"detectors.json": out_dir / "detectors.json", "detectors.md": out_dir / "detectors.md"}
    paths["detectors.json"].write_text(json.dumps(r, ensure_ascii=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    paths["detectors.md"].write_text(render_markdown(r), encoding="utf-8", newline="\n")
    return paths
