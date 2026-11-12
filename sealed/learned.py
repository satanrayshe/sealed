"""A learned injection detector in the standard library: hashed n-grams and logistic regression.

Features: character 3- to 5-grams and word unigrams of a window of the
text, hashed with CRC-32 into 2**18 buckets, binary and L2-normalised. The
window is taken after folding, so padding cannot push text out of it:
invisible characters are removed and NFKC is applied first (the keyword
detector's folding), runs of whitespace become one space, and then the first
2,000 characters are kept. Folding stops once the window is full, so the cost
per field is bounded however much NFKC expands the text. Model: logistic
regression trained by plain stochastic gradient descent, 4 epochs, learning
rate 0.5 / sqrt(1 + t / 1000), balanced class weights, examples shuffled with
seed 2026. These settings were chosen before the first training run and have
not been tuned on the project's own attack or benign sets (docs/EVAL-PLAN.md,
deviations).

Training data: three public corpora (see tools/fetch_corpora.py):
deepset/prompt-injections, Lakera/gandalf_ignore_instructions and
reshabhs/SPML_Chatbot_Prompt_Injection. The weights file is derived from them
and attributed to them (README, License and dependencies).

The shipped weights are pinned in this file (SHA-256, bias, buckets): `load`
refuses any other file, and `LearnedDetector` then reports an error for every
field instead of scoring. `LearnedDetector` provides `name` and
`score(text)`, so it plugs into the same place as the keyword baseline, which
stays the default.
"""

from __future__ import annotations

import array
import hashlib
import json
import math
import random
import re
import sys
import unicodedata
import zlib
from pathlib import Path

from .detect import _PIECE, MAX_SCAN_CHARS
from .quarantine import INVISIBLE

BUCKETS = 1 << 18
MAX_CHARS = 2000
EPOCHS = 4
SEED = 2026
WEIGHTS = Path(__file__).with_name("learned_weights.bin")
META = Path(__file__).with_name("learned_weights.json")
_WORD = re.compile(r"\w+")
# The shipped weights (sealed/learned_weights.bin). Changing them means changing these three values.
PINNED = {"weights_sha256": "0d627790592d8f48cb71e5a9e8dd6befedd0e8ffd50bbcf77df27b4ce1c79ef1", "bias": -4.864243763064946,
          "buckets": BUCKETS}


def window(text: str) -> str:
    """Invisible characters removed, NFKC folded in 256-character pieces, casefolded, whitespace runs made one
    space, then the first MAX_CHARS characters. Equal to " ".join(_fold(text).split())[:MAX_CHARS], but stops
    folding once the window is full."""
    text = INVISIBLE.sub("", text[:MAX_SCAN_CHARS])
    parts, visible = [], 0
    for start in range(0, len(text), _PIECE):
        piece = text[start:start + _PIECE]
        if not piece.isascii():
            piece = unicodedata.normalize("NFKC", piece)
        piece = piece.casefold()
        parts.append(piece)
        visible += len("".join(piece.split()))
        if visible > MAX_CHARS:
            break
    return " ".join("".join(parts).split())[:MAX_CHARS]


def features(text: str) -> list[int]:
    """Sorted bucket indices present in the text's window."""
    folded = " " + window(text) + " "
    found = set()
    for n in (3, 4, 5):
        for i in range(len(folded) - n + 1):
            found.add(zlib.crc32(("c" + folded[i:i + n]).encode("utf-8", "surrogatepass")) & (BUCKETS - 1))
    for word in _WORD.findall(folded):
        found.add(zlib.crc32(("w" + word).encode("utf-8", "surrogatepass")) & (BUCKETS - 1))
    return sorted(found)


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class Model:
    def __init__(self, weights: array.array | None = None, bias: float = 0.0) -> None:
        self.w = weights if weights is not None else array.array("d", bytes(8 * BUCKETS))
        self.bias = bias

    def margin(self, indices: list[int]) -> float:
        if not indices:
            return self.bias
        scale = 1.0 / math.sqrt(len(indices))
        w = self.w
        return self.bias + scale * sum(w[i] for i in indices)

    def probability(self, text: str) -> float:
        return _sigmoid(self.margin(features(text)))


def train(records: list[tuple[str, int]], epochs: int = EPOCHS, seed: int = SEED) -> Model:
    """Seeded SGD on logistic loss with balanced class weights."""
    examples = [(features(text), label) for text, label in records]
    positives = sum(label for _, label in examples)
    negatives = len(examples) - positives
    weight = {1: len(examples) / (2 * max(positives, 1)), 0: len(examples) / (2 * max(negatives, 1))}
    model = Model()
    rng = random.Random(seed)
    order = list(range(len(examples)))
    step = 0
    w = model.w
    for _ in range(epochs):
        rng.shuffle(order)
        for index in order:
            indices, label = examples[index]
            rate = 0.5 / math.sqrt(1 + step / 1000)
            step += 1
            gradient = (_sigmoid(model.margin(indices)) - label) * weight[label] * rate
            if indices:
                change = gradient / math.sqrt(len(indices))
                for i in indices:
                    w[i] -= change
            model.bias -= gradient
    return model


def save(model: Model, meta: dict, weights_path: Path = WEIGHTS, meta_path: Path = META) -> None:
    packed = array.array("f", model.w)
    if sys.byteorder != "little":
        packed.byteswap()
    weights_path.write_bytes(packed.tobytes())
    meta = dict(meta, bias=model.bias, buckets=BUCKETS,
                weights_sha256=hashlib.sha256(weights_path.read_bytes()).hexdigest())
    meta_path.write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load(weights_path: Path = WEIGHTS, meta_path: Path = META, *, pinned: dict | None = PINNED) -> Model:
    """The weights, checked against the values pinned in code (the shipped files), or, with pinned=None, only
    against their own metadata (a freshly trained model in an output directory)."""
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    data = weights_path.read_bytes()
    expected = pinned if pinned is not None else meta
    digest = hashlib.sha256(data).hexdigest()
    if (digest != expected.get("weights_sha256") or digest != meta.get("weights_sha256")
            or expected.get("buckets") != BUCKETS or meta.get("buckets") != BUCKETS or len(data) != 4 * BUCKETS
            or meta.get("bias") != expected.get("bias") or not isinstance(expected.get("bias"), float)):
        raise ValueError("the learned detector's weights do not match the values they are pinned to")
    packed = array.array("f")
    packed.frombytes(data)
    if sys.byteorder != "little":
        packed.byteswap()
    return Model(array.array("d", packed), expected["bias"])


class DetectorUnavailable(RuntimeError):
    """The weights could not be loaded. Every field is then reported as a detector error, never as clean."""


class LearnedDetector:
    name = "ngram-logreg-1"

    def __init__(self, model: Model | None = None) -> None:
        self._model = model
        self._failure: str | None = None

    def load(self) -> Model:
        """Loads the shipped weights once; a failure is remembered, so it is not retried for every field."""
        if self._model is None:
            if self._failure is None:
                try:
                    self._model = load()
                except Exception as error:  # missing, altered or unreadable files
                    self._failure = f"the learned detector's weights could not be loaded ({type(error).__name__})"
            if self._model is None:
                raise DetectorUnavailable(self._failure)
        return self._model

    def score(self, text: str) -> float:
        return self.load().probability(text)


def read_corpus(path: Path) -> list[tuple[str, int]]:
    records = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            if isinstance(item.get("text"), str) and item.get("label") in (0, 1):
                records.append((item["text"], item["label"]))
    return records


def average_precision(scored: list[tuple[float, int]]) -> float | None:
    """Average precision over the distinct score thresholds; None without both classes.

    Records with the same score form one step of the precision-recall curve
    (the usual definition, as in scikit-learn), so the result does not depend
    on the order of the input. A keyword detector gives many records the same
    score, where a rank-by-rank sum would depend on file order.
    """
    positives = sum(label for _, label in scored)
    if positives == 0 or positives == len(scored):
        return None
    groups: dict[float, list[int]] = {}
    for score, label in scored:
        group = groups.setdefault(score, [0, 0])
        group[0 if label else 1] += 1
    hits = seen = 0
    total = 0.0
    for score in sorted(groups, reverse=True):
        positive, negative = groups[score]
        hits += positive
        seen += positive + negative
        total += positive / positives * hits / seen
    return total
