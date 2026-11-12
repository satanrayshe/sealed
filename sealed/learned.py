"""A learned injection detector in the standard library: hashed n-grams and logistic regression.

Features: character 3- to 5-grams and word unigrams of the folded text (the
same folding as the keyword detector: invisible characters removed, NFKC in
pieces, casefolded), at most the first 2,000 characters, hashed with CRC-32
into 2**18 buckets, binary and L2-normalised. Model: logistic regression
trained by plain stochastic gradient descent, 4 epochs, learning rate
0.5 / sqrt(1 + t / 1000), balanced class weights, examples shuffled with seed
2026. These settings were fixed before any evaluation and are not tuned on
the project's own attack or benign sets.

Training data: three public corpora (see tools/fetch_corpora.py):
deepset/prompt-injections (Apache-2.0), Lakera/gandalf_ignore_instructions
(MIT) and reshabhs/SPML_Chatbot_Prompt_Injection (MIT). The weights file is
derived from them and attributed to them.

`LearnedDetector` provides `name` and `score(text)`, so it plugs into the same
place as the keyword baseline, which stays the default.
"""

from __future__ import annotations

import array
import hashlib
import json
import math
import random
import re
import sys
import zlib
from pathlib import Path

from .detect import _fold

BUCKETS = 1 << 18
MAX_CHARS = 2000
EPOCHS = 4
SEED = 2026
WEIGHTS = Path(__file__).with_name("learned_weights.bin")
META = Path(__file__).with_name("learned_weights.json")
_WORD = re.compile(r"\w+")


def features(text: str) -> list[int]:
    """Sorted bucket indices present in the text."""
    folded = " " + _fold(text[:MAX_CHARS]) + " "
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


def load(weights_path: Path = WEIGHTS, meta_path: Path = META) -> Model:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    data = weights_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != meta["weights_sha256"] or len(data) != 4 * meta["buckets"]:
        raise ValueError("the learned detector's weights do not match their metadata")
    packed = array.array("f")
    packed.frombytes(data)
    if sys.byteorder != "little":
        packed.byteswap()
    return Model(array.array("d", packed), meta["bias"])


class LearnedDetector:
    name = "ngram-logreg-1"

    def __init__(self, model: Model | None = None) -> None:
        self._model = model

    def score(self, text: str) -> float:
        if self._model is None:
            self._model = load()
        return self._model.probability(text)


def read_corpus(path: Path) -> list[tuple[str, int]]:
    records = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            if isinstance(item.get("text"), str) and item.get("label") in (0, 1):
                records.append((item["text"], item["label"]))
    return records


def average_precision(scored: list[tuple[float, int]]) -> float | None:
    """Area under the precision-recall curve as average precision; None without both classes."""
    positives = sum(label for _, label in scored)
    if positives == 0 or positives == len(scored):
        return None
    hits, total = 0, 0.0
    for rank, (_, label) in enumerate(sorted(scored, key=lambda x: -x[0]), 1):
        if label:
            hits += 1
            total += hits / rank
    return total / positives
