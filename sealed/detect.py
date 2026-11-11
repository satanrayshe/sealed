"""Injection evidence: a detector interface and the keyword-filter baseline.

A detector scores one piece of quarantined free text from 0 to 1. Its only
use is the escalation hook in policy.py: a score at or above the policy
threshold raises the action by at most one level (never to contain) and
adds one level of uncertainty. A detector never sees, and never changes,
the narrator's input.

KeywordDetector is the baseline. A learned classifier (character n-gram
TF-IDF with logistic regression) is planned; it only has to provide
`name` and `score(text)` to plug in here.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Protocol

from .contract import FreeText


class Detector(Protocol):
    name: str

    def score(self, text: str) -> float:
        """Probability-like score in [0, 1] that the text holds instructions."""
        ...


# Characters that render as nothing (zero-width, joiners, bidi controls, tag characters).
_INVISIBLE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮"
    "⁠-⁯ㅤ︀-️﻿ﾠ\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
# Anything that is not a letter, digit or Indic/combining mark separates words.
_NON_WORD = re.compile(r"[^\ẁ-ͯऀ-෿]+|_+")

# Phrases, matched as whole words after normalisation. Written for the
# baseline from common injection wording; not tuned on the evaluation set.
PHRASES: tuple[str, ...] = (
    # direct override
    "ignore previous", "ignore all previous", "ignore prior", "ignore the above", "ignore above",
    "ignore all instructions", "ignore your instructions", "ignore the instructions", "ignore these instructions",
    "disregard previous", "disregard prior", "disregard the above", "disregard all", "disregard your",
    "disregard any", "forget previous", "forget all previous", "forget your instructions", "forget the above",
    "previous instructions", "prior instructions", "new instructions", "updated instructions",
    "override instructions", "system prompt", "developer mode", "jailbreak",
    # persona hijack
    "you are now", "from now on you", "pretend to be", "roleplay as", "admin note", "soc admin",
    "note to the analyst", "note to the model", "message to the model", "note from the security team",
    "security team note",
    # decision manipulation
    "classify as benign", "classify this as benign", "classify this alert as benign", "mark as benign",
    "mark this as benign", "treat as benign", "label as benign", "no action", "take no action",
    "do not escalate", "do not alert", "do not flag", "do not report", "close this alert", "close the alert",
    "suppress this alert", "dismiss this alert", "false positive",
    # context manipulation
    "red team exercise", "authorised red team", "authorized red team", "penetration test",
    "authorised test", "authorized test",
    "on the allowlist", "on the whitelist", "allowlisted", "whitelisted", "known good",
    "expected behaviour", "expected behavior", "pre approved", "already approved",
    # Hindi: "ignore the instructions", "previous instructions", "all previous instructions"
    "निर्देशों को अनदेखा", "निर्देश अनदेखा", "पिछले निर्देश", "पिछले सभी निर्देश",
)

# Raw patterns, matched on the casefolded text before word splitting.
PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("chat-token", re.compile(r"<\|[a-z_]{2,24}\|>")),
    ("inst-token", re.compile(r"\[/?inst\]")),
    ("sys-token", re.compile(r"<</?sys>>")),
    ("role-line", re.compile(r"(?:^|\n)\s*(?:system|assistant|user|developer)\s*:")),
    ("markdown-header", re.compile(r"#{2,}\s*(?:system|instructions?|response)\b")),
    ("delimiter-tag", re.compile(r"</?\s*(?:alert_data|system|instructions?)\s*>")),
    ("json-key", re.compile(r"\"\s*(?:action|severity|signals|id)\s*\"\s*:")),
)

_MIN_SQUASHED = 12  # spaced-out letters ("i g n o r e ...") are matched only for long phrases


def normalise(text: str) -> str:
    """Lowercase words separated by single spaces, invisible characters removed, NFKC folded."""
    folded = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text)).casefold()
    return " ".join(_NON_WORD.sub(" ", folded).split())


class KeywordDetector:
    name = "keyword-baseline-1"

    def __init__(self, phrases: Iterable[str] = PHRASES, patterns=PATTERNS) -> None:
        self._phrases = tuple(dict.fromkeys(normalise(p) for p in phrases))
        self._squashed = tuple((p, p.replace(" ", "")) for p in self._phrases
                               if len(p.replace(" ", "")) >= _MIN_SQUASHED)
        self._patterns = tuple(patterns)

    def matches(self, text: str) -> list[str]:
        """Names of the phrases and patterns found in the text (for tests and reports)."""
        folded = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text)).casefold()
        words = f" {normalise(text)} "
        squashed = words.replace(" ", "")
        found = [p for p in self._phrases if f" {p} " in words]
        found += [p for p, s in self._squashed if p not in found and s in squashed]
        found += [name for name, pattern in self._patterns if pattern.search(folded)]
        return found

    def score(self, text: str) -> float:
        return 1.0 - 0.5 ** len(self.matches(text))


@dataclass(frozen=True)
class FieldScore:
    field: str
    score: float
    flagged: bool
    error: bool = False


def scan(detector: Detector, items: Iterable[FreeText], threshold: float) -> tuple[FieldScore, ...]:
    """Score every quarantined field. A detector failure counts as 0 and is recorded."""
    results = []
    for item in items:
        error = False
        try:
            value = float(detector.score(item.text))
        except Exception:  # a plug-in detector must not be able to crash the explainer
            value, error = 0.0, True
        if not math.isfinite(value):
            value, error = 0.0, True
        value = min(1.0, max(0.0, value))
        results.append(FieldScore(item.field, value, value >= threshold, error))
    return tuple(results)
