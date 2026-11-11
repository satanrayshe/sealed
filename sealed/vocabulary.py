"""Signal vocabulary and grammar.

A signal string is recognised only if, after light normalisation, it is an
optional count followed by one of the declared phrases in vocabulary.json:

    signal := [count] phrase
    count  := 1-7 ASCII digits | a number word (zero..twenty, thirty..ninety, hundred, thousand)
    phrase := one of the declared phrases of the ~40 signal types

Normalisation: ASCII only, at most 120 characters, lowercase, a "_" or "-"
between two letters or digits read as a space, the filler word "synthetic"
dropped. Any other character (including a "-" before a number, so there
are no negative counts) makes the whole signal unrecognised. A recognised signal becomes a Fact
(a vocabulary code plus an optional integer); nothing else of the input
string survives. An unrecognised signal survives only as a count.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_DATA = json.loads(Path(__file__).with_name("vocabulary.json").read_text(encoding="utf-8"))

VERSION: str = _DATA["version"]
SEVERITIES: tuple[str, ...] = tuple(_DATA["severities"])
ACTIONS: tuple[str, ...] = tuple(_DATA["actions"])
FAMILIES: dict[str, str] = dict(_DATA["families"])
MAX_SIGNAL_CHARS = 120
MAX_COUNT = 9_999_999  # seven digits

_ALPHABET = re.compile(r"[a-z0-9 ]*")
_SEPARATOR = re.compile(r"(?<=[a-z0-9])[-_](?=[a-z0-9])")  # "-" or "_" between two letters/digits
_NUMBER_WORDS: dict[str, int] = dict(_DATA["number_words"])
_FILLER = frozenset(_DATA["filler_words"])


@dataclass(frozen=True)
class SignalType:
    code: str
    family: str
    kind: str  # "flag" or "count"
    meaning: str
    phrases: tuple[str, ...]
    one: str
    many: str

    def sentence(self, count: int | None) -> str:
        """Plain-English sentence for this signal (no citation)."""
        if self.kind == "flag":
            return self.one
        return (self.one if count == 1 else self.many).format(count=count)


def _words(text: str) -> list[str] | None:
    """Split text into grammar words, or None if it is outside the grammar's alphabet."""
    if len(text) > MAX_SIGNAL_CHARS or not text.isascii():
        return None
    # A "-" or "_" anywhere else (say "-5") stays and fails the alphabet check.
    text = _SEPARATOR.sub(" ", text.lower())
    if not _ALPHABET.fullmatch(text):
        return None
    return [w for w in text.split(" ") if w and w not in _FILLER]


def _count(word: str) -> int | None:
    if word.isdigit() and len(word) <= 7:
        return int(word)
    return _NUMBER_WORDS.get(word)


def _load_signals() -> dict[str, SignalType]:
    signals: dict[str, SignalType] = {}
    for raw in _DATA["signals"]:
        kind = raw["kind"]
        if kind == "flag":
            one = many = raw["sentence"]
        elif kind == "count":
            one, many = raw["one"], raw["many"]
            if "{count}" not in one or "{count}" not in many:
                raise ValueError(f"count signal {raw['code']} needs {{count}} in its sentences")
        else:
            raise ValueError(f"signal {raw['code']} has unknown kind {kind}")
        if raw["code"] in signals:
            raise ValueError(f"duplicate signal code {raw['code']}")
        if raw["family"] not in FAMILIES:
            raise ValueError(f"signal {raw['code']} has unknown family")
        signals[raw["code"]] = SignalType(
            raw["code"], raw["family"], kind, raw["meaning"], tuple(raw["phrases"]), one, many
        )
    return signals


SIGNALS: dict[str, SignalType] = _load_signals()
ORDER: dict[str, int] = {code: i for i, code in enumerate(SIGNALS)}
UNRECOGNISED = SignalType(
    "unrecognised", "context", "count", _DATA["unrecognised"]["meaning"], (),
    _DATA["unrecognised"]["one"], _DATA["unrecognised"]["many"],
)


def _phrase_table() -> dict[str, str]:
    table: dict[str, str] = {}
    for sig in SIGNALS.values():
        for phrase in sig.phrases:
            words = _words(phrase)
            if words is None or " ".join(words) != phrase or _count(words[0]) is not None:
                raise ValueError(f"phrase {phrase!r} is not in normal form")
            if phrase in table:
                raise ValueError(f"phrase {phrase!r} is declared twice")
            table[phrase] = sig.code
    return table


_PHRASES: dict[str, str] = _phrase_table()


def _action_table() -> dict[str, str]:
    table: dict[str, str] = {}
    for action, aliases in _DATA["action_aliases"].items():
        if action not in ACTIONS:
            raise ValueError(f"alias for unknown action {action}")
        for alias in [action, *aliases]:
            words = _words(alias)
            if words is None:
                raise ValueError(f"action alias {alias!r} is outside the alphabet")
            table[" ".join(words)] = action
    return table


_ACTION_ALIASES: dict[str, str] = _action_table()


@dataclass(frozen=True)
class Fact:
    """A recognised signal: a vocabulary code and, for count signals, a count.

    The constructor refuses anything that is not a vocabulary code with a
    bounded integer, so a Fact can never carry free text.
    """

    code: str
    count: int | None = None

    def __post_init__(self) -> None:
        sig = SIGNALS.get(self.code) if type(self.code) is str else None
        if sig is None:
            raise ValueError("unknown signal code")
        if sig.kind == "count":
            if type(self.count) is not int or not 0 <= self.count <= MAX_COUNT:
                raise ValueError("a count signal needs an integer count from 0 to 9,999,999")
        elif self.count is not None:
            raise ValueError("a flag signal takes no count")


def parse_signal(value: object) -> Fact | None:
    """Return the Fact for a signal string, or None if it does not match the grammar."""
    if not isinstance(value, str):
        return None
    words = _words(value)
    if not words:
        return None
    count = _count(words[0])
    if count is not None:
        words = words[1:]
    code = _PHRASES.get(" ".join(words))
    if code is None:
        return None
    if (SIGNALS[code].kind == "count") != (count is not None):
        return None  # count signals need a count; flags must not have one
    # The code comes from our own table, never from the input string.
    return Fact(SIGNALS[code].code, count)


def parse_severity(value: object) -> str:
    """A declared severity, or "unknown" for anything else (including wrong types)."""
    if isinstance(value, str):
        text = value.strip().lower()
        if text in SEVERITIES:
            return SEVERITIES[SEVERITIES.index(text)]
    return "unknown"


def parse_action(value: object) -> str:
    """The alert's own suggested action: a declared action, "unrecognised" or "absent".

    An optional leading "mock" is accepted, so "mock step-up" reads as step-up.
    """
    if value is None:
        return "absent"
    if not isinstance(value, str):
        return "unrecognised"
    words = _words(value)
    if not words:
        return "unrecognised"
    if words[0] == "mock":
        words = words[1:]
    return _ACTION_ALIASES.get(" ".join(words), "unrecognised")
