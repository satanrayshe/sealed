"""The sealed view: the only thing a narrator model ever receives.

seal() takes the recognised facts and the number of unrecognised signals.
It never receives the alert, so nothing else about an alert (id, severity,
action, entity fields, unrecognised text, extra fields, key order) can
reach the model input.

It keeps one item per signal type (the highest count when a type repeats;
the policy reports the inconsistency), sorts items in vocabulary order and
numbers them S1, S2, ...; the unrecognised count, if any, comes last. The
view is serialised canonically (sorted keys, no spaces, ASCII) and appended
to a fixed prompt. Those exact bytes are the model input, and their SHA-256
is reported with every explanation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable

from .contract import MAX_SIGNALS
from .vocabulary import ORDER, SIGNALS, UNRECOGNISED, Fact

VIEW_SCHEMA = "sealed-view/1"
PROMPT_VERSION = "sealed-narrator-prompt/1"


def _glossary() -> str:
    lines = [f"{code}: {sig.meaning}" + (" (count)" if sig.kind == "count" else "")
             for code, sig in SIGNALS.items()]
    lines.append(f"unrecognised: {UNRECOGNISED.meaning} (count)")
    return "\n".join(lines)


NARRATOR_PROMPT = (
    f"[{PROMPT_VERSION}]\n"
    "You turn security-alert evidence into plain sentences for a junior analyst.\n"
    'FACTS below is a JSON object. Its "evidence" list holds items with an id (S1, S2, ...), '
    "a signal code from the GLOSSARY and, for some codes, a count.\n"
    "Rules:\n"
    "1. Write one short sentence per evidence item, in the order given.\n"
    "2. End each sentence with the id of the item it describes in square brackets, for example [S1].\n"
    "3. Use only the signals and counts in FACTS. Add no names, places, times, numbers, causes or guesses.\n"
    "4. Do not judge the alert and do not suggest any action; other components do that.\n"
    '5. Reply with JSON only, in the form {"sentences": ["..."]}.\n'
    "GLOSSARY:\n" + _glossary() + "\n"
    "FACTS:\n"
)
assert NARRATOR_PROMPT.isascii()


@dataclass(frozen=True)
class Evidence:
    id: str
    signal: str
    count: int | None

    def as_dict(self) -> dict:
        item = {"id": self.id, "signal": self.signal}
        if self.count is not None:
            item["count"] = self.count
        return item


@dataclass(frozen=True)
class SealedView:
    evidence: tuple[Evidence, ...]
    canonical_json: str
    model_input: bytes  # the exact narrator input: prompt plus canonical view
    sha256: str

    @property
    def model_input_text(self) -> str:
        return self.model_input.decode("ascii")

    def item(self, evidence_id: str) -> Evidence | None:
        return next((e for e in self.evidence if e.id == evidence_id), None)


def seal(facts: Iterable[Fact], unrecognised: int) -> SealedView:
    """Build the sealed view from structured facts only."""
    if type(unrecognised) is not int or not 0 <= unrecognised <= MAX_SIGNALS:
        raise ValueError("unrecognised must be an integer from 0 to MAX_SIGNALS")
    highest: dict[str, int | None] = {}
    for fact in facts:
        if type(fact) is not Fact:
            raise TypeError("seal() accepts Fact objects only")
        checked = Fact(fact.code, fact.count)  # re-run validation in case the object was tampered with
        if checked.count is None:
            highest[checked.code] = None
        else:
            highest[checked.code] = max(checked.count, highest.get(checked.code) or 0)

    evidence = [
        Evidence(f"S{n}", SIGNALS[code].code, highest[code])
        for n, code in enumerate(sorted(highest, key=ORDER.__getitem__), 1)
    ]
    if unrecognised:
        evidence.append(Evidence(f"S{len(evidence) + 1}", UNRECOGNISED.code, unrecognised))

    canonical = json.dumps(
        {"view": VIEW_SCHEMA, "evidence": [e.as_dict() for e in evidence]},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    model_input = (NARRATOR_PROMPT + canonical + "\n").encode("ascii")
    return SealedView(tuple(evidence), canonical, model_input, hashlib.sha256(model_input).hexdigest())
