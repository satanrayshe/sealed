"""The verifier: a narrator sentence is shown only if the sealed view supports it.

A sentence is dropped when it
  * is not a string, is empty or is longer than 400 characters;
  * cites nothing, cites an id that is not in the view, or has a malformed citation;
  * contains a number (digits or a number word) that is not the count of an item it cites;
  * contains an entity: an IP or e-mail address, a URL, a domain or file name, a path, a quoted
    string, a non-ASCII character, or a capitalised word other than the first word and the
    acronyms the vocabulary itself uses;
  * judges the alert or names an action (benign, safe, malicious, allow, block, contain, ...),
    because deciding is the policy's job.

The view holds no names, hosts or free text, so any entity in a narrative was made up by the
model. A rule-based check cannot catch every invented lowercase word. The guarantee that
matters is upstream: the model never saw attacker text, so it cannot repeat it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .view import SealedView

MAX_SENTENCE_CHARS = 400
CITATION = re.compile(r"\[(S[0-9]{1,3})\]")
ALLOWED_CAPS = frozenset({"MFA", "IP", "DNS", "VPN", "USB", "MB", "Tor"})
NUMBER_WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
    "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30,
    "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90, "hundred": 100,
    "thousand": 1000, "million": 1_000_000, "billion": 1_000_000_000, "dozen": 12, "once": 1, "twice": 2,
}
JUDGEMENT = re.compile(
    r"\b(benign|harmless|safe|authori[sz]ed|legitimate|malicious|compromised?|attack(?:s|er|ers)?|"
    r"test(?:s|ing)?|exercise|allow(?:s|ed)?|block(?:s|ed)?|contain(?:s|ed|ment)?|escalat\w*|"
    r"recommend\w*|should|must|ignor\w*|suspicious|fraud\w*|monitor(?:s|ed|ing)?|step[- ]?up|"
    r"false positive|true positive|no action)\b"
)
ENTITY = re.compile(
    r"\d{1,3}(?:\.\d{1,3}){3}"            # IPv4 address
    r"|@|://|www\.|[/\\]"                  # e-mail, URL, path
    r"|\b[A-Za-z0-9-]+\.[A-Za-z]{2,}\b"    # domain or file name
    r"|[\"`]|(?<![A-Za-z])'|'(?![A-Za-z])"  # quotation marks (apostrophes inside words are fine)
)
_TYPOGRAPHY = str.maketrans({"’": "'", "‘": "'", "–": "-", "—": "-"})


@dataclass(frozen=True)
class Verified:
    kept: tuple[str, ...]
    dropped: tuple[tuple[int, str], ...]  # (position in the narrator output, reason code)


def _numbers(text: str) -> list[int | None]:
    """Every number in the text; None for one that is not a whole number."""
    found: list[int | None] = []
    for token in re.findall(r"\d[\d,.]*\d|\d", text):
        token = token.replace(",", "")
        found.append(int(token) if token.isdigit() else None)
    found += [NUMBER_WORDS[w] for w in re.findall(r"[a-z]+", text.lower()) if w in NUMBER_WORDS]
    return found


def check(view: SealedView, sentence: object) -> str | None:
    """Reason code for dropping the sentence, or None if the view supports it."""
    if not isinstance(sentence, str):
        return "not-a-string"
    text = sentence.translate(_TYPOGRAPHY).strip()
    if not text:
        return "empty"
    if len(text) > MAX_SENTENCE_CHARS:
        return "too-long"
    cited = CITATION.findall(text)
    if not cited:
        return "no-citation"
    items = [view.item(evidence_id) for evidence_id in cited]
    if None in items:
        return "unknown-citation"
    body = CITATION.sub(" ", text)
    if "[" in body or "]" in body:
        return "malformed-citation"
    if not body.isascii():
        return "non-ascii"
    if JUDGEMENT.search(body.lower()):
        return "judgement"
    if ENTITY.search(body):
        return "entity"
    counts = {item.count for item in items if item.count is not None}
    if any(n is None or n not in counts for n in _numbers(body)):
        return "unsupported-number"
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", body)
    for position, word in enumerate(words):
        if word in ALLOWED_CAPS or word.islower():
            continue
        if position == 0 and word[0].isupper() and (len(word) == 1 or word[1:].islower()):
            continue
        return "entity"
    return None


def verify(view: SealedView, sentences: object) -> Verified:
    if not isinstance(sentences, list):
        return Verified((), ((0, "not-a-list"),))
    kept, dropped = [], []
    for position, sentence in enumerate(sentences):
        reason = check(view, sentence)
        if reason is None:
            kept.append(sentence.translate(_TYPOGRAPHY).strip())
        else:
            dropped.append((position, reason))
    return Verified(tuple(kept), tuple(dropped))
