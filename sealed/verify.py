"""The verifier: a narrator sentence is shown only if it passes every check below.

A sentence is dropped when it
  * is not a string, is empty, is longer than 400 characters or holds a control character;
  * cites nothing, cites an id that is not in the view, cites more than one item (each sentence
    describes exactly one evidence item) or has a malformed citation;
  * uses a character outside plain ASCII letters, digits, spaces and . , ' - [ ];
  * judges the alert, names or orders an action, or negates a fact (benign, safe, malicious,
    block, disable, close, critical, no, none, without, ...), because deciding is the policy's job;
  * contains an entity: an IP address, a domain or file name, a quoted string, a capitalised
    word inside the sentence other than the acronyms the vocabulary uses, or a first word that
    is neither a vocabulary word nor a common sentence opener;
  * contains a number (digits, a number word, an ordinal or a quantity word such as "dozens")
    that is not the count of the item it cites;
  * uses a word that is neither in the cited signal's own vocabulary entry (its phrases, meaning
    and template sentences) nor in a short list of connecting words, so a sentence cannot attach
    another signal's fact, a unit or a story to the item it cites.

The view holds no names, hosts or free text, so any entity in a narrative was made up by the
model. These checks catch invented numbers, entities and verdicts; they cannot prove that a
paraphrase is faithful (an invented lowercase word or a reworded fact can pass). The guarantee
that matters is upstream: the model never saw attacker text, so it cannot repeat it, and the
template narrator, which is the default, says only what the vocabulary says.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .view import SealedView
from .vocabulary import SIGNALS, UNRECOGNISED

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
# Quantities that never equal an exact count. "first" and "second" are left out: "first seen" and
# "60 seconds" are ordinary wording here.
QUANTITY_WORDS = frozenset({
    "hundreds", "thousands", "millions", "billions", "trillion", "trillions", "dozens", "half", "quarter",
    "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth", "tenth", "thrice", "double", "triple",
})
JUDGEMENT = re.compile(
    r"\b(benign|harmless|safe|unsafe|authori[sz]ed|legitimate|genuine|innocent|malicious|compromised?|"
    r"hacked|attack(?:s|er|ers)?|threats?|risky?|dangerous|harmful|critical|routine|expected|intended|fine|"
    r"test(?:s|ing)?|exercise|allow(?:s|ed)?|block(?:s|ed)?|contain(?:s|ed|ment)?|escalat\w*|recommend\w*|"
    r"should|must|ignor\w*|disregard\w*|dismiss\w*|disable|lock|reset|close|worry|suspicious|fraud\w*|"
    r"monitor(?:s|ed|ing)?|step[- ]?up|false positive|true positive|no|none|nothing|without)\b"
)
ALLOWED_CHARS = re.compile(r"[A-Za-z0-9 .,'\-\[\]]*")
ENTITY = re.compile(
    r"\d{1,3}(?:\.\d{1,3}){3}"            # IPv4 address
    r"|\b[A-Za-z0-9-]+\.[A-Za-z]{2,}\b"    # domain or file name
    r"|(?<![A-Za-z])'|'(?![A-Za-z])"       # a quote mark (an apostrophe inside a word is fine)
)
_TYPOGRAPHY = str.maketrans({"\u2019": "'", "\u2018": "'", "\u2013": "-", "\u2014": "-"})
_OPENERS = {"the", "a", "an", "this", "these", "there", "it", "its", "they", "their", "some", "each", "both"}


_CONNECTING = frozenset("""a an the this that these those there it its they their s also total
was were is are be been being has have had on of in at to for from by with into during after before
and or recorded seen observed detected logged noted reported happened occurred times used account user""".split())


def _stem(word: str) -> str:
    return word[:-1] if len(word) > 3 and word.endswith("s") else word


def _signal_words() -> dict[str, frozenset[str]]:
    words = {}
    for sig in [*SIGNALS.values(), UNRECOGNISED]:
        texts = [sig.meaning, sig.one, sig.many, *sig.phrases]
        words[sig.code] = frozenset(_stem(w) for text in texts for w in re.findall(r"[a-z]+", text.lower()))
    return words


SIGNAL_WORDS = _signal_words()
CONNECTING_STEMS = frozenset(_stem(w) for w in _CONNECTING) | frozenset(NUMBER_WORDS)


def _vocabulary_words() -> frozenset[str]:
    texts = [UNRECOGNISED.meaning, UNRECOGNISED.one, UNRECOGNISED.many]
    for sig in SIGNALS.values():
        texts += [sig.meaning, sig.one, sig.many, *sig.phrases]
    return frozenset(w.lower() for text in texts for w in re.findall(r"[A-Za-z]+", text)) | _OPENERS


KNOWN_WORDS = _vocabulary_words()


@dataclass(frozen=True)
class Verified:
    kept: tuple[str, ...]
    dropped: tuple[tuple[int, str], ...]  # (position in the narrator output, reason code)


def _numbers(text: str) -> list[int | None]:
    """Every number in the text; None for one that cannot be an exact whole count."""
    found: list[int | None] = []
    for token in re.findall(r"\d[\d,.]*\d|\d", text):
        token = token.replace(",", "")
        found.append(int(token) if token.isdigit() else None)
    for word in re.findall(r"[a-z]+", text.lower()):
        if word in NUMBER_WORDS:
            found.append(NUMBER_WORDS[word])
        elif word in QUANTITY_WORDS:
            found.append(None)
    return found


def check(view: SealedView, sentence: object) -> str | None:
    """Reason code for dropping the sentence, or None if it passes every check."""
    if not isinstance(sentence, str):
        return "not-a-string"
    text = sentence.translate(_TYPOGRAPHY).strip()
    if not text:
        return "empty"
    if len(text) > MAX_SENTENCE_CHARS:
        return "too-long"
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return "control-character"  # e.g. terminal escape codes from a misbehaving model or cache
    cited = set(CITATION.findall(text))
    if not cited:
        return "no-citation"
    if any(view.item(evidence_id) is None for evidence_id in cited):
        return "unknown-citation"
    if len(cited) > 1:
        return "several-citations"
    item = view.item(cited.pop())
    body = CITATION.sub(" ", text)
    if "[" in body or "]" in body:
        return "malformed-citation"
    if not body.isascii():
        return "non-ascii"
    if not ALLOWED_CHARS.fullmatch(body):
        return "unexpected-character"
    if JUDGEMENT.search(body.lower()):
        return "judgement"
    if ENTITY.search(body):
        return "entity"
    if any(n is None or n != item.count for n in _numbers(body)):
        return "unsupported-number"
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", body)
    for position, word in enumerate(words):
        if word in ALLOWED_CAPS or word.islower():
            continue
        if (position == 0 and word[0].isupper() and word[1:] == word[1:].lower()
                and (word.lower() in KNOWN_WORDS or word.lower() in NUMBER_WORDS)):
            continue
        return "entity"
    own = SIGNAL_WORDS[item.signal]
    if any(_stem(w) not in own and _stem(w) not in CONNECTING_STEMS for w in re.findall(r"[a-z]+", body.lower())):
        return "off-topic"
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
