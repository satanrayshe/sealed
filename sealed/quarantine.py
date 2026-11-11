"""Showing attacker-controlled text safely: escaped, truncated, inside a quote.

These are written as escapes, so the text cannot break out of its quote,
hide characters, reorder the line or push fake text onto the next line:
backslash and quote; every control, format, surrogate, private-use and
unassigned code point; line and paragraph separators and unusual spaces;
every default-ignorable code point (zero-width characters, joiners,
variation selectors, Hangul fillers and the like) and the blank Braille
pattern; and every space that follows another space. Letters of any script
are shown as they are, so a Devanagari name still reads as a name.
"""

from __future__ import annotations

import re
import unicodedata

DISPLAY_CHARS = 160
WRAP = 60  # characters of escaped text per display line, so a report line stays under 80 columns

# Default_Ignorable_Code_Point (Unicode DerivedCoreProperties) plus U+2800 BRAILLE PATTERN BLANK.
INVISIBLE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    "\u2800\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    "\U000e0000-\U000e0fff]"
)
_SIMPLE = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_UNIT = re.compile(r"\\(?:x[0-9a-f]{2}|u[0-9a-f]{4}|U[0-9a-f]{8}|.)|.", re.DOTALL)


def _code(ch: str) -> str:
    code = ord(ch)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


def _escape_char(ch: str, previous: str) -> str:
    if ch in _SIMPLE:
        return _SIMPLE[ch]
    if ch == " ":
        return _code(ch) if previous == " " else ch
    category = unicodedata.category(ch)
    if category[0] == "C" or category in ("Zl", "Zp", "Zs") or INVISIBLE.match(ch):
        return _code(ch)
    return ch


def escape(text: str, limit: int = DISPLAY_CHARS) -> tuple[str, bool]:
    """Return (quoted escaped text, truncated?) for the first `limit` characters."""
    shown = text[:limit]
    body = "".join(_escape_char(ch, shown[i - 1] if i else "") for i, ch in enumerate(shown))
    return '"' + body + '"', len(text) > limit


def wrap(escaped: str, width: int = WRAP) -> list[str]:
    """Split escaped text into display lines of at most `width` characters.

    Breaks after a space where it can, and never inside an escape sequence.
    Nothing is dropped: joining the lines gives the escaped text back.
    """
    lines: list[str] = []
    line: list[str] = []
    for unit in _UNIT.findall(escaped):
        while line and sum(map(len, line)) + len(unit) > width:
            spaces = [i for i, u in enumerate(line[:-1]) if u == " "]
            cut = spaces[-1] + 1 if spaces else len(line)
            lines.append("".join(line[:cut]))
            line = line[cut:]
        line.append(unit)
    if line or not lines:
        lines.append("".join(line))
    return lines
