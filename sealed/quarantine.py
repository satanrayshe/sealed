"""Showing attacker-controlled text safely: escaped, truncated, inside a quote.

Backslash, quote and every invisible or control character (C0/C1 controls,
zero-width and bidi format characters, surrogates, private-use and
unassigned code points, line and paragraph separators, unusual spaces) are
written as escapes, so the text cannot break out of its quote, hide
characters or reorder the line it is printed on. Letters of any script are
shown as they are, so a Devanagari name still reads as a name.
"""

from __future__ import annotations

import unicodedata

DISPLAY_CHARS = 160
_SIMPLE = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _escape_char(ch: str) -> str:
    if ch in _SIMPLE:
        return _SIMPLE[ch]
    category = unicodedata.category(ch)
    if category[0] == "C" or category in ("Zl", "Zp") or (category == "Zs" and ch != " "):
        code = ord(ch)
        if code < 0x100:
            return f"\\x{code:02x}"
        return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"
    return ch


def escape(text: str, limit: int = DISPLAY_CHARS) -> tuple[str, bool]:
    """Return (quoted escaped text, truncated?) for the first `limit` characters."""
    return '"' + "".join(_escape_char(ch) for ch in text[:limit]) + '"', len(text) > limit
