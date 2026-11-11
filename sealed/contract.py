"""Track 4 input contract: reading and validating alerts.

Input shape (Track 4): {"alerts": [{"id", "severity", "signals": [...], "action"}]}
plus the optional entity fields "username", "user_agent", "url" and "host".

Three outcomes, applied in this order:

* Reject the whole input when it cannot be read: not UTF-8, empty, too big,
  not JSON, nested too deep, a non-finite or oversized number, a repeated
  top-level key, no "alerts" list, or too many alerts.
* Reject one alert when it cannot be identified or its structure is wrong:
  not an object, a repeated key, id missing / not a string / blank / too
  long, signals not a list, too many signals, an entity field that is not a
  string. Alerts sharing an id are replays if their content is identical
  (the first is explained, the rest are marked duplicates) and are all
  rejected if their content differs.
* Degrade, never reject, when a value is merely unknown: unknown severity,
  unrecognised or absent action, unrecognised signals, missing signals.
  The policy turns these into uncertainty.

Error messages name the place and the problem, never the offending value.
Every string that does not become a structured value is kept as FreeText,
which is quarantined: shown escaped, scanned for injection, never given to
a model.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass

from .vocabulary import Fact, parse_action, parse_severity, parse_signal

MAX_INPUT_BYTES = 5_000_000
MAX_ALERTS = 1000
MAX_SIGNALS = 100
MAX_ID_CHARS = 256
ENTITY_FIELDS = ("username", "user_agent", "url", "host")
CONTRACT_FIELDS = ("id", "severity", "signals", "action") + ENTITY_FIELDS


@dataclass(frozen=True)
class Issue:
    code: str
    where: str  # JSON path built only from our own field names and indices
    message: str

    def as_dict(self) -> dict:
        return {"code": self.code, "where": self.where, "message": self.message}


@dataclass(frozen=True)
class FreeText:
    field: str  # our own label, e.g. "username" or "signals[2] (unrecognised signal 1)"
    text: str   # raw text: quarantined, never shown unescaped, never given to a model


@dataclass(frozen=True)
class Alert:
    index: int
    id: str
    severity: str                    # a declared severity or "unknown"
    facts: tuple[Fact, ...]          # recognised signals, in input order
    unrecognised: int                # how many signals did not match the grammar
    signals_missing: bool            # "signals" absent, null or empty
    input_action: str                # a declared action, "unrecognised" or "absent"
    free_text: tuple[FreeText, ...]  # everything that did not become a structured value
    ignored_fields: int              # fields outside the contract


@dataclass(frozen=True)
class Rejected:
    index: int
    id: str | None  # only when the id itself was valid
    issues: tuple[Issue, ...]


@dataclass(frozen=True)
class Duplicate:
    index: int
    id: str
    duplicate_of: int


@dataclass(frozen=True)
class Document:
    issues: tuple[Issue, ...]  # input-level problems; when present there are no items
    items: tuple[Alert | Rejected | Duplicate, ...]
    ignored_fields: int        # top-level fields other than "alerts"

    @property
    def ok(self) -> bool:
        return not self.issues


class _Object(dict):
    """A JSON object that remembers whether a key was repeated."""

    repeated_key = False


def _object(pairs: list[tuple[str, object]]) -> _Object:
    obj = _Object()
    for key, value in pairs:
        if key in obj:
            obj.repeated_key = True
        obj[key] = value
    return obj


def _no_constants(name: str) -> object:
    raise ValueError("NaN and Infinity are not allowed")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


def _load_json(data: bytes | str) -> tuple[object, Issue | None]:
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_INPUT_BYTES:
            return None, Issue("too-large", "$", f"input is larger than {MAX_INPUT_BYTES} bytes")
        try:
            text = bytes(data).decode("utf-8-sig")
        except UnicodeDecodeError as err:
            return None, Issue("not-utf8", "$", f"input is not valid UTF-8 (byte {err.start})")
    elif isinstance(data, str):
        if len(data) > MAX_INPUT_BYTES:
            return None, Issue("too-large", "$", f"input is longer than {MAX_INPUT_BYTES} characters")
        text = data[1:] if data.startswith("﻿") else data
    else:
        return None, Issue("not-text", "$", "input must be bytes or text")
    if not text.strip():
        return None, Issue("empty-input", "$", "input is empty")
    try:
        obj = json.loads(text, object_pairs_hook=_object,
                         parse_constant=_no_constants, parse_float=_finite_float)
    except RecursionError:
        return None, Issue("too-deep", "$", "input is nested too deeply")
    except json.JSONDecodeError as err:
        return None, Issue("not-json", "$",
                           f"input is not valid JSON (line {err.lineno}, column {err.colno}: {err.msg})")
    except ValueError:
        return None, Issue("bad-number", "$", "input contains a number that is not finite or is too long")
    return obj, None


def _as_text(value: object) -> str:
    """Text form of a value that sits where free text can appear."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (RecursionError, ValueError, TypeError):
        return "<value could not be shown>"


def _canonical(raw: object) -> str | None:
    try:
        return json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (RecursionError, ValueError, TypeError):
        return None


def _parse_alert(index: int, raw: object) -> Alert | Rejected:
    where = f"$.alerts[{index}]"
    if not isinstance(raw, dict):
        return Rejected(index, None, (Issue("alert-not-an-object", where, "each alert must be a JSON object"),))
    issues: list[Issue] = []
    if getattr(raw, "repeated_key", False):
        issues.append(Issue("duplicate-key", where, "the alert repeats a field name"))

    alert_id = raw.get("id")
    valid_id: str | None = None
    if "id" not in raw or alert_id is None:
        issues.append(Issue("missing-id", f"{where}.id", "id is required"))
    elif not isinstance(alert_id, str):
        issues.append(Issue("wrong-type", f"{where}.id", "id must be a string"))
    elif not alert_id.strip():
        issues.append(Issue("blank-id", f"{where}.id", "id must not be blank"))
    elif len(alert_id) > MAX_ID_CHARS:
        issues.append(Issue("id-too-long", f"{where}.id", f"id is longer than {MAX_ID_CHARS} characters"))
    else:
        valid_id = alert_id

    signals = raw.get("signals")
    if signals is not None and not isinstance(signals, list):
        issues.append(Issue("wrong-type", f"{where}.signals", "signals must be a list"))
    elif signals is not None and len(signals) > MAX_SIGNALS:
        issues.append(Issue("too-many-signals", f"{where}.signals", f"more than {MAX_SIGNALS} signals"))

    for name in ENTITY_FIELDS:
        value = raw.get(name)
        if value is not None and not isinstance(value, str):
            issues.append(Issue("wrong-type", f"{where}.{name}", f"{name} must be a string"))

    if issues:
        return Rejected(index, valid_id, tuple(issues))
    assert valid_id is not None

    free: list[FreeText] = [FreeText("id", valid_id)]
    severity = parse_severity(raw.get("severity"))
    if severity == "unknown" and raw.get("severity") is not None:
        free.append(FreeText("severity", _as_text(raw["severity"])))
    action = parse_action(raw.get("action"))
    if action == "unrecognised":
        free.append(FreeText("action", _as_text(raw["action"])))

    facts: list[Fact] = []
    unrecognised = 0
    for position, value in enumerate(signals or []):
        fact = parse_signal(value)
        if fact is None:
            unrecognised += 1
            free.append(FreeText(f"signals[{position}] (unrecognised signal {unrecognised})", _as_text(value)))
        else:
            facts.append(fact)

    for name in ENTITY_FIELDS:
        if isinstance(raw.get(name), str):
            free.append(FreeText(name, raw[name]))
    extras = [key for key in raw if key not in CONTRACT_FIELDS]
    for number, key in enumerate(extras, 1):
        free.append(FreeText(f"extra field {number}", _as_text({key: raw[key]})))

    return Alert(index, valid_id, severity, tuple(facts), unrecognised, not signals,
                 action, tuple(free), len(extras))


def _resolve_duplicate_ids(items: list[Alert | Rejected], raw_alerts: list) -> list:
    groups: dict[str, list[int]] = {}
    for item in items:
        if item.id is not None:
            groups.setdefault(item.id, []).append(item.index)
    resolved: list[Alert | Rejected | Duplicate] = list(items)
    for alert_id, indices in groups.items():
        if len(indices) < 2:
            continue
        forms = {_canonical(raw_alerts[i]) for i in indices}
        if len(forms) == 1 and None not in forms:
            for i in indices[1:]:
                resolved[i] = Duplicate(i, alert_id, indices[0])
            continue
        for i in indices:
            others = ", ".join(f"alerts[{j}]" for j in indices if j != i)
            issue = Issue("conflicting-duplicate-id", f"$.alerts[{i}].id",
                          f"id is shared with {others} and their content differs")
            earlier = items[i].issues if isinstance(items[i], Rejected) else ()
            resolved[i] = Rejected(i, alert_id, earlier + (issue,))
    return resolved


def parse_document(data: bytes | str) -> Document:
    """Read and validate a Track 4 input document. Never raises on bad input."""
    obj, issue = _load_json(data)
    if issue is not None:
        return Document((issue,), (), 0)
    if not isinstance(obj, dict):
        return Document((Issue("not-an-object", "$", 'top level must be a JSON object with an "alerts" list'),), (), 0)
    if getattr(obj, "repeated_key", False):
        return Document((Issue("duplicate-key", "$", "the top level repeats a field name"),), (), 0)
    if "alerts" not in obj:
        return Document((Issue("missing-alerts", "$", 'top level has no "alerts" field'),), (), 0)
    alerts = obj["alerts"]
    if not isinstance(alerts, list):
        return Document((Issue("wrong-type", "$.alerts", '"alerts" must be a list'),), (), 0)
    if len(alerts) > MAX_ALERTS:
        return Document((Issue("too-many-alerts", "$.alerts", f"more than {MAX_ALERTS} alerts"),), (), 0)
    items = [_parse_alert(i, raw) for i, raw in enumerate(alerts)]
    return Document((), tuple(_resolve_duplicate_ids(items, alerts)), len(obj) - 1)
