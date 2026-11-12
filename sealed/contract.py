"""Track 4 input contract: reading and validating alerts.

Input shape (Track 4): {"alerts": [{"id", "severity", "signals": [...], "action"}]}
plus the optional entity fields "username", "user_agent", "url" and "host".

Three outcomes, applied in this order:

* Reject the whole input when it cannot be read: not UTF-8, empty, too big,
  nested more than MAX_DEPTH levels deep, not JSON, a non-finite or
  oversized number, a repeated top-level key, no "alerts" list, too many
  alerts, or a negative number in a top-level field other than "alerts".
  The depth is counted before json.loads runs, so the limit is the same in
  every interpreter, whatever its stack size, and nothing later recurses
  deeper than it.
* Reject one alert when it cannot be identified, its structure or a type is
  wrong, or it holds a negative number: not an object, a repeated key, id
  missing / not a string / blank / too long, signals not a list or a signal
  that is not a string, severity, action or an entity field present but not
  a string, or any negative number anywhere in the alert (every number in an
  alert is read as a counter or timestamp, which the track requires to be
  finite and nonnegative).
* Degrade, never reject, when a string value is merely unknown: unknown or
  missing severity, unrecognised or missing action, unrecognised signals,
  missing signals, and an id shared with a valid alert whose content
  differs. The policy turns these into uncertainty. JSON null means the
  field is absent. Valid alerts with an id and identical content are
  replays: the first is explained and the copies are marked duplicates.

Error messages name the place and the problem, never the offending value;
paths use our own field names, indices and positions, never input keys.
Every other string that does not become a structured value is kept as
FreeText, which is quarantined: scanned for injection, never given to a
model, and shown escaped, except undocumented extra fields, which are never
shown. The id is shown escaped and never given to a model too. At most 20
unrecognised signals and 20 extra fields per alert are kept as FreeText;
the rest are only counted.
"""

from __future__ import annotations

import dataclasses
import json
import math
import re
from dataclasses import dataclass
from itertools import accumulate

from .vocabulary import Fact, parse_action, parse_severity, parse_signal

MAX_INPUT_BYTES = 5_000_000
MAX_DEPTH = 100  # nested objects and arrays; the top-level object is level 1, an alert is level 3
MAX_ALERTS = 1000
MAX_ID_CHARS = 256
MAX_QUARANTINED = 20  # per alert, for unrecognised signals and for extra fields separately
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
    shown: bool = True  # False for undocumented extra fields: scanned and counted, never printed


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
    quarantine_omitted: int = 0      # free-text items beyond the per-alert cap: counted, not kept
    id_conflicts: int = 0            # other versions of this id with different content


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


# A JSON string, or an unterminated one running to the end of the text. Every match succeeds on its first
# attempt (an escape takes the character after the backslash, and the end of the text closes the string), so
# removing all strings is linear in the length of the text.
_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*(?:"|\\?\Z)', re.DOTALL)
_NOT_BRACKET = re.compile(r"[^\[\]{}]+")
_STEP = {"[": 1, "{": 1, "]": -1, "}": -1}


def _too_deep(text: str) -> bool:
    """True when objects and arrays nest more than MAX_DEPTH levels deep, found without parsing.

    Brackets inside strings do not count. Iterative and linear. For text that is
    not JSON the count is an upper bound on the depth json.loads reaches before
    it stops, so json.loads never recurses past MAX_DEPTH after this returns False.
    """
    if text.count("[") + text.count("{") <= MAX_DEPTH:
        return False
    brackets = _NOT_BRACKET.sub("", _STRING.sub("", text))
    return max(accumulate(map(_STEP.__getitem__, brackets)), default=0) > MAX_DEPTH


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
        text = data[1:] if data.startswith("\ufeff") else data
    else:
        return None, Issue("not-text", "$", "input must be bytes or text")
    if not text.strip():
        return None, Issue("empty-input", "$", "input is empty")
    too_deep = Issue("too-deep", "$", f"input nests objects and arrays more than {MAX_DEPTH} levels deep")
    if _too_deep(text):
        return None, too_deep
    try:
        obj = json.loads(text, object_pairs_hook=_object,
                         parse_constant=_no_constants, parse_float=_finite_float)
    except RecursionError:  # not reached after the depth check unless the interpreter's stack is tiny
        return None, too_deep
    except json.JSONDecodeError as err:
        return None, Issue("not-json", "$",
                           f"input is not valid JSON (line {err.lineno}, column {err.colno}: {err.msg})")
    except ValueError:
        return None, Issue("bad-number", "$", "input contains a number that is not finite or is too long")
    return obj, None


def _as_text(value: object) -> str:
    """Every key and leaf of a JSON value in document order, one per line.

    Only text that someone actually wrote is collected (keys, strings, and
    numbers as written), never JSON punctuation we would add ourselves, so a
    nested {"id": ...} in an extra field is not mistaken for injected JSON.
    Iterative, so deep nesting cannot overflow the stack.
    """
    if isinstance(value, str):
        return value
    parts: list[str] = []
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in reversed(list(item.items())):
                stack.append(child)
                stack.append(key)
        elif isinstance(item, list):
            stack.extend(reversed(item))
        elif isinstance(item, str):
            parts.append(item)
        else:
            parts.append(json.dumps(item))
    return "\n".join(parts)


def _negative_number_path(obj: dict, known: tuple[str, ...] = CONTRACT_FIELDS,
                          other: str = "extra field", skip: tuple[str, ...] = ()) -> str | None:
    """Path of the first negative number anywhere in a JSON object, or None.

    The path is built from our own field names (`known`), indices and positions
    ("<extra field 2>", "<key 1>"), never from input keys, so it cannot carry
    a secret. Keys in `skip` are not walked. Iterative, depth-first, in document order.
    """
    numbers: dict[str, int] = {}
    for key in obj:
        if key not in known and key not in skip:
            numbers[key] = len(numbers) + 1

    def label(key: str) -> str:
        return f".{key}" if key in known else f".<{other} {numbers[key]}>"

    stack = [(((label(k), v) for k, v in obj.items() if k not in skip), "")]
    while stack:
        step = next(stack[-1][0], None)
        if step is None:
            stack.pop()
            continue
        part, value = step
        if isinstance(value, dict):
            children = ((f".<key {n}>", v) for n, v in enumerate(value.values(), 1))
            stack.append((children, stack[-1][1] + part))
        elif isinstance(value, list):
            children = ((f"[{n}]", v) for n, v in enumerate(value))
            stack.append((children, stack[-1][1] + part))
        elif type(value) in (int, float) and value < 0:
            return stack[-1][1] + part
    return None


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
    elif signals:
        position = next((p for p, s in enumerate(signals) if not isinstance(s, str)), None)
        if position is not None:  # the first one is enough; the message never repeats a value
            issues.append(Issue("wrong-type", f"{where}.signals[{position}]", "each signal must be a string"))

    for name in ("severity", "action") + ENTITY_FIELDS:  # null means the field is absent
        value = raw.get(name)
        if value is not None and not isinstance(value, str):
            issues.append(Issue("wrong-type", f"{where}.{name}", f"{name} must be a string"))

    negative = _negative_number_path(raw)
    if negative is not None:
        issues.append(Issue("negative-number", where + negative,
                            "numbers must be finite and nonnegative (every number in an alert is a counter or timestamp)"))

    if issues:
        return Rejected(index, valid_id, tuple(issues))
    assert valid_id is not None

    # The id is echoed (escaped) as the alert's name and never given to a model. It is not
    # scanned for injection: ids come from the alerting pipeline, and descriptive test ids
    # such as "false-positive-3" would raise false flags.
    free: list[FreeText] = []
    severity = parse_severity(raw.get("severity"))
    if severity == "unknown" and raw.get("severity") is not None:
        free.append(FreeText("severity", raw["severity"]))
    action = parse_action(raw.get("action"))
    if action == "unrecognised":
        free.append(FreeText("action", raw["action"]))

    facts: list[Fact] = []
    seen: set[Fact] = set()
    unrecognised = omitted = 0
    for position, value in enumerate(signals or []):
        fact = parse_signal(value)
        if fact is None:
            unrecognised += 1
            if unrecognised <= MAX_QUARANTINED:
                free.append(FreeText(f"signals[{position}] (unrecognised signal {unrecognised})", value))
            else:
                omitted += 1
        elif fact not in seen:  # a repeated fact adds nothing
            seen.add(fact)
            facts.append(fact)

    for name in ENTITY_FIELDS:
        if isinstance(raw.get(name), str):
            free.append(FreeText(name, raw[name]))
    extras = [key for key in raw if key not in CONTRACT_FIELDS]
    for number, key in enumerate(extras[:MAX_QUARANTINED], 1):
        # Undocumented fields are scanned (name, then contents) but never printed: they may hold anything.
        free.append(FreeText(f"extra field {number}", _as_text({key: raw[key]}), shown=False))
    omitted += max(0, len(extras) - MAX_QUARANTINED)

    return Alert(index, valid_id, severity, tuple(facts), unrecognised, not signals,
                 action, tuple(free), len(extras), quarantine_omitted=omitted)


def _resolve_duplicate_ids(items: list[Alert | Rejected], raw_alerts: list) -> list:
    """Replays become duplicates; differing versions of an id are all explained, flagged as conflicts.

    Only valid alerts take part. A rejected alert stays rejected and never masks,
    or is masked by, a valid alert with the same id.
    """
    groups: dict[str, list[int]] = {}
    for item in items:
        if isinstance(item, Alert):
            groups.setdefault(item.id, []).append(item.index)
    resolved: list[Alert | Rejected | Duplicate] = list(items)
    for alert_id, indices in groups.items():
        if len(indices) < 2:
            continue
        first_of_form: dict[str | None, int] = {}
        for i in indices:
            form = _canonical(raw_alerts[i])
            if form is not None and form in first_of_form:
                resolved[i] = Duplicate(i, alert_id, first_of_form[form])
            else:
                first_of_form[form if form is not None else f"unreadable-{i}"] = i
        if len(first_of_form) > 1:
            for i in first_of_form.values():
                resolved[i] = dataclasses.replace(items[i], id_conflicts=len(first_of_form) - 1)
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
    negative = _negative_number_path(obj, known=(), other="top-level field", skip=("alerts",))
    if negative is not None:
        return Document((Issue("negative-number", "$" + negative,
                               "numbers must be finite and nonnegative, top-level fields included"),), (), 0)
    if len(alerts) > MAX_ALERTS:
        return Document((Issue("too-many-alerts", "$.alerts", f"more than {MAX_ALERTS} alerts"),), (), 0)
    items = [_parse_alert(i, raw) for i, raw in enumerate(alerts)]
    return Document((), tuple(_resolve_duplicate_ids(items, alerts)), len(obj) - 1)
