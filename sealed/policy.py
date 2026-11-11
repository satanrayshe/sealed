"""The declared policy: policy.json decides the action and the uncertainty.

Inputs to decide() are structured only: vocabulary facts, counts, enums and
one boolean from the injection detector. No model output and no free text
can reach a decision.

Actions (allow < monitor < step-up < contain) are mock recommendations and
are never executed. Rules only raise the action, so no signal, recognised
or not, can lower an action that a rule has set. The one exception is R00
(no recognised signal at all gives monitor), which a real signal replaces.

Injection evidence can raise the action by at most one level, never to
contain, and only for an alert that already exists. These two limits are
enforced in code as well as in the table, so a bad table cannot lift them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .vocabulary import ACTIONS, MAX_COUNT, SIGNALS, Fact

HARD_MAX_RAISE = 1
HARD_CEILING = "step-up"
PREDICATES = (
    "signals_missing", "no_signal_recognised", "some_signals_unrecognised", "unknown_severity",
    "input_action_unrecognised", "input_action_disagrees", "injection_evidence", "contradiction",
)


def rank(action: str) -> int:
    return ACTIONS.index(action)


@dataclass(frozen=True)
class Condition:
    signal: str
    low: int
    high: int


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str  # "all", "no_evidence" or "inconsistent_counts"
    text: str
    conditions: tuple[Condition, ...] = ()
    action: str | None = None
    family: str | None = None


@dataclass(frozen=True)
class UncertaintyRule:
    id: str
    when: str
    add: int
    text: str


@dataclass(frozen=True)
class Policy:
    version: str
    sha256: str
    default_action: str
    action_rules: tuple[Rule, ...]
    contradiction_rules: tuple[Rule, ...]
    levels: tuple[str, ...]
    uncertainty_rules: tuple[UncertaintyRule, ...]
    threshold: float
    max_raise: int
    ceiling: str


class PolicyError(ValueError):
    pass


def _check(ok: bool, message: str) -> None:
    if not ok:
        raise PolicyError(message)


def _conditions(raw_rule: dict) -> tuple[Condition, ...]:
    conditions = []
    _check(isinstance(raw_rule.get("all"), list) and raw_rule["all"], f"rule {raw_rule.get('id')} needs conditions")
    for raw in raw_rule["all"]:
        code = raw.get("signal")
        _check(code in SIGNALS, f"rule {raw_rule['id']} names an unknown signal")
        bounds = {k: raw[k] for k in ("min", "max") if k in raw}
        _check(set(raw) <= {"signal", "min", "max"}, f"rule {raw_rule['id']} has an unknown condition key")
        if SIGNALS[code].kind == "flag":
            _check(not bounds, f"rule {raw_rule['id']}: a flag signal takes no bounds")
        for value in bounds.values():
            _check(type(value) is int and 0 <= value <= MAX_COUNT, f"rule {raw_rule['id']} has a bad bound")
        low, high = bounds.get("min", 0), bounds.get("max", MAX_COUNT)
        _check(low <= high, f"rule {raw_rule['id']} has min above max")
        conditions.append(Condition(code, low, high))
    return tuple(conditions)


def load_policy(raw_bytes: bytes) -> Policy:
    """Parse and validate a policy table. Raises PolicyError if anything is off."""
    data = json.loads(raw_bytes.decode("utf-8"))
    _check(data.get("default_action") in ACTIONS, "default_action must be a declared action")

    seen: set[str] = set()
    action_rules = []
    for raw in data["action_rules"]:
        _check(raw.get("id") not in seen, f"rule id {raw.get('id')} is repeated")
        seen.add(raw["id"])
        _check(raw.get("action") in ACTIONS, f"rule {raw['id']} has an unknown action")
        kind = raw.get("kind", "all")
        _check(kind in ("all", "no_evidence"), f"rule {raw['id']} has an unknown kind")
        conditions = _conditions(raw) if kind == "all" else ()
        action_rules.append(Rule(raw["id"], kind, raw["text"], conditions, raw["action"], raw.get("family")))

    contradiction_rules = []
    for raw in data["contradiction_rules"]:
        _check(raw.get("id") not in seen, f"rule id {raw.get('id')} is repeated")
        seen.add(raw["id"])
        kind = raw.get("kind", "all")
        _check(kind in ("all", "inconsistent_counts"), f"rule {raw['id']} has an unknown kind")
        conditions = _conditions(raw) if kind == "all" else ()
        contradiction_rules.append(Rule(raw["id"], kind, raw["text"], conditions))

    levels = tuple(data["uncertainty"]["levels"])
    _check(len(levels) >= 2, "need at least two uncertainty levels")
    uncertainty_rules = []
    for raw in data["uncertainty"]["rules"]:
        _check(raw.get("when") in PREDICATES, f"uncertainty rule {raw.get('id')} has an unknown predicate")
        _check(type(raw.get("add")) is int and raw["add"] >= 0, f"uncertainty rule {raw['id']} has a bad add")
        uncertainty_rules.append(UncertaintyRule(raw["id"], raw["when"], raw["add"], raw["text"]))

    esc = data["injection_escalation"]
    _check(type(esc.get("max_raise")) is int and 0 <= esc["max_raise"] <= HARD_MAX_RAISE,
           "injection escalation may raise by at most one level")
    _check(esc.get("ceiling") in ACTIONS and rank(esc["ceiling"]) <= rank(HARD_CEILING),
           "injection escalation may never reach contain")
    _check(isinstance(esc.get("threshold"), (int, float)) and 0 < esc["threshold"] <= 1,
           "threshold must be in (0, 1]")

    return Policy(
        version=data["version"], sha256=hashlib.sha256(raw_bytes).hexdigest(),
        default_action=data["default_action"], action_rules=tuple(action_rules),
        contradiction_rules=tuple(contradiction_rules), levels=levels,
        uncertainty_rules=tuple(uncertainty_rules), threshold=float(esc["threshold"]),
        max_raise=esc["max_raise"], ceiling=esc["ceiling"],
    )


POLICY_PATH = Path(__file__).with_name("policy.json")
POLICY = load_policy(POLICY_PATH.read_bytes())


@dataclass(frozen=True)
class Reason:
    rule: str
    add: int
    text: str


@dataclass(frozen=True)
class Decision:
    action: str                 # final mock recommendation
    policy_action: str          # before the injection-evidence hook
    rules: tuple[str, ...]      # action rules that fired, in table order
    escalated: bool
    contradictions: tuple[str, ...]
    uncertainty: str
    reasons: tuple[Reason, ...]
    input_action_agrees: bool | None  # None when the alert gave no usable action


def _fires(rule: Rule, values: dict[str, list[int | None]]) -> bool:
    if rule.kind == "no_evidence":
        return not values
    if rule.kind == "inconsistent_counts":
        return any(len(set(counts)) > 1 for counts in values.values())
    for cond in rule.conditions:
        counts = values.get(cond.signal)
        if counts is None:
            return False
        if SIGNALS[cond.signal].kind == "count" and not any(cond.low <= c <= cond.high for c in counts):
            return False
    return True


def escalate(action: str, flagged: bool, policy: Policy = POLICY) -> str:
    """The injection-evidence hook: at most one level up, never to contain, never down."""
    if not flagged:
        return action
    ceiling = min(rank(policy.ceiling), rank(HARD_CEILING))
    step = max(0, min(policy.max_raise, HARD_MAX_RAISE))
    current = rank(action)
    if current >= ceiling:
        return action
    return ACTIONS[min(current + step, ceiling)]


def decide(
    facts: Iterable[Fact],
    *,
    unrecognised: int,
    signals_missing: bool,
    severity: str,
    input_action: str,
    injection_flagged: bool,
    policy: Policy = POLICY,
) -> Decision:
    values: dict[str, list[int | None]] = {}
    for fact in facts:
        values.setdefault(fact.code, []).append(fact.count)

    fired = [r for r in policy.action_rules if _fires(r, values)]
    policy_action = max((r.action for r in fired), key=rank, default=policy.default_action)
    action = escalate(policy_action, injection_flagged, policy)
    contradictions = [r for r in policy.contradiction_rules if _fires(r, values)]

    holds = {
        "signals_missing": signals_missing,
        "no_signal_recognised": not signals_missing and not values,
        "some_signals_unrecognised": bool(values) and unrecognised > 0,
        "unknown_severity": severity == "unknown",
        "input_action_unrecognised": input_action not in ACTIONS,
        "input_action_disagrees": input_action in ACTIONS and input_action != policy_action,
        "injection_evidence": injection_flagged,
    }
    reasons: list[Reason] = []
    for rule in policy.uncertainty_rules:
        if rule.when == "contradiction":
            reasons.extend(Reason(c.id, rule.add, c.text) for c in contradictions)
        elif holds[rule.when]:
            reasons.append(Reason(rule.id, rule.add, rule.text))
    level = min(len(policy.levels) - 1, sum(r.add for r in reasons))

    return Decision(
        action=action,
        policy_action=policy_action,
        rules=tuple(r.id for r in fired),
        escalated=action != policy_action,
        contradictions=tuple(c.id for c in contradictions),
        uncertainty=policy.levels[level],
        reasons=tuple(reasons),
        input_action_agrees=(input_action == policy_action) if input_action in ACTIONS else None,
    )
