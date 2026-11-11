"""Property tests, run as seeded fuzzing (thousands of cases, fixed seeds).

Invariance: the narrator's input bytes, and so their SHA-256, are identical
for any value of any free-text field: id, severity, action, the four entity
fields, the text of an unrecognised signal, and extra field names and
values, under any key order and JSON layout.

Monotonicity: unknown or unrecognised values, and instruction-like text,
never lower the action and never lower the uncertainty.

Each check is a plain function of its inputs so Hypothesis can drive it later.
"""

import copy
import json
import random
import unittest

from sealed.contract import CONTRACT_FIELDS, MAX_ID_CHARS
from sealed.explain import explain
from sealed.generate import synthetic_alerts
from sealed.narrate import OllamaNarrator, TemplateNarrator
from sealed.verify import verify
from sealed.view import seal
from sealed.vocabulary import ACTIONS, SEVERITIES, SIGNALS, Fact, parse_action, parse_signal
from tests.fuzz import fuzz_strings
from tests.test_narrate import FakeTransport, reply

INVARIANCE_CASES = 6_000
JOINT_CASES = 1_000
MONOTONICITY_CASES = 3_000
LEVELS = ("low", "medium", "high")
FREE_TEXT_FIELDS = ("id", "severity", "action", "username", "user_agent", "url", "host",
                    "unrecognised_signal", "extra_key", "extra_value")

BASE = {
    "id": "alert-001", "severity": "review", "action": "mock step-up",
    "signals": ["new synthetic device", "five failed synthetic attempts", "~not a signal~"],
    "username": "priya.iyer", "user_agent": "Mozilla/5.0", "url": "https://portal.campus.example/login",
    "host": "ws-0042.campus.example",
}


def encode(alert: dict, layout_seed: int) -> str | bytes:
    """Serialise one alert with a random key order and JSON layout."""
    rng = random.Random(layout_seed)
    items = list(alert.items())
    rng.shuffle(items)
    text = json.dumps({"alerts": [dict(items)]}, ensure_ascii=rng.random() < 0.5, indent=rng.choice([None, 0, 2]))
    if rng.random() < 0.5:
        try:
            return text.encode("utf-8")
        except UnicodeEncodeError:  # lone surrogates can only travel as \u escapes
            pass
    return text


def set_field(alert: dict, field: str, value: str) -> dict | None:
    """Put value into one free-text position; None when that would not be free text."""
    alert = copy.deepcopy(alert)
    if field == "unrecognised_signal":
        if parse_signal(value) is not None:
            return None
        alert["signals"][2] = value
    elif field == "extra_key":
        if value in CONTRACT_FIELDS or value in alert:
            return None
        alert[value] = "x"
    elif field == "extra_value":
        alert["note"] = value
    else:
        alert[field] = value
    return alert


def first_result(data) -> dict:
    return explain(data)["results"][0]


BASE_RESULT = first_result(json.dumps({"alerts": [BASE]}))
BASE_SHA = BASE_RESULT["model_input"]["sha256"]
BASE_VIEW = BASE_RESULT["model_input"]["view"]


def check_invariance(field: str, value: str, layout_seed: int) -> str:
    alert = set_field(BASE, field, value)
    if alert is None:
        return "skipped"
    result = first_result(encode(alert, layout_seed))
    if field == "id" and (not value.strip() or len(value) > MAX_ID_CHARS):
        assert result["status"] == "rejected", "a blank or oversized id must be rejected"
        return "rejected"
    assert result["status"] == "explained", f"free text in {field} must never cause a rejection"
    assert result["model_input"]["view"] == BASE_VIEW, f"view changed via {field}"
    assert result["model_input"]["sha256"] == BASE_SHA, f"model input changed via {field}"
    return "ok"


class Invariance(unittest.TestCase):
    def test_any_value_in_any_free_text_field(self):
        outcomes = {"ok": 0, "skipped": 0, "rejected": 0}
        categories = set()
        for i, (category, value) in enumerate(fuzz_strings(seed=20261112, n=INVARIANCE_CASES)):
            field = FREE_TEXT_FIELDS[i % len(FREE_TEXT_FIELDS)]
            categories.add(category)
            try:
                outcomes[check_invariance(field, value, layout_seed=i)] += 1
            except AssertionError as err:
                self.fail(f"case {i} ({category} in {field}, {len(value)} chars): {err}")
        self.assertEqual(sum(outcomes.values()), INVARIANCE_CASES)
        self.assertGreaterEqual(outcomes["ok"], 5_000)
        self.assertEqual(len(categories), 10)

    def test_all_fields_at_once(self):
        values = [v for _, v in fuzz_strings(seed=7, n=JOINT_CASES * 8)]
        for i in range(JOINT_CASES):
            chunk = values[i * 8:(i + 1) * 8]
            alert = dict(BASE, severity=chunk[0], action=chunk[1], username=chunk[2], user_agent=chunk[3],
                         url=chunk[4], host=chunk[5], comment=chunk[6])
            alert["id"] = "id-" + chunk[7][:200]
            if parse_signal(chunk[6]) is None:
                alert["signals"] = BASE["signals"][:2] + [chunk[6]]
            result = first_result(encode(alert, layout_seed=i))
            with self.subTest(case=i):
                self.assertEqual(result["model_input"]["sha256"], BASE_SHA)

    def test_the_request_bytes_sent_to_a_model_are_identical(self):
        transport = FakeTransport(reply(["5 failed sign-in attempts were recorded on the account [S1]."]))
        narrator = OllamaNarrator("qwen2.5:7b-instruct", transport=transport)
        explain(json.dumps({"alerts": [BASE]}), narrator=narrator)
        for i, (_, value) in enumerate(fuzz_strings(seed=99, n=500)):
            field = FREE_TEXT_FIELDS[3 + i % 7]  # every field that cannot be rejected
            alert = set_field(BASE, field, value)
            if alert is not None:
                explain(encode(alert, layout_seed=i), narrator=narrator)
        bodies = {body for _, body, _ in transport.calls}
        self.assertGreater(len(transport.calls), 450)
        self.assertEqual(len(bodies), 1)

    def test_signal_order_and_spelling_do_not_matter(self):
        spellings = [["new device", "5 failed attempts"], ["five failed attempts", "New-Device"],
                     ["5_failed_logins", "synthetic unknown device", "5 failed attempts"]]
        hashes = {first_result(json.dumps({"alerts": [dict(BASE, signals=s + ["~x~"])]}))["model_input"]["sha256"]
                  for s in spellings}
        self.assertEqual(hashes, {BASE_SHA})


def _rank(result: dict) -> tuple[int, int]:
    return ACTIONS.index(result["recommendation"]["action"]), LEVELS.index(result["uncertainty"]["level"])


def mutate(alert: dict, kind: str, value: object, rng: random.Random) -> dict:
    alert = copy.deepcopy(alert)
    if kind == "unrecognised_signal":
        signals = list(alert.get("signals") or [])
        signals.append(value if parse_signal(value) is None else f"~{value}")
        alert["signals"] = signals
    elif kind == "unknown_severity":
        alert["severity"] = value if str(value).strip().lower() not in SEVERITIES else f"~{value}"
    elif kind == "unrecognised_action":
        alert["action"] = value if value is None or parse_action(value) == "unrecognised" else f"~{value}"
    elif kind == "free_text":
        alert[rng.choice(["username", "user_agent", "url", "host"])] = value
    elif kind == "extra_field":
        alert[f"note_{rng.randint(0, 999)}"] = value
    return alert


MUTATIONS = ("unrecognised_signal", "unknown_severity", "unrecognised_action", "free_text", "extra_field")


def fit(kind: str, value: object) -> object:
    """The values a mutation may carry without breaking the contract's types.

    Signals and entity fields hold strings; severity and action hold a string or null
    (absent); an extra field may hold any JSON value that is not a negative number.
    """
    if kind == "extra_field" or (kind in ("unknown_severity", "unrecognised_action") and value is None):
        return value
    return value if isinstance(value, str) else str(value)


def check_monotone(base: dict, kinds: list[str], values: list, seed: int) -> None:
    rng = random.Random(seed)
    before = first_result(json.dumps({"alerts": [base]}))
    assert not before["injection_evidence"]["flagged_fields"], "bases must start clean"
    after_alert = base
    for kind, value in zip(kinds, values):
        after_alert = mutate(after_alert, kind, value, rng)
    after = first_result(encode(after_alert, layout_seed=seed))
    assert after["status"] == "explained"
    (a0, u0), (a1, u1) = _rank(before), _rank(after)
    assert a1 >= a0, f"action fell from {ACTIONS[a0]} to {ACTIONS[a1]} after {kinds}"
    assert u1 >= u0, f"uncertainty fell from {LEVELS[u0]} to {LEVELS[u1]} after {kinds}"
    # Stricter: these must add at least one level (more if the text is also instruction-like).
    if kinds == ["unknown_severity"] and base.get("severity") in SEVERITIES:
        assert u1 >= min(u0 + 1, 2), "an unknown severity must add a level"
    if kinds == ["unrecognised_signal"] and before["observed_signals"] and not before["unrecognised_signals"]:
        assert u1 >= min(u0 + 1, 2), "a first unrecognised signal must add a level"


class Monotonicity(unittest.TestCase):
    def bases(self):
        alerts = synthetic_alerts()
        extra = [dict(BASE, signals=[]), dict(BASE, signals=["~a~", "~b~"]), dict(BASE, signals=["known device"]),
                 {"id": "bare", "signals": ["admin role granted"]}]
        return alerts + [{k: v for k, v in a.items() if k != "username"} for a in extra]

    def test_unknown_values_never_lower_action_or_uncertainty(self):
        rng = random.Random(4)
        bases = self.bases()
        values = [v for _, v in fuzz_strings(seed=31, n=MONOTONICITY_CASES * 2)]
        values += [None, 7, 1.5, True, [], {"a": 1}, {"b": [0, 2.5, None]}]  # odd but valid, never negative
        for case in range(MONOTONICITY_CASES):
            base = bases[case % len(bases)]
            kinds = [rng.choice(MUTATIONS) for _ in range(1 if case % 3 else rng.randint(2, 3))]
            picked = [fit(k, rng.choice(values)) for k in kinds]
            try:
                check_monotone(base, kinds, picked, seed=case)
            except AssertionError as err:
                self.fail(f"case {case} on {base.get('id')}: {err}")


class TemplateOracle(unittest.TestCase):
    def test_template_output_always_survives_the_verifier(self):
        rng = random.Random(11)
        codes = list(SIGNALS)
        for case in range(2_000):
            facts = []
            for code in rng.sample(codes, rng.randint(0, 12)):
                if SIGNALS[code].kind == "count":
                    facts.append(Fact(code, rng.choice([0, 1, 2, rng.randint(3, 999), rng.randint(1000, 9_999_999)])))
                else:
                    facts.append(Fact(code))
            view = seal(facts, rng.randint(0, 5))
            result = verify(view, TemplateNarrator().narrate(view))
            with self.subTest(case=case):
                self.assertEqual(result.dropped, ())
                self.assertEqual(len(result.kept), len(view.evidence))


class NeverCrashes(unittest.TestCase):
    def test_mangled_documents(self):
        rng = random.Random(5)
        seed_text = json.dumps({"alerts": [BASE, dict(BASE, id="b")]})
        alphabet = '{}[]",:\\ 0123456789aeflnrstu-.\x00\ud800\u202e'
        for case in range(2_000):
            chars = list(seed_text)
            for _ in range(rng.randint(1, 8)):
                position = rng.randrange(len(chars))
                roll = rng.random()
                if roll < 0.4:
                    del chars[position]
                elif roll < 0.8:
                    chars.insert(position, rng.choice(alphabet))
                else:
                    chars[position] = rng.choice(alphabet)
            text = "".join(chars)
            data = text if rng.random() < 0.5 else text.encode("utf-8", "surrogatepass")
            report = explain(data)
            json.dumps(report, ensure_ascii=True)


if __name__ == "__main__":
    unittest.main()
