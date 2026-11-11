import copy
import dataclasses
import json
import unittest

from sealed.policy import POLICY, POLICY_PATH, PolicyError, decide, escalate, load_policy
from sealed.vocabulary import ACTIONS, Fact, parse_signal


def facts(*signals):
    out = []
    for text in signals:
        fact = parse_signal(text)
        assert fact is not None, text
        out.append(fact)
    return out


def run(*signals, unrecognised=0, missing=None, severity="review", input_action=None, flagged=False):
    fs = facts(*signals)
    return decide(
        fs, unrecognised=unrecognised,
        signals_missing=(not signals and not unrecognised) if missing is None else missing,
        severity=severity, input_action=input_action or "absent", injection_flagged=flagged,
    )


def reason_ids(decision):
    return [r.rule for r in decision.reasons]


class TrackExample(unittest.TestCase):
    def test_new_device_and_five_failures(self):
        d = run("new synthetic device", "five failed synthetic attempts", input_action="step-up")
        self.assertEqual(d.action, "step-up")
        self.assertEqual(d.policy_action, "step-up")
        self.assertEqual(d.rules, ("R01", "R02", "R08"))
        self.assertEqual(d.uncertainty, "low")
        self.assertEqual(d.reasons, ())
        self.assertIs(d.input_action_agrees, True)
        self.assertFalse(d.escalated)


class Families(unittest.TestCase):
    CASES = [
        (("7 failed attempts",), "step-up"),
        (("3 failed attempts",), "monitor"),
        (("2 failed attempts",), "allow"),
        (("8 failed attempts", "success after failures"), "contain"),
        (("impossible travel", "6200 km between logins", "40 minutes between logins"), "step-up"),
        (("impossible travel", "2 concurrent sessions"), "contain"),
        (("12 mfa push requests", "new device"), "step-up"),
        (("6 mfa push requests", "mfa approved"), "contain"),
        (("admin role granted",), "monitor"),
        (("admin role granted", "self granted"), "step-up"),
        (("self granted", "audit logging disabled"), "contain"),
        (("regular beacon interval", "rare destination", "40 outbound callbacks"), "step-up"),
        (("regular beacon interval", "rare destination", "900 outbound callbacks"), "contain"),
        (("bulk download", "sensitive files"), "step-up"),
        (("sensitive files", "external share", "450 files downloaded"), "contain"),
        (("known device", "usual location"), "allow"),
    ]

    def test_family_scenarios(self):
        for signals, expected in self.CASES:
            with self.subTest(signals=signals):
                self.assertEqual(run(*signals).action, expected)


class Uncertainty(unittest.TestCase):
    def test_missing_signals(self):
        d = run(missing=True)
        self.assertEqual(d.action, "monitor")
        self.assertEqual(d.rules, ("R00",))
        self.assertEqual(d.uncertainty, "high")
        self.assertIn("U1", reason_ids(d))

    def test_nothing_recognised(self):
        d = run(unrecognised=3, missing=False)
        self.assertEqual(d.action, "monitor")
        self.assertEqual(d.uncertainty, "high")
        self.assertIn("U2", reason_ids(d))

    def test_partial_coverage(self):
        d = run("7 failed attempts", unrecognised=1, input_action="step-up")
        self.assertEqual(reason_ids(d), ["U3"])
        self.assertEqual(d.uncertainty, "medium")

    def test_unknown_severity(self):
        d = run("7 failed attempts", severity="unknown", input_action="step-up")
        self.assertEqual(reason_ids(d), ["U4"])
        self.assertEqual(d.uncertainty, "medium")

    def test_input_action_missing_or_unrecognised(self):
        for value in ["absent", "unrecognised"]:
            d = run("7 failed attempts", input_action=value)
            self.assertEqual(reason_ids(d), ["U5"])
            self.assertIsNone(d.input_action_agrees)

    def test_input_action_disagrees(self):
        d = run("7 failed attempts", input_action="allow")
        self.assertEqual(d.action, "step-up")  # the alert's own suggestion never decides
        self.assertEqual(reason_ids(d), ["U6"])
        self.assertIs(d.input_action_agrees, False)

    def test_contradictions(self):
        cases = {
            "C01": ("new device", "known device"),
            "C02": ("impossible travel", "usual location"),
            "C03": ("success after failures", "0 failed attempts"),
            "C04": ("mfa approved", "0 mfa push requests"),
            "C05": ("bulk download", "0 files downloaded"),
            "C06": ("regular beacon", "1 outbound callback"),
            "C07": ("impossible travel", "corporate vpn"),
            "C08": ("regular beacon", "allowlisted destination", "50 callbacks"),
            "C09": ("admin role granted", "approved change ticket"),
            "C10": ("5 failed attempts", "9 failed attempts"),
        }
        for rule, signals in cases.items():
            with self.subTest(rule=rule):
                d = run(*signals)
                self.assertIn(rule, d.contradictions)
                self.assertIn(rule, reason_ids(d))

    def test_mixed_evidence_never_lowers_the_action(self):
        self.assertEqual(run("admin role granted", "self granted").action,
                         run("admin role granted", "self granted", "approved change ticket").action)
        self.assertEqual(run("impossible travel").action, run("impossible travel", "corporate vpn").action)

    def test_levels_cap_at_high(self):
        d = run("new device", "known device", "impossible travel", "usual location", unrecognised=2,
                severity="unknown", input_action="unrecognised", flagged=True)
        self.assertEqual(d.uncertainty, "high")


class InjectionHook(unittest.TestCase):
    def test_one_level_never_contain_never_down(self):
        self.assertEqual(escalate("allow", True), "monitor")
        self.assertEqual(escalate("monitor", True), "step-up")
        self.assertEqual(escalate("step-up", True), "step-up")
        self.assertEqual(escalate("contain", True), "contain")
        for action in ACTIONS:
            self.assertEqual(escalate(action, False), action)

    def test_code_limits_hold_even_with_a_hostile_table(self):
        hostile = dataclasses.replace(POLICY, max_raise=5, ceiling="contain")
        self.assertEqual(escalate("allow", True, hostile), "monitor")
        self.assertEqual(escalate("monitor", True, hostile), "step-up")
        self.assertEqual(escalate("step-up", True, hostile), "step-up")

    def test_decision_records_escalation_and_uncertainty(self):
        d = run("admin role granted", input_action="monitor", flagged=True)
        self.assertEqual((d.policy_action, d.action, d.escalated), ("monitor", "step-up", True))
        self.assertIs(d.input_action_agrees, True)  # compared with the policy's own action
        self.assertEqual(reason_ids(d), ["U7"])

    def test_escalation_works_on_an_alert_without_evidence_too(self):
        d = run(missing=True, flagged=True)
        self.assertEqual(d.action, "step-up")


class TableValidation(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    def load(self, data):
        return load_policy(json.dumps(data).encode())

    def test_shipped_table_is_valid_and_hashed(self):
        self.assertEqual(POLICY.version, "sealed-policy-1")
        self.assertEqual(len(POLICY.sha256), 64)
        self.assertEqual(self.load(self.raw).action_rules, POLICY.action_rules)

    def test_bad_tables_are_refused(self):
        def mutate(fn):
            data = copy.deepcopy(self.raw)
            fn(data)
            return data

        bad = {
            "unknown signal": lambda d: d["action_rules"][1]["all"][0].update(signal="made_up"),
            "unknown action": lambda d: d["action_rules"][1].update(action="delete-user"),
            "ceiling contain": lambda d: d["injection_escalation"].update(ceiling="contain"),
            "raise two": lambda d: d["injection_escalation"].update(max_raise=2),
            "zero threshold": lambda d: d["injection_escalation"].update(threshold=0),
            "flag with bound": lambda d: d["action_rules"][8]["all"][0].update(min=1),
            "min above max": lambda d: d["action_rules"][1]["all"][0].update(max=1),
            "negative add": lambda d: d["uncertainty"]["rules"][0].update(add=-1),
            "unknown predicate": lambda d: d["uncertainty"]["rules"][0].update(when="always"),
            "repeated id": lambda d: d["action_rules"][2].update(id="R01"),
            "bad default": lambda d: d.update(default_action="ignore"),
            "empty conditions": lambda d: d["action_rules"][1].update(all=[]),
            "bool bound": lambda d: d["action_rules"][1]["all"][0].update(min=True),
        }
        for name, fn in bad.items():
            with self.subTest(name=name):
                with self.assertRaises((PolicyError, KeyError)):
                    self.load(mutate(fn))


if __name__ == "__main__":
    unittest.main()
