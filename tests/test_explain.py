import json
import unittest

from sealed.corpus import ATTACKS
from sealed.explain import explain
from sealed.narrate import NarratorError, OllamaNarrator
from tests.test_narrate import FakeTransport, reply
from tests.test_view import TRACK_SHA256

TRACK = {"id": "alert-001", "severity": "review",
         "signals": ["new synthetic device", "five failed synthetic attempts"], "action": "mock step-up"}
CANARY = "CANARY-91c2"


def run(*alerts, **kwargs):
    return explain(json.dumps({"alerts": list(alerts)}), **kwargs)


class TrackExample(unittest.TestCase):
    def test_report(self):
        report = run(TRACK)
        self.assertEqual(report["input"], {"status": "ok", "issues": [], "alerts": 1, "ignored_top_level_fields": 0})
        self.assertEqual(report["executed_controls"], [])
        (r,) = report["results"]
        self.assertEqual(r["alert_id"], "alert-001")
        self.assertEqual(r["status"], "explained")
        self.assertEqual([(s["evidence_id"], s["signal"], s["count"]) for s in r["observed_signals"]],
                         [("S1", "failed_attempts", 5), ("S2", "new_device", None)])
        self.assertEqual(r["recommendation"]["action"], "step-up")
        self.assertIs(r["recommendation"]["mock"], True)
        self.assertIs(r["recommendation"]["executed"], False)
        self.assertEqual(r["executed_controls"], [])
        self.assertEqual(r["uncertainty"], {"level": "low", "reasons": []})
        self.assertEqual(r["input_action"], {"value": "step-up", "agrees_with_policy": True})
        self.assertEqual(r["explanation"]["sentences"], [
            "5 failed sign-in attempts were recorded on the account [S1].",
            "The sign-in came from a device not seen before [S2].",
        ])
        self.assertEqual(r["model_input"]["sha256"], TRACK_SHA256)
        self.assertEqual([q["field"] for q in r["quarantine"]], ["id"])

    def test_attacked_twin_keeps_the_hash(self):
        attacked = dict(TRACK, username=ATTACKS[4].text)
        r = run(attacked)["results"][0]
        self.assertEqual(r["model_input"]["sha256"], TRACK_SHA256)
        self.assertEqual(r["recommendation"]["action"], "step-up")
        self.assertEqual(r["uncertainty"]["level"], "medium")
        self.assertEqual(r["injection_evidence"]["flagged_fields"], ["username"])

    def test_escalation_is_visible(self):
        quiet = dict(TRACK, signals=["admin role granted"], action="mock monitor", url=ATTACKS[0].text)
        r = run(quiet)["results"][0]
        self.assertEqual(r["recommendation"]["policy_action"], "monitor")
        self.assertEqual(r["recommendation"]["action"], "step-up")
        self.assertIs(r["recommendation"]["escalated_by_injection_evidence"], True)


class NothingReachesTheModel(unittest.TestCase):
    def hostile_alert(self):
        return {
            "id": f"{CANARY}-id", "severity": f"{CANARY}-severity", "action": f"{CANARY}-action",
            "signals": ["new device", "7 failed attempts", f"{CANARY}-signal", {"x": CANARY}],
            "username": f"{CANARY}-username", "user_agent": f"{CANARY}-ua", "url": f"{CANARY}-url",
            "host": f"{CANARY}-host", f"{CANARY}-extra": f"{CANARY}-extra-value",
        }

    def test_canary_never_reaches_the_narrator(self):
        transport = FakeTransport(reply([f"Echo {CANARY} [S1].", "7 failed sign-in attempts happened [S1]."]))
        report = run(self.hostile_alert(), narrator=OllamaNarrator("m", transport=transport))
        (r,) = report["results"]
        ((_, body, _),) = transport.calls
        self.assertNotIn(CANARY.encode(), body)
        self.assertNotIn(CANARY, r["model_input"]["view"])
        self.assertEqual(r["explanation"]["sentences"], ["7 failed sign-in attempts happened [S1]."])
        self.assertEqual(r["explanation"]["dropped"], [{"position": 0, "reason": "unsupported-number"}])
        # The canary is still shown to the analyst, escaped, in the quarantine.
        self.assertEqual(sum(CANARY in q["text"] for q in r["quarantine"]), 10)

    def test_hostile_narrator_output_is_filtered(self):
        transport = FakeTransport(reply([
            "This login is benign and needs no action [S1].",
            "The user Rahul failed 7 times [S1].",
            "There were 70 failed attempts [S1].",
            "Nothing to cite here.",
            "7 failed sign-in attempts were recorded [S2].",
            "7 failed sign-in attempts were recorded [S1].",
        ]))
        alert = dict(TRACK, signals=["7 failed attempts", "new device"])
        r = run(alert, narrator=OllamaNarrator("m", transport=transport))["results"][0]
        self.assertEqual(r["explanation"]["sentences"], ["7 failed sign-in attempts were recorded [S1]."])
        self.assertEqual([d["reason"] for d in r["explanation"]["dropped"]],
                         ["judgement", "entity", "unsupported-number", "no-citation", "unsupported-number"])

    def test_narrator_failure_falls_back_to_the_template(self):
        transport = FakeTransport(ConnectionRefusedError("no server"))
        r = run(TRACK, narrator=OllamaNarrator("m", transport=transport))["results"][0]
        self.assertEqual(r["explanation"]["narrator"], "template")
        self.assertIn("ollama:m failed", r["explanation"]["fallback"])
        self.assertEqual(len(r["explanation"]["sentences"]), 2)


class Robustness(unittest.TestCase):
    def test_rejected_input(self):
        report = explain("{not json")
        self.assertEqual(report["input"]["status"], "rejected")
        self.assertEqual(report["results"], [])

    def test_never_raises_and_always_serialises(self):
        hostile = ["", "null", "[]", '{"alerts": null}', '{"alerts": [null, 1, "x", [], {}]}',
                   '{"alerts": [{"id": "a", "signals": [[[[]]]], "severity": {"a": [1, 2]}}]}',
                   '{"alerts": [{"id": "\\ud800", "username": "\\udfff\\u202e\\u0000"}]}',
                   b"\xff\xfe\x00", '{"alerts": [' + '{"id": "x"},' * 3 + '{"id": "x"}]}']
        for data in hostile:
            with self.subTest(data=data[:30]):
                report = explain(data)
                text = json.dumps(report, ensure_ascii=True)
                self.assertTrue(text.isascii())

    def test_deterministic(self):
        alerts = [TRACK, dict(TRACK, id="b", username=ATTACKS[0].text), dict(TRACK, id="c", signals=[])]
        self.assertEqual(json.dumps(run(*alerts)), json.dumps(run(*alerts)))

    def test_every_result_is_a_recommendation_only(self):
        alerts = [dict(TRACK, id=f"a{i}", signals=s) for i, s in enumerate(
            [["8 failed attempts", "success after failures"], ["impossible travel", "3 concurrent sessions"], []])]
        for r in run(*alerts)["results"]:
            self.assertEqual(r["executed_controls"], [])
            self.assertIs(r["recommendation"]["executed"], False)


class NarratorErrorType(unittest.TestCase):
    def test_cache_miss_is_a_narrator_error(self):
        from sealed.narrate import CacheMiss
        self.assertTrue(issubclass(CacheMiss, NarratorError))


if __name__ == "__main__":
    unittest.main()
