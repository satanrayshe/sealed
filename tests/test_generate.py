import base64
import codecs
import collections
import json
import unittest
from pathlib import Path

from sealed.attackset import PLAIN_EN
from sealed.corpus import ATTACKS
from sealed.explain import explain
from sealed.generate import FAMILIES, PER_FAMILY, data_files, synthetic_alerts
from sealed.vocabulary import parse_signal

DATA = Path(__file__).resolve().parent.parent / "data"


class Reproducible(unittest.TestCase):
    def test_committed_files_match_the_generator_byte_for_byte(self):
        for name, text in data_files().items():
            with self.subTest(name=name):
                self.assertEqual((DATA / name).read_bytes(), text.encode("utf-8"))

    def test_seed_matters(self):
        self.assertNotEqual(synthetic_alerts(seed=1), synthetic_alerts(seed=2))
        self.assertEqual(synthetic_alerts(seed=1), synthetic_alerts(seed=1))


class SyntheticAlerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alerts = json.loads((DATA / "synthetic_alerts.json").read_text(encoding="utf-8"))["alerts"]
        cls.report = explain((DATA / "synthetic_alerts.json").read_bytes())

    def test_three_hundred_across_six_families(self):
        self.assertEqual(len(self.alerts), 300)
        families = collections.Counter(alert["id"][4:6] for alert in self.alerts)
        self.assertEqual(sorted(families.values()), [PER_FAMILY] * len(FAMILIES))
        self.assertEqual(len({alert["id"] for alert in self.alerts}), 300)

    def test_every_alert_is_explained_with_every_signal_recognised(self):
        results = self.report["results"]
        self.assertTrue(all(r["status"] == "explained" for r in results))
        self.assertEqual(sum(len(r["unrecognised_signals"]) for r in results), 0)

    def test_no_clean_alert_is_flagged_as_injection(self):
        flagged = [r["alert_id"] for r in self.report["results"] if r["injection_evidence"]["flagged_fields"]]
        self.assertEqual(flagged, [])

    def test_policy_outcomes_are_varied(self):
        actions = collections.Counter(r["recommendation"]["action"] for r in self.report["results"])
        self.assertGreaterEqual(len(actions), 3)
        self.assertTrue(any(r["uncertainty"]["reasons"] for r in self.report["results"]))

    def test_entities_are_synthetic(self):
        for alert in self.alerts:
            self.assertTrue(alert["host"].endswith(".campus.example"))
            if "url" in alert:
                self.assertRegex(alert["url"], r"^https://[a-z0-9.-]+\.example/")


class OtherData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.benign = json.loads((DATA / "benign_oddities.json").read_text(encoding="utf-8"))["benign_oddities"]
        cls.attacks = json.loads((DATA / "attack_set.json").read_text(encoding="utf-8"))["attack_set"]

    def test_benign_set(self):
        kinds = collections.Counter(item["kind"] for item in self.benign)
        self.assertEqual(set(kinds), {"latin-indian-name", "devanagari-name", "ignore-or-system-username",
                                      "long-user-agent", "url-with-prompt", "hostname"})
        self.assertTrue(any(0x900 <= ord(ch) <= 0x97F for item in self.benign for ch in item["value"]))
        self.assertTrue(all(len(i["value"]) >= 400 for i in self.benign if i["kind"] == "long-user-agent"))
        names = [i["value"].lower() for i in self.benign if i["kind"] == "ignore-or-system-username"]
        self.assertTrue(any("ignore" in n for n in names) and any("system" in n for n in names))
        self.assertTrue(all("prompt" in i["value"] for i in self.benign if i["kind"] == "url-with-prompt"))
        self.assertTrue(all(i["split"] == "dev" for i in self.benign[:97]))
        self.assertEqual({i["split"] for i in self.benign[97:]}, {"dev", "test"})

    def test_attack_set_tags(self):
        self.assertTrue(190 <= len(self.attacks) <= 210)
        self.assertEqual(len({a["id"] for a in self.attacks}), len(self.attacks))
        self.assertEqual({a["class"] for a in self.attacks},
                         {"direct-override", "persona-hijack", "context-manipulation", "obfuscated"})
        self.assertEqual({a["language"] for a in self.attacks}, {"en", "hi", "hinglish"})
        for encoding in ["base64", "rot13", "leetspeak", "homoglyph", "zero-width", "bidi", "split", "json",
                         "markdown", "url", "hostname"]:
            self.assertIn(encoding, {a["encoding"] for a in self.attacks})
        fields = {"username", "user_agent", "url", "host", "signals", "note", "action", "severity"}
        for a in self.attacks:
            self.assertLessEqual(set(a["fields"]), fields, a["id"])
            self.assertIn(a["split"], ("dev", "test"))
            if a["encoding"] == "split":
                self.assertEqual(len(a["parts"]), len(a["fields"]), a["id"])
            else:
                self.assertIsInstance(a["text"], str)

    def test_old_strings_are_dev_and_every_class_has_a_test_half(self):
        old = {a.id for a in ATTACKS}
        self.assertTrue(all(a["split"] == "dev" for a in self.attacks if a["id"] in old))
        for cls in {a["class"] for a in self.attacks}:
            new = [a for a in self.attacks if a["class"] == cls and a["id"] not in old]
            tests = sum(a["split"] == "test" for a in new)
            self.assertIn(tests, (len(new) // 2, len(new) - len(new) // 2))

    def test_encoded_strings_hide_their_plaintext(self):
        for a in self.attacks:
            if a["encoding"] == "base64":
                self.assertTrue(base64.b64decode(a["text"]).decode().isascii(), a["id"])
            if a["encoding"] == "rot13" and a["id"].startswith("OB"):
                plain = codecs.encode(a["text"], "rot13")
                self.assertIn(plain, [text for _, text in PLAIN_EN])

    def test_no_attack_string_reads_as_a_signal(self):
        for a in self.attacks:
            for text in a.get("parts", [a.get("text")]):
                self.assertIsNone(parse_signal(text), a["id"])


if __name__ == "__main__":
    unittest.main()
