import collections
import json
import unittest
from pathlib import Path

from sealed.corpus import ATTACKS
from sealed.explain import explain
from sealed.generate import FAMILIES, PER_FAMILY, data_files, synthetic_alerts

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
    def test_benign_oddities(self):
        items = json.loads((DATA / "benign_oddities.json").read_text(encoding="utf-8"))["benign_oddities"]
        kinds = collections.Counter(item["kind"] for item in items)
        self.assertEqual(set(kinds), {"latin-indian-name", "devanagari-name", "ignore-or-system-username",
                                      "long-user-agent"})
        self.assertTrue(any("ऀ" <= ch <= "ॿ" for item in items for ch in item["value"]))
        self.assertTrue(all(len(i["value"]) >= 400 for i in items if i["kind"] == "long-user-agent"))
        names = [i["value"].lower() for i in items if i["kind"] == "ignore-or-system-username"]
        self.assertTrue(any("ignore" in n for n in names) and any("system" in n for n in names))

    def test_attack_strings_mirror_the_corpus(self):
        items = json.loads((DATA / "attack_strings.json").read_text(encoding="utf-8"))["attack_strings"]
        self.assertEqual([(i["id"], i["family"], i["text"]) for i in items],
                         [(a.id, a.family, a.text) for a in ATTACKS])
        self.assertEqual({a.family for a in ATTACKS},
                         {"direct-override", "persona-hijack", "context-manipulation", "obfuscated"})


if __name__ == "__main__":
    unittest.main()
