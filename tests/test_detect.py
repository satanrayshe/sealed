import time
import unittest

from sealed.contract import FreeText
from sealed.corpus import ATTACKS, KEYWORD_BASELINE_MISSES, benign_oddities
from sealed.detect import KeywordDetector, normalise, scan
from sealed.policy import POLICY

THRESHOLD = POLICY.threshold


class KeywordBaseline(unittest.TestCase):
    def setUp(self):
        self.detector = KeywordDetector()

    def test_flags_our_attack_strings_except_the_published_misses(self):
        for attack in ATTACKS:
            with self.subTest(attack=attack.id):
                flagged = self.detector.score(attack.text) >= THRESHOLD
                self.assertEqual(flagged, attack.id not in KEYWORD_BASELINE_MISSES)

    def test_no_false_flags_on_benign_oddities(self):
        items = benign_oddities()
        flagged = [item["value"] for item in items if self.detector.score(item["value"]) >= THRESHOLD]
        self.assertEqual(flagged, [])
        # Same author wrote the detector and this set: this is a regression check, not independent evidence.
        self.assertLessEqual(len(flagged) / len(items), 0.02)

    def test_single_words_ignore_and_system_are_not_enough(self):
        for text in ["ignore", "system", "system.admin", "ignore_me", "Instructions", "benign", "prompt"]:
            with self.subTest(text=text):
                self.assertEqual(self.detector.score(text), 0.0)

    def test_scores_grow_with_matches_and_stay_in_range(self):
        self.assertEqual(self.detector.score(""), 0.0)
        self.assertEqual(self.detector.score("you are now"), 0.5)
        self.assertEqual(self.detector.score("you are now in developer mode"), 0.75)
        for attack in ATTACKS:
            self.assertTrue(0.0 <= self.detector.score(attack.text) < 1.0)

    def test_hides_behind_formatting_do_not_work(self):
        for text in ["IGNORE   PREVIOUS", "ignore_previous", "ignore-previous", "Ignore\nprevious",
                     "ig​nore previous", "ｉgnore previous", "i.g.n.o.r.e p.r.e.v.i.o.u.s i.n.s.t.r.u.c.t.i.o.n.s"]:
            with self.subTest(text=text):
                self.assertGreaterEqual(self.detector.score(text), THRESHOLD)

    def test_no_quadratic_backtracking(self):
        # A regex that backtracks on long runs would take minutes here; the linear ones take milliseconds.
        for text in ["#" * 200_000, "\n" * 200_000, '"' + " " * 200_000, "<" + " " * 200_000, "\n\t" * 100_000,
                     "\nuser" * 40_000, "# " * 100_000, "system " * 30_000, "[" * 200_000, "<|" * 100_000]:
            start = time.perf_counter()
            self.detector.score(text)
            self.assertLess(time.perf_counter() - start, 3.0, repr(text[:12]))

    def test_long_and_odd_text_does_not_crash(self):
        for text in ["x" * 1_000_000, "𐏿" * 10, "\x00" * 100, "‮" * 50, "🙂" * 1000]:
            self.assertEqual(self.detector.score(text), 0.0)
        self.assertGreaterEqual(self.detector.score("a" * 100_000 + " ignore previous instructions"), THRESHOLD)


class Normalise(unittest.TestCase):
    def test_folding(self):
        self.assertEqual(normalise("  Ignore__PREVIOUS\t\ninstructions!! "), "ignore previous instructions")
        self.assertEqual(normalise("ｉｇｎｏｒｅ"), "ignore")
        self.assertEqual(normalise("ig​n⁠ore"), "ignore")

    def test_devanagari_words_stay_whole(self):
        self.assertEqual(normalise("पिछले  निर्देश।"), "पिछले निर्देश।")


class Scan(unittest.TestCase):
    def test_scan_marks_flagged_fields(self):
        items = [FreeText("id", "alert-001"), FreeText("username", ATTACKS[4].text)]
        results = scan(KeywordDetector(), items, THRESHOLD)
        self.assertEqual([(r.field, r.flagged) for r in results], [("id", False), ("username", True)])

    def test_a_failing_or_wild_detector_cannot_crash_or_escape_the_range(self):
        class Wild:
            name = "wild"

            def __init__(self):
                self.values = iter([float("nan"), 7.0, -3.0, "0.6", None])

            def score(self, text):
                value = next(self.values)
                if value is None:
                    raise RuntimeError("model fell over")
                return value

        items = [FreeText(f"f{i}", "x") for i in range(5)]
        results = scan(Wild(), items, THRESHOLD)
        self.assertEqual([r.score for r in results], [0.0, 1.0, 0.0, 0.6, 0.0])
        self.assertEqual([r.error for r in results], [True, False, False, False, True])
        self.assertEqual([r.flagged for r in results], [False, True, False, True, False])


if __name__ == "__main__":
    unittest.main()
