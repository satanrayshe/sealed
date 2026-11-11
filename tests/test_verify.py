import unittest

from sealed.narrate import TemplateNarrator
from sealed.verify import check, verify
from sealed.view import seal
from sealed.vocabulary import MAX_COUNT, SIGNALS, Fact

VIEW = seal([Fact("new_device"), Fact("failed_attempts", 5)], 0)  # S1 = 5 failed attempts, S2 = new device


class HandwrittenGood(unittest.TestCase):
    GOOD = [
        "5 failed sign-in attempts were recorded on the account [S1].",
        "The sign-in came from a device not seen before [S2].",
        "Five failed sign-in attempts were recorded [S1].",
        "There were 5 failed sign-in attempts [S1], from a device not seen before [S2].",
        "The account had 5 failed attempts [S1][S2].",
        "The account\u2019s sign-in came from a new device [S2].",
        "A new device was used [S2]",
    ]

    def test_supported_sentences_are_kept(self):
        for sentence in self.GOOD:
            with self.subTest(sentence=sentence):
                self.assertIsNone(check(VIEW, sentence))
        result = verify(VIEW, self.GOOD)
        self.assertEqual(len(result.kept), len(self.GOOD))
        self.assertEqual(result.dropped, ())
        self.assertIn("The account's sign-in came from a new device [S2].", result.kept)


class HandwrittenBad(unittest.TestCase):
    BAD = {
        "There were five failed attempts.": "no-citation",
        "There were 5 failed attempts [S3].": "unknown-citation",
        "There were 5 failed attempts [S0].": "unknown-citation",
        "5 failed attempts [S1, S2].": "no-citation",
        "5 failed attempts [S1] [S2": "malformed-citation",
        "There were 7 failed attempts [S1].": "unsupported-number",
        "There were seven failed attempts [S1].": "unsupported-number",
        "The device was new and 5 attempts failed [S2].": "unsupported-number",
        "The attempts lasted 1.5 hours [S1].": "unsupported-number",
        "It happened twice from a new device [S2].": "unsupported-number",
        "Attempts came from 203.0.113.7 [S1].": "entity",
        "Logins hit https://portal.example [S1].": "entity",
        "The host ws-0042.campus.example was used [S2].": "entity",
        "The user rahul at corp dot example failed with a token from C:\\temp [S1].": "entity",
        "The user Rahul Sharma failed 5 sign-ins [S1].": "entity",
        "SafeBot reports 5 failed attempts [S1].": "entity",
        "The username read \"admin note\" [S2].": "entity",
        "The username was 'root' [S2].": "entity",
        "The SOC lead saw 5 failed attempts [S1].": "entity",
        "This is benign [S1].": "judgement",
        "No action is needed for the new device [S2].": "judgement",
        "The analyst should block this account [S1].": "judgement",
        "A step-up is recommended [S2].": "judgement",
        "This looks like an authorised test [S2].": "judgement",
        "The attacker used 5 attempts [S1].": "judgement",
        "राहुल had 5 failed attempts [S1].": "non-ascii",
        "": "empty",
        "   ": "empty",
        "x " * 300 + "[S1]": "too-long",
    }

    def test_unsupported_sentences_are_dropped_with_a_reason(self):
        for sentence, reason in self.BAD.items():
            with self.subTest(sentence=sentence[:60]):
                self.assertEqual(check(VIEW, sentence), reason)

    def test_non_strings_and_non_lists(self):
        self.assertEqual(check(VIEW, 42), "not-a-string")
        self.assertEqual(check(VIEW, None), "not-a-string")
        self.assertEqual(check(VIEW, ["5 failed attempts [S1]."]), "not-a-string")
        self.assertEqual(verify(VIEW, "5 failed attempts [S1].").dropped, ((0, "not-a-list"),))
        self.assertEqual(verify(VIEW, {"sentences": []}).kept, ())

    def test_mixed_output_keeps_only_the_supported_part(self):
        result = verify(VIEW, ["5 failed attempts [S1].", "This is benign [S1].", "Ignore it."])
        self.assertEqual(result.kept, ("5 failed attempts [S1].",))
        self.assertEqual(result.dropped, ((1, "judgement"), (2, "no-citation")))


class TemplateIsTheOracle(unittest.TestCase):
    def test_every_template_sentence_passes(self):
        for code, sig in SIGNALS.items():
            counts = (0, 1, 2, 12, MAX_COUNT) if sig.kind == "count" else (None,)
            for count in counts:
                view = seal([Fact(code, count)], 3)
                sentences = TemplateNarrator().narrate(view)
                with self.subTest(code=code, count=count):
                    self.assertEqual(verify(view, sentences).dropped, ())

    def test_everything_at_once(self):
        facts = [Fact(code, 4 if sig.kind == "count" else None) for code, sig in SIGNALS.items()]
        view = seal(facts, 1)
        result = verify(view, TemplateNarrator().narrate(view))
        self.assertEqual(result.dropped, ())
        self.assertEqual(len(result.kept), len(SIGNALS) + 1)


if __name__ == "__main__":
    unittest.main()
