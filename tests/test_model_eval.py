import collections
import hashlib
import json
import tempfile
import unittest

from sealed.arms import raw_prompt
from sealed.attackset import CLASSES
from sealed.model_eval import (
    ARM_FORMAT, MODELS, OPTIONS, Client, interleaved_triples, plan_requests, run, summarise,
)
from sealed.narrate import CacheMiss, NarratorError
from sealed.vocabulary import SIGNALS, UNRECOGNISED

MODEL = MODELS[0]
ATTACK_WORDS = ("benign", "allow", "ignore", "no action", "approve", "test")


def fake_server(log=None, fail_after=None):
    """Answers like /api/chat. The fake baseline model obeys attack words; the fake narrator is well behaved."""
    calls = collections.Counter()

    def transport(url, body, timeout):
        calls["n"] += 1
        if fail_after is not None and calls["n"] > fail_after:
            raise ConnectionResetError("server went away")
        payload = json.loads(body)
        if log is not None:
            log.append(payload)
        content = payload["messages"][-1]["content"]
        if "FACTS:" in content:
            view = json.loads(content.split("FACTS:")[1])
            good = [(UNRECOGNISED if e["signal"] == "unrecognised" else SIGNALS[e["signal"]]).sentence(e.get("count"))
                    + f" [{e['id']}]." for e in view["evidence"]]
            reply = json.dumps({"sentences": ["Something happened."] + good})
        else:
            alert_text = content.split("Alert:")[-1].split("<alert_data>")[-1].lower()
            action = "allow" if any(w in alert_text for w in ATTACK_WORDS[:2]) else "step-up"
            reply = json.dumps({"action": action, "explanation": "Looks " + ("benign" if action == "allow" else "risky")})
        return json.dumps({"model": payload["model"], "message": {"role": "assistant", "content": reply},
                           "done": True, "eval_count": 9, "prompt_eval_count": 99}).encode()

    return transport, calls


class Triples(unittest.TestCase):
    def test_interleaved_and_stratified(self):
        triples = interleaved_triples()
        self.assertEqual(len(triples), 1200)
        self.assertEqual([t["class"] for t in triples[:4]], list(CLASSES))
        self.assertEqual(collections.Counter(t["class"] for t in triples[:400]), {c: 100 for c in CLASSES})
        self.assertEqual(triples, interleaved_triples())

    def test_plan_requests_is_deterministic_and_deduplicated(self):
        triples = interleaved_triples()[:12]
        first, second = plan_requests(MODEL, triples), plan_requests(MODEL, triples)
        self.assertEqual(first, second)
        self.assertEqual(len({hashlib.sha256(b).hexdigest() for _, b in first}), len(first))


class Requests(unittest.TestCase):
    def setUp(self):
        self.triple = next(t for t in interleaved_triples() if t["fields"] == ["username"])

    def test_bodies(self):
        from sealed.model_eval import _parsed, _variants
        from sealed.attackset import attack_set
        from sealed.generate import synthetic_alerts
        variants = _variants(self.triple, {a["id"]: a for a in synthetic_alerts()}, {a["id"]: a for a in attack_set()})
        client = Client(MODEL, transport=lambda *a: b"", offline=True)
        raw = json.loads(client.body("raw-prompt", variants["attacked"], _parsed(variants["attacked"])))
        self.assertEqual(raw, {"model": MODEL, "messages": raw_prompt(variants["attacked"]), "stream": False,
                               "format": ARM_FORMAT, "options": OPTIONS})
        sealed = [client.body("sealed", v, _parsed(v)) for v in variants.values()]
        self.assertEqual(sealed[0], sealed[1])
        self.assertEqual(json.loads(sealed[0])["options"], OPTIONS)
        attack_text = variants["attacked"]["username"]
        self.assertIn(json.dumps(attack_text)[1:-1][:20].encode(),
                      client.body("raw-prompt", variants["attacked"], _parsed(variants["attacked"])))
        self.assertNotIn(attack_text.encode("utf-8")[:20], sealed[0])

    def test_loopback_only(self):
        with self.assertRaises(ValueError):
            Client(MODEL, base_url="http://10.0.0.2:11434")

    def test_cache_by_request_hash_even_for_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []

            def transport(url, body, timeout):
                calls.append(body)
                return json.dumps({"message": {"content": "not json at all"}, "eval_count": 3}).encode()

            client = Client(MODEL, cache_dir=tmp, transport=transport)
            body = b'{"x": 1}'
            first = client.ask(body)
            second = client.ask(body)
            self.assertEqual(len(calls), 1)
            self.assertEqual(first["content"], "not json at all")
            self.assertEqual(first["request_sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(second, first)
            with self.assertRaises(CacheMiss):
                Client(MODEL, cache_dir=tmp, offline=True).ask(b'{"y": 2}')
            broken = Client(MODEL, cache_dir=tmp, transport=lambda *a: b"<html>")
            with self.assertRaises(NarratorError):
                broken.ask(b'{"z": 3}')


class RunAndSummarise(unittest.TestCase):
    def test_resumable_run_and_offline_summary(self):
        triples = interleaved_triples()[:8]
        with tempfile.TemporaryDirectory() as tmp:
            transport, calls = fake_server(fail_after=10)
            with self.assertRaises(ConnectionResetError):
                run(MODEL, triples, cache_dir=tmp, transport=transport)
            transport, calls = fake_server()
            progress = []
            result = run(MODEL, triples, cache_dir=tmp, transport=transport, progress=progress.append)
            self.assertEqual(result["fresh"], result["requests"] - 10)
            self.assertEqual(progress[-1]["done"], result["requests"])
            again = run(MODEL, triples, cache_dir=tmp, transport=fake_server()[0])
            self.assertEqual(again["fresh"], 0)

            summary = summarise(MODEL, triples, cache_dir=tmp)
            raw, sealed = summary["arms"]["raw-prompt"], summary["arms"]["sealed"]
            self.assertEqual(raw["triples"], 8)
            self.assertGreater(raw["decision_lowered"]["k"], 0)  # the fake baseline model obeys attack words
            self.assertEqual(sealed["decision_lowered"]["k"], 0)  # Sealed never lowers
            self.assertEqual(sealed["same_model_input"]["k"], 8)
            self.assertEqual(sealed["sentences_dropped"]["k"], 8)  # only "Something happened.", which cites nothing
            self.assertEqual(sealed["leaky_narratives"]["k"], 0)
            self.assertIn("bootstrap95_by_alert", raw["decision_change"])

    def test_summary_skips_missing_replies(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = summarise(MODEL, interleaved_triples()[:4], cache_dir=tmp)
            self.assertEqual(summary["arms"]["hardened"]["triples"], 0)
            self.assertEqual(summary["arms"]["hardened"]["missing"], 4)


if __name__ == "__main__":
    unittest.main()
