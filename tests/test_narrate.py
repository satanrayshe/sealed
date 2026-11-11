import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from sealed.narrate import (
    OUTPUT_SCHEMA, CacheMiss, NarratorError, OllamaNarrator, TemplateNarrator, parse_reply,
)
from sealed.view import seal
from sealed.vocabulary import Fact

TRACK_VIEW = seal([Fact("new_device"), Fact("failed_attempts", 5)], 0)


def reply(sentences) -> bytes:
    content = json.dumps({"sentences": sentences})
    return json.dumps({"model": "m", "message": {"role": "assistant", "content": content}, "done": True}).encode()


class FakeTransport:
    """Records every request and answers with a canned reply. Never touches the network."""

    def __init__(self, answer: bytes | Exception):
        self.answer = answer
        self.calls = []

    def __call__(self, url, body, timeout):
        self.calls.append((url, body, timeout))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


class Template(unittest.TestCase):
    def test_track_example(self):
        self.assertEqual(TemplateNarrator().narrate(TRACK_VIEW), [
            "5 failed sign-in attempts were recorded on the account [S1].",
            "The sign-in came from a device not seen before [S2].",
        ])

    def test_singular_unrecognised_and_empty(self):
        view = seal([Fact("failed_attempts", 1)], 1)
        self.assertEqual(TemplateNarrator().narrate(view), [
            "1 failed sign-in attempt was recorded on the account [S1].",
            "1 signal did not match the vocabulary and was set aside unread [S2].",
        ])
        self.assertEqual(TemplateNarrator().narrate(seal([], 0)), [])


class Ollama(unittest.TestCase):
    GOOD = ["Five failed sign-ins happened [S1].", "The device was new [S2]."]

    def test_request_is_exactly_the_sealed_input(self):
        transport = FakeTransport(reply(self.GOOD))
        narrator = OllamaNarrator("qwen2.5:7b-instruct", transport=transport)
        self.assertEqual(narrator.narrate(TRACK_VIEW), self.GOOD)
        ((url, body, _),) = transport.calls
        self.assertEqual(url, "http://127.0.0.1:11434/api/chat")
        payload = json.loads(body)
        self.assertEqual(payload["model"], "qwen2.5:7b-instruct")
        self.assertEqual(payload["options"], {"temperature": 0, "seed": 0})
        self.assertIs(payload["stream"], False)
        self.assertEqual(payload["format"], OUTPUT_SCHEMA)
        self.assertEqual(payload["messages"], [{"role": "user", "content": TRACK_VIEW.model_input_text}])
        self.assertEqual(payload["messages"][0]["content"].encode("ascii"), TRACK_VIEW.model_input)
        self.assertEqual(set(payload), {"model", "messages", "stream", "format", "options"})

    def test_cache_is_keyed_by_the_input_hash_and_replays_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            transport = FakeTransport(reply(self.GOOD))
            online = OllamaNarrator("qwen2.5:7b-instruct", cache_dir=tmp, transport=transport)
            online.narrate(TRACK_VIEW)
            online.narrate(TRACK_VIEW)
            self.assertEqual(len(transport.calls), 1)
            path = Path(tmp) / "qwen2.5_7b_instruct" / f"{TRACK_VIEW.sha256}.json"
            self.assertTrue(path.is_file())
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["model_input_sha256"], TRACK_VIEW.sha256)
            self.assertEqual(record["request_sha256"], hashlib.sha256(transport.calls[0][1]).hexdigest())

            never = FakeTransport(AssertionError("offline replay must not call the transport"))
            offline = OllamaNarrator("qwen2.5:7b-instruct", cache_dir=tmp, offline=True, transport=never)
            self.assertEqual(offline.narrate(TRACK_VIEW), self.GOOD)
            with self.assertRaises(CacheMiss):
                offline.narrate(seal([Fact("off_hours")], 0))

    def test_cache_from_other_settings_or_corrupt_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            OllamaNarrator("m1", cache_dir=tmp, transport=FakeTransport(reply(self.GOOD))).narrate(TRACK_VIEW)
            other_seed = OllamaNarrator("m1", cache_dir=tmp, offline=True, seed=7)
            with self.assertRaises(CacheMiss):
                other_seed.narrate(TRACK_VIEW)
            path = other_seed.cache_path(TRACK_VIEW)
            path.write_text("{not json", encoding="utf-8")
            transport = FakeTransport(reply(["Fresh [S1]."]))
            fresh = OllamaNarrator("m1", cache_dir=tmp, transport=transport)
            self.assertEqual(fresh.narrate(TRACK_VIEW), ["Fresh [S1]."])
            self.assertEqual(len(transport.calls), 1)

    def test_only_loopback_servers(self):
        for url in ["http://10.0.0.5:11434", "http://example.com", "http://127.0.0.1.evil.example:11434",
                    "http://localhost@evil.example", "ftp://127.0.0.1", "file:///etc/passwd", "127.0.0.1:11434"]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    OllamaNarrator("m", base_url=url)
        for url in ["http://localhost:11434", "http://[::1]:11434", "http://127.0.0.1:8080/"]:
            OllamaNarrator("m", base_url=url)

    def test_model_name_is_checked(self):
        for name in ["", " qwen", "qwen 7b", "../../etc", "a" * 200, None]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    OllamaNarrator(name)

    def test_bad_replies_raise_narrator_error(self):
        bad = [
            b"", b"not json", b"[]", json.dumps({"message": {}}).encode(),
            json.dumps({"message": {"content": "not json"}}).encode(),
            json.dumps({"message": {"content": json.dumps({"text": "x"})}}).encode(),
            reply("one string"), reply([1, 2]), reply([None]), b"\xff\xfe", b"x" * 300_000,
        ]
        for raw in bad:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(NarratorError):
                    parse_reply(raw)

    def test_transport_failures_raise_narrator_error(self):
        for err in [ConnectionRefusedError("down"), TimeoutError("slow"), OSError("x")]:
            narrator = OllamaNarrator("m", transport=FakeTransport(err))
            with self.assertRaises(NarratorError):
                narrator.narrate(TRACK_VIEW)

    def test_long_replies_are_truncated(self):
        narrator = OllamaNarrator("m", transport=FakeTransport(reply(["x [S1]."] * 80)))
        self.assertEqual(len(narrator.narrate(TRACK_VIEW)), 50)


if __name__ == "__main__":
    unittest.main()
