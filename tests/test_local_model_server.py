"""The optional model server, tested with a fake model: no GPU, no torch."""

import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path

from sealed.model_eval import MODELS as EVAL_MODELS
from sealed.narrate import OllamaNarrator
from sealed.view import seal
from sealed.vocabulary import Fact

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("local_model_server", ROOT / "tools" / "local_model_server.py")
server_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server_module)


class FakeBackend:
    tag = "qwen3-1.7b:bf16"

    def __init__(self, content='{"sentences": ["5 failed sign-in attempts were recorded on the account [S1]."]}',
                 error=None):
        self.content, self.error, self.seen = content, error, []

    def generate(self, messages):
        self.seen.append(messages)
        if self.error:
            raise self.error
        return {"content": self.content, "prompt_tokens": 12, "completion_tokens": 7, "done_reason": "stop"}


class OutOfMemoryError(RuntimeError):
    pass


class Module(unittest.TestCase):
    def test_imports_no_ml_library_at_module_level(self):
        source = (ROOT / "tools" / "local_model_server.py").read_text(encoding="utf-8")
        top = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
        self.assertFalse(any(name in line for line in top for name in ("torch", "transformers", "bitsandbytes")))

    def test_pins_match_the_runner(self):
        self.assertEqual(sorted(server_module.MODELS), sorted(EVAL_MODELS))
        for tag, spec in server_module.MODELS.items():
            self.assertRegex(spec["revision"], r"^[0-9a-f]{40}$")
            self.assertEqual(spec["precision"], tag.split(":")[1])
            self.assertEqual(spec["licence"], "Apache-2.0")

    def test_sealed_never_imports_the_server(self):
        for path in (ROOT / "sealed").glob("*.py"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith(("import ", "from ")):
                    self.assertNotIn("tools", line, path.name)
                    self.assertNotIn("local_model_server", line, path.name)
                    self.assertNotIn("torch", line, path.name)

    def test_memory_check(self):
        spec = server_module.MODELS["qwen3-1.7b:bf16"]
        need = server_module.needed_bytes(spec)
        self.assertIsNone(server_module.memory_refusal(need, spec))
        self.assertIn("refusing to load", server_module.memory_refusal(need - 1, spec))
        small = server_module.needed_bytes(server_module.MODELS["granite-4.0-micro:nf4"])
        self.assertLess(small, need)

    def test_missing_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                server_module.snapshot_dir(server_module.MODELS["qwen3-1.7b:bf16"], Path(tmp))

    def test_out_of_memory_is_recognised(self):
        self.assertTrue(server_module.is_out_of_memory(OutOfMemoryError("x")))
        self.assertTrue(server_module.is_out_of_memory(RuntimeError("CUDA out of memory. Tried to allocate")))
        self.assertFalse(server_module.is_out_of_memory(ValueError("bad")))


class Chat(unittest.TestCase):
    def test_reply_shape(self):
        backend = FakeBackend()
        status, body = server_module.chat(backend, {"model": backend.tag, "stream": False, "options": {"temperature": 0},
                                                    "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(status, 200)
        self.assertEqual(body["message"], {"role": "assistant", "content": backend.content})
        self.assertEqual((body["done"], body["eval_count"], body["prompt_eval_count"]), (True, 7, 12))
        self.assertEqual(backend.seen, [[{"role": "user", "content": "hi"}]])

    def test_refusals(self):
        backend = FakeBackend()
        ok = {"model": backend.tag, "stream": False, "messages": [{"role": "user", "content": "hi"}]}
        self.assertEqual(server_module.chat(backend, dict(ok, model="other:bf16"))[0], 404)
        self.assertEqual(server_module.chat(backend, {k: v for k, v in ok.items() if k != "stream"})[0], 400)
        self.assertEqual(server_module.chat(backend, dict(ok, stream=True))[0], 400)
        for messages in [[], "hi", [{"role": "tool", "content": "x"}], [{"role": "user", "content": 5}],
                         [{"role": "user", "content": "x", "images": []}]]:
            self.assertEqual(server_module.chat(backend, dict(ok, messages=messages))[0], 400)
        self.assertEqual(server_module.chat(backend, ["not", "an", "object"])[0], 400)


class OverHttp(unittest.TestCase):
    def start(self, backend):
        fatal = []
        server = HTTPServer(("127.0.0.1", 0), server_module.make_handler(backend, fatal.append))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1], fatal

    def test_the_sealed_narrator_talks_to_it_unchanged(self):
        backend = FakeBackend()
        port, _ = self.start(backend)
        narrator = OllamaNarrator(backend.tag, base_url=f"http://127.0.0.1:{port}")
        view = seal([Fact("failed_attempts", 5)], 0)
        self.assertEqual(narrator.narrate(view), ["5 failed sign-in attempts were recorded on the account [S1]."])
        self.assertEqual(backend.seen[0], [{"role": "user", "content": view.model_input_text}])

    def test_tags_host_check_and_out_of_memory(self):
        import http.client
        backend = FakeBackend(error=OutOfMemoryError("CUDA out of memory"))
        port, fatal = self.start(backend)

        def request(method, path, host, body=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            connection.putrequest(method, path, skip_host=True)
            connection.putheader("Host", host)
            if body is not None:
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            data = response.read()
            connection.close()
            return response.status, data

        status, data = request("GET", "/api/tags", f"127.0.0.1:{port}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["models"][0]["details"]["revision"],
                         server_module.MODELS["qwen3-1.7b:bf16"]["revision"])
        self.assertEqual(request("GET", "/api/tags", "evil.example")[0], 403)
        body = json.dumps({"model": backend.tag, "stream": False,
                           "messages": [{"role": "user", "content": "hi"}]}).encode()
        status, data = request("POST", "/api/chat", f"127.0.0.1:{port}", body)
        self.assertEqual(status, 503)
        self.assertEqual(fatal, ["CUDA out of memory during generation"])


if __name__ == "__main__":
    unittest.main()
