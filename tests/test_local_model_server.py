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
        import time
        for _ in range(100):  # the server records the stop just after it sends the reply
            if fatal:
                break
            time.sleep(0.05)
        self.assertEqual(fatal, ["CUDA out of memory during generation"])

    def raw_request(self, port, method, path, headers, body=b""):
        import http.client
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders(body or None)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, data

    def test_requests_are_checked_before_any_work(self):
        backend = FakeBackend()
        port, _ = self.start(backend)
        host = f"127.0.0.1:{port}"
        body = json.dumps({"model": backend.tag, "stream": False,
                           "messages": [{"role": "user", "content": "hi"}]}).encode()
        ok = {"Host": host, "Content-Type": "application/json", "Content-Length": str(len(body))}
        self.assertEqual(self.raw_request(port, "POST", "/api/chat", ok, body)[0], 200)
        self.assertEqual(self.raw_request(port, "POST", "/api/chat", dict(ok, Origin=f"http://{host}"), body)[0], 200)
        cases = [
            (dict(ok, Origin="https://evil.example"), body, 403),  # a web page posting cross-site
            (dict(ok, **{"Content-Type": "text/plain"}), body, 415),  # a "simple" CORS request
            (dict(ok, **{"Content-Length": "\u00b2"}), b"", 411),  # isdigit() but not a decimal number
            (dict(ok, **{"Content-Length": "5000001"}), b"", 413),
        ]
        for headers, payload, status in cases:
            with self.subTest(headers=headers):
                self.assertEqual(self.raw_request(port, "POST", "/api/chat", headers, payload)[0], status)
        deep = b"[" * 200_000 + b"]" * 200_000
        self.assertEqual(self.raw_request(port, "POST", "/api/chat", dict(ok, **{"Content-Length": str(len(deep))}),
                                          deep)[0], 400)
        self.assertEqual(len(backend.seen), 2)  # only the two good requests reached the model
        self.assertEqual(self.raw_request(port, "GET", "/api/tags", {"Host": host, "Origin": "https://evil.example"})[0],
                         403)

    def test_prompt_caps(self):
        backend = FakeBackend(error=server_module.PromptTooLong("the prompt has 9000 tokens"))
        long = {"model": backend.tag, "stream": False,
                "messages": [{"role": "user", "content": "x" * (server_module.MAX_PROMPT_CHARS + 1)}]}
        self.assertEqual(server_module.chat(backend, long)[0], 413)
        self.assertEqual(backend.seen, [])  # refused before tokenising
        short = dict(long, messages=[{"role": "user", "content": "hi"}])
        self.assertEqual(server_module.chat(backend, short)[0], 413)  # over the token cap

    def test_a_stalled_client_is_dropped(self):
        import socket
        from unittest import mock
        with mock.patch.object(server_module, "SOCKET_TIMEOUT", 0.5):
            port, _ = self.start(FakeBackend())
        with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
            client.sendall(f"POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json"
                           f"\r\nContent-Length: 1000\r\n\r\n{{".encode())
            client.settimeout(10)
            self.assertEqual(client.recv(100), b"")  # the server closed the connection

    def test_the_port_is_bound_exclusively(self):
        first = server_module.LocalHTTPServer(("127.0.0.1", 0), server_module.make_handler(FakeBackend(), print))
        self.addCleanup(first.server_close)
        port = first.server_address[1]
        self.assertEqual(server_module.serve(FakeBackend(), port), 5)

    def test_the_server_can_watch_its_driver(self):
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
        wait = server_module.parent_waiter(child.pid)
        self.assertIsNotNone(wait)
        done = threading.Thread(target=wait, daemon=True)
        done.start()
        done.join(timeout=20)
        self.assertFalse(done.is_alive())
        child.wait(timeout=20)

    def test_the_driver_records_what_produced_each_reply(self):
        import hashlib
        spec = importlib.util.spec_from_file_location("run_model_arms", ROOT / "tools" / "run_model_arms.py")
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        backend = FakeBackend()
        port, _ = self.start(backend)
        self.assertTrue(driver.server_ready(port))
        meta = driver.generation_meta(backend.tag, port)
        pinned = server_module.MODELS[backend.tag]
        self.assertEqual(meta["server_sha256"],
                         hashlib.sha256((ROOT / "tools" / "local_model_server.py").read_bytes()).hexdigest())
        self.assertEqual((meta["tag"], meta["repo"], meta["revision"], meta["precision"]),
                         (backend.tag, pinned["repo"], pinned["revision"], pinned["precision"]))
        self.assertEqual((meta["max_new_tokens"], meta["do_sample"], meta["seed"], meta["template_kwargs"]),
                         (384, False, 0, {"enable_thinking": False}))


if __name__ == "__main__":
    unittest.main()
