"""The model-arm driver, tested without a GPU: status writes, memory backoff and which server it trusts."""

import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = _load("run_model_arms")
server_module = _load("local_model_server")


class Backend:
    tag = "granite-4.0-micro:nf4"

    def generate(self, messages):
        return {"content": "{}", "prompt_tokens": 1, "completion_tokens": 1, "done_reason": "stop"}


class Status(unittest.TestCase):
    def test_a_reader_holding_status_json_never_stops_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            driver.write_status(log_dir, {"state": "running"})
            with open(log_dir / "status.json", encoding="utf-8"):  # on Windows this blocks os.replace
                driver.write_status(log_dir, {"state": "running", "done": 2})  # must not raise
            driver.write_status(log_dir, {"state": "running", "done": 3})
            self.assertEqual(json.loads((log_dir / "status.json").read_text(encoding="utf-8"))["done"], 3)
            if os.name == "nt":
                self.assertIn("status.json not updated", (log_dir / "run.log").read_text(encoding="utf-8"))


class Backoff(unittest.TestCase):
    def wait(self, free_values, minutes=45):
        clock = [0.0]
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds

        values = iter(free_values)
        with tempfile.TemporaryDirectory() as tmp:
            ok = driver.wait_for_memory(5 * driver.GIB, Path(tmp), "m", free=lambda: next(values),
                                        sleep=sleep, clock=lambda: clock[0], poll_seconds=1, minutes=minutes)
            text = (Path(tmp) / "run.log").read_text(encoding="utf-8") if (Path(tmp) / "run.log").exists() else ""
        return ok, sleeps, text

    def test_waits_until_enough_memory_is_free_polling_at_most_every_30_seconds(self):
        ok, sleeps, text = self.wait([2 * driver.GIB, 3 * driver.GIB, 6 * driver.GIB])
        self.assertTrue(ok)
        self.assertEqual(sleeps, [30, 30])
        self.assertIn("backoff:", text)
        self.assertIn("backoff over", text)

    def test_gives_up_after_the_time_limit(self):
        ok, sleeps, text = self.wait([driver.GIB] * 1000, minutes=45)
        self.assertFalse(ok)
        self.assertEqual(sum(sleeps), 45 * 60)
        self.assertIn("gave up after 45 min", text)

    def test_enough_memory_means_no_wait_and_no_log(self):
        ok, sleeps, text = self.wait([8 * driver.GIB])
        self.assertTrue(ok)
        self.assertEqual((sleeps, text), ([], ""))

    def test_need_is_the_servers_own_estimate(self):
        settings = driver.server_settings()
        spec = settings.MODELS["qwen3-1.7b:bf16"]
        self.assertEqual(settings.needed_bytes(spec), server_module.needed_bytes(spec))
        self.assertGreater(settings.needed_bytes(spec), spec["params"] * 2 + settings.MARGIN_GIB * driver.GIB)


class WhichServer(unittest.TestCase):
    def start(self, instance):
        with mock.patch.object(server_module, "INSTANCE", instance):
            handler = server_module.make_handler(Backend(), lambda reason: None)
        server = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_ready_only_for_its_own_server_with_the_right_model(self):
        port = self.start("token-a")
        self.assertTrue(driver.server_ready(port, Backend.tag, "token-a"))
        self.assertFalse(driver.server_ready(port, Backend.tag, "token-b"))  # someone else's server
        self.assertFalse(driver.server_ready(port, "qwen3-1.7b:bf16", "token-a"))  # wrong model
        found = driver.tags(port)
        self.assertEqual((found["name"], found["pid"]), (Backend.tag, os.getpid()))

    def test_nothing_listening(self):
        import socket
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.assertIsNone(driver.tags(port))
        self.assertFalse(driver.server_ready(port))

    def test_plan_items_are_checked(self):
        for plan in ("qwen3-1.7b:bf16=0", "qwen3-1.7b:bf16=\u00b2", "nope:bf16=10", "qwen3-1.7b:bf16=1201"):
            with self.assertRaises(SystemExit):
                with mock.patch("sys.stderr"):
                    driver.main(["--plan", plan, "--server-python", "python", "--log-dir", tempfile.gettempdir()])


if __name__ == "__main__":
    unittest.main()
