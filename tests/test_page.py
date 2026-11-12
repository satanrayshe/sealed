"""The public browser page: its bundle is up to date, its Python entry point matches the CLI, its files follow
the safety rules, and the reply export never publishes a dry run. The page in a real browser:
tests/test_page_browser.py."""

import contextlib
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sealed.app import clean_twin
from sealed.contract import MAX_DEPTH
from sealed.explain import explain
from sealed.model_eval import MODELS, PLAN_LIMITS, Client
from sealed.page import (BASELINES, ENTITY_FIELDS, EXAMPLE_ATTACK, PAGE_SCHEMA, REPLIES_SCHEMA, baseline_prompts,
                         detector_status, page_state, presets, presets_document, prompt_sha256)
from sealed.arms import raw_prompt
from tests.test_view import TRACK_SHA256

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PAGE = DOCS / "page"
SAMPLES = ROOT / "sealed" / "samples"
CDN = "https://cdn.jsdelivr.net/pyodide/v0.27.7/full/"
CSP = (f"default-src 'none'; script-src 'self' {CDN} 'wasm-unsafe-eval'; connect-src 'self' {CDN}; "
       "style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_page = _load("build_page")
export = _load("export_page_replies")
ask_baselines = _load("ask_baselines")


def state(text, detector="keyword"):
    return json.loads(page_state(text, detector))


class Bundle(unittest.TestCase):
    def test_generated_files_are_up_to_date(self):
        self.assertEqual(build_page.stale(), [], "run python tools/build_page.py")

    def test_bundle_holds_the_package_and_its_data_only(self):
        names = set(build_page.bundle_contents(build_page.BUNDLE.read_bytes()))
        self.assertIn("sealed/page.py", names)
        self.assertIn("sealed/explain.py", names)
        for data in ["sealed/policy.json", "sealed/vocabulary.json", "sealed/learned_weights.bin",
                     "sealed/learned_weights.json", "sealed/samples/track_example.json"]:
            self.assertIn(data, names)
        self.assertFalse([n for n in names if "__pycache__" in n or n.startswith("sealed/web/")])
        self.assertEqual(names, set(build_page.bundle_sources()))

    def test_bundle_is_reproducible(self):
        sources = build_page.bundle_sources()
        first, second = build_page.build_bundle(sources), build_page.build_bundle(sources)
        self.assertEqual(first, second)
        self.assertEqual(build_page.bundle_contents(first), sources)

    def test_a_changed_source_makes_the_bundle_stale(self):
        changed = dict(build_page.bundle_sources())
        changed["sealed/policy.json"] += b" "
        with mock.patch.object(build_page, "bundle_sources", return_value=changed):
            self.assertIn("docs/page/sealed.zip", build_page.stale())

    def test_check_mode(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(build_page.main(["--check"]), 0)
        self.assertIn("up to date", out.getvalue())


class PageState(unittest.TestCase):
    def test_same_report_and_hash_as_the_cli(self):
        for name in ["track_example.json", "attacked_username.json", "edge_cases.json"]:
            with self.subTest(name=name):
                data = (SAMPLES / name).read_bytes()
                got = state(data.decode("utf-8"))
                self.assertEqual(got["schema"], PAGE_SCHEMA)
                self.assertEqual(got["report"], explain(data))

    def test_the_attacked_twin_has_the_clean_hash(self):
        got = state((SAMPLES / "attacked_username.json").read_text(encoding="utf-8"))
        result = got["report"]["results"][0]
        self.assertEqual(result["model_input"]["sha256"], TRACK_SHA256)
        self.assertEqual(got["seal_checks"], [{"index": 0, "clean_twin_sha256": TRACK_SHA256, "identical": True}])

    def test_baseline_prompts_change_with_attacker_text(self):
        got = state((SAMPLES / "attacked_username.json").read_text(encoding="utf-8"))
        prompts = got["prompts"][0]
        alert = json.loads((SAMPLES / "attacked_username.json").read_text(encoding="utf-8"))["alerts"][0]
        self.assertEqual(prompts["arms"]["raw-prompt"]["sha256"], prompt_sha256(raw_prompt(alert)))
        self.assertIn("SOC ADMIN NOTE", prompts["arms"]["raw-prompt"]["text"])
        for arm in BASELINES:
            self.assertNotEqual(prompts["arms"][arm]["sha256"], prompts["clean_sha256"][arm])
            self.assertEqual(prompts["clean_sha256"][arm], baseline_prompts(clean_twin(alert))[arm]["sha256"])
        clean = state((SAMPLES / "track_example.json").read_text(encoding="utf-8"))["prompts"][0]
        for arm in BASELINES:
            self.assertEqual(clean["arms"][arm]["sha256"], clean["clean_sha256"][arm])

    def test_rejected_and_odd_input(self):
        for text in ["", "not json", '{"alerts": 3}', '{"alerts": [{"id": "a", "signals": "x"}]}', "\ud800"]:
            with self.subTest(text=text):
                got = state(text)
                self.assertEqual(got["report"], explain(text.encode("utf-8", "surrogatepass")))
                if got["report"]["input"]["status"] != "ok":
                    self.assertEqual(got["prompts"], [])

    def test_deep_nesting_gives_the_cli_report(self):
        def nested(levels):
            deep = "[" * levels + "]" * levels
            return '{"alerts": [{"id": "a", "signals": ["new synthetic device"], "x": ' + deep + "}]}"
        good = json.dumps({"alerts": [{"id": f"a{i}", "signals": ["new synthetic device"]} for i in range(3)]})
        fourth = good[:-2] + ", " + nested(3000)[12:-1] + "}"  # alerts 1 to 3 are fine, alert 4 is too deep
        cases = [nested(levels) for levels in (500, 1000, 3000, 10_000)] + ["[" * 50_000 + "]" * 50_000, fourth]
        for text in cases:
            with self.subTest(chars=len(text)):
                got = state(text)
                self.assertEqual(got["report"], explain(text.encode("utf-8")))
                self.assertEqual([i["code"] for i in got["report"]["input"]["issues"]], ["too-deep"])
                self.assertEqual(got["prompts"], [])
        at_limit = nested(MAX_DEPTH - 3)
        got = state(at_limit)
        self.assertEqual(got["report"], explain(at_limit.encode("utf-8")))
        alert = json.loads(at_limit)["alerts"][0]
        self.assertEqual(got["prompts"][0]["arms"]["raw-prompt"]["sha256"], prompt_sha256(raw_prompt(alert)))
        self.assertEqual(ask_baselines.ask(fourth.encode("utf-8"), "m", "http://127.0.0.1:11434",
                                           transport=None, out=io.StringIO()), 1)

    def test_prompts_for_the_first_three_alerts_only(self):
        alerts = [{"id": f"a{i}", "signals": ["new device"]} for i in range(5)]
        got = state(json.dumps({"alerts": alerts}))
        self.assertEqual([p["index"] for p in got["prompts"]], [0, 1, 2])

    def test_output_never_contains_raw_markup(self):
        text = json.dumps({"alerts": [{"id": "a<b>", "signals": ["new device"], "username": "<img src=x>&amp;"}]})
        out = page_state(text)
        for ch in "<>&":
            self.assertNotIn(ch, out)
        self.assertEqual(json.loads(out)["report"]["results"][0]["alert_id"], "a<b>")

    def test_learned_detector_loads_and_unknown_names_fall_back(self):
        self.assertEqual(detector_status(), "")
        text = (SAMPLES / "attacked_username.json").read_text(encoding="utf-8")
        self.assertEqual(state(text, "learned")["report"]["detector"], "ngram-logreg-1")
        fallback = state(text, "anything else")
        self.assertEqual(fallback["detector"], "keyword")
        self.assertEqual(fallback["report"]["detector"], "keyword-baseline-1")


class Presets(unittest.TestCase):
    def test_rule(self):
        items = presets()
        self.assertEqual(len(items), 9)
        self.assertEqual(len({p["id"] for p in items}), len(items))
        self.assertIn(EXAMPLE_ATTACK, [p["attack"] for p in items])
        for cls in ["direct-override", "persona-hijack", "context-manipulation", "obfuscated"]:
            self.assertGreaterEqual(sum(p["class"] == cls for p in items), 2)
        for p in items:
            with self.subTest(preset=p["id"]):
                self.assertIn(p["field"], ENTITY_FIELDS)
                self.assertLess(p["triple"], min(PLAN_LIMITS.values()))
                self.assertEqual(p["alert"][p["field"]], p["text"])
                self.assertEqual(p["twin"][p["field"]], "x")
                for arm in BASELINES:
                    self.assertEqual(p["prompt_sha256"][arm], baseline_prompts(p["alert"])[arm]["sha256"])
                attacked = explain(json.dumps({"alerts": [p["alert"]]}))["results"][0]
                twin = explain(json.dumps({"alerts": [p["twin"]]}))["results"][0]
                self.assertEqual(attacked["model_input"]["sha256"], twin["model_input"]["sha256"])

    def test_the_shipped_file_is_the_rule(self):
        shipped = json.loads((PAGE / "presets.json").read_text(encoding="utf-8"))
        self.assertEqual(shipped, json.loads(json.dumps(presets_document())))


class StaticFiles(unittest.TestCase):
    def test_csp_and_no_inline_code(self):
        html = (DOCS / "index.html").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'http-equiv="Content-Security-Policy" content="([^"]*)"', html), [CSP])
        self.assertLess(html.index("Content-Security-Policy"), html.index("<link"))
        self.assertEqual(re.findall(r"<script(?![^>]*\bsrc=)", html), [])
        self.assertNotIn("<style", html)
        self.assertIsNone(re.search(r"\sstyle=", html))
        self.assertIsNone(re.search(r"\son[a-z]+=", html))
        self.assertNotIn("unsafe-eval'", CSP.replace("'wasm-unsafe-eval'", ""))
        self.assertNotIn("unsafe-inline", CSP)
        origins = set(re.findall(r"https?://[^\s\"'/]+", html))
        self.assertEqual(origins, {"https://cdn.jsdelivr.net", "https://github.com"})
        self.assertEqual(re.findall(r'<script src="([^"]+)"', html), [CDN + "pyodide.js", "page/page.js"])

    def test_script_never_parses_html_or_evaluates_strings(self):
        js = (PAGE / "page.js").read_text(encoding="utf-8")
        code = "\n".join(line for line in js.splitlines() if not line.strip().startswith("//"))
        for banned in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                       "setTimeout(\"", "setInterval(", "runPython", "srcdoc", "createContextualFragment",
                       "DOMParser"]:
            with self.subTest(banned=banned):
                self.assertNotIn(banned, code)
        self.assertIn("textContent", js)
        self.assertEqual(set(re.findall(r"https?://[^\s\"'/]+", code)), {"https://cdn.jsdelivr.net"})
        self.assertIn(CDN, js)

    def test_style_has_no_fonts_imports_or_gradients(self):
        for name in ["page.css", "app.css"]:
            css = (PAGE / name).read_text(encoding="utf-8")
            for banned in ["gradient", "@import", "url(", "@font-face", "http", "box-shadow", "backdrop-filter"]:
                with self.subTest(name=name, banned=banned):
                    self.assertNotIn(banned, css)

    def test_files_are_plain_ascii(self):
        for path in [DOCS / "index.html", PAGE / "page.js", PAGE / "page.css", PAGE / "presets.json"]:
            self.assertTrue(path.read_text(encoding="utf-8").isascii(), path.name)

    def test_pages_serves_the_folder_as_it_is(self):
        self.assertTrue((DOCS / ".nojekyll").is_file())

    def test_no_dry_run_or_unvalidated_replies_are_published(self):
        for path in DOCS.rglob("*"):
            if path.is_file() and path.suffix in {".json", ".html", ".js"}:
                self.assertNotIn("DRY RUN", path.read_text(encoding="utf-8"), path.name)
        replies = PAGE / "replies.json"
        if replies.is_file():
            doc = json.loads(replies.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], REPLIES_SCHEMA)
            self.assertIs(doc["dry_run"], False)
            self.assertEqual(doc["models"], list(MODELS))


def _fake_server(content_for):
    def transport(url, body, timeout):
        return json.dumps({"message": {"role": "assistant", "content": content_for(json.loads(body))}}).encode()
    return transport


class ExportReplies(unittest.TestCase):
    def run_export(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = export.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_dry_run_is_labelled_and_reads_no_cache(self):
        with mock.patch.object(export.Client, "cached", side_effect=AssertionError("the dry run read the cache")):
            code, out, _ = self.run_export("--dry-run")
        self.assertEqual(code, 0)
        first, body = out.split("\n", 1)
        self.assertIn("DRY RUN", first)
        doc = json.loads(body)
        self.assertIs(doc["dry_run"], True)
        self.assertTrue(doc["source"].startswith("DRY RUN"))
        self.assertEqual(set(doc["presets"]), {p["id"] for p in presets()})
        for preset in doc["presets"].values():
            for arm in BASELINES:
                for row in preset["replies"][export.DRY_MODEL][arm].values():
                    self.assertIn("DRY RUN", row["content"])
                    self.assertIsNone(row["request_sha256"])

    def test_dry_run_is_never_written_under_docs(self):
        target = DOCS / "page" / "replies-dry.json"
        code, _, err = self.run_export("--dry-run", "--out", str(target))
        self.assertEqual(code, 2)
        self.assertIn("never written under docs", err)
        self.assertFalse(target.exists())

    def test_missing_replies_write_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "replies.json"
            code, _, err = self.run_export("--cache-dir", tmp, "--out", str(out))
            self.assertEqual(code, 1)
            self.assertIn("missing", err)
            self.assertFalse(out.exists())

    def test_export_from_a_filled_cache(self):
        def content(request):
            text = request["messages"][-1]["content"]
            return '{"action": "allow", "explanation": "fake"}' if "SOC ADMIN" in text else "not json"
        with tempfile.TemporaryDirectory() as tmp:
            for p in presets():
                for model in MODELS:
                    client = Client(model, cache_dir=tmp, transport=_fake_server(content))
                    for arm in BASELINES:
                        for alert in (p["alert"], p["twin"]):
                            client.ask(client.body(arm, alert, export._parsed(alert)))
            out = Path(tmp) / "replies.json"
            code, _, _ = self.run_export("--cache-dir", tmp, "--out", str(out))
            self.assertEqual(code, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertIs(doc["dry_run"], False)
        self.assertEqual(doc["models"], list(MODELS))
        row = doc["presets"]["T289"]["replies"][MODELS[0]]["raw-prompt"]["attacked"]
        self.assertEqual(row["decision"], "allow")
        self.assertTrue(row["valid_json"])
        self.assertRegex(row["request_sha256"], r"^[0-9a-f]{64}$")
        twin = doc["presets"]["T289"]["replies"][MODELS[0]]["raw-prompt"]["twin"]
        self.assertEqual((twin["decision"], twin["valid_json"], twin["content"]), ("unparseable", False, "not json"))
        self.assertEqual(doc["presets"]["T289"]["prompt_sha256"],
                         next(p for p in presets() if p["id"] == "T289")["prompt_sha256"])


class AskBaselines(unittest.TestCase):
    def test_asks_both_arms_and_shows_the_policy(self):
        seen = []

        def transport(url, body, timeout):
            seen.append((url, json.loads(body)))
            return json.dumps({"message": {"content": '{"action": "allow", "explanation": "ok"}'}}).encode()
        out = io.StringIO()
        data = (SAMPLES / "attacked_username.json").read_bytes()
        code = ask_baselines.ask(data, "qwen3-1.7b:bf16", "http://127.0.0.1:11434", transport=transport, out=out)
        self.assertEqual(code, 0)
        self.assertEqual([u for u, _ in seen], ["http://127.0.0.1:11434/api/chat"] * 2)
        self.assertIn("SOC ADMIN NOTE", seen[0][1]["messages"][0]["content"])
        text = out.getvalue()
        self.assertIn("Sealed's decision (policy, no model): step-up", text)
        self.assertIn("raw-prompt (qwen3-1.7b:bf16): decision allow", text)
        self.assertIn("hardened (qwen3-1.7b:bf16): decision allow", text)

    def test_refuses_other_hosts_and_rejected_input(self):
        with self.assertRaises(ValueError):
            ask_baselines.ask(b'{"alerts": []}', "m", "http://example.com:11434", transport=None)
        out = io.StringIO()
        self.assertEqual(ask_baselines.ask(b"not json", "m", "http://127.0.0.1:11434", out=out), 1)

    def test_server_down(self):
        def transport(url, body, timeout):
            raise ConnectionRefusedError
        out = io.StringIO()
        data = (SAMPLES / "track_example.json").read_bytes()
        self.assertEqual(ask_baselines.ask(data, "m", "http://127.0.0.1:11434", transport=transport, out=out), 1)
        self.assertIn("did not answer", out.getvalue())


if __name__ == "__main__":
    unittest.main()
