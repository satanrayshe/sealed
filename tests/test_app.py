import http.client
import json
import re
import unittest

from sealed.app import CSP, SAMPLES, WEB, clean_twin, handle, start_in_thread
from sealed.contract import MAX_INPUT_BYTES
from sealed.explain import explain

PORT = 8765
HOST = {"Host": f"127.0.0.1:{PORT}"}
JSON = {**HOST, "Content-Type": "application/json"}


def post(body, headers=JSON):
    return handle("POST", "/api/explain", headers, body if isinstance(body, bytes) else body.encode(), PORT)


class Handler(unittest.TestCase):
    def test_static_files_carry_the_security_headers(self):
        for path, kind in [("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")]:
            with self.subTest(path=path):
                response = handle("GET", path, HOST, None, PORT)
                self.assertEqual(response.status, 200)
                self.assertTrue(response.content_type.startswith(kind))
                self.assertEqual(response.headers["Content-Security-Policy"], CSP)
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("script-src 'self'", CSP)
        self.assertNotIn("unsafe", CSP)

    def test_samples(self):
        data = json.loads(handle("GET", "/api/samples", HOST, None, PORT).body)
        self.assertEqual(set(data), {"track_example", "attacked_username", "edge_cases"})
        self.assertEqual(data["track_example"], (SAMPLES / "track_example.json").read_text(encoding="utf-8"))

    def test_only_local_hosts_are_answered(self):
        for headers in [{}, {"Host": "evil.example"}, {"Host": f"evil.example:{PORT}"}, {"Host": "127.0.0.1:9999"}]:
            with self.subTest(headers=headers):
                self.assertEqual(handle("GET", "/", headers, None, PORT).status, 403)
        self.assertEqual(handle("GET", "/", {"Host": f"localhost:{PORT}"}, None, PORT).status, 200)

    def test_unknown_paths_and_methods(self):
        self.assertEqual(handle("GET", "/etc/passwd", HOST, None, PORT).status, 404)
        self.assertEqual(handle("GET", "/../sealed/app.py", HOST, None, PORT).status, 404)
        self.assertEqual(handle("PUT", "/api/explain", JSON, b"{}", PORT).status, 405)
        self.assertEqual(handle("POST", "/", JSON, b"{}", PORT).status, 405)

    def test_cross_site_and_wrong_type_posts_are_refused(self):
        body = (SAMPLES / "track_example.json").read_bytes()
        self.assertEqual(post(body, {**JSON, "Origin": "https://evil.example"}).status, 403)
        self.assertEqual(post(body, {**HOST, "Content-Type": "text/plain"}).status, 415)
        self.assertEqual(post(body, {**JSON, "Origin": f"http://127.0.0.1:{PORT}"}).status, 200)

    def test_explain_returns_the_report_and_a_seal_check(self):
        body = (SAMPLES / "attacked_username.json").read_bytes()
        data = json.loads(post(body).body)
        self.assertEqual(data["report"], explain(body))
        (check,) = data["seal_checks"]
        self.assertTrue(check["identical"])
        self.assertEqual(check["clean_twin_sha256"], data["report"]["results"][0]["model_input"]["sha256"])

    def test_seal_checks_only_for_explained_alerts(self):
        data = json.loads(post((SAMPLES / "edge_cases.json").read_bytes()).body)
        explained = [r["index"] for r in data["report"]["results"] if r["status"] == "explained"]
        self.assertEqual([c["index"] for c in data["seal_checks"]], explained)
        self.assertTrue(all(c["identical"] for c in data["seal_checks"]))

    def test_rejected_input_has_no_seal_checks(self):
        data = json.loads(post("{not json").body)
        self.assertEqual(data["report"]["input"]["status"], "rejected")
        self.assertEqual(data["seal_checks"], [])

    def test_response_never_contains_raw_markup(self):
        hostile = {"alerts": [{"id": "<b>id</b>", "signals": ["new device"],
                               "username": "<script>alert(1)</script>&<img src=x onerror=alert(2)>"}]}
        body = post(json.dumps(hostile)).body
        for character in (b"<", b">", b"&"):
            self.assertNotIn(character, body)
        self.assertIn("<script>", json.loads(body)["report"]["results"][0]["quarantine"][0]["text"])

    def test_clean_twin_keeps_only_trusted_fields(self):
        alert = {"id": "a", "severity": "high", "signals": ["x"], "action": "monitor", "username": "u", "note": "n"}
        self.assertEqual(clean_twin(alert), {"id": "a", "severity": "high", "signals": ["x"], "action": "monitor"})


class StaticFilesFollowTheRules(unittest.TestCase):
    def test_page_has_no_inline_code_and_no_external_origin(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"<script(?![^>]*\bsrc=)", html), [])
        self.assertNotIn("<style", html)
        self.assertIsNone(re.search(r"\sstyle=", html))
        self.assertIsNone(re.search(r"\son[a-z]+=", html))
        self.assertNotIn("http", html)

    def test_script_never_parses_html_or_evaluates_strings(self):
        js = (WEB / "app.js").read_text(encoding="utf-8")
        code = "\n".join(line for line in js.splitlines() if not line.strip().startswith("//"))
        for banned in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                       "setTimeout(\"", "setInterval(", "http"]:
            with self.subTest(banned=banned):
                self.assertNotIn(banned, code)
        self.assertIn("textContent", js)

    def test_style_has_no_fonts_imports_or_gradients(self):
        css = (WEB / "app.css").read_text(encoding="utf-8")
        for banned in ["gradient", "@import", "url(", "@font-face", "http", "box-shadow"]:
            with self.subTest(banned=banned):
                self.assertNotIn(banned, css)
        self.assertIn(":focus-visible", css)
        self.assertIn("max-width: 860px", css)

    def test_web_files_are_plain_ascii(self):
        for name in ["index.html", "app.js", "app.css"]:
            self.assertTrue((WEB / name).read_text(encoding="utf-8").isascii(), name)


class RealSocket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.thread = start_in_thread(0)
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, headers, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response, data

    def test_bound_to_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_page_over_http(self):
        response, data = self.request("GET", "/", {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Security-Policy"), CSP)
        self.assertIn(b"<textarea", data)

    def test_oversized_body_is_refused_unread(self):
        response, _ = self.request("POST", "/api/explain", {
            "Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json",
            "Content-Length": str(MAX_INPUT_BYTES + 1)})
        self.assertEqual(response.status, 413)

    def test_missing_length_is_refused(self):
        response, _ = self.request("POST", "/api/explain", {"Host": f"127.0.0.1:{self.port}",
                                                            "Content-Type": "application/json"})
        self.assertEqual(response.status, 411)

    def test_foreign_host_over_http(self):
        response, _ = self.request("GET", "/", {"Host": "rebind.example"})
        self.assertEqual(response.status, 403)

    def test_explain_over_http(self):
        body = (SAMPLES / "attacked_username.json").read_bytes()
        response, data = self.request("POST", "/api/explain", {
            "Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json",
            "Content-Length": str(len(body))}, body)
        self.assertEqual(response.status, 200)
        self.assertTrue(json.loads(data)["seal_checks"][0]["identical"])


if __name__ == "__main__":
    unittest.main()
