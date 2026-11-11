"""Real reports must match the documented output schema, and the README must show real output.

The validator below covers only the JSON Schema keywords our schema files use
(type, const, enum, required, properties, additionalProperties, items,
oneOf, $ref, pattern, maxItems, minLength, maxLength), so the check needs no
third-party package.
"""

import json
import re
import unittest
from pathlib import Path

from sealed.cli import SAMPLES
from sealed.explain import explain

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_SCHEMA = json.loads((ROOT / "schema" / "output.schema.json").read_text(encoding="utf-8"))
INPUT_SCHEMA = json.loads((ROOT / "schema" / "input.schema.json").read_text(encoding="utf-8"))


def _is_type(value, name):
    if name == "integer":
        return type(value) is int
    if name == "number":
        return type(value) in (int, float)
    if name == "boolean":
        return type(value) is bool
    return isinstance(value, {"string": str, "array": list, "object": dict, "null": type(None)}[name])


def _same(a, b):
    return type(a) is type(b) and a == b


def errors(value, schema, root, path="$"):
    if "$ref" in schema:
        return errors(value, root["$defs"][schema["$ref"].split("/")[-1]], root, path)
    if "oneOf" in schema:
        passing = sum(not errors(value, option, root, path) for option in schema["oneOf"])
        return [] if passing == 1 else [f"{path}: matches {passing} options of oneOf"]
    found = []
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, n) for n in names):
            return [f"{path}: expected {names}"]
    if "const" in schema and not _same(value, schema["const"]):
        found.append(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and not any(_same(value, e) for e in schema["enum"]):
        found.append(f"{path}: {value!r} not in enum")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            found.append(f"{path}: does not match {schema['pattern']}")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            found.append(f"{path}: bad length")
    if isinstance(value, list):
        if len(value) > schema.get("maxItems", len(value)):
            found.append(f"{path}: too many items")
        if "items" in schema:
            for i, item in enumerate(value):
                found += errors(item, schema["items"], root, f"{path}[{i}]")
    if isinstance(value, dict):
        found += [f"{path}: missing {key}" for key in schema.get("required", []) if key not in value]
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                found += errors(item, properties[key], root, f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                found.append(f"{path}: unexpected key {key}")
    return found


def reports():
    inputs = {name: (SAMPLES / name).read_bytes() for name in
              ["track_example.json", "attacked_username.json", "edge_cases.json"]}
    inputs["synthetic"] = (ROOT / "data" / "synthetic_alerts.json").read_bytes()
    inputs["rejected"] = b"{oops"
    inputs["empty"] = b'{"alerts": []}'
    return {name: explain(data) for name, data in inputs.items()}


class OutputSchema(unittest.TestCase):
    def test_the_validator_is_not_vacuous(self):
        report = explain((SAMPLES / "track_example.json").read_bytes())
        broken = json.loads(json.dumps(report))
        broken["results"][0]["recommendation"]["executed"] = True
        broken["results"][0]["surprise"] = 1
        broken["executed_controls"] = ["lock account"]
        del broken["results"][0]["model_input"]["sha256"]
        self.assertEqual(errors(broken, OUTPUT_SCHEMA, OUTPUT_SCHEMA),
                         ["$.results[0]: matches 0 options of oneOf", "$.executed_controls: too many items"])
        inner = errors(broken["results"][0], {"$ref": "#/$defs/explained"}, OUTPUT_SCHEMA)
        self.assertEqual(len(inner), 3)

    def test_real_reports_match_the_schema(self):
        for name, report in reports().items():
            with self.subTest(name=name):
                self.assertEqual(errors(report, OUTPUT_SCHEMA, OUTPUT_SCHEMA), [])

    def test_sample_inputs_match_the_input_schema(self):
        for name in ["track_example.json", "attacked_username.json"]:
            data = json.loads((SAMPLES / name).read_text(encoding="utf-8"))
            self.assertEqual(errors(data, INPUT_SCHEMA, INPUT_SCHEMA), [])
        data = json.loads((ROOT / "data" / "synthetic_alerts.json").read_text(encoding="utf-8"))
        self.assertEqual(errors(data, INPUT_SCHEMA, INPUT_SCHEMA), [])


class Readme(unittest.TestCase):
    def test_readme_shows_the_real_output_of_the_track_example(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        block = readme.split("<!-- track-example-output -->\n```json\n", 1)[1].split("\n```", 1)[0]
        actual = json.dumps(explain((SAMPLES / "track_example.json").read_bytes()), ensure_ascii=True, indent=2)
        self.assertEqual(block, actual)

    def test_readme_first_screen_names_the_principle(self):
        first_screen = (ROOT / "README.md").read_text(encoding="utf-8")[:1500]
        self.assertIn("dual-LLM / CaMeL principle (Willison 2023", first_screen)
        self.assertIn("arXiv 2503.18813", first_screen)


if __name__ == "__main__":
    unittest.main()
