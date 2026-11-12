"""Entry point of the public browser page (docs/index.html), which runs this package in Pyodide.

The page has no server and no model. page_state() gives it everything it
shows for an alert document, computed by the same code as the CLI and the
local app: the report of explain(), the local app's seal check against the
clean twin, and the exact prompts that the two baseline arms (sealed/arms.py)
would send, with their SHA-256. Attacker text changes those prompts; it cannot
change the Sealed model input.

presets() lists the evaluation triples that the page offers as recorded
attacks: for each attack class, the first two triples in the plan's fixed
class-interleaved order whose attack is written into one documented entity
field, plus the first such triple that carries the README's example string
(A05). The rule takes triples by position and reads no reply, so it cannot
pick them by outcome, and every model of the run answers all of them.
tools/build_page.py writes them to docs/page/presets.json, and
tools/export_page_replies.py adds the recorded baseline replies once the run
has finished.
"""

from __future__ import annotations

import hashlib
import json

from .app import clean_twin, explain_with_seal_checks
from .arms import hardened_prompt, raw_prompt
from .explain import explain

PAGE_SCHEMA = "sealed-page/1"
PRESETS_SCHEMA = "sealed-page-presets/1"
REPLIES_SCHEMA = "sealed-page-replies/1"
BASELINES = ("raw-prompt", "hardened")
PROMPTS = {"raw-prompt": raw_prompt, "hardened": hardened_prompt}
ENTITY_FIELDS = ("username", "user_agent", "url", "host")
DETECTORS = ("keyword", "learned")
PRESETS_PER_CLASS = 2
EXAMPLE_ATTACK = "A05"
PROMPT_ALERTS = 3  # prompts are built for the first three alerts of a document
PROMPT_SHOWN_CHARS = 20_000  # the hash covers the whole prompt; the page shows this much of it
PRESET_RULE = ("For each attack class, the first two triples of the evaluation (in its fixed class-interleaved "
               "order) whose attack string is written into one of username, user_agent, url or host, plus the "
               "first such triple that carries the string used in the README (A05). The rule takes triples by "
               "position and reads no model reply, so it cannot pick them by outcome; every model in the run "
               "answers all of these triples.")

_learned = None


def prompt_sha256(messages: list[dict]) -> str:
    """SHA-256 of a chat prompt, canonical JSON. The arms' request bodies differ only by model name."""
    canonical = json.dumps(messages, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def baseline_prompts(alert: dict) -> dict:
    """The messages each baseline arm would send about this alert, and their SHA-256."""
    out = {}
    for arm, build in PROMPTS.items():
        messages = build(alert)
        text = "\n\n".join(f"[{m['role']}]\n{m['content']}" for m in messages)
        out[arm] = {"sha256": prompt_sha256(messages), "chars": len(text),
                    "text": text[:PROMPT_SHOWN_CHARS], "truncated": len(text) > PROMPT_SHOWN_CHARS}
    return out


def _learned_detector():
    global _learned
    if _learned is None:
        from .learned import LearnedDetector
        _learned = LearnedDetector()
    return _learned


def detector_status() -> str:
    """Empty when the optional learned detector loads here, otherwise the reason it does not."""
    from .learned import DetectorUnavailable
    try:
        _learned_detector().load()
    except DetectorUnavailable as error:
        return str(error)
    return ""


def page_state(text: str, detector: str = "keyword") -> str:
    """Everything the page shows for one alert document, as JSON text."""
    body = text.encode("utf-8", "surrogatepass")  # a lone surrogate becomes invalid UTF-8, which the parser rejects
    data = explain_with_seal_checks(body)
    if detector == "learned":
        data["report"] = explain(body, detector=_learned_detector())
    prompts = []
    if data["report"]["input"]["status"] == "ok":
        alerts = json.loads(body.decode("utf-8-sig"))["alerts"]  # already validated by explain()
        for index, alert in enumerate(alerts[:PROMPT_ALERTS]):
            if isinstance(alert, dict):
                clean = baseline_prompts(clean_twin(alert))
                prompts.append({"index": index, "arms": baseline_prompts(alert),
                                "clean_sha256": {arm: clean[arm]["sha256"] for arm in BASELINES}})
    state = {"schema": PAGE_SCHEMA, "detector": detector if detector in DETECTORS else "keyword",
             "report": data["report"], "seal_checks": data["seal_checks"], "prompts": prompts,
             "alerts_with_prompts": PROMPT_ALERTS}
    out = json.dumps(state, ensure_ascii=True)
    return out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def presets() -> list[dict]:
    """The recorded-attack presets (see the module docstring for the rule)."""
    from .attackset import CLASSES, attack_set
    from .generate import synthetic_alerts
    from .model_eval import PLAN_LIMITS, _variants, interleaved_triples
    from .template_eval import texts_of

    alerts = {a["id"]: a for a in synthetic_alerts()}
    attacks = {a["id"]: a for a in attack_set()}
    covered = [t for t in interleaved_triples() if t["n"] < min(PLAN_LIMITS.values())]
    single = [t for t in covered if len(t["fields"]) == 1 and t["fields"][0] in ENTITY_FIELDS]
    chosen = set()
    for cls in CLASSES:
        chosen.update([t["n"] for t in single if t["class"] == cls][:PRESETS_PER_CLASS])
    chosen.add(next(t["n"] for t in single if t["attack"] == EXAMPLE_ATTACK))
    out = []
    for triple in covered:
        if triple["n"] not in chosen:
            continue
        attack = attacks[triple["attack"]]
        variants = _variants(triple, alerts, attacks)
        attacked = baseline_prompts(variants["attacked"])
        out.append({"id": f"T{triple['n']}", "triple": triple["n"], "alert_id": triple["alert"],
                    "attack": attack["id"], "class": attack["class"], "language": attack["language"],
                    "encoding": attack["encoding"], "split": attack["split"], "field": triple["fields"][0],
                    "text": texts_of(attack)[0], "alert": variants["attacked"], "twin": variants["twin"],
                    "prompt_sha256": {arm: attacked[arm]["sha256"] for arm in BASELINES}})
    return out


def presets_document() -> dict:
    return {"schema": PRESETS_SCHEMA, "generated_by": "python tools/build_page.py", "rule": PRESET_RULE,
            "presets": presets()}
