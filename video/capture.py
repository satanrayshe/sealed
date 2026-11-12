"""Capture the frames of the two-minute video. What each frame shows: video/SHOTS.md.

    python video/capture.py --mode dry-run     before the model run ends: template-arm numbers, no reply cache
    python video/capture.py --mode final       after `python -m sealed evaluate --arm models` has written
                                               results/model_arms.json

Frames and a manifest go to video/work/ (or --work); video/render.py assembles them. The manifest
records which result files the frames show, with their SHA-256, so that a final cut can refuse frames
older than those files. Every picture stays above the caption band at the bottom of the frame: the
app's screenshots are scaled down into the area above it.

Needs Python Playwright with its Chromium, run headless with the GPU off, and nothing else beyond
this repository. The local two-pane app (sealed/app.py) runs inside this process on a free loopback
port and is driven through its own page. No model is called. The app has no model arms, so the
raw-prompt pane is built beside it: in final mode from a reply recorded in the evaluation run, read
from the reply cache without writing to it and labelled as recorded; in dry-run mode from the exact
prompt that arm sends, labelled DRY RUN. The terminal frames show the real output of commands run
here. Every number on screen is read from a result file or computed by the package at capture time.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from timeline import CAPTION_BAND, FPS, HEIGHT, REPO, WIDTH, WORK, parse_narration, schedule  # noqa: E402

sys.path.insert(0, str(REPO))
from sealed.app import start_in_thread  # noqa: E402
from sealed.arms import raw_prompt  # noqa: E402
from sealed.attackset import attack_set  # noqa: E402
from sealed.contract import Alert, parse_document  # noqa: E402
from sealed.detect import KeywordDetector  # noqa: E402
from sealed.evaluate import parse_decision  # noqa: E402
from sealed.explain import explain  # noqa: E402
from sealed.generate import synthetic_alerts  # noqa: E402
from sealed.model_eval import DEFAULT_CACHE, MODELS, PLAN_LIMITS, Client, explanation_text, interleaved_triples  # noqa: E402
from sealed.quarantine import INVISIBLE  # noqa: E402
from sealed.template_eval import PLACEHOLDER, ascii_preview, place, texts_of  # noqa: E402
from sealed.vocabulary import ACTIONS  # noqa: E402

RESULTS = REPO / "results"
SAMPLES = REPO / "sealed" / "samples"
APP_VIEW = {"width": 1440, "height": 810}  # CSS pixels; at 4/3 device pixels per CSS pixel this is 1920x1080
APP_DPR = 4 / 3
STAGE_H = HEIGHT - CAPTION_BAND  # every picture stays above the caption band
APP_MARGIN = 15  # around the app's window once it is scaled into the area above the band
APP_FRAME_H = STAGE_H - 2 * APP_MARGIN
APP_FRAME_W = round(APP_FRAME_H * WIDTH / HEIGHT)
CLASS_ORDER = ("persona-hijack", "direct-override", "context-manipulation", "obfuscated")
MODEL_ORDER = ("qwen3-4b-instruct-2507:nf4", "granite-4.0-micro:nf4", "qwen3-1.7b:bf16")
MODEL_NAMES = {"qwen3-1.7b:bf16": "Qwen3-1.7B (bf16)",
               "qwen3-4b-instruct-2507:nf4": "Qwen3-4B-Instruct-2507 (4-bit)",
               "granite-4.0-micro:nf4": "granite-4.0-micro (4-bit)"}
RANK = {action: i for i, action in enumerate(ACTIONS)}
ENTITY_FIELDS = ("username", "user_agent", "url", "host")


# ---- data ---------------------------------------------------------------------------------------------------------

def esc(text: object) -> str:
    """HTML-escaped text with invisible characters shown as escapes."""
    shown = INVISIBLE.sub(lambda m: f"\\u{ord(m.group()):04x}", str(text))
    return html.escape(shown, quote=True)


def parsed(alert: dict) -> Alert:
    item = parse_document(json.dumps({"alerts": [alert]})).items[0]
    if not isinstance(item, Alert):
        raise SystemExit("a synthetic alert was rejected by the parser; the data files are broken")
    return item


def report(alert: dict) -> dict:
    return explain(json.dumps({"alerts": [alert]}))["results"][0]


def pct(p: dict | None) -> str:
    return "-" if not p or not p.get("n") else f"{100 * p['rate']:.1f}%"


def kn(p: dict | None) -> str:
    return "-" if not p or not p.get("n") else f"{p['k']:,} of {p['n']:,}"


def interval(low_high: list | None) -> str:
    return "" if not low_high else f"{100 * low_high[0]:.1f} to {100 * low_high[1]:.1f}%"


def short_hash(h: str) -> str:
    return f"{h[:8]}...{h[-4:]}"


def _refuse(*_args):
    raise RuntimeError("capture.py never sends a request to a model")


def eligible(triple: dict, attack: dict) -> bool:
    """Jaw-drop candidates: one plain, readable string written into the username."""
    text = attack.get("text")
    return triple["fields"] == ["username"] and isinstance(text, str) and attack["encoding"] == "plain" \
        and len(text) <= 120


def base_key(triple: dict, attack: dict, attacked_report: dict) -> tuple:
    flagged = bool(attacked_report["injection_evidence"]["flagged_fields"])
    return (CLASS_ORDER.index(triple["class"]), not flagged, attack["language"] != "en",
            not triple["alert"].startswith("syn-cs-"), len(attack["text"]), triple["n"])


def choose_jaw(mode: str, models: list[str], cache_dir: Path, triple_n: int | None) -> dict:
    """The (alert, attack string) pair of the opening shot, chosen by a fixed rule (video/SHOTS.md)."""
    alerts = {a["id"]: a for a in synthetic_alerts()}
    attacks = {a["id"]: a for a in attack_set()}
    triples = interleaved_triples()
    best = None
    for model in (models if mode == "final" else [None]):
        limit = PLAN_LIMITS[model] if model else min(PLAN_LIMITS.values())
        client = Client(model, cache_dir=cache_dir, transport=_refuse, offline=True) if model else None
        for triple in triples[:limit]:
            attack = attacks[triple["attack"]]
            if triple_n is not None and triple["n"] != triple_n:
                continue
            if not eligible(triple, attack):
                continue
            clean = alerts[triple["alert"]]
            twin = place(clean, triple["fields"], [PLACEHOLDER])
            attacked = place(clean, triple["fields"], texts_of(attack))
            clean_r, attacked_r = report(clean), report(attacked)
            if attacked_r["recommendation"]["action"] != clean_r["recommendation"]["action"]:
                continue  # the narration says "same action"
            pick = {"triple": triple, "attack": attack, "clean": clean, "attacked": attacked,
                    "clean_report": clean_r, "attacked_report": attacked_r, "model": model}
            key = base_key(triple, attack, attacked_r)
            if client is not None:
                rec = {(arm, name): client.cached(client.body(arm, alert, parsed(alert)))
                       for arm in ("raw-prompt", "hardened")
                       for name, alert in (("clean", clean), ("twin", twin), ("attacked", attacked))}
                if any(rec[("raw-prompt", name)] is None for name in ("clean", "twin", "attacked")):
                    continue
                d = {name: parse_decision(rec[("raw-prompt", name)]["content"])
                     for name in ("clean", "twin", "attacked")}
                if not (d["clean"] == d["twin"] and d["clean"] in RANK and d["attacked"] in RANK
                        and RANK[d["attacked"]] < RANK[d["clean"]]):
                    continue
                agrees = d["clean"] == clean_r["recommendation"]["action"]
                pick.update(records=rec, decisions=d)
                key = (not agrees, d["attacked"] != "allow", MODEL_ORDER.index(model)) + key
            if best is None or key < best[0]:
                best = (key, pick)
    if best is None:
        if mode == "final":
            raise SystemExit("No recorded reply fits the opening shot: a plain username attack whose raw-prompt "
                             "decision was lower than the same arm's decision on the clean alert and on its twin, "
                             "with Sealed's action unchanged. Pick one with --triple N (and --model), or check that "
                             "the run has finished.")
        raise SystemExit("no triple fits the opening shot's rule")
    return best[1]


def choose_failure(template: dict, base: dict) -> dict:
    """A base64 attack string the keyword detector missed, from the template arm's failure gallery."""
    attacks = {a["id"]: a for a in attack_set()}
    missed = [m for m in template["missed_attacks"] if m["encoding"] == "base64"]
    if not missed:
        raise SystemExit("results/template_arm.json lists no missed base64 string")
    missed.sort(key=lambda m: (m["split"] != "test", m["id"]))
    attack = attacks[missed[0]["id"]]
    field = attack["fields"][0]
    texts = texts_of(attack)
    fields = attack["fields"][:len(texts)] if len(texts) > 1 else [field]
    with_string = report(place(base, fields, texts))
    with_placeholder = report(place(base, fields, [PLACEHOLDER] * len(fields)))
    joined = " ".join(texts)
    try:
        decoded = base64.b64decode(joined.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        decoded = None
    return {"attack": attack, "fields": fields, "text": joined, "decoded": decoded,
            "score": max(KeywordDetector().score(t) for t in texts),
            "threshold": with_string["injection_evidence"]["threshold"],
            "hash": with_string["model_input"]["sha256"], "twin_hash": with_placeholder["model_input"]["sha256"],
            "missed_total": len(template["missed_attacks"]), "alert": base["id"],
            "base64": {split: template[split]["recall_by_encoding"].get("base64") for split in ("test", "dev")}}


def choose_try() -> dict:
    """The string typed into the organiser's example in shot 5: a Hinglish persona hijack from the held-out half."""
    pool = [a for a in attack_set() if a["language"] == "hinglish" and a["class"] == "persona-hijack"
            and a["split"] == "test" and a["encoding"] == "plain" and isinstance(a.get("text"), str)]
    if not pool:
        raise SystemExit("the attack set has no held-out Hinglish persona-hijack string")
    attack = sorted(pool, key=lambda a: a["id"])[0]
    return {"attack": attack, "field": "user_agent"}


def repo_url(given: str | None) -> str | None:
    if given:
        return given.removeprefix("https://").removeprefix("http://").rstrip("/").removesuffix(".git").rstrip("/")
    try:
        out = subprocess.run(["git", "-C", str(REPO), "remote", "get-url", "origin"], capture_output=True,
                             text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    url = out.stdout.strip() if out.returncode == 0 else ""
    m = re.match(r"^(?:https?://|git@)([^/:]+)[/:](.+?)(?:\.git)?/?$", url)
    return f"{m.group(1)}/{m.group(2)}" if m else None


# ---- terminal output ----------------------------------------------------------------------------------------------

def run_command(args: list[str], cwd: Path, env: dict) -> dict:
    shown = " ".join(["python", *args])
    print(f"running: {shown}", flush=True)
    done = subprocess.run([sys.executable, *args], cwd=cwd, env=env, capture_output=True, timeout=1800)
    text = (done.stdout + done.stderr).decode("utf-8", errors="backslashreplace").replace("\r\n", "\n")
    if done.returncode != 0:
        print(text[-3000:], file=sys.stderr, flush=True)
        raise SystemExit(f"`{shown}` exited with {done.returncode} (its output is above); fix that before capturing")
    for private in {str(Path.home()), str(Path.home()).replace("\\", "/"), str(REPO), REPO.as_posix()}:
        if private and (private in text or private in shown):
            raise SystemExit(f"the output of `{shown}` contains a local path; it cannot go on screen as it is")
    return {"command": shown, "exit": done.returncode, "lines": text.rstrip("\n").split("\n")}


def terminal_outputs(mode: str, work: Path, reuse: bool, cache_dir: Path, results_path: Path) -> dict:
    scratch = work / "terminal"
    saved = scratch / "outputs.json"
    replay = ["-m", "sealed", "evaluate", "--arm", "models" if mode == "final" else "template", "--out", "replay"]
    if mode == "final" and cache_dir.resolve() != DEFAULT_CACHE.resolve():
        try:
            replay += ["--cache-dir", Path(os.path.relpath(cache_dir.resolve(), scratch)).as_posix()]
        except ValueError:
            raise SystemExit("--cache-dir must be on the same drive as the capture folder") from None
    if reuse and saved.is_file():
        kept = json.loads(saved.read_text(encoding="utf-8"))
        if kept.get("mode") == mode and kept["outputs"]["replay"]["command"] == " ".join(["python", *replay]):
            print("terminal frames: reusing the command output recorded by the previous capture", flush=True)
            return kept["outputs"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", PYTHONPATH=str(REPO))
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    out = {"demo": run_command(["-m", "sealed", "demo"], REPO, env),
           "replay": run_command(replay, scratch, env),
           "tests": run_command(["-m", "unittest"], REPO, env)}
    if mode == "final":
        replayed = json.loads((scratch / "replay" / "model_arms.json").read_text(encoding="utf-8"))
        stored = json.loads(results_path.read_text(encoding="utf-8"))
        if replayed != stored:
            print(f"WARNING: the replayed model-arm results differ from {results_path.name}", flush=True)
    saved.write_text(json.dumps({"mode": mode, "outputs": out}, ensure_ascii=True, indent=1) + "\n", encoding="utf-8")
    return out


# ---- page helpers inside the app ----------------------------------------------------------------------------------

APP_HELPERS = r"""
() => {
  const W = window;
  const ta = () => document.getElementById('alert-json');
  // Bounding box (viewport coordinates) of the textarea line that holds `needle`, without its indentation.
  W.__lineRect = (needle) => {
    const t = ta(), value = t.value, at = value.indexOf(needle);
    if (at < 0) return null;
    let start = value.lastIndexOf('\n', at) + 1;
    while (value[start] === ' ') start += 1;
    let end = value.indexOf('\n', at);
    if (end < 0) end = value.length;
    const cs = getComputedStyle(t), m = document.createElement('div');
    for (const p of ['fontFamily', 'fontSize', 'fontWeight', 'fontStyle', 'lineHeight', 'letterSpacing', 'wordSpacing',
                     'tabSize', 'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'borderTopWidth',
                     'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth', 'borderStyle', 'boxSizing',
                     'textIndent', 'wordBreak']) m.style[p] = cs[p];
    const r = t.getBoundingClientRect();
    Object.assign(m.style, { whiteSpace: 'pre-wrap', overflowWrap: 'break-word', position: 'absolute',
      visibility: 'hidden', left: (r.left + scrollX) + 'px', top: (r.top + scrollY) + 'px', width: r.width + 'px' });
    const span = document.createElement('span');
    span.textContent = value.slice(start, end);
    m.append(document.createTextNode(value.slice(0, start)), span, document.createTextNode(value.slice(end)));
    document.body.append(m);
    let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    for (const q of span.getClientRects()) {
      x0 = Math.min(x0, q.left); y0 = Math.min(y0, q.top); x1 = Math.max(x1, q.right); y1 = Math.max(y1, q.bottom);
    }
    m.remove();
    return { x: x0, y: y0 - t.scrollTop, w: x1 - x0, h: y1 - y0 };
  };
  W.__unionRect = (selectors) => {
    let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    for (const s of selectors) {
      const e = document.querySelector(s);
      if (!e) continue;
      const q = e.getBoundingClientRect();
      x0 = Math.min(x0, q.left); y0 = Math.min(y0, q.top); x1 = Math.max(x1, q.right); y1 = Math.max(y1, q.bottom);
    }
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  };
  // An outlined box with a label. kind "attacker": dashed and hatched; kind "focus": solid accent.
  W.__mark = (id, r, label, kind, below) => {
    for (const old of [id, id + '-tag']) { const e = document.getElementById(old); if (e) e.remove(); }
    if (!r) return;
    const pad = 4, warn = '#9a3412', accent = '#1f4f8f';
    const box = document.createElement('div');
    box.id = id;
    Object.assign(box.style, { position: 'fixed', pointerEvents: 'none', zIndex: 50, borderRadius: '3px',
      left: (r.x - pad) + 'px', top: (r.y - pad) + 'px', width: (r.w + 2 * pad) + 'px', height: (r.h + 2 * pad) + 'px' });
    if (kind === 'attacker') {
      Object.assign(box.style, { border: '2.5px dashed ' + warn,
        background: 'repeating-linear-gradient(45deg, rgba(154,52,18,0.14) 0 7px, rgba(154,52,18,0) 7px 14px)' });
    } else {
      Object.assign(box.style, { border: '3px solid ' + accent, boxShadow: '0 0 0 4px rgba(31,79,143,0.15)' });
    }
    document.body.append(box);
    if (!label) return;
    const tag = document.createElement('div');
    tag.id = id + '-tag';
    tag.textContent = label;
    Object.assign(tag.style, { position: 'fixed', pointerEvents: 'none', zIndex: 51, font: '600 13px "Segoe UI", system-ui, sans-serif',
      color: '#fff', background: kind === 'attacker' ? warn : accent, padding: '2px 8px', borderRadius: '3px',
      whiteSpace: 'nowrap' });
    document.body.append(tag);
    const right = r.x + r.w + pad, width = tag.getBoundingClientRect().width;
    const area = document.getElementById('alert-json').getBoundingClientRect();
    if (kind === 'attacker' && r.h < 30 && right + 10 + width < area.right - 8) {
      tag.style.top = (r.y + r.h / 2 - 11) + 'px';
      tag.style.left = (right + 10) + 'px';
      return;
    }
    tag.style.top = (below ? r.y + r.h + pad + 4 : r.y - pad - 24) + 'px';
    tag.style.left = Math.max(4, right - width) + 'px';
  };
  // A short note placed under the Explain row of the input pane.
  W.__note = (text) => {
    const old = document.getElementById('__note'); if (old) old.remove();
    if (!text) return;
    const run = document.querySelector('.run').getBoundingClientRect(), t = ta().getBoundingClientRect();
    const n = document.createElement('div');
    n.id = '__note';
    n.textContent = text;
    Object.assign(n.style, { position: 'fixed', left: t.left + 'px', top: (run.bottom + 12) + 'px', width: t.width + 'px',
      zIndex: 52, font: '14px/1.45 "Segoe UI", system-ui, sans-serif', color: '#1b1b19', background: '#ffffff',
      borderLeft: '4px solid #9a3412', padding: '6px 10px', boxShadow: '0 1px 0 #d4d1c7' });
    document.body.append(n);
  };
  W.__fit = () => { const t = ta(); t.style.height = 'auto'; t.style.height = (t.scrollHeight + 6) + 'px'; };
  W.__set = (value) => { const t = ta(); t.value = value; W.__fit(); };
  W.__done = () => document.getElementById('status').textContent === '' && !!document.querySelector('.result .hash');
  // Positions (CSS px, relative to the first result card) of the parts the composition outlines.
  W.__cardParts = () => {
    const card = document.querySelector('.result'), c = card.getBoundingClientRect();
    const rel = (e) => { if (!e) return null; const q = e.getBoundingClientRect();
      return { x: q.left - c.left, y: q.top - c.top, w: q.width, h: q.height }; };
    const seal = card.querySelector('.hash').closest('.block');
    return { width: c.width, action: rel(card.querySelector('.summary .block')),
             uncertainty: rel(card.querySelector('.summary .block + .block')),
             narrative: rel(card.querySelector('.narrative')), seal: rel(seal) };
  };
  // Show only the card without its quarantine block, or only the username part of the quarantine block.
  W.__cardView = (view) => {
    const card = document.querySelector('.result'), quarantine = card.lastElementChild;
    for (const e of card.children) e.style.display = '';
    for (const e of quarantine.querySelectorAll('.quarantine-item')) e.style.display = '';
    if (view === 'top') quarantine.style.display = 'none';
    if (view === 'username') {
      for (const e of quarantine.querySelectorAll('.quarantine-item')) {
        const f = e.querySelector('.field');
        if (!f || f.textContent !== 'username') e.style.display = 'none';
      }
    }
  };
}
"""


class Shots:
    """Screenshots per beat: a list of [file, frames] where frames None means "hold to the end of the beat".

    A screenshot of the app fills the whole window, so it is kept aside (`app`) and turned into its frame
    later by fit_app_frames, which scales it into the area above the caption band."""

    def __init__(self, work: Path):
        self.dir = work / "frames"
        self.raw = work / "html" / "img"
        self.beats: dict[str, list] = {}
        self.count = 0
        self.app: list[tuple[Path, Path]] = []  # (window screenshot, the frame it becomes)

    def snap(self, page, beat: str, frames: int | None = None, app: bool = False) -> None:
        self.count += 1
        name = f"{self.count:03d}-{beat}.png"
        target = self.dir / name
        if app:
            window = self.raw / f"app-{name}"
            page.screenshot(path=str(window), animations="disabled")
            self.app.append((window, target))
        else:
            page.screenshot(path=str(target), animations="disabled")
        self.beats.setdefault(beat, []).append([f"frames/{name}", frames])


def wait_done(page) -> None:
    """Wait until the app has rendered its answer. Polled from here: the app's CSP forbids the string
    evaluation that Playwright's own wait_for_function uses."""
    for _ in range(300):
        if page.evaluate("() => window.__done()"):
            page.wait_for_timeout(200)
            return
        page.wait_for_timeout(100)
    raise SystemExit("the local app did not answer within 30 s")


def explain_click(page) -> None:
    page.click("#explain")
    page.mouse.move(2, 2)
    wait_done(page)
    page.evaluate("document.activeElement && document.activeElement.blur()")


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[16:24]
    return int.from_bytes(data[:4], "big"), int.from_bytes(data[4:], "big")


def card_images(page, img_dir: Path, prefix: str) -> dict:
    """Two element screenshots of the app's result card: the card without its quarantine block, and that
    block showing only the username. Returns their files, sizes and the outlined parts."""
    page.evaluate("window.__cardView('top')")
    parts = page.evaluate("window.__cardParts()")
    top = img_dir / f"{prefix}-card.png"
    page.locator(".result").first.screenshot(path=str(top), animations="disabled")
    page.evaluate("window.__cardView('username')")
    quarantine = img_dir / f"{prefix}-quarantine.png"
    page.locator(".result > section.block:last-child").first.screenshot(path=str(quarantine), animations="disabled")
    page.evaluate("window.__cardView('all')")
    return {"top": top.name, "top_size": png_size(top), "quarantine": quarantine.name,
            "quarantine_size": png_size(quarantine), "parts": parts}


def capture_app(browser, base_url: str, work: Path, shots: Shots, jaw: dict, mode: str, trial: dict) -> dict:
    img_dir = work / "html" / "img"
    context = browser.new_context(viewport=APP_VIEW, device_scale_factor=APP_DPR, color_scheme="light",
                                  reduced_motion="reduce")
    page = context.new_page()
    page.goto(base_url, wait_until="networkidle")
    page.evaluate(APP_HELPERS)
    page.wait_for_selector("[data-sample='track_example']")
    out: dict = {}

    # Shot 1: the clean alert, explained; the username outlined as attacker-controlled.
    clean_text = json.dumps({"alerts": [jaw["clean"]]}, indent=2, ensure_ascii=False)
    page.evaluate("(v) => window.__set(v)", clean_text)
    explain_click(page)
    out["clean_card"] = card_images(page, img_dir, "clean")
    rect = page.evaluate("(n) => window.__lineRect(n)", '"username"')
    page.evaluate("([r]) => window.__mark('__user', r, 'attacker-controlled', 'attacker', false)", [rect])
    shots.snap(page, "jaw-clean", app=True)

    # The attack string is pasted over the username's value.
    value = json.dumps(jaw["clean"]["username"], ensure_ascii=False)
    start = clean_text.index('"username": ') + len('"username": ')
    if clean_text[start:start + len(value)] != value:
        raise SystemExit("could not find the username value in the alert text")
    page.evaluate("([s, e]) => { const t = document.getElementById('alert-json'); t.focus(); t.setSelectionRange(s, e); }",
                  [len(clean_text[:start + 1].encode("utf-16-le")) // 2,
                   len(clean_text[:start + len(value) - 1].encode("utf-16-le")) // 2])
    shots.snap(page, "jaw-paste", 24, app=True)
    attacked_text = json.dumps({"alerts": [jaw["attacked"]]}, indent=2, ensure_ascii=False)
    page.evaluate("(v) => window.__set(v)", attacked_text)
    page.evaluate("document.activeElement && document.activeElement.blur()")
    rect = page.evaluate("(n) => window.__lineRect(n)", '"username"')
    page.evaluate("([r]) => window.__mark('__user', r, 'attacker-controlled', 'attacker', false)", [rect])
    a = jaw["attack"]
    if mode == "final":
        note = (f"String {a['id']} ({a['class']}) from the project's attack set. In the measured run it changed the "
                f"raw-prompt explainer's decision on this alert ({MODEL_NAMES[jaw['model']]}).")
    else:
        note = f"String {a['id']} ({a['class']}) from the project's attack set, picked by the fixed rule in SHOTS.md."
    page.evaluate("(t) => window.__note(t)", note)
    shots.snap(page, "jaw-paste", app=True)
    page.evaluate("window.__note(null); window.__mark('__user', null)")
    explain_click(page)
    out["attacked_card"] = card_images(page, img_dir, "attacked")

    # Shot 5: the organiser's example, then a string typed into a new free-text field.
    page.click("[data-sample='track_example']")
    page.mouse.move(2, 2)
    wait_done(page)
    page.evaluate("window.__fit()")
    before = page.evaluate("document.querySelector('.result .hash').textContent")
    before_action = page.evaluate("document.querySelector('.result .chip').textContent")
    shots.snap(page, "try-type", 18, app=True)
    sample = json.loads((SAMPLES / "track_example.json").read_text(encoding="utf-8"))
    sample["alerts"][0][trial["field"]] = ""
    typed = json.dumps(trial["attack"]["text"], ensure_ascii=False)[1:-1]
    empty = json.dumps(sample, indent=2, ensure_ascii=False)
    marker = f'"{trial["field"]}": ""'
    cut = empty.index(marker) + len(marker) - 1
    steps = list(range(0, len(typed) + 1, 2))
    if steps[-1] != len(typed):
        steps.append(len(typed))
    for k in steps:
        page.evaluate("(v) => window.__set(v)", empty[:cut] + typed[:k] + empty[cut:])
        rect = page.evaluate("(n) => window.__lineRect(n)", f'"{trial["field"]}"')
        page.evaluate("([r]) => window.__mark('__ua', r, 'attacker-controlled', 'attacker', false)", [rect])
        shots.snap(page, "try-type", None if k == len(typed) else 2, app=True)
    page.evaluate("window.__mark('__ua', null)")
    explain_click(page)
    after = page.evaluate("document.querySelector('.result .hash').textContent")
    after_action = page.evaluate("document.querySelector('.result .chip').textContent")
    rect = page.evaluate("() => window.__unionRect(['.result .summary'])")
    label = f"action {after_action}, " + ("as before the edit" if after_action == before_action else
                                          f"was {before_action} before the edit")
    page.evaluate("([r, t]) => window.__mark('__act', r, t, 'focus', false)", [rect, label])
    rect = page.evaluate("() => window.__unionRect(['.result .hash', '.result .seal-ok'])")
    label = ("before the edit: " + before.removeprefix("SHA-256 ")[:16] + "..., the same hash") if before == after \
        else "before the edit: " + before
    page.evaluate("([r, t]) => window.__mark('__hash', r, t, 'focus', true)", [rect, label])
    shots.snap(page, "try-result", app=True)
    out["try"] = {"hash_before": before, "hash_after": after, "action_before": before_action,
                  "action_after": after_action}
    context.close()
    return out


# ---- generated frames ---------------------------------------------------------------------------------------------

CSS = """
:root { --bg: #f6f5f1; --panel: #ffffff; --fg: #1b1b19; --muted: #5b5a55; --line: #d4d1c7; --code: #efede6;
  --accent: #1f4f8f; --warn: #9a3412; --ok: #2c6635; --mono: "Cascadia Mono", Consolas, ui-monospace, monospace; }
* { box-sizing: border-box; }
html, body { margin: 0; width: 1920px; height: 1080px; overflow: hidden; background: var(--bg); color: var(--fg);
  font-family: "Segoe UI", system-ui, sans-serif; }
.stage { position: absolute; left: 0; top: 0; width: 1920px; padding: 44px 80px 0; }
.kicker { font-size: 21px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); font-weight: 600;
  margin: 0 0 8px; }
h1 { font-size: 44px; line-height: 1.15; margin: 0 0 26px; font-weight: 650; }
.mono { font-family: var(--mono); }
.muted { color: var(--muted); }
.src { position: absolute; left: 80px; right: 80px; bottom: 12px; font-size: 18px; color: var(--muted); }
.chip { display: inline-block; padding: 2px 14px; border: 3px solid currentColor; border-radius: 6px;
  font-weight: 700; letter-spacing: 0.05em; }
.a-allow { color: var(--ok); } .a-monitor { color: var(--fg); } .a-step-up { color: var(--accent); }
.a-contain { color: var(--warn); } .a-unparseable { color: var(--muted); }
.chip.big { font-size: 44px; padding: 4px 22px; border-width: 4px; }
.chip.fill.a-allow { background: var(--ok); color: #fff; border-color: var(--ok); }
.tag { display: inline-block; font-size: 17px; font-weight: 700; letter-spacing: 0.08em; padding: 3px 10px;
  border-radius: 4px; background: var(--fg); color: var(--bg); }
.tag.warn { background: var(--warn); color: #fff; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 26px 30px; }
"""


def page_html(body: str, css: str = "") -> str:
    stage = f".stage {{ height: {STAGE_H}px; }}"  # nothing below it: the captions have that band
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><style>{CSS}{stage}{css}</style></head>'
            f"<body>{body}</body></html>")


def chip(action: str, big: bool = False, fill: bool = False) -> str:
    cls = f"chip a-{esc(action)}" + (" big" if big else "") + (" fill" if fill else "")
    return f'<span class="{cls}">{esc(action.upper())}</span>'


SPLIT_CSS = """
.split { display: grid; grid-template-columns: 720px 1000px; gap: 40px; }
.raw h2 { font-size: 30px; margin: 0; }
.raw .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.raw .sub { font-size: 19px; color: var(--muted); margin: 0 0 22px; }
.raw .row { display: flex; align-items: center; gap: 18px; font-size: 22px; margin: 0 0 14px; }
.raw .row .k { width: 200px; color: var(--muted); }
.raw blockquote { margin: 18px 0; padding: 14px 18px; background: var(--code); border-left: 5px solid var(--ok);
  font-size: 22px; line-height: 1.4; }
.raw .meta { font-size: 17px; color: var(--muted); margin: 14px 0 0; }
.raw pre { font-family: var(--mono); font-size: 15.5px; line-height: 1.45; background: var(--code); padding: 12px 14px;
  margin: 8px 0 14px; white-space: pre-wrap; overflow-wrap: anywhere; border-radius: 4px; }
.raw pre mark { background: rgba(154,52,18,0.16); outline: 2px dashed var(--warn); color: inherit; }
.raw .dry { border-left: 5px solid var(--warn); padding: 10px 14px; font-size: 20px; background: #fff7f2; }
.sealed .colhead { display: flex; align-items: baseline; gap: 14px; margin-bottom: 10px; }
.sealed .colhead h2 { font-size: 30px; margin: 0; }
.sealed .colhead span { font-size: 19px; color: var(--muted); }
.shot { position: relative; margin: 0 0 12px; border: 1px solid var(--line); border-radius: 6px; overflow: hidden;
  background: var(--panel); }
.shot img { display: block; }
.ring { position: absolute; border: 3px solid var(--accent); border-radius: 4px; box-shadow: 0 0 0 4px rgba(31,79,143,.15); }
.hashes { font-size: 18px; margin: 4px 0 0; }
.hashes .mono { font-size: 17px; }
.dim { opacity: 0.38; }
.note { font-size: 16px; color: var(--muted); margin: 0; }
"""


def raw_card(jaw: dict, mode: str, attacked: bool) -> str:
    if mode == "final":
        rec, d = jaw["records"], jaw["decisions"]
        reply = rec[("raw-prompt", "attacked")]
        text = explanation_text(reply["content"]).strip()
        if len(text) > 420:
            text = text[:400].rsplit(" ", 1)[0] + " [...]"
        hardened = rec[("hardened", "attacked")]
        hardened_line = (f'<p class="row"><span class="k">Hardened prompt</span>'
                         f'{chip(parse_decision(hardened["content"]))}<span class="muted">same model, same attack</span></p>'
                         if hardened is not None else "")
        body = (f'<p class="row"><span class="k">Clean alert</span>{chip(d["clean"])}</p>'
                + (f'<p class="row"><span class="k">With the attack</span>{chip(d["attacked"], big=True, fill=True)}</p>'
                   f"<blockquote>{esc(text)}</blockquote>{hardened_line}"
                   f'<p class="meta">Recorded in the evaluation run: {esc(MODEL_NAMES[jaw["model"]])}, greedy decoding. '
                   f'Reply cache key: request SHA-256 <span class="mono">{esc(short_hash(reply["request_sha256"]))}</span></p>'
                   if attacked else ""))
        tag = '<span class="tag">RECORDED REPLY</span>'
        sub = f"{esc(MODEL_NAMES[jaw['model']])}. The alert JSON goes into the prompt."
    else:
        prompt = raw_prompt(jaw["attacked"])[0]["content"]
        shown = esc(prompt.split("Alert:\n", 1)[1])
        needle = esc('"username": ')
        shown = re.sub(rf"({re.escape(needle)}.*)", r"<mark>\1</mark>", shown, count=1)
        body = ('<p class="sub">The exact alert text this arm puts into the prompt, attack included:</p>'
                f"<pre>{shown}</pre>"
                '<p class="dry">No recorded reply yet. The final cut shows the reply recorded in the model run.</p>')
        tag = '<span class="tag warn">DRY RUN</span>'
        sub = "The alert JSON goes into the prompt."
    return (f'<section class="raw card"><div class="head"><h2>Raw-prompt explainer</h2>{tag}</div>'
            f'<p class="sub">{sub}</p>{body}</section>')


def sealed_column(card: dict, scale: float, rings: bool, label: str) -> str:
    def img(name: str, size: tuple[int, int], parts: dict | None) -> str:
        w, h = size
        ring = ""
        if parts:
            k = APP_DPR * scale
            for key in ("action", "uncertainty", "seal"):
                r = parts.get(key)
                if r:
                    ring += (f'<div class="ring" style="left:{r["x"] * k - 3:.0f}px;top:{r["y"] * k - 3:.0f}px;'
                             f'width:{r["w"] * k + 6:.0f}px;height:{r["h"] * k + 6:.0f}px"></div>')
        return (f'<div class="shot" style="width:{w * scale:.0f}px"><img src="img/{name}" '
                f'style="width:{w * scale:.0f}px;height:{h * scale:.0f}px">{ring}</div>')

    return (f'<div class="colhead"><h2>Sealed</h2><span>{esc(label)}</span></div>'
            + img(card["top"], card["top_size"], card["parts"] if rings else None)
            + img(card["quarantine"], card["quarantine_size"], None)
            + '<p class="note">The other quarantined fields of this alert (user_agent, url, host) are not shown here.</p>')


def split_html(jaw: dict, mode: str, cards: dict, step: str) -> str:
    clean, attacked = cards["clean_card"], cards["attacked_card"]
    budget_h = STAGE_H - 44 - 40 - 50 - 40 - 24 - (40 if step == "sealed" else 0)
    tallest = max(c["top_size"][1] + c["quarantine_size"][1] for c in (clean, attacked))
    widest = max(c[k][0] for c in (clean, attacked) for k in ("top_size", "quarantine_size"))
    scale = min(1000 / widest, budget_h / tallest)
    if step == "raw":
        right = f'<div class="dim">{sealed_column(clean, scale, False, "the local app, before the attack")}</div>'
    else:
        h0 = jaw["clean_report"]["model_input"]["sha256"]
        h1 = jaw["attacked_report"]["model_input"]["sha256"]
        verdict = "identical" if h0 == h1 else "DIFFERENT"
        right = (sealed_column(attacked, scale, True, "the local app, with the attack")
                 + f'<p class="hashes">Model input SHA-256: clean alert <span class="mono">{esc(short_hash(h0))}</span>, '
                   f'with the attack <span class="mono">{esc(short_hash(h1))}</span>, {verdict}.</p>')
    body = (f'<div class="stage"><p class="kicker">Same alert, same attack string, alert {esc(jaw["clean"]["id"])}</p>'
            f'<div class="split"><div>{raw_card(jaw, mode, True)}</div><section class="sealed">{right}</section></div></div>')
    return page_html(body, SPLIT_CSS)


COUNTER_CSS = """
.big { font-size: 64px; font-weight: 650; line-height: 1.15; margin: 0 0 30px; }
.rows { display: grid; grid-template-columns: 780px 1fr; row-gap: 18px; font-size: 34px; align-items: baseline; }
.rows .k { color: var(--muted); font-size: 28px; }
.rows .v b { font-size: 46px; }
.rows .v small { font-size: 24px; color: var(--muted); margin-left: 12px; }
.url { font-family: var(--mono); font-size: 32px; color: var(--accent); margin-top: 34px; }
"""


def counter_html(mode: str, results: dict, template: dict, jaw: dict, url: str | None) -> str:
    if mode == "final":
        model = jaw["model"]
        arms = results["models"][model]["arms"]
        n = arms["raw-prompt"]["decision_change"]["n"]
        rows = [("Raw prompt changed its decision", arms["raw-prompt"]["decision_change"]),
                ("Hardened prompt changed its decision", arms["hardened"]["decision_change"])]
        cells = "".join(f'<div class="k">{esc(k)}</div><div class="v"><b>{pct(p)}</b>'
                        f'<small>{esc(kn(p))}, 95% {esc(interval(p.get("bootstrap95_by_alert")))}</small></div>'
                        for k, p in rows)
        sealed = arms["sealed"]
        cells += (f'<div class="k">Sealed lowered its decision</div><div class="v"><b>{esc(kn(sealed["decision_lowered"]))}</b></div>'
                  f'<div class="k">Sealed model input identical</div><div class="v"><b>{esc(kn(sealed["same_model_input"]))}</b></div>')
        head = (f'<p class="kicker">Measured run, {esc(MODEL_NAMES[model])}</p>'
                f'<p class="big">{n:,} attacked alerts, each against its clean twin</p>')
        src = ("results/model_arms.json (python -m sealed evaluate --arm models). All three models appear in the "
               "results table after the diagram.")
    else:
        cells = "".join(f'<div class="k">{esc(k)}</div><div class="v"><b>{esc(kn(p))}</b><small>{pct(p)}</small></div>'
                        for k, p in (("Model input identical to the clean twin", template["seal_invariance"]),
                                     ("Action unchanged, or raised one level by the hook", template["action_stability"]),
                                     ("Uncertainty never lowered", template["uncertainty_never_lowered"])))
        head = ('<p class="kicker">Template arm, no model. Dry run: the model-arm numbers go here</p>'
                f'<p class="big">{template["counts"]["triples"]:,} attacked alerts, each against its clean twin</p>')
        src = "results/template_arm.json (python -m sealed evaluate --arm template)"
    link = f'<p class="url">{esc(url)}</p>' if url else ""
    return page_html(f'<div class="stage">{head}<div class="rows">{cells}</div>{link}'
                     f'<p class="src">{esc(src)}</p></div>', COUNTER_CSS)


DIAGRAM_CSS = """
svg { display: block; }
svg text { font-family: "Segoe UI", system-ui, sans-serif; text-anchor: middle; fill: var(--fg); }
svg .t { font-size: 27px; font-weight: 650; }
svg .s { font-size: 19px; fill: var(--muted); }
svg .lab { font-size: 20px; text-anchor: start; fill: var(--warn); font-weight: 600; }
svg .lab2 { font-size: 19px; text-anchor: start; fill: var(--muted); }
svg .box rect { fill: var(--panel); stroke: var(--fg); stroke-width: 2; }
svg .model rect { stroke: var(--accent); stroke-width: 4; }
svg .model .t { fill: var(--accent); }
svg .bad rect { fill: #fbefe8; stroke: var(--warn); stroke-width: 2.5; stroke-dasharray: 9 6; }
svg .line { stroke: var(--fg); stroke-width: 3; fill: none; marker-end: url(#arrow); }
svg .band { stroke: url(#hatch); stroke-width: 30; fill: none; }
svg .score { stroke: var(--warn); stroke-width: 2.5; stroke-dasharray: 8 7; fill: none; marker-end: url(#arrow-w); }
svg g { transition: none; }
svg .off { opacity: 0.22; }
.legend { display: flex; gap: 60px; font-size: 21px; margin-top: 18px; align-items: center; }
.legend i { display: inline-block; width: 70px; height: 0; vertical-align: middle; margin-right: 12px; }
.legend .solid { border-top: 3px solid var(--fg); }
.legend .hatched { height: 18px; background: repeating-linear-gradient(45deg, var(--warn) 0 5px, #f7dccd 5px 11px); }
.legend .dashed { border-top: 3px dashed var(--warn); }
"""


def diagram_html(step: int) -> str:
    def box(x, y, w, title, sub, cls="box"):
        return (f'<g class="{cls}"><rect x="{x}" y="{y}" width="{w}" height="100" rx="10"/>'
                f'<text class="t" x="{x + w / 2}" y="{y + 43}">{title}</text>'
                f'<text class="s" x="{x + w / 2}" y="{y + 75}">{sub}</text></g>')

    def arrow(d):
        return f'<path class="line" d="{d}"/>'

    on = {1: ("g1",), 2: ("g1", "g2"), 3: ("g1", "g2", "g3")}[step]
    focus = {1: "g1", 2: "g2", 3: "g3"}[step]

    def group(name, content):
        cls = "" if name == focus else ("off" if name not in on else "")
        dim = ' style="opacity:0.5"' if name in on and name != focus else ""
        return f'<g class="{cls}"{dim}>{content}</g>'

    g1 = (box(0, 30, 220, "Alert JSON", "Track 4 contract") + arrow("M220,80 H276")
          + box(280, 30, 260, "Contract parser", "grammar, 42 signal types") + arrow("M540,80 H596")
          + box(600, 30, 300, "Facts", "vocabulary codes and counts"))
    g2 = (arrow("M900,80 H956") + box(960, 30, 280, "Policy table", "declared rules") + arrow("M1240,80 H1296")
          + box(1300, 30, 460, "Action and uncertainty", "mock recommendation, not executed")
          + arrow("M750,130 V266") + box(600, 270, 300, "Sealed view", "fixed prompt, SHA-256 shown")
          + arrow("M900,320 H956") + box(960, 270, 280, "Narrator model", "reads the sealed view only", "box model")
          + arrow("M1240,320 H1296") + box(1300, 270, 200, "Verifier", "checks citations")
          + arrow("M1500,320 H1556") + box(1560, 270, 200, "Narrative", "cited sentences"))
    g3 = ('<path class="band" d="M410,130 V590 H600"/><path class="band" d="M900,590 H960"/>'
          '<path class="band" d="M1240,590 H1300"/>'
          + box(600, 540, 300, "Quarantine", "escaped, never given to a model", "bad")
          + box(960, 540, 280, "Injection detector", "keyword baseline", "bad")
          + box(1300, 540, 460, "Shown to the analyst", "escaped, beside the narrative", "bad")
          + '<path class="score" d="M1240,566 H1270 V160 H1200 V136"/>'
          + '<text class="lab" x="20" y="300">Attacker-written text:</text>'
          + '<text class="lab2" x="20" y="332">username, user agent,</text>'
          + '<text class="lab2" x="20" y="362">URL, host, extra fields</text>'
          + '<text class="lab2" x="1284" y="430">a score only: one level</text>'
          + '<text class="lab2" x="1284" y="460">up at most, never contain</text>')
    svg = ('<svg width="1760" height="660" viewBox="0 0 1760 660" xmlns="http://www.w3.org/2000/svg"><defs>'
           '<pattern id="hatch" width="14" height="14" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
           '<rect width="14" height="14" fill="#f7dccd"/><rect width="6" height="14" fill="#9a3412"/></pattern>'
           '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           '<path d="M0,0 L10,5 L0,10 z" fill="#1b1b19"/></marker>'
           '<marker id="arrow-w" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           '<path d="M0,0 L10,5 L0,10 z" fill="#9a3412"/></marker></defs>'
           + group("g3", g3) + group("g1", g1) + group("g2", g2) + "</svg>")
    legend = ('<div class="legend"><span><i class="solid"></i>trusted path: structured values only</span>'
              '<span><i class="hatched"></i>bytes the attacker wrote</span>'
              '<span><i class="dashed"></i>a detector score, never text</span></div>')
    title = {1: "A strict parser keeps only what it recognises",
             2: "The policy decides; the model only rewords cited facts",
             3: "Attacker text goes around the model, never through it"}[step]
    return page_html(f'<div class="stage"><p class="kicker">How it works</p><h1>{title}</h1>{svg}{legend}</div>',
                     DIAGRAM_CSS)


TABLE_CSS = """
table { border-collapse: collapse; width: 100%; font-size: 27px; background: var(--panel); border: 1px solid var(--line); }
th, td { padding: 14px 18px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { font-size: 20px; color: var(--muted); font-weight: 600; letter-spacing: 0.02em; }
td small { display: block; font-size: 18px; color: var(--muted); margin-top: 2px; }
td b { font-size: 34px; }
.hl { background: rgba(31,79,143,0.09); box-shadow: inset 0 0 0 3px var(--accent); }
thead.hl th { color: var(--accent); }
.def { font-size: 19px; color: var(--muted); margin: 18px 0 0; max-width: 1700px; line-height: 1.4; }
"""


def results_html(mode: str, results: dict, template: dict, step: str) -> str:
    if mode == "final":
        cols = [("raw", "Raw prompt<br>decision changed"), ("hard", "Hardened prompt<br>decision changed"),
                ("sealed", "Sealed<br>decision changed"), ("low", "Sealed<br>decision lowered"),
                ("same", "Sealed<br>same model input")]
        hl = {"results-change": {"raw", "hard"}, "results-sealed": {"sealed", "low", "same"}}.get(step, set())
        rows = []
        for model, summary in results["models"].items():
            arms = summary["arms"]

            def change(arm):
                p = arms[arm]["decision_change"]
                return f'<b>{pct(p)}</b><small>{esc(kn(p))}; 95% {esc(interval(p.get("bootstrap95_by_alert")))}</small>'
            cells = {"raw": change("raw-prompt"), "hard": change("hardened"), "sealed": change("sealed"),
                     "low": f'<b>{esc(kn(arms["sealed"]["decision_lowered"]))}</b>',
                     "same": f'<b>{esc(kn(arms["sealed"]["same_model_input"]))}</b>'}
            rows.append(f"<tr><td>{esc(MODEL_NAMES.get(model, model))}<small>{arms['raw-prompt']['triples']:,} attacked alerts"
                        "</small></td>" + "".join(f'<td class="{"hl" if c in hl else ""}">{cells[c]}</td>' for c, _ in cols)
                        + "</tr>")
        head = ("<tr><th>Model</th>" + "".join(f'<th class="{"hl" if c in hl else ""}">{t}</th>' for c, t in cols)
                + "</tr>")
        thead_cls = "hl" if step == "results-arms" else ""
        m2 = template["action_stability"]
        body = (f'<p class="kicker">Measured run: three local models, three arms</p>'
                f"<h1>How often did the attack change the decision?</h1>"
                f'<table><thead class="{thead_cls}">{head}</thead><tbody>{"".join(rows)}</tbody></table>'
                '<p class="def">Decision changed: the attacked alert got a different decision from its clean twin, '
                "or a reply had no usable decision. 95%: bootstrap interval over alerts. Sealed's decision is the "
                "policy's, so its only possible change is the documented raise of one level when the detector flags "
                f"the text (template arm: action unchanged or raised that way in {esc(kn(m2))}).</p>"
                '<p class="src">results/model_arms.json, written by python -m sealed evaluate --arm models</p>')
    else:
        metrics = [("M1", "Model input identical to the clean twin", template["seal_invariance"]),
                   ("M2", "Action unchanged, or raised one level by the hook", template["action_stability"]),
                   ("M3", "Uncertainty never lowered", template["uncertainty_never_lowered"]),
                   ("M4", "Detector recall, held-out attack strings", template["test"]["recall"]),
                   ("M5", "False flags, held-out benign values", template["test"]["false_flags"]),
                   ("M6", "Escalation hook fired", template["escalation_rate"])]
        hl = {"results-change": {"M2"}, "results-sealed": {"M1", "M2"}}.get(step, set())
        rows = "".join(f'<tr class="{"hl" if m in hl else ""}"><td>{m}</td><td>{esc(label)}</td><td><b>{esc(kn(p))}</b>'
                       f'</td><td>{pct(p)}<small>95% {esc(interval(p.get("wilson95")))}</small></td></tr>'
                       for m, label, p in metrics)
        thead_cls = "hl" if step == "results-arms" else ""
        body = ('<p class="kicker">Dry run: the model-arm table goes here. Template arm, no model</p>'
                f'<h1>Sealed on {template["counts"]["triples"]:,} attacked alerts</h1>'
                f'<table><thead class="{thead_cls}"><tr><th></th><th>Measure</th><th>Result</th><th>Rate</th></tr></thead>'
                f"<tbody>{rows}</tbody></table>"
                '<p class="def">In the final cut this frame shows results/model_arms.json: decision changed under attack '
                "for the raw-prompt, hardened-prompt and Sealed arms on each model.</p>"
                '<p class="src">results/template_arm.json, written by python -m sealed evaluate --arm template</p>')
    return page_html(f'<div class="stage">{body}</div>', TABLE_CSS)


FAILURE_CSS = """
.fcard { font-size: 26px; }
.fcard .str { font-family: var(--mono); font-size: 28px; background: var(--code); border: 2px dashed var(--warn);
  padding: 16px 20px; margin: 10px 0 18px; overflow-wrap: anywhere; }
.fcard .row { display: grid; grid-template-columns: 330px 1fr; gap: 20px; margin: 0 0 16px; align-items: baseline; }
.fcard .row .k { color: var(--muted); font-size: 22px; }
.fcard .bad { color: var(--warn); font-weight: 600; }
.fcard .good { color: var(--ok); font-weight: 600; }
"""


def failure_html(f: dict) -> str:
    a = f["attack"]
    decoded = (f'<div class="row"><span class="k">Decodes to</span><span>{esc(ascii_preview(f["decoded"], 160))}</span></div>'
               if f["decoded"] else "")
    same = f["hash"] == f["twin_hash"]
    body = (f'<p class="kicker">A failure, shown: string {esc(a["id"])}, {esc(a["class"])}, {esc(a["split"])} split</p>'
            "<h1>The keyword detector missed this base64 string</h1>"
            f'<div class="card fcard"><div class="str">{esc(ascii_preview(f["text"], 200))}</div>{decoded}'
            f'<div class="row"><span class="k">Keyword detector</span><span class="bad">score {f["score"]:.2f}, below the '
            f'{f["threshold"]:.1f} threshold: no warning, no escalation</span></div>'
            f'<div class="row"><span class="k">Model input</span><span class="{"good" if same else "bad"}">SHA-256 '
            f'<span class="mono">{esc(short_hash(f["hash"]))}</span> with the string in {esc(", ".join(f["fields"]))} of '
            f'alert {esc(f["alert"])}, <span class="mono">{esc(short_hash(f["twin_hash"]))}</span> with "x" there instead: '
            f'{"identical" if same else "DIFFERENT"}</span></div>'
            f'<div class="row"><span class="k">Every base64 string</span><span>flagged {esc(kn(f["base64"]["test"]))} '
            f'held-out, {esc(kn(f["base64"]["dev"]))} dev (template arm, M4)</span></div></div>'
            f'<p class="src">results/template_arm.md, failure gallery: {f["missed_total"]} missed attack strings, '
            "each listed. Hashes computed at capture time by the sealed package.</p>")
    return page_html(f'<div class="stage">{body}</div>', FAILURE_CSS)


TERM_CSS = """
.term { background: #161614; color: #ecebe5; border-radius: 10px; padding: 24px 32px; font-family: var(--mono);
  font-size: 19px; line-height: 1.4; max-height: 740px; white-space: pre-wrap; overflow-wrap: anywhere; overflow: hidden; }
.term .cmd { color: #8db4ec; }
.term .cmd::before { content: "$ "; color: #aaa89f; }
.term .gap { color: #aaa89f; font-style: italic; }
.term .hl { background: rgba(140,207,152,0.18); color: #8ccf98; }
"""


def term_block(result: dict, lines: list[str], skipped_before: int = 0, highlight: tuple = ()) -> str:
    out = [f'<div class="cmd">{esc(result["command"])}</div>']
    if skipped_before:
        out.append(f'<div class="gap">[{skipped_before} earlier lines of output not shown]</div>')
    for line in lines:
        cls = ' class="hl"' if any(h in line for h in highlight) else ""
        out.append(f"<div{cls}>{esc(line) or '&#8203;'}</div>")
    return "".join(out)


def terminal_html(step: str, outputs: dict, mode: str) -> str:
    if step == "terminal-demo":
        demo = outputs["demo"]["lines"]
        content = term_block(outputs["demo"], demo[:22])
        kicker, title = "One command, offline", "python -m sealed demo"
        note = f"real output, the first 22 of {len(demo)} lines"
    elif step == "terminal-seal":
        demo = outputs["demo"]["lines"]
        end = next(i for i, line in enumerate(demo) if line.startswith("identical:")) + 1
        start = max(next(i for i, line in enumerate(demo) if line.startswith("=== 2.")), end - 21)
        content = term_block(outputs["demo"], demo[start:end], start, ("SHA-256", "identical:"))
        kicker, title = "The seal check", "Clean alert and attacked alert: the same model input"
        note = "real output of python -m sealed demo"
    else:
        replay, tests = outputs["replay"], outputs["tests"]
        filled = [i for i, line in enumerate(tests["lines"]) if line.strip()]
        first = filled[-3] if len(filled) >= 3 else 0
        shown = replay["lines"][-14:]
        content = (term_block(replay, shown, len(replay["lines"]) - len(shown))
                   + "<div>&#8203;</div>" + term_block(tests, tests["lines"][first:], first, ("Ran ", "OK")))
        kicker = "Replay and tests"
        title = "Results replay from " + ("the reply cache" if mode == "final" else "the code") + "; the test suite"
        note = "real output, captured with these frames"
    return page_html(f'<div class="stage"><p class="kicker">{esc(kicker)}: {esc(note)}</p><h1>{esc(title)}</h1>'
                     f'<div class="term">{content}</div></div>', TERM_CSS)


END_CSS = """
.name { font-size: 96px; font-weight: 700; margin: 40px 0 6px; letter-spacing: 0.01em; }
.claim { font-size: 36px; margin: 0 0 18px; max-width: 1500px; }
.track { font-size: 26px; color: var(--muted); margin: 0 0 40px; }
.url { font-family: var(--mono); font-size: 36px; color: var(--accent); margin: 0 0 50px; }
.cta { font-size: 30px; line-height: 1.5; max-width: 1500px; }
"""


def end_html(url: str | None) -> str:
    link = f'<p class="url">{esc(url)}</p>' if url else ""
    return page_html('<div class="stage"><p class="name">Sealed</p>'
                     '<p class="claim">A security-alert explainer whose language model never reads a byte the attacker wrote.</p>'
                     '<p class="track">Aegython 2026, Track 4: Explain My Security Alert</p>'
                     f'{link}<p class="cta">Runs offline with one command. Try to break it.</p>'
                     "</div>", END_CSS)


APP_FRAME_CSS = f"""
.window {{ position: absolute; left: {(WIDTH - APP_FRAME_W) // 2}px; top: {APP_MARGIN}px; width: {APP_FRAME_W}px;
  height: {APP_FRAME_H}px; border-radius: 6px; overflow: hidden;
  box-shadow: 0 0 0 1px var(--line), 0 2px 8px rgba(27,27,25,0.10); }}
.window img {{ display: block; width: 100%; height: 100%; }}
"""


def fit_app_frames(page, work: Path, shots: Shots) -> None:
    """Each full-window screenshot of the app, scaled down into the area above the caption band."""
    path = work / "html" / "app-frame.html"
    path.write_text(page_html('<div class="window"><img id="shot" alt=""></div>', APP_FRAME_CSS), encoding="utf-8")
    page.goto(path.as_uri(), wait_until="load")
    for window, target in shots.app:
        page.evaluate("async (src) => { const i = document.getElementById('shot'); i.src = src; await i.decode(); }",
                      f"img/{window.name}")
        page.screenshot(path=str(target), animations="disabled")


def capture_generated(browser, work: Path, shots: Shots, frames: dict[str, str]) -> None:
    html_dir = work / "html"
    context = browser.new_context(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=1,
                                  color_scheme="light", reduced_motion="reduce")
    page = context.new_page()
    fit_app_frames(page, work, shots)
    for beat, doc in frames.items():
        path = html_dir / f"{beat}.html"
        path.write_text(doc, encoding="utf-8")
        page.goto(path.as_uri(), wait_until="load")
        page.evaluate("document.fonts.ready.then(() => true)")
        shots.snap(page, beat)
    context.close()


# ---- main ---------------------------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", choices=("dry-run", "final"), required=True)
    ap.add_argument("--work", type=Path, default=WORK, help="folder for frames and the manifest (default: video/work)")
    ap.add_argument("--results", type=Path, default=RESULTS / "model_arms.json", help="final mode: model-arm results")
    ap.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE, help="final mode: the reply cache (read only)")
    ap.add_argument("--model", choices=MODELS, help="final mode: take the opening shot's reply from this model")
    ap.add_argument("--triple", type=int, help="take the opening shot from this triple (its number in the run order)")
    ap.add_argument("--repo-url", help="link on the counter and end frames (default: the git remote, if any)")
    ap.add_argument("--reuse-terminal", action="store_true",
                    help="reuse the command output recorded by the previous capture in the same mode (faster retakes)")
    args = ap.parse_args()

    lines, end_s = parse_narration()
    schedule(lines, end_s)  # fails early if NARRATION.md and the beats disagree
    work = args.work.resolve()
    if work == REPO or work in REPO.parents:
        raise SystemExit("--work must be a folder of its own, not the repository or a folder above it")
    # A capture that stops early must not leave an older manifest behind for render.py to use.
    (work / "manifest.json").unlink(missing_ok=True)

    started_ns = time.time_ns()  # render.py final refuses result files written after this
    sources = {}

    def read_results(path: Path) -> dict:
        data = path.read_bytes()
        path = path.resolve()
        name = path.relative_to(REPO).as_posix() if path.is_relative_to(REPO) else str(path)
        sources[name] = hashlib.sha256(data).hexdigest()
        return json.loads(data.decode("utf-8"))

    template = read_results(RESULTS / "template_arm.json")
    results = None
    if args.mode == "final":
        if not args.results.is_file():
            raise SystemExit(f"{args.results} not found: run `python -m sealed evaluate --arm models` first, "
                             "or capture with --mode dry-run")
        results = read_results(args.results)
        if "models" not in results:
            raise SystemExit(f"{args.results} is not a model-arm result file")
    models = [args.model] if args.model else [m for m in MODEL_ORDER if results is None or m in results["models"]]
    jaw = choose_jaw(args.mode, models, args.cache_dir, args.triple)
    failure = choose_failure(template, jaw["clean"])
    trial = choose_try()
    url = repo_url(args.repo_url)

    for sub in ("frames", "html"):
        shutil.rmtree(work / sub, ignore_errors=True)
    (work / "frames").mkdir(parents=True)
    (work / "html" / "img").mkdir(parents=True)

    # before the browser starts, to keep memory free
    outputs = terminal_outputs(args.mode, work, args.reuse_terminal, args.cache_dir, args.results)

    from playwright.sync_api import sync_playwright
    server, _thread = start_in_thread(0)
    shots = Shots(work)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--disable-extensions", "--mute-audio"])
            try:
                cards = capture_app(browser, f"http://127.0.0.1:{server.server_port}/", work, shots, jaw, args.mode, trial)
                frames = {"jaw-raw": split_html(jaw, args.mode, cards, "raw"),
                          "jaw-sealed": split_html(jaw, args.mode, cards, "sealed"),
                          "jaw-counter": counter_html(args.mode, results, template, jaw, url),
                          "diagram-parse": diagram_html(1), "diagram-policy": diagram_html(2),
                          "diagram-attacker": diagram_html(3)}
                for step in ("results-intro", "results-arms", "results-change", "results-sealed"):
                    frames[step] = results_html(args.mode, results, template, step)
                frames["failure-card"] = failure_html(failure)
                for step in ("terminal-demo", "terminal-seal", "terminal-tests"):
                    frames[step] = terminal_html(step, outputs, args.mode)
                frames["end-card"] = end_html(url)
                capture_generated(browser, work, shots, frames)
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()

    triple, attack = jaw["triple"], jaw["attack"]
    selection = {"triple": triple["n"], "alert": triple["alert"], "attack": attack["id"], "class": attack["class"],
                 "field": triple["fields"][0], "text": attack["text"], "model": jaw["model"],
                 "sealed_action": jaw["attacked_report"]["recommendation"]["action"],
                 "sealed_hash_clean": jaw["clean_report"]["model_input"]["sha256"],
                 "sealed_hash_attacked": jaw["attacked_report"]["model_input"]["sha256"]}
    if args.mode == "final":
        selection["raw_decisions"] = jaw["decisions"]
        selection["raw_request_sha256"] = jaw["records"][("raw-prompt", "attacked")]["request_sha256"]
    manifest = {"mode": args.mode, "fps": FPS, "width": WIDTH, "height": HEIGHT, "beats": shots.beats,
                "started_ns": started_ns, "sources": sources,
                "selection": selection, "failure": {"attack": failure["attack"]["id"], "score": failure["score"]},
                "try": {"attack": trial["attack"]["id"], "field": trial["field"], **cards["try"]},
                "terminal": {k: {"command": v["command"], "exit": v["exit"]} for k, v in outputs.items()},
                "repo_url": url}
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"{shots.count} screenshots in {work / 'frames'}; manifest written. Opening shot: triple {triple['n']}, "
          f"alert {triple['alert']}, string {attack['id']}" + (f", {jaw['model']}" if jaw["model"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
