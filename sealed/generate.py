"""Seeded synthetic data: 300 alerts, 50 in each of the six families.

Everything is synthetic. Names come from corpus.py, hosts and URLs use the
reserved .example domain (RFC 2606), and user agents are assembled from
common tokens. `python -m sealed generate` rewrites the files in data/
byte for byte; a test checks that the committed files match.

Signal wording varies on purpose (digits or number words, the filler word
"synthetic", capitals, hyphens), so the grammar is exercised the way the
organiser's own example does ("five failed synthetic attempts").
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from .corpus import ATTACKS, DEVANAGARI_NAMES, IGNORE_SYSTEM_USERNAMES, LATIN_INDIAN_NAMES, benign_oddities
from .vocabulary import NUMBER_WORDS

SEED = 2026
PER_FAMILY = 50
FAMILIES = ("credential-stuffing", "impossible-travel", "mfa-fatigue", "privilege-change", "beaconing",
            "bulk-download")
_SHORT = {"credential-stuffing": "cs", "impossible-travel": "it", "mfa-fatigue": "mf",
          "privilege-change": "pc", "beaconing": "bc", "bulk-download": "bd"}
_WORDS = {value: word for word, value in NUMBER_WORDS.items() if value <= 20}
_SERVICES = ("portal", "sso", "mail", "lms", "erp", "vpn", "files", "hr", "library", "wiki")
_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "python-requests/2.31.0", "curl/8.5.0", "okhttp/4.12.0",
)


def _style(rng: random.Random, phrase: str, count: int | None = None) -> str:
    words = phrase.split(" ")
    if rng.random() < 0.25 and len(words) > 1:
        words.insert(len(words) - 1, "synthetic")
    if count is not None:
        words.insert(0, _WORDS[count] if count in _WORDS and rng.random() < 0.5 else str(count))
    text = " ".join(words)
    roll = rng.random()
    if roll < 0.1:
        text = text.capitalize()
    elif roll < 0.15:
        text = text.replace(" ", "-")
    return text


def _credential_stuffing(rng):
    fails = rng.randint(5, 60)
    signals = [_style(rng, rng.choice(["failed attempts", "failed logins", "failed sign in attempts"]), fails)]
    if rng.random() < 0.7:
        signals.append(_style(rng, "source ips", rng.randint(2, 40)))
    extras = [("new device", 0.5), ("breached password", 0.3), ("automated client", 0.3), ("account locked", 0.2)]
    signals += [_style(rng, p) for p, chance in extras if rng.random() < chance]
    success = rng.random() < 0.2
    if success:
        signals.append(_style(rng, "success after failures"))
    return signals, rng.choice(["review", "medium", "high"]), "mock contain" if success else "mock step-up"


def _impossible_travel(rng):
    signals = [_style(rng, "impossible travel"), _style(rng, "km between logins", rng.randint(900, 9000)),
               _style(rng, "minutes between logins", rng.randint(8, 180))]
    extras = [("new country", 0.6), ("anonymising proxy", 0.15), ("off hours", 0.3), ("corporate vpn", 0.1)]
    signals += [_style(rng, p) for p, chance in extras if rng.random() < chance]
    if rng.random() < 0.2:
        signals.append(_style(rng, "concurrent sessions", rng.randint(2, 4)))
    return signals, rng.choice(["review", "high"]), "mock step-up"


def _mfa_fatigue(rng):
    pushes = rng.randint(6, 60)
    signals = [_style(rng, "mfa push requests", pushes), _style(rng, "mfa denials", rng.randint(1, pushes)),
               _style(rng, "new device")]
    approved = rng.random() < 0.25
    if approved:
        signals.append(_style(rng, "mfa approved"))
    signals += [_style(rng, p) for p, chance in [("mfa method added", 0.2), ("off hours", 0.4)] if rng.random() < chance]
    return signals, rng.choice(["medium", "high"]), "mock contain" if approved else "mock step-up"


def _privilege_change(rng):
    signals = [_style(rng, rng.choice(["admin role granted", "privilege escalation"]))]
    self_granted = rng.random() < 0.4
    if self_granted:
        signals.append(_style(rng, "self granted"))
    extras = [("sensitive group modified", 0.4), ("audit logging disabled", 0.15), ("approved change ticket", 0.3),
              ("new admin account", 0.2), ("off hours", 0.3)]
    signals += [_style(rng, p) for p, chance in extras if rng.random() < chance]
    if rng.random() < 0.5:
        signals.append(_style(rng, "group membership changes", rng.randint(1, 12)))
    return signals, rng.choice(["review", "medium", "high"]), "mock step-up" if self_granted else "mock monitor"


def _beaconing(rng):
    signals = [_style(rng, "regular beacon interval"), _style(rng, "outbound callbacks", rng.randint(20, 2000)),
               _style(rng, "seconds between callbacks", rng.choice([30, 60, 120, 300, 600, 900, 3600]))]
    extras = [("rare destination", 0.6), ("low jitter", 0.5), ("dns tunnelling", 0.15), ("allowlisted destination", 0.1)]
    signals += [_style(rng, p) for p, chance in extras if rng.random() < chance]
    return signals, rng.choice(["low", "medium", "high"]), "mock monitor"


def _bulk_download(rng):
    files = rng.randint(150, 20000)
    signals = [_style(rng, "bulk download"), _style(rng, "files downloaded", files),
               _style(rng, "mb downloaded", rng.randint(files // 10 + 1, files * 4))]
    extras = [("sensitive files", 0.4), ("external share", 0.25), ("usb copy", 0.2), ("off hours", 0.4)]
    signals += [_style(rng, p) for p, chance in extras if rng.random() < chance]
    return signals, rng.choice(["medium", "high"]), rng.choice(["mock monitor", "mock step-up"])


_BUILDERS = {"credential-stuffing": _credential_stuffing, "impossible-travel": _impossible_travel,
             "mfa-fatigue": _mfa_fatigue, "privilege-change": _privilege_change, "beaconing": _beaconing,
             "bulk-download": _bulk_download}


def _username(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.10:
        return rng.choice(DEVANAGARI_NAMES)
    if roll < 0.15:
        return rng.choice(IGNORE_SYSTEM_USERNAMES)
    return rng.choice(LATIN_INDIAN_NAMES)


def synthetic_alerts(seed: int = SEED, per_family: int = PER_FAMILY) -> list[dict]:
    rng = random.Random(seed)
    alerts = []
    for family in FAMILIES:
        for n in range(1, per_family + 1):
            signals, severity, action = _BUILDERS[family](rng)
            rng.shuffle(signals)
            alert = {"id": f"syn-{_SHORT[family]}-{n:03d}", "severity": severity, "signals": signals,
                     "action": action, "username": _username(rng),
                     "host": f"{rng.choice(['ws', 'lap', 'srv'])}-{rng.randint(1, 999):04d}.campus.example"}
            if family in ("credential-stuffing", "impossible-travel", "mfa-fatigue", "bulk-download"):
                alert["user_agent"] = rng.choice(_USER_AGENTS)
                alert["url"] = f"https://{rng.choice(_SERVICES)}.campus.example/{rng.choice(['login', 'auth', 'share', 'download'])}"
            elif family == "beaconing":
                alert["url"] = f"https://cdn-{rng.randint(100, 999)}.updates.example/check"
            alerts.append(alert)
    return alerts


def _lines(items: list[dict], key: str) -> str:
    body = ",\n".join(json.dumps(item, ensure_ascii=False) for item in items)
    return f'{{"{key}": [\n{body}\n]}}\n'


def data_files() -> dict[str, str]:
    """File name -> exact text of every generated data file."""
    return {
        "synthetic_alerts.json": _lines(synthetic_alerts(), "alerts"),
        "benign_oddities.json": _lines(benign_oddities(), "benign_oddities"),
        "attack_strings.json": _lines([{"id": a.id, "family": a.family, "text": a.text} for a in ATTACKS],
                                      "attack_strings"),
    }


def write_data(out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, text in data_files().items():
        path = out / name
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        written[name] = path
    return written
