"""The video's timeline, shared by capture.py and render.py.

video/NARRATION.md is the single source of timing: each numbered voice-over
line carries its start time, and the file states when the video ends. Every
beat (one picture, or one short animation that then holds its last frame)
starts with a narration line, so the pictures, the captions and the voice
share one clock.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

VIDEO = Path(__file__).resolve().parent
REPO = VIDEO.parent
NARRATION = VIDEO / "NARRATION.md"
WORK = VIDEO / "work"
FPS = 30
WIDTH, HEIGHT = 1920, 1080
CAPTION_BAND = 150  # pixels at the bottom of every frame kept free for the burned-in captions
MAX_SECONDS = 118.0  # the cut must not exceed 1:58

LINE = re.compile(r"^\s*(\d+)\.\s+\*\*(\d+):(\d{2}(?:\.\d+)?)\*\*\s+(.+?)\s*$", re.M)
END = re.compile(r"video ends at \*\*(\d+):(\d{2}(?:\.\d+)?)\*\*", re.I)


@dataclass(frozen=True)
class Line:
    number: int
    start: float
    text: str


@dataclass(frozen=True)
class Beat:
    name: str
    shot: int
    line: int  # the narration line this beat starts with
    fade: int  # frames of crossfade from the previous beat into this one (0: hard cut)


# Shots and beats, in order. SHOTS.md describes what each one shows.
BEATS = (
    Beat("jaw-clean", 1, 1, 0),
    Beat("jaw-paste", 1, 2, 0),
    Beat("jaw-raw", 1, 3, 6),
    Beat("jaw-sealed", 1, 4, 8),
    Beat("jaw-counter", 1, 5, 8),
    Beat("diagram-parse", 2, 6, 12),
    Beat("diagram-policy", 2, 7, 8),
    Beat("diagram-attacker", 2, 8, 8),
    Beat("results-intro", 3, 9, 12),
    Beat("results-arms", 3, 10, 6),
    Beat("results-change", 3, 11, 6),
    Beat("results-sealed", 3, 12, 6),
    Beat("failure-card", 3, 13, 10),
    Beat("terminal-demo", 4, 14, 12),
    Beat("terminal-seal", 4, 15, 0),
    Beat("terminal-tests", 4, 16, 0),
    Beat("try-type", 5, 17, 12),
    Beat("try-result", 5, 18, 0),
    Beat("end-card", 6, 19, 12),
)


def parse_narration(path: Path = NARRATION) -> tuple[list[Line], float]:
    """The numbered lines with their start times (seconds), and the end of the video."""
    text = path.read_text(encoding="utf-8")
    lines = [Line(int(m.group(1)), int(m.group(2)) * 60 + float(m.group(3)), m.group(4).strip())
             for m in LINE.finditer(text)]
    end = END.search(text)
    if not lines or end is None:
        raise SystemExit(f"{path.name}: no timed lines, or no line saying when the video ends")
    if [line.number for line in lines] != list(range(1, len(lines) + 1)):
        raise SystemExit(f"{path.name}: lines must be numbered 1, 2, 3, ... in order")
    if any(b.start <= a.start for a, b in zip(lines, lines[1:])):
        raise SystemExit(f"{path.name}: line start times must increase")
    end_s = int(end.group(1)) * 60 + float(end.group(2))
    if end_s <= lines[-1].start:
        raise SystemExit(f"{path.name}: the video must end after the last line starts")
    if end_s > MAX_SECONDS:
        raise SystemExit(f"{path.name}: the video ends at {end_s:.1f} s, over the {MAX_SECONDS:.0f} s limit")
    return lines, end_s


def schedule(lines: list[Line], end_s: float) -> list[tuple[Beat, float, float]]:
    """(beat, start s, end s) for every beat; a beat lasts until the next one starts."""
    starts = {line.number: line.start for line in lines}
    missing = sorted({b.line for b in BEATS} - set(starts))
    if missing:
        raise SystemExit(f"NARRATION.md has no line {missing[0]}, which a beat starts with")
    timed = [(beat, starts[beat.line]) for beat in BEATS]
    return [(beat, t0, timed[i + 1][1] if i + 1 < len(timed) else end_s) for i, (beat, t0) in enumerate(timed)]


def frame_of(seconds: float) -> int:
    return round(seconds * FPS)
