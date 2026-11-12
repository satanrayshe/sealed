"""Assemble the video from the captured frames and the narration timings (video/SHOTS.md).

    python video/render.py plan                                  print every beat with its start, end and length
    python video/render.py draft --out OUT.mp4                   silent cut for timing: captions burned in with
                                                                 their line numbers, a running clock, OUT.srt beside it
    python video/render.py final --voice video/voice --out OUT.mp4
                                                                 one recording per narration line
    python video/render.py final --voice-file take.m4a --cuts cuts.txt --out OUT.mp4
                                                                 one long take and a cut list: one row per line,
                                                                 "<line> <start> <end>", in seconds or m:ss.s

Run video/capture.py first; its frames and manifest are read from video/work/ (or --work). The cut
is 1920x1080 at 30 fps with the narration lines burned in as captions, and it may not exceed 1:58.
A capture made with --mode dry-run carries a DRY RUN tag in the corner of every frame. `final` refuses
such a capture, and a capture older than the result files its frames show; it then writes nothing.

Final mode, per line: low rumble is cut, the silence before and after the words is trimmed, and the
line starts when its caption does. A line that runs into the next one is sped up, without changing
its pitch, by at most 20%; past that the line is named and nothing is written. The mixed voice is
levelled to -16 LUFS integrated (-1.5 dBTP) in two loudnorm passes. Needs ffmpeg and ffprobe on
PATH; crossfades need Pillow (without it, beats change with a hard cut).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from timeline import FPS, HEIGHT, MAX_SECONDS, REPO, WIDTH, WORK, frame_of, parse_narration, schedule  # noqa: E402

MAX_TEMPO = 1.20
LEAD_S = 0.05  # each recording starts this long after its caption
GAP_S = 0.15  # silence kept before the next line
WORDS_PER_S = 2.5  # pace assumed for caption chunks when no recording is given
LOUDNESS = "I=-16:TP=-1.5:LRA=11"
AUDIO_EXT = {".m4a", ".mp3", ".wav", ".aac", ".ogg", ".opus", ".flac", ".webm", ".amr", ".3gp", ".mp4", ".caf"}


def run(cmd: list[str], cwd: Path | None = None, capture: bool = False) -> str:
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if done.returncode != 0:
        raise SystemExit(f"{cmd[0]} failed (exit {done.returncode}):\n{done.stderr[-2000:]}")
    return done.stdout + done.stderr if capture else ""


def duration(path: Path) -> float:
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of",
                          "default=nw=1:nk=1", str(path)], capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        raise SystemExit(f"ffprobe could not read {path}")
    return float(out.stdout.strip().splitlines()[0])


def stamp(t: float, sep: str = ".") -> str:
    """0:00:00.00 for ASS (sep "."), 00:00:00,000 for SRT (sep ",")."""
    if sep == ",":
        ms = int(round(t * 1000))
        return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"
    cs = int(round(t * 100))
    return f"{cs // 360000}:{cs // 6000 % 60:02d}:{cs // 100 % 60:02d}.{cs % 100:02d}"


# ---- pictures -----------------------------------------------------------------------------------------------------

def ease(x: float) -> float:
    return 4 * x ** 3 if x < 0.5 else 1 - (-2 * x + 2) ** 3 / 2


def sequence(manifest: dict, sched: list, work: Path, out_dir: Path) -> list[tuple[Path, int]]:
    """(image, frames) for the whole cut, with crossfades written as extra images."""
    try:
        from PIL import Image
    except ImportError:
        Image = None
        print("Pillow is not installed: beats change with hard cuts")
    seq: list[list] = []
    for beat, t0, t1 in sched:
        items = manifest["beats"].get(beat.name)
        if not items:
            raise SystemExit(f"the capture has no frames for beat {beat.name}; run video/capture.py again")
        if [n for _, n in items].count(None) != 1 or items[-1][1] is not None:
            raise SystemExit(f"beat {beat.name}: the manifest must end each beat with one held frame")
        total = frame_of(t1) - frame_of(t0)
        hold = total - sum(n for _, n in items[:-1])
        entries = [[work / name, n] for name, n in items[:-1]] + [[work / items[-1][0], hold]]
        fade = beat.fade if seq and Image is not None else 0
        if hold < 1 or entries[0][1] <= fade:
            raise SystemExit(f"beat {beat.name} is too short ({total} frames) for its pictures; "
                             "move the next narration line later in NARRATION.md")
        if fade:
            a = Image.open(seq[-1][0]).convert("RGB")
            b = Image.open(entries[0][0]).convert("RGB")
            for j in range(fade):
                path = out_dir / f"fade-{beat.name}-{j:02d}.png"
                Image.blend(a, b, ease((j + 1) / (fade + 1))).save(path, compress_level=1)
                seq.append([path, 1])
            entries[0][1] -= fade
        seq.extend(entries)
    return [(path, n) for path, n in seq if n > 0]


def write_concat(seq: list[tuple[Path, int]], path: Path) -> None:
    rows = ["ffconcat version 1.0"]
    for image, n in seq:
        rows += [f"file '{image.resolve().as_posix()}'", f"duration {n / FPS:.6f}"]
    rows.append(f"file '{seq[-1][0].resolve().as_posix()}'")
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


# ---- captions -----------------------------------------------------------------------------------------------------

def chunks(text: str, limit: int = 62) -> list[str]:
    """A narration line cut into captions: sentences, merged while short, split at commas while long."""
    parts: list[str] = []
    for sentence in re.split(r"(?<=[.?!])\s+", text):
        while len(sentence) > limit + 16:
            cuts = [m.start() for m in re.finditer(r"[,:;] ", sentence)]
            if not cuts:
                break
            at = min(cuts, key=lambda k: abs(k - len(sentence) / 2))
            parts.append(sentence[:at + 1])
            sentence = sentence[at + 2:]
        parts.append(sentence)
    merged: list[str] = []
    for part in parts:
        if merged and len(merged[-1]) + 1 + len(part) <= limit:
            merged[-1] += " " + part
        else:
            merged.append(part)
    return merged


def caption_events(lines: list, end_s: float, spoken: dict[int, float] | None) -> list[tuple[float, float, int, str]]:
    """(start, end, line number, text) per caption. A line's captions share its spoken time by word count."""
    events = []
    for i, line in enumerate(lines):
        stop = (lines[i + 1].start if i + 1 < len(lines) else end_s) - 0.25
        pieces = chunks(line.text)
        words = [len(p.split()) for p in pieces]
        talk = spoken.get(line.number) if spoken else None
        talk = min(stop - line.start, talk if talk else sum(words) / WORDS_PER_S)
        t = line.start
        for k, (piece, w) in enumerate(zip(pieces, words)):
            last = k == len(pieces) - 1
            nxt = t + talk * w / sum(words)
            events.append((t, stop if last else nxt, line.number, piece))
            t = nxt
    return events


def ass_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("{", "(").replace("}", ")")


def write_ass(out_dir: Path, events: list, end_s: float, draft: bool, dry_run: bool) -> list[str]:
    """One subtitle file per track: the captions, the DRY RUN tag and the draft's clock. They are kept apart
    because ffmpeg's subtitle path drops an event that starts at the same instant as another one in its file."""
    head = f"""[Script Info]
ScriptType: v4.00+
PlayResX: {WIDTH}
PlayResY: {HEIGHT}
WrapStyle: 0
ScaledBorderAndShadow: yes

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Cap,Segoe UI,42,&H00EEF0F2,&H000000FF,&H1A141616,&H1A141616,0,0,0,0,100,100,0,0,3,14,0,2,200,200,44,1
Style: Tag,Segoe UI,30,&H00FFFFFF,&H000000FF,&H0012349A,&H0012349A,-1,0,0,0,100,100,2,0,3,10,0,9,40,40,26,1
Style: Clock,Consolas,26,&H00EEF0F2,&H000000FF,&H40141616,&H40141616,0,0,0,0,100,100,0,0,3,8,0,1,30,30,24,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""
    tracks: dict[str, list[str]] = {"captions": []}
    for t0, t1, number, text in events:
        prefix = "{\\c&H9FA8AA&}" + f"{number}  " + "{\\r}" if draft else ""
        tracks["captions"].append(f"Dialogue: 0,{stamp(t0)},{stamp(t1)},Cap,,0,0,0,,{prefix}{ass_text(text)}")
    if dry_run:
        tracks["tag"] = [f"Dialogue: 1,{stamp(0)},{stamp(end_s)},Tag,,0,0,0,,DRY RUN"]
    if draft:
        tracks["clock"] = [f"Dialogue: 1,{stamp(s)},{stamp(min(s + 1, end_s))},Clock,,0,0,0,,{s // 60}:{s % 60:02d}"
                           for s in range(int(end_s) + 1)]
    names = []
    for name, rows in tracks.items():
        (out_dir / f"{name}.ass").write_text(head + "\n".join(rows) + "\n", encoding="utf-8")
        names.append(f"{name}.ass")
    return names


def write_srt(path: Path, events: list) -> None:
    rows = []
    for i, (t0, t1, number, text) in enumerate(events, 1):
        rows += [str(i), f"{stamp(t0, ',')} --> {stamp(t1, ',')}", f"[{number}] {text}", ""]
    path.write_text("\n".join(rows), encoding="utf-8")


def fonts_dir(out_dir: Path) -> str:
    """A fonts folder for libass holding the caption fonts, when this system has them where Windows keeps them."""
    target = out_dir / "fonts"
    target.mkdir(exist_ok=True)
    system = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    for name in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf"):
        if (system / name).is_file() and not (target / name).exists():
            shutil.copy(system / name, target / name)
    return "fonts"


def encode_video(seq: list, subtitle_files: list[str], out_dir: Path, target: Path, end_s: float) -> None:
    write_concat(seq, out_dir / "list.ffconcat")
    total = frame_of(end_s)
    fonts = fonts_dir(out_dir)
    burn = ",".join(f"subtitles={name}:fontsdir={fonts}" for name in subtitle_files)
    vf = f"fps={FPS},scale={WIDTH}:{HEIGHT},{burn},scale=out_color_matrix=bt709:out_range=tv,format=yuv420p"
    run(["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-nostats", "-f", "concat", "-safe", "0",
         "-i", "list.ffconcat", "-vf", vf, "-frames:v", str(total), "-r", str(FPS), "-c:v", "libx264",
         "-preset", "slow", "-crf", "18", "-pix_fmt", "yuv420p", "-colorspace", "bt709", "-color_primaries", "bt709",
         "-color_trc", "bt709", "-color_range", "tv", "-threads", "2", "-filter_threads", "1", "-an",
         "-movflags", "+faststart", str(target.resolve())], cwd=out_dir)


# ---- voice --------------------------------------------------------------------------------------------------------

def seconds(text: str) -> float:
    m = re.fullmatch(r"(?:(\d+):)?(\d+(?:\.\d+)?)", text.strip())
    if not m:
        raise SystemExit(f"cut list: {text!r} is not a time in seconds or m:ss.s")
    return int(m.group(1) or 0) * 60 + float(m.group(2))


def sources(args, count: int, tmp: Path) -> dict[int, Path]:
    """One audio file per narration line, from a folder of recordings or from a long take and a cut list."""
    found: dict[int, list[Path]] = {}
    if args.voice:
        if not args.voice.is_dir():
            raise SystemExit(f"not a folder: {args.voice}")
        for p in sorted(args.voice.iterdir()):
            if p.is_file() and p.suffix.lower() in AUDIO_EXT:
                m = re.search(r"\d+", p.stem)
                if not m:
                    raise SystemExit(f"{p.name}: no line number in the file name")
                found.setdefault(int(m.group()), []).append(p)
    else:
        if not args.voice_file.is_file() or not args.cuts.is_file():
            raise SystemExit("--voice-file and --cuts must both name existing files")
        for row in args.cuts.read_text(encoding="utf-8").splitlines():
            row = row.split("#", 1)[0].strip()
            if not row:
                continue
            parts = row.replace(",", " ").split()
            if len(parts) != 3 or not parts[0].isdigit():
                raise SystemExit(f"cut list: {row!r} is not '<line> <start> <end>'")
            k, a, b = int(parts[0]), seconds(parts[1]), seconds(parts[2])
            if b <= a:
                raise SystemExit(f"cut list, line {k}: the end is not after the start")
            clip = tmp / f"cut-{k:02d}.wav"
            run(["ffmpeg", "-y", "-v", "error", "-ss", f"{a:.3f}", "-to", f"{b:.3f}", "-i", str(args.voice_file),
                 "-ac", "1", "-ar", "48000", str(clip)])
            found.setdefault(k, []).append(clip)
    problems = [f"line {k}: more than one recording" for k, v in sorted(found.items()) if len(v) > 1]
    problems += [f"there is no line {k} (lines are 1 to {count})" for k in sorted(found) if not 1 <= k <= count]
    problems += [f"line {k}: no recording" for k in range(1, count + 1) if k not in found]
    if problems:
        raise SystemExit("Recordings:\n  " + "\n  ".join(problems))
    return {k: v[0] for k, v in found.items()}


def trim(src: Path, out: Path, threshold_db: float) -> float:
    edge = f"silenceremove=start_periods=1:start_threshold={threshold_db}dB:start_silence=0.08"
    run(["ffmpeg", "-y", "-v", "error", "-i", str(src), "-af",
         f"highpass=f=80,{edge},areverse,{edge},areverse,aresample=48000", "-ac", "1", str(out)])
    return duration(out)


def loudnorm_measure(path: Path) -> dict:
    log = run(["ffmpeg", "-hide_banner", "-nostats", "-i", str(path), "-af", f"loudnorm={LOUDNESS}:print_format=json",
               "-f", "null", "-"], capture=True)
    m = re.findall(r"\{[^{}]*\"input_i\"[^{}]*\}", log)
    if not m:
        raise SystemExit("loudnorm did not report a measurement")
    return json.loads(m[-1])


def build_voice(args, lines: list, end_s: float, tmp: Path) -> tuple[Path, dict[int, float]]:
    files = sources(args, len(lines), tmp)
    placed, spoken, too_long = [], {}, []
    for i, line in enumerate(lines):
        nxt = lines[i + 1].start if i + 1 < len(lines) else end_s
        slot = nxt - line.start - LEAD_S - GAP_S
        clip = tmp / f"line{line.number:02d}.wav"
        d = trim(files[line.number], clip, args.threshold)
        if d < 0.3:
            raise SystemExit(f"line {line.number} ({files[line.number].name}): nothing louder than {args.threshold} dB; "
                             "check the recording or lower --threshold")
        tempo = max(1.0, d / slot)
        note = ""
        if tempo > MAX_TEMPO:
            too_long.append((line.number, d - slot * MAX_TEMPO))
            note = "  TOO LONG"
        elif tempo > 1.0:
            fast = tmp / f"line{line.number:02d}-fast.wav"
            run(["ffmpeg", "-y", "-v", "error", "-i", str(clip), "-af", f"atempo={tempo:.4f}", str(fast)])
            clip, note = fast, f"  sped up {100 * (tempo - 1):.0f}%"
        spoken[line.number] = d / tempo
        print(f"line {line.number:2d} at {int(line.start // 60)}:{line.start % 60:04.1f}  {d:5.2f} s spoken, "
              f"{slot:5.2f} s free{note}")
        placed.append((line.start + LEAD_S, clip))
    if too_long:
        for number, over in too_long:
            print(f"Line {number} is {over:.1f} s too long even at {MAX_TEMPO:g}x. Record it again a little faster.")
        raise SystemExit("Nothing written.")
    inputs, chains = [], []
    for j, (start, clip) in enumerate(placed):
        inputs += ["-i", str(clip)]
        chains.append(f"[{j}:a]adelay={round(start * 1000)}:all=1[a{j}]")
    mix = "".join(f"[a{j}]" for j in range(len(placed)))
    raw = tmp / "voice-mix.wav"
    run(["ffmpeg", "-y", "-v", "error", *inputs, "-filter_complex",
         ";".join(chains) + f";{mix}amix=inputs={len(placed)}:normalize=0,apad,atrim=0:{end_s:.3f}[out]",
         "-map", "[out]", "-ac", "1", "-ar", "48000", str(raw)])
    m = loudnorm_measure(raw)
    levelled = tmp / "voice.wav"
    norm = (f"loudnorm={LOUDNESS}:measured_I={m['input_i']}:measured_TP={m['input_tp']}:measured_LRA={m['input_lra']}:"
            f"measured_thresh={m['input_thresh']}:offset={m['target_offset']}:linear=true")
    run(["ffmpeg", "-y", "-v", "error", "-i", str(raw), "-af", f"{norm},aresample=48000", "-ac", "1", "-ar", "48000",
         str(levelled)])
    print(f"voice: {m['input_i']} LUFS before levelling, {loudnorm_measure(levelled)['input_i']} LUFS after")
    return levelled, spoken


# ---- commands -----------------------------------------------------------------------------------------------------

def load(work: Path) -> dict:
    path = work / "manifest.json"
    if not path.is_file():
        raise SystemExit(f"{path} not found: run video/capture.py first")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if (manifest.get("width"), manifest.get("height"), manifest.get("fps")) != (WIDTH, HEIGHT, FPS):
        raise SystemExit("the capture was made for another frame size or rate; capture again")
    return manifest


def stale_sources(manifest: dict) -> list[str]:
    """The result files shown in the frames that are missing, or were written after the capture started."""
    sources, started = manifest.get("sources"), manifest.get("started_ns")
    if not sources or not isinstance(started, int):
        return ["the manifest does not say which result files the frames show"]
    problems = []
    for name, sha256 in sources.items():
        path = Path(name) if Path(name).is_absolute() else REPO / name
        if not path.is_file():
            problems.append(f"{name} is missing")
        elif path.stat().st_mtime_ns > started or hashlib.sha256(path.read_bytes()).hexdigest() != sha256:
            problems.append(f"{name} was written after the frames were captured")
    return problems


def cmd_plan(_args) -> int:
    lines, end_s = parse_narration()
    text = {line.number: line.text for line in lines}
    print(f"{'beat':18s} {'shot':>4s} {'line':>4s} {'start':>7s} {'end':>7s} {'length':>6s}")
    for beat, t0, t1 in schedule(lines, end_s):
        print(f"{beat.name:18s} {beat.shot:4d} {beat.line:4d} {t0:7.1f} {t1:7.1f} {t1 - t0:6.1f}  {text[beat.line][:48]}")
    print(f"video ends at {int(end_s // 60)}:{end_s % 60:04.1f} ({end_s:.1f} s, limit {MAX_SECONDS:.0f} s)")
    return 0


def cmd_render(args) -> int:
    lines, end_s = parse_narration()
    sched = schedule(lines, end_s)
    work = args.work.resolve()
    manifest = load(work)
    out = args.out.resolve()
    if out.suffix.lower() != ".mp4":
        raise SystemExit("--out must name an .mp4 file")
    dry_run = manifest["mode"] != "final"
    draft = args.command == "draft"
    stale = stale_sources(manifest)
    if not draft and dry_run:
        raise SystemExit("These frames come from a dry-run capture: template-arm numbers and a DRY RUN tag on every "
                         "frame. Capture the final frames with `python video/capture.py --mode final`, then render "
                         "again. Nothing written.")
    if not draft and stale:
        raise SystemExit("These frames are older than the results they show:\n  " + "\n  ".join(stale)
                         + "\nCapture them again with `python video/capture.py --mode final`. Nothing written.")
    if stale:
        print("Note: these frames are older than the results they show (" + "; ".join(stale) + ")")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = work / "render"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)

    voice, spoken = (None, None)
    if not draft:
        voice, spoken = build_voice(args, lines, end_s, tmp)
    events = caption_events(lines, end_s, spoken)
    subtitle_files = write_ass(tmp, events, end_s, draft, dry_run)
    seq = sequence(manifest, sched, work, tmp)
    silent = out if draft else tmp / "picture.mp4"
    encode_video(seq, subtitle_files, tmp, silent, end_s)
    if draft:
        write_srt(out.with_suffix(".srt"), events)
    else:
        run(["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-i", str(silent), "-i", str(voice),
             "-map", "0:v:0", "-map", "1:a:0", "-c:v", "copy", "-af", "afade=t=out:st=%.3f:d=0.3" % (end_s - 0.3),
             "-c:a", "aac", "-b:a", "192k", "-ar", "48000", "-ac", "2", "-t", f"{end_s:.3f}",
             "-movflags", "+faststart", str(out)])
    length = duration(out)
    if length > MAX_SECONDS + 0.05:
        raise SystemExit(f"{out.name} runs {length:.2f} s, over the {MAX_SECONDS:.0f} s limit")
    extra = f" and {out.with_suffix('.srt').name}" if draft else ""
    print(f"wrote {out.name}{extra}: {length:.2f} s, {WIDTH}x{HEIGHT} at {FPS} fps"
          + (" (DRY RUN frames)" if dry_run else ""))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="print the beat table").set_defaults(handler=cmd_plan)
    for name in ("draft", "final"):
        p = sub.add_parser(name, help="silent cut with timing aids" if name == "draft" else "cut with the voice track")
        p.add_argument("--out", type=Path, required=True, help="the .mp4 to write")
        p.add_argument("--work", type=Path, default=WORK, help="the capture folder (default: video/work)")
        p.set_defaults(handler=cmd_render)
        if name == "final":
            src = p.add_mutually_exclusive_group(required=True)
            src.add_argument("--voice", type=Path, help="folder with one recording per line (line_01.m4a, ...)")
            src.add_argument("--voice-file", type=Path, help="one long take; needs --cuts")
            p.add_argument("--cuts", type=Path, help="cut list for --voice-file: '<line> <start> <end>' per row")
            p.add_argument("--threshold", type=float, default=-45.0,
                           help="level in dB below which sound counts as silence when trimming (default -45)")
    args = ap.parse_args()
    if args.command == "final" and args.voice_file and not args.cuts:
        ap.error("--voice-file needs --cuts")
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
