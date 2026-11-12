"""Build the public browser page's generated files: python tools/build_page.py

The page (docs/index.html) runs the sealed package in the browser with
Pyodide. This writes, under docs/page/:

  sealed.zip    the package as the page unpacks it: sealed/*.py, the JSON and
                binary data next to them and the samples (not the local app's
                web files)
  app.css       a copy of the local app's stylesheet, which the page reuses
  presets.json  the recorded-attack presets (sealed/page.py, presets())

The zip is reproducible: sorted entries, a fixed timestamp and fixed
permissions. `--check` writes nothing and exits 1 if any file is out of date
with the source; tests/test_page.py runs the same check.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "sealed"
OUT = ROOT / "docs" / "page"
BUNDLE = OUT / "sealed.zip"
STYLESHEET = OUT / "app.css"
PRESETS = OUT / "presets.json"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def bundle_sources(package: Path = PACKAGE) -> dict[str, bytes]:
    """Archive name -> bytes, for every file the page needs."""
    paths = [*package.glob("*.py"), *package.glob("*.json"), *package.glob("*.bin"),
             *(package / "samples").glob("*.json")]
    return {path.relative_to(package.parent).as_posix(): path.read_bytes() for path in sorted(paths)}


def build_bundle(sources: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in sorted(sources):
            info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, sources[name], compresslevel=9)
    return buffer.getvalue()


def bundle_contents(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def presets_text() -> str:
    sys.path.insert(0, str(ROOT))
    from sealed.page import presets_document
    return json.dumps(presets_document(), ensure_ascii=True, indent=1) + "\n"


def expected() -> dict[Path, bytes]:
    return {STYLESHEET: (PACKAGE / "web" / "app.css").read_bytes(), PRESETS: presets_text().encode("ascii")}


def stale() -> list[str]:
    """Names of the generated files that are missing or differ from what the source gives."""
    out = []
    if not BUNDLE.is_file() or bundle_contents(BUNDLE.read_bytes()) != bundle_sources():
        out.append(BUNDLE.relative_to(ROOT).as_posix())
    for path, data in expected().items():
        if not path.is_file() or path.read_bytes() != data:
            out.append(path.relative_to(ROOT).as_posix())
    return out


def write() -> list[Path]:
    OUT.mkdir(parents=True, exist_ok=True)
    BUNDLE.write_bytes(build_bundle(bundle_sources()))
    files = expected()
    for path, data in files.items():
        path.write_bytes(data)
    return [BUNDLE, *files]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python tools/build_page.py", description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 if a generated file is stale")
    args = parser.parse_args(argv)
    if args.check:
        names = stale()
        for name in names:
            print(f"out of date: {name} (run python tools/build_page.py)")
        if not names:
            print("page files are up to date")
        return 1 if names else 0
    for path in write():
        print(f"wrote {path.relative_to(ROOT).as_posix()} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
