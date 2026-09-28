#!/usr/bin/env python3
"""
Extract the minimum GTA Chinatown Wars Android files needed for reverse
engineering/mod development from a user-supplied APK.

This tool does not download or bundle game data.
"""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

TARGETS = {
    "lib/arm64-v8a/libGame.so": "libGame.so",
    "lib/arm64-v8a/libopenal.so": "libopenal.so",
    "assets/game.pak": "game.pak",
    "assets/dxt.bin": "dxt.bin",
    "assets/buttonconfig": "buttonconfig",
}

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", type=Path, help="Path to your GTA Chinatown Wars APK")
    ap.add_argument("-o", "--out", type=Path, default=Path("ctw_input"))
    args = ap.parse_args()

    if not args.apk.is_file():
        print(f"ERROR: APK not found: {args.apk}", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    found = {}
    with zipfile.ZipFile(args.apk) as zf:
        names = set(zf.namelist())
        for src, dst_name in TARGETS.items():
            if src not in names:
                continue
            dst = args.out / dst_name
            with zf.open(src) as r, dst.open("wb") as w:
                shutil.copyfileobj(r, w)
            found[src] = {
                "output": str(dst),
                "size": dst.stat().st_size,
                "sha256": sha256(dst),
            }

    manifest = {
        "apk": str(args.apk),
        "apk_sha256": sha256(args.apk),
        "files": found,
    }
    manifest_path = args.out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    required = [
        "lib/arm64-v8a/libGame.so",
        "assets/game.pak",
        "assets/dxt.bin",
    ]
    missing = [x for x in required if x not in found]

    print(f"manifest: {manifest_path}")
    for src, meta in found.items():
        print(f"OK {src} -> {meta['output']}  {meta['size']} bytes  {meta['sha256']}")
    if missing:
        print("MISSING REQUIRED:")
        for item in missing:
            print(f"  - {item}")
        return 1

    print("CTW_INGEST_GREEN")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
