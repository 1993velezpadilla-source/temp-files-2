import argparse
import datetime
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

import wifi_lab


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def make_bundle(output, capture="", bssid=""):
    created = datetime.datetime.now().astimezone().isoformat()
    output = Path(output)
    if output.suffix.lower() != ".zip":
        output = output.with_suffix(".zip")

    with tempfile.TemporaryDirectory(prefix="wifi_lab_bundle_") as td:
        root = Path(td)

        networks, scan_raw = wifi_lab.scan_networks()
        readiness = wifi_lab.readiness_check()
        diagnostics = wifi_lab.adapter_diagnostics()

        payload = {
            "created_at": created,
            "app_version": wifi_lab.APP_VERSION,
            "scope": "Authorized classroom/home-lab evidence bundle",
            "target_bssid": bssid,
            "scan": networks,
            "readiness": readiness,
            "diagnostics": diagnostics,
        }

        if not networks:
            payload["scan_raw_excerpt"] = scan_raw[:2000]

        if capture:
            c = Path(capture)
            payload["capture_path"] = str(c)
            payload["capture_exists"] = c.exists()
            if c.exists():
                payload["capture_sha256"] = sha256(c)
                payload["capture_statistics"] = wifi_lab.capture_statistics(capture)
                payload["capture_analysis"] = wifi_lab.analyze_capture(capture, bssid or None)
                payload["capture_quality"] = wifi_lab.capture_quality(capture, bssid)
                payload["passive_ap_profile"] = wifi_lab.passive_ap_profiles(capture)
                if bssid:
                    payload["target_station_summary"] = wifi_lab.anonymized_station_summary(capture, bssid)

                evidence_dir = root / "evidence"
                evidence_dir.mkdir(exist_ok=True)
                shutil.copy2(c, evidence_dir / c.name)

        report_path = root / "exam_report.json"
        wifi_lab.save_report(payload, str(report_path))

        try:
            markdown = wifi_lab.export_markdown_from_json(str(report_path), str(root / "exam_report.md"))
        except Exception as e:
            (root / "markdown_error.txt").write_text(str(e), encoding="utf-8")
            markdown = None

        files = []
        for p in sorted(root.rglob("*")):
            if p.is_file():
                files.append({
                    "path": p.relative_to(root).as_posix(),
                    "size": p.stat().st_size,
                    "sha256": sha256(p),
                })

        manifest = {
            "created_at": created,
            "app_version": wifi_lab.APP_VERSION,
            "bundle_files": files,
            "notes": [
                "This bundle records passive/authorized observations.",
                "No password cracking or forced deauthentication is performed.",
            ],
        }
        write_json(root / "manifest.json", manifest)

        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    z.write(p, p.relative_to(root).as_posix())

    return output


def main():
    ap = argparse.ArgumentParser(description="Build a portable WiFi Security Lab evidence bundle.")
    ap.add_argument("--capture", default="", help="Optional PCAP/PCAPNG file.")
    ap.add_argument("--bssid", default="", help="Optional authorized target AP BSSID.")
    ap.add_argument("--out", default="wifi_lab_exam_bundle.zip")
    args = ap.parse_args()

    out = make_bundle(args.out, args.capture, args.bssid)
    print(f"Evidence bundle saved: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
