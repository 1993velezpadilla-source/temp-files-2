import argparse
import json
from pathlib import Path

import wifi_lab


def analyze_folder(folder):
    root = Path(folder)
    captures = sorted(list(root.glob("*.pcap")) + list(root.glob("*.pcapng")))
    results = []
    for p in captures:
        stats = wifi_lab.capture_statistics(str(p))
        profile = wifi_lab.passive_ap_profiles(str(p))
        results.append({
            "file": str(p),
            "statistics": stats,
            "ap_count": len(profile.get("aps", [])),
            "ssid_groups": profile.get("ssid_groups", []),
        })
    return {
        "folder": str(root),
        "capture_count": len(captures),
        "captures": results,
    }


def main():
    ap = argparse.ArgumentParser(description="Batch-triage PCAP/PCAPNG files for passive Wi-Fi lab evidence.")
    ap.add_argument("folder")
    ap.add_argument("--out", default="wifi_lab_batch_report.json")
    args = ap.parse_args()

    result = analyze_folder(args.folder)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Analyzed {result['capture_count']} capture(s).")
    print(f"Report saved: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
