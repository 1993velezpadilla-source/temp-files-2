import argparse
import datetime
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


APP_VERSION = "0.2"


def run(cmd):
    try:
        p = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
        return p.returncode, p.stdout
    except Exception as e:
        return 127, f"ERROR: {e}"


def classify_security(raw):
    s = (raw or "").upper()
    if "WPA3" in s or "SAE" in s:
        mode = "WPA3"
    elif "WPA2" in s or "RSN" in s:
        mode = "WPA2"
    elif "WPA" in s:
        mode = "WPA"
    elif "WEP" in s:
        mode = "WEP"
    elif "OPEN" in s or "NONE" in s or not s.strip():
        mode = "OPEN/UNKNOWN"
    else:
        mode = "UNKNOWN"

    return {
        "mode": mode,
        "raw": raw or "",
        "wps_indicated": "WPS" in s,
        "notes": security_notes(mode),
    }


def security_notes(mode):
    return {
        "WPA3": "Modern security. WPA3-SAE is not equivalent to legacy WPA2-PSK handshake testing.",
        "WPA2": "WPA2-Personal commonly uses a four-message EAPOL key exchange after authentication.",
        "WPA": "Legacy WPA detected; document exact cipher/authentication before assessment.",
        "WEP": "Obsolete security; should be replaced rather than relied upon.",
        "OPEN/UNKNOWN": "No reliable protected-mode classification was exposed by the scanner.",
        "UNKNOWN": "Security string was not recognized; inspect raw scanner output.",
    }.get(mode, "")


def _split_nmcli(line):
    fields, buf, esc = [], [], False
    for ch in line.rstrip("\n"):
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    fields.append("".join(buf))
    return fields


def scan_windows():
    rc, out = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if rc != 0:
        return [], out

    results = []
    ssid = ""
    security = ""
    current = None

    def finish():
        nonlocal current
        if current:
            current["security_detail"] = classify_security(current.get("security"))
            results.append(current)
            current = None

    for raw in out.splitlines():
        line = raw.strip()

        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", line, re.I)
        if m:
            finish()
            ssid = m.group(1).strip()
            security = ""
            continue

        if line.lower().startswith("authentication"):
            security = line.split(":", 1)[1].strip() if ":" in line else ""
            if current:
                current["security"] = security
            continue

        m = re.match(r"BSSID\s+\d+\s*:\s*(.*)", line, re.I)
        if m:
            finish()
            current = {
                "ssid": ssid,
                "bssid": m.group(1).strip(),
                "security": security,
                "signal": "",
                "channel": "",
                "radio": "",
                "source": "netsh",
            }
            continue

        if not current:
            continue

        low = line.lower()
        if low.startswith("signal") and ":" in line:
            current["signal"] = line.split(":", 1)[1].strip()
        elif low.startswith("channel") and ":" in line:
            current["channel"] = line.split(":", 1)[1].strip()
        elif low.startswith("radio type") and ":" in line:
            current["radio"] = line.split(":", 1)[1].strip()

    finish()
    return results, out


def scan_linux():
    rc, out = run([
        "nmcli", "-t", "-f",
        "SSID,BSSID,SIGNAL,CHAN,SECURITY",
        "dev", "wifi", "list", "--rescan", "yes"
    ])
    if rc != 0:
        return [], out

    results = []
    for line in out.splitlines():
        parts = _split_nmcli(line)
        if len(parts) < 5:
            continue
        ssid, bssid, signal, channel = parts[:4]
        security = ":".join(parts[4:])
        results.append({
            "ssid": ssid,
            "bssid": bssid,
            "signal": signal,
            "channel": channel,
            "security": security,
            "radio": "",
            "source": "nmcli",
            "security_detail": classify_security(security),
        })
    return results, out


def scan_networks():
    system = platform.system().lower()
    if "windows" in system:
        return scan_windows()
    if "linux" in system:
        return scan_linux()
    return [], f"Unsupported scanner platform: {platform.system()}"


def tool_exists(name):
    return shutil.which(name) is not None


def adapter_diagnostics():
    data = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "tools": {
            "tshark": tool_exists("tshark"),
            "dumpcap": tool_exists("dumpcap"),
            "nmcli": tool_exists("nmcli"),
            "iw": tool_exists("iw"),
            "netsh": tool_exists("netsh"),
        },
        "capture_interfaces": [],
        "raw": {},
    }

    if tool_exists("tshark"):
        rc, out = run(["tshark", "-D"])
        data["raw"]["tshark_interfaces"] = out
        if rc == 0:
            for line in out.splitlines():
                m = re.match(r"\s*(\d+)\.\s+(.*)", line)
                if m:
                    data["capture_interfaces"].append({
                        "index": int(m.group(1)),
                        "description": m.group(2).strip(),
                    })

    if platform.system().lower().startswith("win") and tool_exists("netsh"):
        rc, out = run(["netsh", "wlan", "show", "drivers"])
        data["raw"]["wlan_drivers"] = out
        data["windows_wlan_driver_query_ok"] = rc == 0

    if platform.system().lower() == "linux":
        if tool_exists("iw"):
            rc, out = run(["iw", "dev"])
            data["raw"]["iw_dev"] = out
            data["iw_query_ok"] = rc == 0
        if tool_exists("nmcli"):
            rc, out = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
            data["raw"]["nmcli_devices"] = out
            data["nmcli_query_ok"] = rc == 0

    data["capture_analysis_ready"] = bool(data["tools"]["tshark"])
    data["note"] = (
        "Live 802.11 capture depends on adapter/driver support and permissions. "
        "This tool analyzes imported captures; it does not force client disconnects."
    )
    return data


def _tshark_field_names():
    if not tool_exists("tshark"):
        return set()
    rc, out = run(["tshark", "-G", "fields"])
    if rc != 0:
        return set()
    names = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            names.add(parts[2])
    return names


def _first_supported_field(available, candidates):
    for c in candidates:
        if c in available:
            return c
    return None


def _parse_int(value):
    v = (value or "").strip()
    if not v:
        return None
    first = v.split(",")[0].strip()
    try:
        return int(first, 0)
    except ValueError:
        try:
            return int(first, 16)
        except ValueError:
            return None


def classify_key_message(key_info):
    if key_info is None:
        return None

    install = bool(key_info & 0x0040)
    ack = bool(key_info & 0x0080)
    mic = bool(key_info & 0x0100)
    secure = bool(key_info & 0x0200)

    if ack and not mic:
        return 1
    if not ack and mic and not secure:
        return 2
    if ack and mic and install:
        return 3
    if not ack and mic and secure:
        return 4
    return None


def normalize_mac(value):
    return re.sub(r"[^0-9a-f]", "", (value or "").lower())


def analyze_capture(path, target_bssid=None):
    p = Path(path)
    result = {
        "capture": str(p),
        "exists": p.exists(),
        "target_bssid": target_bssid or "",
        "tool": "tshark",
        "eapol_frames": [],
        "message_counts": {"M1": 0, "M2": 0, "M3": 0, "M4": 0, "UNKNOWN": 0},
        "handshake_evidence": "NOT_ANALYZED",
        "warnings": [],
    }

    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        return result

    if not tool_exists("tshark"):
        result["warnings"].append("tshark is not installed or not on PATH.")
        return result

    available = _tshark_field_names()
    key_info_field = _first_supported_field(available, [
        "wlan_rsna_eapol.keydes.key_info",
        "eapol.keydes.key_info",
        "wlan_rsna_eapol.keydes.keyinfo",
    ])

    fields = [
        "frame.number",
        "frame.time_epoch",
        "wlan.sa",
        "wlan.da",
        "wlan.bssid",
        "eapol.type",
    ]
    if key_info_field:
        fields.append(key_info_field)

    cmd = ["tshark", "-r", str(p), "-Y", "eapol", "-T", "fields", "-E", "separator=\t"]
    for field in fields:
        cmd += ["-e", field]

    rc, out = run(cmd)
    if rc != 0:
        result["warnings"].append("tshark could not read the capture.")
        result["tshark_output"] = out
        return result

    target = normalize_mac(target_bssid)
    for line in out.splitlines():
        cols = line.split("\t")
        cols += [""] * (len(fields) - len(cols))
        row = dict(zip(fields, cols))

        if target:
            macs = {
                normalize_mac(row.get("wlan.sa")),
                normalize_mac(row.get("wlan.da")),
                normalize_mac(row.get("wlan.bssid")),
            }
            if target not in macs:
                continue

        key_info = _parse_int(row.get(key_info_field)) if key_info_field else None
        msg = classify_key_message(key_info)

        record = {
            "frame": row.get("frame.number", ""),
            "time_epoch": row.get("frame.time_epoch", ""),
            "source": row.get("wlan.sa", ""),
            "destination": row.get("wlan.da", ""),
            "bssid": row.get("wlan.bssid", ""),
            "eapol_type": row.get("eapol.type", ""),
            "key_info": row.get(key_info_field, "") if key_info_field else "",
            "message": f"M{msg}" if msg else "UNKNOWN",
        }
        result["eapol_frames"].append(record)
        result["message_counts"][record["message"]] += 1

    seen = {k for k, v in result["message_counts"].items() if k != "UNKNOWN" and v > 0}
    if {"M1", "M2", "M3", "M4"}.issubset(seen):
        result["handshake_evidence"] = "COMPLETE_4_WAY_SEQUENCE_OBSERVED"
    elif len(seen) >= 2:
        result["handshake_evidence"] = "PARTIAL_EAPOL_KEY_SEQUENCE"
    elif result["eapol_frames"]:
        result["handshake_evidence"] = "EAPOL_PRESENT_UNCLASSIFIED"
    else:
        result["handshake_evidence"] = "NO_EAPOL_FOUND"

    if not key_info_field:
        result["warnings"].append(
            "This tshark build did not expose a recognized RSN EAPOL key-info field; "
            "EAPOL frames can be listed but M1-M4 classification may be unavailable."
        )

    result["recognized_key_info_field"] = key_info_field or ""
    result["eapol_frame_count"] = len(result["eapol_frames"])
    return result


def save_report(payload, output="wifi_lab_report.json"):
    p = Path(output)
    envelope = {
        "app": "WiFi Security Lab",
        "version": APP_VERSION,
        "created_at": datetime.datetime.now().astimezone().isoformat(),
        "scope": "Authorized classroom/home-lab auditing",
        "payload": payload,
        "safety": {
            "password_cracking": False,
            "forced_deauthentication": False,
            "credential_extraction": False,
        },
    }
    p.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    return p


def print_networks(networks):
    if not networks:
        print("No networks found.")
        return
    for i, n in enumerate(networks, 1):
        sec = n.get("security_detail", {}).get("mode", n.get("security", ""))
        print(
            f"[{i:02}] {n.get('ssid') or '<hidden>'} | "
            f"{n.get('bssid') or '?'} | {sec} | "
            f"signal {n.get('signal') or '?'} | ch {n.get('channel') or '?'}"
        )


def command_scan(args):
    networks, raw = scan_networks()
    print_networks(networks)
    if args.json:
        print(json.dumps(networks, indent=2))
    if args.report:
        p = save_report({"scan": networks}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if networks else 2


def command_diag(args):
    data = adapter_diagnostics()
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"diagnostics": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0


def command_capture(args):
    data = analyze_capture(args.capture, args.bssid)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_analysis": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("eapol_frame_count", 0) else 3


def command_interactive(args):
    print(f"\nWIFI SECURITY LAB v{APP_VERSION}\n")
    networks, _ = scan_networks()
    if not networks:
        print("No networks found, or this platform/adapter does not expose scan data.")
        return 2

    print_networks(networks)
    try:
        idx = int(input("\nSelect authorized lab target: ")) - 1
        target = networks[idx]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return 2

    print("\nTARGET LOCKED")
    print(f"SSID: {target.get('ssid') or '<hidden>'}")
    print(f"BSSID: {target.get('bssid') or '?'}")
    print(f"SECURITY: {target.get('security_detail', {}).get('mode', '?')}")
    print(f"CHANNEL: {target.get('channel') or '?'}")
    print(f"SIGNAL: {target.get('signal') or '?'}")

    payload = {
        "target": target,
        "diagnostics": adapter_diagnostics(),
    }

    capture = input("\nOptional PCAP/PCAPNG path (Enter to skip): ").strip()
    if capture:
        analysis = analyze_capture(capture, target.get("bssid"))
        payload["capture_analysis"] = analysis
        print("\nCAPTURE ANALYSIS")
        print(f"EAPOL frames: {analysis.get('eapol_frame_count', 0)}")
        print(f"Handshake evidence: {analysis.get('handshake_evidence')}")
        print(f"Messages: {analysis.get('message_counts')}")

    report_path = save_report(payload, args.report or "wifi_lab_report.json")
    print(f"\nReport saved: {report_path}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Authorized Wi-Fi security lab scanner and EAPOL evidence analyzer."
    )
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="Scan nearby Wi-Fi networks.")
    s.add_argument("--json", action="store_true")
    s.add_argument("--report", default="")
    s.set_defaults(func=command_scan)

    d = sub.add_parser("diag", help="Inspect local Wi-Fi/capture tooling.")
    d.add_argument("--report", default="")
    d.set_defaults(func=command_diag)

    c = sub.add_parser("capture", help="Analyze an imported PCAP/PCAPNG for EAPOL evidence.")
    c.add_argument("capture")
    c.add_argument("--bssid", default="", help="Optional AP BSSID filter.")
    c.add_argument("--report", default="")
    c.set_defaults(func=command_capture)

    i = sub.add_parser("interactive", help="Scan, select a target and optionally analyze a capture.")
    i.add_argument("--report", default="wifi_lab_report.json")
    i.set_defaults(func=command_interactive)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        args = parser.parse_args(["interactive"])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
