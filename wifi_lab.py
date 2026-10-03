import argparse
import csv
import datetime
import json
import hashlib
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path


APP_VERSION = "1.8"


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
            "capinfos": tool_exists("capinfos"),
            "editcap": tool_exists("editcap"),
            "mergecap": tool_exists("mergecap"),
            "tcpdump": tool_exists("tcpdump"),
            "kismet": tool_exists("kismet"),
            "kismetdb_to_pcap": tool_exists("kismetdb_to_pcap"),
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




def tool_version(name):
    if not tool_exists(name):
        return ""
    probes = {
        "tshark": [[name, "--version"]],
        "dumpcap": [[name, "--version"]],
        "capinfos": [[name, "--version"]],
        "editcap": [[name, "--version"]],
        "mergecap": [[name, "--version"]],
        "nmcli": [[name, "--version"]],
        "iw": [[name, "--version"]],
        "kismet": [[name, "--version"]],
    }
    for cmd in probes.get(name, [[name, "--version"], [name, "-v"]]):
        rc, out = run(cmd)
        if rc == 0 and out.strip():
            return out.splitlines()[0].strip()
    return ""


def neighbor_snapshot():
    system = platform.system().lower()
    data = {"platform": platform.system(), "commands": {}}
    if "windows" in system:
        commands = {
            "arp": ["arp", "-a"],
            "getmac": ["getmac", "/v"],
        }
    elif "linux" in system:
        commands = {
            "ip_neigh": ["ip", "neigh"],
        }
    else:
        commands = {}

    for name, cmd in commands.items():
        rc, out = run(cmd)
        data["commands"][name] = {"ok": rc == 0, "output": out}
    return data


def readiness_check():
    diag = adapter_diagnostics()
    networks, scan_raw = scan_networks()
    local = local_network_info()
    available = _tshark_field_names() if tool_exists("tshark") else set()

    required_field_groups = {
        "ssid": ["wlan.ssid"],
        "bssid": ["wlan.bssid"],
        "eapol": ["eapol.type"],
        "pmf_capable": ["wlan.rsn.capabilities.mfpc", "wlan_mgt.rsn.capabilities.mfpc"],
        "pmf_required": ["wlan.rsn.capabilities.mfpr", "wlan_mgt.rsn.capabilities.mfpr"],
        "wps": ["wps.ap_setup_locked", "wps.config_methods"],
        "akm": ["wlan.rsn.akms.type", "wlan_mgt.rsn.akms.type"],
        "pairwise_cipher": ["wlan.rsn.pcs.type", "wlan_mgt.rsn.pcs.type"],
    }

    support = {}
    for logical, options in required_field_groups.items():
        support[logical] = _first_supported_field(available, options) or ""

    checks = {
        "wifi_scan_available": bool(networks),
        "tshark_available": bool(diag["tools"].get("tshark")),
        "capture_interfaces_visible": bool(diag.get("capture_interfaces")),
        "local_gateway_detected": bool(local.get("gateway")),
        "ssid_field_supported": bool(support["ssid"]),
        "bssid_field_supported": bool(support["bssid"]),
        "eapol_field_supported": bool(support["eapol"]),
        "pmf_fields_supported": bool(support["pmf_capable"] or support["pmf_required"]),
        "wps_fields_supported": bool(support["wps"]),
        "rsn_fields_supported": bool(support["akm"] or support["pairwise_cipher"]),
    }

    essential = [
        checks["wifi_scan_available"],
        checks["tshark_available"],
        checks["ssid_field_supported"],
        checks["bssid_field_supported"],
        checks["eapol_field_supported"],
    ]
    if all(essential):
        status = "READY_FOR_SCAN_AND_IMPORTED_CAPTURE_ANALYSIS"
    elif checks["wifi_scan_available"]:
        status = "SCAN_READY_CAPTURE_ANALYSIS_INCOMPLETE"
    else:
        status = "NOT_READY"

    versions = {}
    for name in ["tshark", "dumpcap", "capinfos", "editcap", "mergecap", "nmcli", "iw", "kismet"]:
        v = tool_version(name)
        if v:
            versions[name] = v

    return {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "status": status,
        "checks": checks,
        "supported_fields": support,
        "tool_versions": versions,
        "network_count_visible": len(networks),
        "local_gateway": local.get("gateway", ""),
        "capture_interfaces": diag.get("capture_interfaces", []),
        "notes": [
            "A passing readiness check confirms scan/import-analysis capability, not monitor-mode support.",
            "Raw 802.11 live capture still depends on adapter, driver, operating system and permissions.",
        ],
        "scan_error_excerpt": scan_raw[:500] if not networks else "",
    }


def capture_quality(path, target_bssid=""):
    stats = capture_statistics(path)
    profile = passive_ap_profiles(path)
    handshake = analyze_capture(path, target_bssid or None)

    target_norm = normalize_mac(target_bssid)
    target_profile = None
    if target_norm:
        for ap in profile.get("aps", []):
            if normalize_mac(ap.get("bssid")) == target_norm:
                target_profile = ap
                break

    checks = {
        "file_exists": bool(stats.get("exists")),
        "frames_present": (stats.get("frame_count") or 0) > 0,
        "management_frames_present": any(
            (v or 0) > 0 for v in stats.get("management_counts", {}).values()
        ),
        "ap_profiles_present": bool(profile.get("aps")),
        "target_ap_observed": bool(target_profile) if target_bssid else None,
        "eapol_present": (handshake.get("eapol_frame_count") or 0) > 0,
        "complete_4_way_observed": handshake.get("handshake_evidence") == "COMPLETE_4_WAY_SEQUENCE_OBSERVED",
        "signal_metadata_present": any(
            ap.get("signal_dbm_avg") is not None for ap in profile.get("aps", [])
        ),
        "security_metadata_present": any(
            ap.get("akm_types") or ap.get("pairwise_cipher_types") or ap.get("group_cipher_types")
            for ap in profile.get("aps", [])
        ),
        "pmf_metadata_present": any(
            ap.get("pmf_capable") or ap.get("pmf_required") for ap in profile.get("aps", [])
        ),
        "wps_metadata_present": any(
            ap.get("wps_advertised") for ap in profile.get("aps", [])
        ),
    }

    missing = []
    if not checks["file_exists"]:
        missing.append("capture file")
    if checks["file_exists"] and not checks["frames_present"]:
        missing.append("packet frames")
    if checks["frames_present"] and not checks["management_frames_present"]:
        missing.append("802.11 management evidence")
    if target_bssid and not checks["target_ap_observed"]:
        missing.append("selected target BSSID")
    if not checks["eapol_present"]:
        missing.append("EAPOL evidence")
    elif not checks["complete_4_way_observed"]:
        missing.append("complete M1/M2/M3/M4 observation")

    core_values = [
        checks["file_exists"],
        checks["frames_present"],
        checks["management_frames_present"],
        checks["ap_profiles_present"],
        checks["eapol_present"],
    ]
    if target_bssid:
        core_values.append(checks["target_ap_observed"])

    if all(core_values) and checks["complete_4_way_observed"]:
        status = "STRONG_EVIDENCE_SET"
    elif all(core_values):
        status = "USABLE_PARTIAL_EVIDENCE"
    elif checks["frames_present"]:
        status = "CAPTURE_PRESENT_BUT_MISSING_CORE_EVIDENCE"
    else:
        status = "UNUSABLE_OR_EMPTY"

    return {
        "capture": str(path),
        "target_bssid": target_bssid,
        "status": status,
        "checks": checks,
        "missing_core_evidence": missing,
        "handshake_evidence": handshake.get("handshake_evidence"),
        "message_counts": handshake.get("message_counts"),
        "target_profile": target_profile,
        "capture_statistics": stats,
        "warnings": list(dict.fromkeys(
            (profile.get("warnings") or []) + (handshake.get("warnings") or [])
        )),
    }


def radio_capabilities():
    system = platform.system().lower()
    data = {
        "platform": platform.system(),
        "monitor_mode_detected": None,
        "monitor_mode_evidence": [],
        "capture_linktypes": {},
        "notes": [],
    }

    if "linux" in system and tool_exists("iw"):
        rc, out = run(["iw", "list"])
        data["iw_list_ok"] = rc == 0
        if rc == 0:
            in_modes = False
            monitor = False
            for raw in out.splitlines():
                stripped = raw.strip()
                if stripped == "Supported interface modes:":
                    in_modes = True
                    continue
                if in_modes:
                    if raw and not raw.startswith("\t") and not raw.startswith(" "):
                        in_modes = False
                    elif stripped.startswith("*"):
                        mode = stripped.lstrip("*").strip()
                        if mode:
                            data["monitor_mode_evidence"].append(mode)
                        if mode == "monitor":
                            monitor = True
            data["monitor_mode_detected"] = monitor
        else:
            data["notes"].append("iw list failed; monitor-mode capability was not determined.")

    elif "windows" in system:
        if tool_exists("netsh"):
            rc, out = run(["netsh", "wlan", "show", "drivers"])
            data["netsh_driver_query_ok"] = rc == 0
            data["driver_excerpt"] = out[:4000]
        data["notes"].append(
            "Windows raw 802.11 capture support is driver-dependent; a normal Wi-Fi scan does not prove monitor-mode capability."
        )

    elif "darwin" in system:
        data["notes"].append(
            "macOS monitor/raw-capture capability depends on interface and OS permissions; this checker does not change interface mode."
        )

    if tool_exists("dumpcap"):
        rc, out = run(["dumpcap", "-D"])
        if rc == 0:
            interfaces = []
            for line in out.splitlines():
                m = re.match(r"\s*(\d+)\.\s+(.*)", line)
                if m:
                    interfaces.append((m.group(1), m.group(2).strip()))
            for idx, desc in interfaces[:20]:
                lrc, lout = run(["dumpcap", "-L", "-i", idx])
                if lrc == 0:
                    data["capture_linktypes"][idx] = {
                        "interface": desc,
                        "linktypes": [x.strip() for x in lout.splitlines() if x.strip()],
                    }

    data["kismet_detected"] = tool_exists("kismet")
    data["kismetdb_converter_detected"] = tool_exists("kismetdb_to_pcap")
    data["note"] = "Capability inspection only; this command does not enable monitor mode or alter the interface."
    return data


def convert_kismetdb(input_path, output_path=""):
    src = Path(input_path)
    out = Path(output_path) if output_path else src.with_suffix(".pcapng")
    result = {
        "input": str(src),
        "output": str(out),
        "tool": "kismetdb_to_pcap",
        "ok": False,
        "input_sha256_before": "",
        "input_sha256_after": "",
        "output_sha256": "",
        "output_exists": False,
        "log": "",
    }
    if not src.exists():
        result["log"] = "Input KismetDB file does not exist."
        return result
    if not tool_exists("kismetdb_to_pcap"):
        result["log"] = "kismetdb_to_pcap is not installed or not on PATH."
        return result
    if out.exists():
        result["log"] = "Output already exists; refusing to overwrite it."
        return result

    result["input_sha256_before"] = file_sha256(src)
    rc, log = run([
        "kismetdb_to_pcap",
        "--in", str(src),
        "--out", str(out),
        "--skip-clean",
    ])
    result["log"] = log
    result["input_sha256_after"] = file_sha256(src) if src.exists() else ""
    result["output_exists"] = out.exists()
    if out.exists():
        result["output_sha256"] = file_sha256(out)
    result["ok"] = (
        rc == 0
        and out.exists()
        and result["input_sha256_before"] == result["input_sha256_after"]
    )
    return result


def minimize_capture(input_path, output_path, target_bssid=""):
    src = Path(input_path)
    out = Path(output_path)
    result = {
        "input": str(src),
        "output": str(out),
        "target_bssid": target_bssid,
        "ok": False,
        "input_sha256": "",
        "output_sha256": "",
        "filter": "",
        "log": "",
    }
    if not src.exists():
        result["log"] = "Input capture does not exist."
        return result
    if not tool_exists("tshark"):
        result["log"] = "tshark is not installed or not on PATH."
        return result
    if out.exists():
        result["log"] = "Output already exists; refusing to overwrite it."
        return result

    filt = "(wlan.fc.type == 0) || eapol"
    if target_bssid:
        filt = f"(({filt}) && (wlan.bssid == {target_bssid} || eapol))"

    result["filter"] = filt
    result["input_sha256"] = file_sha256(src)
    rc, log = run([
        "tshark", "-r", str(src),
        "-Y", filt,
        "-w", str(out),
    ])
    result["log"] = log
    if out.exists():
        result["output_sha256"] = file_sha256(out)
    result["ok"] = rc == 0 and out.exists()
    return result

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()



def pyshark_availability():
    data = {
        "installed": False,
        "version": "",
        "import_error": "",
        "tshark_available": tool_exists("tshark"),
        "note": "Optional parsing layer; PyShark delegates packet dissection to TShark.",
    }
    try:
        import pyshark  # type: ignore
        data["installed"] = True
        data["version"] = getattr(pyshark, "__version__", "") or ""
    except Exception as e:
        data["import_error"] = str(e)
    return data


def pyshark_capture_summary(path, target_bssid=""):
    p = Path(path)
    result = {
        "capture": str(p),
        "target_bssid": target_bssid,
        "backend": "pyshark",
        "available": False,
        "packet_count": 0,
        "eapol_count": 0,
        "management_count": 0,
        "layer_counts": {},
        "warnings": [],
    }
    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        return result
    try:
        import pyshark  # type: ignore
    except Exception as e:
        result["warnings"].append(f"PyShark is not installed: {e}")
        return result

    result["available"] = True
    display_filter = ""
    if target_bssid:
        display_filter = f"wlan.bssid == {target_bssid} || eapol"

    cap = None
    try:
        cap = pyshark.FileCapture(
            str(p),
            display_filter=display_filter or None,
            keep_packets=False,
            use_json=True,
            include_raw=False,
        )
        layers = {}
        packets = 0
        eapol = 0
        mgmt = 0
        for packet in cap:
            packets += 1
            layer_names = [getattr(layer, "layer_name", "") for layer in packet.layers]
            for name in layer_names:
                if name:
                    layers[name] = layers.get(name, 0) + 1
            if "eapol" in layer_names:
                eapol += 1
            try:
                wlan = packet.wlan
                fc_type = str(getattr(wlan, "fc_type", ""))
                if fc_type == "0":
                    mgmt += 1
            except Exception:
                pass

        result["packet_count"] = packets
        result["eapol_count"] = eapol
        result["management_count"] = mgmt
        result["layer_counts"] = dict(
            sorted(layers.items(), key=lambda kv: (-kv[1], kv[0]))[:50]
        )
    except Exception as e:
        result["warnings"].append(f"PyShark could not parse the capture: {e}")
    finally:
        try:
            if cap is not None:
                cap.close()
        except Exception:
            pass
    return result


def capinfos_summary(path):
    p = Path(path)
    result = {
        "capture": str(p),
        "exists": p.exists(),
        "available": tool_exists("capinfos"),
        "raw": "",
        "warnings": [],
    }
    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        return result
    if not tool_exists("capinfos"):
        result["warnings"].append("capinfos is not installed or not on PATH.")
        return result

    rc, out = run(["capinfos", str(p)])
    result["raw"] = out
    result["ok"] = rc == 0
    if rc != 0:
        result["warnings"].append("capinfos could not inspect the capture.")
    return result


def merge_capture_files(inputs, output):
    files = [Path(x) for x in inputs]
    out = Path(output)
    result = {
        "inputs": [str(x) for x in files],
        "output": str(out),
        "tool": "mergecap",
        "ok": False,
        "input_hashes": {},
        "output_sha256": "",
        "log": "",
    }
    if len(files) < 2:
        result["log"] = "At least two capture files are required."
        return result
    missing = [str(x) for x in files if not x.exists()]
    if missing:
        result["log"] = "Missing input capture(s): " + ", ".join(missing)
        return result
    if out.exists():
        result["log"] = "Output already exists; refusing to overwrite it."
        return result
    if not tool_exists("mergecap"):
        result["log"] = "mergecap is not installed or not on PATH."
        return result

    result["input_hashes"] = {str(x): file_sha256(x) for x in files}
    rc, log = run(["mergecap", "-w", str(out)] + [str(x) for x in files])
    result["log"] = log
    result["ok"] = rc == 0 and out.exists()
    if out.exists():
        result["output_sha256"] = file_sha256(out)
    return result


def trim_capture_file(input_path, output_path, start_time="", stop_time=""):
    src = Path(input_path)
    out = Path(output_path)
    result = {
        "input": str(src),
        "output": str(out),
        "start_time": start_time,
        "stop_time": stop_time,
        "tool": "editcap",
        "ok": False,
        "input_sha256": "",
        "output_sha256": "",
        "log": "",
    }
    if not src.exists():
        result["log"] = "Input capture does not exist."
        return result
    if out.exists():
        result["log"] = "Output already exists; refusing to overwrite it."
        return result
    if not tool_exists("editcap"):
        result["log"] = "editcap is not installed or not on PATH."
        return result
    if not start_time and not stop_time:
        result["log"] = "Provide --start and/or --stop."
        return result

    cmd = ["editcap"]
    if start_time:
        cmd += ["-A", start_time]
    if stop_time:
        cmd += ["-B", stop_time]
    cmd += [str(src), str(out)]

    result["input_sha256"] = file_sha256(src)
    rc, log = run(cmd)
    result["log"] = log
    result["ok"] = rc == 0 and out.exists()
    if out.exists():
        result["output_sha256"] = file_sha256(out)
    return result


def offline_toolchain_report():
    diag = adapter_diagnostics()
    return {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "wireshark_tools": {
            name: {
                "installed": bool(diag.get("tools", {}).get(name)),
                "version": tool_version(name) if diag.get("tools", {}).get(name) else "",
            }
            for name in ["tshark", "dumpcap", "capinfos", "editcap", "mergecap"]
        },
        "kismet": {
            "installed": bool(diag.get("tools", {}).get("kismet")),
            "converter": tool_exists("kismetdb_to_pcap"),
        },
        "pyshark": pyshark_availability(),
        "notes": [
            "These integrations are for offline/imported evidence analysis and packaging.",
            "No tool in this report enables password cracking or forced deauthentication.",
        ],
    }


def passive_live_capture(interface, output="passive_live.pcapng", duration_seconds=60, target_bssid=""):
    out = Path(output)
    result = {
        "interface": str(interface),
        "output": str(out),
        "duration_seconds": int(duration_seconds),
        "target_bssid": target_bssid,
        "ok": False,
        "capture_sha256": "",
        "capture_statistics": {},
        "capture_analysis": {},
        "warnings": [],
        "note": (
            "Passive capture only. This command does not enable monitor mode, "
            "transmit deauthentication frames, disconnect clients, or alter the interface."
        ),
    }

    if not tool_exists("tshark"):
        result["warnings"].append("tshark is not installed or not on PATH.")
        return result

    try:
        duration = max(1, min(int(duration_seconds), 600))
    except Exception:
        duration = 60
    result["duration_seconds"] = duration

    if out.exists():
        result["warnings"].append("Output already exists; refusing to overwrite it.")
        return result

    rc, log = run([
        "tshark",
        "-i", str(interface),
        "-a", f"duration:{duration}",
        "-w", str(out),
    ])
    result["tshark_exit_code"] = rc
    result["tshark_log"] = log[-4000:]

    if not out.exists():
        result["warnings"].append("No capture file was produced.")
        return result

    result["capture_sha256"] = file_sha256(out)
    result["capture_statistics"] = capture_statistics(out)
    result["capture_analysis"] = analyze_capture(out, target_bssid or None)
    result["ok"] = rc == 0 or result["capture_statistics"].get("frame_count", 0) > 0
    return result

def local_network_info():
    system = platform.system().lower()
    data = {
        "platform": platform.system(),
        "gateway": "",
        "commands": {},
    }

    if "windows" in system:
        commands = {
            "ipconfig": ["ipconfig", "/all"],
            "route_ipv4": ["route", "print", "-4"],
            "wlan_interfaces": ["netsh", "wlan", "show", "interfaces"],
        }
    elif "linux" in system:
        commands = {
            "ip_addr": ["ip", "addr"],
            "ip_route": ["ip", "route"],
            "nmcli_general": ["nmcli", "-t", "-f", "GENERAL.DEVICE,GENERAL.TYPE,GENERAL.STATE,IP4.ADDRESS,IP4.GATEWAY", "device", "show"],
        }
    else:
        commands = {}

    for name, cmd in commands.items():
        rc, out = run(cmd)
        data["commands"][name] = {"ok": rc == 0, "output": out}

    route_text = "\n".join(v["output"] for v in data["commands"].values())
    gateway_patterns = [
        r"Default Gateway[ .:]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
        r"\bdefault\s+via\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
        r"IP4\.GATEWAY[^:]*:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
    ]
    for pattern in gateway_patterns:
        m = re.search(pattern, route_text, re.I)
        if m:
            data["gateway"] = m.group(1)
            break

    return data


def _count_tshark_filter(path, display_filter):
    if not tool_exists("tshark"):
        return None
    rc, out = run([
        "tshark", "-r", str(path),
        "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number",
    ])
    if rc != 0:
        return None
    return sum(1 for line in out.splitlines() if line.strip())


def capture_statistics(path):
    p = Path(path)
    data = {
        "capture": str(p),
        "exists": p.exists(),
        "size_bytes": p.stat().st_size if p.exists() else 0,
        "sha256": file_sha256(p) if p.exists() else "",
        "frame_count": 0,
        "first_epoch": "",
        "last_epoch": "",
        "duration_seconds": None,
        "management_counts": {},
        "tool_support": {
            "tshark": tool_exists("tshark"),
            "capinfos": tool_exists("capinfos"),
        },
    }
    if not p.exists() or not tool_exists("tshark"):
        return data

    rc, out = run([
        "tshark", "-r", str(p),
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
    ])
    if rc == 0:
        epochs = []
        frames = 0
        for line in out.splitlines():
            if not line.strip():
                continue
            cols = line.split("\t")
            frames += 1
            if len(cols) > 1 and cols[1].strip():
                try:
                    epochs.append(float(cols[1].split(",")[0]))
                except ValueError:
                    pass
        data["frame_count"] = frames
        if epochs:
            data["first_epoch"] = f"{min(epochs):.6f}"
            data["last_epoch"] = f"{max(epochs):.6f}"
            data["duration_seconds"] = round(max(epochs) - min(epochs), 6)

    subtype_filters = {
        "association_request": "wlan.fc.type == 0 && wlan.fc.subtype == 0",
        "association_response": "wlan.fc.type == 0 && wlan.fc.subtype == 1",
        "probe_request": "wlan.fc.type == 0 && wlan.fc.subtype == 4",
        "probe_response": "wlan.fc.type == 0 && wlan.fc.subtype == 5",
        "beacon": "wlan.fc.type == 0 && wlan.fc.subtype == 8",
        "disassociation_observed": "wlan.fc.type == 0 && wlan.fc.subtype == 10",
        "authentication": "wlan.fc.type == 0 && wlan.fc.subtype == 11",
        "deauthentication_observed": "wlan.fc.type == 0 && wlan.fc.subtype == 12",
    }
    for name, filt in subtype_filters.items():
        data["management_counts"][name] = _count_tshark_filter(p, filt)

    return data


def _field_value(row, field):
    return (row.get(field, "") or "").strip()


def passive_ap_profiles(path):
    p = Path(path)
    result = {
        "capture": str(p),
        "aps": [],
        "ssid_groups": [],
        "warnings": [],
        "privacy": "Station identifiers are counted/anonymized; this report does not expose client MAC addresses.",
    }

    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        return result
    if not tool_exists("tshark"):
        result["warnings"].append("tshark is not installed or not on PATH.")
        return result

    available = _tshark_field_names()
    candidates = {
        "ssid": ["wlan.ssid"],
        "bssid": ["wlan.bssid"],
        "source": ["wlan.sa"],
        "destination": ["wlan.da"],
        "signal": ["radiotap.dbm_antsignal", "wlan.dbm_antsignal"],
        "channel": ["wlan.ds.current_channel", "radiotap.channel.freq"],
        "mfpc": ["wlan.rsn.capabilities.mfpc", "wlan_mgt.rsn.capabilities.mfpc"],
        "mfpr": ["wlan.rsn.capabilities.mfpr", "wlan_mgt.rsn.capabilities.mfpr"],
        "akm": ["wlan.rsn.akms.type", "wlan_mgt.rsn.akms.type"],
        "pairwise_cipher": ["wlan.rsn.pcs.type", "wlan_mgt.rsn.pcs.type"],
        "group_cipher": ["wlan.rsn.gcs.type", "wlan_mgt.rsn.gcs.type"],
        "wps_locked": ["wps.ap_setup_locked"],
        "wps_methods": ["wps.config_methods"],
    }
    fields = {}
    for logical, options in candidates.items():
        chosen = _first_supported_field(available, options)
        if chosen:
            fields[logical] = chosen

    required = [fields.get("ssid"), fields.get("bssid")]
    if not all(required):
        result["warnings"].append("This TShark build does not expose wlan.ssid/wlan.bssid as expected.")
        return result

    ordered = list(dict.fromkeys(fields.values()))
    cmd = [
        "tshark", "-r", str(p),
        "-Y", "wlan.fc.type == 0 && (wlan.fc.subtype == 8 || wlan.fc.subtype == 5)",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ]
    for field in ordered:
        cmd += ["-e", field]

    rc, out = run(cmd)
    if rc != 0:
        result["warnings"].append("TShark could not parse management frames.")
        return result

    profiles = {}
    for line in out.splitlines():
        cols = line.split("\t")
        cols += [""] * (len(ordered) - len(cols))
        row = dict(zip(ordered, cols))
        bssid = _field_value(row, fields["bssid"]).lower()
        if not bssid:
            continue

        prof = profiles.setdefault(bssid, {
            "bssid": bssid,
            "ssids": set(),
            "hidden_ssid_observed": False,
            "signals_dbm": [],
            "channels": set(),
            "pmf_capable": set(),
            "pmf_required": set(),
            "akm_types": set(),
            "pairwise_cipher_types": set(),
            "group_cipher_types": set(),
            "wps_advertised": False,
            "wps_setup_locked_values": set(),
            "wps_config_methods": set(),
            "management_observations": 0,
        })
        prof["management_observations"] += 1

        ssid = _field_value(row, fields["ssid"])
        if ssid:
            prof["ssids"].add(ssid)
        else:
            prof["hidden_ssid_observed"] = True

        if fields.get("signal"):
            raw = _field_value(row, fields["signal"])
            if raw:
                try:
                    prof["signals_dbm"].append(float(raw.split(",")[0]))
                except ValueError:
                    pass

        if fields.get("channel"):
            value = _field_value(row, fields["channel"])
            if value:
                prof["channels"].add(value)

        for logical, target in [
            ("mfpc", "pmf_capable"),
            ("mfpr", "pmf_required"),
            ("akm", "akm_types"),
            ("pairwise_cipher", "pairwise_cipher_types"),
            ("group_cipher", "group_cipher_types"),
            ("wps_locked", "wps_setup_locked_values"),
            ("wps_methods", "wps_config_methods"),
        ]:
            if fields.get(logical):
                value = _field_value(row, fields[logical])
                if value:
                    prof[target].add(value)

        if fields.get("wps_locked") and _field_value(row, fields["wps_locked"]):
            prof["wps_advertised"] = True
        if fields.get("wps_methods") and _field_value(row, fields["wps_methods"]):
            prof["wps_advertised"] = True

    serial = []
    for bssid, prof in sorted(profiles.items()):
        signals = prof.pop("signals_dbm")
        prof["signal_dbm_min"] = min(signals) if signals else None
        prof["signal_dbm_max"] = max(signals) if signals else None
        prof["signal_dbm_avg"] = round(sum(signals) / len(signals), 2) if signals else None

        for key in [
            "ssids", "channels", "pmf_capable", "pmf_required",
            "akm_types", "pairwise_cipher_types", "group_cipher_types",
            "wps_setup_locked_values", "wps_config_methods",
        ]:
            prof[key] = sorted(prof[key])

        if prof["pmf_required"] and any(v in {"1", "true", "True"} for v in prof["pmf_required"]):
            prof["pmf_summary"] = "REQUIRED"
        elif prof["pmf_capable"] and any(v in {"1", "true", "True"} for v in prof["pmf_capable"]):
            prof["pmf_summary"] = "CAPABLE_NOT_CONFIRMED_REQUIRED"
        else:
            prof["pmf_summary"] = "NOT_CONFIRMED"

        serial.append(prof)

    result["aps"] = serial

    groups = {}
    for prof in serial:
        for ssid in prof["ssids"]:
            g = groups.setdefault(ssid, {"ssid": ssid, "bssids": [], "security_signatures": set()})
            g["bssids"].append(prof["bssid"])
            signature = (
                tuple(prof["akm_types"]),
                tuple(prof["pairwise_cipher_types"]),
                tuple(prof["group_cipher_types"]),
                prof["pmf_summary"],
                prof["wps_advertised"],
            )
            g["security_signatures"].add(repr(signature))

    for ssid, g in sorted(groups.items()):
        signatures = g.pop("security_signatures")
        g["bssid_count"] = len(g["bssids"])
        g["multiple_bssids"] = g["bssid_count"] > 1
        g["configuration_inconsistency"] = len(signatures) > 1
        g["note"] = (
            "Multiple BSSIDs for one SSID can be normal in multi-AP/mesh deployments. "
            "Configuration inconsistency means the observed security properties differ and should be reviewed."
            if g["multiple_bssids"] else ""
        )
        result["ssid_groups"].append(g)

    result["supported_fields_used"] = fields
    return result


def anonymized_station_summary(path, target_bssid):
    p = Path(path)
    result = {
        "capture": str(p),
        "target_bssid": target_bssid,
        "unique_station_count": 0,
        "station_tokens": [],
        "note": "Tokens are one-way SHA-256 prefixes, not client MAC addresses.",
    }
    if not p.exists() or not tool_exists("tshark") or not target_bssid:
        return result

    rc, out = run([
        "tshark", "-r", str(p),
        "-Y", f"wlan.bssid == {target_bssid}",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "wlan.sa",
        "-e", "wlan.da",
        "-e", "wlan.bssid",
    ])
    if rc != 0:
        return result

    b = normalize_mac(target_bssid)
    stations = set()
    for line in out.splitlines():
        cols = line.split("\t") + ["", "", ""]
        for mac in cols[:2]:
            n = normalize_mac(mac)
            if n and n != b and n != "ffffffffffff":
                stations.add(n)

    tokens = sorted(hashlib.sha256(s.encode("ascii")).hexdigest()[:12] for s in stations)
    result["unique_station_count"] = len(tokens)
    result["station_tokens"] = tokens
    return result


def compare_capture_profiles(baseline_path, current_path):
    base = passive_ap_profiles(baseline_path)
    cur = passive_ap_profiles(current_path)

    def index(profiles):
        return {
            normalize_mac(ap.get("bssid")): ap
            for ap in profiles.get("aps", [])
            if ap.get("bssid")
        }

    a = index(base)
    b = index(cur)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    common = sorted(set(a) & set(b))

    fields = [
        "ssids",
        "channels",
        "pmf_summary",
        "akm_types",
        "pairwise_cipher_types",
        "group_cipher_types",
        "wps_advertised",
        "wps_setup_locked_values",
    ]
    changed = []
    for mac in common:
        diffs = {}
        for field in fields:
            if a[mac].get(field) != b[mac].get(field):
                diffs[field] = {
                    "baseline": a[mac].get(field),
                    "current": b[mac].get(field),
                }
        if diffs:
            changed.append({"bssid": b[mac].get("bssid"), "changes": diffs})

    def ssid_index(profiles):
        return {
            g.get("ssid"): g
            for g in profiles.get("ssid_groups", [])
            if g.get("ssid")
        }

    sa = ssid_index(base)
    sb = ssid_index(cur)
    ssid_changes = []
    for ssid in sorted(set(sa) | set(sb)):
        left = sa.get(ssid)
        right = sb.get(ssid)
        if left != right:
            ssid_changes.append({
                "ssid": ssid,
                "baseline": left,
                "current": right,
            })

    return {
        "baseline_capture": str(baseline_path),
        "current_capture": str(current_path),
        "baseline_sha256": file_sha256(baseline_path) if Path(baseline_path).exists() else "",
        "current_sha256": file_sha256(current_path) if Path(current_path).exists() else "",
        "added_bssids": [b[x].get("bssid") for x in added],
        "removed_bssids": [a[x].get("bssid") for x in removed],
        "changed_bssids": changed,
        "ssid_group_changes": ssid_changes,
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
            "ssid_group_change_count": len(ssid_changes),
        },
        "note": (
            "Changes are observational. A changed BSSID/security signature can have benign causes "
            "such as AP replacement, mesh behavior, roaming, firmware updates or configuration changes."
        ),
    }


def _md_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown_report(report):
    lines = [
        "# WiFi Security Lab Report",
        "",
        f"- App version: {report.get('version', APP_VERSION)}",
        f"- Created: {report.get('created_at', '')}",
        f"- Scope: {report.get('scope', '')}",
        "",
    ]
    payload = report.get("payload", {}) if isinstance(report, dict) else {}

    target = payload.get("target")
    if target:
        lines += [
            "## Target",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| SSID | {_md_escape(target.get('ssid') or '<hidden>')} |",
            f"| BSSID | {_md_escape(target.get('bssid') or '')} |",
            f"| Security | {_md_escape(target.get('security_detail', {}).get('mode', target.get('security', '')))} |",
            f"| Channel | {_md_escape(target.get('channel') or '')} |",
            f"| Signal | {_md_escape(target.get('signal') or '')} |",
            "",
        ]

    fingerprint = payload.get("target_fingerprint")
    if fingerprint:
        lines += [
            f"- Target fingerprint (SHA-256): `{_md_escape(fingerprint)}`",
            "",
        ]

    lock_validation = payload.get("target_lock_validation")
    if lock_validation:
        lines += [
            "## Target Revalidation",
            "",
            f"- Status: **{_md_escape(lock_validation.get('status'))}**",
            f"- Exact BSSID visible: {bool(lock_validation.get('exact_bssid_match'))}",
            f"- Same-SSID BSSID count: {len(lock_validation.get('same_ssid_bssids') or [])}",
            "",
        ]

    verdict = payload.get("exam_verdict")
    if verdict:
        lines += [
            "## Exam Evidence Verdict",
            "",
            f"- Status: **{_md_escape(verdict.get('status'))}**",
        ]
        for reason in verdict.get("reasons") or []:
            lines.append(f"- {_md_escape(reason)}")
        lines.append("")

    reconciliation = payload.get("target_capture_reconciliation")
    if reconciliation:
        lines += [
            "## Target / Capture Reconciliation",
            "",
            f"- Status: **{_md_escape(reconciliation.get('status'))}**",
        ]
        checks = reconciliation.get("checks") or {}
        for key, value in checks.items():
            lines.append(f"- {key}: {_md_escape(value)}")
        lines.append("")

    doctor = payload.get("capture_doctor")
    if doctor:
        lines += [
            "## Capture Doctor",
            "",
            f"- Status: **{_md_escape(doctor.get('status'))}**",
            f"- 802.11 frames: {doctor.get('wlan_frame_count')}",
            f"- Radiotap frames: {doctor.get('radiotap_frame_count')}",
            f"- EAPOL frames: {doctor.get('eapol_frame_count')}",
            f"- Malformed frames: {doctor.get('malformed_frame_count')}",
            "",
        ]
        for warning in doctor.get("warnings") or []:
            lines.append(f"- Warning: {_md_escape(warning)}")
        if doctor.get("warnings"):
            lines.append("")

    readiness = payload.get("readiness") or payload.get("diagnostics")
    if readiness:
        lines += [
            "## Readiness / Diagnostics",
            "",
            f"- Status: **{_md_escape(readiness.get('status', 'captured'))}**",
            "",
        ]
        for key, value in (readiness.get("checks") or {}).items():
            state = "PASS" if value else "CHECK"
            lines.append(f"- {key}: {state}")

    quality = payload.get("capture_quality")
    if quality:
        lines += [
            "",
            "## Capture Quality",
            "",
            f"- Status: **{_md_escape(quality.get('status'))}**",
            f"- Handshake evidence: {_md_escape(quality.get('handshake_evidence'))}",
            "",
        ]
        missing = quality.get("missing_core_evidence") or []
        if missing:
            lines.append("Missing core evidence:")
            for item in missing:
                lines.append(f"- {_md_escape(item)}")
        else:
            lines.append("No core-evidence gaps were reported by the analyzer.")

    analysis = payload.get("capture_analysis")
    if analysis:
        lines += [
            "",
            "## EAPOL Evidence",
            "",
            f"- Matching EAPOL frames: {analysis.get('eapol_frame_count', 0)}",
            f"- Evidence state: {_md_escape(analysis.get('handshake_evidence'))}",
            "",
            "| Message | Count |",
            "|---|---:|",
        ]
        for key in ["M1", "M2", "M3", "M4", "UNKNOWN"]:
            lines.append(f"| {key} | {analysis.get('message_counts', {}).get(key, 0)} |")

    stats = payload.get("capture_statistics")
    if stats:
        lines += [
            "",
            "## Capture Integrity",
            "",
            f"- SHA-256: {stats.get('sha256', '')}",
            f"- Size: {stats.get('size_bytes', 0)} bytes",
            f"- Frames: {stats.get('frame_count', 0)}",
            f"- Duration: {stats.get('duration_seconds')} seconds",
        ]

    chsum = payload.get("channel_security_summary")
    if chsum:
        lines += [
            "",
            "## Environment Summary",
            "",
            f"- Networks visible: {chsum.get('network_count', 0)}",
        ]
        if chsum.get("security_modes"):
            lines.append("- Security modes:")
            for item in chsum["security_modes"]:
                lines.append(f"  - {item.get('mode')}: {item.get('network_count')}")

    timeline = payload.get("timeline")
    if timeline:
        lines += [
            "",
            "## Event Timeline",
            "",
            f"- Events recorded: {timeline.get('event_count', 0)}",
            f"- Truncated: {timeline.get('truncated', False)}",
        ]
        for event in (timeline.get("events") or [])[:30]:
            lines.append(
                f"- frame {event.get('frame')}: {event.get('event')} "
                f"{event.get('source')} -> {event.get('destination')}"
            )

    findings = payload.get("security_findings") or []
    if findings:
        lines += [
            "",
            "## Defensive Findings",
            "",
        ]
        for item in findings:
            lines.append(
                f"- **{_md_escape(item.get('severity'))}** "
                f"{_md_escape(item.get('finding'))} "
                f"Recommendation: {_md_escape(item.get('recommendation'))}"
            )

    lines += [
        "",
        "## Scope Note",
        "",
        "This report documents passive/authorized lab observations. It does not claim ownership, intent, or maliciousness for observed devices.",
        "",
    ]
    return "\n".join(lines)



def _html_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_html_report(report):
    payload = report.get("payload", {}) if isinstance(report, dict) else {}
    target = payload.get("target") or {}
    verdict = payload.get("exam_verdict") or {}
    quality = payload.get("capture_quality") or {}
    analysis = payload.get("capture_analysis") or {}
    findings = payload.get("security_findings") or []
    stats = payload.get("capture_statistics") or {}
    readiness = payload.get("readiness") or {}

    def row(label, value):
        return (
            "<tr><th>" + _html_escape(label) + "</th><td>" +
            _html_escape(value if value not in (None, "") else "—") +
            "</td></tr>"
        )

    finding_rows = []
    for item in findings:
        finding_rows.append(
            "<tr>"
            "<td>" + _html_escape(item.get("severity", "")) + "</td>"
            "<td>" + _html_escape(item.get("category", "")) + "</td>"
            "<td>" + _html_escape(item.get("finding", "")) + "</td>"
            "<td>" + _html_escape(item.get("recommendation", "")) + "</td>"
            "</tr>"
        )
    if not finding_rows:
        finding_rows.append("<tr><td colspan='4'>No findings recorded.</td></tr>")

    counts = analysis.get("message_counts") or {}
    eapol_rows = "".join(
        "<tr><th>" + key + "</th><td>" + _html_escape(counts.get(key, 0)) + "</td></tr>"
        for key in ["M1", "M2", "M3", "M4", "UNKNOWN"]
    )

    target_rows = "".join([
        row("SSID", target.get("ssid") or "<hidden>"),
        row("BSSID", target.get("bssid")),
        row("Security", (target.get("security_detail") or {}).get("mode") or target.get("security")),
        row("Channel", target.get("channel")),
        row("Signal", target.get("signal")),
    ])

    capture_rows = "".join([
        row("Verdict", verdict.get("status")),
        row("Capture quality", quality.get("status")),
        row("Handshake evidence", analysis.get("handshake_evidence")),
        row("EAPOL frames", analysis.get("eapol_frame_count", 0)),
        row("Capture SHA-256", stats.get("sha256")),
        row("Frames", stats.get("frame_count")),
        row("Duration (seconds)", stats.get("duration_seconds")),
    ])

    readiness_rows = "".join([
        row("Readiness", readiness.get("status")),
        row("Visible networks", readiness.get("network_count_visible")),
        row("Local gateway", readiness.get("local_gateway")),
    ])

    created = report.get("created_at", "")
    version = report.get("version", APP_VERSION)
    scope = report.get("scope", "")

    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Security Lab Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f5f7;color:#17191c}
main{max-width:980px;margin:24px auto;padding:0 16px 48px}
header{background:#111820;color:#fff;padding:24px;border-radius:14px}
section{background:#fff;margin-top:16px;padding:20px;border-radius:12px;border:1px solid #ddd}
h1,h2{margin-top:0}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;vertical-align:top;padding:9px;border-bottom:1px solid #e5e5e5}
th{width:220px}
.small{opacity:.75;font-size:.92rem}
code{word-break:break-all}
.badge{display:inline-block;padding:4px 9px;border-radius:999px;background:#eceff3;font-weight:700}
</style>
</head>
<body><main>
<header>
<h1>WiFi Security Lab Report</h1>
<div>Version """ + _html_escape(version) + """</div>
<div class="small">""" + _html_escape(created) + """</div>
<div class="small">""" + _html_escape(scope) + """</div>
</header>
<section><h2>Authorized Target</h2><table>""" + target_rows + """</table></section>
<section><h2>Environment Readiness</h2><table>""" + readiness_rows + """</table></section>
<section><h2>Evidence Result</h2><table>""" + capture_rows + """</table></section>
<section><h2>EAPOL Key Messages Observed</h2><table>""" + eapol_rows + """</table></section>
<section><h2>Security Findings</h2>
<table>
<tr><th>Severity</th><th>Category</th><th>Finding</th><th>Recommendation</th></tr>
""" + "".join(finding_rows) + """
</table></section>
<section><h2>Scope</h2>
<p>This report documents passive and authorized classroom/home-lab observations.
It does not perform password cracking, forced deauthentication, or credential extraction.</p>
</section>
</main></body></html>"""


def export_html_from_json(json_path, output_path=""):
    p = Path(json_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    out = Path(output_path) if output_path else p.with_suffix(".html")
    out.write_text(render_html_report(data), encoding="utf-8")
    return out

def export_markdown_from_json(json_path, output_path=""):
    p = Path(json_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    out = Path(output_path) if output_path else p.with_suffix(".md")
    out.write_text(render_markdown_report(data), encoding="utf-8")
    return out




def channel_security_summary(networks=None):
    if networks is None:
        networks, _ = scan_networks()

    channels = {}
    security = {}
    for net in networks:
        ch = str(net.get("channel") or "unknown")
        mode = (net.get("security_detail") or {}).get("mode") or net.get("security") or "UNKNOWN"
        channels[ch] = channels.get(ch, 0) + 1
        security[mode] = security.get(mode, 0) + 1

    def channel_key(item):
        key = item[0]
        try:
            return (0, int(key))
        except ValueError:
            return (1, key)

    return {
        "network_count": len(networks),
        "channels": [
            {"channel": ch, "network_count": count}
            for ch, count in sorted(channels.items(), key=channel_key)
        ],
        "security_modes": [
            {"mode": mode, "network_count": count}
            for mode, count in sorted(security.items())
        ],
    }


def _station_token(mac, target_bssid=""):
    n = normalize_mac(mac)
    if not n:
        return ""
    if target_bssid and n == normalize_mac(target_bssid):
        return "TARGET_AP"
    if n == "ffffffffffff":
        return "BROADCAST"
    return "STA-" + hashlib.sha256(n.encode("ascii")).hexdigest()[:10]


def capture_timeline(path, target_bssid="", max_events=500):
    p = Path(path)
    result = {
        "capture": str(p),
        "target_bssid": target_bssid,
        "max_events": max_events,
        "events": [],
        "truncated": False,
        "warnings": [],
        "privacy": "Non-target station MAC addresses are replaced with one-way tokens.",
    }
    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        return result
    if not tool_exists("tshark"):
        result["warnings"].append("tshark is not installed or not on PATH.")
        return result

    available = _tshark_field_names()
    fields = [
        "frame.number",
        "frame.time_epoch",
        "wlan.fc.type",
        "wlan.fc.subtype",
        "wlan.sa",
        "wlan.da",
        "wlan.bssid",
        "eapol.type",
    ]
    fields = [x for x in fields if x in available or x in {
        "frame.number", "frame.time_epoch", "wlan.sa", "wlan.da", "wlan.bssid", "eapol.type"
    }]

    filt = "(wlan.fc.type == 0) || eapol"
    if target_bssid:
        filt = f"(({filt}) && (wlan.bssid == {target_bssid} || eapol))"

    cmd = [
        "tshark", "-r", str(p),
        "-Y", filt,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ]
    for field in fields:
        cmd += ["-e", field]

    rc, out = run(cmd)
    if rc != 0:
        result["warnings"].append("TShark could not build the event timeline.")
        return result

    subtype_names = {
        "0": "association_request",
        "1": "association_response",
        "4": "probe_request",
        "5": "probe_response",
        "8": "beacon",
        "10": "disassociation_observed",
        "11": "authentication",
        "12": "deauthentication_observed",
    }

    for line in out.splitlines():
        cols = line.split("\t")
        cols += [""] * (len(fields) - len(cols))
        row = dict(zip(fields, cols))

        eapol = row.get("eapol.type", "")
        subtype = row.get("wlan.fc.subtype", "")
        event_type = "eapol" if eapol else subtype_names.get(subtype, "management")
        event = {
            "frame": row.get("frame.number", ""),
            "time_epoch": row.get("frame.time_epoch", ""),
            "event": event_type,
            "source": _station_token(row.get("wlan.sa", ""), target_bssid),
            "destination": _station_token(row.get("wlan.da", ""), target_bssid),
            "bssid": "TARGET_AP" if target_bssid and normalize_mac(row.get("wlan.bssid", "")) == normalize_mac(target_bssid) else row.get("wlan.bssid", ""),
        }
        result["events"].append(event)
        if len(result["events"]) >= max_events:
            result["truncated"] = True
            break

    result["event_count"] = len(result["events"])
    return result

def build_security_findings(target=None, passive_profile=None, target_bssid=""):
    findings = []
    target = target or {}
    mode = (target.get("security_detail") or {}).get("mode") or target.get("security") or ""
    mode_upper = str(mode).upper()

    if mode_upper == "WEP":
        findings.append({
            "severity": "HIGH",
            "category": "legacy_security",
            "finding": "WEP detected.",
            "recommendation": "Replace WEP with WPA2-AES or WPA3 and rotate credentials.",
        })
    elif mode_upper == "WPA":
        findings.append({
            "severity": "HIGH",
            "category": "legacy_security",
            "finding": "Legacy WPA detected.",
            "recommendation": "Migrate to WPA2-AES or WPA3 and disable legacy TKIP where possible.",
        })
    elif mode_upper.startswith("OPEN"):
        findings.append({
            "severity": "HIGH",
            "category": "unencrypted_network",
            "finding": "Open or unclassified protection was reported by the operating-system scan.",
            "recommendation": "Confirm the AP configuration and enable modern authenticated encryption if this is not an intentional guest network.",
        })
    elif mode_upper == "WPA2":
        findings.append({
            "severity": "INFO",
            "category": "security_mode",
            "finding": "WPA2 detected.",
            "recommendation": "Prefer AES/CCMP, disable legacy compatibility modes, and use a strong unique passphrase.",
        })
    elif mode_upper == "WPA3":
        findings.append({
            "severity": "INFO",
            "category": "security_mode",
            "finding": "WPA3 detected.",
            "recommendation": "Keep firmware current and verify Protected Management Frames are configured as expected.",
        })

    aps = (passive_profile or {}).get("aps", [])
    wanted = normalize_mac(target_bssid or target.get("bssid", ""))
    ap = None
    if wanted:
        for candidate in aps:
            if normalize_mac(candidate.get("bssid")) == wanted:
                ap = candidate
                break

    if ap:
        if ap.get("wps_advertised"):
            locked_values = {str(v).lower() for v in ap.get("wps_setup_locked_values", [])}
            if "0" in locked_values or "false" in locked_values:
                sev = "MEDIUM"
                finding = "WPS was advertised and the capture indicated setup was not locked."
            else:
                sev = "LOW"
                finding = "WPS advertisement was observed; setup-lock state was not conclusively unsafe."
            findings.append({
                "severity": sev,
                "category": "wps",
                "finding": finding,
                "recommendation": "Disable WPS when it is not required and prefer normal WPA2/WPA3 enrollment.",
            })

        pmf = ap.get("pmf_summary")
        if pmf == "REQUIRED":
            findings.append({
                "severity": "INFO",
                "category": "pmf",
                "finding": "Protected Management Frames were observed as required.",
                "recommendation": "No change required based on this observation.",
            })
        elif pmf == "CAPABLE_NOT_CONFIRMED_REQUIRED":
            findings.append({
                "severity": "LOW",
                "category": "pmf",
                "finding": "Protected Management Frames capability was observed but requirement was not confirmed.",
                "recommendation": "Consider requiring PMF where client compatibility permits.",
            })
        elif pmf == "NOT_CONFIRMED":
            findings.append({
                "severity": "LOW",
                "category": "pmf",
                "finding": "Protected Management Frames were not confirmed by the imported evidence.",
                "recommendation": "Verify PMF settings directly on the authorized AP.",
            })

    for group in (passive_profile or {}).get("ssid_groups", []):
        if group.get("configuration_inconsistency"):
            findings.append({
                "severity": "MEDIUM",
                "category": "configuration_consistency",
                "finding": f"SSID {group.get('ssid')} was observed with differing security properties across BSSIDs.",
                "recommendation": "Review AP/mesh nodes to confirm that security settings are intentionally consistent.",
            })

    if not findings:
        findings.append({
            "severity": "INFO",
            "category": "insufficient_data",
            "finding": "No defensive finding could be derived from the available metadata.",
            "recommendation": "Collect/inspect additional authorized configuration evidence.",
        })

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: severity_order.get(x.get("severity"), 9))
    return findings


def zip_directory(directory, output_path=""):
    base = Path(directory)
    if not base.exists() or not base.is_dir():
        return {"ok": False, "error": "Bundle directory does not exist."}
    out = Path(output_path) if output_path else base.with_suffix(".zip")
    if out.exists():
        return {"ok": False, "error": "ZIP output already exists.", "output": str(out)}

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(base.rglob("*")):
            if item.is_file():
                zf.write(item, item.relative_to(base))

    return {
        "ok": True,
        "directory": str(base),
        "output": str(out),
        "sha256": file_sha256(out),
        "size_bytes": out.stat().st_size,
    }


def verify_bundle(directory):
    base = Path(directory)
    manifest_path = base / "manifest.json"
    result = {
        "directory": str(base),
        "manifest": str(manifest_path),
        "ok": False,
        "checks": {},
        "missing": [],
        "mismatched": [],
    }
    if not manifest_path.exists():
        result["missing"].append("manifest.json")
        return result

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    hashes = manifest.get("file_hashes", {})
    for rel, expected in hashes.items():
        p = base / rel
        if not p.exists():
            result["missing"].append(rel)
            result["checks"][rel] = False
            continue
        actual = file_sha256(p)
        ok = actual == expected
        result["checks"][rel] = ok
        if not ok:
            result["mismatched"].append({
                "file": rel,
                "expected": expected,
                "actual": actual,
            })

    result["ok"] = bool(hashes) and not result["missing"] and not result["mismatched"] and all(result["checks"].values())
    return result

def save_target_lock(target, output="wifi_target_lock.json"):
    p = Path(output)
    data = {
        "created_at": datetime.datetime.now().astimezone().isoformat(),
        "ssid": target.get("ssid", ""),
        "bssid": target.get("bssid", ""),
        "security": target.get("security", ""),
        "security_detail": target.get("security_detail", {}),
        "channel": target.get("channel", ""),
        "signal": target.get("signal", ""),
        "source": target.get("source", ""),
    }
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


def load_target_lock(path="wifi_target_lock.json"):
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def select_and_lock_target(index=None, bssid="", ssid="", output="wifi_target_lock.json"):
    networks, raw = scan_networks()
    if not networks:
        return {
            "ok": False,
            "error": "No networks found.",
            "scan_error_excerpt": raw[:500],
        }

    target = None
    candidates = []
    if bssid:
        wanted = normalize_mac(bssid)
        for net in networks:
            if normalize_mac(net.get("bssid")) == wanted:
                target = net
                break
    elif ssid:
        candidates = [
            net for net in networks
            if (net.get("ssid") or "") == ssid
        ]
        if len(candidates) == 1:
            target = candidates[0]
        elif len(candidates) > 1:
            return {
                "ok": False,
                "error": "SSID is ambiguous because multiple BSSIDs are visible.",
                "ssid": ssid,
                "candidate_count": len(candidates),
                "candidates": candidates,
                "action": "Choose the intended BSSID explicitly.",
            }
    elif index is not None:
        if 0 <= index < len(networks):
            target = networks[index]

    if target is None:
        return {
            "ok": False,
            "error": "Requested target was not present in the current scan.",
            "requested_ssid": ssid,
            "requested_bssid": bssid,
            "visible_networks": len(networks),
        }

    p = save_target_lock(target, output)
    return {
        "ok": True,
        "target": target,
        "lock_file": str(p),
    }



def target_fingerprint(target):
    target = target or {}
    canonical = "|".join([
        str(target.get("ssid") or "").strip(),
        normalize_mac(target.get("bssid")),
        str(target.get("security") or "").strip().upper(),
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_target_lock_against_scan(target_lock_path="wifi_target_lock.json"):
    target = load_target_lock(target_lock_path)
    networks, raw = scan_networks()
    result = {
        "target_file": target_lock_path,
        "target": target,
        "target_fingerprint": target_fingerprint(target) if target else "",
        "status": "NO_TARGET",
        "exact_bssid_match": None,
        "same_ssid_bssids": [],
        "security_changed": None,
        "channel_changed": None,
        "scan_error_excerpt": raw[:500] if not networks else "",
    }
    if not target:
        return result

    wanted_bssid = normalize_mac(target.get("bssid"))
    wanted_ssid = str(target.get("ssid") or "")
    exact = None
    same_ssid = []

    for net in networks:
        if wanted_ssid and str(net.get("ssid") or "") == wanted_ssid:
            same_ssid.append(net)
        if wanted_bssid and normalize_mac(net.get("bssid")) == wanted_bssid:
            exact = net

    result["same_ssid_bssids"] = same_ssid
    result["exact_bssid_match"] = exact

    if exact:
        old_sec = str(target.get("security") or "").strip().upper()
        new_sec = str(exact.get("security") or "").strip().upper()
        old_ch = str(target.get("channel") or "").strip()
        new_ch = str(exact.get("channel") or "").strip()
        result["security_changed"] = bool(old_sec and new_sec and old_sec != new_sec)
        result["channel_changed"] = bool(old_ch and new_ch and old_ch != new_ch)

        if result["security_changed"]:
            result["status"] = "SEEN_SECURITY_CHANGED"
        elif result["channel_changed"]:
            result["status"] = "SEEN_CHANNEL_CHANGED"
        else:
            result["status"] = "SEEN_EXACT"
    elif same_ssid:
        result["status"] = "SSID_SEEN_BSSID_MISSING"
    else:
        result["status"] = "NOT_SEEN"

    return result


def exam_run(ssid="", bssid="", capture_path="", target_file="wifi_target_lock.json", output_dir="wifi_exam_bundle"):
    if not ssid and not bssid:
        return {
            "ok": False,
            "status": "TARGET_REQUIRED",
            "error": "Provide the instructor-designated SSID or BSSID.",
        }

    lock = select_and_lock_target(
        bssid=bssid,
        ssid=ssid,
        output=target_file,
    )
    if not lock.get("ok"):
        return {
            "ok": False,
            "status": "TARGET_LOCK_FAILED",
            "lock": lock,
        }

    validation = validate_target_lock_against_scan(target_file)
    bundle = build_exam_bundle(
        capture_path=capture_path,
        target_lock_path=target_file,
        output_dir=output_dir,
    )

    verdict = None
    if capture_path:
        verdict = exam_verdict(lock.get("target"), capture_path)

    return {
        "ok": True,
        "status": "COMPLETE_WITH_CAPTURE" if capture_path else "TARGET_LOCKED_NO_CAPTURE",
        "target": lock.get("target"),
        "target_fingerprint": target_fingerprint(lock.get("target")),
        "target_validation": validation,
        "verdict": verdict,
        "bundle": bundle,
    }

def build_exam_bundle(capture_path="", target_lock_path="wifi_target_lock.json", output_dir="wifi_exam_bundle"):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    target = load_target_lock(target_lock_path)
    networks, scan_raw = scan_networks()
    readiness = readiness_check()
    diagnostics = adapter_diagnostics()
    local = local_network_info()
    neighbors = neighbor_snapshot()

    payload = {
        "target": target,
        "target_fingerprint": target_fingerprint(target) if target else "",
        "target_lock_validation": validate_target_lock_against_scan(target_lock_path) if target else {"status": "NO_TARGET"},
        "scan": networks,
        "channel_security_summary": channel_security_summary(networks),
        "readiness": readiness,
        "diagnostics": diagnostics,
        "radio_capabilities": radio_capabilities(),
        "offline_toolchain": offline_toolchain_report(),
        "local_network": local,
        "neighbor_snapshot": neighbors,
        "security_findings": build_security_findings(target=target),
        "preflight": exam_preflight(target_lock_path, capture_path),
        "evidence_completeness": evidence_completeness(target, capture_path) if target else {"status": "NO_TARGET", "score_percent": 0},
    }

    if capture_path:
        bssid = target.get("bssid", "") if target else ""
        payload["capture_doctor"] = capture_doctor(capture_path)
        payload["capture_statistics"] = capture_statistics(capture_path)
        payload["capinfos"] = capinfos_summary(capture_path)
        payload["pyshark_summary"] = pyshark_capture_summary(capture_path, bssid)
        payload["capture_analysis"] = analyze_capture(capture_path, bssid or None)
        payload["deauth_observation"] = deauth_observation_analysis(capture_path, bssid, 15.0)
        payload["capture_quality"] = capture_quality(capture_path, bssid)
        payload["passive_ap_profile"] = passive_ap_profiles(capture_path)
        payload["timeline"] = capture_timeline(capture_path, bssid, max_events=500)
        payload["channel_observations"] = channel_observation_summary(capture_path)
        if bssid:
            payload["target_event_timeline"] = target_event_timeline(
                capture_path, bssid, window_seconds=15.0, max_events=500
            )
        payload["security_findings"] = build_security_findings(
            target=target,
            passive_profile=payload["passive_ap_profile"],
            target_bssid=bssid,
        )
        if bssid:
            payload["target_station_summary"] = anonymized_station_summary(capture_path, bssid)
        payload["target_capture_reconciliation"] = reconcile_target_with_capture(target, capture_path) if target else {"status": "NO_TARGET"}
        payload["exam_verdict"] = exam_verdict(target, capture_path) if target else {"status": "NO_TARGET"}

    report_path = out / "exam_bundle.json"
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
    report_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    md_path = out / "exam_bundle.md"
    md_path.write_text(render_markdown_report(envelope), encoding="utf-8")

    html_path = out / "exam_bundle.html"
    html_path.write_text(render_html_report(envelope), encoding="utf-8")

    custody_path = out / "chain_of_custody.json"
    custody = chain_of_custody(
        [str(report_path), str(md_path), str(html_path)] + ([capture_path] if capture_path else []),
        output=str(custody_path),
        target_lock_path=target_lock_path,
    )

    manifest = {
        "created_at": envelope["created_at"],
        "app_version": APP_VERSION,
        "target_lock": target_lock_path,
        "capture": capture_path,
        "capture_sha256": (
            file_sha256(capture_path)
            if capture_path and Path(capture_path).exists()
            else ""
        ),
        "files": {
            "json_report": str(report_path),
            "markdown_report": str(md_path),
            "html_report": str(html_path),
            "chain_of_custody": str(custody_path),
        },
        "file_hashes": {
            "exam_bundle.json": file_sha256(report_path),
            "exam_bundle.md": file_sha256(md_path),
            "exam_bundle.html": file_sha256(html_path),
            "chain_of_custody.json": file_sha256(custody_path),
        },
        "scan_error_excerpt": scan_raw[:500] if not networks else "",
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "output_dir": str(out),
        "json_report": str(report_path),
        "markdown_report": str(md_path),
        "html_report": str(html_path),
        "chain_of_custody": str(custody_path),
        "manifest": str(manifest_path),
        "target": target,
        "capture_included": bool(capture_path),
    }


def _station_token(mac):
    n = normalize_mac(mac)
    if not n or n == "ffffffffffff":
        return ""
    return hashlib.sha256(n.encode("ascii")).hexdigest()[:12]


def target_event_timeline(path, target_bssid, window_seconds=15.0, max_events=500):
    p = Path(path)
    result = {
        "capture": str(p),
        "target_bssid": target_bssid,
        "events": [],
        "event_counts": {},
        "nearby_event_correlations": [],
        "window_seconds": float(window_seconds),
        "warnings": [],
        "note": (
            "Correlations are temporal observations only. They do not prove that one frame caused another."
        ),
    }

    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        return result
    if not target_bssid:
        result["warnings"].append("A target BSSID is required.")
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
        "wlan.fc.type",
        "wlan.fc.subtype",
        "wlan.sa",
        "wlan.da",
        "wlan.bssid",
        "eapol.type",
    ]
    if key_info_field:
        fields.append(key_info_field)

    filt = (
        f"(wlan.bssid == {target_bssid}) && "
        "((wlan.fc.type == 0) || eapol)"
    )
    cmd = [
        "tshark", "-r", str(p),
        "-Y", filt,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ]
    for field in fields:
        cmd += ["-e", field]

    rc, out = run(cmd)
    if rc != 0:
        result["warnings"].append("TShark could not build the target timeline.")
        result["tshark_output"] = out[:2000]
        return result

    subtype_names = {
        0: "association_request",
        1: "association_response",
        4: "probe_request",
        5: "probe_response",
        8: "beacon",
        10: "disassociation_observed",
        11: "authentication",
        12: "deauthentication_observed",
    }
    target_norm = normalize_mac(target_bssid)
    parsed = []

    for line in out.splitlines():
        cols = line.split("\t")
        cols += [""] * (len(fields) - len(cols))
        row = dict(zip(fields, cols))

        try:
            epoch = float((row.get("frame.time_epoch") or "0").split(",")[0])
        except ValueError:
            epoch = 0.0

        etype = ""
        details = {}
        eapol_value = (row.get("eapol.type") or "").strip()
        if eapol_value:
            key_info = _parse_int(row.get(key_info_field)) if key_info_field else None
            msg = classify_key_message(key_info)
            etype = f"eapol_m{msg}" if msg else "eapol_observed"
            details["eapol_type"] = eapol_value
            details["key_info"] = row.get(key_info_field, "") if key_info_field else ""
        else:
            try:
                subtype = int((row.get("wlan.fc.subtype") or "-1").split(",")[0], 0)
            except ValueError:
                subtype = -1
            etype = subtype_names.get(subtype, f"management_subtype_{subtype}")

        sa = row.get("wlan.sa", "")
        da = row.get("wlan.da", "")
        station_tokens = []
        for mac in (sa, da):
            n = normalize_mac(mac)
            if n and n not in {target_norm, "ffffffffffff"}:
                tok = _station_token(mac)
                if tok and tok not in station_tokens:
                    station_tokens.append(tok)

        event = {
            "frame": row.get("frame.number", ""),
            "epoch": epoch,
            "event": etype,
            "station_tokens": station_tokens,
            "details": details,
        }
        parsed.append(event)

    parsed.sort(key=lambda e: (e["epoch"], int(e["frame"] or 0)))
    if parsed:
        base = parsed[0]["epoch"]
        for event in parsed:
            event["relative_seconds"] = round(event["epoch"] - base, 6)

    counts = {}
    for event in parsed:
        counts[event["event"]] = counts.get(event["event"], 0) + 1

    disconnects = [
        e for e in parsed
        if e["event"] in {"deauthentication_observed", "disassociation_observed"}
    ]
    eapol_events = [e for e in parsed if e["event"].startswith("eapol_")]
    correlations = []
    for d in disconnects:
        for e in eapol_events:
            delta = e["epoch"] - d["epoch"]
            if 0 <= delta <= float(window_seconds):
                correlations.append({
                    "disconnect_frame": d["frame"],
                    "disconnect_event": d["event"],
                    "eapol_frame": e["frame"],
                    "eapol_event": e["event"],
                    "delta_seconds": round(delta, 6),
                    "shared_station_token": bool(
                        set(d["station_tokens"]) & set(e["station_tokens"])
                    ),
                })
                break

    result["event_counts"] = counts
    result["nearby_event_correlations"] = correlations
    result["total_events"] = len(parsed)
    result["events_truncated"] = len(parsed) > int(max_events)
    result["events"] = parsed[:int(max_events)]
    result["recognized_key_info_field"] = key_info_field or ""
    return result


def channel_observation_summary(path):
    p = Path(path)
    result = {
        "capture": str(p),
        "channels": [],
        "warnings": [],
        "note": "Passive capture counts only; this is not an RF spectrum measurement.",
    }
    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        return result
    if not tool_exists("tshark"):
        result["warnings"].append("tshark is not installed or not on PATH.")
        return result

    available = _tshark_field_names()
    channel_field = _first_supported_field(available, [
        "wlan_radio.channel",
        "wlan.ds.current_channel",
        "radiotap.channel.freq",
    ])
    signal_field = _first_supported_field(available, [
        "radiotap.dbm_antsignal",
        "wlan.dbm_antsignal",
    ])
    bssid_field = _first_supported_field(available, ["wlan.bssid"])

    if not channel_field:
        result["warnings"].append("No supported channel/frequency field was found in this TShark build.")
        return result

    fields = ["frame.number", channel_field]
    if bssid_field:
        fields.append(bssid_field)
    if signal_field:
        fields.append(signal_field)

    cmd = [
        "tshark", "-r", str(p),
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ]
    for field in fields:
        cmd += ["-e", field]

    rc, out = run(cmd)
    if rc != 0:
        result["warnings"].append("TShark could not summarize channel observations.")
        return result

    buckets = {}
    for line in out.splitlines():
        cols = line.split("\t")
        cols += [""] * (len(fields) - len(cols))
        row = dict(zip(fields, cols))
        channel = (row.get(channel_field) or "").strip()
        if not channel:
            continue
        item = buckets.setdefault(channel, {
            "channel_or_frequency": channel,
            "frame_count": 0,
            "bssids": set(),
            "signals_dbm": [],
        })
        item["frame_count"] += 1
        if bssid_field:
            b = (row.get(bssid_field) or "").strip().lower()
            if b:
                item["bssids"].add(b)
        if signal_field:
            raw = (row.get(signal_field) or "").strip()
            if raw:
                try:
                    item["signals_dbm"].append(float(raw.split(",")[0]))
                except ValueError:
                    pass

    serial = []
    for _, item in sorted(buckets.items(), key=lambda kv: (-kv[1]["frame_count"], kv[0])):
        signals = item.pop("signals_dbm")
        item["bssids"] = sorted(item["bssids"])
        item["unique_bssid_count"] = len(item["bssids"])
        item["signal_dbm_avg"] = round(sum(signals) / len(signals), 2) if signals else None
        serial.append(item)

    result["channels"] = serial
    result["channel_field"] = channel_field
    result["signal_field"] = signal_field or ""
    return result



def watch_target(ssid="", bssid="", interval_seconds=2.0, samples=30):
    interval_seconds = max(0.5, float(interval_seconds))
    samples = max(1, min(int(samples), 300))
    wanted_bssid = normalize_mac(bssid)
    observations = []
    previous_signature = None

    result = {
        "ssid": ssid,
        "bssid": bssid,
        "interval_seconds": interval_seconds,
        "requested_samples": samples,
        "observations": observations,
        "changes": [],
        "status": "NOT_SEEN",
        "note": "Uses normal operating-system Wi-Fi scans only.",
    }

    if not ssid and not bssid:
        result["status"] = "INVALID_TARGET"
        result["error"] = "Provide an SSID or BSSID."
        return result

    for i in range(samples):
        networks, raw = scan_networks()
        if wanted_bssid:
            matches = [
                n for n in networks
                if normalize_mac(n.get("bssid")) == wanted_bssid
            ]
        else:
            matches = [
                n for n in networks
                if (n.get("ssid") or "") == ssid
            ]

        stamp = datetime.datetime.now().astimezone().isoformat()
        entry = {
            "sample": i + 1,
            "timestamp": stamp,
            "match_count": len(matches),
            "matches": matches,
        }

        if len(matches) == 1:
            n = matches[0]
            signature = (
                n.get("bssid", ""),
                n.get("channel", ""),
                n.get("security", ""),
                n.get("signal", ""),
            )
            entry["state"] = "UNIQUE_MATCH"
            if previous_signature is not None and signature != previous_signature:
                result["changes"].append({
                    "timestamp": stamp,
                    "previous": {
                        "bssid": previous_signature[0],
                        "channel": previous_signature[1],
                        "security": previous_signature[2],
                        "signal": previous_signature[3],
                    },
                    "current": {
                        "bssid": signature[0],
                        "channel": signature[1],
                        "security": signature[2],
                        "signal": signature[3],
                    },
                })
            previous_signature = signature
            result["status"] = "SEEN"
        elif len(matches) > 1:
            entry["state"] = "AMBIGUOUS"
            result["status"] = "AMBIGUOUS"
        else:
            entry["state"] = "NOT_SEEN"
            if not networks:
                entry["scan_error_excerpt"] = raw[:300]

        observations.append(entry)
        if i + 1 < samples:
            time.sleep(interval_seconds)

    result["unique_match_samples"] = sum(
        1 for x in observations if x.get("state") == "UNIQUE_MATCH"
    )
    result["ambiguous_samples"] = sum(
        1 for x in observations if x.get("state") == "AMBIGUOUS"
    )
    result["missing_samples"] = sum(
        1 for x in observations if x.get("state") == "NOT_SEEN"
    )
    return result


def _signal_score(value):
    raw = str(value or "").strip().lower()
    if not raw:
        return -10000.0
    m = re.search(r"-?\d+(?:\.\d+)?", raw)
    if not m:
        return -10000.0
    number = float(m.group(0))
    if "%" in raw:
        return number
    if "dbm" in raw or number < 0:
        return number + 100.0
    return number


def find_visible_targets(query, exact=False):
    networks, raw = scan_networks()
    q = str(query or "").strip()
    if not q:
        return {
            "query": q,
            "exact": bool(exact),
            "matches": [],
            "error": "A non-empty SSID query is required.",
        }

    qfold = q.casefold()
    matches = []
    for net in networks:
        ssid = str(net.get("ssid") or "")
        folded = ssid.casefold()
        ok = folded == qfold if exact else qfold in folded
        if ok:
            item = dict(net)
            item["signal_score"] = _signal_score(item.get("signal"))
            matches.append(item)

    matches.sort(
        key=lambda n: (-n.get("signal_score", -10000.0), n.get("ssid", ""), n.get("bssid", ""))
    )
    result = {
        "query": q,
        "exact": bool(exact),
        "visible_network_count": len(networks),
        "match_count": len(matches),
        "matches": matches,
        "scan_error_excerpt": raw[:500] if not networks else "",
    }
    if matches:
        result["strongest_signal_candidate"] = matches[0]
        result["note"] = (
            "Strongest signal is only a convenience hint. In multi-AP/mesh environments, "
            "choose the BSSID the instructor identifies rather than assuming strongest means correct."
        )
    return result


def reconcile_target_with_capture(target, capture_path):
    target = target or {}
    profile = passive_ap_profiles(capture_path)
    wanted_bssid = normalize_mac(target.get("bssid"))
    wanted_ssid = str(target.get("ssid") or "")
    wanted_channel = str(target.get("channel") or "").strip()

    matched = None
    for ap in profile.get("aps", []):
        if wanted_bssid and normalize_mac(ap.get("bssid")) == wanted_bssid:
            matched = ap
            break

    checks = {
        "capture_exists": Path(capture_path).exists(),
        "target_bssid_present": bool(matched) if wanted_bssid else None,
        "target_ssid_matches": None,
        "target_channel_matches": None,
    }

    if matched is not None:
        ssids = {str(x) for x in matched.get("ssids", [])}
        if wanted_ssid:
            checks["target_ssid_matches"] = wanted_ssid in ssids

        channels = {str(x) for x in matched.get("channels", [])}
        if wanted_channel and channels:
            checks["target_channel_matches"] = wanted_channel in channels

    if not checks["capture_exists"]:
        status = "NO_CAPTURE"
    elif wanted_bssid and not checks["target_bssid_present"]:
        status = "TARGET_MISMATCH"
    elif checks["target_ssid_matches"] is False:
        status = "TARGET_METADATA_MISMATCH"
    elif checks["target_channel_matches"] is False:
        status = "TARGET_CHANNEL_CHANGED_OR_MISMATCHED"
    elif matched:
        status = "TARGET_CONFIRMED_IN_CAPTURE"
    else:
        status = "INSUFFICIENT_TARGET_METADATA"

    return {
        "status": status,
        "target": target,
        "matched_capture_profile": matched,
        "checks": checks,
        "capture": str(capture_path),
        "warnings": profile.get("warnings", []),
        "note": (
            "A channel mismatch can be benign if the AP changed channels between the operating-system scan "
            "and the capture. BSSID/SSID agreement is stronger evidence of target identity."
        ),
    }


def exam_verdict(target=None, capture_path=""):
    target = target or {}
    result = {
        "status": "NO_EVIDENCE",
        "target": target,
        "capture": capture_path,
        "reasons": [],
        "reconciliation": None,
        "capture_quality": None,
    }

    if not target:
        result["status"] = "NO_TARGET"
        result["reasons"].append("No authorized AP target is locked.")
        return result

    if not capture_path:
        result["status"] = "TARGET_ONLY"
        result["reasons"].append("Target is locked but no capture was supplied.")
        return result

    rec = reconcile_target_with_capture(target, capture_path)
    quality = capture_quality(capture_path, target.get("bssid", ""))
    result["reconciliation"] = rec
    result["capture_quality"] = quality

    if rec.get("status") in {"TARGET_MISMATCH", "TARGET_METADATA_MISMATCH"}:
        result["status"] = "MISMATCH"
        result["reasons"].append("The imported capture does not match the locked target strongly enough.")
        return result

    qstatus = quality.get("status")
    if rec.get("status") == "TARGET_CONFIRMED_IN_CAPTURE" and qstatus == "STRONG_EVIDENCE_SET":
        result["status"] = "PASS"
        result["reasons"].append("Locked target is confirmed in the capture and a complete four-way EAPOL sequence was observed.")
    elif rec.get("status") in {"TARGET_CONFIRMED_IN_CAPTURE", "TARGET_CHANNEL_CHANGED_OR_MISMATCHED"} and qstatus == "USABLE_PARTIAL_EVIDENCE":
        result["status"] = "PARTIAL"
        result["reasons"].append("Target evidence is usable but the capture is incomplete.")
    elif qstatus == "CAPTURE_PRESENT_BUT_MISSING_CORE_EVIDENCE":
        result["status"] = "NO_CORE_EVIDENCE"
        result["reasons"].append("Capture exists but required target/EAPOL evidence is missing.")
    else:
        result["status"] = "INCONCLUSIVE"
        result["reasons"].append("Available observations are insufficient for a strong exam evidence verdict.")

    return result


def export_scan_csv(output_path="wifi_scan.csv", query=""):
    networks, _ = scan_networks()
    if query:
        q = query.casefold()
        networks = [n for n in networks if q in str(n.get("ssid") or "").casefold()]

    out = Path(output_path)
    fields = ["ssid", "bssid", "security", "signal", "channel", "radio", "source"]
    with out.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        for net in networks:
            writer.writerow({k: net.get(k, "") for k in fields})

    return {
        "output": str(out),
        "row_count": len(networks),
        "sha256": file_sha256(out),
    }


def capture_doctor(path):
    p = Path(path)
    data = {
        "capture": str(p),
        "exists": p.exists(),
        "size_bytes": p.stat().st_size if p.exists() else 0,
        "sha256": file_sha256(p) if p.exists() else "",
        "status": "NOT_CHECKED",
        "checks": {},
        "encapsulation_types": [],
        "capinfos_excerpt": "",
        "warnings": [],
    }

    if not p.exists():
        data["status"] = "MISSING_FILE"
        data["warnings"].append("Capture file does not exist.")
        return data

    if not tool_exists("tshark"):
        data["status"] = "TSHARK_MISSING"
        data["warnings"].append("TShark is required for capture validation.")
        return data

    rc, out = run(["tshark", "-r", str(p), "-c", "1", "-T", "fields", "-e", "frame.number"])
    data["checks"]["tshark_readable"] = rc == 0

    stats = capture_statistics(p)
    data["checks"]["frames_present"] = (stats.get("frame_count") or 0) > 0
    data["frame_count"] = stats.get("frame_count", 0)
    data["duration_seconds"] = stats.get("duration_seconds")

    def count_filter(display_filter):
        return _count_tshark_filter(p, display_filter)

    wlan_count = count_filter("wlan")
    radiotap_count = count_filter("radiotap")
    eapol_count = count_filter("eapol")
    malformed_count = count_filter("_ws.malformed")

    data["checks"]["wlan_frames_present"] = bool(wlan_count)
    data["checks"]["radiotap_present"] = bool(radiotap_count)
    data["checks"]["eapol_present"] = bool(eapol_count)
    data["checks"]["malformed_frames_absent"] = (malformed_count == 0) if malformed_count is not None else None
    data["wlan_frame_count"] = wlan_count
    data["radiotap_frame_count"] = radiotap_count
    data["eapol_frame_count"] = eapol_count
    data["malformed_frame_count"] = malformed_count

    available = _tshark_field_names()
    encap_field = _first_supported_field(available, ["frame.encap_type"])
    if encap_field:
        rc, out = run([
            "tshark", "-r", str(p),
            "-T", "fields",
            "-E", "occurrence=f",
            "-e", encap_field,
        ])
        if rc == 0:
            values = sorted({x.strip() for x in out.splitlines() if x.strip()})
            data["encapsulation_types"] = values[:50]

    if tool_exists("capinfos"):
        rc, out = run(["capinfos", str(p)])
        data["checks"]["capinfos_readable"] = rc == 0
        data["capinfos_excerpt"] = out[:6000]
    else:
        data["checks"]["capinfos_readable"] = None

    if not data["checks"]["tshark_readable"]:
        data["status"] = "UNREADABLE_CAPTURE"
    elif not data["checks"]["frames_present"]:
        data["status"] = "EMPTY_CAPTURE"
    elif not data["checks"]["wlan_frames_present"]:
        data["status"] = "READABLE_NON_80211_CAPTURE"
    elif data["checks"]["eapol_present"]:
        data["status"] = "READY_FOR_WIFI_AND_EAPOL_ANALYSIS"
    else:
        data["status"] = "READY_FOR_WIFI_ANALYSIS_NO_EAPOL"

    if data["checks"]["malformed_frames_absent"] is False:
        data["warnings"].append("Malformed frames were reported by TShark; inspect capture quality.")
    if not data["checks"]["radiotap_present"] and data["checks"]["wlan_frames_present"]:
        data["warnings"].append(
            "802.11 frames are present but radiotap metadata was not observed; signal/channel metadata may be limited."
        )

    return data


def capture_ap_index(path, ssid_query=""):
    profile = passive_ap_profiles(path)
    q = str(ssid_query or "").casefold()
    rows = []

    for ap in profile.get("aps", []):
        ssids = [str(x) for x in ap.get("ssids", [])]
        if q and not any(q in s.casefold() for s in ssids):
            continue
        rows.append({
            "bssid": ap.get("bssid", ""),
            "ssids": ssids,
            "channels": ap.get("channels", []),
            "signal_dbm_avg": ap.get("signal_dbm_avg"),
            "pmf_summary": ap.get("pmf_summary", ""),
            "wps_advertised": ap.get("wps_advertised", False),
            "akm_types": ap.get("akm_types", []),
            "pairwise_cipher_types": ap.get("pairwise_cipher_types", []),
            "management_observations": ap.get("management_observations", 0),
        })

    rows.sort(
        key=lambda x: (
            -(x["signal_dbm_avg"] if isinstance(x.get("signal_dbm_avg"), (int, float)) else -999),
            x.get("bssid", ""),
        )
    )
    return {
        "capture": str(path),
        "ssid_query": ssid_query,
        "match_count": len(rows),
        "aps": rows,
        "warnings": profile.get("warnings", []),
        "note": (
            "This is an index of APs already present in the imported capture. "
            "It does not probe or transmit to any network."
        ),
    }


def evidence_completeness(target=None, capture_path=""):
    target = target or {}
    checks = {
        "target_present": bool(target),
        "target_bssid_present": bool(target.get("bssid")),
        "target_security_classified": bool(
            (target.get("security_detail") or {}).get("mode") or target.get("security")
        ),
        "capture_present": False,
        "capture_hash_available": False,
        "target_seen_in_capture": False,
        "eapol_present": False,
        "complete_4_way_observed": False,
        "ap_profile_available": False,
        "timeline_available": False,
    }
    details = {}
    if capture_path:
        p = Path(capture_path)
        checks["capture_present"] = p.exists()
        if p.exists():
            details["capture_sha256"] = file_sha256(p)
            checks["capture_hash_available"] = bool(details["capture_sha256"])
            bssid = target.get("bssid", "")
            quality = capture_quality(capture_path, bssid)
            analysis = analyze_capture(capture_path, bssid or None)
            profile = passive_ap_profiles(capture_path)
            timeline = target_event_timeline(capture_path, bssid) if bssid else {"total_events": 0}
            checks["target_seen_in_capture"] = (
                quality.get("checks", {}).get("target_ap_observed") is True
                if bssid else False
            )
            checks["eapol_present"] = (analysis.get("eapol_frame_count") or 0) > 0
            checks["complete_4_way_observed"] = (
                analysis.get("handshake_evidence") == "COMPLETE_4_WAY_SEQUENCE_OBSERVED"
            )
            checks["ap_profile_available"] = bool(profile.get("aps"))
            checks["timeline_available"] = (timeline.get("total_events") or 0) > 0
            details["capture_quality"] = quality.get("status")
            details["handshake_evidence"] = analysis.get("handshake_evidence")
            details["message_counts"] = analysis.get("message_counts")
    weights = {
        "target_present": 10,
        "target_bssid_present": 10,
        "target_security_classified": 10,
        "capture_present": 15,
        "capture_hash_available": 10,
        "target_seen_in_capture": 15,
        "eapol_present": 10,
        "complete_4_way_observed": 10,
        "ap_profile_available": 5,
        "timeline_available": 5,
    }
    score = sum(weights[k] for k, ok in checks.items() if ok)
    if score >= 90:
        status = "EXCELLENT_EVIDENCE_COMPLETENESS"
    elif score >= 70:
        status = "GOOD_EVIDENCE_COMPLETENESS"
    elif score >= 45:
        status = "PARTIAL_EVIDENCE_COMPLETENESS"
    else:
        status = "INSUFFICIENT_EVIDENCE_COMPLETENESS"
    missing = [k for k, ok in checks.items() if not ok]
    return {
        "score_percent": score,
        "status": status,
        "checks": checks,
        "missing": missing,
        "details": details,
        "note": "This is an evidence-completeness score, not a password-recovery probability.",
    }


def exam_preflight(target_lock_path="wifi_target_lock.json", capture_path=""):
    target = load_target_lock(target_lock_path)
    readiness = readiness_check()
    toolchain = offline_toolchain_report()
    radio = radio_capabilities()
    blockers = []
    warnings = []

    if not target:
        blockers.append("No target lock is present.")
    else:
        validation = validate_target_lock_against_scan(target_lock_path)
        if validation.get("status") not in {"SEEN_EXACT", "SEEN_CHANNEL_CHANGED"}:
            warnings.append(
                f"Locked target is not currently an exact visible match: {validation.get('status')}"
            )

    if not readiness.get("checks", {}).get("wifi_scan_available"):
        blockers.append("Normal Wi-Fi scanning is not available on this machine.")
    if capture_path and not Path(capture_path).exists():
        blockers.append("The requested capture file does not exist.")
    if capture_path and not tool_exists("tshark"):
        blockers.append("TShark is required for imported capture analysis.")
    if not tool_exists("tshark"):
        warnings.append("No TShark detected; scan-only mode can still work.")
    if radio.get("monitor_mode_detected") is False:
        warnings.append(
            "Monitor mode was not detected. This does not prevent imported-capture analysis."
        )

    completeness = evidence_completeness(target, capture_path) if target else {
        "score_percent": 0,
        "status": "NO_TARGET",
        "checks": {},
        "missing": ["target_present"],
        "details": {},
    }

    status = "READY" if not blockers else "BLOCKED"
    if status == "READY" and warnings:
        status = "READY_WITH_WARNINGS"

    return {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "status": status,
        "blockers": blockers,
        "warnings": warnings,
        "target": target,
        "readiness": readiness,
        "toolchain": toolchain,
        "radio_capabilities": radio,
        "evidence_completeness": completeness,
    }


def chain_of_custody(paths, output="chain_of_custody.json", target_lock_path="wifi_target_lock.json"):
    items = []
    for raw in paths:
        p = Path(raw)
        item = {
            "path": str(p),
            "exists": p.exists(),
            "size_bytes": p.stat().st_size if p.exists() and p.is_file() else 0,
            "sha256": file_sha256(p) if p.exists() and p.is_file() else "",
            "modified_epoch": p.stat().st_mtime if p.exists() else None,
        }
        items.append(item)

    target = load_target_lock(target_lock_path)
    record = {
        "app": "WiFi Security Lab",
        "version": APP_VERSION,
        "created_at": datetime.datetime.now().astimezone().isoformat(),
        "host": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
        },
        "target": target,
        "target_fingerprint": target_fingerprint(target) if target else "",
        "evidence": items,
        "note": (
            "Hashes document the exact files inspected at the time this record was generated."
        ),
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record["record_sha256"] = hashlib.sha256(canonical).hexdigest()
    out = Path(output)
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return {
        "output": str(out),
        "record_sha256": record["record_sha256"],
        "evidence_count": len(items),
        "record": record,
    }


def deauth_observation_analysis(path, target_bssid="", correlation_window=15.0):
    p = Path(path)
    result = {
        "capture": str(p),
        "target_bssid": target_bssid,
        "correlation_window_seconds": float(correlation_window),
        "deauthentication_observed": 0,
        "disassociation_observed": 0,
        "authentication_observed": 0,
        "association_requests": 0,
        "eapol_frames": 0,
        "correlated_reconnect_sequences": [],
        "status": "NOT_ANALYZED",
        "warnings": [],
        "note": (
            "Passive observation only. This function never transmits deauthentication "
            "or disassociation frames."
        ),
    }

    if not p.exists():
        result["warnings"].append("Capture file does not exist.")
        result["status"] = "NO_CAPTURE"
        return result
    if not tool_exists("tshark"):
        result["warnings"].append("tshark is not installed or not on PATH.")
        result["status"] = "TSHARK_MISSING"
        return result

    bssid_filter = f" && wlan.bssid == {target_bssid}" if target_bssid else ""

    filters = {
        "deauthentication_observed": f"wlan.fc.type == 0 && wlan.fc.subtype == 12{bssid_filter}",
        "disassociation_observed": f"wlan.fc.type == 0 && wlan.fc.subtype == 10{bssid_filter}",
        "authentication_observed": f"wlan.fc.type == 0 && wlan.fc.subtype == 11{bssid_filter}",
        "association_requests": f"wlan.fc.type == 0 && wlan.fc.subtype == 0{bssid_filter}",
        "eapol_frames": f"eapol{bssid_filter}",
    }
    for key, filt in filters.items():
        count = _count_tshark_filter(p, filt)
        result[key] = count if count is not None else 0

    timeline = target_event_timeline(
        p,
        target_bssid,
        window_seconds=correlation_window,
        max_events=5000,
    ) if target_bssid else capture_timeline(p, "", max_events=5000)

    events = timeline.get("events", [])
    deauths = [
        e for e in events
        if e.get("event") in {"deauthentication_observed", "disassociation_observed"}
    ]

    reconnects = []
    for d in deauths:
        seq = {
            "disconnect_frame": d.get("frame"),
            "disconnect_event": d.get("event"),
            "disconnect_relative_seconds": d.get("relative_seconds"),
            "station_tokens": d.get("station_tokens", []),
            "auth_frame": None,
            "assoc_frame": None,
            "first_eapol_frame": None,
            "delta_to_eapol_seconds": None,
        }
        d_epoch = float(d.get("epoch") or 0.0)
        for e in events:
            e_epoch = float(e.get("epoch") or 0.0)
            if e_epoch < d_epoch:
                continue
            delta = e_epoch - d_epoch
            if delta > float(correlation_window):
                break

            shared = True
            dtok = set(d.get("station_tokens", []))
            etok = set(e.get("station_tokens", []))
            if dtok and etok:
                shared = bool(dtok & etok)

            if not shared:
                continue

            if seq["auth_frame"] is None and e.get("event") == "authentication":
                seq["auth_frame"] = e.get("frame")
            elif seq["assoc_frame"] is None and e.get("event") == "association_request":
                seq["assoc_frame"] = e.get("frame")
            elif seq["first_eapol_frame"] is None and str(e.get("event", "")).startswith("eapol_"):
                seq["first_eapol_frame"] = e.get("frame")
                seq["delta_to_eapol_seconds"] = round(delta, 6)
                break

        if seq["first_eapol_frame"] is not None:
            reconnects.append(seq)

    result["correlated_reconnect_sequences"] = reconnects

    if reconnects:
        result["status"] = "DISCONNECT_TO_REAUTH_SEQUENCE_OBSERVED"
    elif result["deauthentication_observed"] or result["disassociation_observed"]:
        result["status"] = "DISCONNECT_FRAMES_OBSERVED_NO_EAPOL_CORRELATION"
    else:
        result["status"] = "NO_DISCONNECT_FRAMES_OBSERVED"

    return result


def load_verified_exam_result(path, target=None):
    p = Path(path)
    target = target or {}
    result = {
        "source": str(p),
        "status": "NO_RESULT",
        "target_ssid": "",
        "target_bssid": "",
        "result_value": "",
        "result_sha256": "",
        "source_sha256": "",
        "warnings": [],
    }

    if not p.exists():
        result["warnings"].append("Result file does not exist.")
        return result

    result["source_sha256"] = file_sha256(p)

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        result["status"] = "INVALID_RESULT"
        result["warnings"].append("Result file is not valid JSON: " + str(e))
        return result

    ssid = str(data.get("target_ssid", ""))
    bssid = str(data.get("target_bssid", ""))
    value = str(data.get("result_value", ""))

    result["target_ssid"] = ssid
    result["target_bssid"] = bssid

    if not value:
        result["status"] = "EMPTY_RESULT"
        result["warnings"].append("Result value is empty.")
        return result

    expected_bssid = normalize_mac(target.get("bssid", ""))
    supplied_bssid = normalize_mac(bssid)
    expected_ssid = str(target.get("ssid", "") or "")

    if expected_bssid and supplied_bssid != expected_bssid:
        result["status"] = "TARGET_MISMATCH"
        result["warnings"].append("Result BSSID does not match the locked target.")
        return result

    if expected_ssid and ssid and ssid != expected_ssid:
        result["status"] = "TARGET_MISMATCH"
        result["warnings"].append("Result SSID does not match the locked target.")
        return result

    result["result_value"] = value
    result["result_sha256"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
    result["status"] = "RESULT_VERIFIED"
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










def command_channels(args):
    networks, _ = scan_networks()
    data = channel_security_summary(networks)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"channel_security_summary": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if networks else 2


def command_timeline(args):
    data = capture_timeline(args.capture, args.bssid, args.max_events)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"timeline": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("event_count", 0) else 3

def command_findings(args):
    target = load_target_lock(args.target_file)
    profile = passive_ap_profiles(args.capture) if args.capture else {}
    data = {
        "target": target,
        "capture": args.capture,
        "findings": build_security_findings(
            target=target,
            passive_profile=profile,
            target_bssid=target.get("bssid", "") if target else "",
        ),
    }
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"security_findings": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0


def command_verify_bundle(args):
    data = verify_bundle(args.directory)
    print(json.dumps(data, indent=2))
    return 0 if data.get("ok") else 8


def command_zip_bundle(args):
    data = zip_directory(args.directory, args.output)
    print(json.dumps(data, indent=2))
    return 0 if data.get("ok") else 9

def command_radio(args):
    data = radio_capabilities()
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"radio_capabilities": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0


def command_kismet_import(args):
    data = convert_kismetdb(args.input, args.output)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"kismet_import": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("ok") else 6


def command_minimize(args):
    data = minimize_capture(args.input, args.output, args.bssid)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_minimization": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("ok") else 7

def command_selftest(args):
    checks = {}

    checks["security_wpa3"] = classify_security("WPA3-Personal").get("mode") == "WPA3"
    checks["security_wpa2"] = classify_security("WPA2-Personal").get("mode") == "WPA2"
    checks["security_wep"] = classify_security("WEP").get("mode") == "WEP"
    checks["mac_normalize"] = normalize_mac("AA:BB:cc:DD:ee:FF") == "aabbccddeeff"
    checks["nmcli_split"] = _split_nmcli(r"Lab\:SSID:aa\:bb\:cc\:dd\:ee\:ff:80:6:WPA2")[:2] == [
        "Lab:SSID", "aa:bb:cc:dd:ee:ff"
    ]

    dummy = {
        "version": APP_VERSION,
        "created_at": "selftest",
        "scope": "selftest",
        "payload": {
            "target": {
                "ssid": "TEST",
                "bssid": "00:11:22:33:44:55",
                "security": "WPA2",
                "security_detail": {"mode": "WPA2"},
                "channel": "6",
                "signal": "100%",
            }
        },
    }
    md = render_markdown_report(dummy)
    checks["markdown_render"] = "# WiFi Security Lab Report" in md and "00:11:22:33:44:55" in md

    passed = all(checks.values())
    result = {
        "version": APP_VERSION,
        "passed": passed,
        "checks": checks,
    }
    print(json.dumps(result, indent=2))
    return 0 if passed else 10

def command_lock(args):
    if args.index is None and not args.bssid and not args.ssid:
        networks, _ = scan_networks()
        print_networks(networks)
        try:
            idx = int(input("\nSelect authorized lab target: ")) - 1
        except ValueError:
            print("Invalid selection.")
            return 2
        data = select_and_lock_target(index=idx, output=args.output)
    else:
        idx = args.index - 1 if args.index is not None else None
        data = select_and_lock_target(index=idx, bssid=args.bssid, ssid=args.ssid, output=args.output)

    print(json.dumps(data, indent=2))
    return 0 if data.get("ok") else 2


def command_show_lock(args):
    data = load_target_lock(args.target_file)
    if not data:
        print("No target lock found.")
        return 2
    print(json.dumps(data, indent=2))
    return 0


def command_bundle(args):
    if args.ssid or args.bssid:
        locked = select_and_lock_target(
            bssid=args.bssid,
            ssid=args.ssid,
            output=args.target_file,
        )
        if not locked.get("ok"):
            print(json.dumps(locked, indent=2))
            return 2

    data = build_exam_bundle(
        capture_path=args.capture,
        target_lock_path=args.target_file,
        output_dir=args.output_dir,
    )
    print(json.dumps(data, indent=2))
    return 0



def command_validate_lock(args):
    data = validate_target_lock_against_scan(args.target_file)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"target_lock_validation": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") in {"SEEN_EXACT", "SEEN_CHANNEL_CHANGED"} else 12


def command_exam_run(args):
    data = exam_run(
        ssid=args.ssid,
        bssid=args.bssid,
        capture_path=args.capture,
        target_file=args.target_file,
        output_dir=args.output_dir,
    )
    print(json.dumps(data, indent=2))
    return 0 if data.get("ok") else 13

def command_target_timeline(args):
    data = target_event_timeline(
        args.capture,
        args.bssid,
        window_seconds=args.window,
        max_events=args.max_events,
    )
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"target_timeline": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("total_events", 0) else 6


def command_capture_channels(args):
    data = channel_observation_summary(args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"channel_observations": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("channels") else 7



def command_watch(args):
    data = watch_target(
        ssid=args.ssid,
        bssid=args.bssid,
        interval_seconds=args.interval,
        samples=args.samples,
    )
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"target_watch": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") in {"SEEN", "AMBIGUOUS"} else 9



def command_doctor(args):
    data = capture_doctor(args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_doctor": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") in {"READY_FOR_WIFI_AND_EAPOL_ANALYSIS", "READY_FOR_WIFI_ANALYSIS_NO_EAPOL"} else 14


def command_pcap_index(args):
    data = capture_ap_index(args.capture, args.ssid)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_ap_index": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("match_count", 0) else 15

def command_find(args):
    data = find_visible_targets(args.query, exact=args.exact)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"target_search": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("match_count", 0) else 8


def command_reconcile(args):
    target = load_target_lock(args.target_file)
    if not target:
        data = {"status": "NO_TARGET", "error": f"Could not load target lock: {args.target_file}"}
        print(json.dumps(data, indent=2))
        return 2
    data = reconcile_target_with_capture(target, args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"target_capture_reconciliation": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") in {"TARGET_CONFIRMED_IN_CAPTURE", "TARGET_CHANNEL_CHANGED_OR_MISMATCHED"} else 10


def command_verdict(args):
    target = load_target_lock(args.target_file)
    data = exam_verdict(target, args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"exam_verdict": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") in {"PASS", "PARTIAL"} else 11


def command_scan_csv(args):
    data = export_scan_csv(args.output, args.query)
    print(json.dumps(data, indent=2))
    return 0


def command_pyshark(args):
    data = pyshark_capture_summary(args.capture, args.bssid)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"pyshark_summary": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("available") else 16


def command_capinfos(args):
    data = capinfos_summary(args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capinfos": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("ok") else 17


def command_merge(args):
    data = merge_capture_files(args.inputs, args.output)
    print(json.dumps(data, indent=2))
    return 0 if data.get("ok") else 18


def command_trim(args):
    data = trim_capture_file(args.capture, args.output, args.start, args.stop)
    print(json.dumps(data, indent=2))
    return 0 if data.get("ok") else 19


def command_toolchain(args):
    data = offline_toolchain_report()
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"offline_toolchain": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0


def command_preflight(args):
    data = exam_preflight(args.target_file, args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"preflight": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") in {"READY", "READY_WITH_WARNINGS"} else 20


def command_completeness(args):
    target = load_target_lock(args.target_file)
    data = evidence_completeness(target, args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"evidence_completeness": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("score_percent", 0) >= 45 else 21


def command_custody(args):
    data = chain_of_custody(
        args.paths,
        output=args.output,
        target_lock_path=args.target_file,
    )
    print(json.dumps({
        "output": data.get("output"),
        "record_sha256": data.get("record_sha256"),
        "evidence_count": data.get("evidence_count"),
    }, indent=2))
    return 0


def command_deauth_observe(args):
    data = deauth_observation_analysis(
        args.capture,
        target_bssid=args.bssid,
        correlation_window=args.window,
    )
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"deauth_observation": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") != "NOT_ANALYZED" else 22


def command_passive_live(args):
    data = passive_live_capture(
        interface=args.interface,
        output=args.output,
        duration_seconds=args.duration,
        target_bssid=args.bssid,
    )
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"passive_live_capture": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("ok") else 20


def command_final_result(args):
    target = load_target_lock(args.target_file)
    data = load_verified_exam_result(args.result_file, target=target)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({
            "target": target,
            "final_result": data,
        }, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") == "RESULT_VERIFIED" else 21


def command_compare(args):
    data = compare_capture_profiles(args.baseline, args.current)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_comparison": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0



def command_html(args):
    out = export_html_from_json(args.report_json, args.output)
    print(f"HTML report saved: {out}")
    return 0

def command_markdown(args):
    out = export_markdown_from_json(args.report_json, args.output)
    print(f"Markdown report saved: {out}")
    return 0

def command_readiness(args):
    data = readiness_check()
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"readiness": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") == "READY_FOR_SCAN_AND_IMPORTED_CAPTURE_ANALYSIS" else 4


def command_quality(args):
    data = capture_quality(args.capture, args.bssid)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_quality": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("status") in {"STRONG_EVIDENCE_SET", "USABLE_PARTIAL_EVIDENCE"} else 5


def command_neighbors(args):
    data = neighbor_snapshot()
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"neighbor_snapshot": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0

def command_netinfo(args):
    data = local_network_info()
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"local_network": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0


def command_stats(args):
    data = capture_statistics(args.capture)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_statistics": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("exists") else 2


def command_profile(args):
    data = passive_ap_profiles(args.capture)
    if args.bssid:
        data["target_station_summary"] = anonymized_station_summary(args.capture, args.bssid)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"passive_profile": data}, args.report)
        print(f"\nReport saved: {p}")
    return 0 if data.get("aps") else 3

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
        "local_network": local_network_info(),
        "readiness": readiness_check(),
    }

    capture = input("\nOptional PCAP/PCAPNG path (Enter to skip): ").strip()
    if capture:
        analysis = analyze_capture(capture, target.get("bssid"))
        payload["capture_analysis"] = analysis
        payload["capture_statistics"] = capture_statistics(capture)
        payload["capture_quality"] = capture_quality(capture, target.get("bssid"))
        payload["passive_ap_profile"] = passive_ap_profiles(capture)
        payload["target_station_summary"] = anonymized_station_summary(capture, target.get("bssid"))
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

    ch = sub.add_parser("channels", help="Summarize visible networks by channel and security mode.")
    ch.add_argument("--report", default="")
    ch.set_defaults(func=command_channels)

    tl = sub.add_parser("timeline", help="Build an anonymized management/EAPOL event timeline from a capture.")
    tl.add_argument("capture")
    tl.add_argument("--bssid", default="")
    tl.add_argument("--max-events", type=int, default=500)
    tl.add_argument("--report", default="")
    tl.set_defaults(func=command_timeline)

    fd = sub.add_parser("findings", help="Generate defensive findings from the locked target and optional passive capture.")
    fd.add_argument("--capture", default="")
    fd.add_argument("--target-file", default="wifi_target_lock.json")
    fd.add_argument("--report", default="")
    fd.set_defaults(func=command_findings)

    vb = sub.add_parser("verify-bundle", help="Verify hashes in an exam evidence bundle.")
    vb.add_argument("directory")
    vb.set_defaults(func=command_verify_bundle)

    zb = sub.add_parser("zip-bundle", help="Create a ZIP archive of an exam evidence bundle.")
    zb.add_argument("directory")
    zb.add_argument("--output", default="")
    zb.set_defaults(func=command_zip_bundle)

    radio = sub.add_parser("radio", help="Inspect capture/monitor-mode capability without changing interface mode.")
    radio.add_argument("--report", default="")
    radio.set_defaults(func=command_radio)

    ki = sub.add_parser("kismet-import", help="Convert an existing KismetDB log to PCAP-NG without cleaning the source.")
    ki.add_argument("input")
    ki.add_argument("--output", default="")
    ki.add_argument("--report", default="")
    ki.set_defaults(func=command_kismet_import)

    mn = sub.add_parser("minimize", help="Create an evidence-minimized PCAP containing management/EAPOL observations.")
    mn.add_argument("input")
    mn.add_argument("output")
    mn.add_argument("--bssid", default="", help="Optional authorized AP BSSID.")
    mn.add_argument("--report", default="")
    mn.set_defaults(func=command_minimize)

    stest = sub.add_parser("selftest", help="Run offline internal consistency checks.")
    stest.set_defaults(func=command_selftest)

    lk = sub.add_parser("lock", help="Scan and persist one authorized AP as the exam target.")
    lk.add_argument("--index", type=int, default=None, help="1-based network index from the current scan.")
    lk.add_argument("--bssid", default="", help="Lock a currently visible BSSID.")
    lk.add_argument("--output", default="wifi_target_lock.json")
    lk.set_defaults(func=command_lock)

    sl = sub.add_parser("show-lock", help="Display the persisted authorized target.")
    sl.add_argument("--target-file", default="wifi_target_lock.json")
    sl.set_defaults(func=command_show_lock)

    vl = sub.add_parser("validate-lock", help="Re-scan and verify that the persisted authorized AP is still the same target.")
    vl.add_argument("--target-file", default="wifi_target_lock.json")
    vl.add_argument("--report", default="")
    vl.set_defaults(func=command_validate_lock)

    er = sub.add_parser("exam-run", help="One-shot exam flow: scan, exact target lock, validation, bundle, and optional capture verdict.")
    er.add_argument("--ssid", default="", help="Exact instructor-designated SSID.")
    er.add_argument("--bssid", default="", help="Instructor-designated BSSID when known.")
    er.add_argument("--capture", default="", help="Optional authorized PCAP/PCAPNG.")
    er.add_argument("--target-file", default="wifi_target_lock.json")
    er.add_argument("--output-dir", default="wifi_exam_bundle")
    er.set_defaults(func=command_exam_run)

    bd = sub.add_parser("bundle", help="Generate a complete exam evidence bundle from current diagnostics and an optional capture.")
    bd.add_argument("--capture", default="")
    bd.add_argument("--ssid", default="", help="Optional exact SSID to lock before building the bundle.")
    bd.add_argument("--bssid", default="", help="Optional BSSID to lock before building the bundle.")
    bd.add_argument("--target-file", default="wifi_target_lock.json")
    bd.add_argument("--output-dir", default="wifi_exam_bundle")
    bd.set_defaults(func=command_bundle)

    tl = sub.add_parser("target-timeline", help="Build a passive event timeline for one authorized AP.")
    tl.add_argument("capture")
    tl.add_argument("--bssid", required=True, help="Selected authorized AP BSSID.")
    tl.add_argument("--window", type=float, default=15.0, help="Correlation window in seconds.")
    tl.add_argument("--max-events", type=int, default=500)
    tl.add_argument("--report", default="")
    tl.set_defaults(func=command_target_timeline)

    ch = sub.add_parser("capture-channels", help="Summarize passive channel/frequency observations in a capture.")
    ch.add_argument("capture")
    ch.add_argument("--report", default="")
    ch.set_defaults(func=command_capture_channels)

    wt = sub.add_parser("watch", help="Watch an authorized SSID/BSSID with normal OS Wi-Fi scans.")
    wt.add_argument("--ssid", default="", help="Exact SSID to observe.")
    wt.add_argument("--bssid", default="", help="Exact BSSID to observe.")
    wt.add_argument("--interval", type=float, default=2.0, help="Seconds between scans; minimum 0.5.")
    wt.add_argument("--samples", type=int, default=30, help="Number of scans; maximum 300.")
    wt.add_argument("--report", default="")
    wt.set_defaults(func=command_watch)

    doc = sub.add_parser("doctor", help="Validate whether a PCAP/PCAPNG is usable for Wi-Fi/EAPOL analysis.")
    doc.add_argument("capture")
    doc.add_argument("--report", default="")
    doc.set_defaults(func=command_doctor)

    pi = sub.add_parser("pcap-index", help="List APs already present in an imported capture.")
    pi.add_argument("capture")
    pi.add_argument("--ssid", default="", help="Optional case-insensitive SSID substring.")
    pi.add_argument("--report", default="")
    pi.set_defaults(func=command_pcap_index)

    fnd = sub.add_parser("find", help="Find visible SSIDs by exact or partial name and sort by signal.")
    fnd.add_argument("query")
    fnd.add_argument("--exact", action="store_true")
    fnd.add_argument("--report", default="")
    fnd.set_defaults(func=command_find)

    rc = sub.add_parser("reconcile", help="Confirm that an imported capture belongs to the locked authorized AP.")
    rc.add_argument("capture")
    rc.add_argument("--target-file", default="wifi_target_lock.json")
    rc.add_argument("--report", default="")
    rc.set_defaults(func=command_reconcile)

    vd = sub.add_parser("verdict", help="Produce PASS/PARTIAL/MISMATCH/NO-EVIDENCE status for the locked AP and capture.")
    vd.add_argument("capture")
    vd.add_argument("--target-file", default="wifi_target_lock.json")
    vd.add_argument("--report", default="")
    vd.set_defaults(func=command_verdict)

    scsv = sub.add_parser("scan-csv", help="Export the current Wi-Fi scan as CSV.")
    scsv.add_argument("--output", default="wifi_scan.csv")
    scsv.add_argument("--query", default="", help="Optional case-insensitive SSID substring.")
    scsv.set_defaults(func=command_scan_csv)

    ps = sub.add_parser("pyshark", help="Optional PyShark/TShark summary of an imported capture.")
    ps.add_argument("capture")
    ps.add_argument("--bssid", default="")
    ps.add_argument("--report", default="")
    ps.set_defaults(func=command_pyshark)

    ci = sub.add_parser("capinfos", help="Run Wireshark capinfos against an imported capture.")
    ci.add_argument("capture")
    ci.add_argument("--report", default="")
    ci.set_defaults(func=command_capinfos)

    mg = sub.add_parser("merge", help="Merge two or more capture files chronologically with mergecap.")
    mg.add_argument("inputs", nargs="+")
    mg.add_argument("--output", required=True)
    mg.set_defaults(func=command_merge)

    tr = sub.add_parser("trim", help="Trim an imported capture by time range with editcap.")
    tr.add_argument("capture")
    tr.add_argument("--output", required=True)
    tr.add_argument("--start", default="", help="editcap-compatible start time.")
    tr.add_argument("--stop", default="", help="editcap-compatible stop time.")
    tr.set_defaults(func=command_trim)

    tc = sub.add_parser("toolchain", help="Report installed offline capture-analysis integrations.")
    tc.add_argument("--report", default="")
    tc.set_defaults(func=command_toolchain)

    pf = sub.add_parser("preflight", help="Check target, tools and optional capture before an exam run.")
    pf.add_argument("--target-file", default="wifi_target_lock.json")
    pf.add_argument("--capture", default="")
    pf.add_argument("--report", default="")
    pf.set_defaults(func=command_preflight)

    ec = sub.add_parser("completeness", help="Score completeness of the authorized evidence set.")
    ec.add_argument("--target-file", default="wifi_target_lock.json")
    ec.add_argument("--capture", default="")
    ec.add_argument("--report", default="")
    ec.set_defaults(func=command_completeness)

    cu = sub.add_parser("custody", help="Hash evidence files into a chain-of-custody record.")
    cu.add_argument("paths", nargs="+")
    cu.add_argument("--output", default="chain_of_custody.json")
    cu.add_argument("--target-file", default="wifi_target_lock.json")
    cu.set_defaults(func=command_custody)

    dao = sub.add_parser("deauth-observe", help="Passively detect disconnect frames and correlate them with later reauthentication/EAPOL.")
    dao.add_argument("capture")
    dao.add_argument("--bssid", default="", help="Optional authorized AP BSSID.")
    dao.add_argument("--window", type=float, default=15.0, help="Correlation window in seconds.")
    dao.add_argument("--report", default="")
    dao.set_defaults(func=command_deauth_observe)

    plc = sub.add_parser("passive-live", help="Passively capture for a fixed time on an already-prepared interface, then analyze EAPOL evidence.")
    plc.add_argument("--interface", required=True, help="TShark interface index/name from 'tshark -D'.")
    plc.add_argument("--output", default="passive_live.pcapng")
    plc.add_argument("--duration", type=int, default=60, help="Capture duration in seconds, max 600.")
    plc.add_argument("--bssid", default="", help="Optional authorized AP BSSID for post-capture EAPOL filtering.")
    plc.add_argument("--report", default="")
    plc.set_defaults(func=command_passive_live)

    fr = sub.add_parser("final-result", help="Validate and display an authorized exam result against the locked target.")
    fr.add_argument("result_file")
    fr.add_argument("--target-file", default="wifi_target_lock.json")
    fr.add_argument("--report", default="")
    fr.set_defaults(func=command_final_result)

    cp = sub.add_parser("compare", help="Compare two passive capture profiles for configuration drift.")
    cp.add_argument("baseline")
    cp.add_argument("current")
    cp.add_argument("--report", default="")
    cp.set_defaults(func=command_compare)

    ht = sub.add_parser("html", help="Render a saved JSON lab report as a standalone HTML report.")
    ht.add_argument("report_json")
    ht.add_argument("--output", default="")
    ht.set_defaults(func=command_html)

    md = sub.add_parser("markdown", help="Render a saved JSON lab report as Markdown.")
    md.add_argument("report_json")
    md.add_argument("--output", default="")
    md.set_defaults(func=command_markdown)

    rd = sub.add_parser("readiness", help="Check whether the machine is ready for scan/imported-capture analysis.")
    rd.add_argument("--report", default="")
    rd.set_defaults(func=command_readiness)

    q = sub.add_parser("quality", help="Score whether a capture contains useful authorized exam evidence.")
    q.add_argument("capture")
    q.add_argument("--bssid", default="", help="Optional selected AP BSSID.")
    q.add_argument("--report", default="")
    q.set_defaults(func=command_quality)

    nb = sub.add_parser("neighbors", help="Snapshot the local OS neighbor table without scanning other hosts.")
    nb.add_argument("--report", default="")
    nb.set_defaults(func=command_neighbors)

    n = sub.add_parser("netinfo", help="Collect local interface/gateway diagnostics.")
    n.add_argument("--report", default="")
    n.set_defaults(func=command_netinfo)

    st = sub.add_parser("stats", help="Summarize an imported capture without modifying the network.")
    st.add_argument("capture")
    st.add_argument("--report", default="")
    st.set_defaults(func=command_stats)

    pr = sub.add_parser("profile", help="Build passive AP security profiles from a capture.")
    pr.add_argument("capture")
    pr.add_argument("--bssid", default="", help="Optional target AP for anonymized station counts.")
    pr.add_argument("--report", default="")
    pr.set_defaults(func=command_profile)

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
