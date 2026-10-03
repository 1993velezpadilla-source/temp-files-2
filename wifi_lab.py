import argparse
import datetime
import json
import hashlib
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


APP_VERSION = "0.9"


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
    for name in ["tshark", "dumpcap", "capinfos", "nmcli", "iw", "kismet"]:
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


def export_markdown_from_json(json_path, output_path=""):
    p = Path(json_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    out = Path(output_path) if output_path else p.with_suffix(".md")
    out.write_text(render_markdown_report(data), encoding="utf-8")
    return out



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


def select_and_lock_target(index=None, bssid="", output="wifi_target_lock.json"):
    networks, raw = scan_networks()
    if not networks:
        return {
            "ok": False,
            "error": "No networks found.",
            "scan_error_excerpt": raw[:500],
        }

    target = None
    if bssid:
        wanted = normalize_mac(bssid)
        for net in networks:
            if normalize_mac(net.get("bssid")) == wanted:
                target = net
                break
    elif index is not None:
        if 0 <= index < len(networks):
            target = networks[index]

    if target is None:
        return {
            "ok": False,
            "error": "Requested target was not present in the current scan.",
            "visible_networks": len(networks),
        }

    p = save_target_lock(target, output)
    return {
        "ok": True,
        "target": target,
        "lock_file": str(p),
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
        "scan": networks,
        "readiness": readiness,
        "diagnostics": diagnostics,
        "radio_capabilities": radio_capabilities(),
        "local_network": local,
        "neighbor_snapshot": neighbors,
        "security_findings": build_security_findings(target=target),
    }

    if capture_path:
        bssid = target.get("bssid", "") if target else ""
        payload["capture_statistics"] = capture_statistics(capture_path)
        payload["capture_analysis"] = analyze_capture(capture_path, bssid or None)
        payload["capture_quality"] = capture_quality(capture_path, bssid)
        payload["passive_ap_profile"] = passive_ap_profiles(capture_path)
        payload["security_findings"] = build_security_findings(
            target=target,
            passive_profile=payload["passive_ap_profile"],
            target_bssid=bssid,
        )
        if bssid:
            payload["target_station_summary"] = anonymized_station_summary(capture_path, bssid)

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
        },
        "file_hashes": {
            "exam_bundle.json": file_sha256(report_path),
            "exam_bundle.md": file_sha256(md_path),
        },
        "scan_error_excerpt": scan_raw[:500] if not networks else "",
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "output_dir": str(out),
        "json_report": str(report_path),
        "markdown_report": str(md_path),
        "manifest": str(manifest_path),
        "target": target,
        "capture_included": bool(capture_path),
    }

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
    if args.index is None and not args.bssid:
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
        data = select_and_lock_target(index=idx, bssid=args.bssid, output=args.output)

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
    data = build_exam_bundle(
        capture_path=args.capture,
        target_lock_path=args.target_file,
        output_dir=args.output_dir,
    )
    print(json.dumps(data, indent=2))
    return 0

def command_compare(args):
    data = compare_capture_profiles(args.baseline, args.current)
    print(json.dumps(data, indent=2))
    if args.report:
        p = save_report({"capture_comparison": data}, args.report)
        print(f"\nReport saved: {p}")
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

    bd = sub.add_parser("bundle", help="Generate a complete exam evidence bundle from current diagnostics and an optional capture.")
    bd.add_argument("--capture", default="")
    bd.add_argument("--target-file", default="wifi_target_lock.json")
    bd.add_argument("--output-dir", default="wifi_exam_bundle")
    bd.set_defaults(func=command_bundle)

    cp = sub.add_parser("compare", help="Compare two passive capture profiles for configuration drift.")
    cp.add_argument("baseline")
    cp.add_argument("current")
    cp.add_argument("--report", default="")
    cp.set_defaults(func=command_compare)

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
