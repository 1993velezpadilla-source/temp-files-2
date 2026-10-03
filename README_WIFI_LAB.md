# WiFi Security Lab v1.7

Functions-first CLI for an authorized classroom/home Wi-Fi security assessment.

## Core workflow

The exam-oriented path is now:

```text
scan/find -> lock exact AP -> validate lock -> inspect environment ->
analyze authorized capture -> reconcile target -> verdict -> bundle -> verify bundle
```

No GUI work is required for this flow.

## Implemented

### Target discovery and locking
- Nearby Wi-Fi discovery on Windows/Linux.
- Exact/partial SSID search.
- BSSID-aware selection so duplicate SSIDs are not confused.
- Target lock file with SSID, BSSID, security, channel and signal.
- Re-validation of a locked AP against a fresh scan.
- Passive watch mode for a designated SSID/BSSID.
- Scan export to CSV.

### Security and radio metadata
- WPA3 / WPA2 / WPA / WEP / open-or-unknown classification.
- Channel and signal information when exposed by the operating system.
- WPS advertisement/setup-lock observations from imported captures.
- PMF/MFP capable/required observations.
- RSN AKM, pairwise cipher and group cipher observations.
- Hidden-SSID observations.
- SSID-to-BSSID grouping and configuration-consistency warnings.
- Passive channel/frequency summaries.
- Radio/adapter capability inspection without changing interface mode.

### Capture analysis
- PCAP/PCAPNG import.
- Capture SHA-256, size, frame count and duration.
- Beacon/probe/authentication/association/disassociation/deauthentication counts.
- EAPOL detection.
- Conservative M1/M2/M3/M4 classification when TShark exposes the required key-info field.
- BSSID filtering for the selected authorized AP.
- Capture-quality checks explaining exactly what evidence is missing.
- Capture doctor and AP index.
- Passive event timeline for a selected AP.
- Temporal correlation of already-observed disconnect-management frames with later EAPOL events.
- Anonymized station tokens/counts; raw client MAC addresses are not put into the report.
- Comparison of two capture profiles for configuration drift.
- Optional KismetDB-to-PCAP import when the official converter is installed.
- Evidence-minimization export containing management/EAPOL evidence only.

### Exam packaging
- One-command exam run.
- PASS / PARTIAL / MISMATCH / NO-EVIDENCE style verdicts.
- Security findings with remediation notes.
- JSON evidence report.
- Markdown report.
- Standalone HTML report.
- Manifest with SHA-256 hashes.
- Bundle integrity verification.
- ZIP packaging of the completed bundle.
- Optional PyShark parser summary as a second TShark-backed view.
- `capinfos` metadata inspection.
- `mergecap` support to combine multiple authorized captures chronologically.
- `editcap` support to trim an imported capture by time range.
- Offline toolchain inventory for Wireshark/Kismet/PyShark components.
- Exam preflight that reports blockers and warnings before the run.
- Evidence-completeness score for the locked AP/capture set.
- Chain-of-custody JSON with SHA-256 hashes for evidence/report files.
- Passive deauthentication/disassociation observation with reconnect/EAPOL correlation.

## Intentionally not implemented

This project does not perform password brute-force/cracking, forced deauthentication, or credential extraction from arbitrary Wi-Fi networks.

It can observe and document deauthentication/disassociation frames that already exist in an authorized capture, but it does not transmit them.

## Requirements

- Python 3.10+ recommended.
- Wireshark/TShark for PCAP/PCAPNG analysis.
- Windows scanning uses `netsh`.
- Linux scanning uses `nmcli`; `iw` improves capability diagnostics.
- Optional: Kismet tools for importing a KismetDB produced separately in an authorized lab.

## Fast exam commands

Find the instructor-designated SSID:

```bash
python wifi_lab.py find "SSID_NAME" --exact
```

Lock the intended AP:

```bash
python wifi_lab.py lock --ssid "SSID_NAME"
```

If the SSID has multiple BSSIDs, lock the exact AP:

```bash
python wifi_lab.py lock --bssid AA:BB:CC:DD:EE:FF
```

Confirm it is still the same AP:

```bash
python wifi_lab.py validate-lock
```

Check the machine:

```bash
python wifi_lab.py readiness
python wifi_lab.py radio
```

Inspect an authorized capture before relying on it:

```bash
python wifi_lab.py doctor exam.pcapng
python wifi_lab.py pcap-index exam.pcapng
```

Analyze EAPOL evidence:

```bash
python wifi_lab.py capture exam.pcapng --bssid AA:BB:CC:DD:EE:FF
```

Build the passive target timeline:

```bash
python wifi_lab.py target-timeline exam.pcapng --bssid AA:BB:CC:DD:EE:FF
```

Confirm the capture matches the locked AP:

```bash
python wifi_lab.py reconcile exam.pcapng
```

Generate a high-level result:

```bash
python wifi_lab.py verdict exam.pcapng
```

Run the exam path in one command:

```bash
python wifi_lab.py exam-run --ssid "SSID_NAME" --capture exam.pcapng
```

Create a complete evidence bundle:

```bash
python wifi_lab.py bundle --capture exam.pcapng
```

The bundle contains:

```text
wifi_exam_bundle/
  exam_bundle.json
  exam_bundle.md
  exam_bundle.html
  manifest.json
  chain_of_custody.json
```

Verify the hashes:

```bash
python wifi_lab.py verify-bundle wifi_exam_bundle
```

Package it:

```bash
python wifi_lab.py zip-bundle wifi_exam_bundle
```

Render HTML from any saved JSON report:

```bash
python wifi_lab.py html exam_bundle.json
```

## Evidence states

Handshake analysis may report:

- `COMPLETE_4_WAY_SEQUENCE_OBSERVED`
- `PARTIAL_EAPOL_KEY_SEQUENCE`
- `EAPOL_PRESENT_UNCLASSIFIED`
- `NO_EAPOL_FOUND`

Capture quality may report:

- `STRONG_EVIDENCE_SET`
- `USABLE_PARTIAL_EVIDENCE`
- `CAPTURE_PRESENT_BUT_MISSING_CORE_EVIDENCE`
- `UNUSABLE_OR_EMPTY`

## Hardware note

Normal Wi-Fi scanning and raw 802.11 capture are different capabilities. A laptop or phone being able to list networks does not prove that its Wi-Fi adapter/driver can capture raw management/EAPOL traffic. Use the readiness/radio/doctor commands before the exam machine is trusted.

## Development priority

Core behavior first. GUI polish comes after the CLI, evidence pipeline and packaging path are stable.


## Additional offline tooling

Inspect available analysis components:

```bash
python wifi_lab.py toolchain
```

Optional PyShark summary:

```bash
python wifi_lab.py pyshark exam.pcapng --bssid AA:BB:CC:DD:EE:FF
```

Wireshark capture metadata:

```bash
python wifi_lab.py capinfos exam.pcapng
```

Merge multiple authorized captures:

```bash
python wifi_lab.py merge part1.pcapng part2.pcapng --output combined.pcapng
```

Trim a capture to a relevant time window:

```bash
python wifi_lab.py trim combined.pcapng --output focused.pcapng --start "2026-10-03 09:10:00" --stop "2026-10-03 09:15:00"
```

These operations are offline evidence-processing utilities. They do not transmit Wi-Fi frames.


## Exam preflight

Run this before trusting the machine or capture:

```bash
python wifi_lab.py preflight --capture exam.pcapng
```

It reports READY, READY_WITH_WARNINGS, or BLOCKED and lists the exact blockers.

## Evidence completeness

```bash
python wifi_lab.py completeness --capture exam.pcapng
```

The percentage measures how complete the authorized evidence set is. It is **not** a password-recovery probability.

## Chain of custody

Hash one or more evidence files:

```bash
python wifi_lab.py custody exam.pcapng wifi_exam_bundle/exam_bundle.json --output chain_of_custody.json
```

The record includes SHA-256 hashes, file sizes, timestamps, host/runtime metadata, target fingerprint, and its own record hash.


## Passive deauth/reconnect analysis

Analyze disconnect frames that are already present in an authorized capture and correlate them with later authentication/association/EAPOL:

```bash
python wifi_lab.py deauth-observe exam.pcapng --bssid AA:BB:CC:DD:EE:FF --window 15 --report deauth_observation.json
```

Possible statuses include:

- `DISCONNECT_TO_REAUTH_SEQUENCE_OBSERVED`
- `DISCONNECT_FRAMES_OBSERVED_NO_EAPOL_CORRELATION`
- `NO_DISCONNECT_FRAMES_OBSERVED`

This command is passive only. It does not transmit deauthentication or disassociation frames.
