# WiFi Security Lab v1.2

Functions-first CLI for an authorized classroom/home Wi-Fi security assessment.

## Implemented now

- Nearby Wi-Fi discovery.
- Per-BSSID target selection instead of assuming an SSID name.
- Security classification: WPA3 / WPA2 / WPA / WEP / open-or-unknown.
- Signal and channel display when the operating system exposes them.
- Adapter/tool diagnostics.
- TShark capture-interface discovery.
- PCAP/PCAPNG import.
- EAPOL frame detection.
- Conservative 4-way key-message classification (M1/M2/M3/M4) when the installed TShark build exposes a recognized RSN key-info field.
- BSSID filtering so imported evidence can be restricted to the selected authorized AP.
- JSON evidence reports with timestamps.
- SHA-256 integrity fingerprint for imported captures.
- Capture frame count, time span and management-frame event counts.
- Passive AP profiling from beacon/probe-response evidence.
- PMF/MFP capable/required observations when exposed by TShark.
- WPS advertisement/setup-lock observations.
- RSN AKM, pairwise cipher and group cipher observations.
- Hidden-SSID observations.
- SSID-to-BSSID grouping and configuration-inconsistency warnings.
- Local interface/gateway snapshot.
- Anonymized station counts/tokens for a selected authorized AP (no raw client MACs in the report).
- Readiness check for scanner, TShark, capture interfaces and required Wireshark fields.
- Capture-quality assessment that explains missing exam evidence.
- Local neighbor-table snapshot without active host scanning.
- Tool-version inventory for reproducibility.
- Automatic Windows EXE build pipeline plus Python compile/smoke checks.


## Exam-surprise workflow

The CLI now supports a practical unknown-SSID exam flow without hardcoding the instructor's AP:

- \`find <name>\`: exact/partial SSID search, sorted by observed signal.
- \`lock\`: persist one authorized BSSID so later analysis cannot silently switch targets.
- \`watch\`: repeat normal OS scans and document whether the locked AP remains visible.
- \`reconcile <capture>\`: compare the persisted AP identity with imported capture evidence.
- \`verdict <capture>\`: return \`PASS\`, \`PARTIAL\`, \`MISMATCH\`, \`NO_CORE_EVIDENCE\`, or \`INCONCLUSIVE\`.
- \`timeline\` / \`target-timeline\`: passive management/EAPOL event chronology.
- \`channels\` / \`capture-channels\`: channel/security observations.
- \`findings\`: defensive configuration findings.
- \`bundle\`: produce a complete evidence folder.
- \`verify-bundle\`: verify bundle hashes.
- \`zip-bundle\`: package the evidence folder.
- \`scan-csv\`: export the current OS scan for quick instructor review.

Examples:

\`\`\`
python wifi_lab.py find Profesor --exact
python wifi_lab.py lock --bssid AA:BB:CC:DD:EE:FF
python wifi_lab.py reconcile exam.pcapng --report reconcile.json
python wifi_lab.py verdict exam.pcapng --report verdict.json
python wifi_lab.py scan-csv --output visible_networks.csv
\`\`\`

The strongest-signal result is shown only as a convenience hint. Multi-AP and mesh networks may expose several BSSIDs for the same SSID, so the intended BSSID should be explicitly locked when the instructor identifies it.

## Intentionally not implemented

This project does not include password brute-force/cracking, forced deauthentication, or extraction of credentials from arbitrary Wi-Fi networks.

## Requirements

Python 3.10+ recommended.

For capture analysis, install Wireshark/TShark and make sure \`tshark\` is on PATH.

### Windows

Scanning uses:

\`\`\`
netsh wlan show networks mode=bssid
\`\`\`

Diagnostics also query:

\`\`\`
netsh wlan show drivers
\`\`\`

### Linux

Scanning uses:

\`\`\`
nmcli dev wifi list
\`\`\`

Diagnostics can also use \`iw\` when installed.

## Commands

Interactive flow:

\`\`\`
python wifi_lab.py
\`\`\`

or:

\`\`\`
python wifi_lab.py interactive
\`\`\`

Scan only:

\`\`\`
python wifi_lab.py scan
\`\`\`

Diagnostics:

\`\`\`
python wifi_lab.py diag
\`\`\`

Local interface/gateway diagnostics:

```
python wifi_lab.py netinfo
```

Capture statistics and integrity fingerprint:

```
python wifi_lab.py stats exam.pcapng
```

Build passive AP security profiles:

```
python wifi_lab.py profile exam.pcapng
```

For a selected authorized AP, include anonymized station counts:

```
python wifi_lab.py profile exam.pcapng --bssid AA:BB:CC:DD:EE:FF
```

Analyze an authorized capture:

\`\`\`
python wifi_lab.py capture exam.pcapng
\`\`\`

Filter the analysis to one AP:

\`\`\`
python wifi_lab.py capture exam.pcapng --bssid AA:BB:CC:DD:EE:FF
\`\`\`

Write a report:

\`\`\`
python wifi_lab.py capture exam.pcapng --report exam_report.json
\`\`\`

## Handshake evidence statuses

- \`COMPLETE_4_WAY_SEQUENCE_OBSERVED\`: M1, M2, M3 and M4 were all observed.
- \`PARTIAL_EAPOL_KEY_SEQUENCE\`: two or more classified key-message types were observed.
- \`EAPOL_PRESENT_UNCLASSIFIED\`: EAPOL exists but this local TShark build did not provide enough key metadata for reliable M1-M4 classification.
- \`NO_EAPOL_FOUND\`: no matching EAPOL evidence was found.

## Important hardware note

Scanning for nearby networks and capturing raw 802.11 traffic are different capabilities. Live raw capture depends on the Wi-Fi adapter, driver, operating system and permissions. This program therefore analyzes imported capture files rather than assuming every laptop/phone can enter monitor mode.

## Development priority

Core functions first. GUI polish comes only after the scanner, diagnostics, evidence parser and reporting path are stable.


## Passive-only event observation

The capture statistics command may report how many association, authentication, disassociation and deauthentication frames were **already present in the imported capture**. It does not transmit any of those frames.

## Wireshark compatibility

The program asks the installed TShark build for its field registry and only uses fields actually supported on that machine. This is important because Wireshark renamed several 802.11 management/RSN fields across major versions.



## Readiness

Before a lab/exam machine is used:

```
python wifi_lab.py readiness --report readiness.json
```

Possible high-level states include:

- `READY_FOR_SCAN_AND_IMPORTED_CAPTURE_ANALYSIS`
- `SCAN_READY_CAPTURE_ANALYSIS_INCOMPLETE`
- `NOT_READY`

## Capture quality

Check whether an imported capture contains the expected AP/evidence:

```
python wifi_lab.py quality exam.pcapng --bssid AA:BB:CC:DD:EE:FF --report quality.json
```

The quality report distinguishes a strong evidence set, usable partial evidence, a capture missing core evidence, and an unusable/empty capture.

## Local neighbor snapshot

This reads only the operating system's existing ARP/neighbor table; it does not probe the LAN:

```
python wifi_lab.py neighbors
```

## Windows executable

GitHub Actions now performs a Python compile check and CLI smoke test, then packages `wifi_lab.py` as a one-file Windows executable with PyInstaller.


## One-shot exam run

When the instructor gives only the network name, use the exact SSID:

\`\`\`
python wifi_lab.py exam-run --ssid "InstructorNetwork"
\`\`\`

If the SSID maps to more than one BSSID, the command stops instead of guessing. Re-run with the instructor-designated BSSID:

\`\`\`
python wifi_lab.py exam-run --bssid AA:BB:CC:DD:EE:FF
\`\`\`

If an authorized capture is available:

\`\`\`
python wifi_lab.py exam-run --bssid AA:BB:CC:DD:EE:FF --capture exam.pcapng
\`\`\`

This produces a persistent target lock, target fingerprint, current-scan validation, evidence bundle, capture reconciliation, and technical exam verdict.

To re-check the target later:

\`\`\`
python wifi_lab.py validate-lock
\`\`\`

A channel change does not automatically mean the target is wrong; APs can change channels. A BSSID/SSID mismatch is treated more seriously.
