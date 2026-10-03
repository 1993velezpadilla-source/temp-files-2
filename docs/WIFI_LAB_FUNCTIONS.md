# WiFi Security Lab — Function-first status

Current branch: `wifi-security-lab-v1`

## Core workflow

1. `RUN_WIFI_LAB.bat readiness`
2. `RUN_WIFI_LAB.bat scan`
3. Lock the authorized AP by BSSID.
4. Import an authorized PCAP/PCAPNG if one is available.
5. Run capture quality + EAPOL evidence analysis.
6. Build a portable evidence ZIP.

Example:

```bat
RUN_WIFI_LAB.bat bundle --capture exam.pcapng --bssid AA:BB:CC:DD:EE:FF --out exam_bundle.zip
```

## Functions already present in wifi_lab.py

- Windows/Linux Wi-Fi discovery.
- Per-BSSID target selection.
- WPA/WPA2/WPA3/WEP/open classification.
- Adapter and capture-tool inventory.
- TShark interface enumeration.
- Local interface/gateway snapshot.
- Imported PCAP/PCAPNG statistics and SHA-256 fingerprint.
- Passive beacon/probe-response AP profiling.
- RSN AKM/cipher observations.
- PMF capable/required observations when available.
- WPS advertisement/setup-lock observations when available.
- EAPOL frame detection and conservative M1/M2/M3/M4 classification.
- Capture quality/readiness states.
- SSID-to-BSSID grouping and configuration-drift comparison.
- Anonymized station counting for a selected authorized AP.
- JSON + Markdown evidence reports.

## New helper tools

### wifi_lab_bundle.py

Creates one ZIP containing the report, manifest, hashes and optional capture evidence.

### wifi_lab_batch.py

Processes a folder of PCAP/PCAPNG files and creates one triage JSON report.

### RUN_WIFI_LAB.bat

Windows launcher so the exam workflow does not depend on remembering Python commands.

## Scope

The project is intentionally passive/diagnostic: it does not transmit forced disconnects and does not automate password brute-force/cracking.
