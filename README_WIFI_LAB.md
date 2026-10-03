# WiFi Security Lab v0.2

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
