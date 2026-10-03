# WiFi Security Lab v1

Classroom-focused Wi-Fi evidence tool.

## What this build does
- Lists nearby Wi-Fi access points on Windows (netsh) or Linux (nmcli).
- Locks the selected SSID/BSSID as the exam target.
- Imports .pcap/.pcapng/.cap evidence.
- Uses TShark to isolate EAPOL frames for the selected BSSID.
- Reports observed RSNA 4-way handshake message numbers when Wireshark exposes them.
- Records a manual candidate credential and an instructor/device validation event.
- Exports a timestamped text report.

## What it intentionally does not do
This branch does not automate password guessing, brute force, dictionary attacks, deauthentication, packet injection, or credential extraction.

## Requirements
Python 3.11+ and Tkinter.
For packet analysis, install Wireshark/TShark and ensure tshark is on PATH.
On Linux, nmcli is used for discovery.

## Run
```
python app.py
```

## Windows build
The GitHub Actions workflow builds a standalone EXE with PyInstaller. TShark is not bundled; install Wireshark on the exam/lab machine.

## Exam workflow
1. Scan.
2. Select the AP identified by the instructor.
3. Lock target.
4. Open authorized capture.
5. Analyze EAPOL evidence.
6. Record instructor/device validation.
7. Save report.
