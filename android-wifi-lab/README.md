# WiFi Exam Lab Android

Native Android companion for the authorized Wi-Fi exam workflow.

## Current APK features

- Nearby Wi-Fi scan using Android WifiManager.
- Per-BSSID target selection and lock.
- Security classification: WPA3 / WPA2 / WPA / WEP / open-or-unknown.
- Channel, signal and BSSID display.
- Persistent locked target.
- PCAP/PCAPNG import for file-format detection, SHA-256, size and a lightweight EAPOL EtherType marker heuristic.
- Verified final-result JSON import tied to the locked SSID/BSSID.
- Exam report export as JSON.
- Touch-safe layout for phones and foldables.

## Scope

This Android build does not brute-force or crack unknown Wi-Fi passwords and does not transmit deauthentication frames.

## Build

GitHub Actions workflow `wifi-lab-android.yml` builds `app-debug.apk` and uploads it as an artifact.
