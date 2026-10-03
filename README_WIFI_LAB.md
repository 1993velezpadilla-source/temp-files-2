# WiFi Security Lab v0.1

Authorized classroom/home-lab Wi-Fi auditing helper.

## What it does
- Scans nearby Wi-Fi networks.
- Shows SSID, BSSID, security type, signal and channel when the OS exposes them.
- Lets the user lock one authorized target.
- Saves a JSON evidence report.

## Platforms
- Windows: uses `netsh wlan show networks mode=bssid`
- Linux: uses `nmcli dev wifi list`

## Run
```
python wifi_lab.py
```

## Important limitation
This build does **not** include password cracking, forced deauthentication, or credential extraction.

## Next safe milestones
- GUI instead of terminal.
- Better WPA2/WPA3/WPS classification.
- Adapter capability checks.
- Import/display authorized capture evidence.
- Export a polished exam report.
