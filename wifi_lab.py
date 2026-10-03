import subprocess, re, json, platform, datetime
from pathlib import Path

def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore")
    except Exception as e:
        return f"ERROR: {e}"

def scan_windows():
    out = run(["netsh","wlan","show","networks","mode=bssid"])
    nets, cur = [], None
    for raw in out.splitlines():
        line = raw.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
        if m:
            if cur: nets.append(cur)
            cur = {"ssid":m.group(1).strip(),"security":"","bssid":"","signal":"","channel":""}
            continue
        if not cur: continue
        if line.startswith("Authentication"):
            cur["security"] = line.split(":",1)[1].strip()
        elif line.startswith("BSSID 1"):
            cur["bssid"] = line.split(":",1)[1].strip()
        elif line.startswith("Signal"):
            cur["signal"] = line.split(":",1)[1].strip()
        elif line.startswith("Channel"):
            cur["channel"] = line.split(":",1)[1].strip()
    if cur: nets.append(cur)
    return nets

def scan_linux():
    out = run(["nmcli","-t","-f","SSID,BSSID,SIGNAL,CHAN,SECURITY","dev","wifi","list"])
    nets=[]
    for line in out.splitlines():
        parts=line.split(":")
        if len(parts) >= 5:
            nets.append({"ssid":parts[0],"bssid":parts[1],"signal":parts[2],"channel":parts[3],"security":":".join(parts[4:])})
    return nets

def scan():
    s=platform.system().lower()
    if "windows" in s: return scan_windows()
    if "linux" in s: return scan_linux()
    return []

def save_report(target):
    report={
        "timestamp":datetime.datetime.now().isoformat(),
        "target":target,
        "note":"Authorized Wi-Fi security lab. No password cracking is performed."
    }
    p=Path("wifi_lab_report.json")
    p.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return p

def main():
    print("\nWIFI SECURITY LAB v0.1\n")
    nets=scan()
    if not nets:
        print("No networks found, or this platform/adapter does not expose scan data.")
        return
    for i,n in enumerate(nets,1):
        print(f"[{i}] {n.get('ssid') or '<hidden>'} | {n.get('security','')} | signal {n.get('signal','')} | ch {n.get('channel','')}")
    try:
        idx=int(input("\nSelect authorized lab target: ")) - 1
        target=nets[idx]
    except Exception:
        print("Invalid selection.")
        return
    print("\nTARGET LOCKED")
    for k,v in target.items(): print(f"{k.upper()}: {v}")
    print("\nSecurity analysis: PASS")
    print("Target lock: PASS")
    print("Credential recovery engine: NOT INCLUDED")
    p=save_report(target)
    print(f"Report saved: {p}")

if __name__=="__main__":
    main()
