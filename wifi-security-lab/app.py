import os, platform, re, subprocess, shutil, datetime, tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "WiFi Security Lab"
TARGET = None

def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, shell=isinstance(cmd, str))
    return p.returncode, p.stdout, p.stderr

def scan_windows():
    code, out, err = run(["netsh","wlan","show","networks","mode=bssid"])
    if code != 0:
        raise RuntimeError(err or out or "netsh scan failed")
    nets=[]; current=None
    for raw in out.splitlines():
        line=raw.strip()
        m=re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
        if m:
            if current: nets.append(current)
            current={"ssid":m.group(1).strip() or "<hidden>","bssid":"","security":"","signal":"","channel":""}
            continue
        if not current: continue
        if line.lower().startswith("authentication"):
            current["security"]=line.split(":",1)[1].strip()
        elif re.match(r"BSSID\s+\d+", line, re.I) and not current["bssid"]:
            current["bssid"]=line.split(":",1)[1].strip()
        elif line.lower().startswith("signal") and not current["signal"]:
            current["signal"]=line.split(":",1)[1].strip()
        elif line.lower().startswith("channel") and not current["channel"]:
            current["channel"]=line.split(":",1)[1].strip()
    if current: nets.append(current)
    return nets

def scan_linux():
    if not shutil.which("nmcli"):
        raise RuntimeError("nmcli not found")
    code,out,err=run(["nmcli","-t","-f","SSID,BSSID,SECURITY,SIGNAL,CHAN","dev","wifi","list","--rescan","yes"])
    if code != 0:
        raise RuntimeError(err or out)
    nets=[]
    for line in out.splitlines():
        # nmcli escapes ':' inside values; this parser intentionally keeps discovery simple.
        parts=line.split(":")
        if len(parts) < 8: continue
        ssid=parts[0] or "<hidden>"
        bssid=":".join(parts[1:7])
        security=parts[7] if len(parts)>7 else ""
        signal=parts[8] if len(parts)>8 else ""
        channel=parts[9] if len(parts)>9 else ""
        nets.append({"ssid":ssid,"bssid":bssid,"security":security,"signal":signal,"channel":channel})
    return nets

def scan_networks():
    system=platform.system().lower()
    if system=="windows":
        return scan_windows()
    if system=="linux":
        return scan_linux()
    raise RuntimeError("Live scan currently supports Windows or Linux.")

def analyze_capture(path, bssid=""):
    tshark=shutil.which("tshark")
    if not tshark:
        raise RuntimeError("TShark is required. Install Wireshark/TShark first.")
    fields=["frame.number","wlan.sa","wlan.da","wlan.bssid","wlan_rsna_eapol.keydes.msgnr"]
    cmd=[tshark,"-r",path,"-Y","eapol","-T","fields"]
    for f in fields: cmd += ["-e",f]
    cmd += ["-E","separator=|","-E","occurrence=f"]
    code,out,err=run(cmd)
    if code != 0:
        raise RuntimeError(err or "TShark failed")
    rows=[]; msgs=set()
    for line in out.splitlines():
        cols=(line.split("|")+[""]*5)[:5]
        row=dict(zip(fields,cols))
        if bssid:
            bb=bssid.lower()
            participants=" ".join([row["wlan.sa"],row["wlan.da"],row["wlan.bssid"]]).lower()
            if bb not in participants:
                continue
        if row["wlan_rsna_eapol.keydes.msgnr"].isdigit():
            msgs.add(int(row["wlan_rsna_eapol.keydes.msgnr"]))
        rows.append(row)
    return rows, msgs

def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("920x650")
        self.minsize(820,560)
        self.target=None
        self.capture_path=None
        self.rows=[]
        self.msgs=set()
        self.build()

    def build(self):
        top=ttk.Frame(self,padding=12); top.pack(fill="x")
        ttk.Label(top,text=APP_TITLE,font=("Segoe UI",18,"bold")).pack(side="left")
        ttk.Button(top,text="SCAN WI-FI",command=self.scan).pack(side="right")

        cols=("ssid","bssid","security","signal","channel")
        self.tree=ttk.Treeview(self,columns=cols,show="headings",height=10)
        for c,w in zip(cols,(220,190,180,100,80)):
            self.tree.heading(c,text=c.upper()); self.tree.column(c,width=w,anchor="w")
        self.tree.pack(fill="x",padx=12)
        ttk.Button(self,text="LOCK SELECTED TARGET",command=self.lock_target).pack(pady=8)

        self.target_lbl=ttk.Label(self,text="TARGET: none",padding=(12,6))
        self.target_lbl.pack(fill="x")

        box=ttk.LabelFrame(self,text="Authentication evidence",padding=12); box.pack(fill="x",padx=12,pady=8)
        row=ttk.Frame(box); row.pack(fill="x")
        ttk.Button(row,text="OPEN PCAP / PCAPNG",command=self.open_capture).pack(side="left")
        ttk.Button(row,text="ANALYZE EAPOL",command=self.analyze).pack(side="left",padx=8)
        self.evidence_lbl=ttk.Label(row,text="No capture loaded"); self.evidence_lbl.pack(side="left",padx=8)

        cand=ttk.LabelFrame(self,text="Manual credential candidate (lab / instructor-provided)",padding=12); cand.pack(fill="x",padx=12,pady=8)
        self.candidate=tk.StringVar()
        ttk.Entry(cand,textvariable=self.candidate,show="*",width=42).pack(side="left")
        self.show_var=tk.BooleanVar(value=False)
        ttk.Checkbutton(cand,text="Show",variable=self.show_var,command=self.toggle_candidate).pack(side="left",padx=8)
        ttk.Button(cand,text="MARK VERIFIED BY INSTRUCTOR DEVICE",command=self.mark_verified).pack(side="left",padx=8)

        self.status=tk.Text(self,height=12,wrap="word")
        self.status.pack(fill="both",expand=True,padx=12,pady=8)
        self.log("Ready. This build discovers APs and validates capture evidence; it does not automate password guessing.")

        bottom=ttk.Frame(self,padding=12); bottom.pack(fill="x")
        ttk.Button(bottom,text="SAVE REPORT",command=self.save_report).pack(side="right")

    def toggle_candidate(self):
        for w in self.winfo_children():
            pass
        # Find entry recursively
        def rec(parent):
            for c in parent.winfo_children():
                if isinstance(c, ttk.Entry):
                    c.configure(show="" if self.show_var.get() else "*")
                rec(c)
        rec(self)

    def log(self,msg):
        self.status.insert("end",f"[{now()}] {msg}\n"); self.status.see("end")

    def scan(self):
        try:
            nets=scan_networks()
            for i in self.tree.get_children(): self.tree.delete(i)
            for n in nets:
                self.tree.insert("", "end", values=(n["ssid"],n["bssid"],n["security"],n["signal"],n["channel"]))
            self.log(f"Scan complete: {len(nets)} access points listed.")
        except Exception as e:
            messagebox.showerror("Scan failed",str(e)); self.log(f"SCAN ERROR: {e}")

    def lock_target(self):
        sel=self.tree.selection()
        if not sel:
            messagebox.showwarning("Target","Select an access point first."); return
        vals=self.tree.item(sel[0],"values")
        self.target=dict(zip(("ssid","bssid","security","signal","channel"),vals))
        self.target_lbl.config(text=f'TARGET LOCKED — SSID: {self.target["ssid"]} | BSSID: {self.target["bssid"]} | Security: {self.target["security"]} | Ch: {self.target["channel"]}')
        self.log(f'Target locked: {self.target["ssid"]} / {self.target["bssid"]}')

    def open_capture(self):
        p=filedialog.askopenfilename(filetypes=[("Packet captures","*.pcap *.pcapng *.cap"),("All files","*.*")])
        if p:
            self.capture_path=p; self.evidence_lbl.config(text=os.path.basename(p)); self.log(f"Capture selected: {p}")

    def analyze(self):
        if not self.capture_path:
            messagebox.showwarning("Capture","Open a capture first."); return
        try:
            bssid=self.target["bssid"] if self.target else ""
            self.rows,self.msgs=analyze_capture(self.capture_path,bssid)
            full={1,2,3,4}.issubset(self.msgs)
            self.log(f"EAPOL frames matching target: {len(self.rows)}")
            self.log(f"Observed 4-way message numbers: {sorted(self.msgs) if self.msgs else 'not exposed by dissector'}")
            self.log("HANDSHAKE EVIDENCE: COMPLETE 1/2/3/4" if full else "HANDSHAKE EVIDENCE: PARTIAL/UNCONFIRMED")
            self.evidence_lbl.config(text=f"EAPOL={len(self.rows)} | messages={sorted(self.msgs)}")
        except Exception as e:
            messagebox.showerror("Analysis failed",str(e)); self.log(f"ANALYSIS ERROR: {e}")

    def mark_verified(self):
        if not self.candidate.get():
            messagebox.showwarning("Candidate","Enter the credential candidate being tested in the controlled lab."); return
        self.log("CREDENTIAL VALIDATION: instructor/device manual confirmation recorded as PASS.")
        messagebox.showinfo("Verified","Manual validation recorded. Save the report for evidence.")

    def save_report(self):
        p=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("Text report","*.txt")])
        if not p: return
        target=self.target or {}
        report=[
            "WIFI SECURITY LAB REPORT",
            f"Generated: {now()}",
            f"SSID: {target.get('ssid','')}",
            f"BSSID: {target.get('bssid','')}",
            f"Security: {target.get('security','')}",
            f"Signal: {target.get('signal','')}",
            f"Channel: {target.get('channel','')}",
            f"Capture: {self.capture_path or ''}",
            f"EAPOL frames: {len(self.rows)}",
            f"Observed handshake message numbers: {sorted(self.msgs)}",
            "",
            "EVENT LOG",
            self.status.get("1.0","end").strip()
        ]
        with open(p,"w",encoding="utf-8") as f: f.write("\n".join(report))
        self.log(f"Report saved: {p}")

if __name__=="__main__":
    App().mainloop()
