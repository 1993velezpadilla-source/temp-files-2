package com.gtx.wifiexamlab;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int REQ_PERMS = 100;
    private static final int REQ_CAPTURE = 200;
    private static final int REQ_RESULT = 201;
    private static final int REQ_EXPORT = 202;

    private WifiManager wifiManager;
    private final ArrayList<ScanResult> networks = new ArrayList<>();
    private ArrayAdapter<String> adapter;
    private ListView networkList;
    private TextView statusView;
    private TextView targetView;
    private TextView captureView;
    private TextView resultView;

    private int selectedIndex = -1;
    private String lockedSsid = "";
    private String lockedBssid = "";
    private String lockedSecurity = "";
    private int lockedChannel = 0;
    private int lockedSignal = 0;

    private String captureName = "";
    private String captureSha256 = "";
    private long captureBytes = 0;
    private String captureFormat = "";
    private long eapolMarkerCount = 0;

    private String verifiedResult = "";
    private String verifiedResultHash = "";

    private final BroadcastReceiver scanReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            refreshScanResults();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        loadLockedTarget();
        buildUi();
        requestWifiPermissions();
    }

    @Override
    protected void onResume() {
        super.onResume();
        registerReceiver(scanReceiver, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
    }

    @Override
    protected void onPause() {
        super.onPause();
        try {
            unregisterReceiver(scanReceiver);
        } catch (Exception ignored) {}
    }

    private void buildUi() {
        int pad = dp(14);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("WiFi Exam Lab");
        title.setTextSize(26f);
        title.setPadding(0, 0, 0, dp(8));
        root.addView(title);

        statusView = new TextView(this);
        statusView.setText("READY — passive/authorized workflow");
        statusView.setTextSize(14f);
        statusView.setPadding(0, 0, 0, dp(10));
        root.addView(statusView);

        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);

        Button scan = new Button(this);
        scan.setText("SCAN WIFI");
        scan.setOnClickListener(v -> startWifiScan());
        row1.addView(scan, new LinearLayout.LayoutParams(0, dp(52), 1f));

        Button lock = new Button(this);
        lock.setText("LOCK TARGET");
        lock.setOnClickListener(v -> lockSelectedTarget());
        row1.addView(lock, new LinearLayout.LayoutParams(0, dp(52), 1f));

        root.addView(row1);

        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);

        Button capture = new Button(this);
        capture.setText("IMPORT CAPTURE");
        capture.setOnClickListener(v -> chooseCapture());
        row2.addView(capture, new LinearLayout.LayoutParams(0, dp(52), 1f));

        Button result = new Button(this);
        result.setText("IMPORT RESULT");
        result.setOnClickListener(v -> chooseResult());
        row2.addView(result, new LinearLayout.LayoutParams(0, dp(52), 1f));

        root.addView(row2);

        Button export = new Button(this);
        export.setText("EXPORT EXAM REPORT");
        export.setOnClickListener(v -> createReportFile());
        root.addView(export, new LinearLayout.LayoutParams(-1, dp(52)));

        targetView = new TextView(this);
        targetView.setTextSize(15f);
        targetView.setPadding(0, dp(8), 0, dp(8));
        updateTargetView();
        root.addView(targetView);

        TextView networksLabel = new TextView(this);
        networksLabel.setText("VISIBLE NETWORKS");
        networksLabel.setTextSize(13f);
        root.addView(networksLabel);

        networkList = new ListView(this);
        adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_activated_1, new ArrayList<>());
        networkList.setAdapter(adapter);
        networkList.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
        networkList.setOnItemClickListener((parent, view, position, id) -> {
            selectedIndex = position;
            networkList.setItemChecked(position, true);
            ScanResult r = networks.get(position);
            statusView.setText("Selected: " + safeSsid(r) + " / " + r.BSSID);
        });
        root.addView(networkList, new LinearLayout.LayoutParams(-1, 0, 1f));

        ScrollView bottomScroll = new ScrollView(this);
        LinearLayout bottom = new LinearLayout(this);
        bottom.setOrientation(LinearLayout.VERTICAL);

        captureView = new TextView(this);
        captureView.setTextSize(13f);
        captureView.setPadding(0, dp(8), 0, dp(8));
        captureView.setText("CAPTURE: none");
        bottom.addView(captureView);

        resultView = new TextView(this);
        resultView.setTextSize(15f);
        resultView.setPadding(0, dp(8), 0, dp(8));
        resultView.setText("FINAL RESULT: none");
        bottom.addView(resultView);

        bottomScroll.addView(bottom);
        root.addView(bottomScroll, new LinearLayout.LayoutParams(-1, dp(160)));

        setContentView(root);
    }

    private void requestWifiPermissions() {
        ArrayList<String> perms = new ArrayList<>();
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            perms.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            perms.add(Manifest.permission.NEARBY_WIFI_DEVICES);
        }
        if (!perms.isEmpty()) {
            requestPermissions(perms.toArray(new String[0]), REQ_PERMS);
        }
    }

    private boolean hasScanPermission() {
        return checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    private void startWifiScan() {
        if (!hasScanPermission()) {
            statusView.setText("Location permission required for Wi-Fi scan.");
            requestWifiPermissions();
            return;
        }
        if (!wifiManager.isWifiEnabled()) {
            statusView.setText("Wi-Fi is disabled. Enable Wi-Fi and scan again.");
            startActivity(new Intent(Settings.ACTION_WIFI_SETTINGS));
            return;
        }

        statusView.setText("Scanning…");
        boolean accepted = wifiManager.startScan();
        if (!accepted) {
            statusView.setText("Android scan request throttled; loading cached scan results.");
            refreshScanResults();
        }
    }

    private void refreshScanResults() {
        if (!hasScanPermission()) return;

        List<ScanResult> fresh;
        try {
            fresh = wifiManager.getScanResults();
        } catch (SecurityException e) {
            statusView.setText("Permission blocked Wi-Fi results: " + e.getMessage());
            return;
        }

        networks.clear();
        networks.addAll(fresh);
        Collections.sort(networks, Comparator.comparingInt((ScanResult r) -> r.level).reversed());

        ArrayList<String> labels = new ArrayList<>();
        for (ScanResult r : networks) {
            String sec = classifySecurity(r.capabilities);
            int channel = frequencyToChannel(r.frequency);
            labels.add(
                    safeSsid(r) + "\n" +
                    r.BSSID + "   " + sec + "   ch " + channel +
                    "   " + r.level + " dBm"
            );
        }
        adapter.clear();
        adapter.addAll(labels);
        adapter.notifyDataSetChanged();
        selectedIndex = -1;
        statusView.setText("Scan complete: " + networks.size() + " BSSID(s)");
    }

    private void lockSelectedTarget() {
        if (selectedIndex < 0 || selectedIndex >= networks.size()) {
            toast("Select a network first.");
            return;
        }
        ScanResult r = networks.get(selectedIndex);
        lockedSsid = safeSsid(r);
        lockedBssid = r.BSSID == null ? "" : r.BSSID;
        lockedSecurity = classifySecurity(r.capabilities);
        lockedChannel = frequencyToChannel(r.frequency);
        lockedSignal = r.level;
        verifiedResult = "";
        verifiedResultHash = "";
        saveLockedTarget();
        updateTargetView();
        resultView.setText("FINAL RESULT: none");
        statusView.setText("TARGET LOCKED ✅");
    }

    private void updateTargetView() {
        if (targetView == null) return;
        if (lockedBssid.isEmpty()) {
            targetView.setText("TARGET: not locked");
        } else {
            targetView.setText(
                    "TARGET LOCKED\n" +
                    "SSID: " + lockedSsid + "\n" +
                    "BSSID: " + lockedBssid + "\n" +
                    "Security: " + lockedSecurity +
                    " | ch " + lockedChannel +
                    " | " + lockedSignal + " dBm"
            );
        }
    }

    private void saveLockedTarget() {
        getSharedPreferences("exam", MODE_PRIVATE).edit()
                .putString("ssid", lockedSsid)
                .putString("bssid", lockedBssid)
                .putString("security", lockedSecurity)
                .putInt("channel", lockedChannel)
                .putInt("signal", lockedSignal)
                .apply();
    }

    private void loadLockedTarget() {
        SharedPreferences p = getSharedPreferences("exam", MODE_PRIVATE);
        lockedSsid = p.getString("ssid", "");
        lockedBssid = p.getString("bssid", "");
        lockedSecurity = p.getString("security", "");
        lockedChannel = p.getInt("channel", 0);
        lockedSignal = p.getInt("signal", 0);
    }

    private void chooseCapture() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.setType("*/*");
        i.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(i, REQ_CAPTURE);
    }

    private void chooseResult() {
        if (lockedBssid.isEmpty()) {
            toast("Lock the target before importing a result.");
            return;
        }
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.setType("application/json");
        i.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(i, REQ_RESULT);
    }

    private void createReportFile() {
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.setType("application/json");
        i.putExtra(Intent.EXTRA_TITLE, "wifi_exam_report.json");
        startActivityForResult(i, REQ_EXPORT);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();

        try {
            if (requestCode == REQ_CAPTURE) {
                inspectCapture(uri);
            } else if (requestCode == REQ_RESULT) {
                importVerifiedResult(uri);
            } else if (requestCode == REQ_EXPORT) {
                writeExamReport(uri);
            }
        } catch (Exception e) {
            statusView.setText("Error: " + e.getMessage());
        }
    }

    private void inspectCapture(Uri uri) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[64 * 1024];
        long bytes = 0;
        long markerCount = 0;
        int previous = -1;
        byte[] first = new byte[4];
        int firstCount = 0;

        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException("Could not open capture.");
            int n;
            while ((n = in.read(buffer)) > 0) {
                if (firstCount < 4) {
                    int copy = Math.min(4 - firstCount, n);
                    System.arraycopy(buffer, 0, first, firstCount, copy);
                    firstCount += copy;
                }

                md.update(buffer, 0, n);
                bytes += n;
                for (int x = 0; x < n; x++) {
                    int current = buffer[x] & 0xff;
                    if (previous == 0x88 && current == 0x8e) markerCount++;
                    previous = current;
                }
            }
        }

        captureName = uri.getLastPathSegment() == null ? "capture" : uri.getLastPathSegment();
        captureSha256 = hex(md.digest());
        captureBytes = bytes;
        eapolMarkerCount = markerCount;
        captureFormat = detectCaptureFormat(first, firstCount);

        captureView.setText(
                "CAPTURE IMPORTED\n" +
                captureName + "\n" +
                "Format: " + captureFormat + "\n" +
                "Size: " + captureBytes + " bytes\n" +
                "SHA-256: " + captureSha256 + "\n" +
                "EAPOL marker heuristic: " + eapolMarkerCount
        );
        statusView.setText("Capture integrity metadata ready ✅");
    }

    private void importVerifiedResult(Uri uri) throws Exception {
        String raw = readText(uri, 1024 * 1024);
        JSONObject o = new JSONObject(raw);
        String ssid = o.optString("target_ssid", "");
        String bssid = o.optString("target_bssid", "");
        String value = o.optString("result_value", "");

        if (value.isEmpty()) {
            resultView.setText("FINAL RESULT: empty result file");
            return;
        }

        if (!normalizeMac(lockedBssid).equals(normalizeMac(bssid))) {
            resultView.setText("FINAL RESULT: TARGET_MISMATCH (BSSID)");
            return;
        }
        if (!ssid.isEmpty() && !lockedSsid.equals(ssid)) {
            resultView.setText("FINAL RESULT: TARGET_MISMATCH (SSID)");
            return;
        }

        verifiedResult = value;
        verifiedResultHash = sha256(value.getBytes("UTF-8"));
        resultView.setText(
                "FINAL RESULT VERIFIED ✅\n" +
                "SSID: " + lockedSsid + "\n" +
                "BSSID: " + lockedBssid + "\n" +
                "Result: " + verifiedResult + "\n" +
                "SHA-256: " + verifiedResultHash
        );
        statusView.setText("Verified final result loaded ✅");
    }

    private void writeExamReport(Uri uri) throws Exception {
        JSONObject target = new JSONObject();
        target.put("ssid", lockedSsid);
        target.put("bssid", lockedBssid);
        target.put("security", lockedSecurity);
        target.put("channel", lockedChannel);
        target.put("signal_dbm", lockedSignal);

        JSONObject capture = new JSONObject();
        capture.put("name", captureName);
        capture.put("format", captureFormat);
        capture.put("size_bytes", captureBytes);
        capture.put("sha256", captureSha256);
        capture.put("eapol_marker_heuristic", eapolMarkerCount);

        JSONObject result = new JSONObject();
        result.put("status", verifiedResult.isEmpty() ? "NO_RESULT" : "RESULT_VERIFIED");
        result.put("value", verifiedResult);
        result.put("sha256", verifiedResultHash);

        JSONObject report = new JSONObject();
        report.put("app", "WiFi Exam Lab Android");
        report.put("created_at", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US).format(new Date()));
        report.put("target", target);
        report.put("capture", capture);
        report.put("final_result", result);
        report.put("scope", "Authorized classroom/home-lab auditing");
        report.put("password_cracking", false);
        report.put("forced_deauthentication", false);

        try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
            if (out == null) throw new IllegalStateException("Could not create report.");
            out.write(report.toString(2).getBytes("UTF-8"));
        }

        statusView.setText("Exam report exported ✅");
    }

    private String readText(Uri uri, int maxBytes) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            if (in == null) throw new IllegalStateException("Could not open file.");
            byte[] b = new byte[8192];
            int n;
            int total = 0;
            while ((n = in.read(b)) > 0) {
                total += n;
                if (total > maxBytes) throw new IllegalStateException("File is too large.");
                out.write(b, 0, n);
            }
            return out.toString("UTF-8");
        }
    }

    private String safeSsid(ScanResult r) {
        String s = r.SSID;
        return (s == null || s.isEmpty()) ? "<hidden>" : s;
    }

    private String classifySecurity(String caps) {
        String c = caps == null ? "" : caps.toUpperCase(Locale.US);
        if (c.contains("SAE") || c.contains("WPA3")) return "WPA3";
        if (c.contains("RSN") || c.contains("WPA2")) return "WPA2";
        if (c.contains("WPA")) return "WPA";
        if (c.contains("WEP")) return "WEP";
        return "OPEN/UNKNOWN";
    }

    private int frequencyToChannel(int f) {
        if (f == 2484) return 14;
        if (f >= 2412 && f <= 2472) return (f - 2407) / 5;
        if (f >= 5000 && f <= 5895) return (f - 5000) / 5;
        if (f >= 5955 && f <= 7115) return (f - 5950) / 5;
        return 0;
    }

    private String detectCaptureFormat(byte[] b, int n) {
        if (n < 4) return "UNKNOWN";
        int b0 = b[0] & 0xff, b1 = b[1] & 0xff, b2 = b[2] & 0xff, b3 = b[3] & 0xff;
        if (b0 == 0x0a && b1 == 0x0d && b2 == 0x0d && b3 == 0x0a) return "PCAPNG";
        if ((b0 == 0xd4 && b1 == 0xc3 && b2 == 0xb2 && b3 == 0xa1) ||
            (b0 == 0xa1 && b1 == 0xb2 && b2 == 0xc3 && b3 == 0xd4) ||
            (b0 == 0x4d && b1 == 0x3c && b2 == 0xb2 && b3 == 0xa1) ||
            (b0 == 0xa1 && b1 == 0xb2 && b2 == 0x3c && b3 == 0x4d)) return "PCAP";
        return "UNKNOWN";
    }

    private String normalizeMac(String s) {
        return s == null ? "" : s.replace(":", "").replace("-", "").trim().toLowerCase(Locale.US);
    }

    private String sha256(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format(Locale.US, "%02x", b & 0xff));
        return sb.toString();
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    private int dp(int n) {
        return Math.round(n * getResources().getDisplayMetrics().density);
    }
}
