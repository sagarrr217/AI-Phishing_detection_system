# 🛡️ PhishShield AI — Real-Time Phishing Threat Protection Chrome Extension

A real-time, privacy-first **Google Chrome Extension (Manifest V3)** that protects users from deceptive phishing websites, credential harvesting traps, homoglyph domain attacks, and fraudulent URLs as they browse.

---

## ⚡ Key Highlights & Core Capabilities

- **Real-Time Zero-Latency Detection**: Evaluates URLs in `<3ms` directly in-browser using client-side heuristics, Shannon entropy, homoglyph substitutions, and high-risk TLD filters.
- **Automated In-Page Threat Warning Pop-Up**: When a user navigates to a dangerous or fraudulent site, PhishShield AI immediately injects an unmissable, isolated modal overlay (`#phishshield-overlay-host`) preventing credential theft.
- **Audible Alert & Desktop Notifications**: Emits an alert chime and native Chrome desktop notification on high-risk detections.
- **Interactive Toolbar Action Popup**:
  - Radial Safety Score Gauge ($0 - 100$) with color-coded risk bands.
  - Live metric breakdown: Protocol encryption, Brand Spoofing Sentinel, Shannon Entropy, TLD abuse correlation.
  - Expandable Explainable AI (XAI) diagnostic findings list.
  - **Quick Link Scanner**: Allows pasting links from emails, SMS, or chats to inspect them safely *before* opening.
- **Custom Whitelist & Sensitivity Controls**: Supports Strict, Balanced, and Permissive sensitivity thresholds, custom domain exemptions, and optional connection to local FastAPI machine learning servers.
- **Self-Contained & Isolated**: Does not require any external server to work, zero cloud telemetry, runs 100% client-side.

---

## 📂 Project Architecture

```
x:\project\phishing detection extention\
│
├── manifest.json              # Chrome Extension Manifest V3 configuration
├── background.js              # Background service worker (navigation & badge controller)
├── test_samples.html          # Interactive local testbench for simulated phishing links
├── README.md                  # Installation and developer documentation
│
├── scripts/
│   ├── detector-engine.js     # Standalone heuristic, entropy, brand & ML feature analyzer
│   └── test_engine.js         # Automated test suite (6/6 passing unit tests)
│
├── content/
│   ├── content.js             # Content script: DOM password trap sensor & overlay injector
│   └── content.css            # Scoped modal styles, pulse animations, and danger card UI
│
├── popup/
│   ├── popup.html             # Toolbar action popup dashboard
│   ├── popup.css              # Cyber-themed dark mode styling with radial gauge
│   └── popup.js               # Popup controller & quick URL scanner
│
├── options/
│   ├── options.html           # Settings & whitelist management dashboard
│   ├── options.css            # Settings styling & custom slider switches
│   └── options.js             # Settings persistence to chrome.storage
│
└── icons/
    ├── generate_icons.py      # Pillow generation script for crisp cyber shield icons
    ├── icon16.png             # 16x16 toolbar icon
    ├── icon32.png             # 32x32 high-DPI icon
    ├── icon48.png             # 48x48 extensions manager icon
    └── icon128.png            # 128x128 Chrome Web Store icon
```

---

## 🚀 How to Load and Install in Google Chrome

1. Open **Google Chrome** (or any Chromium browser like Brave, Microsoft Edge, Opera).
2. In the URL address bar, navigate to:
   ```
   chrome://extensions
   ```
3. In the top-right corner, turn ON **"Developer mode"**.
4. Click the **"Load unpacked"** button in the top-left toolbar.
5. In the file picker dialog, navigate to and select the folder:
   ```
   X:\project\phishing detection extention
   ```
6. Click **Select Folder**.
7. You will immediately see **"PhishShield AI — Real-Time Phishing Protection"** installed with its glowing cyber shield icon!
8. Click the puzzle icon (Extensions) in your Chrome toolbar and **pin** PhishShield AI to your toolbar.

---

## 🧪 How to Test Real-Time Detection

### Method 1: Use the Built-in Testbench
1. In Chrome, press `Ctrl + O` and open:
   ```
   X:\project\phishing detection extention\test_samples.html
   ```
2. Click any of the simulated phishing links (e.g. `http://paypal-verification-update.tk/login` or `http://192.168.1.100/chase/login.php`).
3. Notice how PhishShield immediately:
   - Changes the toolbar badge to **`!`** (Red Alert).
   - Injects the warning modal pop-up: **"CRITICAL PHISHING THREAT DETECTED"**.
   - Displays the safety score (e.g. `15/100`), the reasons, and offers a 1-click **"Leave This Dangerous Site"** button.

### Method 2: Test Any Link via Quick Scanner in the Toolbar Popup
1. Click the **PhishShield AI shield icon** in the Chrome toolbar.
2. Switch to the **"Quick Scanner"** tab.
3. Paste any URL or click the sample chip (e.g. `PayPal Phish`, `IP Phish`, or `Safe Google`).
4. Click **Analyze** to inspect the URL topology and safety score instantly.

---

## ⚙️ Settings & Configuration

Click the gear icon in the extension popup or right-click the extension icon and select **Options**:
- **Real-Time Navigation Protection**: Enable/disable automated background monitoring.
- **Sensitivity Level**:
  - *Strict*: Flags minor anomalies, elevated entropy, and uncommon TLDs.
  - *Balanced (Default)*: Calibrated for minimal false positives with maximal attack catch rate.
  - *Permissive*: Blocks only confirmed high-danger exploits.
- **Warning Pop-Up Mode**: Toggle modal overlay and alert audio tone.
- **Whitelist Management**: Add trusted internal domains (`intranet.mycompany.com`) to bypass scanning.
- **Optional FastAPI Connection**: Toggle connection to `http://localhost:8000/api/scan` if running the Python microservice from the main project.

