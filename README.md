# PhishShield AI — Intelligent Phishing Link Detection System

An AI-powered cybersecurity web application that detects phishing URLs, zero-day lookalike domains, homograph attacks, and credential harvesting traps.

![PhishShield Logo](assets/shield-logo.jpg)

---

## 🎯 How It Works

Users simply paste any link into the web application. PhishShield AI conducts a multi-vector heuristic & machine learning inspection in milliseconds:

1. **Lexical & Topology Analysis:**
   - Detects direct IP hostnames (e.g. `http://192.168.1.45/login`).
   - Identifies credential injection tricks via the `@` symbol.
   - Detects URL parser evasion via multiple consecutive slashes `//`.
   - Analyzes excessive subdomain depth (domain nesting).

2. **Homoglyph & Brand Impersonation Defense:**
   - Detects IDN homograph punycode (`xn--...`).
   - Scans for visual letter-to-digit substitutions (e.g., `paypa1`, `go0gle`, `app1e`).
   - Cross-references high-value target brands (PayPal, Netflix, Microsoft, Google, Steam, Chase, Binance) against unauthorized root domains.

3. **Information Theory & Obfuscation:**
   - Computes **Shannon Entropy** ($H = -\sum p(x) \log_2 p(x)$) of hostname and path to spot Domain Generation Algorithms (DGA) and randomized tracking tokens.

4. **Network & Protocol Integrity:**
   - Flags unencrypted HTTP connections.
   - Checks against high-risk spam/phishing abuse TLDs (`.tk`, `.ml`, `.top`, `.xyz`, etc.).
   - Detects URL shortener cloaking (`bit.ly`, `tinyurl`, `t.co`).

---

## 🚀 Running the Web Application

### Option 1: Instant Local View (No dependencies needed)
You can directly open `index.html` in any web browser:
- Double click [index.html](file:///c:/Users/Lenovo/project/index.html) in your file explorer.
- Or launch a local web server:
  ```bash
  # Using Python built-in server:
  python -m http.server 3000
  ```
  Then visit `http://localhost:3000` in your browser.

---

### Option 2: Running with Python FastAPI Microservice
To run the full decoupled AI REST backend:

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the API server:
   ```bash
   python api.py
   ```
   API runs at: `http://127.0.0.1:8000`  
   Interactive API docs (Swagger): `http://127.0.0.1:8000/docs`

---

## 📁 Project Structure

```
project/
├── assets/
│   └── shield-logo.jpg          # Branding security emblem
├── index.html                   # Modern cyber-dark web interface
├── style.css                    # Glassmorphism design system & micro-animations
├── app.js                       # AI detection engine & reactive UI logic
├── api.py                       # Python FastAPI backend microservice
├── requirements.txt             # Backend dependencies
└── README.md                    # Project documentation
```
