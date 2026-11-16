"""
PhishShield AI — Machine Learning Model Training Pipeline
Trains a RandomForestClassifier on a curated dataset of legitimate and phishing URLs.
Extracts 15 numerical and topological features per URL and exports phishing_model.pkl.
"""

import json
import math
import os
import re
from urllib.parse import urlparse
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

# Reference lists for feature extraction
HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'click', 'buzz', 
    'club', 'fit', 'surf', 'monster', 'country', 'stream', 'download', 'win',
    'bid', 'loan', 'men', 'trade', 'date', 'faith', 'party', 'review'
}

KNOWN_TARGET_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'netflix', 'amazon', 
    'facebook', 'instagram', 'chase', 'wellsfargo', 'binance', 'metamask',
    'coinbase', 'steam', 'twitter', 'dropbox', 'linkedin', 'bank'
]

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'security', 'account', 
    'banking', 'update', 'wallet', 'confirm', 'password', 'billing', 'urgent',
    'authenticate', 'recover', 'free', 'airdrop', 'reward', 'alert', 'session'
]

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "is_https",
    "is_ip_address",
    "subdomain_count",
    "count_dots",
    "count_hyphens",
    "count_at_symbol",
    "count_double_slash",
    "has_port",
    "shannon_entropy",
    "is_high_risk_tld",
    "brand_target_flag",
    "keyword_density",
    "digit_ratio"
]

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for char in set(text):
        p_x = text.count(char) / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)

def extract_features(raw_url: str) -> list:
    url = raw_url.strip()
    if not re.match(r'^https?://', url, re.I):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse('http://invalid.url')

    hostname = (parsed.hostname or '').lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # 1. Lengths
    url_length = len(url)
    hostname_length = len(hostname)

    # 2. Protocol
    is_https = 1 if parsed.scheme == 'https' else 0

    # 3. IP host
    is_ip = 1 if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', hostname) else 0

    # 4. Subdomains
    parts = hostname.split('.')
    subdomain_count = max(0, len(parts) - 2) if not is_ip else 0
    tld = parts[-1] if len(parts) > 1 and not is_ip else ''

    # 5. Characters
    count_dots = hostname.count('.')
    count_hyphens = hostname.count('-')
    count_at = 1 if '@' in url else 0
    count_double_slash = 1 if '//' in url[8:] else 0
    has_port = 1 if parsed.port and parsed.port not in [80, 443] else 0

    # 6. Entropy & TLD
    entropy = calculate_shannon_entropy(hostname)
    is_high_risk_tld = 1 if tld in HIGH_RISK_TLDS else 0

    # 7. Brand targeting (target brand present on unauthorized domain)
    brand_flag = 0
    for brand in KNOWN_TARGET_BRANDS:
        if (brand in hostname or brand in path) and not hostname.endswith(f"{brand}.com"):
            brand_flag = 1
            break

    # 8. Phishing keywords
    full_lower = url.lower()
    matched_kws = sum(1 for kw in PHISHING_KEYWORDS if kw in full_lower)
    keyword_density = min(5, matched_kws)

    # 9. Digit ratio in hostname
    digits = sum(1 for c in hostname if c.isdigit())
    digit_ratio = round(digits / len(hostname), 3) if hostname else 0.0

    return [
        url_length,
        hostname_length,
        is_https,
        is_ip,
        subdomain_count,
        count_dots,
        count_hyphens,
        count_at,
        count_double_slash,
        has_port,
        entropy,
        is_high_risk_tld,
        brand_flag,
        keyword_density,
        digit_ratio
    ]

def build_dataset():
    """Generates a comprehensive dataset of 1,200 labeled benign and phishing URLs."""
    data = []
    labels = []  # 0 = Benign, 1 = Phishing

    # 1. Benign Samples (Top legitimate global domains & URLs)
    benign_bases = [
        "https://www.google.com/search?q=machine+learning",
        "https://accounts.google.com/signin/v2/identifier",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://github.com/torvalds/linux/commits/master",
        "https://en.wikipedia.org/wiki/Artificial_intelligence",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://apple.com/iphone-15-pro/specs/",
        "https://www.microsoft.com/en-us/windows",
        "https://support.microsoft.com/en-us/office",
        "https://netflix.com/browse",
        "https://twitter.com/home",
        "https://www.linkedin.com/feed/",
        "https://www.reddit.com/r/MachineLearning/",
        "https://stackoverflow.com/questions/tagged/python",
        "https://www.nytimes.com/section/technology",
        "https://www.bbc.com/news/world",
        "https://www.chase.com/personal/banking",
        "https://www.wellsfargo.com/",
        "https://www.paypal.com/myaccount/summary",
        "https://www.binance.com/en/trade/BTC_USDT",
        "https://docs.python.org/3/library/math.html",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
        "https://pypi.org/project/scikit-learn/",
        "https://arxiv.org/abs/1706.03762",
        "https://huggingface.co/models",
        "https://kaggle.com/datasets",
        "https://medium.com/topic/technology",
        "https://slack.com/help",
        "https://zoom.us/join",
        "https://dropbox.com/home"
    ]

    for base in benign_bases:
        for i in range(20):
            url = f"{base}?page={i}&ref=nav_{i}" if '?' not in base else f"{base}&page={i}"
            data.append(url)
            labels.append(0)

    # 2. Phishing Samples (Brand spoofs, IP hosts, homoglyphs, DGA, high-risk TLDs)
    phishing_templates = [
        "http://paypa1-security-verification.com/login?token={i}",
        "http://192.168.1.{i}/netflix-billing-update/index.php",
        "http://secure.bank-update.verify-account{i}.tk/session",
        "http://accounts.google.com.security-notice{i}.xyz/checkpoint",
        "http://apple-id-verify.support{i}.top/recover?id=883",
        "http://wellsfargo-online-banking-auth{i}.ml/portal",
        "http://binance-airdrop-reward{i}.click/connect-wallet",
        "http://metamask-seed-restore{i}.buzz/auth.php",
        "http://micros0ft-office365-login{i}.cf/owa/auth",
        "http://steam-community-gift{i}.top/trade/claim",
        "http://amazon-prime-payment-failed{i}.gq/update",
        "http://chase-bank-verify-pin{i}.work/session/login.html",
        "http://coinbase-suspended-account{i}.xyz/unlock",
        "http://faceb00k-appeal-case{i}.club/login.php",
        "http://user@paypal-verify-account{i}.top/index.php",
        "http://secure-login-token-98847a98b{i}.country/confirm",
        "http://xn--gogle-1qa.com/login?u={i}",
        "http://update-wallet-credentials{i}.monster/seed",
        "http://banking-portal-secure-auth{i}.click/login",
        "http://login.chasebank.auth-verify{i}.tk/app"
    ]

    for template in phishing_templates:
        for i in range(30):
            url = template.format(i=i)
            data.append(url)
            labels.append(1)

    return data, labels

def train_and_export():
    print("=" * 60)
    print("PhishShield AI — Machine Learning Model Training")
    print("=" * 60)

    # 1. Dataset Generation
    urls, labels = build_dataset()
    print(f"[*] Generated dataset with {len(urls)} samples ({labels.count(0)} Benign, {labels.count(1)} Phishing)")

    # 2. Feature Extraction
    print("[*] Extracting 15 numerical & topological features per URL...")
    X = np.array([extract_features(u) for u in urls])
    y = np.array(labels)

    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"[*] Training on {len(X_train)} samples, testing on {len(X_test)} samples")

    # 4. Train Random Forest Classifier
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_split=3,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = clf.predict(X_test)
    accuracy = round(accuracy_score(y_test, y_pred) * 100, 2)
    precision = round(precision_score(y_test, y_pred) * 100, 2)
    recall = round(recall_score(y_test, y_pred) * 100, 2)
    f1 = round(f1_score(y_test, y_pred) * 100, 2)

    print("\n" + "-" * 40)
    print("MODEL EVALUATION RESULTS:")
    print(f" -> Accuracy:  {accuracy}%")
    print(f" -> Precision: {precision}%")
    print(f" -> Recall:    {recall}%")
    print(f" -> F1-Score:  {f1}%")
    print("-" * 40 + "\n")

    # 6. Feature Importances
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    feature_ranking = []
    print("Top Predictive AI Features:")
    for rank, idx in enumerate(sorted_idx[:8], 1):
        feat_name = FEATURE_NAMES[idx]
        feat_imp = round(float(importances[idx]) * 100, 2)
        print(f"  {rank}. {feat_name:20s}: {feat_imp}% importance")
        feature_ranking.append({"feature": feat_name, "importance": feat_imp})

    # 7. Save Model & Metadata
    model_path = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
    meta_path = os.path.join(os.path.dirname(__file__), "model_metadata.json")

    joblib.dump(clf, model_path)
    print(f"\n[+] Successfully saved trained model to: {model_path}")

    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 120,
        "max_depth": 12,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "feature_names": FEATURE_NAMES,
        "top_features": feature_ranking
    }

    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Successfully saved model metadata to: {meta_path}")
    print("=" * 60)

if __name__ == "__main__":
    train_and_export()
