/**
 * PhishShield AI — Minimal & Intuitive Popup Script
 * Designed for effortless understanding in <2 seconds.
 * Powered by client-side 120-Tree Random Forest ML Model.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Navigation Tabs
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanes.forEach(p => p.classList.add('is-hidden'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const targetPane = document.getElementById(btn.dataset.tab);
      if (targetPane) targetPane.classList.remove('is-hidden');
    });
  });

  // Header Elements
  const headerStatusPill = document.getElementById('header-status-pill');
  const headerStatusText = document.getElementById('header-status-text');
  const openOptionsBtn = document.getElementById('open-options-btn');

  // Hero Card Elements
  const tabLoading = document.getElementById('tab-loading');
  const tabResultContent = document.getElementById('tab-result-content');
  const heroCard = document.getElementById('hero-card');
  const heroIconBox = document.getElementById('hero-icon-box');
  const safetyScoreVal = document.getElementById('safety-score-val');
  const verdictHeadline = document.getElementById('verdict-headline');
  const verdictDesc = document.getElementById('verdict-desc');
  const domainLockIcon = document.getElementById('domain-lock-icon');
  const domainText = document.getElementById('domain-text');
  const copyUrlBtn = document.getElementById('copy-url-btn');

  // 3-Point Checklist Elements
  const bulletSsl = document.getElementById('bullet-ssl');
  const valSsl = document.getElementById('val-ssl');
  const bulletDomain = document.getElementById('bullet-domain');
  const valDomain = document.getElementById('val-domain');
  const bulletAi = document.getElementById('bullet-ai');
  const valAi = document.getElementById('val-ai');

  // Technical Details Drawer
  const toggleDetails = document.getElementById('toggle-details');
  const detailsToggleLabel = document.getElementById('details-toggle-label');
  const detailsDrawer = document.getElementById('details-drawer');
  const chevronIcon = toggleDetails ? toggleDetails.querySelector('.chevron-icon') : null;
  const detailAiProb = document.getElementById('detail-ai-prob');
  const detailEntropy = document.getElementById('detail-entropy');
  const detailTld = document.getElementById('detail-tld');
  const detailFindings = document.getElementById('detail-findings');

  // Action Buttons
  const rescanBtn = document.getElementById('rescan-btn');
  const whitelistBtn = document.getElementById('whitelist-btn');

  // Manual Scanner
  const manualUrlInput = document.getElementById('manual-url-input');
  const manualScanBtn = document.getElementById('manual-scan-btn');
  const manualResultBox = document.getElementById('manual-result-box');
  const sampleChips = document.querySelectorAll('.sample-chip');

  let currentTabUrl = '';
  let currentTabHost = '';

  // Open Options Page
  function openOptions() {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options/options.html'));
    }
  }
  if (openOptionsBtn) openOptionsBtn.addEventListener('click', openOptions);

  // Toggle Technical Details Drawer
  if (toggleDetails && detailsDrawer) {
    toggleDetails.addEventListener('click', () => {
      const isHidden = detailsDrawer.classList.toggle('is-hidden');
      toggleDetails.setAttribute('aria-expanded', !isHidden ? 'true' : 'false');
      if (detailsToggleLabel) {
        detailsToggleLabel.textContent = isHidden ? 'Show Technical Details' : 'Hide Technical Details';
      }
      if (chevronIcon) {
        chevronIcon.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(180deg)';
      }
    });
  }

  // Copy URL Button with friendly checkmark animation
  if (copyUrlBtn) {
    copyUrlBtn.addEventListener('click', () => {
      if (currentTabUrl) {
        navigator.clipboard.writeText(currentTabUrl).then(() => {
          const originalHTML = copyUrlBtn.innerHTML;
          copyUrlBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width:13px;height:13px;">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
          `;
          setTimeout(() => {
            copyUrlBtn.innerHTML = originalHTML;
          }, 1500);
        });
      }
    });
  }

  // Inspect Active Tab
  function inspectActiveTab() {
    if (tabLoading) tabLoading.classList.remove('is-hidden');
    if (tabResultContent) tabResultContent.classList.add('is-hidden');

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      let activeTab = tabs && tabs[0];
      if (!activeTab || !activeTab.url) {
        chrome.tabs.query({ active: true, lastFocusedWindow: true }, (lastTabs) => {
          handleTabInspection(lastTabs ? lastTabs[0] : null);
        });
      } else {
        handleTabInspection(activeTab);
      }
    });
  }

  function handleTabInspection(tab) {
    if (tabLoading) tabLoading.classList.add('is-hidden');
    if (tabResultContent) tabResultContent.classList.remove('is-hidden');

    if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
      renderSystemTab(tab?.url || 'chrome://');
      return;
    }

    currentTabUrl = tab.url;
    try {
      currentTabHost = new URL(tab.url).hostname;
    } catch (e) {
      currentTabHost = tab.url;
    }

    // Direct real-time scan using the 120-tree ML model & continuous scoring
    const result = PhishShieldEngine.analyzeURL(tab.url);
    renderMinimalResults(result);

    // Sync with background service worker to update badge & logs
    chrome.runtime.sendMessage({
      action: 'UPDATE_ACTIVE_TAB_RESULT',
      payload: { tabId: tab.id, url: tab.url, result }
    });
  }

  function renderSystemTab(url) {
    heroCard.className = 'hero-card hero-safe';
    heroIconBox.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        <polyline points="9 12 11 14 15 10"></polyline>
      </svg>
    `;
    safetyScoreVal.textContent = '100';
    verdictHeadline.textContent = 'Browser Internal Page';
    verdictDesc.textContent = 'PhishShield is active. Internal browser tabs are completely safe.';
    domainLockIcon.textContent = '🔒';
    domainText.textContent = url;

    bulletSsl.className = 'check-bullet';
    bulletSsl.textContent = '✓';
    valSsl.textContent = 'Internal Browser Memory';
    valSsl.className = 'check-status safe';

    bulletDomain.className = 'check-bullet';
    bulletDomain.textContent = '✓';
    valDomain.textContent = 'Verified System Tab';
    valDomain.className = 'check-status safe';

    bulletAi.className = 'check-bullet';
    bulletAi.textContent = '✓';
    valAi.textContent = 'Safe';
    valAi.className = 'check-status safe';
  }

  function renderMinimalResults(res) {
    const score = typeof res.safetyScore === 'number' ? res.safetyScore : 50;
    const status = res.status; // 'safe', 'warning', or 'danger'

    safetyScoreVal.textContent = score;

    // Header Pill
    if (status === 'safe') {
      headerStatusPill.className = 'status-pill status-safe';
      headerStatusText.textContent = 'Protected';
    } else if (status === 'warning') {
      headerStatusPill.className = 'status-pill status-warn';
      headerStatusText.textContent = 'Caution';
    } else {
      headerStatusPill.className = 'status-pill status-danger';
      headerStatusText.textContent = 'Threat';
    }

    // Hero Card Style & Headline
    heroCard.className = `hero-card hero-${status}`;

    if (status === 'safe') {
      heroIconBox.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          <polyline points="9 12 11 14 15 10"></polyline>
        </svg>
      `;
      verdictHeadline.textContent = 'This Website is Safe';
      verdictDesc.textContent = res.verdictSummary || 'Verified destination. No phishing or fraudulent signs detected.';
    } else if (status === 'warning') {
      heroIconBox.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
          <line x1="12" y1="9" x2="12" y2="13"></line>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
      `;
      verdictHeadline.textContent = 'Caution: Unsecured Site';
      verdictDesc.textContent = res.verdictSummary || 'This site has security warnings. Do not submit sensitive passwords.';
    } else {
      heroIconBox.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
      `;
      verdictHeadline.textContent = 'Phishing Threat Detected!';
      verdictDesc.textContent = res.adviceDetail || 'Dangerous fake website attempting to steal credentials or payment details.';
    }

    // Domain display
    domainLockIcon.textContent = res.parsed?.protocol === 'https' ? '🔒' : '⚠️';
    domainText.textContent = currentTabHost || res.url;
    domainText.title = res.url;

    // 3-Point Checklist: Plain English
    // 1. Connection
    const isHttps = res.parsed?.protocol === 'https';
    if (isHttps) {
      bulletSsl.className = 'check-bullet';
      bulletSsl.textContent = '✓';
      valSsl.textContent = 'Secure (HTTPS)';
      valSsl.className = 'check-status safe';
    } else {
      bulletSsl.className = 'check-bullet warn';
      bulletSsl.textContent = '!';
      valSsl.textContent = 'Insecure (Unencrypted HTTP)';
      valSsl.className = 'check-status warn';
    }

    // 2. Identity & Spoofing
    const hasBrandSpoof = res.findings?.some(f => f.title?.includes('Targeting Brand') || f.title?.includes('Homoglyph'));
    if (!hasBrandSpoof) {
      bulletDomain.className = 'check-bullet';
      bulletDomain.textContent = '✓';
      valDomain.textContent = 'Authentic Domain';
      valDomain.className = 'check-status safe';
    } else {
      bulletDomain.className = 'check-bullet danger';
      bulletDomain.textContent = '✗';
      valDomain.textContent = 'Impersonation / Spoof';
      valDomain.className = 'check-status danger';
    }

    // 3. AI Scan
    const aiProb = res.aiPhishingProb !== undefined ? Math.round(res.aiPhishingProb * 100) : 0;
    if (status === 'safe') {
      bulletAi.className = 'check-bullet';
      bulletAi.textContent = '✓';
      valAi.textContent = 'Passed (Clean)';
      valAi.className = 'check-status safe';
    } else if (status === 'warning') {
      bulletAi.className = 'check-bullet warn';
      bulletAi.textContent = '!';
      valAi.textContent = `${aiProb}% Threat Probability`;
      valAi.className = 'check-status warn';
    } else {
      bulletAi.className = 'check-bullet danger';
      bulletAi.textContent = '✗';
      valAi.textContent = `High Risk (${aiProb}% Threat)`;
      valAi.className = 'check-status danger';
    }

    // Technical Drawer Data
    if (detailAiProb) detailAiProb.textContent = `${aiProb}%`;
    if (detailEntropy) detailEntropy.textContent = res.metrics?.entropyLabel || 'Normal';
    if (detailTld) detailTld.textContent = res.metrics?.tldLabel || 'Standard';

    if (detailFindings) {
      const findings = res.findings || [];
      detailFindings.innerHTML = findings.map(f => {
        const cls = f.severity === 'danger' ? '' : (f.severity === 'warning' ? 'warn' : 'safe');
        return `<div class="finding-tag ${cls}">• ${escapeHtml(f.title)}</div>`;
      }).join('') || '<div style="font-size:10.5px;color:#64748b;">No red flags detected.</div>';
    }
  }

  // Re-check Site Button
  if (rescanBtn) {
    rescanBtn.addEventListener('click', () => {
      rescanBtn.innerHTML = `
        <div class="spinner" style="width:11px;height:11px;border-width:2px;margin:0;"></div>
        <span>Checking...</span>
      `;
      inspectActiveTab();
      setTimeout(() => {
        rescanBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="23 4 23 10 17 10"></polyline>
            <polyline points="1 20 1 14 7 14"></polyline>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
          </svg>
          <span>Re-check Site</span>
        `;
      }, 500);
    });
  }

  // Whitelist Button
  if (whitelistBtn) {
    whitelistBtn.addEventListener('click', () => {
      if (!currentTabHost) return;
      chrome.runtime.sendMessage({
        action: 'ADD_TO_WHITELIST',
        payload: { domain: currentTabHost }
      }, () => {
        whitelistBtn.textContent = '✓ Trusted';
        whitelistBtn.style.color = 'var(--safe-green)';
        setTimeout(() => {
          whitelistBtn.textContent = 'Trust Site';
          whitelistBtn.style.color = '';
        }, 2000);
      });
    });
  }

  // Manual Scanner
  function performManualScan(url) {
    if (!url || !url.trim()) return;
    const cleanUrl = url.trim();

    manualResultBox.classList.remove('is-hidden');
    manualResultBox.innerHTML = `
      <div style="text-align:center;padding:14px;font-size:12px;color:#94a3b8;background:var(--bg-main);border-radius:8px;">
        <div class="spinner" style="margin:0 auto 6px auto;width:20px;height:20px;"></div>
        Scanning URL with AI Model...
      </div>
    `;

    setTimeout(() => {
      const r = PhishShieldEngine.analyzeURL(cleanUrl);
      const score = r.safetyScore;
      const status = r.status;
      const statusLabel = status === 'safe' ? 'SAFE' : (status === 'warning' ? 'CAUTION' : 'DANGEROUS PHISHING');
      const badgeCls = `status-${status}`;

      manualResultBox.innerHTML = `
        <div class="hero-card hero-${status}" style="margin-top:6px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
            <span class="status-pill ${badgeCls}">${statusLabel}</span>
            <span style="font-size:12px;font-weight:700;color:#fff;">Score: ${score}/100</span>
          </div>
          <div style="font-size:13px;font-weight:700;color:#fff;margin-bottom:2px;">
            ${escapeHtml(r.verdictHeadline)}
          </div>
          <div style="font-size:11.5px;color:#94a3b8;line-height:1.35;margin-bottom:6px;">
            ${escapeHtml(r.verdictSummary || r.adviceDetail)}
          </div>
          <div style="font-family:var(--font-mono);font-size:10.5px;color:#38bdf8;word-break:break-all;background:rgba(0,0,0,0.3);padding:4px 8px;border-radius:4px;">
            ${escapeHtml(r.url)}
          </div>
        </div>
      `;
    }, 150);
  }

  if (manualScanBtn) {
    manualScanBtn.addEventListener('click', () => {
      performManualScan(manualUrlInput.value);
    });
  }

  if (manualUrlInput) {
    manualUrlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        performManualScan(manualUrlInput.value);
      }
    });
  }

  sampleChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const url = chip.dataset.sample;
      manualUrlInput.value = url;
      performManualScan(url);
    });
  });

  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initial load
  inspectActiveTab();
});
