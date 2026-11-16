/**
 * PhishShield AI — Content Script & Real-Time Security Sentinel
 * Runs in the context of web pages to perform local DOM security checks,
 * listen for background threat alerts, and display the unmissable phishing warning modal.
 */

(function () {
  'use strict';

  let overlayHost = null;
  let shadowRoot = null;

  /**
   * Synthesize security warning alert tone via Web Audio API
   */
  function playSecurityAudioAlert() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(480, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(260, ctx.currentTime + 0.35);

      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.36);
    } catch (e) {
      // Audio playback restrictions fallback
    }
  }

  /**
   * Injects the phishing threat modal overlay into an isolated Shadow DOM
   */
  function showThreatModal(result, settings = {}) {
    if (sessionStorage.getItem('ps_dismissed') === '1') {
      return; // User has already explicitly dismissed for this session
    }

    if (overlayHost) {
      overlayHost.remove();
    }

    // Play audible alert if enabled
    if (settings.enableAudioAlert !== false) {
      playSecurityAudioAlert();
    }

    overlayHost = document.createElement('div');
    overlayHost.id = 'phishshield-overlay-host';
    overlayHost.style.all = 'initial';
    overlayHost.style.position = 'fixed';
    overlayHost.style.zIndex = '2147483647';
    overlayHost.style.top = '0';
    overlayHost.style.left = '0';

    shadowRoot = overlayHost.attachShadow({ mode: 'open' });

    // Fetch and inject CSS
    const styleEl = document.createElement('style');
    styleEl.textContent = `
      :host {
        all: initial;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #f1f5f9;
      }
      #ps-backdrop {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(5, 8, 18, 0.88);
        backdrop-filter: blur(20px) saturate(160%);
        -webkit-backdrop-filter: blur(20px) saturate(160%);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
        box-sizing: border-box;
        animation: psFade 0.22s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }
      @keyframes psFade {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      @keyframes psRise {
        from { opacity: 0; transform: scale(0.94) translateY(24px); }
        to { opacity: 1; transform: scale(1) translateY(0); }
      }
      @keyframes psHalo {
        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.55); }
        70% { box-shadow: 0 0 0 16px rgba(239, 68, 68, 0); }
        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
      }
      .ps-card {
        width: 100%;
        max-width: 580px;
        background: #0b1122;
        border: 1px solid rgba(239, 68, 68, 0.45);
        border-radius: 20px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.85), 0 0 45px rgba(239, 68, 68, 0.22), inset 0 1px 0 rgba(255, 255, 255, 0.08);
        overflow: hidden;
        box-sizing: border-box;
        color: #f1f5f9;
        animation: psRise 0.28s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }
      .ps-header {
        background: linear-gradient(135deg, rgba(220, 38, 38, 0.25) 0%, rgba(11, 17, 34, 0.95) 100%);
        border-bottom: 1px solid rgba(239, 68, 68, 0.25);
        padding: 22px 26px;
        display: flex;
        align-items: center;
        gap: 16px;
      }
      .ps-icon {
        width: 54px;
        height: 54px;
        min-width: 54px;
        border-radius: 50%;
        background: rgba(239, 68, 68, 0.15);
        border: 2px solid #ef4444;
        display: flex;
        align-items: center;
        justify-content: center;
        animation: psHalo 2s infinite;
      }
      .ps-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 10.5px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #f87171;
        background: rgba(239, 68, 68, 0.16);
        padding: 3px 8px;
        border-radius: 6px;
        border: 1px solid rgba(239, 68, 68, 0.35);
        margin-bottom: 5px;
      }
      .ps-title {
        margin: 0;
        font-size: 18.5px;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: -0.02em;
        line-height: 1.25;
      }
      .ps-body {
        padding: 22px 26px;
        display: flex;
        flex-direction: column;
        gap: 14px;
      }
      .ps-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: rgba(4, 7, 18, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.07);
        border-radius: 10px;
        padding: 10px 14px;
      }
      .ps-score-tag {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12.5px;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 6px;
        background: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.4);
      }
      .ps-ai-pill {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 11px;
        font-weight: 700;
        color: #38bdf8;
        background: rgba(0, 229, 255, 0.12);
        border: 1px solid rgba(0, 229, 255, 0.25);
        padding: 3px 9px;
        border-radius: 6px;
      }
      .ps-summary {
        font-size: 13px;
        line-height: 1.5;
        color: #e2e8f0;
        background: rgba(239, 68, 68, 0.09);
        border-left: 4px solid #ef4444;
        padding: 12px 14px;
        border-radius: 0 8px 8px 0;
      }
      .ps-url {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 11px;
        background: #040712;
        padding: 8px 12px;
        border-radius: 8px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        color: #94a3b8;
        word-break: break-all;
        max-height: 52px;
        overflow-y: auto;
      }
      .ps-toggle {
        background: transparent;
        border: none;
        color: #38bdf8;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        padding: 2px 0;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        text-align: left;
      }
      .ps-toggle:hover { color: #7dd3fc; }
      .ps-findings {
        display: none;
        flex-direction: column;
        gap: 6px;
        max-height: 140px;
        overflow-y: auto;
      }
      .ps-findings.show { display: flex; }
      .ps-item {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 6px;
        padding: 8px 10px;
        border-left: 3px solid #ef4444;
      }
      .ps-item-title { font-size: 11.5px; font-weight: 700; color: #f8fafc; }
      .ps-item-desc { font-size: 10.5px; color: #94a3b8; margin-top: 2px; }
      .ps-footer {
        padding: 18px 26px 22px;
        display: flex;
        flex-direction: column;
        gap: 8px;
        border-top: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(4, 7, 18, 0.5);
      }
      .ps-btn-leave {
        width: 100%;
        min-height: 44px;
        padding: 12px 18px;
        border-radius: 10px;
        font-size: 13.5px;
        font-weight: 700;
        background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
        color: #ffffff;
        border: 1px solid rgba(239, 68, 68, 0.6);
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        box-shadow: 0 4px 16px rgba(220, 38, 38, 0.45);
        transition: transform 0.15s ease, filter 0.15s ease;
      }
      .ps-btn-leave:hover {
        transform: translateY(-1px);
        filter: brightness(1.1);
        box-shadow: 0 6px 20px rgba(220, 38, 38, 0.6);
      }
      .ps-btn-leave:focus-visible {
        outline: 3px solid #ffffff;
        outline-offset: 2px;
      }
      .ps-btn-dismiss {
        width: 100%;
        padding: 8px 12px;
        border-radius: 8px;
        font-size: 11.5px;
        font-weight: 600;
        background: transparent;
        color: #64748b;
        border: 1px solid transparent;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      .ps-btn-dismiss:hover {
        color: #94a3b8;
        background: rgba(255, 255, 255, 0.04);
        border-color: rgba(255, 255, 255, 0.08);
      }
    `;

    shadowRoot.appendChild(styleEl);

    // Build markup
    const backdrop = document.createElement('div');
    backdrop.id = 'ps-backdrop';

    const findingsHtml = (result.findings || []).map(f => `
      <div class="ps-item">
        <div class="ps-item-title">${escapeHtml(f.title)}</div>
        <div class="ps-item-desc">${escapeHtml(f.detail)}</div>
      </div>
    `).join('');

    const aiProbPct = result.aiPhishingProb !== undefined ? Math.round(result.aiPhishingProb * 100) : 95;

    backdrop.innerHTML = `
      <div class="ps-card" role="alertdialog" aria-modal="true" aria-labelledby="ps-title-id">
        <div class="ps-header">
          <div class="ps-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width:28px;height:28px;">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
          </div>
          <div>
            <div class="ps-badge">PhishShield AI Alert</div>
            <h2 class="ps-title" id="ps-title-id">CRITICAL PHISHING THREAT DETECTED</h2>
          </div>
        </div>
        <div class="ps-body">
          <div class="ps-row">
            <span class="ps-score-tag">Score: ${result.safetyScore || 15}/100 (DANGER)</span>
            <span class="ps-ai-pill">AI: ${aiProbPct}% Phish Prob (120 Trees)</span>
          </div>
          <div class="ps-summary">
            ${escapeHtml(result.adviceDetail || 'This page has been identified as a high-risk malicious or phishing site attempting to steal your credentials.')}
          </div>
          <div class="ps-url" title="Suspicious URL">${escapeHtml(result.url || window.location.href)}</div>
          
          ${result.findings && result.findings.length > 0 ? `
            <button class="ps-toggle" id="ps-toggle-btn" aria-expanded="false">
              <span>▶</span> View Technical Diagnostic Findings (${result.findings.length})
            </button>
            <div class="ps-findings" id="ps-findings-box">
              ${findingsHtml}
            </div>
          ` : ''}
        </div>
        <div class="ps-footer">
          <button class="ps-btn-leave" id="ps-leave-btn" autofocus>
            🛡️ Leave This Dangerous Site (Recommended)
          </button>
          <button class="ps-btn-dismiss" id="ps-dismiss-btn">
            Dismiss Warning & Proceed at My Own Risk
          </button>
        </div>
      </div>
    `;

    shadowRoot.appendChild(backdrop);
    document.documentElement.appendChild(overlayHost);

    // Auto-focus the safe escape button
    const leaveBtn = shadowRoot.getElementById('ps-leave-btn');
    if (leaveBtn) {
      setTimeout(() => leaveBtn.focus(), 50);
      leaveBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'NAVIGATE_TO_SAFETY' }, () => {
          window.location.href = 'https://www.google.com';
        });
      });
    }

    const dismissBtn = shadowRoot.getElementById('ps-dismiss-btn');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => {
        sessionStorage.setItem('ps_dismissed', '1');
        overlayHost.remove();
        overlayHost = null;
      });
    }

    const toggleBtn = shadowRoot.getElementById('ps-toggle-btn');
    const findingsBox = shadowRoot.getElementById('ps-findings-box');
    if (toggleBtn && findingsBox) {
      toggleBtn.addEventListener('click', () => {
        const isShown = findingsBox.classList.toggle('show');
        toggleBtn.setAttribute('aria-expanded', isShown ? 'true' : 'false');
        toggleBtn.querySelector('span').textContent = isShown ? '▼' : '▶';
      });
    }
  }

  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Real-time DOM inspection: Checks for suspicious password fields or forms
   */
  function inspectDOMForCredentialTraps() {
    // Only inspect HTTP or suspicious domains
    const isHTTP = window.location.protocol === 'http:';
    const pwdInputs = document.querySelectorAll('input[type="password"]');

    if (pwdInputs.length > 0 && isHTTP) {
      console.warn('[PhishShield AI] Plaintext password input detected on unencrypted HTTP page!');
      chrome.runtime.sendMessage({ action: 'DOM_CREDENTIALS_DETECTED' }, (res) => {
        if (res && res.updatedResult) {
          showThreatModal(res.updatedResult);
        }
      });
    }
  }

  /**
   * Listen for messages from background service worker
   */
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'INJECT_THREAT_POPUP') {
      showThreatModal(msg.result, msg.settings);
      sendResponse({ received: true });
    }
  });

  /**
   * Local immediate pre-check on document start / DOM content loaded
   */
  function initRealtimeCheck() {
    if (typeof PhishShieldEngine !== 'undefined') {
      const quickResult = PhishShieldEngine.analyzeURL(window.location.href);
      if (quickResult.status === 'danger') {
        showThreatModal(quickResult);
      }
    }
  }

  // Run on initial load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initRealtimeCheck();
      inspectDOMForCredentialTraps();
    });
  } else {
    initRealtimeCheck();
    inspectDOMForCredentialTraps();
  }

  // Observe DOM for dynamically loaded password forms (SPAs)
  const observer = new MutationObserver(() => {
    inspectDOMForCredentialTraps();
  });
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }

})();
