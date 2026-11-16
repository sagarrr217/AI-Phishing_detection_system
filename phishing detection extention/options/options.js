/**
 * PhishShield AI — Options Page Controller
 * Manages user preferences, custom domain whitelists, sensitivity thresholds,
 * and optional local machine learning API configurations.
 */

document.addEventListener('DOMContentLoaded', () => {
  const realtimeToggle = document.getElementById('realtime-toggle');
  const sensitivitySelect = document.getElementById('sensitivity-select');
  const modalToggle = document.getElementById('modal-toggle');
  const audioToggle = document.getElementById('audio-toggle');
  const notifyToggle = document.getElementById('notify-toggle');

  const whitelistInput = document.getElementById('whitelist-input');
  const addWhitelistBtn = document.getElementById('add-whitelist-btn');
  const whitelistTagsContainer = document.getElementById('whitelist-tags-container');

  const backendToggle = document.getElementById('backend-toggle');
  const apiUrlInput = document.getElementById('api-url-input');
  const testApiBtn = document.getElementById('test-api-btn');
  const apiStatusBadge = document.getElementById('api-status-badge');

  const saveBtnTop = document.getElementById('save-btn-top');
  const saveBtnBottom = document.getElementById('save-btn-bottom');
  const resetBtn = document.getElementById('reset-btn');
  const saveToast = document.getElementById('save-toast');

  let currentWhitelist = [];

  const DEFAULTS = {
    realtimeProtection: true,
    sensitivity: 'balanced',
    alertMode: 'modal',
    enableNotifications: true,
    enableAudioAlert: true,
    apiBaseUrl: 'http://localhost:8000',
    useBackendIfAvailable: false,
    whitelist: [
      'google.com',
      'microsoft.com',
      'apple.com',
      'github.com',
      'paypal.com',
      'amazon.com',
      'netflix.com'
    ]
  };

  /**
   * Load stored settings
   */
  function loadSettings() {
    chrome.storage.local.get('settings', (data) => {
      const s = Object.assign({}, DEFAULTS, data.settings || {});

      realtimeToggle.checked = s.realtimeProtection !== false;
      sensitivitySelect.value = s.sensitivity || 'balanced';
      modalToggle.checked = s.alertMode !== 'notification_only';
      audioToggle.checked = s.enableAudioAlert !== false;
      notifyToggle.checked = s.enableNotifications !== false;

      backendToggle.checked = !!s.useBackendIfAvailable;
      apiUrlInput.value = s.apiBaseUrl || 'http://localhost:8000';

      currentWhitelist = Array.isArray(s.whitelist) ? [...s.whitelist] : [...DEFAULTS.whitelist];
      renderWhitelistTags();
    });
  }

  /**
   * Render Whitelist Tag Pills
   */
  function renderWhitelistTags() {
    whitelistTagsContainer.innerHTML = '';
    currentWhitelist.forEach((domain, idx) => {
      const tag = document.createElement('div');
      tag.className = 'whitelist-tag';
      tag.innerHTML = `
        <span>${escapeHtml(domain)}</span>
        <span class="whitelist-tag-remove" data-index="${idx}" title="Remove domain">&times;</span>
      `;
      whitelistTagsContainer.appendChild(tag);
    });

    // Attach remove handlers
    whitelistTagsContainer.querySelectorAll('.whitelist-tag-remove').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const index = parseInt(e.target.dataset.index, 10);
        currentWhitelist.splice(index, 1);
        renderWhitelistTags();
      });
    });
  }

  /**
   * Add new domain to whitelist
   */
  function addDomain() {
    let domain = whitelistInput.value.trim().toLowerCase();
    if (!domain) return;

    // Strip http/https and paths if pasted
    domain = domain.replace(/^https?:\/\//i, '').split('/')[0];

    if (!currentWhitelist.includes(domain)) {
      currentWhitelist.push(domain);
      renderWhitelistTags();
      whitelistInput.value = '';
    }
  }

  addWhitelistBtn.addEventListener('click', addDomain);
  whitelistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addDomain();
  });

  /**
   * Test Connection to FastAPI Backend
   */
  testApiBtn.addEventListener('click', async () => {
    const url = apiUrlInput.value.trim().replace(/\/+$/, '');
    apiStatusBadge.className = 'api-status-badge';
    apiStatusBadge.textContent = 'Pinging...';

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${url}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://google.com' }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        apiStatusBadge.className = 'api-status-badge api-status-connected';
        apiStatusBadge.textContent = '✓ Microservice Online';
      } else {
        apiStatusBadge.className = 'api-status-badge api-status-error';
        apiStatusBadge.textContent = 'Server Error (HTTP ' + res.status + ')';
      }
    } catch (e) {
      apiStatusBadge.className = 'api-status-badge api-status-error';
      apiStatusBadge.textContent = 'Offline / Inaccessible';
    }
  });

  /**
   * Save All Settings
   */
  function saveSettings() {
    const settings = {
      realtimeProtection: realtimeToggle.checked,
      sensitivity: sensitivitySelect.value,
      alertMode: modalToggle.checked ? 'modal' : 'notification_only',
      enableAudioAlert: audioToggle.checked,
      enableNotifications: notifyToggle.checked,
      useBackendIfAvailable: backendToggle.checked,
      apiBaseUrl: apiUrlInput.value.trim(),
      whitelist: currentWhitelist
    };

    chrome.storage.local.set({ settings }, () => {
      chrome.runtime.sendMessage({ action: 'RELOAD_SETTINGS' });
      showToast();
    });
  }

  function showToast() {
    saveToast.classList.remove('is-hidden');
    setTimeout(() => {
      saveToast.classList.add('is-hidden');
    }, 2400);
  }

  saveBtnTop.addEventListener('click', saveSettings);
  saveBtnBottom.addEventListener('click', saveSettings);

  resetBtn.addEventListener('click', () => {
    if (confirm('Reset all PhishShield AI settings and whitelist to defaults?')) {
      chrome.storage.local.set({ settings: DEFAULTS }, () => {
        loadSettings();
        showToast();
      });
    }
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

  loadSettings();
});

