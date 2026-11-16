/**
 * PhishShield AI — Chrome Extension Background Service Worker
 * Manifest V3 background processor for real-time navigation monitoring,
 * tab analysis, dynamic badge states, threat notifications, and history management.
 */

importScripts('scripts/ml-model-data.js');
importScripts('scripts/detector-engine.js');

const DEFAULT_SETTINGS = {
  realtimeProtection: true,
  sensitivity: 'balanced', // 'strict', 'balanced', 'permissive'
  alertMode: 'modal', // 'modal', 'banner', 'badge_only'
  enableNotifications: true,
  enableAudioAlert: true,
  apiBaseUrl: 'http://localhost:8000',
  useBackendIfAvailable: true,
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

// In-memory tab analysis cache
const tabAnalysisCache = new Map();

/**
 * Initialize extension default settings on install
 */
chrome.runtime.onInstalled.addListener(async (details) => {
  const current = await chrome.storage.local.get(['settings', 'history']);
  if (!current.settings) {
    await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  }
  if (!current.history) {
    await chrome.storage.local.set({ history: [] });
  }
  console.log('[PhishShield AI] Extension installed/updated. Background Service Worker active.');
});

/**
 * Helper to fetch settings from storage
 */
async function getSettings() {
  const data = await chrome.storage.local.get('settings');
  return Object.assign({}, DEFAULT_SETTINGS, data.settings || {});
}

/**
 * Checks if a hostname or domain is in user's whitelist
 */
function isDomainWhitelisted(hostname, whitelist = []) {
  if (!hostname) return false;
  const cleanHost = hostname.toLowerCase();
  return whitelist.some(domain => {
    const cleanDomain = domain.toLowerCase().trim();
    return cleanHost === cleanDomain || cleanHost.endsWith('.' + cleanDomain);
  });
}

/**
 * Saves scan result to recent history
 */
async function logScanToHistory(result) {
  try {
    const data = await chrome.storage.local.get('history');
    let history = data.history || [];
    
    // Add timestamp and ID
    const entry = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      url: result.url,
      hostname: result.parsed?.hostname || 'unknown',
      status: result.status,
      safetyScore: result.safetyScore,
      verdictHeadline: result.verdictHeadline,
      isMalicious: result.isMalicious
    };

    // Filter out duplicates within last 3 entries for same host
    history = history.filter(h => h.url !== entry.url || (Date.now() - new Date(h.timestamp).getTime()) > 300000);
    history.unshift(entry);
    if (history.length > 50) history = history.slice(0, 50);

    await chrome.storage.local.set({ history });
  } catch (e) {
    console.error('[PhishShield AI] Error saving scan to history:', e);
  }
}

/**
 * Updates extension action badge for a tab
 */
function updateTabBadge(tabId, result) {
  if (!tabId || !result) return;

  if (result.status === 'danger') {
    chrome.action.setBadgeText({ tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#DC2626' }); // Crimson Red
    chrome.action.setTitle({ tabId, title: `PhishShield ALERT: Malicious Phishing Site (${result.safetyScore}/100)` });
  } else if (result.status === 'warning') {
    chrome.action.setBadgeText({ tabId, text: 'WARN' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#D97706' }); // Amber
    chrome.action.setTitle({ tabId, title: `PhishShield Caution: Suspicious Link (${result.safetyScore}/100)` });
  } else {
    chrome.action.setBadgeText({ tabId, text: 'SAFE' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#059669' }); // Emerald Green
    chrome.action.setTitle({ tabId, title: `PhishShield Verified: Safe Website (${result.safetyScore}/100)` });
  }
}

/**
 * Analyze Tab URL and trigger real-time alerts if dangerous
 */
async function inspectTab(tabId, url) {
  if (!url || typeof url !== 'string') return;

  // Ignore internal and privileged URLs
  if (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:') ||
    url.startsWith('view-source:')
  ) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  const settings = await getSettings();
  if (!settings.realtimeProtection) {
    chrome.action.setBadgeText({ tabId, text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748B' });
    return;
  }

  // Parse hostname
  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch (e) {
    return;
  }

  // Check Whitelist
  if (isDomainWhitelisted(hostname, settings.whitelist)) {
    chrome.action.setBadgeText({ tabId, text: 'PASS' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#059669' });
    chrome.action.setTitle({ tabId, title: `Whitelisted Domain: ${hostname}` });
    return;
  }

  // Analyze URL
  let result;
  if (settings.useBackendIfAvailable && settings.apiBaseUrl) {
    result = await PhishShieldEngine.scanUrlWithBackendFallback(url, settings.apiBaseUrl);
  } else {
    result = PhishShieldEngine.analyzeURL(url);
  }

  // Store in cache
  tabAnalysisCache.set(tabId, result);

  // Update badge UI
  updateTabBadge(tabId, result);

  // Log scan history
  logScanToHistory(result);

  // Check if threshold requires real-time in-page warning popup
  let shouldTriggerAlert = false;
  if (result.status === 'danger') {
    shouldTriggerAlert = true;
  } else if (result.status === 'warning' && settings.sensitivity === 'strict') {
    shouldTriggerAlert = true;
  }

  if (shouldTriggerAlert) {
    // 1. Chrome Desktop Notification
    if (settings.enableNotifications) {
      try {
        chrome.notifications.create(`threat-${tabId}-${Date.now()}`, {
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '🚨 PHISHING RISK DETECTED!',
          message: `${hostname} has been identified as a dangerous website (${result.safetyScore}/100). Do not input sensitive credentials!`,
          priority: 2
        });
      } catch (err) {
        // Notification permission fallback
      }
    }

    // 2. Dispatch message to Content Script to inject in-page warning overlay
    try {
      chrome.tabs.sendMessage(tabId, {
        action: 'INJECT_THREAT_POPUP',
        result,
        settings
      });
    } catch (err) {
      // Content script may not have injected yet if page is loading
    }
  }
}

/**
 * Listen for navigation committed events (fires immediately on navigation)
 */
chrome.webNavigation.onCommitted.addListener((details) => {
  // Only inspect top-level frame (frameId === 0)
  if (details.frameId === 0) {
    inspectTab(details.tabId, details.url);
  }
});

/**
 * Listen for tab updates (e.g., URL change, page load completion)
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const targetUrl = changeInfo.url || tab.url;
  if (targetUrl && (changeInfo.status === 'complete' || changeInfo.url)) {
    inspectTab(tabId, targetUrl);
  }
});

/**
 * Listen for tab activation (fires when user switches between open tabs)
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url) {
      inspectTab(tab.id, tab.url);
    }
  } catch (e) {
    // Ignore if tab is transitional
  }
});

/**
 * Clean cache on tab close
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  tabAnalysisCache.delete(tabId);
});

/**
 * Handle incoming messages from popup, content scripts, and options
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const { action, payload } = request;

  if (action === 'GET_CURRENT_TAB_ANALYSIS') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs || tabs.length === 0) {
        sendResponse({ error: 'No active tab found' });
        return;
      }
      const activeTab = tabs[0];
      const cached = tabAnalysisCache.get(activeTab.id);
      if (cached && cached.url === activeTab.url) {
        sendResponse({ result: cached, tab: activeTab });
      } else {
        const result = PhishShieldEngine.analyzeURL(activeTab.url || '');
        tabAnalysisCache.set(activeTab.id, result);
        updateTabBadge(activeTab.id, result);
        sendResponse({ result, tab: activeTab });
      }
    });
    return true; // Keep message channel open for async response
  }

  if (action === 'UPDATE_ACTIVE_TAB_RESULT') {
    if (payload && payload.result) {
      const tabId = payload.tabId;
      if (tabId) {
        tabAnalysisCache.set(tabId, payload.result);
        updateTabBadge(tabId, payload.result);
      }
      logScanToHistory(payload.result);
    }
    sendResponse({ success: true });
    return true;
  }

  if (action === 'SCAN_MANUAL_URL') {
    (async () => {
      const settings = await getSettings();
      let res;
      if (settings.useBackendIfAvailable && settings.apiBaseUrl) {
        res = await PhishShieldEngine.scanUrlWithBackendFallback(payload.url, settings.apiBaseUrl);
      } else {
        res = PhishShieldEngine.analyzeURL(payload.url);
      }
      sendResponse({ result: res });
    })();
    return true;
  }

  if (action === 'CLOSE_CURRENT_TAB') {
    const tabId = sender.tab ? sender.tab.id : payload?.tabId;
    if (tabId) {
      chrome.tabs.remove(tabId);
    }
    sendResponse({ success: true });
    return true;
  }

  if (action === 'NAVIGATE_TO_SAFETY') {
    const tabId = sender.tab ? sender.tab.id : payload?.tabId;
    if (tabId) {
      chrome.tabs.update(tabId, { url: 'https://www.google.com' });
    }
    sendResponse({ success: true });
    return true;
  }

  if (action === 'ADD_TO_WHITELIST') {
    (async () => {
      const settings = await getSettings();
      const domain = payload.domain.toLowerCase().trim();
      if (!settings.whitelist.includes(domain)) {
        settings.whitelist.push(domain);
        await chrome.storage.local.set({ settings });
      }
      if (sender.tab && sender.tab.id) {
        chrome.action.setBadgeText({ tabId: sender.tab.id, text: 'PASS' });
        chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: '#059669' });
      }
      sendResponse({ success: true, whitelist: settings.whitelist });
    })();
    return true;
  }

  if (action === 'REMOVE_FROM_WHITELIST') {
    (async () => {
      const settings = await getSettings();
      const domain = payload.domain.toLowerCase().trim();
      settings.whitelist = settings.whitelist.filter(d => d !== domain);
      await chrome.storage.local.set({ settings });
      sendResponse({ success: true, whitelist: settings.whitelist });
    })();
    return true;
  }

  if (action === 'DOM_CREDENTIALS_DETECTED') {
    // Content script discovered sensitive login form on suspicious or HTTP page
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      const cached = tabAnalysisCache.get(tabId) || PhishShieldEngine.analyzeURL(sender.tab.url);
      cached.safetyScore = Math.min(cached.safetyScore, 12);
      cached.threatScore = Math.max(cached.threatScore, 88);
      cached.status = 'danger';
      cached.isMalicious = true;
      cached.findings.push({
        severity: 'danger',
        title: 'Unsecured Credential Form Detected',
        detail: 'Page contains password or credit card input fields on an unverified or insecure domain.'
      });
      tabAnalysisCache.set(tabId, cached);
      updateTabBadge(tabId, cached);
      sendResponse({ success: true, updatedResult: cached });
    }
    return true;
  }

  if (action === 'RELOAD_SETTINGS') {
    getSettings().then(settings => sendResponse({ settings }));
    return true;
  }
});

