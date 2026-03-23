import '../lib/url-utils.js';
import { DEFAULT_BASE_URL, THREAT_COLORS } from '../lib/constants.js';
import { getSettings, saveSettings, setCache, getApiToken, saveApiToken, clearApiToken, getApiTokenValidated } from '../lib/storage.js';
import { checkHealth, fetchUniFiSettings, batchThreatLookup, fetchTrafficStats, setBaseUrl, getBaseUrl, setAuthToken, getAuthToken, setAuthErrorHandler } from '../lib/api-client.js';

const SW_LOG_PREFIX = '[ULI][SW]';
const PERMISSION_RETRY_DELAYS_MS = [0, 150, 350, 800, 1200];
// Loaded by `import '../lib/url-utils.js'` above — always available.
const toOriginPattern = globalThis.ULI_URL_UTILS.toOriginPattern;

function swLog(...args) {
  console.log(SW_LOG_PREFIX, ...args);
}

function swWarn(...args) {
  console.warn(SW_LOG_PREFIX, ...args);
  swWarnCount++;
}

function swError(...args) {
  console.error(SW_LOG_PREFIX, ...args);
  swErrorCount++;
}

// Diagnostic counter — exposed via DEBUG message for user bug reports
let swErrorCount = 0;
let swWarnCount = 0;
const swStartedAt = Date.now();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function hasPermissionWithRetry(origin, source, delaysMs = PERMISSION_RETRY_DELAYS_MS) {
  for (let i = 0; i < delaysMs.length; i++) {
    if (delaysMs[i] > 0) await sleep(delaysMs[i]);
    try {
      const hasPermission = await chrome.permissions.contains({ origins: [origin] });
      swLog('permission check', { source, origin, attempt: i + 1, hasPermission });
      if (hasPermission) return true;
    } catch (err) {
      swWarn('permission check failed', { source, origin, attempt: i + 1, error: err?.message });
      return false;
    }
  }
  return false;
}

// ── Startup & Auto-Discovery ────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  discover();
});

chrome.runtime.onStartup.addListener(() => {
  discover();
});

/**
 * Auto-discover the Log Insight server and UniFi controller URL.
 * 1. Try stored URL first, then localhost:8090
 * 2. If found, fetch UniFi settings to get controller URL
 * 3. Register content scripts for the controller origin
 */
let discoverRunning = false;
async function discover() {
  if (discoverRunning) { swLog('discover already running — skipped'); return; }
  discoverRunning = true;
  swLog('discover start');

  // Load API token from storage
  const storedToken = await getApiToken();
  if (storedToken) {
    setAuthToken(storedToken);
    swLog('API token loaded from storage');
  }

  try {
    const settings = await getSettings();

    // Try stored URL first
    if (settings.logInsightUrl) {
      const health = await checkHealth(settings.logInsightUrl);
      if (health) {
        setBaseUrl(settings.logInsightUrl);
        await onConnected(health, settings);
        return;
      }
    }

    // Try default localhost
    const health = await checkHealth(DEFAULT_BASE_URL);
    if (health) {
      setBaseUrl(DEFAULT_BASE_URL);
      await saveSettings({ logInsightUrl: DEFAULT_BASE_URL });
      await onConnected(health, { ...settings, logInsightUrl: DEFAULT_BASE_URL });
      return;
    }

    // Not found — popup will prompt user
    setBadge('?', '#fbbf24');
  } catch (err) {
    swError('Discovery failed:', err);
    setBadge('!', '#f87171');
  } finally {
    discoverRunning = false;
  }
}

// Set up 401 handler — show auth error badge
setAuthErrorHandler(async () => {
  swWarn('API returned 401 — token revoked or expired');
  setBadge('!', '#f87171');
  // Mark token as invalidated so popup shows auth gate on next open
  try { await chrome.storage.local.set({ apiTokenValidated: false }); } catch (err) { swWarn('failed to persist apiTokenValidated:', err?.message); }
});

/**
 * Called when Log Insight server is successfully reached.
 */
async function onConnected(health, settings) {
  setBadge('', '#34d399'); // green — connected
  await setCache('health', { data: health, timestamp: Date.now() });

  // Always mark as configured — Log Insight is reachable
  await saveSettings({ configured: true });

  // Discover controller URL from UniFi settings
  try {
    if (!settings.controllerUrl) {
      const unifi = await fetchUniFiSettings();
      if (unifi && unifi.host) {
        const controllerUrl = unifi.host.replace(/\/+$/, '');
        await saveSettings({ controllerUrl });
        await registerContentScripts(controllerUrl, { source: 'onConnected:auto-discovered' });
      }
    } else {
      await registerContentScripts(settings.controllerUrl, { source: 'onConnected:existing-controller' });
    }
  } catch (err) {
    swError('Controller discovery/registration failed:', err);
  }
}

// ── Dynamic Content Script Registration ─────────────────────────────────────

async function registerContentScripts(controllerUrl, options = {}) {
  const source = options.source || 'unknown';
  if (!controllerUrl) {
    swWarn('registerContentScripts skipped: missing controllerUrl', { source });
    return { ok: false, reason: 'missing_controller_url' };
  }

  // Build origin match pattern from controller URL
  const origin = toOriginPattern(controllerUrl);
  if (!origin) {
    swWarn('registerContentScripts skipped: invalid controller URL', { source, controllerUrl });
    return { ok: false, reason: 'invalid_controller_url' };
  }
  swLog('registerContentScripts start', { source, controllerUrl, origin });

  // Check host permission for the controller origin
  const hasPermission = await hasPermissionWithRetry(origin, source);
  if (!hasPermission) {
    // Can't request permissions from service worker — store for popup to handle
    await chrome.storage.local.set({ pendingOrigin: origin });
    swWarn('registerContentScripts blocked by missing permission; pendingOrigin saved', { source, origin });
    return { ok: false, reason: 'missing_permission', origin };
  }

  // Permission granted — clear any pending request
  await chrome.storage.local.remove('pendingOrigin');

  // Unregister any existing scripts first
  try {
    await chrome.scripting.unregisterContentScripts({ ids: ['uli-controller'] });
  } catch (err) {
    swWarn('unregisterContentScripts (pre-register cleanup):', err?.message);
  }

  // Register content scripts for future page loads.
  const scripts = [
    'content/shared-utils.js',
    'content/controller-detector.js',
    'content/tab-injector.js',
    'content/flow-enricher.js',
    'content/panel-enricher.js',
  ];
  try {
    await chrome.scripting.registerContentScripts([{
      id: 'uli-controller',
      matches: [origin],
      js: scripts,
      css: ['content/styles.css'],
      runAt: 'document_idle',
    }]);
  } catch (err) {
    swError(`Failed to register content scripts for origin ${origin}:`, err);
    return { ok: false, reason: 'register_failed', origin, error: err?.message };
  }

  // Inject into already-open controller tabs so the user doesn't have to refresh.
  let tabCount = 0;
  let injectedTabs = 0;
  try {
    const tabs = await chrome.tabs.query({ url: [origin] });
    tabCount = tabs.length;
    swLog('injecting scripts into open tabs', { source, origin, tabCount });
    for (const tab of tabs) {
      if (!tab.id) continue;
      try {
        await chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: ['content/styles.css'] });
      } catch (err) {
        swWarn('insertCSS failed', { source, tabId: tab.id, error: err?.message });
      }
      try {
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: scripts });
        injectedTabs += 1;
      } catch (err) {
        swWarn('executeScript failed', { source, tabId: tab.id, error: err?.message });
      }
    }
  } catch (err) {
    swWarn('tabs query for injection failed', { source, origin, error: err?.message });
  }
  swLog('registerContentScripts complete', { source, origin, tabCount, injectedTabs });
  return { ok: true, origin, tabCount, injectedTabs };
}

// ── Permission Granted Fallback (Firefox popup closes during permission dialog) ─

chrome.permissions.onAdded.addListener(async (permissions) => {
  const origins = permissions.origins || [];
  if (origins.length === 0) return;
  swLog('permissions.onAdded fired', { origins });

  // Clear pending origin if it matches the newly granted permission
  const cached = await chrome.storage.local.get('pendingOrigin');
  if (cached.pendingOrigin && origins.includes(cached.pendingOrigin)) {
    await chrome.storage.local.remove('pendingOrigin');
    swLog('cleared pendingOrigin from onAdded', { pendingOrigin: cached.pendingOrigin });
  }

  // Register content scripts for the controller if we have the URL
  const settings = await getSettings();
  if (settings.controllerUrl) {
    const origin = toOriginPattern(settings.controllerUrl);
    if (origin && origins.includes(origin)) {
      await registerContentScripts(settings.controllerUrl, { source: 'permissions.onAdded' });
    } else {
      swLog('permissions.onAdded origin did not match current controllerUrl', {
        currentControllerUrl: settings.controllerUrl,
        currentOrigin: origin,
        grantedOrigins: origins,
      });
    }
  }
});

// ── Badge Icon ──────────────────────────────────────────────────────────────

function setBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

// ── Message Handling (content scripts -> service worker) ────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch(err => {
    sendResponse({ ok: false, error: err.message });
  });
  return true; // async response
});

async function handleMessage(msg) {
  // Restore in-memory state if service worker restarted
  if (!getBaseUrl()) {
    const s = await getSettings();
    if (s.logInsightUrl) setBaseUrl(s.logInsightUrl);
  }
  if (!getAuthToken()) {
    const storedToken = await getApiToken();
    if (storedToken) setAuthToken(storedToken);
  }

  switch (msg.type) {
    case 'HEALTH_CHECK': {
      const health = await checkHealth(msg.url || undefined);
      return { ok: !!health, data: health };
    }

    case 'TRAFFIC_STATS': {
      const stats = await fetchTrafficStats(msg.timeRange || '24h');
      if (stats && stats._authRequired) return { ok: false, authRequired: true };
      return { ok: !!stats, data: stats };
    }

    case 'BATCH_THREAT_LOOKUP': {
      const ips = Array.isArray(msg.ips) ? msg.ips : [];
      const { results, error } = await batchThreatLookup(ips);
      if (error) {
        swWarn('BATCH_THREAT_LOOKUP error:', error);
      }
      return { ok: !error, data: results, error };
    }

    case 'GET_CONFIG': {
      const settings = await getSettings();
      return { ok: true, data: settings };
    }

    case 'SET_BASE_URL': {
      if (typeof msg.url !== 'string' || !msg.url.trim()) {
        return { ok: false, error: 'Missing or invalid url' };
      }
      const url = msg.url.replace(/\/+$/, '');
      try {
        new URL(url);
      } catch {
        return { ok: false, error: 'Invalid URL format' };
      }
      const health = await checkHealth(url);
      if (!health) return { ok: false, error: 'Could not connect' };
      const currentSettings = await getSettings();
      setBaseUrl(url);
      await saveSettings({ logInsightUrl: url });
      await onConnected(health, { ...currentSettings, logInsightUrl: url });
      return { ok: true, data: health };
    }

    case 'SET_CONTROLLER_URL': {
      // Save-only: does NOT call registerContentScripts or onConnected.
      // Permission may not yet be granted. The popup's save-controller flow
      // calls PERMISSION_GRANTED immediately after, which triggers
      // registerContentScripts. On startup, onConnected (via SET_BASE_URL /
      // discover) handles registration for existing controller URLs.
      if (typeof msg.url !== 'string' || !msg.url.trim()) {
        return { ok: false, error: 'Missing or invalid url' };
      }
      const controllerUrl = msg.url.replace(/\/+$/, '');
      try {
        new URL(controllerUrl);
      } catch {
        return { ok: false, error: 'Invalid URL format' };
      }
      await saveSettings({ controllerUrl });
      swLog('controller URL saved', { controllerUrl });
      return { ok: true };
    }

    case 'PERMISSION_GRANTED': {
      // Called from popup after user grants permission
      const settings = await getSettings();
      const controllerUrl = typeof msg.controllerUrl === 'string' && msg.controllerUrl.trim()
        ? msg.controllerUrl.replace(/\/+$/, '')
        : settings.controllerUrl;
      swLog('PERMISSION_GRANTED message received', {
        origin: msg.origin || null,
        controllerUrl,
      });
      if (controllerUrl) {
        const result = await registerContentScripts(controllerUrl, { source: 'message:PERMISSION_GRANTED' });
        return { ok: true, data: result };
      }
      return { ok: false, error: 'No controller URL available after permission grant' };
    }

    case 'GET_BASE_URL': {
      return { ok: true, url: getBaseUrl() };
    }

    case 'GET_THREAT_COLORS': {
      return { ok: true, data: THREAT_COLORS };
    }

    case 'DEBUG': {
      const settings = await getSettings();
      const pending = await chrome.storage.local.get('pendingOrigin');
      let registeredScripts = [];
      try {
        registeredScripts = await chrome.scripting.getRegisteredContentScripts();
      } catch (e) {
        registeredScripts = [{ error: e.message }];
      }
      let permissions = {};
      try {
        permissions = await chrome.permissions.getAll();
      } catch (e) {
        permissions = { error: e.message };
      }
      const manifest = chrome.runtime.getManifest();
      return {
        ok: true,
        data: {
          extensionVersion: manifest.version,
          swUptime: Math.round((Date.now() - swStartedAt) / 1000) + 's',
          swErrors: swErrorCount,
          swWarnings: swWarnCount,
          settings,
          baseUrl: getBaseUrl(),
          pendingOrigin: pending.pendingOrigin || null,
          registeredScripts,
          permissions,
        },
      };
    }

    // Won't Fix: SET_API_TOKEN race condition — popup disables the save button during
    // in-flight requests and chrome.runtime.sendMessage serializes from each sender.
    case 'SET_API_TOKEN': {
      const token = typeof msg.token === 'string' ? msg.token.trim() : '';
      if (!token) {
        setAuthToken('');
        await clearApiToken();
        return { ok: true };
      }
      // Validate token before persisting — prevents bad tokens surviving SW restarts
      if (getBaseUrl()) {
        setAuthToken(token); // set in-memory for fetchTrafficStats to use
        let stats;
        try {
          stats = await fetchTrafficStats('1h');
        } catch (err) {
          setAuthToken(''); // clear in-memory — don't persist
          setBadge('!', '#f87171');
          swWarn('token validation failed:', err?.message);
          return { ok: false, error: 'Token validation failed — check server connectivity' };
        }
        if (stats && stats._authRequired) {
          setAuthToken(''); // clear in-memory — don't persist
          setBadge('!', '#f87171');
          return { ok: false, error: 'Token rejected — check it is valid and not expired' };
        }
        if (stats) {
          await saveApiToken(token, { validated: true });
          swLog('API token saved (validated)');
          setBadge('', '#34d399');
          // Auto-discover controller URL now that we have a valid token
          const settings = await getSettings();
          if (!settings.controllerUrl) {
            try {
              const unifi = await fetchUniFiSettings();
              if (unifi && unifi.host) {
                const controllerUrl = unifi.host.replace(/\/+$/, '');
                await saveSettings({ controllerUrl });
                await registerContentScripts(controllerUrl, { source: 'SET_API_TOKEN:auto-discovered' });
                swLog('controller auto-discovered after token save', { controllerUrl });
              }
            } catch (err) {
              swWarn('controller auto-discovery after token save failed:', err?.message);
            }
          }
          return { ok: true, data: stats };
        }
        // stats is null — network issue, token may still be valid but unvalidated.
        // Persist validated:false so the popup can render "Unvalidated" after refresh.
        await saveApiToken(token, { validated: false });
        setBadge('?', '#fbbf24');
        swWarn('token saved but validation inconclusive (network unreachable)');
        return { ok: true, warning: 'Token saved but could not be validated — network unreachable' };
      }
      // No base URL configured yet — persist token for later use
      setAuthToken(token);
      await saveApiToken(token);
      swLog('API token saved (no base URL to validate against)');
      return { ok: true };
    }

    case 'GET_API_TOKEN': {
      const validated = await getApiTokenValidated();
      return { ok: true, token: getAuthToken(), validated };
    }

    case 'CLEAR_API_TOKEN': {
      setAuthToken('');
      await clearApiToken();
      swLog('API token cleared');
      return { ok: true };
    }

    case 'DISCONNECT': {
      setBaseUrl('');
      setAuthToken('');
      await clearApiToken();
      setBadge('?', '#fbbf24');
      try {
        await chrome.scripting.unregisterContentScripts({ ids: ['uli-controller'] });
      } catch (err) {
        swWarn('unregisterContentScripts (disconnect):', err?.message);
      }
      return { ok: true };
    }

    default:
      return { ok: false, error: `Unknown message type: ${msg.type}` };
  }
}
