// -- Elements --

const setupView = document.getElementById('setup-view');
const connectedView = document.getElementById('connected-view');

const hostInput = document.getElementById('host-input');
const portInput = document.getElementById('port-input');
const connectBtn = document.getElementById('connect-btn');
const setupError = document.getElementById('setup-error');

const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const versionBadge = document.getElementById('version-badge');
const totalLogs = document.getElementById('total-logs');
const blockedToday = document.getElementById('blocked-today');

const openDashboard = document.getElementById('open-dashboard');
const openThreatMap = document.getElementById('open-threat-map');
const openLogs = document.getElementById('open-logs');

const controllerStatus = document.getElementById('controller-status');
const controllerDisplay = document.getElementById('controller-display');
const controllerImg = document.getElementById('controller-img');
const controllerUrl = document.getElementById('controller-url');
const editControllerBtn = document.getElementById('edit-controller-btn');
const controllerEdit = document.getElementById('controller-edit');
const controllerInput = document.getElementById('controller-input');
const saveControllerBtn = document.getElementById('save-controller-btn');
const grantBanner = document.getElementById('grant-banner');
const grantBtn = document.getElementById('grant-btn');
const controllerError = document.getElementById('controller-error');

const toggleTab = document.getElementById('toggle-tab');
const toggleEnrich = document.getElementById('toggle-enrich');
const reloadBar = document.getElementById('reload-bar');
const reloadBtn = document.getElementById('reload-btn');
const disconnectBtn = document.getElementById('disconnect-btn');

let initialTabInjection = true;
let initialFlowEnrichment = true;
const PERMISSION_RETRY_DELAYS_MS = [0, 120, 300, 700];
const POPUP_LOG_PREFIX = '[ULI][Popup]';
// Loaded by url-utils.js <script> in popup.html — always available.
const toOriginPattern = globalThis.ULI_URL_UTILS.toOriginPattern;

function popupLog(...args) {
  console.log(POPUP_LOG_PREFIX, ...args);
}

function popupWarn(...args) {
  console.warn(POPUP_LOG_PREFIX, ...args);
}

// -- Theme --

function applyTheme(theme) {
  const safeTheme = theme === 'light' ? 'light' : 'dark';
  document.body.setAttribute('data-theme', safeTheme);
}

async function syncPopupTheme() {
  applyTheme('dark');

  try {
    const cache = await chrome.storage.local.get('unifiUiTheme');
    if (cache.unifiUiTheme === 'light' || cache.unifiUiTheme === 'dark') {
      applyTheme(cache.unifiUiTheme);
    }
  } catch {
    // Ignore cache read errors; theme lookup below may still work.
  }

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const activeTab = tabs && tabs[0];
    if (!activeTab || !activeTab.id) return;

    const resp = await chrome.tabs.sendMessage(activeTab.id, { type: 'ULI_GET_THEME' });
    if (resp && resp.ok && (resp.theme === 'light' || resp.theme === 'dark')) {
      applyTheme(resp.theme);
      await chrome.storage.local.set({ unifiUiTheme: resp.theme });
    }
  } catch {
    // No content script on the active tab, or messaging blocked.
  }
}

// -- Helpers --

/** Auto-prepend protocol if bare IP/hostname entered */
function normalizeUrl(input, defaultProto = 'http') {
  let val = input.trim().replace(/\/+$/, '');
  if (!val) return '';
  if (!/^https?:\/\//i.test(val)) {
    val = `${defaultProto}://${val}`;
  }
  return val;
}

function formatNumber(n) {
  if (n === null || n === undefined) return '-';
  return n.toLocaleString();
}

function stripProto(url) {
  return url.replace(/^https?:\/\//, '');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function hasPermissionWithRetry(origin, delaysMs = PERMISSION_RETRY_DELAYS_MS) {
  if (!origin) return false;
  for (let i = 0; i < delaysMs.length; i++) {
    if (delaysMs[i] > 0) await sleep(delaysMs[i]);
    try {
      const hasPermission = await chrome.permissions.contains({ origins: [origin] });
      popupLog('permission check', { origin, attempt: i + 1, hasPermission });
      if (hasPermission) return true;
    } catch (err) {
      popupWarn('permission check failed', { origin, attempt: i + 1, error: err?.message });
      return false;
    }
  }
  return false;
}

function setControllerPermissionState(hasPermission) {
  controllerStatus.hidden = false;
  if (hasPermission) {
    controllerStatus.textContent = 'Active';
    controllerStatus.className = 'status-pill active';
    grantBanner.hidden = true;
    return;
  }
  controllerStatus.textContent = 'Needs Access';
  controllerStatus.className = 'status-pill pending';
  grantBanner.hidden = false;
}

// -- Init --

async function init() {
  popupLog('init start');
  await syncPopupTheme();
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
    if (!resp || !resp.ok || !resp.data) {
      popupWarn('GET_CONFIG failed; switching to setup', { response: resp });
      showSetup();
      return;
    }
    const settings = resp.data;

    initialTabInjection = settings.enableTabInjection;
    initialFlowEnrichment = settings.enableFlowEnrichment;
    toggleTab.checked = settings.enableTabInjection;
    toggleEnrich.checked = settings.enableFlowEnrichment;

    if (!settings.logInsightUrl || !settings.configured) {
      showSetup();
      return;
    }

    await showConnected(settings);
  } catch (err) {
    console.error('Popup init error:', err);
    showSetup();
  }
}

// -- Setup View --

function showSetup() {
  setupView.hidden = false;
  connectedView.hidden = true;
}

connectBtn.addEventListener('click', async () => {
  const host = hostInput.value.trim();
  const port = portInput.value.trim() || '8090';
  if (!host) {
    showSetupError('Please enter an address');
    return;
  }

  const url = normalizeUrl(`${host}:${port}`, 'http');

  try {
    new URL(url);
  } catch {
    showSetupError('Invalid address');
    return;
  }

  connectBtn.textContent = 'Connecting...';
  connectBtn.disabled = true;
  setupError.hidden = true;

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'SET_BASE_URL', url });

    if (resp.ok) {
      const cfg = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
      if (!cfg || !cfg.ok || !cfg.data) {
        showSetupError('Connected but failed to load settings');
        return;
      }
      await showConnected(cfg.data);
    } else {
      showSetupError(resp.error || 'Could not reach server');
    }
  } catch (err) {
    showSetupError(err.message || 'Connection failed');
  } finally {
    connectBtn.textContent = 'Connect';
    connectBtn.disabled = false;
  }
});

hostInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') connectBtn.click();
});
portInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') connectBtn.click();
});

function showSetupError(msg) {
  setupError.textContent = msg;
  setupError.hidden = false;
}

// -- Connected View --

async function showConnected(settings) {
  setupView.hidden = true;
  connectedView.hidden = true;

  const baseUrl = settings.logInsightUrl;

  // Quick links
  openDashboard.href = baseUrl;
  openThreatMap.href = baseUrl + '/#threat-map';
  openLogs.href = baseUrl + '/#logs';

  // Reset controller section
  controllerDisplay.hidden = true;
  controllerEdit.hidden = true;
  grantBanner.hidden = true;
  controllerError.hidden = true;
  controllerStatus.hidden = true;
  controllerImg.hidden = true;

  // Load gateway device image from Log Insight API
  controllerImg.src = `${baseUrl}/api/unifi/gateway-image`;
  controllerImg.onload = () => { controllerImg.hidden = false; };
  controllerImg.onerror = () => { controllerImg.hidden = true; };

  const ctrlUrl = settings.controllerUrl;

  if (ctrlUrl) {
    // We have a controller URL — show it
    controllerUrl.textContent = stripProto(ctrlUrl);
    controllerUrl.title = ctrlUrl;
    controllerDisplay.hidden = false;

    // Check permission
    const origin = toOriginPattern(ctrlUrl);
    let hasPermission = false;
    if (origin) {
      hasPermission = await hasPermissionWithRetry(origin);
      try {
        const pending = await chrome.storage.local.get('pendingOrigin');
        popupLog('showConnected controller state', {
          controllerUrl: ctrlUrl,
          origin,
          hasPermission,
          pendingOrigin: pending.pendingOrigin || null,
        });
      } catch (err) {
        popupWarn('failed to read pendingOrigin', { error: err?.message });
      }
    }

    setControllerPermissionState(hasPermission);
  } else {
    // No controller URL — show edit form
    controllerEdit.hidden = false;
    controllerStatus.textContent = 'Not Set';
    controllerStatus.className = 'status-pill pending';
    controllerStatus.hidden = false;
  }

  // Health check
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'HEALTH_CHECK' });
    if (resp.ok && resp.data) {
      statusDot.className = 'status-dot connected';
      statusText.textContent = 'Connected';
      versionBadge.textContent = `v${resp.data.version}`;
      totalLogs.textContent = formatNumber(resp.data.total_logs);
      blockedToday.textContent = '-';
    } else {
      statusDot.className = 'status-dot disconnected';
      statusText.textContent = 'Unreachable';
      versionBadge.textContent = '';
    }
  } catch {
    statusDot.className = 'status-dot disconnected';
    statusText.textContent = 'Unreachable';
    versionBadge.textContent = '';
  }

  connectedView.hidden = false;
}

// -- Grant Access --

grantBtn.addEventListener('click', () => {
  const ctrlUrl = controllerUrl.title;
  if (!ctrlUrl) return;

  const origin = toOriginPattern(ctrlUrl);
  if (!origin) return;

  controllerError.hidden = true;
  grantBtn.disabled = true;
  grantBtn.textContent = 'Granting...';
  popupLog('requesting permission', { origin, controllerUrl: ctrlUrl });

  // permissions.request MUST be the first async call (Firefox gesture requirement)
  chrome.permissions.request({ origins: [origin] }).then(async (granted) => {
    popupLog('permission request resolved', { origin, granted });
    grantBtn.disabled = false;
    grantBtn.textContent = 'Grant Access';

    if (granted) {
      await chrome.storage.local.remove('pendingOrigin');
      const resp = await chrome.runtime.sendMessage({
        type: 'PERMISSION_GRANTED',
        origin,
        controllerUrl: ctrlUrl,
      });
      popupLog('PERMISSION_GRANTED response', resp);
      const hasPermission = await hasPermissionWithRetry(origin);
      setControllerPermissionState(hasPermission);
      if (!hasPermission) {
        controllerError.textContent = 'Permission propagation delayed. Reopen popup in a moment.';
        controllerError.hidden = false;
      }
    } else {
      controllerError.textContent = 'Permission denied — please try again';
      controllerError.hidden = false;
    }
  }).catch((err) => {
    // Firefox: popup may close during dialog. Service worker onAdded handles it.
    // If we're still alive, just reset the button.
    popupWarn('permission request rejected/aborted', { origin, error: err?.message });
    grantBtn.disabled = false;
    grantBtn.textContent = 'Grant Access';
  });
});

// -- Edit Controller --

editControllerBtn.addEventListener('click', () => {
  // Pre-fill with current URL (stripped of protocol for easy editing)
  const current = controllerUrl.title || '';
  controllerInput.value = stripProto(current);
  controllerDisplay.hidden = true;
  controllerEdit.hidden = false;
  controllerError.hidden = true;
  grantBanner.hidden = true;
  controllerInput.focus();
});

// -- Save Controller --

saveControllerBtn.addEventListener('click', () => {
  const raw = controllerInput.value.trim();
  if (!raw) {
    controllerError.textContent = 'Please enter an address';
    controllerError.hidden = false;
    return;
  }

  // UniFi controllers default to HTTPS
  const url = normalizeUrl(raw, 'https');

  let origin;
  try {
    origin = toOriginPattern(url);
    if (!origin) throw new Error();
  } catch {
    controllerError.textContent = 'Invalid address';
    controllerError.hidden = false;
    return;
  }

  controllerError.hidden = true;
  saveControllerBtn.disabled = true;
  saveControllerBtn.textContent = 'Saving...';
  popupLog('requesting permission for controller save', { origin, url });

  // Request permission first (Firefox: must be first async call from click handler)
  chrome.permissions.request({ origins: [origin] }).then(async (granted) => {
    popupLog('save controller permission resolved', { origin, granted, url });
    // Save URL regardless of permission outcome
    await chrome.runtime.sendMessage({ type: 'SET_CONTROLLER_URL', url });

    if (granted) {
      await chrome.storage.local.remove('pendingOrigin');
      const resp = await chrome.runtime.sendMessage({
        type: 'PERMISSION_GRANTED',
        origin,
        controllerUrl: url,
      });
      popupLog('PERMISSION_GRANTED response (save flow)', resp);
    }

    saveControllerBtn.disabled = false;
    saveControllerBtn.textContent = 'Save';

    // Refresh to show new state
    init();
  }).catch(async (err) => {
    // Firefox popup might close. Save the URL anyway so next open picks it up.
    popupWarn('save controller permission request rejected/aborted', { origin, url, error: err?.message });
    try {
      await chrome.runtime.sendMessage({ type: 'SET_CONTROLLER_URL', url });
    } catch (innerErr) {
      popupWarn('SET_CONTROLLER_URL on popup close:', innerErr?.message);
    }

    saveControllerBtn.disabled = false;
    saveControllerBtn.textContent = 'Save';
  });
});

controllerInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') saveControllerBtn.click();
});

// -- Toggles --

function onToggleChanged() {
  chrome.storage.sync.set({
    enableTabInjection: toggleTab.checked,
    enableFlowEnrichment: toggleEnrich.checked,
  });
  const changed = toggleTab.checked !== initialTabInjection ||
                  toggleEnrich.checked !== initialFlowEnrichment;
  reloadBar.hidden = !changed;
}

toggleTab.addEventListener('change', onToggleChanged);
toggleEnrich.addEventListener('change', onToggleChanged);

// -- Reload controller tabs --

reloadBtn.addEventListener('click', async () => {
  reloadBar.hidden = true;
  initialTabInjection = toggleTab.checked;
  initialFlowEnrichment = toggleEnrich.checked;

  const resp = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
  const ctrlUrl = resp?.data?.controllerUrl;
  if (!ctrlUrl) return;

  try {
    const origin = new URL(ctrlUrl).origin;
    const tabs = await chrome.tabs.query({ url: [origin + '/*'] });
    for (const tab of tabs) {
      chrome.tabs.reload(tab.id);
    }
  } catch (err) {
    popupWarn('reload controller tabs failed:', err?.message);
  }
});

// -- Reset --

disconnectBtn.addEventListener('click', async () => {
  try {
    const perms = await chrome.permissions.getAll();
    const dynamicOrigins = (perms.origins || []).filter(o =>
      !o.includes('chrome-extension://') && !o.includes('moz-extension://')
    );
    if (dynamicOrigins.length > 0) {
      await chrome.permissions.remove({ origins: dynamicOrigins });
    }
  } catch (err) {
    popupWarn('disconnect permission cleanup failed:', err?.message);
  }

  await chrome.storage.sync.set({ logInsightUrl: '', controllerUrl: '', configured: false });
  await chrome.storage.local.remove(['pendingOrigin', 'health']);
  await chrome.runtime.sendMessage({ type: 'DISCONNECT' });
  showSetup();
});

// -- Debug --

async function loadDebug() {
  const out = document.getElementById('debug-out');
  if (!out) return;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'DEBUG' });
    out.textContent = JSON.stringify(resp, null, 2);
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

// -- Start --

init();
loadDebug();
