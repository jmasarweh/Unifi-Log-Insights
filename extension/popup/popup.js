// -- Elements --

const setupView = document.getElementById('setup-view');
const connectedView = document.getElementById('connected-view');
const authGateView = document.getElementById('auth-gate-view');

const authGateTokenInput = document.getElementById('auth-gate-token-input');
const authGateSaveBtn = document.getElementById('auth-gate-save-btn');
const authGateError = document.getElementById('auth-gate-error');
const authGateDisconnectBtn = document.getElementById('auth-gate-disconnect-btn');
const authGateVersion = document.getElementById('auth-gate-version');

const hostInput = document.getElementById('host-input');
const portInput = document.getElementById('port-input');
const connectBtn = document.getElementById('connect-btn');
const setupError = document.getElementById('setup-error');

const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const versionFooter = document.getElementById('version-footer');
const trafficOverview = document.getElementById('traffic-overview');
const totalLogs = document.getElementById('total-logs');
const statAllowed = document.getElementById('stat-allowed');
const statBlocked = document.getElementById('stat-blocked');
const statThreats = document.getElementById('stat-threats');
const toDirections = document.getElementById('to-directions');

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

const tokenStatus = document.getElementById('token-status');
const tokenDisplay = document.getElementById('token-display');
const tokenPreview = document.getElementById('token-preview');
const editTokenBtn = document.getElementById('edit-token-btn');
const clearTokenBtn = document.getElementById('clear-token-btn');
const tokenEdit = document.getElementById('token-edit');
const tokenInput = document.getElementById('token-input');
const saveTokenBtn = document.getElementById('save-token-btn');
const tokenError = document.getElementById('token-error');

let initialTabInjection = true;
let initialFlowEnrichment = true;
let detectedAuthRequired = false;
const PERMISSION_RETRY_DELAYS_MS = [0, 120, 300, 700];
const POPUP_LOG_PREFIX = '[ULI][Popup]';
// Loaded by url-utils.js <script> in popup.html — always available.
const toOriginPattern = globalThis.ULI_URL_UTILS.toOriginPattern;

// Safe: ULI tokens are 50+ chars (prefix + 43 random). substring(0,16) shows
// the known "uli-extension_" prefix + 2 random chars — less than the 8-char
// token_prefix already visible to admins in the token list.
function formatTokenPreview(token) {
  return token.substring(0, 16) + '...';
}

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

const DIRECTION_ICONS = {
  inbound: '\u2193', outbound: '\u2191', inter_vlan: '\u21D4',
  nat: '\u2934\uFE0E', local: '\u27F3', vpn: '\u26E8',
};

const DIRECTION_LABELS = {
  inbound: 'INBOUND', outbound: 'OUTBOUND', inter_vlan: 'VLAN',
  nat: 'NAT', local: 'LOCAL', vpn: 'VPN',
};

function renderDirections(dirMap) {
  toDirections.textContent = '';
  const entries = Object.entries(dirMap);
  if (entries.length === 0) {
    toDirections.hidden = true;
    return;
  }
  for (const [dir, count] of entries) {
    const badge = document.createElement('span');
    badge.className = `to-dir-badge to-dir-${dir}`;
    badge.title = DIRECTION_LABELS[dir] || dir.toUpperCase();

    const icon = document.createElement('span');
    icon.textContent = DIRECTION_ICONS[dir] || '';

    const val = document.createElement('span');
    val.className = 'to-dir-count';
    val.textContent = formatNumber(count);

    badge.append(icon, val);
    toDirections.appendChild(badge);
  }
  toDirections.hidden = false;
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

    initialTabInjection = !!settings.enableTabInjection;
    initialFlowEnrichment = !!settings.enableFlowEnrichment;
    toggleTab.checked = initialTabInjection;
    toggleEnrich.checked = initialFlowEnrichment;

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
  authGateView.hidden = true;
  const sep = document.querySelector('.port-sep');
  if (detectedAuthRequired) {
    hostInput.placeholder = 'https://logs.yourdomain.com';
    portInput.hidden = true;
    if (sep) sep.hidden = true;
  } else {
    hostInput.placeholder = '192.168.1.50';
    portInput.hidden = false;
    if (sep) sep.hidden = false;
  }
}

connectBtn.addEventListener('click', async () => {
  const host = hostInput.value.trim();
  const port = portInput.value.trim() || '8090';
  if (!host) {
    showSetupError('Please enter an address');
    return;
  }

  // HTTPS full URLs use as-is (standard port 443); bare IPs/hostnames get port appended
  // When auth is required, default to https and skip port
  if (detectedAuthRequired && /^http:\/\//i.test(host)) {
    showSetupError('Authentication requires HTTPS. Remove http:// or use https://.');
    return;
  }
  const isHttps = /^https:\/\//i.test(host);
  let url;
  if (isHttps) {
    url = host.replace(/\/+$/, '');
  } else if (detectedAuthRequired) {
    url = normalizeUrl(host, 'https');
  } else {
    url = normalizeUrl(`${host}:${port}`, 'http');
  }

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
  authGateView.hidden = true;

  const baseUrl = settings.logInsightUrl;
  const extVersion = chrome.runtime.getManifest().version;

  // Check if auth is required and no token is configured.
  // Use allSettled so one failure doesn't discard the others.
  let healthResp = {}, trafficResp = {}, tokenResp = {};
  const [healthResult, trafficResult, tokenResult] = await Promise.allSettled([
    chrome.runtime.sendMessage({ type: 'HEALTH_CHECK' }),
    chrome.runtime.sendMessage({ type: 'TRAFFIC_STATS' }),
    chrome.runtime.sendMessage({ type: 'GET_API_TOKEN' }),
  ]);
  if (healthResult.status === 'fulfilled') {
    healthResp = healthResult.value || {};
  } else {
    popupWarn('HEALTH_CHECK failed:', healthResult.reason?.message);
  }
  if (trafficResult.status === 'fulfilled') {
    trafficResp = trafficResult.value || {};
  } else {
    popupWarn('TRAFFIC_STATS failed:', trafficResult.reason?.message);
  }
  if (tokenResult.status === 'fulfilled') {
    tokenResp = tokenResult.value || {};
  } else {
    popupWarn('GET_API_TOKEN failed:', tokenResult.reason?.message);
  }

  const serverReachable = healthResp.ok && healthResp.data;
  const authRequired = trafficResp.authRequired;
  const hasToken = tokenResp.ok && tokenResp.token;
  detectedAuthRequired = !!authRequired;

  // Auth gate: server reachable, requires auth, and either no token or token was revoked
  if (serverReachable && authRequired && (!hasToken || !tokenResp.validated)) {
    const isHttp = /^http:\/\//i.test(baseUrl);
    if (isHttp) {
      authGateError.textContent = 'Authentication requires HTTPS. Click "Reset Extension" below and reconnect using your external HTTPS address (e.g. https://logs.yourdomain.com).';
      authGateError.hidden = false;
      authGateTokenInput.disabled = true;
      authGateSaveBtn.disabled = true;
    } else {
      authGateError.hidden = true;
      authGateTokenInput.disabled = false;
      authGateSaveBtn.disabled = false;
    }
    authGateVersion.textContent = `App: ${healthResp.data.version}  |  Extension: ${extVersion}`;
    authGateVersion.hidden = false;
    if (!isHttp) authGateTokenInput.focus();
    authGateView.hidden = false;
    return;
  }

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
    controllerUrl.textContent = stripProto(ctrlUrl);
    controllerUrl.title = ctrlUrl;
    controllerDisplay.hidden = false;

    const origin = toOriginPattern(ctrlUrl);
    let hasPermission = false;
    if (origin) {
      hasPermission = await hasPermissionWithRetry(origin);
      try {
        const pending = await chrome.storage.local.get('pendingOrigin');
        popupLog('showConnected controller state', {
          controllerUrl: ctrlUrl, origin, hasPermission,
          pendingOrigin: pending.pendingOrigin || null,
        });
      } catch (err) {
        popupWarn('failed to read pendingOrigin', { error: err?.message });
      }
    }
    setControllerPermissionState(hasPermission);
  } else {
    controllerEdit.hidden = false;
    controllerStatus.textContent = 'Not Set';
    controllerStatus.className = 'status-pill pending';
    controllerStatus.hidden = false;
  }

  // Status + traffic
  if (serverReachable) {
    statusDot.className = 'status-dot connected';
    statusText.textContent = 'Connected';
    versionFooter.textContent = `App: ${healthResp.data.version}  |  Extension: ${extVersion}`;
    versionFooter.hidden = false;
  } else {
    statusDot.className = 'status-dot disconnected';
    statusText.textContent = 'Unreachable';
    versionFooter.textContent = `Extension: ${extVersion}`;
    versionFooter.hidden = false;
  }

  if (trafficResp.ok && trafficResp.data) {
    const t = trafficResp.data;
    totalLogs.textContent = formatNumber(t.total);
    statAllowed.textContent = formatNumber(t.allowed);
    statBlocked.textContent = formatNumber(t.blocked);
    statThreats.textContent = formatNumber(t.threats);
    renderDirections(t.by_direction || {});
    trafficOverview.hidden = false;
  }

  // API Token section — upgrade validation state if traffic stats succeeded
  const tokenValidated = tokenResp.validated !== false
    || (trafficResp.ok && trafficResp.data);
  if (hasToken && !tokenResp.validated && tokenValidated) {
    // Token was unvalidated but traffic stats now succeeded — persist upgrade
    try { await chrome.storage.local.set({ apiTokenValidated: true }); } catch (err) {
      popupWarn('failed to persist apiTokenValidated upgrade', { error: err?.message, tokenValidated, hasToken });
    }
  }

  if (hasToken) {
    tokenPreview.textContent = formatTokenPreview(tokenResp.token);
    tokenDisplay.hidden = false;
    tokenEdit.hidden = true;
    if (!tokenValidated) {
      tokenStatus.textContent = 'Unvalidated';
      tokenStatus.className = 'status-pill warning';
    } else {
      tokenStatus.textContent = 'Configured';
      tokenStatus.className = 'status-pill active';
    }
    tokenStatus.hidden = false;
  } else {
    tokenDisplay.hidden = true;
    tokenEdit.hidden = false;
    tokenStatus.textContent = 'Not Set';
    tokenStatus.className = 'status-pill pending';
    tokenStatus.hidden = false;
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
      if (hasPermission) {
        reloadBar.hidden = false;
      } else {
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

  // Save URL BEFORE permission dialog — popup may close during the dialog
  // and .then()/.catch() won't execute. Writing directly to storage ensures
  // the URL persists even if the popup is destroyed mid-dialog.
  chrome.storage.sync.set({ controllerUrl: url }, () => {
    if (chrome.runtime.lastError) {
      popupWarn('storage.sync.set controllerUrl failed', { url, error: chrome.runtime.lastError.message });
    }
  });

  // Now request permission (Firefox: must be first *permission* call from click handler)
  chrome.permissions.request({ origins: [origin] }).then(async (granted) => {
    popupLog('save controller permission resolved', { origin, granted, url });

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

    // Refresh to show new state, then prompt reload if permission was granted
    await init();
    if (granted) reloadBar.hidden = false;
  }).catch(async (err) => {
    // Popup may have closed during dialog — URL already saved above.
    popupWarn('save controller permission request rejected/aborted', { origin, url, error: err?.message });
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

async function performDisconnect() {
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
}

disconnectBtn.addEventListener('click', performDisconnect);

// -- API Token --

editTokenBtn.addEventListener('click', () => {
  tokenDisplay.hidden = true;
  tokenEdit.hidden = false;
  tokenError.hidden = true;
  tokenInput.value = '';
  tokenInput.focus();
});

clearTokenBtn.addEventListener('click', async () => {
  try {
    await chrome.runtime.sendMessage({ type: 'CLEAR_API_TOKEN' });
    tokenDisplay.hidden = true;
    tokenEdit.hidden = false;
    tokenStatus.textContent = 'Not Set';
    tokenStatus.className = 'status-pill pending';
    tokenError.hidden = true;
  } catch (err) {
    tokenError.textContent = err.message || 'Failed to clear token';
    tokenError.hidden = false;
  }
});

saveTokenBtn.addEventListener('click', async () => {
  const token = tokenInput.value.trim();
  if (!token) {
    tokenError.textContent = 'Please enter a token';
    tokenError.hidden = false;
    return;
  }

  saveTokenBtn.disabled = true;
  saveTokenBtn.textContent = 'Saving...';
  tokenError.hidden = true;
  tokenError.classList.remove('auth-hint');

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'SET_API_TOKEN', token });
    if (resp.ok) {
      tokenPreview.textContent = formatTokenPreview(token);
      tokenDisplay.hidden = false;
      tokenEdit.hidden = true;
      tokenInput.value = '';
      if (resp.warning) {
        // Token saved but validation was inconclusive (e.g. network unreachable)
        tokenStatus.textContent = 'Unvalidated';
        tokenStatus.className = 'status-pill warning';
        statusDot.className = 'status-dot warning';
        statusText.textContent = 'Unvalidated';
      } else {
        tokenStatus.textContent = 'Configured';
        tokenStatus.className = 'status-pill active';
        statusDot.className = 'status-dot connected';
        statusText.textContent = 'Connected';
      }
    } else {
      tokenError.textContent = resp.error || 'Failed to save token';
      tokenError.hidden = false;
    }
  } catch (err) {
    tokenError.textContent = err.message || 'Failed to save token';
    tokenError.hidden = false;
  } finally {
    saveTokenBtn.disabled = false;
    saveTokenBtn.textContent = 'Save';
  }
});

tokenInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') saveTokenBtn.click();
});

// -- Auth Gate --

authGateSaveBtn.addEventListener('click', async () => {
  const token = authGateTokenInput.value.trim();
  if (!token) {
    authGateError.textContent = 'Please enter a token';
    authGateError.hidden = false;
    return;
  }

  authGateSaveBtn.disabled = true;
  authGateSaveBtn.textContent = 'Saving...';
  authGateError.hidden = true;

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'SET_API_TOKEN', token });
    if (resp.ok) {
      authGateTokenInput.value = '';
      // Re-init — showConnected() reads persisted validated state from GET_API_TOKEN
      // and renders "Unvalidated" pill if validation was inconclusive.
      await init();
    } else {
      authGateError.textContent = resp.error || 'Failed to save token';
      authGateError.hidden = false;
    }
  } catch (err) {
    authGateError.textContent = err.message || 'Failed to save token';
    authGateError.hidden = false;
  } finally {
    authGateSaveBtn.disabled = false;
    authGateSaveBtn.textContent = 'Save';
  }
});

authGateTokenInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') authGateSaveBtn.click();
});

authGateDisconnectBtn.addEventListener('click', performDisconnect);

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

init().catch(e => console.error('[ULI] init failed:', e));
loadDebug().catch(e => console.error('[ULI] loadDebug failed:', e));
