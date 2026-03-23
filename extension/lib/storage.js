/**
 * Wrapper around chrome.storage for extension settings.
 * Uses chrome.storage.sync for settings (synced across devices)
 * and chrome.storage.local for cache data.
 */

// Sensitive values (apiToken) are stored in chrome.storage.local only.
const DEFAULTS = {
  logInsightUrl: '',
  controllerUrl: '',
  enableTabInjection: true,
  enableFlowEnrichment: true,
  configured: false,
};

export async function getSettings() {
  try {
    return await chrome.storage.sync.get(DEFAULTS);
  } catch (err) {
    console.error('getSettings failed:', err);
    return { ...DEFAULTS };
  }
}

export async function saveSettings(settings) {
  try {
    await chrome.storage.sync.set(settings);
    return true;
  } catch (err) {
    console.error('saveSettings failed:', err);
    return false;
  }
}

export async function getApiToken() {
  try {
    const result = await chrome.storage.local.get('apiToken');
    return result.apiToken || '';
  } catch (err) {
    console.error('getApiToken failed:', err);
    return '';
  }
}

export async function saveApiToken(token, { validated = true } = {}) {
  try {
    await chrome.storage.local.set({ apiToken: token, apiTokenValidated: validated });
    return true;
  } catch (err) {
    console.error('saveApiToken failed:', err);
    return false;
  }
}

export async function getApiTokenValidated() {
  try {
    const result = await chrome.storage.local.get('apiTokenValidated');
    // Default to true for tokens saved before this field existed
    return result.apiTokenValidated !== false;
  } catch (err) {
    console.error('getApiTokenValidated failed:', err);
    return true;
  }
}

export async function clearApiToken() {
  try {
    await chrome.storage.local.remove(['apiToken', 'apiTokenValidated']);
    return true;
  } catch (err) {
    console.error('clearApiToken failed:', err);
    return false;
  }
}

export async function setCache(key, value) {
  try {
    await chrome.storage.local.set({ [key]: value });
  } catch (err) {
    console.error('setCache failed:', err);
  }
}
