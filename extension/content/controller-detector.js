/**
 * Content script entry point — injected on the UniFi Controller page.
 * Detects the UniFi portal header, fetches extension config, then
 * dispatches a 'uli-ready' event so tab-injector.js and flow-enricher.js
 * can initialize.
 *
 * All three files are registered as content scripts in the same scope.
 * They share the content script isolated world (chrome.runtime access).
 * This file MUST be listed first in the registerContentScripts js array.
 */

(async function () {
  // Guard against duplicate injection (SPA re-navigation)
  if (document.getElementById('uli-detector-ran')) return;
  const guard = document.createElement('div');
  guard.id = 'uli-detector-ran';
  guard.style.display = 'none';
  document.documentElement.appendChild(guard);

  // Wait for the SPA to render the portal header (up to 15s)
  const header = await waitForElement('header[class*="unifi-portal"]', 15000);
  if (!header) return;

  // Fetch extension config from service worker
  let config;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_CONFIG' });
    if (!resp || !resp.ok) return;
    config = resp.data;
  } catch (e) {
    console.debug('GET_CONFIG failed:', e);
    return;
  }

  // Fetch the Log Insight base URL
  let baseUrl = '';
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_BASE_URL' });
    if (resp && resp.ok) baseUrl = resp.url || '';
  } catch (e) {
    console.debug('GET_BASE_URL failed:', e);
  }

  // Store config globally for the other content scripts
  window.__uliConfig = { ...config, baseUrl };

  // Signal that detection is complete — other scripts are listening
  window.dispatchEvent(new CustomEvent('uli-ready'));
})();

function waitForElement(selector, timeout) {
  return new Promise((resolve) => {
    const el = document.querySelector(selector);
    if (el) { resolve(el); return; }

    let settled = false;
    const observer = new MutationObserver(() => {
      const found = document.querySelector(selector);
      if (found && !settled) { settled = true; observer.disconnect(); resolve(found); }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    setTimeout(() => { if (!settled) { settled = true; observer.disconnect(); resolve(null); } }, timeout);
  });
}
