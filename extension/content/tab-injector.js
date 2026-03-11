/**
 * Feature 1: Inject a "Log Insight" tab into the UniFi Controller portal nav.
 * Clicking it embeds the Log Insight app in the UniFi content area below the nav.
 *
 * Activated by 'uli-ready' event from controller-detector.js.
 * Runs in content script isolated world (has chrome.runtime access).
 */

window.addEventListener('uli-ready', async function () {
  const config = window.__uliConfig;
  if (!config) return;

  const onRuntimeMessage = (msg, _sender, sendResponse) => {
    if (!msg || msg.type !== 'ULI_GET_THEME') return;
    sendResponse({ ok: true, theme: detectUniFiTheme() });
    return true;
  };
  chrome.runtime.onMessage.addListener(onRuntimeMessage);
  window.addEventListener('pagehide', () => {
    chrome.runtime.onMessage.removeListener(onRuntimeMessage);
  }, { once: true });
  chrome.storage.local.set({ unifiUiTheme: detectUniFiTheme() }).catch(() => {});

  if (!config.enableTabInjection) return;

  const logInsightUrl = config.baseUrl;
  if (!logInsightUrl) return;

  let logInsightOrigin;
  try {
    logInsightOrigin = new URL(logInsightUrl).origin;
  } catch (e) {
    console.error('Invalid Log Insight URL:', logInsightUrl, e);
    return;
  }
  const iconUrlGreyLight = chrome.runtime.getURL('icons/icon-32-grey.png');
  const iconUrlGreyDark = chrome.runtime.getURL('icons/icon-32-grey-dark.png');
  const iconUrlBlue = chrome.runtime.getURL('icons/icon-32-blue.png');

  /** Return the correct inactive icon URL for the current theme. */
  function inactiveIconUrl() {
    return lastTheme === 'dark' ? iconUrlGreyDark : iconUrlGreyLight;
  }

  let isActive = false;
  let iframeContainer = null;
  let iframe = null;
  let uliTab = null;
  let navRoot = null;        // authoritative nav container (set once at injection)
  let capturedActiveTab = null; // the UniFi tab that was active when we activated
  let themeObs = null;
  let lastUrl = location.href;
  let lastTheme = detectUniFiTheme();

  // Wait for the tab container to render
  const tabContainer = await waitForTabContainer(15000);
  if (!tabContainer) return;

  injectTab(tabContainer);

  // Re-inject if SPA re-renders the header
  const headerObs = new MutationObserver(() => {
    // Use navRoot if still connected, else fall back to fresh query
    const container = (navRoot && navRoot.isConnected) ? navRoot : findTabContainer();
    if (container && !container.querySelector('[data-uli-tab]')) {
      injectTab(container);
    }
  });
  headerObs.observe(document.body, { childList: true, subtree: true });

  // Watch for UniFi theme changes and re-sync tab styling + iframe theme
  themeObs = observeThemeChanges(lastTheme);

  // Route-change safety net: if URL changes while embed is active, force deactivate.
  // Covers pushState, replaceState, popstate, and hashchange.
  const origPushState = history.pushState;
  const origReplaceState = history.replaceState;
  history.pushState = function (...args) {
    origPushState.apply(this, args);
    onPossibleRouteChange();
  };
  history.replaceState = function (...args) {
    origReplaceState.apply(this, args);
    onPossibleRouteChange();
  };
  window.addEventListener('popstate', onPossibleRouteChange);
  window.addEventListener('hashchange', onPossibleRouteChange);

  function onPossibleRouteChange() {
    if (!isActive) { lastUrl = location.href; return; }
    if (location.href !== lastUrl) {
      deactivateEmbed();
    }
    lastUrl = location.href;
  }

  const teardown = () => {
    headerObs.disconnect();
    if (themeObs) {
      themeObs.disconnect();
      themeObs = null;
    }
    history.pushState = origPushState;
    history.replaceState = origReplaceState;
    window.removeEventListener('popstate', onPossibleRouteChange);
    window.removeEventListener('hashchange', onPossibleRouteChange);
    document.removeEventListener('keydown', onEscKey);
    window.removeEventListener('uli-navigate', onUliNavigate);
  };
  window.addEventListener('pagehide', teardown, { once: true });

  function waitForTabContainer(timeout) {
    return new Promise((resolve) => {
      const found = findTabContainer();
      if (found) { resolve(found); return; }
      let settled = false;
      const obs = new MutationObserver(() => {
        const el = findTabContainer();
        if (el && !settled) { settled = true; clearTimeout(timer); obs.disconnect(); resolve(el); }
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
      const timer = setTimeout(() => { if (!settled) { settled = true; obs.disconnect(); resolve(null); } }, timeout);
    });
  }

  function findTabContainer() {
    const candidates = document.querySelectorAll(
      'header[class*="unifi-portal"] div[class*="unifi-portal"]'
    );
    for (const el of candidates) {
      if (el.querySelectorAll(':scope > a').length >= 2) return el;
    }
    return null;
  }

  /**
   * Find the best tab to clone — an inactive tab with text (e.g. "Protect").
   */
  function findInactiveTab(container) {
    const links = container.querySelectorAll(':scope > a');
    let best = null;
    for (const link of links) {
      const text = link.textContent.trim();
      if (!text) continue;
      if (link.hasAttribute('data-uli-tab')) continue;
      if (!isTabActive(link)) return link;
      if (!best) best = link;
    }
    return best;
  }

  /**
   * Find the currently active UniFi tab using explicit ARIA/class signals first,
   * then fall back to URL matching.
   */
  function findActiveUniFiTab(container) {
    const links = container.querySelectorAll(':scope > a');
    let urlMatch = null;
    let fallback = null;

    for (const link of links) {
      if (link.hasAttribute('data-uli-tab')) continue;
      if (!fallback) fallback = link;

      // Prefer explicit active signals (aria-current, aria-selected, active class)
      if (isTabActive(link)) return link;

      // URL match as secondary signal — resolve to absolute path to avoid
      // false positives with short hrefs like "/" or "/network"
      const hrefAttr = link.getAttribute('href') || link.href || '';
      if (!urlMatch && hrefAttr && hrefAttr.length > 1) {
        try {
          const resolved = new URL(hrefAttr, location.href).pathname;
          if (location.pathname.startsWith(resolved)) {
            urlMatch = link;
          }
        } catch { /* skip malformed href */ }
      }
    }
    return urlMatch || fallback;
  }

  /**
   * Check if a tab element has explicit active indicators from UniFi.
   */
  function isTabActive(link) {
    if (link.getAttribute('aria-current') === 'page' ||
        link.getAttribute('aria-current') === 'true') return true;
    if (link.getAttribute('aria-selected') === 'true') return true;
    const cls = link.className || '';
    if (/\bactive\b/i.test(cls) || /\bselected\b/i.test(cls)) return true;
    return false;
  }

  function injectTab(container) {
    if (container.querySelector('[data-uli-tab]')) return;

    const templateTab = findInactiveTab(container);
    if (!templateTab) return;

    const tab = templateTab.cloneNode(true);
    tab.setAttribute('data-uli-tab', 'true');
    tab.removeAttribute('href');
    tab.setAttribute('role', 'button');
    tab.style.cursor = 'pointer';

    // Replace icon SVG with our app icon, keep the title div
    const iconContainer = tab.querySelector('div');
    if (iconContainer) {
      // Remove the SVG but keep the title div
      const svg = iconContainer.querySelector('svg');
      if (svg) svg.remove();

      const img = document.createElement('img');
      img.src = inactiveIconUrl();
      img.width = 24;
      img.height = 24;
      img.alt = 'Log Insight';
      img.style.borderRadius = '4px';
      iconContainer.insertBefore(img, iconContainer.firstChild);

      // Update the title text
      const titleDiv = iconContainer.querySelector('.title');
      if (titleDiv) {
        titleDiv.textContent = 'Log Insight';
      } else {
        // Create title div if it doesn't exist
        const title = document.createElement('div');
        title.className = 'title';
        title.textContent = 'Log Insight';
        iconContainer.appendChild(title);
      }
    }

    tab.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (isActive) {
        deactivateEmbed();
      } else {
        activateEmbed();
      }
    });

    container.appendChild(tab);
    uliTab = tab;
    navRoot = container; // authoritative reference — never re-query for click scope

    // Attach deactivation listeners to each real UniFi tab
    attachDeactivationListeners(container);

    // If we're currently active, apply active styling to the fresh tab
    if (isActive) syncTabStyling();
  }

  function attachDeactivationListeners(container) {
    const links = container.querySelectorAll(':scope > a');
    for (const link of links) {
      if (link.hasAttribute('data-uli-tab')) continue;
      if (link.hasAttribute('data-uli-deactivate')) continue;
      link.setAttribute('data-uli-deactivate', 'true');
      link.addEventListener('click', () => {
        if (isActive) deactivateEmbed();
      }, true);
    }
  }

  // ── Activate / Deactivate ────────────────────────────────────────────────

  function activateEmbed() {
    if (isActive) return;

    // Capture the currently-active UniFi tab BEFORE we modify anything.
    if (navRoot && navRoot.isConnected) {
      capturedActiveTab = findActiveUniFiTab(navRoot);
    }

    // Use fixed overlay so we never touch <main> or hold stale references.
    // Re-create if the SPA removed it from the DOM during app navigation.
    if (!iframeContainer || !iframeContainer.isConnected) {
      iframeContainer = createIframeContainer();
      document.body.appendChild(iframeContainer);
    }

    iframeContainer.style.display = 'block';
    syncTabStyling();
    isActive = true;
    lastUrl = location.href;
  }

  function deactivateEmbed() {
    if (!isActive) return;
    if (iframeContainer) iframeContainer.style.display = 'none';
    restoreTabStyling();
    capturedActiveTab = null;
    isActive = false;
  }

  // ── Tab styling ─────────────────────────────────────────────────────────
  //
  // UniFi drives active tab styling via aria-current="page" matched by
  // CSS-in-JS selectors. Same CSS classes on all tabs — only the ARIA
  // attribute differs. We manipulate aria-current directly instead of
  // fighting CSS specificity with inline style overrides.

  function syncTabStyling() {
    if (!uliTab) return;

    // Remove active indicator from the real UniFi tab
    if (capturedActiveTab && capturedActiveTab.isConnected) {
      capturedActiveTab.removeAttribute('aria-current');
    }

    // Make our tab look active
    uliTab.setAttribute('aria-current', 'page');

    // Swap icon to active blue
    const img = uliTab.querySelector('img');
    if (img) img.src = iconUrlBlue;
  }

  function restoreTabStyling() {
    // Restore the real UniFi tab's active state (only if still connected —
    // after SPA navigation React may have replaced the element)
    if (capturedActiveTab && capturedActiveTab.isConnected) {
      capturedActiveTab.setAttribute('aria-current', 'page');
    }

    // Remove active state from our tab and reset icon to inactive grey
    if (uliTab && uliTab.isConnected) {
      uliTab.removeAttribute('aria-current');
      const img = uliTab.querySelector('img');
      if (img) img.src = inactiveIconUrl();
    }

    // Safety: ensure no lingering aria-current on our tab after React re-renders
    const freshUli = document.querySelector('[data-uli-tab]');
    if (freshUli && freshUli !== uliTab) {
      freshUli.removeAttribute('aria-current');
      const img = freshUli.querySelector('img');
      if (img) img.src = inactiveIconUrl();
      uliTab = freshUli;
    }
  }

  // ── Theme detection ─────────────────────────────────────────────────────

  function detectUniFiTheme() {
    // UniFi uses a dark header bg in dark mode, light in light mode
    const header = document.querySelector('header[class*="unifi-portal"]');
    if (!header) return 'dark';
    const bg = getComputedStyle(header).backgroundColor;
    return isColorDark(bg) ? 'dark' : 'light';
  }

  function isColorDark(color) {
    // Parse rgb(r, g, b) or rgba(r, g, b, a)
    const m = color.match(/(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
    if (!m) return true; // default to dark
    const luminance = (0.299 * +m[1] + 0.587 * +m[2] + 0.114 * +m[3]);
    return luminance < 128;
  }

  function observeThemeChanges(initialTheme) {
    // UniFi toggles themes by re-rendering the entire React tree — the old
    // header element gets replaced, so we must observe document.body with
    // subtree:true to catch the new header appearing. Debounced to 200ms
    // to avoid excessive checks.
    let debounce = null;
    let known = initialTheme;
    const check = () => {
      const current = detectUniFiTheme();
      if (current !== known) {
        known = current;
        lastTheme = current;
        onThemeChanged(current);
      }
    };
    const observer = new MutationObserver(() => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(check, 200);
    });
    observer.observe(document.body, { childList: true, subtree: true });
    return observer;
  }

  function onThemeChanged(theme) {
    if (uliTab) {
      // UniFi re-rendered all tabs with new theme CSS classes.
      // Update our tab's className to match the current inactive tabs
      // so it looks correct both now and after deactivation.
      const container = uliTab.parentElement;
      if (container) {
        const inactiveTab = findInactiveTab(container);
        if (inactiveTab) {
          uliTab.className = inactiveTab.className;
          uliTab.setAttribute('data-uli-tab', 'true');
          uliTab.removeAttribute('href');
          uliTab.style.cursor = 'pointer';
        }
      }

      // Update icon for new theme and re-apply styling
      if (isActive) {
        restoreTabStyling();
        syncTabStyling();
      } else {
        const img = uliTab.querySelector('img');
        if (img) img.src = inactiveIconUrl();
      }
    }

    // Tell the iframe to switch theme
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: 'uli-theme', theme }, logInsightOrigin);
    }
    chrome.storage.local.set({ unifiUiTheme: theme }).catch(() => {});
  }

  // ── Iframe ──────────────────────────────────────────────────────────────

  function createIframeContainer() {
    // Use fixed positioning to overlay the content area.
    // This avoids hiding/showing <main> and holding stale DOM references.
    const header = document.querySelector('header[class*="unifi-portal"]');
    const headerH = header ? header.getBoundingClientRect().height : 48;

    const container = document.createElement('div');
    container.id = 'uli-embed';
    container.style.cssText = `display:none;position:fixed;top:${headerH}px;left:0;right:0;bottom:0;z-index:1000;`;

    const theme = detectUniFiTheme();
    iframe = document.createElement('iframe');
    iframe.src = logInsightUrl + '?theme=' + theme + '&parentOrigin=' + encodeURIComponent(location.origin);
    iframe.sandbox = 'allow-scripts allow-same-origin allow-forms allow-popups';
    iframe.style.cssText = 'width:100%;height:100%;border:none;';

    container.appendChild(iframe);
    return container;
  }

  // ESC to deactivate (ignore when focus is on interactive elements)
  const onEscKey = (e) => {
    if (e.key === 'Escape' && isActive) {
      const el = e.target || document.activeElement;
      if (el && el.matches('input, textarea, select, button, [contenteditable="true"]')) return;
      deactivateEmbed();
    }
  };
  document.addEventListener('keydown', onEscKey);

  // Deactivate when user clicks another UniFi tab.
  // Listeners are attached directly to each tab <a> in attachDeactivationListeners()
  // called from injectTab(). This is more reliable than a document-level handler
  // because content script capture listeners on document can miss events in some
  // browser/extension configurations.

  // Listen for navigation requests from flow-enricher (pill/dot clicks)
  const onUliNavigate = (e) => {
    const { ip } = e.detail || {};
    if (!ip) return;

    // Activate the embed if not already active
    if (!isActive) activateEmbed();

    // Navigate the iframe to logs filtered by IP
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: 'uli-navigate', hash: '#logs?ip=' + encodeURIComponent(ip) }, logInsightOrigin);
    }
  };
  window.addEventListener('uli-navigate', onUliNavigate);
});
