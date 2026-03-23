/**
 * Feature 3: Enrich the UniFi Flow detail side panel with threat data.
 *
 * When the user clicks a flow table row, UniFi opens a property panel on the
 * right showing Source, Destination, and Traffic Info sections. This script
 * detects the panel, extracts public IPs from the Source/Destination sections,
 * fetches threat data from the Log Insight cache, and injects enrichment rows.
 *
 * Activated by 'uli-ready' event from controller-detector.js.
 * Runs in content script isolated world (has chrome.runtime access).
 *
 * UniFi DOM (verified against UniFi Network 9.x):
 * - Panel container: div.PROPERTY_PANEL_CLASSNAME
 * - Collapsible sections: ul > li, title in span[class*="title__"]
 * - Section content: div[class*="contentContainer__"] > div.content > div
 * - Key-value rows: div (flex row) with p[class*="textBlock__"] pairs
 * - Theme: panel classes include -light or -dark suffixes
 */

window.addEventListener('uli-ready', async function () {
  const config = window.__uliConfig;
  if (!config || !config.enableFlowEnrichment) return;

  if (!window.__uliUtils) { console.warn('[ULI][Panel] shared-utils not loaded'); return; }
  const { ABUSE_CATEGORIES, IPV4_RE, isPrivateIP, getThreatLevel, escapeHtml, escapeAttr, detectTheme, navigateToIP, onThemeChange } = window.__uliUtils;

  let threatColors = null;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_THREAT_COLORS' });
    if (resp && resp.ok && resp.data) threatColors = resp.data;
  } catch (err) {
    console.debug('[ULI][Panel] GET_THREAT_COLORS failed, using fallback:', err?.message);
  }
  if (!threatColors) {
    threatColors = {
      none: { bg: '#34d39922', text: '#34d399', border: '#34d39944' },
      low: { bg: '#60a5fa22', text: '#60a5fa', border: '#60a5fa44' },
      medium: { bg: '#fbbf2422', text: '#fbbf24', border: '#fbbf2444' },
      high: { bg: '#fb923c22', text: '#fb923c', border: '#fb923c44' },
      critical: { bg: '#f8717122', text: '#f87171', border: '#f8717144' },
    };
  }

  let panelObserver = null;
  let debounceTimer = null;

  // Re-render enrichment blocks when UniFi theme toggles (light ↔ dark).
  // Strips stale markers so enrichPanel() re-injects with fresh colors.
  const themeObs = onThemeChange(() => {
    for (const el of document.querySelectorAll('[data-uli-panel-enriched]')) el.remove();
    for (const el of document.querySelectorAll('[data-uli-panel-ip]')) el.removeAttribute('data-uli-panel-ip');
    enrichPanel();
  });

  function teardown() {
    if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
    if (panelObserver) { panelObserver.disconnect(); panelObserver = null; }
    themeObs.disconnect();
  }
  window.addEventListener('pagehide', teardown, { once: true });

  // Watch for the property panel appearing / changing in the DOM.
  panelObserver = new MutationObserver(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(enrichPanel, 300);
  });
  panelObserver.observe(document.body, { childList: true, subtree: true });

  // Also run immediately in case panel is already open.
  enrichPanel();

  // ── Core ──────────────────────────────────────────────────────────────

  async function enrichPanel() {
    const panel = document.querySelector('.PROPERTY_PANEL_CLASSNAME');
    if (!panel) return;

    // Extract flow timestamp from panel header for time-range auto-selection.
    const headerEl = panel.querySelector('[class*="panelHeader"] [class*="title__"]');
    const flowTimestamp = headerEl ? headerEl.textContent.trim() : null;

    // Find all collapsible section <li> items.
    const sections = panel.querySelectorAll('ul > li');
    if (!sections.length) return;

    const ipsToEnrich = []; // { sectionEl, ip, sectionName }

    for (const li of sections) {
      const titleEl = li.querySelector('[class*="title__"]');
      if (!titleEl) continue;
      const sectionName = titleEl.textContent.trim();
      if (sectionName !== 'Source' && sectionName !== 'Destination') continue;

      // Find the content container for this section.
      const contentContainer = li.querySelector('[class*="contentContainer__"]');
      if (!contentContainer) continue;

      // Skip if already enriched with the same IP.
      const ip = extractIPFromSection(contentContainer);
      if (!ip || isPrivateIP(ip)) continue;

      const existingMarker = contentContainer.getAttribute('data-uli-panel-ip');
      if (existingMarker === ip) continue; // already enriched for this IP

      // Remove stale enrichment if IP changed.
      const stale = contentContainer.querySelector('[data-uli-panel-enriched]');
      if (stale) stale.remove();

      const dir = sectionName === 'Source' ? 'src' : 'dst';
      ipsToEnrich.push({ contentContainer, ip, sectionName, dir });
    }

    if (!ipsToEnrich.length) return;

    // Batch lookup unique IPs.
    const uniqueIPs = [...new Set(ipsToEnrich.map(e => e.ip))];
    let threatData;
    try {
      const resp = await chrome.runtime.sendMessage({
        type: 'BATCH_THREAT_LOOKUP',
        ips: uniqueIPs,
      });
      if (!resp) return;
      if (resp.error) {
        console.warn('[ULI][Panel] BATCH_THREAT_LOOKUP error:', resp.error);
      }
      // Partial results are accepted intentionally — some IPs may succeed while
      // others fail (e.g., rate-limited). We enrich what we can.
      if (!resp.data || Object.keys(resp.data).length === 0) return;
      threatData = resp.data;
    } catch (e) {
      if (e?.message?.includes('Extension context invalidated')) {
        console.warn('[ULI][Panel] Extension reloaded — tearing down. Refresh the page.');
        teardown();
        return;
      }
      console.warn('[ULI][Panel] BATCH_THREAT_LOOKUP failed:', e?.message);
      return;
    }

    for (const { contentContainer, ip, dir } of ipsToEnrich) {
      const threat = threatData[ip];
      if (!threat) continue;
      const hasScore = threat.threat_score !== null && threat.threat_score !== undefined;
      const hasData = hasScore || threat.rdns || threat.asn_name;
      if (!hasData) continue;

      contentContainer.setAttribute('data-uli-panel-ip', ip);
      injectEnrichmentBlock(contentContainer, ip, threat, flowTimestamp, dir);
    }
  }

  /**
   * Extract an IPv4 address from a section's content rows.
   * Looks for the row labeled "IP Address" and reads its value.
   */
  function extractIPFromSection(contentContainer) {
    const rows = contentContainer.querySelectorAll('[class*="textBlock__"]');
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].textContent.trim() === 'IP Address' && rows[i + 1]) {
        const text = rows[i + 1].textContent.trim();
        const m = text.match(IPV4_RE);
        return m ? m[0] : null;
      }
    }
    return null;
  }

  /**
   * Inject the enrichment block into a section's content container.
   * Uses Shadow DOM for style isolation.
   */
  function injectEnrichmentBlock(contentContainer, ip, threat, flowTimestamp, dir) {
    const isDark = detectTheme() === 'dark';

    // Find the inner rows container to append after.
    const innerContainer = contentContainer.querySelector('.content');
    const target = innerContainer || contentContainer;

    const wrapper = document.createElement('div');
    wrapper.setAttribute('data-uli-panel-enriched', ip);

    const shadow = wrapper.attachShadow({ mode: 'closed' });

    const level = getThreatLevel(threat.threat_score);
    const colors = threatColors[level] || threatColors.none;
    const hasScore = threat.threat_score !== null && threat.threat_score !== undefined;
    const isBlacklisted = threat.threat_categories && threat.threat_categories.includes('blacklist');

    // Theme-adaptive colors — matched from UniFi's actual computed styles.
    // Dark: bg rgb(19,20,22), labels rgb(249,250,250), values rgb(222,224,227).
    // Light: bg white, labels rgb(80,86,94), values rgb(33,35,39).
    const textPrimary = isDark ? '#dee0e3' : '#212327';
    const textSecondary = isDark ? '#f9fafa' : '#50565e';
    const borderColor = isDark ? '#2a2c2e' : '#e5e7eb';
    const bgColor = 'transparent';

    const rows = [];

    // Threat Score row
    if (isBlacklisted) {
      const blBg = isDark ? '#fff' : '#000';
      const blText = isDark ? '#000' : '#fff';
      rows.push(buildRow('Threat', `<span class="pill blacklist" style="background:${blBg};color:${blText}">Blacklist</span>` +
        (hasScore ? ` <span class="score-note">${threat.threat_score}</span>` : '')));
    } else if (hasScore) {
      rows.push(buildRow('Threat Score',
        `<span class="pill" style="background:${colors.bg};color:${colors.text};border:1px solid ${colors.border}">${threat.threat_score}</span>`));
    } else {
      rows.push(buildRow('Threat Score', '<span class="dot no-data"></span> <span class="score-note">No data</span>'));
    }

    // rDNS
    if (threat.rdns) {
      rows.push(buildRow('rDNS', `<span class="value-text" title="${escapeAttr(threat.rdns)}">${escapeHtml(threat.rdns)}</span>`));
    }

    // ASN
    if (threat.asn_name) {
      rows.push(buildRow('ASN', `<span class="value-text" title="${escapeAttr(threat.asn_name)}">${escapeHtml(threat.asn_name)}</span>`));
    }

    // Abuse Categories
    if (threat.threat_categories && threat.threat_categories.length) {
      const decoded = threat.threat_categories
        .filter(c => c !== 'blacklist')
        .map(c => ABUSE_CATEGORIES[parseInt(c, 10)] || ('Category ' + c));
      if (decoded.length) {
        rows.push(buildRow('Categories', `<span class="value-text" title="${escapeAttr(decoded.join(', '))}">${escapeHtml(decoded.join(', '))}</span>`));
      }
    }

    const logoColor = isDark ? '#2dd4bf' : '#14B8A6';
    const logoSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="16" viewBox="0 0 100 116" fill="none"><path d="M 29 68 C 22 62,16 53,16 41 A 34 34 0 1 1 84 41 C 84 53,78 62,71 68 Z" fill="${logoColor}" fill-opacity="0.12"/><path d="M 29 68 C 22 62,16 53,16 41 A 34 34 0 1 1 84 41 C 84 53,78 62,71 68" stroke="${logoColor}" stroke-width="5.2" stroke-linecap="round" fill="none"/><path d="M 28 34 A 18 18 0 0 1 44 22" stroke="${logoColor}" stroke-width="4.8" stroke-linecap="round" fill="none" opacity="0.7"/><line x1="28" y1="75" x2="72" y2="75" stroke="${logoColor}" stroke-width="5.2" stroke-linecap="round"/><line x1="36" y1="84" x2="64" y2="84" stroke="${logoColor}" stroke-width="5.2" stroke-linecap="round"/><text x="50" y="110" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-weight="800" font-size="19" letter-spacing="0.16em" fill="${isDark ? '#14b8a6' : '#0D9488'}">PLUS</text></svg>`;

    shadow.innerHTML =
      '<style>' +
      `:host{display:block;margin-top:8px;padding:8px 0;border-top:1px solid ${borderColor};background:${bgColor};` +
      'font-family:inherit;font-size:14px;line-height:1.4}' +
      `.header{display:flex;align-items:center;gap:6px;margin-bottom:6px;color:${textSecondary};font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}` +
      '.header-logo{width:14px;height:14px;flex-shrink:0;display:flex;align-items:center}' +
      `.row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:3px 0}` +
      `.label{color:${textSecondary};font-size:14px;white-space:nowrap;flex-shrink:0}` +
      `.value{color:${textPrimary};font-size:14px;text-align:right;min-width:0}` +
      `.value-text{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:220px;color:${textPrimary}}` +
      '.pill{padding:2px 8px;border-radius:9999px;font-size:12px;font-weight:600;white-space:nowrap;cursor:pointer}' +
      '.pill:hover{filter:brightness(1.3)}' +
      '.pill.blacklist{border-radius:4px;padding:2px 8px;font-size:11px}' +
      `.score-note{color:${textSecondary};font-size:12px;margin-left:4px}` +
      '.dot{display:inline-block;width:9px;height:9px;border-radius:50%;vertical-align:middle}' +
      '.dot.no-data{background:#9ca3af}' +
      `.link{display:block;color:${isDark ? '#2dd4bf' : '#14B8A6'};font-size:12px;cursor:pointer;text-decoration:none;margin-top:6px;text-align:right}` +
      '.link:hover{text-decoration:underline}' +
      '</style>' +
      `<div class="header"><span class="header-logo">${logoSvg}</span>Insights Plus</div>` +
      rows.join('') +
      '<a class="link" data-uli-nav>View Traffic &#8599;</a>';

    // Click "View traffic" link or pill -> open Log Insight filtered to this IP.
    for (const el of shadow.querySelectorAll('[data-uli-nav], .pill')) {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        navigateToIP(ip, flowTimestamp, dir);
      });
    }

    target.appendChild(wrapper);
  }

  function buildRow(label, valueHtml) {
    return `<div class="row"><span class="label">${escapeHtml(label)}</span><span class="value">${valueHtml}</span></div>`;
  }
});
