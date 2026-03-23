/**
 * Feature 2: Enrich public IPs on UniFi Insights Flow View with
 * threat score, rDNS, and ASN data from Log Insight cache.
 *
 * Activated by 'uli-ready' event from controller-detector.js.
 * Runs in content script isolated world (has chrome.runtime access).
 *
 * UniFi DOM (verified against UniFi Network 9.x):
 * - Flow table wrapper: div.FLOWS_TABLE_WRAPPER_CLASSNAME
 * - Table header cells: thead th (text: "Source", "Src. IP", "Destination", etc.)
 * - Data rows: tbody tr.FLOWS_TABLE_ROW_CLASSNAME
 * - External source IP: img.FLOWS_SOURCE_FLAG_IMAGE_CLASSNAME in cell, <p> has IP
 * - External dest IP: img.FLOWS_DESTINATION_FLAG_IMAGE_CLASSNAME in cell, <p> has IP or "hostname (IP)"
 * - Local device: img.FLOWS_SOURCE_CLIENT_IMAGE_CLASSNAME (skip these)
 * - Cell inner div: div.cellInner__R2HCkU1s (append badge here)
 * - Columns are user-configurable: discover positions from header text
 */

window.addEventListener('uli-ready', async function () {
  const config = window.__uliConfig;
  if (!config || !config.enableFlowEnrichment) return;

  const { ABUSE_CATEGORIES, IPV4_RE, isPrivateIP, getThreatLevel, escapeHtml, escapeAttr, detectTheme, navigateToIP } = window.__uliUtils;
  const IPV6_TOKEN_RE = /[0-9a-fA-F:.]+/g;

  let threatColors = null;
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_THREAT_COLORS' });
    if (resp && resp.ok && resp.data) {
      threatColors = resp.data;
    }
  } catch (err) {
    console.debug('[ULI][Flow] GET_THREAT_COLORS failed, using fallback:', err?.message);
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

  let debounceTimer = null;
  let processing = false;
  let tableObserver = null;
  let remountObserver = null;
  let startupObserver = null;
  let themeObserver = null;
  let observedWrapper = null;
  let lastKnownTheme = detectTheme();
  let themeDebounce = null;

  function teardownObservers() {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    if (themeDebounce) {
      clearTimeout(themeDebounce);
      themeDebounce = null;
    }
    if (tableObserver) {
      tableObserver.disconnect();
      tableObserver = null;
    }
    if (remountObserver) {
      remountObserver.disconnect();
      remountObserver = null;
    }
    if (startupObserver) {
      startupObserver.disconnect();
      startupObserver = null;
    }
    if (themeObserver) {
      themeObserver.disconnect();
      themeObserver = null;
    }
    observedWrapper = null;
  }
  window.addEventListener('pagehide', teardownObservers, { once: true });

  // Watch for UniFi theme changes — strip badges and re-enrich so blacklist
  // colors and IP text colors update without requiring a page refresh.
  (function watchTheme() {
    themeObserver = new MutationObserver(() => {
      if (themeDebounce) clearTimeout(themeDebounce);
      themeDebounce = setTimeout(() => {
        const current = detectTheme();
        if (current !== lastKnownTheme) {
          lastKnownTheme = current;
          stripBadges();
          enrichFlowTable();
        }
      }, 250);
    });
    themeObserver.observe(document.body, { childList: true, subtree: true });
  })();

  /** Remove all injected badges and reset IP text colors. */
  function stripBadges() {
    for (const badge of document.querySelectorAll('[data-uli-badge]')) {
      badge.remove();
    }
    // Reset any colored IP text
    const table = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME table');
    if (table) {
      for (const p of table.querySelectorAll('p[style*="color"]')) {
        p.style.removeProperty('color');
      }
    }
  }

  // The flow table may not exist yet (user might be on a different sub-page).
  // Watch for it to appear.
  startWatching();

  function startWatching() {
    const wrapper = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME');
    if (wrapper) {
      observeTable(wrapper);
      enrichFlowTable();
      return;
    }

    if (startupObserver) return;

    // Table not present — watch for SPA navigation to flow view.
    startupObserver = new MutationObserver(() => {
      const w = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME');
      if (w) {
        startupObserver.disconnect();
        startupObserver = null;
        observeTable(w);
        enrichFlowTable();
      }
    });
    startupObserver.observe(document.body, { childList: true, subtree: true });
  }

  function observeTable(wrapper) {
    if (observedWrapper === wrapper && tableObserver) return;
    observedWrapper = wrapper;

    if (tableObserver) tableObserver.disconnect();

    // Watch for content changes (pagination, sorting, filtering)
    tableObserver = new MutationObserver(() => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => enrichFlowTable(), 500);
    });
    tableObserver.observe(wrapper, { childList: true, subtree: true });

    if (remountObserver) return;

    // Watch for table re-mount (SPA navigation away and back).
    remountObserver = new MutationObserver(() => {
      const w = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME');
      if (w && w !== observedWrapper) {
        observeTable(w);
        enrichFlowTable();
      }
    });
    remountObserver.observe(document.body, { childList: true, subtree: true });
  }

  /**
   * Build column name -> index map from current table headers.
   */
  function getColumnMap(table) {
    const headers = table.querySelectorAll('thead th');
    const map = {};
    for (let i = 0; i < headers.length; i++) {
      map[headers[i].textContent.trim()] = i;
    }
    return map;
  }

  /**
   * Scan the flow table and enrich external IP rows with threat badges.
   */
  async function enrichFlowTable() {
    if (processing) return;
    processing = true;

    try {
      const table = document.querySelector('.FLOWS_TABLE_WRAPPER_CLASSNAME table');
      if (!table) return;

      const tbody = table.querySelector('tbody');
      if (!tbody) return;

      const cols = getColumnMap(table);
      const rows = tbody.querySelectorAll('tr');
      const ipElements = [];

      // Prefer "Source"/"Destination" over "Src. IP"/"Dst. IP" when both exist
      const srcCol = cols['Source'] ?? cols['Src. IP'] ?? -1;
      const dstCol = cols['Destination'] ?? cols['Dst. IP'] ?? -1;
      const usingSrcName = 'Source' in cols;
      const usingDstName = 'Destination' in cols;

      for (const row of rows) {
        const cells = row.querySelectorAll('td');

        // Source IP
        if (srcCol >= 0 && srcCol < cells.length) {
          const cell = cells[srcCol];
          if (usingSrcName) {
            // Only enrich rows with a flag image (external IP)
            if (cell.querySelector('.FLOWS_SOURCE_FLAG_IMAGE_CLASSNAME')) {
              const ip = extractIP(cell);
              if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip, dir: 'src' });
            }
          } else {
            const ip = extractIP(cell);
            if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip, dir: 'src' });
          }
        }

        // Destination IP
        if (dstCol >= 0 && dstCol < cells.length) {
          const cell = cells[dstCol];
          if (usingDstName) {
            if (cell.querySelector('.FLOWS_DESTINATION_FLAG_IMAGE_CLASSNAME')) {
              const ip = extractIP(cell);
              if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip, dir: 'dst' });
            }
          } else {
            const ip = extractIP(cell);
            if (ip && !isPrivateIP(ip)) ipElements.push({ cell, ip, dir: 'dst' });
          }
        }
      }

      if (ipElements.length === 0) return;

      // Batch lookup unique IPs via service worker
      const uniqueIPs = [...new Set(ipElements.map(e => e.ip))];
      let threatData;
      try {
        const resp = await chrome.runtime.sendMessage({
          type: 'BATCH_THREAT_LOOKUP',
          ips: uniqueIPs,
        });
        if (!resp) return;
        if (resp.error) {
          console.warn('[ULI][Flow] BATCH_THREAT_LOOKUP error:', resp.error);
        }
        // Partial results are accepted intentionally — some IPs may succeed while
        // others fail (e.g., rate-limited). We enrich what we can.
        if (!resp.data || Object.keys(resp.data).length === 0) return;
        threatData = resp.data;
      } catch (e) {
        if (e?.message?.includes('Extension context invalidated')) {
          console.warn('[ULI][Flow] Extension reloaded — tearing down. Refresh the page.');
          teardownObservers();
          return;
        }
        console.warn('[ULI][Flow] BATCH_THREAT_LOOKUP failed:', e?.message);
        return;
      }

      for (const { cell, ip, dir } of ipElements) {
        const threat = threatData[ip];
        if (!threat) continue;
        // Skip if no useful data (no score, no rDNS, no ASN)
        const hasScore = threat.threat_score !== null && threat.threat_score !== undefined;
        const hasData = hasScore || threat.rdns || threat.asn_name;
        if (hasData) injectBadge(cell, ip, threat, dir);
      }
    } finally {
      processing = false;
    }
  }

  /**
   * Extract an IPv4 address from a flow table cell.
   * Cell text may be a raw IP, or "hostname (IP)".
   */
  function extractIP(cell) {
    const textEl = cell.querySelector('p');
    if (!textEl) return null;
    const text = textEl.textContent.trim();
    const v6 = extractIPv6(text);
    if (v6) return v6;
    const v4 = text.match(IPV4_RE);
    return v4 ? v4[0] : null;
  }

  function extractIPv6(text) {
    const tokens = text.match(IPV6_TOKEN_RE);
    if (!tokens) return null;
    const candidates = tokens
      .map(t => t.trim())
      .filter(t => t.includes(':') && t.length >= 2)
      .sort((a, b) => b.length - a.length);
    for (const candidate of candidates) {
      if (isValidIPv6(candidate)) return candidate.toLowerCase();
    }
    return null;
  }

  function isValidIPv6(candidate) {
    try {
      // URL parser validates IPv6 literals including compressed and mapped forms.
      new URL(`http://[${candidate}]/`);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Inject a threat badge inline to the right of the IP text in a flow table cell.
   */
  function injectBadge(cell, ip, threat, dir) {
    // Find the inner content div
    const cellInner = cell.querySelector('[class*="cellInner"]') || cell.querySelector('div');
    if (!cellInner) return;
    if (cellInner.querySelector('[data-uli-badge]')) return; // already injected

    // Make the cell inner a flex row so badge sits to the right of IP text
    cellInner.style.display = 'flex';
    cellInner.style.alignItems = 'center';
    cellInner.style.gap = '6px';

    // Truncate IPv6 addresses in the text element
    const textEl = cell.querySelector('p');
    if (textEl && ip.includes(':')) {
      const truncated = truncateIPv6(ip);
      if (truncated !== ip) {
        textEl.title = textEl.textContent.trim();
        textEl.textContent = textEl.textContent.replace(ip, truncated);
      }
    }

    // Color the IP text based on threat score (ThreatMap legend scale)
    if (textEl && threat.threat_score != null) {
      const ipColor = scoreToTextColor(threat.threat_score);
      if (ipColor) textEl.style.color = ipColor;
    }

    const badge = document.createElement('span');
    badge.setAttribute('data-uli-badge', ip);
    badge.style.flexShrink = '0';

    const shadow = badge.attachShadow({ mode: 'closed' });
    const level = getThreatLevel(threat.threat_score);
    const colors = threatColors[level] || threatColors.none;

    const parts = [];
    const hasScore = threat.threat_score !== null && threat.threat_score !== undefined;

    const isBlacklisted = threat.threat_categories && threat.threat_categories.includes('blacklist');
    const isDark = detectTheme() === 'dark';

    if (isBlacklisted) {
      // Blacklist badge replaces the score pill entirely
      // Dark mode: white badge, black text. Light mode: black badge, white text.
      const blBg = isDark ? '#fff' : '#000';
      const blText = isDark ? '#000' : '#fff';
      const tooltipLines = ['Blacklisted'];
      if (hasScore) tooltipLines.push('Threat Score: ' + threat.threat_score);
      if (threat.threat_categories.length > 1) {
        const decoded = threat.threat_categories
          .filter(c => c !== 'blacklist')
          .map(c => ABUSE_CATEGORIES[parseInt(c, 10)] || ('Category ' + c));
        if (decoded.length) tooltipLines.push(decoded.join(', '));
      }
      parts.push(
        '<span class="pill blacklist" style="background:' + blBg +
        ';color:' + blText +
        '" title="' + escapeAttr(tooltipLines.join('\n')) + '">Blacklist</span>'
      );
    } else if (hasScore) {
      // Threat score — colored dot (color from threat level legend)
      const score = threat.threat_score;
      const tooltipLines = ['Threat Score: ' + score];
      if (threat.threat_categories && threat.threat_categories.length) {
        const decoded = threat.threat_categories.map(c => {
          return ABUSE_CATEGORIES[parseInt(c, 10)] || ('Category ' + c);
        });
        tooltipLines.push(decoded.join(', '));
      }
      parts.push(
        '<span class="dot" style="background:' + colors.text +
        '" title="' + escapeAttr(tooltipLines.join('\n')) + '"></span>'
      );
    } else {
      // No threat score — gray dot (unknown, not "safe")
      parts.push(
        '<span class="dot no-data" title="No threat data"></span>'
      );
    }

    // rDNS (shorter truncation for inline display)
    if (threat.rdns) {
      const rdns = threat.rdns.length > 16 ? threat.rdns.slice(0, 14) + '\u2026' : threat.rdns;
      parts.push('<span class="meta" title="' + escapeAttr(threat.rdns) + '">' + escapeHtml(rdns) + '</span>');
    }

    // ASN (shorter truncation for inline display)
    if (threat.asn_name) {
      const asn = threat.asn_name.length > 14 ? threat.asn_name.slice(0, 12) + '\u2026' : threat.asn_name;
      parts.push('<span class="meta asn" title="' + escapeAttr(threat.asn_name) + '">' + escapeHtml(asn) + '</span>');
    }

    shadow.innerHTML =
      '<style>' +
      ':host{display:inline-flex;align-items:center;gap:4px;' +
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:12px;line-height:1}' +
      '.pill{padding:2px 6px;border-radius:9999px;font-size:11px;font-weight:600;' +
      'cursor:pointer;white-space:nowrap;flex-shrink:0}' +
      '.pill:hover{filter:brightness(1.3)}' +
      '.pill.blacklist{font-size:10px;border-radius:4px;padding:2px 7px;line-height:normal;display:inline-flex;align-items:center}' +
      '.dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}' +
      '.dot.no-data{background:#9ca3af}' +
      '.meta{color:#9ca3af;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:110px}' +
      '.asn{color:#6b7280}' +
      '</style>' +
      parts.join('');

    // Click pill/dot -> open Log Insight filtered to this IP
    const clickTarget = shadow.querySelector('.pill') || shadow.querySelector('.dot');
    if (clickTarget) {
      clickTarget.style.cursor = 'pointer';
      clickTarget.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        navigateToIP(ip, null, dir);
      });
    }

    cellInner.appendChild(badge);
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  function truncateIPv6(ip) {
    if (ip.length <= 20) return ip;
    return ip.slice(0, 17) + '\u2026';
  }

  /**
   * Map threat score to the IP text color using the ThreatMap legend scale.
   * <50 blue, 50-70 amber, 70-85 red, 85+ dark red.
   */
  function scoreToTextColor(score) {
    if (score === null || score === undefined || score <= 0) return null;
    if (score < 50) return '#3b82f6';   // blue-500
    if (score < 70) return '#f59e0b';   // amber-500
    if (score < 85) return '#ef4444';   // red-500
    return '#991b1b';                    // red-900
  }
});
