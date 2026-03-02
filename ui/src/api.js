const BASE = '/api'

function buildQS(params) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v)
  }
  return qs
}

export async function fetchLogs(params = {}) {
  const resp = await fetch(`${BASE}/logs?${buildQS(params)}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchLog(id) {
  const resp = await fetch(`${BASE}/logs/${id}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchStats(timeRange = '24h') {
  const resp = await fetch(`${BASE}/stats?time_range=${timeRange}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchHealth() {
  const resp = await fetch(`${BASE}/health`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchAbuseIPDBStatus() {
  const resp = await fetch(`${BASE}/abuseipdb/status`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function enrichIP(ip) {
  const resp = await fetch(`${BASE}/enrich/${encodeURIComponent(ip)}`, { method: 'POST' })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function fetchServices() {
  const resp = await fetch(`${BASE}/services`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchProtocols() {
  const resp = await fetch(`${BASE}/protocols`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export function getExportUrl(params = {}) {
  return `${BASE}/export?${buildQS(params)}`
}

// ── Flow View API ───────────────────────────────────────────────────────────

export async function fetchIPPairs(params = {}) {
  const resp = await fetch(`${BASE}/stats/ip-pairs?${buildQS(params)}`)
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function fetchFlowGraph(params = {}) {
  const resp = await fetch(`${BASE}/flows/graph?${buildQS(params)}`)
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function fetchZoneMatrix(params = {}) {
  const resp = await fetch(`${BASE}/flows/zone-matrix?${buildQS(params)}`)
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function fetchHostDetail(params = {}) {
  const resp = await fetch(`${BASE}/flows/host-detail?${buildQS(params)}`)
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

// ── Saved Views API ─────────────────────────────────────────────────────────

export async function fetchSavedViews() {
  const resp = await fetch(`${BASE}/views`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function createSavedView(name, filters) {
  const resp = await fetch(`${BASE}/views`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, filters })
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function deleteSavedView(id) {
  const resp = await fetch(`${BASE}/views/${id}`, { method: 'DELETE' })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

// ── Threat Map API ──────────────────────────────────────────────────────────

export async function fetchLogsBatch(ids) {
  const resp = await fetch(`${BASE}/logs/batch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids })
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchThreatGeo(params = {}) {
  const resp = await fetch(`${BASE}/threats/geo?${buildQS(params)}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── Setup Wizard API ──────────────────────────────────────────────────────────

export async function fetchConfig() {
  const resp = await fetch(`${BASE}/config`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchWANCandidates() {
  const resp = await fetch(`${BASE}/setup/wan-candidates`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchNetworkSegments(wanInterfaces = []) {
  const qs = wanInterfaces.length ? `?wan_interfaces=${wanInterfaces.join(',')}` : ''
  const resp = await fetch(`${BASE}/setup/network-segments${qs}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function saveSetupConfig(config) {
  const resp = await fetch(`${BASE}/setup/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchInterfaces() {
  const resp = await fetch(`${BASE}/interfaces`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── UniFi Settings API ───────────────────────────────────────────────────────

export async function fetchUniFiSettings() {
  const resp = await fetch(`${BASE}/settings/unifi`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function updateUniFiSettings(settings) {
  const resp = await fetch(`${BASE}/settings/unifi`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function testUniFiConnection(params) {
  const resp = await fetch(`${BASE}/settings/unifi/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function dismissUpgradeModal() {
  const resp = await fetch(`${BASE}/settings/unifi/dismiss-upgrade`, { method: 'POST' })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function dismissVpnToast() {
  const resp = await fetch(`${BASE}/settings/unifi/dismiss-vpn-toast`, { method: 'POST' })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchUniFiNetworkConfig() {
  const resp = await fetch(`${BASE}/setup/unifi-network-config`)
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

// ── Firewall API ─────────────────────────────────────────────────────────────

export async function fetchFirewallPolicies() {
  const resp = await fetch(`${BASE}/firewall/policies`)
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function patchFirewallPolicy(policyId, loggingEnabled, origin) {
  const resp = await fetch(`${BASE}/firewall/policies/${encodeURIComponent(policyId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ loggingEnabled, origin })
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function bulkUpdateFirewallLogging(policies) {
  const resp = await fetch(`${BASE}/firewall/policies/bulk-logging`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policies })
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

// ── UniFi Device Names (Phase 2) ────────────────────────────────────────────

export async function fetchUniFiStatus() {
  const resp = await fetch(`${BASE}/unifi/status`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── Config Export/Import ─────────────────────────────────────────────────────

export async function exportConfig(includeApiKey = false) {
  const resp = await fetch(`${BASE}/config/export?include_api_key=${includeApiKey}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function importConfig(config) {
  const resp = await fetch(`${BASE}/config/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── VPN Network Configuration ───────────────────────────────────────────────

export async function saveVpnNetworks(vpnNetworks, vpnLabels = {}) {
  const resp = await fetch(`${BASE}/config/vpn-networks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vpn_networks: vpnNetworks, vpn_labels: vpnLabels })
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── Retention Configuration ─────────────────────────────────────────────────

export async function fetchRetentionConfig() {
  const resp = await fetch(`${BASE}/config/retention`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function updateRetentionConfig(config) {
  const resp = await fetch(`${BASE}/config/retention`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── MCP Settings ────────────────────────────────────────────────────────────

export async function fetchMcpSettings() {
  const resp = await fetch(`${BASE}/settings/mcp`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function updateMcpSettings(settings) {
  const resp = await fetch(`${BASE}/settings/mcp`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchMcpScopes() {
  const resp = await fetch(`${BASE}/settings/mcp/scopes`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchMcpTokens() {
  const resp = await fetch(`${BASE}/settings/mcp/tokens`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function fetchMcpAudit(limit = 200, offset = 0) {
  const resp = await fetch(`${BASE}/settings/mcp/audit?limit=${limit}&offset=${offset}`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function createMcpToken(payload) {
  const resp = await fetch(`${BASE}/settings/mcp/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function revokeMcpToken(tokenId) {
  const resp = await fetch(`${BASE}/settings/mcp/tokens/${encodeURIComponent(tokenId)}`, {
    method: 'DELETE'
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  return resp.json()
}

export async function runRetentionCleanup() {
  const resp = await fetch(`${BASE}/config/retention/cleanup`, { method: 'POST' })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── UI Settings ─────────────────────────────────────────────────────────

export async function fetchUiSettings() {
  const resp = await fetch(`${BASE}/settings/ui`)
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

export async function updateUiSettings(settings) {
  const resp = await fetch(`${BASE}/settings/ui`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  })
  if (!resp.ok) throw new Error(`API error: ${resp.status}`)
  return resp.json()
}

// ── Version Check ────────────────────────────────────────────────────────────

export async function fetchLatestRelease(currentVersion) {
  // Beta builds: include pre-releases when finding the latest
  if (currentVersion && currentVersion.includes('-beta')) {
    const resp = await fetch(
      'https://api.github.com/repos/jmasarweh/unifi-log-insight/releases?per_page=1'
    )
    if (!resp.ok) return null
    const data = await resp.json()
    if (!data.length) return null
    const r = data[0]
    return { tag: r.tag_name, url: r.html_url, body: r.body || '', prerelease: r.prerelease }
  }
  // Stable builds: /releases/latest skips pre-releases automatically
  const resp = await fetch(
    'https://api.github.com/repos/jmasarweh/unifi-log-insight/releases/latest'
  )
  if (!resp.ok) return null
  const data = await resp.json()
  return { tag: data.tag_name, url: data.html_url, body: data.body || '' }
}

export async function fetchAllReleases() {
  const resp = await fetch(
    'https://api.github.com/repos/jmasarweh/unifi-log-insight/releases'
  )
  if (!resp.ok) return null
  const data = await resp.json()
  return data.map(r => ({ tag: r.tag_name, url: r.html_url, body: r.body || '', prerelease: r.prerelease }))
}
