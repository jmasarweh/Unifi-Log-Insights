const BASE = '/api'

function buildQS(params) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v)
  }
  return qs
}

// ── Auth: global 401 handling ───────────────────────────────────────────────
// Single handler is sufficient — SPA has one App mount point. An array of
// handlers would add complexity with no benefit for this architecture.
let onAuthExpired = null
export function setAuthExpiredHandler(handler) { onAuthExpired = handler }

async function apiFetch(url, options = {}) {
  const resp = await fetch(url, { credentials: 'include', ...options })
  if (resp.status === 401 && onAuthExpired) {
    onAuthExpired()
    throw new Error('Session expired')
  }
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    const err = new Error(body.detail || `API error: ${resp.status}`)
    err.status = resp.status
    throw err
  }
  return resp.json()
}

/**
 * Low-level fetch wrapper: returns the raw Response object.
 * Only handles 401 (calls onAuthExpired and throws). Does NOT check resp.ok —
 * callers (e.g. bulkUpdateFirewallLoggingStream) must check resp.ok themselves
 * and handle non-OK responses appropriately.
 */
async function apiFetchRaw(url, options = {}) {
  const resp = await fetch(url, { credentials: 'include', ...options })
  if (resp.status === 401 && onAuthExpired) {
    onAuthExpired()
    throw new Error('Session expired')
  }
  return resp
}

export async function fetchLogs(params = {}) {
  return apiFetch(`${BASE}/logs?${buildQS(params)}`)
}

export async function fetchLog(id) {
  return apiFetch(`${BASE}/logs/${id}`)
}

export async function fetchStats(timeRange = '24h') {
  return apiFetch(`${BASE}/stats?time_range=${timeRange}`)
}

export async function fetchStatsOverview(timeRange = '24h') {
  return apiFetch(`${BASE}/stats/overview?time_range=${timeRange}`)
}

export async function fetchStatsCharts(timeRange = '24h') {
  return apiFetch(`${BASE}/stats/charts?time_range=${timeRange}`)
}

export async function fetchStatsTables(timeRange = '24h') {
  return apiFetch(`${BASE}/stats/tables?time_range=${timeRange}`)
}

export async function fetchHealth() {
  return apiFetch(`${BASE}/health`)
}

export async function fetchAbuseIPDBStatus() {
  return apiFetch(`${BASE}/abuseipdb/status`)
}

export async function enrichIP(ip) {
  return apiFetch(`${BASE}/enrich/${encodeURIComponent(ip)}`, { method: 'POST' })
}

export async function fetchServices() {
  return apiFetch(`${BASE}/services`)
}

export async function fetchProtocols() {
  return apiFetch(`${BASE}/protocols`)
}

export function getExportUrl(params = {}) {
  return `${BASE}/export?${buildQS(params)}`
}

// ── Flow View API ───────────────────────────────────────────────────────────

export async function fetchIPPairs(params = {}) {
  return apiFetch(`${BASE}/stats/ip-pairs?${buildQS(params)}`)
}

export async function fetchFlowGraph(params = {}) {
  return apiFetch(`${BASE}/flows/graph?${buildQS(params)}`)
}

export async function fetchZoneMatrix(params = {}) {
  return apiFetch(`${BASE}/flows/zone-matrix?${buildQS(params)}`)
}

export async function fetchHostDetail(params = {}) {
  return apiFetch(`${BASE}/flows/host-detail?${buildQS(params)}`)
}

// ── Saved Views API ─────────────────────────────────────────────────────────

export async function fetchSavedViews() {
  return apiFetch(`${BASE}/views`)
}

export async function createSavedView(name, filters) {
  return apiFetch(`${BASE}/views`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, filters })
  })
}

export async function deleteSavedView(id) {
  return apiFetch(`${BASE}/views/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// ── Threat Map API ──────────────────────────────────────────────────────────

export async function fetchLogsBatch(ids) {
  return apiFetch(`${BASE}/logs/batch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids })
  })
}

export async function fetchThreatGeo(params = {}) {
  return apiFetch(`${BASE}/threats/geo?${buildQS(params)}`)
}

// ── Setup Wizard API ──────────────────────────────────────────────────────────

export async function fetchConfig() {
  return apiFetch(`${BASE}/config`)
}

export async function fetchWANCandidates() {
  return apiFetch(`${BASE}/setup/wan-candidates`)
}

export async function fetchNetworkSegments(wanInterfaces = []) {
  const qs = wanInterfaces.length ? `?wan_interfaces=${wanInterfaces.join(',')}` : ''
  return apiFetch(`${BASE}/setup/network-segments${qs}`)
}

export async function saveSetupConfig(config) {
  return apiFetch(`${BASE}/setup/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
}

export async function fetchInterfaces() {
  return apiFetch(`${BASE}/interfaces`)
}

// ── UniFi Settings API ───────────────────────────────────────────────────────

export async function fetchUniFiSettings() {
  return apiFetch(`${BASE}/settings/unifi`)
}

export async function updateUniFiSettings(settings) {
  return apiFetch(`${BASE}/settings/unifi`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  })
}

export async function testUniFiConnection(params) {
  return apiFetch(`${BASE}/settings/unifi/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
}

export async function dismissUpgradeModal() {
  return apiFetch(`${BASE}/settings/unifi/dismiss-upgrade`, { method: 'POST' })
}

export async function dismissVpnToast() {
  return apiFetch(`${BASE}/settings/unifi/dismiss-vpn-toast`, { method: 'POST' })
}

export async function fetchUniFiNetworkConfig() {
  return apiFetch(`${BASE}/setup/unifi-network-config`)
}

// ── Firewall API ─────────────────────────────────────────────────────────────

export async function fetchFirewallPolicies() {
  return apiFetch(`${BASE}/firewall/policies`)
}

export async function patchFirewallPolicy(policyId, loggingEnabled, origin) {
  return apiFetch(`${BASE}/firewall/policies/${encodeURIComponent(policyId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ loggingEnabled, origin })
  })
}

export async function bulkUpdateFirewallLogging(policies) {
  return apiFetch(`${BASE}/firewall/policies/bulk-logging`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policies })
  })
}

export async function bulkUpdateFirewallLoggingStream(policies, onProgress) {
  const resp = await apiFetchRaw(`${BASE}/firewall/policies/bulk-logging-stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policies })
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.status}`)
  }
  if (!resp.body) throw new Error('Response body is empty, streaming not supported')
  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let finalResult = null

  while (true) {
    const { done, value } = await reader.read()
    if (done) {
      buffer += decoder.decode()
      const trailing = buffer.replace(/^data: /, '').trim()
      if (trailing) {
        try {
          const msg = JSON.parse(trailing)
          if (msg.event === 'complete') finalResult = msg
          else if (msg.event === 'error') throw new Error(msg.detail || 'Bulk update failed')
        } catch (e) { if (!(e instanceof SyntaxError)) throw e }
      }
      break
    }
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n\n')
    buffer = lines.pop()
    for (const chunk of lines) {
      const line = chunk.replace(/^data: /, '').trim()
      if (!line) continue
      try {
        const msg = JSON.parse(line)
        if (msg.event === 'progress') {
          onProgress?.(msg)
        } else if (msg.event === 'complete') {
          finalResult = msg
        } else if (msg.event === 'error') {
          throw new Error(msg.detail || 'Bulk update failed')
        }
      } catch (e) {
        if (!(e instanceof SyntaxError)) throw e
      }
    }
  }
  return finalResult
}

// ── UniFi Device Names (Phase 2) ────────────────────────────────────────────

export async function fetchUniFiStatus() {
  return apiFetch(`${BASE}/unifi/status`)
}

// ── Config Export/Import ─────────────────────────────────────────────────────

export async function exportConfig(includeApiKey = false) {
  return apiFetch(`${BASE}/config/export?include_api_key=${includeApiKey}`)
}

export async function importConfig(config) {
  return apiFetch(`${BASE}/config/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
}

// ── VPN Network Configuration ───────────────────────────────────────────────

export async function saveVpnNetworks(vpnNetworks, vpnLabels = {}) {
  return apiFetch(`${BASE}/config/vpn-networks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vpn_networks: vpnNetworks, vpn_labels: vpnLabels })
  })
}

// ── Retention Configuration ─────────────────────────────────────────────────

export async function fetchRetentionConfig() {
  return apiFetch(`${BASE}/config/retention`)
}

export async function updateRetentionConfig(config) {
  return apiFetch(`${BASE}/config/retention`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
}

// ── MCP Settings ────────────────────────────────────────────────────────────

export async function fetchMcpSettings() {
  return apiFetch(`${BASE}/settings/mcp`)
}

export async function updateMcpSettings(settings) {
  return apiFetch(`${BASE}/settings/mcp`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  })
}

export async function fetchMcpScopes() {
  return apiFetch(`${BASE}/settings/mcp/scopes`)
}

export async function fetchMcpAudit(limit = 200, offset = 0) {
  return apiFetch(`${BASE}/settings/mcp/audit?limit=${limit}&offset=${offset}`)
}

export async function runRetentionCleanup() {
  return apiFetch(`${BASE}/config/retention/cleanup`, { method: 'POST' })
}

// ── UI Settings ─────────────────────────────────────────────────────────

export async function fetchUiSettings() {
  return apiFetch(`${BASE}/settings/ui`)
}

export async function updateUiSettings(settings) {
  return apiFetch(`${BASE}/settings/ui`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  })
}

// ── Database Migration ───────────────────────────────────────────────────────

export async function testMigrationConnection(params) {
  return apiFetch(`${BASE}/migration/test-connection`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
}

export async function startMigration(params) {
  return apiFetch(`${BASE}/migration/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
}

export async function getMigrationStatus() {
  return apiFetch(`${BASE}/migration/status`)
}

export async function checkMigrationEnv() {
  return apiFetch(`${BASE}/migration/check-env`)
}

export async function patchMigrationCompose(params) {
  return apiFetch(`${BASE}/migration/patch-compose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
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

// ── Auth API ────────────────────────────────────────────────────────────────

export async function fetchAuthStatus() {
  // Direct fetch (not apiFetch): this is the bootstrap call that determines
  // whether auth is enabled. A 401 here is not a session expiry — it would
  // mean the public endpoint itself is broken. Must not trigger onAuthExpired.
  // Error includes statusText intentionally — richer than status alone for debugging.
  const resp = await fetch(`${BASE}/auth/status`, { credentials: 'include' })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.statusText || resp.status}`)
  }
  return resp.json()
}

export async function authLogin(username, password) {
  // Bypass apiFetch: login 401 means bad credentials, not an expired session
  const resp = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `Login failed (${resp.status})`)
  }
  return resp.json()
}

export async function authSetup(username, password) {
  return apiFetch(`${BASE}/auth/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
}

export async function authLogout() {
  // Direct fetch (not apiFetch): if the session is already expired, apiFetch
  // would trigger onAuthExpired and throw before the logout completes.
  // Logout should always succeed so the client can clear local state.
  const resp = await fetch(`${BASE}/auth/logout`, { method: 'POST', credentials: 'include' })
  // 401 means session already expired — treat as successful logout
  if (!resp.ok && resp.status !== 401) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `Logout failed (${resp.status})`)
  }
  return resp.json().catch(() => ({}))
}

// Bypasses apiFetch intentionally — /auth/me must work before login
// (checking session) so it cannot use the shared error-handling wrapper.
// Error includes statusText intentionally — richer than status alone for debugging.
// body.detail covers all FastAPI error payloads; body.error is not used by this API.
export async function fetchAuthMe() {
  const resp = await fetch(`${BASE}/auth/me`, { credentials: 'include' })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `API error: ${resp.statusText || resp.status}`)
  }
  return resp.json()
}

export async function authChangePassword(current_password, new_password) {
  return apiFetch(`${BASE}/auth/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password, new_password })
  })
}

export async function updateSessionTtl(hours) {
  return apiFetch(`${BASE}/auth/session-ttl`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hours })
  })
}

export async function fetchProxyToken() {
  return apiFetch(`${BASE}/auth/proxy-token`)
}

// ── Token API ───────────────────────────────────────────────────────────────

export async function fetchApiTokens(clientType) {
  const qs = clientType ? `?client_type=${encodeURIComponent(clientType)}` : ''
  return apiFetch(`${BASE}/tokens${qs}`)
}

export async function createApiToken(payload) {
  return apiFetch(`${BASE}/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
}

export async function revokeApiToken(tokenId) {
  return apiFetch(`${BASE}/tokens/${encodeURIComponent(tokenId)}`, { method: 'DELETE' })
}
