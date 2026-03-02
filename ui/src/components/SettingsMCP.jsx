import { useEffect, useMemo, useState } from 'react'
import {
  fetchMcpSettings, updateMcpSettings,
  fetchMcpScopes, fetchMcpTokens, fetchMcpAudit,
  createMcpToken, revokeMcpToken
} from '../api'
import CopyButton from './CopyButton'

const TEAL = 'text-teal-500 hover:text-teal-400'

const ClaudeIcon = () => (
  <img src="/claude-ai-symbol.png" alt="Claude" className="w-4 h-4 shrink-0" />
)

const GeminiIcon = () => (
  <img src="/gemini-cli-logo.png" alt="Gemini CLI" className="w-4 h-4 shrink-0" />
)

export default function SettingsMCP() {
  const [settings, setSettings] = useState(null)
  const [draft, setDraft] = useState(null)
  const [originsText, setOriginsText] = useState('')
  const [scopes, setScopes] = useState([])
  const [tokens, setTokens] = useState([])
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState(null)
  const [auditEntries, setAuditEntries] = useState([])
  const [auditTotal, setAuditTotal] = useState(0)
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditLoaded, setAuditLoaded] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)

  const [tokenName, setTokenName] = useState('')
  const [tokenScopes, setTokenScopes] = useState(new Set())
  const [creating, setCreating] = useState(false)
  const [createdToken, setCreatedToken] = useState(null)
  const [showTokenModal, setShowTokenModal] = useState(false)

  const [lastCreatedToken, setLastCreatedToken] = useState(null)

  const mcpUrl = typeof window !== 'undefined'
    ? `${window.location.origin}/api/mcp`
    : '/api/mcp'

  const tokenValue = lastCreatedToken || '<YOUR_TOKEN>'

  const fullConfig = JSON.stringify({
    mcpServers: {
      'unifi-log-insight': {
        command: 'npx',
        args: ['-y', 'mcp-remote', mcpUrl, '--header', 'Authorization:${AUTH_HEADER}'],
        env: { AUTH_HEADER: `Bearer ${tokenValue}` },
      },
    },
  }, null, 2)

  const serverEntry = `,"unifi-log-insight": ${JSON.stringify({
    command: 'npx',
    args: ['-y', 'mcp-remote', mcpUrl, '--header', 'Authorization:${AUTH_HEADER}'],
    env: { AUTH_HEADER: `Bearer ${tokenValue}` },
  }, null, 2)}`

  const cliCommand = `claude mcp add unifi-log-insight -- npx mcp-remote ${mcpUrl} --header "Authorization: Bearer ${tokenValue}"`

  const geminiCommand = `gemini mcp add --transport http --header "Authorization: Bearer ${tokenValue}" unifi-log-insight ${mcpUrl}`

  const canSave = useMemo(() => {
    if (!settings || !draft) return false
    return JSON.stringify(settings) !== JSON.stringify(draft)
  }, [settings, draft])

  useEffect(() => {
    reloadAll()
  }, [])

  useEffect(() => {
    if (!showTokenModal) return
    const onKey = e => { if (e.key === 'Escape') closeTokenModal() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showTokenModal])

  function closeTokenModal() {
    setShowTokenModal(false)
    setCreatedToken(null)
  }

  async function reloadAll() {
    try {
      const [settingsData, scopesData, tokensData] = await Promise.all([
        fetchMcpSettings(),
        fetchMcpScopes(),
        fetchMcpTokens()
      ])
      setSettings(settingsData)
      setDraft(settingsData)
      setOriginsText((settingsData.allowed_origins || []).join('\n'))
      setScopes(scopesData.scopes || [])
      setTokens(tokensData.tokens || [])
    } catch (e) {
      setMessage({ type: 'error', text: e.message })
    }
  }

  async function handleSave() {
    if (!draft) return
    setSaving(true)
    setMessage(null)
    try {
      const allowedOrigins = originsText
        .split(/\r?\n|,/)
        .map(v => v.trim())
        .filter(Boolean)
      const payload = { ...draft, allowed_origins: allowedOrigins }
      await updateMcpSettings(payload)
      setSettings(payload)
      setDraft(payload)
      setMessage({ type: 'success', text: 'MCP settings saved' })
      setTimeout(() => setMessage(null), 3000)
    } catch (e) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  async function savePartial(partial) {
    setSaving(true)
    setMessage(null)
    try {
      await updateMcpSettings(partial)
      setSettings(prev => ({ ...prev, ...partial }))
      setDraft(prev => ({ ...prev, ...partial }))
      setMessage({ type: 'success', text: 'MCP settings saved' })
      setTimeout(() => setMessage(null), 3000)
    } catch (e) {
      setMessage({ type: 'error', text: e.message })
      throw e
    } finally {
      setSaving(false)
    }
  }

  function toggleScope(id) {
    setTokenScopes(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function handleCreateToken() {
    if (tokenScopes.size === 0) {
      setMessage({ type: 'error', text: 'Select at least one scope' })
      return
    }
    setCreating(true)
    setMessage(null)
    try {
      const result = await createMcpToken({
        name: tokenName.trim() || 'MCP Token',
        scopes: Array.from(tokenScopes),
      })
      setCreatedToken(result.token)
      setLastCreatedToken(result.token)
      setShowTokenModal(true)
      setTokenName('')
      setTokenScopes(new Set())
      const refreshed = await fetchMcpTokens()
      setTokens(refreshed.tokens || [])
      setMessage({ type: 'success', text: 'Token created' })
      setTimeout(() => setMessage(null), 3000)
    } catch (e) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setCreating(false)
    }
  }

  async function handleRevoke(tokenId) {
    if (!tokenId) return
    if (!confirm('Revoke this token? This cannot be undone.')) return
    setMessage(null)
    try {
      await revokeMcpToken(tokenId)
      const refreshed = await fetchMcpTokens()
      setTokens(refreshed.tokens || [])
      setMessage({ type: 'success', text: 'Token revoked' })
      setTimeout(() => setMessage(null), 3000)
    } catch (e) {
      setMessage({ type: 'error', text: e.message })
    }
  }

  async function loadAudit() {
    setAuditLoading(true)
    try {
      const data = await fetchMcpAudit(200, 0)
      setAuditEntries(data.entries || [])
      setAuditTotal(data.total || 0)
      setAuditLoaded(true)
    } catch (e) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setAuditLoading(false)
    }
  }

  if (!draft) {
    return <div className="text-sm text-gray-400">Loading MCP settings...</div>
  }

  return (
    <div className="space-y-8">
      {message && (
        <div className={`text-xs px-3 py-2 rounded border ${
          message.type === 'error'
            ? 'border-red-500/40 text-red-300 bg-red-500/10'
            : 'border-green-500/40 text-green-300 bg-green-500/10'
        }`}>
          {message.text}
        </div>
      )}

      {/* ── MCP Server ─────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          MCP Server
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-200 font-medium">Enable MCP</p>
                <p className="text-xs text-gray-500">Expose MCP tools for AI agents.</p>
              </div>
              <button
                onClick={() => {
                  const prev = draft.enabled
                  const next = !prev
                  setDraft(d => ({ ...d, enabled: next }))
                  savePartial({ enabled: next }).catch(() => {
                    setDraft(d => ({ ...d, enabled: prev }))
                  })
                }}
                className={`px-3 py-1 rounded text-xs font-semibold border transition-colors ${
                  draft.enabled
                    ? 'bg-green-500/10 text-green-300 border-green-500/40'
                    : 'bg-gray-900 text-gray-400 border-gray-700'
                }`}
              >
                {draft.enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-200 font-medium">Audit Trail</p>
                <p className="text-xs text-gray-500">Store tool calls with full request params.</p>
              </div>
              <button
                onClick={() => {
                  const prev = draft.audit_enabled
                  const next = !prev
                  setDraft(d => ({ ...d, audit_enabled: next }))
                  savePartial({ audit_enabled: next }).catch(() => {
                    setDraft(d => ({ ...d, audit_enabled: prev }))
                  })
                }}
                className={`px-3 py-1 rounded text-xs font-semibold border transition-colors ${
                  draft.audit_enabled
                    ? 'bg-green-500/10 text-green-300 border-green-500/40'
                    : 'bg-gray-900 text-gray-400 border-gray-700'
                }`}
              >
                {draft.audit_enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            <div className="flex items-center justify-between">
              <label className="text-sm text-gray-200 font-medium">Audit retention</label>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={draft.audit_retention_days ?? 10}
                  onChange={e => setDraft(prev => ({
                    ...prev,
                    audit_retention_days: Math.max(1, Math.min(365, parseInt(e.target.value) || 1))
                  }))}
                  className="w-16 px-2 py-1 rounded bg-gray-900 border border-gray-600 font-mono text-xs text-gray-200 text-right focus:border-blue-500 focus:outline-none"
                />
                <span className="text-xs text-gray-500">days</span>
              </div>
            </div>

            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="text-xs text-gray-400 hover:text-gray-300 flex items-center gap-1"
            >
              <span>{showAdvanced ? '\u25BE' : '\u25B8'}</span> Advanced
            </button>

            {showAdvanced && (
              <div className="space-y-3 pl-3 border-l border-gray-700">
                <div>
                  <label className="text-sm text-gray-200 font-medium">Allowed Origins (Advanced)</label>
                  <p className="text-xs text-gray-500 mb-2">
                    Only needed for browser-based MCP clients. Most desktop agents do not send an
                    <span className="font-mono"> Origin</span> header. Leave empty unless your client
                    provides an exact origin to allow.
                  </p>
                  <textarea
                    rows={3}
                    value={originsText}
                    onChange={e => {
                      const value = e.target.value
                      setOriginsText(value)
                      const parsed = value
                        .split(/\r?\n|,/)
                        .map(v => v.trim())
                        .filter(Boolean)
                      setDraft(prev => ({ ...prev, allowed_origins: parsed }))
                    }}
                    placeholder="https://your-client.example.com"
                    className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-700 text-xs text-gray-200 font-mono focus:border-blue-500 focus:outline-none"
                  />
                </div>
              </div>
            )}
          </div>

          <div className="border-t border-gray-800" />

          <div className="px-5 py-3 flex items-center justify-between">
            <p className="text-xs text-gray-500">MCP endpoint: /api/mcp</p>
            <button
              onClick={handleSave}
              disabled={!canSave || saving}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                canSave
                  ? 'bg-teal-600 hover:bg-teal-500 text-white'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </section>

      {/* ── MCP Tokens ─────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          MCP Tokens
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-4">
            <p className="text-xs text-gray-500">
              Create tokens for MCP clients. Tokens authenticate agent requests and are shown only once on creation.
            </p>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={tokenName}
                  onChange={e => setTokenName(e.target.value)}
                  placeholder="Token name (optional)"
                  className="flex-1 px-3 py-2 rounded bg-gray-900 border border-gray-700 text-xs text-gray-200 focus:border-blue-500 focus:outline-none"
                />
                <button
                  onClick={handleCreateToken}
                  disabled={creating}
                  className="px-3 py-2 rounded text-xs font-medium bg-teal-600 hover:bg-teal-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {creating ? 'Creating...' : 'Create token'}
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2">
                {scopes.map(scope => (
                  <label key={scope.id} className="flex items-start gap-2 text-xs text-gray-300">
                    <input
                      type="checkbox"
                      checked={tokenScopes.has(scope.id)}
                      onChange={() => toggleScope(scope.id)}
                      className="mt-0.5 ui-checkbox"
                    />
                    <span>
                      <span className="text-gray-200 font-medium">{scope.description}</span>
                      <span className="block text-gray-500 font-mono">{scope.id}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          <div className="border-t border-gray-800" />

          <div className="p-5">
            <p className="text-xs text-gray-500 mb-3">Active tokens</p>
            <div className="space-y-2">
              {tokens.length === 0 && (
                <p className="text-xs text-gray-600">No tokens yet.</p>
              )}
              {tokens.map(token => (
                <div
                  key={token.id}
                  className="flex items-center justify-between gap-3 px-3 py-2 rounded border border-gray-800 bg-gray-900/60"
                >
                  <div className="min-w-0">
                    <p className="text-sm text-gray-200 font-medium truncate">{token.name}</p>
                    <p className="text-[11px] text-gray-500 font-mono truncate">
                      {token.token_prefix?.startsWith('uli-mcp') ? '' : 'uli-mcp_'}{token.token_prefix}… · {token.scopes?.join(', ') || 'no scopes'}
                    </p>
                    <p className="text-[11px] text-gray-600">
                      Created {token.created_at ? new Date(token.created_at).toLocaleString() : 'unknown'}
                      {token.last_used_at && ` · Last used ${new Date(token.last_used_at).toLocaleString()}`}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs uppercase font-semibold px-2 py-0.5 rounded ${
                      token.disabled ? 'bg-gray-700 text-gray-300' : 'bg-green-500/10 text-green-300'
                    }`}>
                      {token.disabled ? 'Disabled' : 'Active'}
                    </span>
                    {!token.disabled && (
                      <button
                        onClick={() => handleRevoke(token.id)}
                        className="px-2 py-1 text-[11px] font-semibold rounded bg-teal-600 hover:bg-teal-500 text-white transition-colors"
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── Client Setup Instructions ──────────────────────────── */}
      <section>
        <details className="group">
          <summary className="flex items-center gap-1 cursor-pointer text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider list-none">
            <span className="transition-transform group-open:rotate-90">&#x25B8;</span> Client Setup Instructions
          </summary>
          <div className="rounded-lg border border-gray-700 bg-gray-950">
            {/* Token status banner */}
            {lastCreatedToken ? (
              <div className="px-5 pt-4 pb-0">
                <div className="flex items-start gap-2 text-[11px] px-3 py-2 rounded border border-green-500/30 bg-green-500/10 text-green-300">
                  <svg className="w-3.5 h-3.5 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.06l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
                  </svg>
                  <span>Your token is pre-filled in all snippets below. They are ready to copy and use.</span>
                </div>
              </div>
            ) : (
              <div className="px-5 pt-4 pb-0">
                <div className="flex items-start gap-2 text-[11px] px-3 py-2 rounded border border-amber-500/30 bg-amber-500/10 text-amber-400">
                  <svg className="w-3.5 h-3.5 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <span>Snippets contain <span className="font-mono font-semibold">&lt;YOUR_TOKEN&gt;</span> as placeholder. Create a token in the MCP Tokens section above, then return here — your token will be auto-filled.</span>
                </div>
              </div>
            )}

            {/* Server URL + Transport */}
            <div className="p-5 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs text-gray-400">Server URL</span>
                <div className="flex items-center gap-1">
                  <span className="text-xs text-gray-200 font-mono bg-gray-900 border border-gray-800 rounded px-2 py-1 break-all">
                    {mcpUrl}
                  </span>
                  <CopyButton text={mcpUrl} color={TEAL} />
                </div>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs text-gray-400">Transport</span>
                <span className="text-xs text-gray-200 font-mono">Streamable HTTP</span>
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Claude Desktop */}
            <div className="p-5 space-y-3">
              <div className="flex items-center gap-2">
                <ClaudeIcon />
                <p className="text-xs font-semibold text-gray-200">Claude Desktop</p>
              </div>
              <p className="text-[11px] text-gray-500">
                Config file location — macOS: <span className="font-mono">~/Library/Application Support/Claude/claude_desktop_config.json</span>{' '}
                Windows: <span className="font-mono">%APPDATA%\Claude\claude_desktop_config.json</span>
              </p>

              <div className="space-y-2">
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] text-gray-300">Copy full config</span>
                  <CopyButton text={fullConfig} color={TEAL} className="ml-0" />
                  <span className="text-gray-600 text-[11px]">·</span>
                  <details className="inline">
                    <summary className="text-[11px] text-teal-400 hover:text-teal-300 cursor-pointer">Show example</summary>
                    <pre className="mt-2 text-[11px] text-gray-300 bg-gray-900 border border-gray-800 rounded p-3 overflow-x-auto whitespace-pre font-mono">
                      {fullConfig}
                    </pre>
                  </details>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] text-gray-300">Copy server entry</span>
                  <CopyButton text={serverEntry} color={TEAL} className="ml-0" />
                  <span className="text-gray-600 text-[11px]">·</span>
                  <details className="inline">
                    <summary className="text-[11px] text-teal-400 hover:text-teal-300 cursor-pointer">Show example</summary>
                    <pre className="mt-2 text-[11px] text-gray-300 bg-gray-900 border border-gray-800 rounded p-3 overflow-x-auto whitespace-pre font-mono">
                      {serverEntry}
                    </pre>
                    <p className="mt-1 text-[11px] text-gray-500">Paste inside the <span className="font-mono font-semibold">mcpServers</span> block, after the last existing entry.</p>
                  </details>
                </div>
              </div>

              <div className="flex items-start gap-2 bg-blue-500/10 border border-blue-500/30 rounded px-3 py-2">
                <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
                </svg>
                <p className="text-xs text-blue-400">
                  Requires <span className="font-mono">npx</span> (Node.js). Restart Claude Desktop after editing.
                </p>
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Claude Code */}
            <div className="p-5 space-y-3">
              <div className="flex items-center gap-2">
                <ClaudeIcon />
                <p className="text-xs font-semibold text-gray-200">Claude Code</p>
              </div>

              <div className="rounded bg-gray-900 border border-gray-800 p-3 overflow-x-auto">
                <pre className="text-[11px] text-gray-300 font-mono whitespace-pre">{cliCommand}</pre>
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="text-[11px] text-gray-300">Copy CLI command</span>
                <CopyButton text={cliCommand} color={TEAL} className="ml-0" />
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Gemini CLI */}
            <div className="p-5 space-y-3">
              <div className="flex items-center gap-2">
                <GeminiIcon />
                <p className="text-xs font-semibold text-gray-200">Gemini CLI</p>
              </div>

              <div className="rounded bg-gray-900 border border-gray-800 p-3 overflow-x-auto">
                <pre className="text-[11px] text-gray-300 font-mono whitespace-pre">{geminiCommand}</pre>
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="text-[11px] text-gray-300">Copy CLI command</span>
                <CopyButton text={geminiCommand} color={TEAL} className="ml-0" />
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Other MCP clients */}
            <div className="px-5 py-3">
              <p className="text-[11px] text-gray-500">
                Any desktop MCP client that supports Streamable HTTP transport can connect using the server URL and bearer token above.
              </p>
            </div>
          </div>
        </details>
      </section>

      {/* ── MCP Audit Log ──────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          MCP Audit Log
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-gray-500">
              {auditLoaded
                ? `Showing latest ${auditEntries.length} of ${auditTotal}`
                : 'Audit log loads on demand'}
            </p>
            <button
              onClick={loadAudit}
              disabled={auditLoading}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                auditLoading
                  ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  : 'border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white'
              }`}
            >
              {auditLoading ? 'Loading...' : (auditLoaded ? 'Refresh' : 'View Audit Log')}
            </button>
          </div>

          {auditLoaded && auditEntries.length === 0 && (
            <p className="text-xs text-gray-600">No audit entries yet.</p>
          )}

          {auditLoaded && (
            <div className="space-y-2">
              {auditEntries.map(entry => (
                <details key={entry.id} className="border border-gray-800 rounded bg-gray-900/60 px-3 py-2">
                  <summary className="cursor-pointer list-none">
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-sm text-gray-200 font-medium truncate">
                          {entry.tool_name}
                          {entry.scope && (
                            <span className="text-[11px] text-gray-500 font-mono ml-2">{entry.scope}</span>
                          )}
                        </p>
                        <p className="text-[11px] text-gray-500">
                          {entry.created_at ? new Date(entry.created_at).toLocaleString() : 'unknown time'}
                          {entry.token_name && ` · ${entry.token_name}`}
                          {entry.token_prefix && ` (${entry.token_prefix}…)`}
                        </p>
                      </div>
                      <span className={`text-xs uppercase font-semibold px-2 py-0.5 rounded ${
                        entry.success ? 'bg-green-500/10 text-green-300' : 'bg-red-500/10 text-red-300'
                      }`}>
                        {entry.success ? 'Success' : 'Error'}
                      </span>
                    </div>
                  </summary>
                  <div className="mt-2 space-y-2">
                    {entry.error && (
                      <div className="text-xs text-red-300 bg-red-500/10 border border-red-500/30 rounded px-2 py-1">
                        {entry.error}
                      </div>
                    )}
                    <div>
                      <p className="text-[11px] text-gray-500 mb-1">Request Params</p>
                      <pre className="text-[11px] text-gray-200 bg-gray-950 border border-gray-800 rounded p-2 overflow-auto">
                        {JSON.stringify(entry.params || {}, null, 2)}
                      </pre>
                    </div>
                  </div>
                </details>
              ))}
            </div>
          )}
        </div>
      </section>

      {showTokenModal && createdToken && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={closeTokenModal}>
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="mcp-token-title"
            className="bg-gray-950 border border-gray-700 rounded-lg shadow-xl max-w-lg w-full mx-4"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
              <span id="mcp-token-title" className="text-sm font-semibold text-gray-200">
                MCP Token Created
              </span>
              <button onClick={closeTokenModal} className="text-gray-400 hover:text-gray-200 text-lg leading-none">
                &times;
              </button>
            </div>
            <div className="px-4 py-4 space-y-3">
              <p className="text-xs text-gray-400">
                This token is shown only once. Copy it now and store it securely.
              </p>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={createdToken}
                  className="flex-1 px-3 py-2 rounded bg-gray-900 border border-gray-700 text-xs text-gray-200 font-mono"
                />
                <CopyButton text={createdToken} color={TEAL} />
              </div>
            </div>
            <div className="px-4 py-3 border-t border-gray-700 flex justify-end">
              <button
                onClick={closeTokenModal}
                className="px-3 py-1.5 rounded text-xs font-medium bg-teal-600 hover:bg-teal-500 text-white transition-colors"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
