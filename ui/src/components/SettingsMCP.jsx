import { useEffect, useMemo, useState } from 'react'
import {
  fetchMcpSettings, updateMcpSettings,
  fetchMcpScopes, fetchMcpAudit,
} from '../api'
import useApiTokens from '../hooks/useApiTokens'
import CopyButton from './CopyButton'
import TokenCreatedModal from './TokenCreatedModal'
import TokenList from './TokenList'

const TEAL = 'text-teal-500 hover:text-teal-400'

const ClaudeIcon = () => (
  <img src="/claude-ai-symbol.png" alt="Claude" className="w-4 h-4 shrink-0" />
)

const GeminiIcon = () => (
  <img src="/gemini-cli-logo.png" alt="Gemini CLI" className="w-4 h-4 shrink-0" />
)

export default function SettingsMCP() {
  const { tokens, reload: reloadTokens, create: createToken, revoke: revokeToken } = useApiTokens('mcp')
  const [settings, setSettings] = useState(null)
  const [draft, setDraft] = useState(null)
  const [originsText, setOriginsText] = useState('')
  const [scopes, setScopes] = useState([])
  const [saving, setSaving] = useState(false)
  const [auditEntries, setAuditEntries] = useState([])
  const [auditTotal, setAuditTotal] = useState(0)
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditLoaded, setAuditLoaded] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)

  // Per-card inline status
  const [serverStatus, setServerStatus] = useState(null) // { type: 'saved'|'error', text }
  const [tokenStatus, setTokenStatus] = useState(null)   // { type: 'saved'|'error', text }
  const [auditStatus, setAuditStatus] = useState(null)   // { type: 'error', text }

  const [tokenName, setTokenName] = useState('')
  const [tokenScopes, setTokenScopes] = useState(new Set())
  const [creating, setCreating] = useState(false)
  const [createdToken, setCreatedToken] = useState(null)
  const [showTokenModal, setShowTokenModal] = useState(false)

  const [lastCreatedToken, setLastCreatedToken] = useState(null)
  const [revoking, setRevoking] = useState(null) // token ID being revoked

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
      const [settingsData, scopesData, tokenErr] = await Promise.all([
        fetchMcpSettings(),
        fetchMcpScopes(),
        reloadTokens(),
      ])
      setSettings(settingsData)
      setDraft(settingsData)
      setOriginsText((settingsData.allowed_origins || []).join('\n'))
      setScopes(scopesData.scopes || [])
      if (tokenErr) setTokenStatus({ type: 'error', text: tokenErr })
    } catch (e) {
      setServerStatus({ type: 'error', text: e.message })
    }
  }

  async function handleSave() {
    if (!draft) return
    setSaving(true)
    setServerStatus(null)
    try {
      const allowedOrigins = originsText
        .split(/\r?\n|,/)
        .map(v => v.trim())
        .filter(Boolean)
      const payload = { ...draft, allowed_origins: allowedOrigins }
      await updateMcpSettings(payload)
      setSettings(payload)
      setDraft(payload)
      setServerStatus({ type: 'saved', text: 'Settings saved' })
    } catch (e) {
      setServerStatus({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  async function savePartial(partial) {
    setSaving(true)
    setServerStatus(null)
    try {
      await updateMcpSettings(partial)
      setSettings(prev => ({ ...prev, ...partial }))
      setDraft(prev => ({ ...prev, ...partial }))
      setServerStatus({ type: 'saved', text: 'Settings saved' })
    } catch (e) {
      setServerStatus({ type: 'error', text: e.message })
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
      setTokenStatus({ type: 'error', text: 'Select at least one scope' })
      return
    }
    setCreating(true)
    setTokenStatus(null)
    try {
      // client_type is required in the create payload — useApiTokens('mcp') only
      // filters the list query, it does not inject client_type into creates.
      const result = await createToken({
        name: tokenName.trim() || 'MCP Token',
        scopes: Array.from(tokenScopes),
        client_type: 'mcp',
      })
      setCreatedToken(result.token)
      setLastCreatedToken(result.token)
      setShowTokenModal(true)
      setTokenName('')
      setTokenScopes(new Set())
      setTokenStatus({ type: 'saved', text: 'Token created' })
    } catch (e) {
      setTokenStatus({ type: 'error', text: e.message })
    } finally {
      setCreating(false)
    }
  }

  async function handleRevoke(tokenId) {
    if (!tokenId) return
    // Native confirm() is appropriate here — project has no ConfirmModal component,
    // and this is a destructive settings action behind admin auth.
    if (!window.confirm('Revoke this token? This cannot be undone.')) return
    setTokenStatus(null)
    setRevoking(tokenId)
    try {
      await revokeToken(tokenId)
      setTokenStatus({ type: 'saved', text: 'Token revoked' })
    } catch (e) {
      setTokenStatus({ type: 'error', text: e.message })
    } finally {
      setRevoking(null)
    }
  }

  async function loadAudit() {
    setAuditLoading(true)
    setAuditStatus(null)
    try {
      const data = await fetchMcpAudit(200, 0)
      setAuditEntries(data.entries || [])
      setAuditTotal(data.total || 0)
      setAuditLoaded(true)
    } catch (e) {
      setAuditStatus({ type: 'error', text: e.message })
    } finally {
      setAuditLoading(false)
    }
  }

  if (!draft) {
    return <div className="text-sm text-gray-400">Loading MCP settings...</div>
  }

  return (
    <div className="space-y-8">
      {/* ── MCP Server ─────────────────────────────────────────── */}
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          MCP Server
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-base text-gray-200 font-medium">Enable MCP</p>
                <p className="text-sm text-gray-500">Expose MCP tools for AI agents.</p>
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
                className={`px-3 py-1 rounded text-sm font-semibold border transition-colors ${
                  draft.enabled
                    ? 'bg-green-500/10 text-green-300 border-green-500/40'
                    : 'bg-black text-gray-400 border-gray-700'
                }`}
              >
                {draft.enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-base text-gray-200 font-medium">Audit Trail</p>
                <p className="text-sm text-gray-500">Store tool calls with full request params.</p>
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
                className={`px-3 py-1 rounded text-sm font-semibold border transition-colors ${
                  draft.audit_enabled
                    ? 'bg-green-500/10 text-green-300 border-green-500/40'
                    : 'bg-black text-gray-400 border-gray-700'
                }`}
              >
                {draft.audit_enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            <div className="flex items-center justify-between">
              <label className="text-base text-gray-200 font-medium">Audit retention</label>
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
                  className="w-16 px-2 py-1 rounded bg-black border border-gray-600 font-mono text-sm text-gray-200 text-right focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
                />
                <span className="text-sm text-gray-500">days</span>
              </div>
            </div>

            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="text-sm text-gray-400 hover:text-gray-300 flex items-center gap-1"
            >
              <span>{showAdvanced ? '\u25BE' : '\u25B8'}</span> Advanced
            </button>

            {showAdvanced && (
              <div className="space-y-3 pl-3 border-l border-gray-700">
                <div>
                  <label className="text-base text-gray-200 font-medium">Allowed Origins (Advanced)</label>
                  <p className="text-sm text-gray-500 mb-2">
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
                    className="w-full px-3 py-2 rounded bg-black border border-gray-700 text-sm text-gray-200 font-mono focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
                  />
                </div>
              </div>
            )}
          </div>

          <div className="border-t border-gray-800" />

          <div className="px-5 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <p className="text-sm text-gray-500">MCP endpoint: /api/mcp</p>
              {serverStatus?.type === 'saved' && <span className="text-sm text-emerald-400">{serverStatus.text}</span>}
              {serverStatus?.type === 'error' && <span className="text-sm text-red-400">{serverStatus.text}</span>}
            </div>
            <button
              onClick={handleSave}
              disabled={!canSave || saving}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
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
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          MCP Tokens
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-4">
            <p className="text-sm text-gray-400">
              Create tokens for MCP clients. Tokens authenticate agent requests and are shown only once on creation.
            </p>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={tokenName}
                  onChange={e => setTokenName(e.target.value)}
                  placeholder="Token name (optional)"
                  className="flex-1 px-3 py-2 rounded bg-black border border-gray-700 text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
                />
                <button
                  onClick={handleCreateToken}
                  disabled={creating}
                  className="px-3 py-2 rounded text-sm font-medium bg-teal-600 hover:bg-teal-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {creating ? 'Creating...' : 'Create token'}
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2">
                {scopes.map(scope => (
                  <label key={scope.id} className="flex items-start gap-2 text-sm text-gray-300">
                    <input
                      type="checkbox"
                      checked={tokenScopes.has(scope.id)}
                      onChange={() => toggleScope(scope.id)}
                      className="mt-0.5 ui-checkbox"
                    />
                    <span>
                      <span className="text-gray-200 font-medium">{scope.description}</span>
                      <span className="block text-sm text-gray-500 font-mono">{scope.id}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          <div className="border-t border-gray-800" />

          <div className="p-5">
            <div className="flex items-center justify-between mb-3">
              <p className="text-base text-gray-200 font-medium">Active tokens</p>
              {tokenStatus && (
                <span className={`text-sm ${tokenStatus.type === 'saved' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {tokenStatus.text}
                </span>
              )}
            </div>
            <TokenList
              tokens={tokens}
              onRevoke={(id) => handleRevoke(id)} // wrapper intentionally drops 2nd arg (name) from TokenList callback
              revokingId={revoking}
              formatPrefix={t => {
                if (!t.token_prefix) return t.client_type || 'mcp'
                return `${t.token_prefix.startsWith('uli-mcp') ? '' : 'uli-mcp_'}${t.token_prefix}…`
              }}
            />
          </div>
        </div>
      </section>

      {/* ── Client Setup Instructions ──────────────────────────── */}
      <section>
        <details className="group">
          <summary className="flex items-center gap-1 cursor-pointer text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider list-none">
            <span className="transition-transform group-open:rotate-90">&#x25B8;</span> Client Setup Instructions
          </summary>
          <div className="rounded-lg border border-gray-700 bg-gray-950">
            {/* Token status banner */}
            {lastCreatedToken ? (
              <div className="px-5 pt-4 pb-0">
                <div className="flex items-start gap-2 text-sm px-3 py-2 rounded border border-green-500/30 bg-green-500/10 text-green-300">
                  <svg className="w-3.5 h-3.5 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.06l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
                  </svg>
                  <span>Your token is pre-filled in all snippets below. They are ready to copy and use.</span>
                </div>
              </div>
            ) : (
              <div className="px-5 pt-4 pb-0">
                <div className="flex items-center gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                  <svg className="w-4 h-4 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <p className="text-sm text-yellow-400/90">Snippets contain <span className="font-mono font-semibold">&lt;YOUR_TOKEN&gt;</span> as placeholder. Create a token in the MCP Tokens section above, then return here — your token will be auto-filled.</p>
                </div>
              </div>
            )}

            {/* Server URL + Transport */}
            <div className="p-5 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm text-gray-400">Server URL</span>
                <div className="flex items-center gap-1">
                  <span className="text-sm text-gray-200 font-mono bg-black border border-gray-800 rounded px-2 py-1 break-all">
                    {mcpUrl}
                  </span>
                  <CopyButton text={mcpUrl} color={TEAL} />
                </div>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm text-gray-400">Transport</span>
                <span className="text-sm text-gray-200 font-mono">Streamable HTTP</span>
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Claude Desktop */}
            <div className="p-5 space-y-3">
              <div className="flex items-center gap-2">
                <ClaudeIcon />
                <p className="text-base font-semibold text-gray-200">Claude Desktop</p>
              </div>
              <div className="text-sm text-gray-500 space-y-1">
                <p>Config file location:</p>
                <p>macOS: <span className="font-mono">~/Library/Application Support/Claude/claude_desktop_config.json</span></p>
                <p>Windows: <span className="font-mono">%APPDATA%\Claude\claude_desktop_config.json</span></p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-1.5">
                  <span className="text-sm text-gray-300">Copy full config</span>
                  <CopyButton text={fullConfig} color={TEAL} className="ml-0" />
                  <span className="text-gray-600 text-sm">·</span>
                  <details className="inline">
                    <summary className="text-sm text-teal-400 hover:text-teal-300 cursor-pointer">Show example</summary>
                    <pre className="mt-2 text-sm text-gray-300 bg-black border border-gray-800 rounded p-3 overflow-x-auto whitespace-pre font-mono">
                      {fullConfig}
                    </pre>
                  </details>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="text-sm text-gray-300">Copy server entry</span>
                  <CopyButton text={serverEntry} color={TEAL} className="ml-0" />
                  <span className="text-gray-600 text-sm">·</span>
                  <details className="inline">
                    <summary className="text-sm text-teal-400 hover:text-teal-300 cursor-pointer">Show example</summary>
                    <pre className="mt-2 text-sm text-gray-300 bg-black border border-gray-800 rounded p-3 overflow-x-auto whitespace-pre font-mono">
                      {serverEntry}
                    </pre>
                    <p className="mt-1 text-sm text-gray-500">Paste inside the <span className="font-mono font-semibold">mcpServers</span> block, after the last existing entry.</p>
                  </details>
                </div>
              </div>

              <div className="flex items-start gap-2 bg-blue-500/10 border border-blue-500/30 rounded px-3 py-2">
                <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
                </svg>
                <p className="text-sm text-blue-400">
                  Requires <span className="font-mono">npx</span> (Node.js). Restart Claude Desktop after editing.
                </p>
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Claude Code */}
            <div className="p-5 space-y-3">
              <div className="flex items-center gap-2">
                <ClaudeIcon />
                <p className="text-base font-semibold text-gray-200">Claude Code</p>
              </div>

              <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                <pre className="text-sm text-gray-300 font-mono whitespace-pre">{cliCommand}</pre>
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="text-sm text-gray-300">Copy CLI command</span>
                <CopyButton text={cliCommand} color={TEAL} className="ml-0" />
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Gemini CLI */}
            <div className="p-5 space-y-3">
              <div className="flex items-center gap-2">
                <GeminiIcon />
                <p className="text-base font-semibold text-gray-200">Gemini CLI</p>
              </div>

              <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                <pre className="text-sm text-gray-300 font-mono whitespace-pre">{geminiCommand}</pre>
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="text-sm text-gray-300">Copy CLI command</span>
                <CopyButton text={geminiCommand} color={TEAL} className="ml-0" />
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Other MCP clients */}
            <div className="px-5 py-3">
              <p className="text-sm text-gray-500">
                Any desktop MCP client that supports Streamable HTTP transport can connect using the server URL and bearer token above.
              </p>
            </div>
          </div>
        </details>
      </section>

      {/* ── MCP Audit Log ──────────────────────────────────────── */}
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          MCP Audit Log
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <p className="text-sm text-gray-500">
                {auditLoaded
                  ? `Showing latest ${auditEntries.length} of ${auditTotal}`
                  : 'Audit log loads on demand'}
              </p>
              {auditStatus?.type === 'error' && (
                <span className="text-sm text-red-400">{auditStatus.text}</span>
              )}
            </div>
            <button
              onClick={loadAudit}
              disabled={auditLoading}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                auditLoading
                  ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  : 'border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white'
              }`}
            >
              {auditLoading ? 'Loading...' : (auditLoaded ? 'Refresh' : 'View Audit Log')}
            </button>
          </div>

          {auditLoaded && auditEntries.length === 0 && (
            <p className="text-sm text-gray-600">No audit entries yet.</p>
          )}

          {auditLoaded && (
            <div className="space-y-2">
              {auditEntries.map(entry => (
                <details key={entry.id} className="border border-gray-800 rounded bg-black/60 px-3 py-2">
                  <summary className="cursor-pointer list-none">
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-base text-gray-200 font-medium truncate">
                          {entry.tool_name}
                          {entry.scope && (
                            <span className="text-sm text-gray-500 font-mono ml-2">{entry.scope}</span>
                          )}
                        </p>
                        <p className="text-sm text-gray-500">
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
                      <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded px-2 py-1">
                        {entry.error}
                      </div>
                    )}
                    <div>
                      <p className="text-sm text-gray-500 mb-1">Request Params</p>
                      <pre className="text-sm text-gray-200 bg-gray-950 border border-gray-800 rounded p-2 overflow-auto">
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

      {showTokenModal && (
        <TokenCreatedModal
          token={createdToken}
          title="MCP Token Created"
          onClose={closeTokenModal}
        />
      )}
    </div>
  )
}
