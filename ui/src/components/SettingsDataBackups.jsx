import { useState, useEffect, useRef } from 'react'
import {
  fetchRetentionConfig, updateRetentionConfig, runRetentionCleanup,
  exportConfig, importConfig,
  testMigrationConnection, startMigration, getMigrationStatus,
  patchMigrationCompose
} from '../api'
import CopyButton from './CopyButton'
import InfoTooltip from './InfoTooltip'

const RETENTION_PRESETS = [30, 60, 90, 120, 180, 365]
const DISK_CRITICAL_BYTES = 512 * 1024 * 1024       // 512 MB
const DISK_WARNING_BYTES  = 2 * 1024 * 1024 * 1024  // 2 GB
const EXTERNAL_DB_WIKI_URL = 'https://github.com/jmasarweh/unifi-log-insight/wiki/External-PostgreSQL-Migration-Guide'

function formatBytes(bytes) {
  if (bytes == null) return '—'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
}

// ── Step pill for migration wizard ──────────────────────────────────────────

const WIZARD_STEPS = ['Configure', 'Migration', 'Required Manual Tasks']

function StepPill({ index, label, current }) {
  const done = index < current
  const active = index === current
  return (
    <div className="flex items-center gap-1.5">
      <span className={`w-5 h-5 rounded-full text-sm font-bold flex items-center justify-center shrink-0 ${
        done ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
        : active ? 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
        : 'bg-gray-800 text-gray-600 border border-gray-700'
      }`}>{done ? '\u2713' : index + 1}</span>
      <span className={`text-sm ${active ? 'text-gray-200' : done ? 'text-gray-400' : 'text-gray-600'}`}>{label}</span>
    </div>
  )
}

// ── Migration Wizard Component ─────────────────────────────────────────────

function MigrationWizard() {
  const [step, setStep] = useState(0) // 0=Configure, 1=Migrate, 2=Post
  const [form, setForm] = useState({
    host: '', port: 5432, dbname: 'unifi_logs',
    user: '', password: '', sslmode: 'disable'
  })
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [composeInput, setComposeInput] = useState('')
  const [composeOutput, setComposeOutput] = useState('')
  const [patchError, setPatchError] = useState(null)
  const [patching, setPatching] = useState(false)
  const [migStatus, setMigStatus] = useState(null)
  const [migError, setMigError] = useState(null)
  const [isExternal, setIsExternal] = useState(false)
  const pollRef = useRef(null)

  // On mount: check current state
  useEffect(() => {
    getMigrationStatus().then(s => {
      setIsExternal(s.is_external)
      if (s.status === 'running') { setStep(1); startPolling() }
      else if (s.status === 'complete') { setStep(1); setMigStatus(s) }
    }).catch(e => console.error('Failed to check migration status:', e))
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  function startPolling() {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const s = await getMigrationStatus()
        setMigStatus(s)
        if (s.status === 'complete') { clearInterval(pollRef.current) }
        else if (s.status === 'failed') { setMigError(s.message); clearInterval(pollRef.current) }
      } catch { /* ignore */ }
    }, 3000)
  }

  async function handleTest() {
    setTesting(true); setTestResult(null)
    try {
      const r = await testMigrationConnection(form)
      setTestResult(r)
    } catch (e) {
      setTestResult({ success: false, message: e.message })
    } finally { setTesting(false) }
  }

  async function handleStartMigration() {
    setMigError(null)
    try {
      await startMigration(form)
      setStep(1)
      startPolling()
    } catch (e) {
      setMigError(e.message)
    }
  }

  function handleReset() {
    setStep(0); setTestResult(null); setMigStatus(null); setMigError(null)
    setComposeInput(''); setComposeOutput(''); setPatchError(null)
  }

  async function handlePatchCompose() {
    setPatching(true); setPatchError(null); setComposeOutput('')
    try {
      const r = await patchMigrationCompose({
        compose_yaml: composeInput,
        host: form.host, port: form.port, dbname: form.dbname,
        user: form.user, sslmode: form.sslmode,
      })
      if (r.success) {
        setComposeOutput(r.compose_yaml)
      } else {
        setPatchError(r.message || 'Failed to patch compose file')
      }
    } catch (e) {
      setPatchError(e.message)
    } finally { setPatching(false) }
  }


  function setField(k, v) { setForm(prev => ({ ...prev, [k]: v })) }

  // Already external — no wizard needed
  if (isExternal) {
    return (
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Database Migration</h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-5">
          <div className="flex items-start gap-2 bg-emerald-500/10 border border-emerald-500/30 rounded px-3 py-2.5">
            <svg className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
            </svg>
            <p className="text-sm text-emerald-400">Already using an external database. Migration is not available.</p>
          </div>
        </div>
      </section>
    )
  }

  return (
    <section>
      <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Database Migration</h2>
      <div className="rounded-lg border border-gray-700 bg-gray-950">
        <div className="p-5 space-y-5">
          {/* Step indicator */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
            {WIZARD_STEPS.map((label, i) => (
              <StepPill key={label} index={i} label={label} current={step} />
            ))}
          </div>

          {/* ── Step 0: Configure ── */}
          {step === 0 && (
            <div className="space-y-4">
              <p className="text-sm text-gray-400">
                Migrate your data to an external PostgreSQL 14+ instance. The target database must already exist — tables are created automatically.
              </p>
              <a
                href={EXTERNAL_DB_WIKI_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300 transition-colors"
              >
                Stuck? Open the full external PostgreSQL guide
                <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </a>

              {/* Form */}
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label htmlFor="mig-host" className="flex items-center gap-1 text-sm font-medium text-gray-200 mb-1">
                    Host
                    <InfoTooltip>
                      <p>If PostgreSQL is in another Docker container on this host, use a host-routable address and mapped port (for example <code className="bg-gray-800 px-1 py-0.5 rounded text-blue-300">host.docker.internal:5432</code> on Docker Desktop or the host gateway IP on Linux).</p>
                      <p>Do not use container bridge IPs like <code className="bg-gray-800 px-1 py-0.5 rounded text-blue-300">172.18.x.x</code>.</p>
                    </InfoTooltip>
                  </label>
                  <input id="mig-host" value={form.host} onChange={e => setField('host', e.target.value)}
                    placeholder="e.g. postgres or 192.168.1.50"
                    className="w-full px-3 py-1.5 rounded bg-black border border-gray-600 text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20" />
                </div>
                <div>
                  <label htmlFor="mig-port" className="block text-sm font-medium text-gray-200 mb-1">Port</label>
                  <input id="mig-port" type="number" value={form.port} onChange={e => setField('port', parseInt(e.target.value) || 5432)}
                    className="w-full px-3 py-1.5 rounded bg-black border border-gray-600 text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20" />
                </div>
              </div>
              <div>
                <label htmlFor="mig-dbname" className="block text-sm font-medium text-gray-200 mb-1">Database Name</label>
                <input id="mig-dbname" value={form.dbname} readOnly
                  className="w-full px-3 py-1.5 rounded bg-black/50 border border-gray-700 text-sm text-gray-400 cursor-not-allowed" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="mig-user" className="block text-sm font-medium text-gray-200 mb-1">Username</label>
                  <input id="mig-user" value={form.user} onChange={e => setField('user', e.target.value)}
                    className="w-full px-3 py-1.5 rounded bg-black border border-gray-600 text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20" />
                </div>
                <div>
                  <label htmlFor="mig-password" className="block text-sm font-medium text-gray-200 mb-1">Password</label>
                  <input id="mig-password" type="password" value={form.password} onChange={e => setField('password', e.target.value)}
                    className="w-full px-3 py-1.5 rounded bg-black border border-gray-600 text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20" />
                </div>
              </div>
              <div>
                <label htmlFor="mig-sslmode" className="block text-sm font-medium text-gray-200 mb-1">SSL Mode</label>
                <select id="mig-sslmode" value={form.sslmode} onChange={e => setField('sslmode', e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-black border border-gray-600 text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20">
                  <option value="disable">disable</option>
                  <option value="require">require</option>
                  <option value="verify-ca">verify-ca</option>
                  <option value="verify-full">verify-full</option>
                </select>
              </div>

              {/* Test result */}
              {testResult && (
                <div className={`flex items-start gap-2 rounded px-3 py-2.5 ${
                  testResult.success
                    ? 'bg-emerald-500/10 border border-emerald-500/30'
                    : 'bg-red-500/10 border border-red-500/30'
                }`}>
                  <svg className={`w-4 h-4 shrink-0 mt-0.5 ${testResult.success ? 'text-emerald-400' : 'text-red-400'}`} fill="currentColor" viewBox="0 0 20 20">
                    {testResult.success ? (
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
                    ) : (
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
                    )}
                  </svg>
                  <div className="text-sm space-y-0.5">
                    <p className={testResult.success ? 'text-emerald-400' : 'text-red-400'}>{testResult.message}</p>
                    {testResult.connectivity_hint && (
                      <p className="text-yellow-400 mt-1">
                        {testResult.connectivity_hint}
                        {' '}
                        <a
                          href={EXTERNAL_DB_WIKI_URL}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="underline text-yellow-300 hover:text-yellow-200"
                        >
                          Full guide
                        </a>
                      </p>
                    )}
                    {testResult.server_version && <p className="text-gray-500">{testResult.server_version}</p>}
                    {testResult.has_foreign_tables && (
                      <p className="text-yellow-400 mt-1">Warning: target has unknown tables ({testResult.foreign_tables.join(', ')}). Migration will be blocked.</p>
                    )}
                  </div>
                </div>
              )}

              {/* Buttons */}
              <div className="flex items-center justify-end gap-3">
                <button onClick={handleTest} disabled={testing || !form.host.trim()}
                  className="px-4 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors disabled:opacity-50">
                  {testing ? 'Testing...' : 'Test Connection'}
                </button>
                {testResult?.success && !testResult.has_foreign_tables && (
                  <button onClick={handleStartMigration}
                    className="px-4 py-1.5 rounded text-sm font-medium bg-teal-600 text-white hover:bg-teal-500 transition-colors">
                    Start Migration
                  </button>
                )}
              </div>

              {migError && (
                <div className="text-sm text-red-400">{migError}</div>
              )}
            </div>
          )}

          {/* ── Step 1: Migration (progress → summary) ── */}
          {step === 1 && (
            <div className="space-y-4">
              {/* In-progress UI */}
              {migStatus?.status !== 'complete' && (
                <>
                  {/* Progress bar */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm text-gray-300">{migStatus?.step || 'Starting...'}</span>
                      <span className="text-sm text-gray-500 font-mono">{migStatus?.progress_pct || 0}%</span>
                    </div>
                    <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden">
                      <div className="h-full bg-teal-500 rounded-full transition-all duration-500 ease-out"
                        style={{ width: `${migStatus?.progress_pct || 0}%` }} />
                    </div>
                    {migStatus?.message && <p className="text-sm text-gray-500 mt-1">{migStatus.message}</p>}
                  </div>

                  {/* Warning */}
                  <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                    <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                    </svg>
                    <p className="text-sm text-yellow-400/90">Do not restart the container while migration is running. Large datasets may take several minutes to transfer.</p>
                  </div>

                  {/* Error state */}
                  {migError && (
                    <div className="space-y-3">
                      <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded px-3 py-2.5">
                        <svg className="w-4 h-4 text-red-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
                        </svg>
                        <div className="text-sm text-red-400">{migError}</div>
                      </div>
                      <div className="flex justify-end">
                        <button onClick={handleReset}
                          className="px-4 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors">
                          Back to Configuration
                        </button>
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* Complete UI */}
              {migStatus?.status === 'complete' && (
                <>
                  <div className="flex items-start gap-2 bg-emerald-500/10 border border-emerald-500/30 rounded px-3 py-2.5">
                    <svg className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
                    </svg>
                    <p className="text-sm text-emerald-400">Migration complete! Your embedded data is untouched and safe.</p>
                  </div>

                  {/* Row count validation table */}
                  {migStatus?.details?.validation && (
                    <div className="rounded border border-gray-700 overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="bg-black">
                            <th className="text-left px-3 py-1.5 text-gray-400 font-semibold">Table</th>
                            <th className="text-right px-3 py-1.5 text-gray-400 font-semibold">Source</th>
                            <th className="text-right px-3 py-1.5 text-gray-400 font-semibold">Target</th>
                            <th className="text-center px-3 py-1.5 text-gray-400 font-semibold">Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(migStatus.details.validation).map(([table, v]) => (
                            <tr key={table} className="border-t border-gray-800">
                              <td className="px-3 py-1.5 font-mono text-gray-300">{table}</td>
                              <td className="text-right px-3 py-1.5 text-gray-400 font-mono">{v.source < 0 ? '—' : v.source.toLocaleString()}</td>
                              <td className="text-right px-3 py-1.5 text-gray-400 font-mono">{v.target < 0 ? '—' : v.target.toLocaleString()}</td>
                              <td className="text-center px-3 py-1.5">
                                <span className={v.status === 'ok' ? 'text-emerald-400' : 'text-red-400'}>
                                  {v.status === 'ok' ? '\u2713' : '\u2717'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  <div className="flex justify-end">
                    <button onClick={() => setStep(2)}
                      className="px-4 py-1.5 rounded text-sm font-medium bg-teal-600 text-white hover:bg-teal-500 transition-colors">
                      Continue
                    </button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* ── Step 2: Required Manual Tasks ── */}
          {step === 2 && (
            <div className="space-y-4">

              {/* Compose patcher — Phase 1: Paste */}
              {!composeOutput && (
                <div className="space-y-3">
                  <p className="text-sm text-gray-400">
                    Update your <code className="bg-gray-800 px-1 py-0.5 rounded">docker-compose.yml</code> to point at the external database. Paste your current file below and we'll generate an updated version.
                  </p>
                  <textarea
                    value={composeInput}
                    onChange={e => setComposeInput(e.target.value)}
                    placeholder="Paste your docker-compose.yml here..."
                    rows={10}
                    className="w-full px-3 py-2 rounded bg-black border border-gray-600 text-sm text-gray-200 font-mono focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20 resize-y"
                  />
                  <div className="flex justify-end">
                    <button onClick={handlePatchCompose} disabled={patching || !composeInput.trim()}
                      className="px-4 py-1.5 rounded text-sm font-medium bg-teal-600 text-white hover:bg-teal-500 transition-colors disabled:opacity-50">
                      {patching ? 'Generating...' : 'Generate Updated Compose'}
                    </button>
                  </div>
                  {patchError && (
                    <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded px-3 py-2.5">
                      <svg className="w-4 h-4 text-red-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
                      </svg>
                      <p className="text-sm text-red-400">{patchError}</p>
                    </div>
                  )}
                </div>
              )}

              {/* Compose patcher — Phase 2: Result */}
              {composeOutput && (
                <div className="space-y-3">
                  <p className="text-sm text-gray-400">
                    1. Copy and save the following as your <code className="bg-gray-800 px-1 py-0.5 rounded">docker-compose.yml</code>
                  </p>
                  <div className="relative rounded bg-black border border-gray-700 p-3">
                    <pre className="text-sm text-gray-300 font-mono whitespace-pre overflow-x-auto max-h-96 overflow-y-auto">{composeOutput}</pre>
                    <div className="absolute top-2 right-2">
                      <CopyButton text={composeOutput} />
                    </div>
                  </div>

                  {/* Instructions */}
                  <div className="space-y-2">
                    <p className="text-sm text-gray-400">
                      2. Set <code className="bg-gray-800 px-1 py-0.5 rounded">DB_PASSWORD</code> in your <code className="bg-gray-800 px-1 py-0.5 rounded">.env</code> file (the password you entered in step 1):
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="bg-gray-800 px-2 py-1 rounded text-sm text-gray-300 font-mono">DB_PASSWORD={form.password}</code>
                      <CopyButton text={`DB_PASSWORD=${form.password}`} />
                    </div>
                    <p className="text-sm text-gray-400">
                      3. Rename <code className="bg-gray-800 px-1 py-0.5 rounded">POSTGRES_PASSWORD</code> to <code className="bg-gray-800 px-1 py-0.5 rounded">SECRET_KEY</code> in your <code className="bg-gray-800 px-1 py-0.5 rounded">.env</code> file (keep the same value — it encrypts stored API keys. If this value changes, previously stored API keys cannot be decrypted.)
                    </p>
                    <p className="text-sm text-gray-400">
                      4. Run <code className="bg-gray-800 px-1 py-0.5 rounded">docker compose up -d</code>
                    </p>
                  </div>

                  {/* pgdata volume note */}
                  <div className="flex items-start gap-2 bg-blue-500/10 border border-blue-500/30 rounded px-3 py-2">
                    <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
                    </svg>
                    <div className="text-sm text-blue-400/90 space-y-1">
                      <p>
                        Your old embedded database volume (<code className="bg-gray-800 px-1 py-0.5 rounded">pgdata</code>) still exists on disk as a safety net.
                        Once you've confirmed the external database is working, remove it from the Unifi Log Insight project directory with:
                      </p>
                      <code className="block bg-gray-800 px-2 py-1 rounded text-blue-300">docker volume rm {(composeInput.match(/^volumes:\s*\n\s+pgdata:\s*\n\s+name:\s*(\S+)/m) || [])[1] || '<project>_pgdata'}</code>
                      <p>This only removes the old embedded volume — your external database is unaffected. Do not use <code className="bg-gray-800 px-1 py-0.5 rounded">docker compose down -v</code> as it removes all volumes.</p>
                    </div>
                  </div>

                  <div className="flex justify-end">
                    <button onClick={() => { setComposeOutput(''); setComposeInput('') }}
                      className="px-4 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors">
                      Paste Different Compose File
                    </button>
                  </div>
                  <p className="text-sm text-gray-500">
                    YAML comments from your original file are not preserved.
                  </p>
                </div>
              )}
              <a
                href={EXTERNAL_DB_WIKI_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300 transition-colors"
              >
                Need help? Open the full external PostgreSQL guide
                <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </a>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

export default function SettingsDataBackups({ totalLogs, storage }) {
  // Retention state
  const [retention, setRetention] = useState(null)
  const [retentionDays, setRetentionDays] = useState(60)
  const [dnsRetentionDays, setDnsRetentionDays] = useState(10)
  const [retentionSaving, setRetentionSaving] = useState(false)
  const [retentionMsg, setRetentionMsg] = useState(null)
  const [showCleanup, setShowCleanup] = useState(false)
  const [cleaningUp, setCleaningUp] = useState(false)

  // Export/Import state
  const [exporting, setExporting] = useState(false)
  const [importPreview, setImportPreview] = useState(null)
  const [importMsg, setImportMsg] = useState(null)
  const fileInputRef = useRef(null)

  useEffect(() => {
    fetchRetentionConfig().then(data => {
      setRetention(data)
      setRetentionDays(data.retention_days)
      setDnsRetentionDays(data.dns_retention_days)
    }).catch(err => console.error('Failed to load retention config:', err))
  }, [])

  // ── Retention handlers ──
  const retentionDirty = retention && (
    retentionDays !== retention.retention_days || dnsRetentionDays !== retention.dns_retention_days
  )

  async function saveRetention() {
    setRetentionSaving(true)
    setRetentionMsg(null)
    try {
      const wasLowered = retention && (
        retentionDays < retention.retention_days || dnsRetentionDays < retention.dns_retention_days
      )
      await updateRetentionConfig({ retention_days: retentionDays, dns_retention_days: dnsRetentionDays })
      setRetention(prev => ({ ...prev, retention_days: retentionDays, dns_retention_days: dnsRetentionDays }))
      setRetentionMsg({ type: 'success', text: 'Retention settings saved' })
      if (wasLowered) {
        setShowCleanup(true)
      } else {
        setShowCleanup(false)
        setTimeout(() => setRetentionMsg(null), 3000)
      }
    } catch (e) {
      setRetentionMsg({ type: 'error', text: e.message })
    } finally {
      setRetentionSaving(false)
    }
  }

  async function handleCleanupNow() {
    setCleaningUp(true)
    setRetentionMsg(null)
    try {
      const result = await runRetentionCleanup()
      setRetentionMsg({ type: 'success', text: `Cleanup complete — ${result.deleted.toLocaleString()} logs removed` })
      setShowCleanup(false)
      setTimeout(() => setRetentionMsg(null), 5000)
    } catch (e) {
      setRetentionMsg({ type: 'error', text: 'Cleanup failed: ' + e.message })
    } finally {
      setCleaningUp(false)
    }
  }

  // ── Export handlers ──
  async function handleExport(includeApiKey) {
    setExporting(true)
    try {
      const data = await exportConfig(includeApiKey)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      const date = new Date().toISOString().slice(0, 10)
      a.href = url
      a.download = `unifi-log-insight-config-${date}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert('Export failed: ' + e.message)
    } finally {
      setExporting(false)
    }
  }

  // ── Import handlers ──
  function handleImportFileSelect(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result)
        if (!data.config || typeof data.config !== 'object') {
          setImportMsg({ type: 'error', text: 'Invalid config file format' })
          setImportPreview(null)
          return
        }
        setImportPreview(data)
        setImportMsg(null)
      } catch {
        setImportMsg({ type: 'error', text: 'Failed to parse JSON file' })
        setImportPreview(null)
      }
    }
    reader.readAsText(file)
  }

  async function handleImportConfirm() {
    if (!importPreview) return
    setImportMsg(null)
    try {
      const result = await importConfig(importPreview)
      setImportMsg({ type: 'success', text: `Imported ${result.imported_keys.length} settings. Reloading...` })
      setTimeout(() => window.location.reload(), 1500)
    } catch (e) {
      setImportMsg({ type: 'error', text: 'Import failed: ' + e.message })
    }
  }

  function cancelImport() {
    setImportPreview(null)
    setImportMsg(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  return (
    <div className="space-y-8">
      {/* ── Data Retention ─────────────────────────────────────── */}
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          Data Retention
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-5">
            {/* General retention slider */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-base text-gray-200 font-medium">Log retention</label>
                <span className="text-sm font-mono font-semibold text-gray-200">{retentionDays} days</span>
              </div>
              <input
                type="range"
                min={1}
                max={365}
                value={retentionDays}
                onChange={e => setRetentionDays(Number(e.target.value))}
                className="w-full accent-teal-500"
                style={{ background: `linear-gradient(to right, #14b8a6 ${((retentionDays - 1) / 364) * 100}%, #374151 ${((retentionDays - 1) / 364) * 100}%)`, borderRadius: '999px', height: '6px' }}
              />
              <div className="flex flex-wrap gap-1.5 mt-2">
                {RETENTION_PRESETS.map(preset => (
                  <button
                    key={preset}
                    onClick={() => setRetentionDays(preset)}
                    className={`text-sm font-mono px-2 py-0.5 rounded border transition-colors ${
                      retentionDays === preset
                        ? 'border-blue-500 text-blue-400 bg-blue-500/10'
                        : 'border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {preset}d
                  </button>
                ))}
              </div>
              {retentionDays > 120 && (
                <div className="mt-2 flex items-center gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                  <svg className="w-4 h-4 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <p className="text-sm text-yellow-400/90">
                    Extended retention may affect query performance on large datasets. Ensure you have enough disk space.
                  </p>
                </div>
              )}
            </div>

            {/* DNS retention input */}
            <div>
              <div className="flex items-center justify-between">
                <label className="text-base text-gray-200 font-medium">DNS log retention</label>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={dnsRetentionDays}
                    onChange={e => setDnsRetentionDays(Math.max(1, Math.min(365, parseInt(e.target.value) || 1)))}
                    className="w-16 px-2 py-1 rounded bg-black border border-gray-600 font-mono text-sm text-gray-200 text-right focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
                  />
                  <span className="text-sm text-gray-500">days</span>
                </div>
              </div>
            </div>

            {/* Info note */}
            <div className="flex items-start gap-2 bg-blue-500/10 border border-blue-500/30 rounded px-3 py-2">
              <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
              </svg>
              <p className="text-sm text-blue-400/90">
                Time range filters in Log Stream and Dashboard automatically adjust to
                show only ranges with available data. If logs from a previous retention
                period haven't been cleaned up yet, filters may extend beyond your
                current retention setting.
              </p>
            </div>
          </div>

          {/* Storage info */}
          {storage && storage.db_size_bytes != null && (() => {
            const dbSize = storage.db_size_bytes
            const volAvail = storage.volume_available_bytes
            const critical = volAvail != null && volAvail < DISK_CRITICAL_BYTES
            const warning = volAvail != null && volAvail < DISK_WARNING_BYTES
            return (
              <div className="px-5 pb-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400">Database size</span>
                  <span className="text-sm text-gray-300 font-mono">{formatBytes(dbSize)}</span>
                </div>
                {volAvail != null && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">Disk space available</span>
                    <span className={`text-sm font-mono ${critical ? 'text-red-400' : warning ? 'text-yellow-400' : 'text-gray-300'}`}>{formatBytes(volAvail)}</span>
                  </div>
                )}
                {critical && (
                  <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded px-3 py-2">
                    <svg className="w-4 h-4 text-red-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                    </svg>
                    <p className="text-sm text-red-400/90">
                      Disk space is critically low. Reduce retention or free up space to prevent log ingestion from stopping.
                    </p>
                  </div>
                )}
                {warning && !critical && (
                  <div className="flex items-center gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                    <svg className="w-4 h-4 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                    </svg>
                    <p className="text-sm text-yellow-400/90">
                      Disk space is running low. Consider lowering retention days or increasing allocated disk space.
                    </p>
                  </div>
                )}
              </div>
            )
          })()}

          {/* Save + status */}
          <div className="border-t border-gray-800" />
          <div className="px-5 py-3 flex items-center justify-between">
            <p className="text-sm text-gray-500">
              {totalLogs != null && <>{totalLogs.toLocaleString()} logs stored · </>}Cleanup runs daily at 03:00 UTC
            </p>
            <div className="flex items-center gap-3">
              {retentionMsg && (
                <span className={`text-sm ${retentionMsg.type === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {retentionMsg.text}
                </span>
              )}
              {showCleanup && (
                <button
                  onClick={handleCleanupNow}
                  disabled={cleaningUp}
                  className="px-4 py-1.5 rounded text-sm font-medium border border-yellow-500/50 text-yellow-400 hover:bg-yellow-500/10 transition-colors disabled:opacity-50"
                >
                  {cleaningUp ? 'Cleaning up...' : 'Run Cleanup Now'}
                </button>
              )}
              <button
                onClick={saveRetention}
                disabled={!retentionDirty || retentionSaving}
                className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
                  retentionDirty
                    ? 'bg-teal-600 text-white hover:bg-teal-500'
                    : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                }`}
              >
                {retentionSaving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ── Export / Import Configuration ──────────────────────── */}
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          Backup &amp; Restore
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          {/* Export */}
          <div className="p-5">
            <h3 className="text-base text-gray-200 font-medium mb-2">Export Configuration</h3>
            <div className="space-y-2">
              <button
                onClick={() => handleExport(false)}
                disabled={exporting}
                className="w-full text-left rounded-lg border border-gray-700 hover:border-gray-500 p-3 transition-colors disabled:opacity-50"
              >
                <div className="text-sm font-medium text-gray-200">Everything without API Key</div>
                <p className="text-sm text-gray-500 mt-1">
                  WAN Config, Network Labels, UniFi Connection (Host, Site, SSL, Polling), Retention Settings, UI Preferences
                </p>
                <div className="flex items-start gap-2 mt-1.5 bg-blue-500/10 border border-blue-500/30 rounded px-2.5 py-1.5">
                  <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
                  </svg>
                  <p className="text-sm text-blue-400/90">
                    You'll need to re-enter your UniFi API key after import, or regenerate one from your controller.
                    Self-hosted credentials (username/password) are never exported.
                  </p>
                </div>
              </button>
              <button
                onClick={() => handleExport(true)}
                disabled={exporting}
                className="w-full text-left rounded-lg border border-gray-700 hover:border-gray-500 p-3 transition-colors disabled:opacity-50"
              >
                <div className="text-sm font-medium text-gray-200">Everything + API Key</div>
                <p className="text-sm text-gray-500 mt-1">
                  All settings above plus your UniFi API key
                </p>
                <div className="flex items-start gap-2 mt-1.5 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                  <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <p className="text-sm text-yellow-400/90">
                    Your API key will be included in plaintext. Store this file securely.
                  </p>
                </div>
              </button>
            </div>
          </div>

          {/* Divider */}
          <div className="border-t border-gray-800" />

          {/* Import */}
          <div className="p-5">
            <h3 className="text-base text-gray-200 font-medium mb-2">Import Configuration</h3>
            <input
              ref={fileInputRef}
              type="file"
              accept=".json"
              onChange={handleImportFileSelect}
              className="hidden"
            />

            {importPreview ? (
              <div className="space-y-3">
                <div className="rounded border border-gray-700 bg-black p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-300">
                      Backup from {importPreview.exported_at ? new Date(importPreview.exported_at).toLocaleDateString() : 'unknown date'}
                    </span>
                    {importPreview.version && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">
                        v{importPreview.version}
                      </span>
                    )}
                  </div>
                  <div className="text-sm text-gray-500">
                    <span className="font-medium text-gray-400">{Object.keys(importPreview.config).length} settings</span> will be imported:
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {Object.keys(importPreview.config).filter(k => k !== 'unifi_api_key').map(key => (
                      <span key={key} className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono">
                        {key}
                      </span>
                    ))}
                  </div>
                  {importPreview.includes_api_key || importPreview.config.unifi_api_key ? (
                    <div className="flex items-center gap-1.5 mt-2">
                      <span className="text-xs px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                        Includes API Key
                      </span>
                    </div>
                  ) : (
                    <p className="text-sm text-blue-400/70 mt-2">
                      No API key in this backup. Your existing key will be kept, or you can add one later in UniFi Settings.
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleImportConfirm}
                    className="px-4 py-1.5 rounded text-sm font-medium bg-teal-600 text-white hover:bg-teal-500 transition-colors"
                  >
                    Confirm Import
                  </button>
                  <button
                    onClick={cancelImport}
                    className="px-4 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
              >
                Import from File
              </button>
            )}

            {importMsg && (
              <div className={`mt-2 text-sm ${importMsg.type === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                {importMsg.text}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ── Database Migration ──────────────────────────────────── */}
      <MigrationWizard />
    </div>
  )
}
