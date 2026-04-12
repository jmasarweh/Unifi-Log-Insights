import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { fetchAdguardConfig, updateAdguardConfig, testAdguardConnection } from '../api'
import InfoTooltip from './InfoTooltip'

const INPUT_CLS = 'w-full px-3 py-1.5 bg-black border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20'

const PASSWORD_PLACEHOLDER = '***'

const POLL_INTERVALS = [
  { value: 15, label: '15 seconds' },
  { value: 30, label: '30 seconds' },
  { value: 60, label: '60 seconds' },
  { value: 120, label: '2 minutes' },
  { value: 300, label: '5 minutes' },
]

// AdGuard Home shield icon (inline SVG — no binary asset needed)
function AdGuardIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 1L3 5v6c0 5.25 3.75 10.15 9 11.25C17.25 21.15 21 16.25 21 11V5L12 1zm0 2.18l7 3.12V11c0 4.36-3.05 8.44-7 9.57C8.05 19.44 5 15.36 5 11V6.3l7-3.12z"/>
    </svg>
  )
}

export default function SettingsAdguard() {
  const [settings, setSettings] = useState(null)
  const [draft, setDraft] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState(null)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [testPassed, setTestPassed] = useState(false)
  const [disabling, setDisabling] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const saveTimerRef = useRef(null)

  const loadConfig = useCallback(async () => {
    try {
      const data = await fetchAdguardConfig()
      setSettings(data)
      setLoadError(null)
      // Pre-populate draft; clear password so the masked '***' is not editable
      setDraft(prev => {
        if (!prev) return { ...data, password: '' }
        return { ...prev, ...data, password: prev.password || '' }
      })
      // If already enabled + connected, allow enabling without re-test
      if (data?.enabled) setTestPassed(true)
    } catch (e) {
      console.error('Failed to load AdGuard settings:', e)
      setLoadError(e.message || 'Failed to load settings')
    }
  }, [])

  useEffect(() => { loadConfig() }, [loadConfig])
  useEffect(() => () => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
  }, [])

  // Detect meaningful changes that need saving
  const hasChanges = useMemo(() => {
    if (!settings || !draft) return false
    return draft.host !== settings.host
      || draft.username !== settings.username
      || (draft.enabled && !settings.enabled)
      || draft.poll_interval !== settings.poll_interval
      || (!!draft.password)
  }, [settings, draft])

  // Require a passing test when enabling or changing host/credentials
  const needsTest = useMemo(() => {
    if (!settings || !draft) return false
    return (draft.enabled && !settings.enabled)
      || draft.host !== settings.host
      || draft.username !== settings.username
      || (!!draft.password)
  }, [settings, draft])

  const canSave = hasChanges && (!needsTest || testPassed)
    && !(draft?.enabled && !draft?.host)

  async function handleSave() {
    setSaving(true)
    setSaveStatus(null)
    setTestResult(null)
    try {
      await updateAdguardConfig(draft)
      setSaveStatus({ type: 'saved', text: 'Settings saved' })
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      saveTimerRef.current = setTimeout(() => setSaveStatus(null), 3000)
      setDraft(prev => ({ ...prev, password: '' }))
      await loadConfig()
    } catch (e) {
      setSaveStatus({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      const result = await testAdguardConnection({
        host: draft.host,
        username: draft.username,
        password: draft.password,
      })
      if (!result.ok) {
        setTestResult({ type: 'error', text: result.detail || 'Connection failed' })
        setTestPassed(false)
      } else {
        setTestResult({
          type: 'success',
          text: result.version
            ? `Connected — AdGuard Home ${result.version}`
            : 'Connection successful',
        })
        setTestPassed(true)
      }
    } catch (e) {
      setTestResult({ type: 'error', text: e.message })
      setTestPassed(false)
    } finally {
      setTesting(false)
    }
  }

  if (loadError) {
    return (
      <div className="text-sm text-red-400">
        Failed to load AdGuard settings: {loadError}
        <button onClick={loadConfig} className="ml-2 text-teal-400 hover:text-teal-300">Retry</button>
      </div>
    )
  }
  if (!draft) {
    return <div className="text-sm text-gray-400">Loading AdGuard settings...</div>
  }

  const passwordSaved = settings?.password === PASSWORD_PLACEHOLDER

  return (
    <div className="space-y-8">
      <section>
        <h2 className="flex items-center gap-2 text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          <AdGuardIcon className="w-5 h-5 text-teal-400" />
          AdGuard Home
        </h2>

        {/* Status card */}
        <div className="rounded-lg border border-gray-700 bg-gray-950 px-4 py-3 mb-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-200">
              {settings?.host || 'AdGuard Home'}
            </span>
            <span className={`flex items-center gap-1.5 text-sm leading-none ${
              settings?.enabled ? 'text-emerald-400' : 'text-gray-500'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full block ${
                settings?.enabled ? 'bg-emerald-400' : 'bg-gray-500'
              }`} />
              {settings?.enabled ? 'Active' : 'Inactive'}
            </span>
          </div>
          {settings?.enabled && settings?.poll_interval && (
            <div className="text-sm text-gray-500 mt-1">
              Polling every {settings.poll_interval}s
            </div>
          )}
        </div>

        {/* Configuration */}
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-5">
            {/* Enable/Disable toggle */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-base text-gray-200 font-medium">Enable AdGuard Home</p>
                <p className="text-sm text-gray-500">Ingest DNS query logs from AdGuard Home v0.107+.</p>
              </div>
              <button
                onClick={() => {
                  if (disabling) return
                  if (draft.enabled) {
                    setDisabling(true)
                    setDraft(d => ({ ...d, enabled: false }))
                    updateAdguardConfig({ ...draft, enabled: false }).then(() => {
                      loadConfig()
                    }).catch(e => {
                      setDraft(d => ({ ...d, enabled: true }))
                      setSaveStatus({ type: 'error', text: e.message || 'Failed to disable' })
                    }).finally(() => setDisabling(false))
                  } else if (testPassed) {
                    setDraft(d => ({ ...d, enabled: true }))
                  }
                }}
                disabled={disabling || (!draft.enabled && !testPassed)}
                className={`px-3 py-1 rounded text-sm font-semibold border transition-colors ${
                  draft.enabled
                    ? 'bg-green-500/10 text-green-300 border-green-500/40'
                    : !testPassed
                      ? 'bg-black text-gray-600 border-gray-800 cursor-not-allowed'
                      : 'bg-black text-gray-400 border-gray-700'
                }`}
              >
                {draft.enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            {/* Host URL */}
            <div>
              <label className="text-sm font-medium text-gray-200 block mb-1">AdGuard Home URL</label>
              <input
                type="text"
                value={draft.host || ''}
                onChange={e => {
                  setDraft(prev => ({ ...prev, host: e.target.value }))
                  setTestPassed(false)
                  setTestResult(null)
                }}
                placeholder="http://192.168.1.1"
                className={INPUT_CLS}
              />
            </div>

            {/* Username */}
            <div>
              <label className="text-sm font-medium text-gray-200 block mb-1">Username</label>
              <input
                type="text"
                value={draft.username || ''}
                onChange={e => {
                  setDraft(prev => ({ ...prev, username: e.target.value }))
                  setTestPassed(false)
                  setTestResult(null)
                }}
                placeholder="admin"
                autoComplete="off"
                className={INPUT_CLS}
              />
            </div>

            {/* Password */}
            <div>
              <label className="text-sm font-medium text-gray-200 block mb-1">Password</label>
              <input
                type="password"
                value={draft.password || ''}
                onChange={e => {
                  setDraft(prev => ({ ...prev, password: e.target.value }))
                  setTestPassed(false)
                  setTestResult(null)
                }}
                placeholder={passwordSaved ? '(saved, leave blank to keep)' : 'AdGuard admin password'}
                autoComplete="new-password"
                className={INPUT_CLS}
              />
            </div>

            {/* Poll interval */}
            <div>
              <label className="flex items-center gap-1 text-sm font-medium text-gray-200 mb-1">
                Poll Interval
                <InfoTooltip>
                  <p>How often to fetch new DNS queries from AdGuard Home. Lower intervals increase query coverage but add more load.</p>
                  <p className="mt-1"><strong className="text-blue-300">15s</strong> for active monitoring, <strong className="text-blue-300">30-60s</strong> for most setups.</p>
                </InfoTooltip>
              </label>
              <select
                value={draft.poll_interval ?? 30}
                onChange={e => setDraft(prev => ({ ...prev, poll_interval: parseInt(e.target.value, 10) }))}
                className={INPUT_CLS}
              >
                {POLL_INTERVALS.map(opt => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>

            {/* Test connection */}
            <div className="flex items-center gap-3">
              <button
                onClick={handleTest}
                disabled={testing || !draft.host}
                className="px-3 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {testing ? 'Testing...' : 'Test Connection'}
              </button>
              {testResult?.type === 'success' && (
                <span className="text-sm text-emerald-400">{testResult.text}</span>
              )}
            </div>
            {testResult?.type === 'error' && (
              <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                </svg>
                <span className="text-sm text-yellow-200">{testResult.text}</span>
              </div>
            )}
          </div>

          <div className="border-t border-gray-800" />

          {/* Save footer */}
          <div className="px-5 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              {saveStatus?.type === 'saved' && <span className="text-sm text-emerald-400">{saveStatus.text}</span>}
              {saveStatus?.type === 'error' && <span className="text-sm text-red-400">{saveStatus.text}</span>}
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
    </div>
  )
}
