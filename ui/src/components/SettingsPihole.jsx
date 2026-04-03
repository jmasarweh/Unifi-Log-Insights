import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { fetchPiholeSettings, updatePiholeSettings, testPiholeConnection } from '../api'
import InfoTooltip from './InfoTooltip'
import piholeLogo from '../assets/pihole-logo.png'

const INPUT_CLS = 'w-full px-3 py-1.5 bg-black border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20'

function formatDate(str) {
  const d = new Date(str)
  return isNaN(d.getTime()) ? 'Unknown' : d.toLocaleString()
}

const POLL_INTERVALS = [
  { value: 15, label: '15 seconds' },
  { value: 30, label: '30 seconds' },
  { value: 60, label: '60 seconds' },
  { value: 120, label: '2 minutes' },
  { value: 300, label: '5 minutes' },
]

const ENRICHMENT_OPTIONS = [
  { value: 'none', label: 'None' },
  { value: 'geoip', label: 'GeoIP only' },
  { value: 'threat', label: 'Threat only' },
  { value: 'both', label: 'Both' },
]

export default function SettingsPihole() {
  const [settings, setSettings] = useState(null)
  const [draft, setDraft] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState(null)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [testPassed, setTestPassed] = useState(false)
  const [polling, setPolling] = useState(false)
  const [disabling, setDisabling] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const pollTimerRef = useRef(null)
  const saveTimerRef = useRef(null)

  const loadSettings = useCallback(async () => {
    try {
      const data = await fetchPiholeSettings()
      setSettings(data)
      setLoadError(null)
      if (data?.status?.connected) { setTestPassed(true); setPolling(false) }
      setDraft(prev => {
        if (!prev) return { ...data, password: '' }
        return { ...prev, ...data, password: prev.password || '' }
      })
    } catch (e) {
      console.error('Failed to load Pi-hole settings:', e)
      setLoadError(e.message || 'Failed to load settings')
    }
  }, [])

  useEffect(() => { loadSettings() }, [loadSettings])
  useEffect(() => () => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current)
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
  }, [])

  const hasChanges = useMemo(() => {
    if (!settings || !draft) return false
    return draft.host !== settings.host
      || (draft.enabled && !settings.enabled)
      || draft.poll_interval !== settings.poll_interval
      || draft.enrichment !== settings.enrichment
      || (!!draft.password)
  }, [settings, draft])

  // Require passing test when enabling or changing host/password
  const needsTest = useMemo(() => {
    if (!settings || !draft) return false
    return (draft.enabled && !settings.enabled) || draft.host !== settings.host
      || (!!draft.password)
  }, [settings, draft])

  // Block save if enabling without a host configured
  const canSave = hasChanges && (!needsTest || testPassed)
    && !(draft?.enabled && !draft?.host)

  async function handleSave() {
    setSaving(true)
    setSaveStatus(null)
    setTestResult(null)
    try {
      await updatePiholeSettings(draft)
      setSaveStatus({ type: 'saved', text: 'Settings saved' })
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      saveTimerRef.current = setTimeout(() => setSaveStatus(null), 3000)
      setDraft(prev => ({ ...prev, password: '' }))
      if (draft.enabled && !settings.enabled) {
        setPolling(true)
        if (pollTimerRef.current) clearTimeout(pollTimerRef.current)
        // Poll until status shows connected (max 10 attempts, 2s apart)
        let attempts = 0
        const pollStatus = async () => {
          if (attempts >= 10) { setPolling(false); return }
          attempts++
          try {
            const data = await fetchPiholeSettings()
            setSettings(data)
            if (data?.status?.connected) {
              setTestPassed(true)
              setPolling(false)
              return
            }
          } catch (err) { console.debug('Pi-hole status poll retry:', err) }
          pollTimerRef.current = setTimeout(pollStatus, 2000)
        }
        pollTimerRef.current = setTimeout(pollStatus, 2000)
      } else {
        await loadSettings()
      }
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
      const result = await testPiholeConnection({
        host: draft.host,
        password: draft.password,
      })
      if (!result.success) {
        setTestResult({ type: 'error', text: result.error || 'Connection failed' })
        setTestPassed(false)
      } else {
        setTestResult({
          type: 'success',
          text: result.version
            ? `Connected - Pi-hole ${result.version}`
            : 'Connection successful',
        })
        setTestPassed(true)
      }
    } catch (e) {
      setTestResult({ type: 'error', text: e.message })
    } finally {
      setTesting(false)
    }
  }

  if (loadError) {
    return (
      <div className="text-sm text-red-400">
        Failed to load Pi-hole settings: {loadError}
        <button onClick={loadSettings} className="ml-2 text-teal-400 hover:text-teal-300">Retry</button>
      </div>
    )
  }
  if (!draft) {
    return <div className="text-sm text-gray-400">Loading Pi-hole settings...</div>
  }

  return (
    <div className="space-y-8">
      <section>
        <h2 className="flex items-center gap-2 text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          <img src={piholeLogo} alt="" className="w-5 h-5" />
          Pi-hole
        </h2>

        {/* Status card */}
        <div className="rounded-lg border border-gray-700 bg-gray-950 px-4 py-3 mb-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-200">
              {settings?.host || 'Pi-hole'}
            </span>
            <span className={`flex items-center gap-1.5 text-sm leading-none ${
              settings?.status?.connected ? 'text-emerald-400'
                : polling ? 'text-yellow-400'
                : settings?.enabled ? 'text-red-400'
                : 'text-gray-500'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full block ${
                settings?.status?.connected ? 'bg-emerald-400'
                  : polling ? 'bg-yellow-400 animate-pulse'
                  : settings?.enabled ? 'bg-red-400'
                  : 'bg-gray-500'
              }`} />
              {settings?.status?.connected ? 'Active' : polling ? 'Polling' : settings?.enabled ? 'Offline' : 'Inactive'}
            </span>
          </div>
          {settings?.status?.last_poll && (
            <div className="text-sm text-gray-500 mt-1">
              Last poll: {formatDate(settings.status.last_poll)}
            </div>
          )}
        </div>

        {/* Configuration */}
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-5">
            {/* Enable/Disable toggle */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-base text-gray-200 font-medium">Enable Pi-hole</p>
                <p className="text-sm text-gray-500">Ingest DNS queries from Pi-hole v6.</p>
              </div>
              <button
                onClick={() => {
                  if (disabling) return
                  if (draft.enabled) {
                    // Disable takes effect immediately
                    setDisabling(true)
                    setDraft(d => ({ ...d, enabled: false }))
                    updatePiholeSettings({ enabled: false }).then(() => {
                      loadSettings()
                    }).catch((e) => {
                      setDraft(d => ({ ...d, enabled: true }))
                      setSaveStatus({ type: 'error', text: e.message || 'Failed to disable' })
                    }).finally(() => setDisabling(false))
                  } else if (testPassed) {
                    // Enable requires passing test first
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

            {/* URL */}
            <div>
              <label className="text-sm font-medium text-gray-200 block mb-1">Pi-hole URL</label>
              <input
                type="text"
                value={draft.host || ''}
                onChange={e => { setDraft(prev => ({ ...prev, host: e.target.value })); setTestPassed(false); setTestResult(null) }}
                placeholder="http://10.10.10.229:60080"
                className={INPUT_CLS}
              />
            </div>

            {/* Password */}
            <div>
              <label className="text-sm font-medium text-gray-200 block mb-1">Password</label>
              <input
                type="password"
                value={draft.password || ''}
                onChange={e => { setDraft(prev => ({ ...prev, password: e.target.value })); setTestPassed(false); setTestResult(null) }}
                placeholder={settings?.password_set ? '(saved, leave blank to keep)' : 'Pi-hole admin password'}
                className={INPUT_CLS}
              />
            </div>

            {/* Poll interval */}
            <div>
              <label className="flex items-center gap-1 text-sm font-medium text-gray-200 mb-1">
                Poll Interval
                <InfoTooltip>
                  <p>How often to fetch new DNS queries from Pi-hole. Lower intervals capture more queries but increase load.</p>
                  <p className="mt-1"><strong className="text-blue-300">15s</strong> for large networks (50+ devices), <strong className="text-blue-300">30-60s</strong> for most homes, <strong className="text-blue-300">2-5m</strong> for light use.</p>
                </InfoTooltip>
              </label>
              <select
                value={draft.poll_interval ?? 60}
                onChange={e => setDraft(prev => ({ ...prev, poll_interval: parseInt(e.target.value, 10) }))}
                className={INPUT_CLS}
              >
                {POLL_INTERVALS.map(opt => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>

            {/* Enrichment */}
            <div>
              <label className="text-sm font-medium text-gray-200 block mb-1">Enrichment</label>
              <select
                value={draft.enrichment || 'both'}
                onChange={e => setDraft(prev => ({ ...prev, enrichment: e.target.value }))}
                className={INPUT_CLS}
              >
                {ENRICHMENT_OPTIONS.map(opt => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
              <p className="text-sm text-gray-500 mt-1">Apply GeoIP and/or threat score enrichment to DNS query IPs.</p>
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
