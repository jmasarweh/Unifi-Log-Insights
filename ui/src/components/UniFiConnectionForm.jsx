import { useState, useRef, useEffect } from 'react'
import { testUniFiConnection } from '../api'

function normalizeHost(raw) {
  const h = raw.trim()
  if (!h) return h
  if (/^https?:\/\//i.test(h)) return h
  return `https://${h}`
}

export default function UniFiConnectionForm({
  onSuccess, onSkip, envApiKey, envHost, savedHost, savedApiKey,
  savedUsername, savedControllerType,
}) {
  const [controllerType, setControllerType] = useState(savedControllerType || 'unifi_os')
  const [host, setHost] = useState(envHost || savedHost || '')
  const [apiKey, setApiKey] = useState('')
  const [useSaved, setUseSaved] = useState(!!savedApiKey)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [useSavedCredentials, setUseSavedCredentials] = useState(!!savedUsername)
  const [site, setSite] = useState('default')
  const [verifySsl, setVerifySsl] = useState(true)
  const [showAdvanced, setShowAdvanced] = useState(true)
  const [testing, setTesting] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [phase, setPhase] = useState(null) // null → 'connected' → 'fetching'
  const timeoutRef = useRef(null)

  const isSelfHosted = controllerType === 'self_hosted'

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
    }
  }, [])

  const hasCredentials = isSelfHosted
    ? useSavedCredentials || (username.trim() && password.trim())
    : envApiKey || useSaved || apiKey.trim()

  const handleTypeChange = (type) => {
    setControllerType(type)
    setResult(null)
    setError(null)
  }

  const handleTest = async () => {
    // Clear any pending timeout from a previous attempt
    if (timeoutRef.current) { clearTimeout(timeoutRef.current); timeoutRef.current = null }
    setTesting(true)
    setError(null)
    setResult(null)
    setPhase(null)
    try {
      const normalizedHost = normalizeHost(host)
      const params = {
        host: normalizedHost,
        site,
        verify_ssl: verifySsl,
        controller_type: controllerType,
      }

      if (isSelfHosted) {
        if (useSavedCredentials) {
          params.use_saved_credentials = true
        } else {
          params.username = username.trim()
          params.password = password
        }
      } else {
        if (envApiKey) {
          params.use_env_key = true
        } else if (useSaved) {
          params.use_saved_key = true
        } else {
          params.api_key = apiKey.trim()
        }
      }

      const res = await testUniFiConnection(params)
      if (res.success) {
        setResult(res)
        setPhase('connected')
        timeoutRef.current = setTimeout(() => {
          setPhase('fetching')
          onSuccess({
            host: normalizedHost,
            site,
            verify_ssl: verifySsl,
            use_env_key: !!envApiKey,
            controller_type: controllerType,
            controller_name: res.controller_name,
            version: res.version,
            site_name: res.site_name,
          })
        }, 1500)
      } else {
        setPhase(null)
        setError(res.error || 'Connection failed')
      }
    } catch (err) {
      setPhase(null)
      setError(err.message || 'Connection failed')
    } finally {
      setTesting(false)
    }
  }

  return (
    <div>
      <h2 className="text-xl font-semibold text-gray-200 mb-2">Connect to UniFi Controller</h2>
      <p className="text-sm text-gray-400 mb-4">
        Optional — enables auto-detection of WAN &amp; network config, device name resolution{!isSelfHosted && ', and firewall management'}
      </p>

      {/* Controller type selector */}
      <div className="mb-4">
        <label className="block text-xs font-medium text-gray-300 mb-2">Controller Type</label>
        <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-gray-900 border border-gray-700">
          <button
            type="button"
            onClick={() => handleTypeChange('unifi_os')}
            className={`px-3 py-2 rounded-md text-xs font-medium transition-colors ${
              !isSelfHosted
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            Cloud Gateway (UniFi OS)
          </button>
          <button
            type="button"
            onClick={() => handleTypeChange('self_hosted')}
            className={`px-3 py-2 rounded-md text-xs font-medium transition-colors ${
              isSelfHosted
                ? 'bg-gray-700 text-white'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            Local Gateway (Self-Hosted)
          </button>
        </div>
      </div>

      {envApiKey && !isSelfHosted && (
        <div className="mb-4 px-3 py-2 rounded bg-blue-500/10 border border-blue-500/30 text-xs text-blue-400">
          API key detected from environment variable
        </div>
      )}

      <div className="space-y-3 p-4 rounded-lg border border-gray-700 bg-gray-950">
        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">UniFi Gateway/Controller IP</label>
          <input
            type="text"
            value={host}
            onChange={e => { setHost(e.target.value); setResult(null); setError(null) }}
            placeholder={isSelfHosted ? '192.168.1.1:8443' : '192.168.1.1'}
            disabled={!!envHost}
            className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none disabled:opacity-50"
          />
          {envHost && (
            <p className="text-xs text-gray-500 mt-1">Set by UNIFI_HOST environment variable</p>
          )}
        </div>

        {/* Credential fields — conditional on controller type */}
        {isSelfHosted ? (
          <div className="space-y-3">
            {useSavedCredentials ? (
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">Credentials</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 px-3 py-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-400">
                    &#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022; (saved)
                  </div>
                  <button
                    onClick={() => { setUseSavedCredentials(false); setResult(null); setError(null) }}
                    className="px-3 py-2 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors whitespace-nowrap"
                  >
                    Change
                  </button>
                </div>
              </div>
            ) : (
              <>
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={e => { setUsername(e.target.value); setResult(null); setError(null) }}
                    placeholder="admin"
                    autoComplete="username"
                    className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={e => { setPassword(e.target.value); setResult(null); setError(null) }}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none"
                  />
                </div>
                {savedUsername && !username.trim() && (
                  <button
                    onClick={() => { setUseSavedCredentials(true); setResult(null); setError(null) }}
                    className="text-xs text-blue-400 hover:text-blue-300"
                  >
                    Use saved credentials
                  </button>
                )}
              </>
            )}
            <p className="text-xs text-gray-500 mt-1">
              Self-hosted controllers require username/password authentication
            </p>
          </div>
        ) : !envApiKey ? (
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">API Key</label>
            {useSaved ? (
              <div className="flex items-center gap-2">
                <div className="flex-1 px-3 py-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-400">
                  &#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022; (saved)
                </div>
                <button
                  onClick={() => { setUseSaved(false); setResult(null); setError(null) }}
                  className="px-3 py-2 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors whitespace-nowrap"
                >
                  Change
                </button>
              </div>
            ) : (
              <>
                <input
                  type="password"
                  value={apiKey}
                  onChange={e => { setApiKey(e.target.value); setResult(null); setError(null) }}
                  placeholder="Enter your UniFi API key"
                  className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none"
                />
                {savedApiKey && !apiKey.trim() && (
                  <button
                    onClick={() => { setUseSaved(true); setResult(null); setError(null) }}
                    className="text-xs text-blue-400 hover:text-blue-300 mt-1"
                  >
                    Use saved key
                  </button>
                )}
              </>
            )}
            <p className="text-xs text-gray-500 mt-1">
              Network &rarr; Settings &rarr; Control Plane &rarr; Integrations &rarr; Your API Keys &rarr; Create API Key
              {host.trim() && (
                <>
                  {' '}&mdash;{' '}
                  <a
                    href={`${normalizeHost(host.trim())}/network/default/settings/control-plane/integrations`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 underline"
                  >
                    Take me there
                  </a>
                </>
              )}
            </p>
          </div>
        ) : null}

        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-xs text-gray-400 hover:text-gray-300 flex items-center gap-1"
        >
          <span>{showAdvanced ? '\u25BE' : '\u25B8'}</span> Advanced
        </button>

        {showAdvanced && (
          <div className="space-y-3 pl-3 border-l border-gray-700">
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1">Site</label>
              <input
                type="text"
                value={site}
                onChange={e => setSite(e.target.value)}
                className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 focus:border-teal-500 focus:outline-none"
              />
            </div>
            <label className="flex items-center gap-2 text-xs text-gray-300">
              <input
                type="checkbox"
                checked={!verifySsl}
                onChange={e => setVerifySsl(!e.target.checked)}
                className="ui-checkbox"
              />
              Skip SSL verification (for self-signed certificates)
            </label>
          </div>
        )}

        {error && (
          <div className="px-3 py-2 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">
            {error}
          </div>
        )}

        {result && result.success && (
          <div className="px-3 py-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400">
            {phase === 'fetching' ? (
              <span className="flex items-center gap-2">
                <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" opacity="0.3" />
                  <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                </svg>
                Retrieving configuration...
              </span>
            ) : (
              <>Connected to {result.controller_name} (v{result.version})</>
            )}
          </div>
        )}

        {result?.warning && (
          <div className="mt-2 px-3 py-2 rounded bg-amber-500/10 border border-amber-500/30 text-xs text-amber-400">
            {result.warning}
          </div>
        )}

      </div>

      {/* Action row */}
      <div className="flex items-center justify-between mt-3">
        {onSkip ? (
          <button
            onClick={onSkip}
            className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
          >
            Skip &mdash; Use Log Detection Instead
          </button>
        ) : <span />}
        {!(result && result.success) && (
          <button
            onClick={handleTest}
            disabled={testing || !host.trim() || !hasCredentials}
            className="px-3 py-1.5 rounded text-xs font-medium bg-teal-600 hover:bg-teal-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {testing ? 'Testing...' : 'Test & Connect'}
          </button>
        )}
      </div>
    </div>
  )
}
