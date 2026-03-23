import { useCallback, useEffect, useState } from 'react'
import { fetchAuthStatus, fetchAuthMe, authChangePassword, authSetup, updateSessionTtl, fetchProxyToken } from '../api'
import CopyButton from './CopyButton'

const INPUT_CLS = 'w-full px-3 py-1.5 bg-black border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20'

export default function SettingsSecurity({ onAuthEnabled }) {
  const [authStatus, setAuthStatus] = useState(null)
  const [me, setMe] = useState(null)
  const [loading, setLoading] = useState(true)

  // Change password
  const [showPwChange, setShowPwChange] = useState(false)
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [pwSaving, setPwSaving] = useState(false)
  const [pwStatus, setPwStatus] = useState(null) // { type: 'saved'|'error', text }
  const [showCurrentPw, setShowCurrentPw] = useState(false)
  const [showNewPw, setShowNewPw] = useState(false)
  const [showConfirmPw, setShowConfirmPw] = useState(false)

  // Enable auth (first-user setup)
  const [setupUser, setSetupUser] = useState('admin')
  const [setupPw, setSetupPw] = useState('')
  const [setupConfirm, setSetupConfirm] = useState('')
  const [setupSaving, setSetupSaving] = useState(false)
  const [setupStatus, setSetupStatus] = useState(null) // { type: 'saved'|'error', text }
  const [showSetupPw, setShowSetupPw] = useState(false)
  const [showSetupConfirm, setShowSetupConfirm] = useState(false)

  // Session duration
  const [sessionTtl, setSessionTtl] = useState(168)
  const [ttlSaving, setTtlSaving] = useState(false)
  const [ttlStatus, setTtlStatus] = useState(null) // 'saved' | 'error'

  // Proxy trust token
  const [proxyToken, setProxyToken] = useState(null)

  const reload = useCallback(async function reload() {
    setLoading(true)
    try {
      const [status, meResp] = await Promise.allSettled([
        fetchAuthStatus(),
        fetchAuthMe(),
      ])
      setProxyToken(null)
      if (status.status === 'fulfilled') {
        setAuthStatus(status.value)
        if (status.value.session_ttl_hours) setSessionTtl(status.value.session_ttl_hours)
        // Load proxy token from admin-only endpoint (post-auth only)
        if (status.value.auth_enabled_effective) {
          try {
            const tokenResp = await fetchProxyToken()
            setProxyToken(tokenResp.token)
          } catch (err) {
            // 401/403 expected for non-admin users — only log unexpected errors.
            const errStatus = err?.status
            if (errStatus !== 401 && errStatus !== 403 && err?.message !== 'Session expired') {
              console.error('Failed to fetch proxy token:', err)
            }
          }
        }
      }
      if (meResp.status === 'fulfilled') setMe(meResp.value)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { reload() }, [reload])

  async function handleChangePassword(e) {
    e.preventDefault()
    setPwStatus(null)
    if (newPw !== confirmPw) { setPwStatus({ type: 'error', text: 'Passwords do not match' }); return }
    if (newPw.length < 8) { setPwStatus({ type: 'error', text: 'Password must be at least 8 characters' }); return }
    setPwSaving(true)
    try {
      await authChangePassword(currentPw, newPw)
      setPwStatus({ type: 'saved', text: 'Password changed' })
      setShowPwChange(false)
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
    } catch (err) {
      setPwStatus({ type: 'error', text: err.message || 'Failed to change password' })
    } finally {
      setPwSaving(false)
    }
  }

  async function handleEnableAuth(e) {
    e.preventDefault()
    setSetupStatus(null)
    if (setupPw !== setupConfirm) { setSetupStatus({ type: 'error', text: 'Passwords do not match' }); return }
    if (setupPw.length < 8) { setSetupStatus({ type: 'error', text: 'Password must be at least 8 characters' }); return }
    if (!setupUser.trim()) { setSetupStatus({ type: 'error', text: 'Username is required' }); return }
    setSetupSaving(true)
    try {
      await authSetup(setupUser.trim(), setupPw)
      setSetupUser('')
      setSetupPw('')
      setSetupConfirm('')
      onAuthEnabled?.()
      reload()
    } catch (err) {
      setSetupStatus({ type: 'error', text: err.message || 'Setup failed' })
    } finally {
      setSetupSaving(false)
    }
  }

  async function handleSaveSessionTtl() {
    setTtlSaving(true)
    setTtlStatus(null)
    try {
      await updateSessionTtl(sessionTtl)
      setAuthStatus(prev => ({ ...prev, session_ttl_hours: sessionTtl }))
      setTtlStatus('saved')
    } catch (err) {
      console.error('Failed to save session TTL:', err)
      setTtlStatus('error')
    } finally {
      setTtlSaving(false)
    }
  }

  function handleCancelPwChange() {
    setShowPwChange(false)
    setCurrentPw('')
    setNewPw('')
    setConfirmPw('')
    setPwStatus(null)
  }

  if (loading) return (
    <div className="space-y-8">
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Authentication</h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950 px-4 py-3 animate-pulse">
          <div className="flex items-center justify-between">
            <div className="h-4 w-32 bg-gray-800 rounded" />
            <div className="h-4 w-16 bg-gray-800 rounded" />
          </div>
        </div>
      </section>
    </div>
  )

  const authEnabled = authStatus?.auth_enabled_effective

  return (
    <div className="space-y-8">
      <section>
        <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Authentication</h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          {/* Status */}
          <div className="px-4 py-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-200 font-medium">
                {authEnabled ? 'Authentication' : 'Authentication disabled'}
              </span>
              <span className={`flex items-center gap-1.5 text-sm leading-none ${authEnabled ? 'text-emerald-400' : 'text-gray-500'}`}>
                <span className={`w-1.5 h-1.5 rounded-full block ${authEnabled ? 'bg-emerald-400' : 'bg-gray-500'}`} />
                {authEnabled ? 'Active' : 'Inactive'}
              </span>
            </div>
            {!authEnabled && (
              <p className="mt-2 text-sm text-gray-500">
                Set <code className="px-1 py-0.5 bg-gray-800 rounded text-gray-400 text-sm">AUTH_ENABLED=true</code> in your <code className="px-1 py-0.5 bg-gray-800 rounded text-gray-400 text-sm">.env</code> or <code className="px-1 py-0.5 bg-gray-800 rounded text-gray-400 text-sm">docker-compose.yml</code> and restart the container.
              </p>
            )}
          </div>

          {!authEnabled && !authStatus?.has_admin && (
            <>
              <div className="border-t border-gray-800" />
              <div className="p-5">
                {authStatus?.is_https ? (
                  <>
                  <form onSubmit={handleEnableAuth} className="space-y-3 max-w-sm">
                    <p className="text-sm text-gray-500 mb-3">Create an admin account to enable authentication and protect your instance.</p>
                    <input
                      type="text"
                      placeholder="Username"
                      value={setupUser}
                      onChange={e => setSetupUser(e.target.value)}
                      disabled={setupSaving}
                      autoComplete="username"
                      className={`${INPUT_CLS} disabled:opacity-50`}
                    />
                    <div className="relative">
                      <input
                        type={showSetupPw ? 'text' : 'password'}
                        placeholder="Password (min 8 characters)"
                        value={setupPw}
                        onChange={e => setSetupPw(e.target.value)}
                        disabled={setupSaving}
                        autoComplete="new-password"
                        className={`${INPUT_CLS} disabled:opacity-50 pr-10`}
                      />
                      <button type="button" onClick={() => setShowSetupPw(v => !v)} aria-label={showSetupPw ? 'Hide password' : 'Show password'} className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-300 transition-colors">
                        {showSetupPw ? (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12c1.292 4.338 5.31 7.5 10.066 7.5.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" /></svg>
                        )}
                      </button>
                    </div>
                    <div className="relative">
                      <input
                        type={showSetupConfirm ? 'text' : 'password'}
                        placeholder="Confirm password"
                        value={setupConfirm}
                        onChange={e => setSetupConfirm(e.target.value)}
                        disabled={setupSaving}
                        autoComplete="new-password"
                        className={`${INPUT_CLS} disabled:opacity-50 pr-10`}
                      />
                      <button type="button" onClick={() => setShowSetupConfirm(v => !v)} aria-label={showSetupConfirm ? 'Hide password' : 'Show password'} className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-300 transition-colors">
                        {showSetupConfirm ? (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12c1.292 4.338 5.31 7.5 10.066 7.5.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" /></svg>
                        )}
                      </button>
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        type="submit"
                        disabled={setupSaving || !setupUser.trim() || setupPw.length < 8 || setupPw !== setupConfirm}
                        className="px-4 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        {setupSaving ? 'Creating account...' : 'Enable Authentication'}
                      </button>
                      {setupStatus?.type === 'error' && (
                        <span className="text-sm text-red-400">{setupStatus.text}</span>
                      )}
                    </div>
                  </form>
                  <div className="mt-4 p-3 rounded bg-blue-500/10 border border-blue-500/30 text-sm text-blue-300">
                    <p className="font-medium text-blue-300">Before enabling authentication, please read:</p>
                    <ul className="mt-1.5 list-disc list-inside space-y-1">
                      <li>
                        <a href="https://insightsplus.dev/docs/authentication" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors">
                          Authentication guide
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                        </a>
                        {' '}&mdash; HTTPS/proxy requirements, session management, API tokens
                      </li>
                      <li>
                        <a href="https://insightsplus.dev/docs/browser-extension" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors">
                          Browser extension setup
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                        </a>
                        {' '}&mdash; token configuration, HTTPS requirement, extension compatibility
                      </li>
                    </ul>
                  </div>
                  </>
                ) : window.location.protocol === 'https:' && authStatus?.proxy_token ? (
                    <div className="space-y-4">
                      <div className="flex items-center gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                        <svg className="w-4 h-4 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                        </svg>
                        <p className="text-sm text-yellow-400/90">
                          HTTPS detected but not reaching the app. Your reverse proxy needs to forward the <code className="px-1 py-0.5 bg-yellow-500/15 rounded text-yellow-300 text-sm">X-ULI-Proxy-Auth</code> header.
                        </p>
                      </div>

                      <div className="space-y-2">
                        <p className="text-sm text-gray-200 font-medium">Your proxy token</p>
                        <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                          <pre className="text-sm text-gray-300 font-mono whitespace-pre select-all">{authStatus.proxy_token}</pre>
                        </div>
                        <div className="flex items-center justify-end gap-1.5">
                          <span className="text-sm text-gray-300">Copy token</span>
                          <CopyButton text={authStatus.proxy_token} color="text-teal-400 hover:text-teal-300" className="ml-0" />
                        </div>
                      </div>

                      <details className="group">
                        <summary className="flex items-center gap-1 cursor-pointer text-sm font-medium text-gray-300 list-none">
                          <span className="transition-transform group-open:rotate-90">&#x25B8;</span> Proxy configuration examples
                        </summary>
                        <div className="mt-2 space-y-3">
                          <div className="space-y-1.5">
                            <p className="text-sm text-gray-400">Nginx</p>
                            <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                              <pre className="text-sm text-gray-300 font-mono whitespace-pre">{`proxy_set_header X-ULI-Proxy-Auth "${authStatus.proxy_token}";`}</pre>
                            </div>
                            <div className="flex items-center justify-end gap-1.5">
                              <span className="text-sm text-gray-300">Copy</span>
                              <CopyButton text={`proxy_set_header X-ULI-Proxy-Auth "${authStatus.proxy_token}";`} color="text-teal-400 hover:text-teal-300" className="ml-0" />
                            </div>
                          </div>
                          <div className="space-y-1.5">
                            <p className="text-sm text-gray-400">Caddy</p>
                            <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                              <pre className="text-sm text-gray-300 font-mono whitespace-pre">{`header_up X-ULI-Proxy-Auth "${authStatus.proxy_token}"`}</pre>
                            </div>
                            <div className="flex items-center justify-end gap-1.5">
                              <span className="text-sm text-gray-300">Copy</span>
                              <CopyButton text={`header_up X-ULI-Proxy-Auth "${authStatus.proxy_token}"`} color="text-teal-400 hover:text-teal-300" className="ml-0" />
                            </div>
                          </div>
                          <div className="space-y-1.5">
                            <p className="text-sm text-gray-400">Traefik</p>
                            <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                              <pre className="text-sm text-gray-300 font-mono whitespace-pre">{`- "traefik.http.middlewares.uli-auth.headers.customrequestheaders.X-ULI-Proxy-Auth=${authStatus.proxy_token}"`}</pre>
                            </div>
                            <div className="flex items-center justify-end gap-1.5">
                              <span className="text-sm text-gray-300">Copy</span>
                              <CopyButton text={`traefik.http.middlewares.uli-auth.headers.customrequestheaders.X-ULI-Proxy-Auth=${authStatus.proxy_token}`} color="text-teal-400 hover:text-teal-300" className="ml-0" />
                            </div>
                          </div>
                        </div>
                      </details>

                      <p className="text-sm text-gray-500">
                        Add the header to your reverse proxy config, then refresh this page.{' '}
                        <a href="https://insightsplus.dev/docs/authentication#reverse-proxy" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-gray-400 hover:text-gray-300 transition-colors">
                          Full guide
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                        </a>
                      </p>
                    </div>
                  ) : (
                    <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                      <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                      </svg>
                      <p className="text-sm text-yellow-400/90">Enabling authentication requires HTTPS. Please access the app through a reverse proxy with TLS enabled.</p>
                    </div>
                  )
                }
              </div>
            </>
          )}

          {authEnabled && me && (
            <>
              <div className="border-t border-gray-800" />
              <div className="p-5 space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-gray-500">Signed in as:</span>
                  <span className="text-gray-200 font-medium">{me.username}</span>
                  <span className="px-1.5 py-0.5 text-xs rounded bg-gray-800 text-gray-400">{me.role || 'user'}</span>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => { setShowPwChange(!showPwChange); setPwStatus(null) }}
                    className="px-3 py-1.5 rounded text-sm font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
                  >
                    Change password
                  </button>
                  {!showPwChange && pwStatus?.type === 'saved' && (
                    <span className="text-sm text-emerald-400">{pwStatus.text}</span>
                  )}
                </div>

                {showPwChange && (
                  <form onSubmit={handleChangePassword} className="mt-3 space-y-3 max-w-sm">
                    <div className="relative">
                      <input
                        type={showCurrentPw ? 'text' : 'password'}
                        placeholder="Current password"
                        value={currentPw}
                        onChange={e => setCurrentPw(e.target.value)}
                        required
                        className={`${INPUT_CLS} pr-10`}
                      />
                      <button type="button" onClick={() => setShowCurrentPw(v => !v)} aria-label={showCurrentPw ? 'Hide password' : 'Show password'} className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-300 transition-colors">
                        {showCurrentPw ? (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12c1.292 4.338 5.31 7.5 10.066 7.5.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" /></svg>
                        )}
                      </button>
                    </div>
                    <div className="relative">
                      <input
                        type={showNewPw ? 'text' : 'password'}
                        placeholder="New password (min 8 characters)"
                        value={newPw}
                        onChange={e => setNewPw(e.target.value)}
                        required
                        minLength={8}
                        className={`${INPUT_CLS} pr-10`}
                      />
                      <button type="button" onClick={() => setShowNewPw(v => !v)} aria-label={showNewPw ? 'Hide password' : 'Show password'} className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-300 transition-colors">
                        {showNewPw ? (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12c1.292 4.338 5.31 7.5 10.066 7.5.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" /></svg>
                        )}
                      </button>
                    </div>
                    <div className="relative">
                      <input
                        type={showConfirmPw ? 'text' : 'password'}
                        placeholder="Confirm new password"
                        value={confirmPw}
                        onChange={e => setConfirmPw(e.target.value)}
                        required
                        className={`${INPUT_CLS} pr-10`}
                      />
                      <button type="button" onClick={() => setShowConfirmPw(v => !v)} aria-label={showConfirmPw ? 'Hide password' : 'Show password'} className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-300 transition-colors">
                        {showConfirmPw ? (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12c1.292 4.338 5.31 7.5 10.066 7.5.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" /></svg>
                        )}
                      </button>
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        type="submit"
                        disabled={pwSaving}
                        className="px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-sm rounded disabled:opacity-50 transition-colors"
                      >
                        {pwSaving ? 'Saving...' : 'Update Password'}
                      </button>
                      <button
                        type="button"
                        onClick={handleCancelPwChange}
                        className="px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors"
                      >
                        Cancel
                      </button>
                      {pwStatus?.type === 'error' && (
                        <span className="text-sm text-red-400">{pwStatus.text}</span>
                      )}
                    </div>
                  </form>
                )}
              </div>
            </>
          )}
        </div>
      </section>

      {authEnabled && (
        <section>
          <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Session Duration</h2>
          <div className="rounded-lg border border-gray-700 bg-gray-950">
            <div className="p-5">
              <div className="flex items-center gap-3 max-w-sm">
                <select
                  value={sessionTtl}
                  onChange={e => { setSessionTtl(Number(e.target.value)); setTtlStatus(null) }}
                  className="px-3 py-1.5 bg-black border border-gray-700 rounded text-sm text-gray-200 focus:outline-none focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20"
                >
                  <option value={1}>1 hour</option>
                  <option value={4}>4 hours</option>
                  <option value={8}>8 hours</option>
                  <option value={24}>1 day</option>
                  <option value={72}>3 days</option>
                  <option value={168}>7 days</option>
                  <option value={720}>30 days</option>
                </select>
                <button
                  onClick={handleSaveSessionTtl}
                  disabled={ttlSaving || sessionTtl === authStatus?.session_ttl_hours}
                  className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                    sessionTtl !== authStatus?.session_ttl_hours
                      ? 'bg-teal-600 hover:bg-teal-500 text-white'
                      : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  }`}
                >
                  {ttlSaving ? 'Saving...' : 'Save'}
                </button>
              </div>
              <p className="mt-2 text-sm text-gray-500">How long sessions remain valid before requiring re-login. Changes apply to new sessions only.</p>
            </div>
            <div className="border-t border-gray-800" />
            <div className="px-5 py-3 flex items-center justify-between">
              <div>
                {ttlStatus === 'saved' && <span className="text-sm text-emerald-400">Session duration updated</span>}
                {ttlStatus === 'error' && <span className="text-sm text-red-400">Failed to save</span>}
              </div>
              <div /> {/* flex spacer — pushes status text left in justify-between layout */}
            </div>
          </div>
        </section>
      )}

      {proxyToken && (
        <section>
          <h2 className="text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider">Reverse Proxy Trust</h2>
          <div className="rounded-lg border border-gray-700 bg-gray-950">
            {/* Warning */}
            {!authStatus?.proxy_trusted && (
              <div className="m-5 mb-0 flex items-center gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                <svg className="w-4 h-4 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                </svg>
                <p className="text-sm text-yellow-400/90">Your reverse proxy is not sending the <span className="font-mono">X-ULI-Proxy-Auth</span> header. HTTPS detection and IP forwarding will not work until configured.</p>
              </div>
            )}

            {/* Token */}
            <div className="p-5 space-y-3">
              <p className="text-sm text-gray-400">
                Add this header to your reverse proxy so the app can verify secure connections.
              </p>
              <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                <pre className="text-sm text-gray-300 font-mono whitespace-pre select-all">{proxyToken}</pre>
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="text-sm text-gray-300">Copy token</span>
                <CopyButton text={proxyToken} color="text-teal-400 hover:text-teal-300" className="ml-0" />
              </div>
            </div>

            <div className="border-t border-gray-800" />

            {/* Proxy setup instructions — collapsible */}
            <div className="p-5">
              <details className="group">
                <summary className="flex items-center gap-1 cursor-pointer text-base font-semibold text-gray-300 mb-3 uppercase tracking-wider list-none">
                  <span className="transition-transform group-open:rotate-90">&#x25B8;</span> Proxy Setup Instructions
                </summary>
                <div className="rounded-lg border border-gray-700 bg-gray-950">
                  {/* nginx */}
                  <div className="p-5 space-y-3">
                    <div className="flex items-center gap-2">
                      <img src="/nginx-logo.png" alt="Nginx" className="w-4 h-4 shrink-0" />
                      <p className="text-base font-semibold text-gray-200">Nginx</p>
                    </div>
                    <p className="text-sm text-gray-400">
                      Add this line inside your <span className="font-mono text-gray-300">location /</span> block:
                    </p>
                    <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                      <pre className="text-sm text-gray-300 font-mono whitespace-pre">{`location / {\n    proxy_set_header X-ULI-Proxy-Auth "${proxyToken}";\n    # ... your existing proxy_pass and other headers ...\n}`}</pre>
                    </div>
                    <div className="flex items-center justify-end gap-1.5">
                      <span className="text-sm text-gray-300">Copy header line</span>
                      <CopyButton text={`proxy_set_header X-ULI-Proxy-Auth "${proxyToken}";`} color="text-teal-400 hover:text-teal-300" className="ml-0" />
                    </div>
                    <div className="flex items-center gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                      <svg className="w-4 h-4 text-yellow-400 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                      </svg>
                      <p className="text-sm text-yellow-400/90">
                        <strong>Nginx Proxy Manager:</strong> Use <strong>Custom Locations</strong> (not the Advanced tab). Add a <span className="font-mono">/</span> location and paste the header line above. The Advanced tab places headers at server level, which nginx silently drops when the location block has its own.{' '}
                        <a href="https://insightsplus.dev/docs/authentication#reverse-proxy" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 underline text-yellow-300 hover:text-yellow-200">
                          Full setup guide
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                        </a>
                      </p>
                    </div>
                  </div>

                  <div className="border-t border-gray-800" />

                  {/* Caddy */}
                  <div className="p-5 space-y-3">
                    <div className="flex items-center gap-2">
                      <img src="/caddy-logo.png" alt="Caddy" className="w-4 h-4 shrink-0" />
                      <p className="text-base font-semibold text-gray-200">Caddy</p>
                    </div>
                    <p className="text-sm text-gray-400">
                      Add <span className="font-mono text-gray-300">header_up</span> inside your <span className="font-mono text-gray-300">reverse_proxy</span> block:
                    </p>
                    <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                      <pre className="text-sm text-gray-300 font-mono whitespace-pre">{`reverse_proxy <your-host>:8090 {\n    header_up X-ULI-Proxy-Auth "${proxyToken}"\n}`}</pre>
                    </div>
                    <div className="flex items-center justify-end gap-1.5">
                      <span className="text-sm text-gray-300">Copy snippet</span>
                      <CopyButton text={`header_up X-ULI-Proxy-Auth "${proxyToken}"`} color="text-teal-400 hover:text-teal-300" className="ml-0" />
                    </div>
                  </div>

                  <div className="border-t border-gray-800" />

                  {/* Traefik */}
                  <div className="p-5 space-y-3">
                    <div className="flex items-center gap-2">
                      <img src="/traefik-logo.png" alt="Traefik" className="w-4 h-4 shrink-0" />
                      <p className="text-base font-semibold text-gray-200">Traefik</p>
                    </div>
                    <p className="text-sm text-gray-400">
                      Add these Docker labels to your service in <span className="font-mono text-gray-300">docker-compose.yml</span>:
                    </p>
                    <div className="rounded bg-black border border-gray-800 p-3 overflow-x-auto">
                      <pre className="text-sm text-gray-300 font-mono whitespace-pre">{`labels:\n  - "traefik.http.middlewares.uli-auth.headers.customrequestheaders.X-ULI-Proxy-Auth=${proxyToken}"\n  - "traefik.http.routers.<your-router>.middlewares=uli-auth"`}</pre>
                    </div>
                    <div className="flex items-center justify-end gap-1.5">
                      <span className="text-sm text-gray-300">Copy middleware label</span>
                      <CopyButton text={`traefik.http.middlewares.uli-auth.headers.customrequestheaders.X-ULI-Proxy-Auth=${proxyToken}`} color="text-teal-400 hover:text-teal-300" className="ml-0" />
                    </div>
                  </div>
                </div>
              </details>
            </div>

            {/* Help text */}
            <div className="border-t border-gray-800" />
            <div className="px-5 py-3">
              <p className="text-sm text-gray-500">
                Token derived from SECRET_KEY, POSTGRES_PASSWORD, or DB_PASSWORD (first non-empty wins). If the secret changes, update your proxy config.{' '}
                <a href="https://insightsplus.dev/docs/authentication#reverse-proxy" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 underline text-gray-400 hover:text-gray-300">
                  Full setup guide
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                </a>
              </p>
            </div>
          </div>
        </section>
      )}
    </div>
  )
}
