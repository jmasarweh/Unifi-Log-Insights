import { useState } from 'react'
import { authLogin } from '../api'

const INPUT_CLS = 'w-full rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 placeholder:text-slate-400 shadow-sm transition focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/15'

// Login only renders after authStatus resolves (authState === 'login'),
// so isHttps is always true or false, never undefined. No guard needed.
// Post-unmount state updates are harmless in React 18 (no warning).
// PropTypes not used in this project.
export default function Login({ onSuccess, isHttps, proxyTrusted, theme, version }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const isDark = theme === 'dark'

  const handleSubmit = async (e) => {
    e.preventDefault()
    // Password is intentionally not trimmed — leading/trailing whitespace may be
    // part of the password. Only username is trimmed.
    if (!username.trim() || !password) return
    setError('')
    setLoading(true)
    try {
      await authLogin(username.trim(), password)
      onSuccess()
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={`flex min-h-dvh items-center justify-center px-4 py-8 ${isDark ? 'bg-[radial-gradient(circle_at_top,_#1e293b_0%,_#0f172a_52%,_#020617_100%)]' : 'bg-[radial-gradient(circle_at_top,_#f8fbfd_0%,_#edf2f7_52%,_#e2e8f0_100%)]'}`}>
      <div className="w-full max-w-5xl">
        {isHttps === false && (
          <div className={`mb-4 rounded-2xl px-4 py-3 text-sm shadow-sm ${isDark ? 'border border-amber-500/30 bg-amber-500/10 text-amber-300' : 'border border-amber-300 bg-amber-50 text-amber-900'}`}>
            {proxyTrusted === false
              ? 'Unable to verify a secure connection. Your reverse proxy may not be sending the required X-ULI-Proxy-Auth header. Check the authentication docs for proxy configuration.'
              : 'Authentication requires HTTPS. Please access the app through a reverse proxy with TLS enabled.'}
          </div>
        )}

        <div className={`overflow-hidden rounded-2xl shadow-[0_24px_60px_rgba(15,23,42,0.12)] ${isDark ? 'border border-slate-800 bg-slate-950 shadow-[0_28px_80px_rgba(2,6,23,0.55)]' : 'border border-slate-200 bg-white'}`}>
          <div className="grid md:grid-cols-[0.92fr_1.08fr]">
            <div className={`relative flex min-h-[320px] items-center justify-center px-10 py-12 md:min-h-[430px] md:border-b-0 md:border-r ${isDark ? 'border-b border-slate-800 bg-[linear-gradient(180deg,_rgba(15,23,42,0.98)_0%,_rgba(15,23,42,0.94)_55%,_rgba(2,6,23,1)_100%)]' : 'border-b border-slate-200 bg-[linear-gradient(180deg,_rgba(240,249,255,0.9)_0%,_rgba(255,255,255,1)_52%,_rgba(248,250,252,1)_100%)]'}`}>
              <div className={`absolute inset-x-10 top-8 h-px bg-gradient-to-r from-transparent ${isDark ? 'via-teal-500/40' : 'via-teal-200'} to-transparent`} aria-hidden="true" />
              <div className="text-center">
                <div className="mb-8 flex justify-center">
                  <svg viewBox="0 0 100 116" className="h-28 w-24 drop-shadow-[0_18px_34px_rgba(13,148,136,0.12)]" fill="none" role="img" aria-label="Insights Plus logo">
                    <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68 Z" fill="#14b8a6" fillOpacity="0.12"/>
                    <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round" fill="none"/>
                    <path d="M 28 34 A 18 18 0 0 1 44 22" stroke="#14b8a6" strokeWidth="4.8" strokeLinecap="round" fill="none" opacity="0.7"/>
                    <line x1="28" y1="75" x2="72" y2="75" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
                    <line x1="36" y1="84" x2="64" y2="84" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
                    <text x="50" y="110" textAnchor="middle" fontFamily="-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif" fontWeight="800" fontSize="19" letterSpacing="0.16em" fill="#0d9488">PLUS</text>
                  </svg>
                </div>
                <div className="space-y-3">
                  <p className={`text-4xl font-black tracking-[0.08em] ${isDark ? 'text-slate-100' : 'text-slate-700'}`}>Insights Plus</p>
                  <div className="flex items-center justify-center">
                    <div className={`w-fit border-t px-6 pt-3 text-sm font-semibold uppercase tracking-[0.35em] ${isDark ? 'border-slate-700 text-slate-400' : 'border-slate-300 text-slate-500'}`}>UniFi SIEM</div>
                  </div>
                </div>
                <p className={`mt-8 text-sm font-medium ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>{version ? `v${version}` : '\u00A0'}</p>
              </div>
            </div>

            <div className="flex items-center px-6 py-8 sm:px-10 md:px-12">
              <div className="w-full max-w-md">
                <h1 className={`text-[2rem] font-semibold tracking-tight ${isDark ? 'text-slate-100' : 'text-slate-800'}`}>Login to your account</h1>
                <p className={`mt-2 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Use your local Insights Plus credentials to continue.</p>

                <form onSubmit={handleSubmit} className="mt-8">
                  <div className="space-y-5">
                    <div>
                      <label htmlFor="login-username" className={`mb-2 block text-sm font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>
                        Username
                      </label>
                      <input
                        id="login-username"
                        type="text"
                        value={username}
                        onChange={e => setUsername(e.target.value)}
                        placeholder="Username"
                        aria-label="Username"
                        disabled={!isHttps || loading}
                        autoFocus={isHttps}
                        autoComplete="username"
                        className={`${isDark ? 'w-full rounded-md border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 shadow-sm transition focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20 disabled:cursor-not-allowed disabled:bg-slate-900/70 disabled:text-slate-500' : `${INPUT_CLS} disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400`}`}
                      />
                    </div>
                    <div>
                      <label htmlFor="login-password" className={`mb-2 block text-sm font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>
                        Password
                      </label>
                      <input
                        id="login-password"
                        type="password"
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        placeholder="Password"
                        aria-label="Password"
                        disabled={!isHttps || loading}
                        autoComplete="current-password"
                        className={`${isDark ? 'w-full rounded-md border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 shadow-sm transition focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20 disabled:cursor-not-allowed disabled:bg-slate-900/70 disabled:text-slate-500' : `${INPUT_CLS} disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400`}`}
                      />
                    </div>
                  </div>

                  {error && (
                    <p className={`mt-4 rounded-md px-3 py-2 text-sm ${isDark ? 'border border-rose-500/30 bg-rose-500/10 text-rose-300' : 'border border-rose-200 bg-rose-50 text-rose-700'}`} role="alert">{error}</p>
                  )}

                  <button
                    type="submit"
                    disabled={!isHttps || loading || !username.trim() || !password}
                    className="mt-6 w-full rounded-md bg-teal-500 px-4 py-3 text-sm font-semibold text-white shadow-[0_12px_24px_rgba(20,184,166,0.22)] transition hover:bg-teal-400 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500 disabled:shadow-none"
                  >
                    {loading ? 'Signing in...' : 'Sign in'}
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
