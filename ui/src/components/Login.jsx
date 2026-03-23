import { useState } from 'react'
import { authLogin } from '../api'

const INPUT_CLS = 'w-full rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 placeholder:text-slate-400 shadow-sm transition focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/15 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400'
const DARK_INPUT_CLS = 'w-full rounded-md border border-zinc-800 bg-black px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-500 shadow-sm transition focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20 disabled:cursor-not-allowed disabled:bg-black/70 disabled:text-zinc-600'

// Login only renders after authStatus resolves (authState === 'login'),
// so isHttps is always true or false, never undefined. No guard needed.
// Post-unmount state updates are harmless in React 18 (no warning).
// PropTypes not used in this project.
export default function Login({ onSuccess, isHttps, proxyTrusted, isEmbedded, theme, version }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
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
    <div className={`flex min-h-dvh items-center justify-center px-4 py-8 ${isDark ? 'bg-[radial-gradient(circle_at_top,_#18181b_0%,_#09090b_52%,_#000000_100%)]' : 'bg-[radial-gradient(circle_at_top,_#f8fbfd_0%,_#edf2f7_52%,_#e2e8f0_100%)]'}`}>
      <div className="w-full max-w-5xl">
        {isHttps === false && (
          <div className={`mb-4 rounded-2xl px-4 py-3 text-sm shadow-sm ${isDark ? 'border border-amber-500/30 bg-amber-500/10 text-amber-300' : 'border border-amber-300 bg-amber-50 text-amber-900'}`}>
            {proxyTrusted === false
              ? isEmbedded
                ? 'Unable to verify a secure connection. Your browser extension may still be configured to use HTTP. Update the extension\'s server URL to use HTTPS, or check your reverse proxy configuration.'
                : 'Unable to verify a secure connection. Your reverse proxy may not be sending the required X-ULI-Proxy-Auth header. Check the authentication docs for proxy configuration.'
              : 'Authentication requires HTTPS. Please access the app through a reverse proxy with TLS enabled.'}
          </div>
        )}

        <div className={`overflow-hidden rounded-2xl shadow-[0_24px_60px_rgba(15,23,42,0.12)] ${isDark ? 'border border-zinc-800 bg-black shadow-[0_28px_80px_rgba(0,0,0,0.62)]' : 'border border-slate-200 bg-white'}`}>
          <div className="grid md:grid-cols-[0.92fr_1.08fr]">
            <div className={`relative flex min-h-[320px] items-center justify-center px-10 py-12 md:min-h-[430px] md:border-b-0 md:border-r ${isDark ? 'border-b border-zinc-800 bg-[linear-gradient(180deg,_rgba(24,24,27,0.98)_0%,_rgba(10,10,10,0.96)_55%,_rgba(0,0,0,1)_100%)]' : 'border-b border-slate-200 bg-[linear-gradient(180deg,_rgba(240,249,255,0.9)_0%,_rgba(255,255,255,1)_52%,_rgba(248,250,252,1)_100%)]'}`}>
              <div className={`absolute inset-x-10 top-8 h-px bg-gradient-to-r from-transparent ${isDark ? 'via-zinc-700' : 'via-teal-200'} to-transparent`} aria-hidden="true" />
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
                  <p className={`text-4xl font-black tracking-[0.08em] ${isDark ? 'text-zinc-100' : 'text-slate-700'}`}>Insights Plus</p>
                  <div className="flex items-center justify-center">
                    <div className={`w-fit border-t px-6 pt-3 text-sm font-semibold uppercase tracking-[0.35em] ${isDark ? 'border-zinc-700 text-zinc-400' : 'border-slate-300 text-slate-500'}`}>UniFi SIEM</div>
                  </div>
                </div>
                <p className={`mt-8 text-sm font-medium ${isDark ? 'text-zinc-500' : 'text-slate-400'}`}>{version ? `v${version}` : '\u00A0'}</p>
              </div>
            </div>

            <div className="flex items-center px-6 py-8 sm:px-10 md:px-12">
              <div className="w-full max-w-md">
                <h1 className={`text-[2rem] font-semibold tracking-tight ${isDark ? 'text-zinc-100' : 'text-slate-800'}`}>Login to your account</h1>
                <p className={`mt-2 text-sm ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>Use your local Insights Plus credentials to continue.</p>

                <form onSubmit={handleSubmit} className="mt-8">
                  <div className="space-y-5">
                    <div>
                      <label htmlFor="login-username" className={`mb-2 block text-sm font-semibold ${isDark ? 'text-zinc-200' : 'text-slate-700'}`}>
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
                        className={isDark ? DARK_INPUT_CLS : INPUT_CLS}
                      />
                    </div>
                    <div>
                      <label htmlFor="login-password" className={`mb-2 block text-sm font-semibold ${isDark ? 'text-zinc-200' : 'text-slate-700'}`}>
                        Password
                      </label>
                      <div className="relative">
                        <input
                          id="login-password"
                          type={showPassword ? 'text' : 'password'}
                          value={password}
                          onChange={e => setPassword(e.target.value)}
                          placeholder="Password"
                          aria-label="Password"
                          disabled={!isHttps || loading}
                          autoComplete="current-password"
                          className={`${isDark ? DARK_INPUT_CLS : INPUT_CLS} pr-10`}
                        />
                        <button type="button" disabled={!isHttps || loading} onClick={() => setShowPassword(v => !v)} aria-label={showPassword ? 'Hide password' : 'Show password'} className={`absolute inset-y-0 right-0 flex items-center pr-3 transition-colors ${isDark ? 'text-zinc-500 hover:text-zinc-300' : 'text-slate-400 hover:text-slate-600'} disabled:opacity-40 disabled:cursor-not-allowed`}>
                          {showPassword ? (
                            <svg className="w-4 h-4" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12c1.292 4.338 5.31 7.5 10.066 7.5.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                          ) : (
                            <svg className="w-4 h-4" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" /></svg>
                          )}
                        </button>
                      </div>
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
