import React, { Suspense, useState, useEffect, useLayoutEffect, useMemo, useCallback, useRef } from 'react'
import LogStream from './components/LogStream'
import SetupWizard from './components/SetupWizard'
import SettingsOverlay from './components/SettingsOverlay'
import { DashboardSkeleton } from './components/Dashboard'
import { ThreatMapSkeleton } from './components/ThreatMap'
import FlowViewSkeleton from './components/FlowViewSkeleton'

const Dashboard = React.lazy(() => import('./components/Dashboard'))
const ThreatMap = React.lazy(() => import('./components/ThreatMap'))
const FlowView = React.lazy(() => import('./components/FlowView'))
import Login from './components/Login'
import { fetchHealth, fetchConfig, fetchLatestRelease, dismissUpgradeModal, dismissVpnToast, fetchInterfaces, fetchUiSettings, updateUiSettings, fetchUniFiSettings, fetchAuthStatus, fetchAuthMe, authLogout, setAuthExpiredHandler } from './api'
import { loadInterfaceLabels } from './utils'
import { isVpnInterface } from './vpnUtils'

function LoadingSplash() {
  return (
    <div className="flex items-center justify-center h-dvh bg-gray-950">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 116" fill="none" className="w-20 h-24">
        <style>{`
          @keyframes trace {
            0% { stroke-dashoffset: 200; }
            100% { stroke-dashoffset: 0; }
          }
          .trace-path {
            stroke-dasharray: 40 160;
            animation: trace 1.8s linear infinite;
          }
          .trace-delay-1 { animation-delay: -0.4s; }
          .trace-delay-2 { animation-delay: -0.8s; }
          .trace-delay-3 { animation-delay: -1.2s; }
          @keyframes arc-pulse {
            0%, 100% { opacity: 0.12; }
            50% { opacity: 0.7; }
          }
          .arc-pulse {
            animation: arc-pulse 2s ease-in-out infinite;
          }
        `}</style>
        {/* Static dim icon */}
        <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68" stroke="#14B8A6" strokeWidth="5.2" strokeLinecap="round" fill="none" opacity="0.15"/>
        <path d="M 28 34 A 18 18 0 0 1 44 22" stroke="#14B8A6" strokeWidth="4.8" strokeLinecap="round" fill="none" className="arc-pulse"/>
        <line x1="28" y1="75" x2="72" y2="75" stroke="#14B8A6" strokeWidth="5.2" strokeLinecap="round" opacity="0.15"/>
        <line x1="36" y1="84" x2="64" y2="84" stroke="#14B8A6" strokeWidth="5.2" strokeLinecap="round" opacity="0.15"/>
        <text x="50" y="110" textAnchor="middle" fontFamily="-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif" fontWeight="800" fontSize="19" letterSpacing="0.16em" fill="#0D9488">PLUS</text>
        {/* Animated chasing traces */}
        <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68" stroke="#14B8A6" strokeWidth="5.2" strokeLinecap="round" fill="none" className="trace-path"/>
        <path d="M 28 34 A 18 18 0 0 1 44 22" stroke="#14B8A6" strokeWidth="4.8" strokeLinecap="round" fill="none" className="trace-path trace-delay-1"/>
        <line x1="28" y1="75" x2="72" y2="75" stroke="#14B8A6" strokeWidth="5.2" strokeLinecap="round" className="trace-path trace-delay-2"/>
        <line x1="36" y1="84" x2="64" y2="84" stroke="#14B8A6" strokeWidth="5.2" strokeLinecap="round" className="trace-path trace-delay-3"/>
      </svg>
    </div>
  )
}

/** Validate an IP-like string (IPv4 dotted-decimal or IPv6 hex+colon). */
function isValidIpFormat(ip) {
  if (!ip || ip.length > 45) return false
  // IPv4: 1-3 digits separated by dots
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return true
  // IPv6: hex groups with colons (including :: compressed and mixed v4-mapped)
  if (/^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':')) return true
  return false
}
const VALID_RANGES = new Set(['1h','6h','24h','7d','30d','60d','90d','180d','365d'])

const TABS = [
  { id: 'logs', label: 'Log Stream', shortLabel: 'Stream' },
  { id: 'flow-view', label: 'Flow View', shortLabel: 'Flow' },
  { id: 'threat-map', label: 'Threat Map', shortLabel: 'Map' },
  { id: 'dashboard', label: 'Dashboard', shortLabel: 'Dashboard' },
]

function formatShortDate(isoStr) {
  if (!isoStr) return '\u2014'
  try {
    const d = new Date(isoStr)
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) +
      ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  } catch { return '\u2014' }
}

function formatAbuseIPDB(abuseipdb) {
  if (!abuseipdb) return '\u2014'

  // Check if paused (429 rate limited)
  if (abuseipdb.paused_until) {
    const pausedDate = new Date(abuseipdb.paused_until * 1000)
    if (pausedDate > new Date()) {
      const resumeStr = pausedDate.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
      return `\u23F8 Paused \u00B7 Resumes ${resumeStr}`
    }
  }

  const limit = abuseipdb.limit
  const remaining = abuseipdb.remaining
  if (limit == null || remaining == null) return '\u2014'
  const used = limit - remaining
  // reset_at from AbuseIPDB is a Unix timestamp (seconds), not ISO string
  let reset = '\u2014'
  if (abuseipdb.reset_at) {
    const ts = Number(abuseipdb.reset_at)
    const d = !isNaN(ts) && ts > 1e9 ? new Date(ts * 1000) : new Date(abuseipdb.reset_at)
    reset = isNaN(d.getTime()) ? '\u2014' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) +
      ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  }
  return `${used.toLocaleString()}/${limit.toLocaleString()} \u00B7 Reset ${reset}`
}

const isEmbedded = window.parent !== window

export default function App() {
  const [activeTab, setActiveTab] = useState(() => {
    const hash = window.location.hash.replace('#', '').split('?')[0]
    const valid = TABS.map(t => t.id)
    return valid.includes(hash) ? hash : 'logs'
  })
  const [health, setHealth] = useState(null)
  const [latestRelease, setLatestRelease] = useState(null)
  const [showWizard, setShowWizard] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const [settingsInitialSection, setSettingsInitialSection] = useState(null)
  const [settingsReconfig, setSettingsReconfig] = useState(false)
  const [config, setConfig] = useState(null)
  const [configLoaded, setConfigLoaded] = useState(false)
  const [showMigrationBanner, setShowMigrationBanner] = useState(false)
  const [showUpgradeModal, setShowUpgradeModal] = useState(false)
  const [showVpnToast, setShowVpnToast] = useState(false)
  const [mapFlyTo, setMapFlyTo] = useState(null)
  const clearMapFlyTo = useCallback(() => setMapFlyTo(null), [])
  const [logsDrill, setLogsDrill] = useState(null)
  const clearLogsDrill = useCallback(() => setLogsDrill(null), [])
  const [drillSource, setDrillSource] = useState(null)
  const activeTabRef = useRef(activeTab)
  activeTabRef.current = activeTab
  const drillSourceRef = useRef(drillSource)
  drillSourceRef.current = drillSource
  const [unlabeledVpn, setUnlabeledVpn] = useState([])
  const [allInterfaces, setAllInterfaces] = useState(null)
  const [showWanToast, setShowWanToast] = useState(false)
  const [showUnifiToast, setShowUnifiToast] = useState(false)
  const [showProxyToast, setShowProxyToast] = useState(false)
  const [theme, setTheme] = useState(() => {
    const urlTheme = new URLSearchParams(window.location.search).get('theme')
    if (urlTheme === 'light' || urlTheme === 'dark') return urlTheme
    return localStorage.getItem('ui_theme') || 'dark'
  })
  const initialThemeRef = useRef(theme)
  const [showStatusTooltip, setShowStatusTooltip] = useState(false)
  const statusRef = useRef(null)
  const [logsPaused, setLogsPaused] = useState(false)
  const onLogsPauseChange = useCallback((paused) => setLogsPaused(paused), [])
  const [uiSettings, setUiSettings] = useState(null)
  const [authState, setAuthState] = useState('loading') // 'loading', 'login', 'authenticated', 'none'
  const [authStatus, setAuthStatus] = useState(null) // response from /api/auth/status

  // Persist URL-derived theme to localStorage so Settings reads the correct value
  useEffect(() => {
    const urlTheme = new URLSearchParams(window.location.search).get('theme')
    if ((urlTheme === 'light' || urlTheme === 'dark') && localStorage.getItem('ui_theme') !== urlTheme) {
      localStorage.setItem('ui_theme', urlTheme)
    }
  }, [])

  // Fetch UI settings after auth resolves (avoids 401 when auth is enabled)
  useEffect(() => {
    if (authState === 'loading' || authState === 'login') return
    fetchUiSettings().then(data => {
      setUiSettings(data)
      if (!localStorage.getItem('ui_theme') && data.ui_theme && data.ui_theme !== initialThemeRef.current) {
        setTheme(data.ui_theme)
        localStorage.setItem('ui_theme', data.ui_theme)
      }
    }).catch(() => {})
  }, [authState]) // eslint-disable-line react-hooks/exhaustive-deps

  useLayoutEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  // Listen for messages from parent window (when embedded in UniFi iframe)
  useEffect(() => {
    if (window.parent === window) return () => {}

    // Build optional origin allowlist from document.referrer.
    // Referrer may be empty (HTTPS→HTTP downgrade strips it), so this is
    // defense-in-depth — the primary security gate is e.source === window.parent
    // (browser-guaranteed, not spoofable). Message types are harmless UI actions
    // (theme toggle, navigation to validated IPs) so no data exfiltration risk.
    const allowedOrigins = new Set()
    if (document.referrer) {
      try {
        allowedOrigins.add(new URL(document.referrer).origin)
      } catch { /* ignore malformed */ }
    }

    const handler = (e) => {
      if (e.source !== window.parent) return
      if (allowedOrigins.size > 0 && !allowedOrigins.has(e.origin)) return
      if (!e.data || !e.data.type) return
      if (e.data.type === 'uli-theme' && (e.data.theme === 'dark' || e.data.theme === 'light')) {
        setTheme(e.data.theme)
      }
      if (e.data.type === 'uli-navigate' && e.data.hash) {
        const params = new URLSearchParams(e.data.hash.split('?')[1] || '')
        const ip = params.get('ip')
        if (ip && isValidIpFormat(ip)) {
          const dir = params.get('dir')
          const ipKey = dir === 'dst' ? 'dst_ip' : 'src_ip'
          const drill = { [ipKey]: ip }
          const range = params.get('range')
          if (VALID_RANGES.has(range)) drill.time_range = range
          setLogsDrill(drill)
          setActiveTab('logs')
        }
      }
    }
    window.addEventListener('message', handler)
    return () => window.removeEventListener('message', handler)
  }, [])

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    localStorage.setItem('ui_theme', next)
    updateUiSettings({ ui_theme: next }).catch(() => {})
  }

  const reloadConfig = (prefetched) => {
    if (prefetched) {
      setConfig(prefetched)
      loadInterfaceLabels(prefetched)
      return Promise.resolve(prefetched)
    }
    return fetchConfig().then(cfg => {
      setConfig(cfg)
      loadInterfaceLabels(cfg)
      return cfg
    })
  }

  // Auth bootstrap — ref so onAuthEnabled() can also arm the 401 handler
  const bootstrapDoneRef = useRef(false)

  useEffect(() => {
    let mounted = true
    bootstrapDoneRef.current = false

    // Only activate the expired handler after bootstrap confirms auth is active.
    // Otherwise, early 401s from parallel API calls (fetchConfig, fetchHealth, etc.)
    // would prematurely flip to the login screen before authStatus is set.
    setAuthExpiredHandler(() => {
      if (mounted && bootstrapDoneRef.current) setAuthState('login')
    })

    fetchAuthStatus()
      .then(async (status) => {
        if (!mounted) return
        setAuthStatus(status)

        // Setup wizard takes priority
        if (status.setup_complete === false) {
          setAuthState('none')
          return
        }

        if (!status.auth_enabled_effective) {
          setAuthState('none')
          return
        }

        // Auth enabled, has users — check session
        try {
          const me = await fetchAuthMe()
          if (me.authenticated) {
            bootstrapDoneRef.current = true
            setAuthState('authenticated')
            // Warn if reverse proxy isn't sending X-ULI-Proxy-Auth
            if (!status.proxy_trusted && !sessionStorage.getItem('proxy_toast_dismissed')) {
              setShowProxyToast(true)
            }
          } else {
            bootstrapDoneRef.current = true
            setAuthState('login')
          }
        } catch {
          bootstrapDoneRef.current = true
          setAuthState('login')
        }
      })
      .catch(() => {
        if (mounted) setAuthState('none') // Can't reach server, proceed without auth
      })

    return () => {
      mounted = false
      setAuthExpiredHandler(null)
    }
  }, [])

  // Load config + interface labels after auth resolves
  useEffect(() => {
    if (authState === 'loading' || authState === 'login') return
    let mounted = true
    fetchConfig()
      .then(cfg => {
        if (!mounted) return
        setConfig(cfg)
        loadInterfaceLabels(cfg)
        if (cfg.setup_complete === false) {
          setShowWizard(true)
        }
        // Check for auto-migrated users (empty labels = defaults)
        if (cfg.setup_complete !== false &&
            Object.keys(cfg.interface_labels || {}).length === 0 &&
            !localStorage.getItem('migration_banner_dismissed')) {
          setShowMigrationBanner(true)
        }
        // Upgrade modal: v1.x -> v2.0 transition
        // TODO: Generalize for future major version transitions (e.g. v3.0).
        // Currently hardcoded to config_version < 2. When a v3.0 migration is needed,
        // consider a migration registry pattern: [{fromVersion, toVersion, modal}].
        if (cfg.setup_complete === true &&
            (cfg.config_version || 0) < 2 &&
            !cfg.upgrade_v2_dismissed) {
          setShowUpgradeModal(true)
        }
        setConfigLoaded(true)
      })
      .catch(err => {
        console.error('Config load failed:', err)
        if (mounted) setConfigLoaded(true)
      })
    return () => { mounted = false }
  }, [authState]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => {})
    const interval = setInterval(() => {
      fetchHealth().then(setHealth).catch(() => {})
    }, 15000)
    return () => clearInterval(interval)
  }, [])

  // Auto-dismiss proxy toast once reverse proxy starts sending X-ULI-Proxy-Auth
  useEffect(() => {
    if (!showProxyToast) return
    const interval = setInterval(() => {
      fetchAuthStatus().then(status => {
        if (status.proxy_trusted) {
          setShowProxyToast(false)
          setAuthStatus(prev => ({ ...prev, proxy_trusted: true, is_https: status.is_https }))
        }
      }).catch(() => {})
    }, 10000)
    return () => clearInterval(interval)
  }, [showProxyToast])

  // Close status tooltip on click outside
  useEffect(() => {
    if (!showStatusTooltip) return
    const handler = (e) => {
      if (statusRef.current && !statusRef.current.contains(e.target)) {
        setShowStatusTooltip(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showStatusTooltip])

  // Detect unlabeled VPN interfaces and show toast
  useEffect(() => {
    if (authState === 'loading' || authState === 'login') return
    if (!config || !configLoaded) return
    const vpnNets = config.vpn_networks || {}
    const wanSet = new Set(config.wan_interfaces || [])

    fetchInterfaces().then(data => {
      const ifaces = data.interfaces || []
      setAllInterfaces(ifaces)
      const unlabeled = ifaces.filter(i => {
        if (wanSet.has(i.name) || i.name.startsWith('br') || i.name.startsWith('eth')) return false
        if (vpnNets[i.name]) return false
        return isVpnInterface(i.name)
      })
      setUnlabeledVpn(unlabeled)
      if (!unlabeled.length) { setShowVpnToast(false); return }
      if (config.vpn_toast_dismissed) return
      setShowVpnToast(true)
    }).catch(() => {})
  }, [authState, config, configLoaded]) // eslint-disable-line react-hooks/exhaustive-deps

  // Check UniFi controller connection status and show toast if disconnected
  useEffect(() => {
    if (authState === 'loading' || authState === 'login') return
    if (!config || !configLoaded) return
    if (!config.unifi_enabled) return
    const dismissed = sessionStorage.getItem('unifi_toast_dismissed')
    if (dismissed) return
    fetchUniFiSettings().then(data => {
      if (data.host && data.api_key_set && data.status?.connected === false) {
        setShowUnifiToast(true)
      }
    }).catch(() => {})
  }, [authState, config, configLoaded]) // eslint-disable-line react-hooks/exhaustive-deps

  // Prompt multi-WAN users to reconfigure when WAN IP mapping is missing
  useEffect(() => {
    if (!config || !configLoaded) return
    if ((config.wan_interfaces || []).length < 2) return
    const ipMap = config.wan_ip_by_iface || {}
    if (Object.keys(ipMap).length > 0) return // Already has WAN IP mapping
    const dismissed = localStorage.getItem('wan_toast_dismissed')
    if (dismissed && Date.now() - parseInt(dismissed) < 7 * 24 * 3600 * 1000) return
    setShowWanToast(true)
  }, [config, configLoaded])

  useEffect(() => {
    if (!health?.version) return
    const cached = sessionStorage.getItem('latest_release')
    if (cached) {
      try {
        const { data, ts } = JSON.parse(cached)
        if (Date.now() - ts < 3600000) { setLatestRelease(data); return }
      } catch { /* ignore */ }
    }
    fetchLatestRelease(health.version).then(release => {
      if (release) {
        setLatestRelease(release)
        sessionStorage.setItem('latest_release', JSON.stringify({ data: release, ts: Date.now() }))
      }
    })
  }, [health?.version])

  // Listen for "View on map" events from LogDetail
  useEffect(() => {
    const handler = (e) => {
      setMapFlyTo(e.detail)
      setActiveTab('threat-map')
    }
    window.addEventListener('viewOnMap', handler)
    return () => window.removeEventListener('viewOnMap', handler)
  }, [])

  // Listen for "Drill to logs" events from FlowView
  useEffect(() => {
    const handler = (e) => {
      setDrillSource(activeTabRef.current)
      setLogsDrill(e.detail)
      setActiveTab('logs')
    }
    window.addEventListener('drillToLogs', handler)
    return () => window.removeEventListener('drillToLogs', handler)
  }, [])

  // Parse URL hash params (e.g. #logs?ip=1.2.3.4) for deep-linking from browser extension
  useEffect(() => {
    const hash = window.location.hash
    if (!hash.includes('?')) return
    const params = new URLSearchParams(hash.split('?')[1])
    const ip = params.get('ip')
    if (ip && isValidIpFormat(ip)) {
      const dir = params.get('dir')
      const ipKey = dir === 'dst' ? 'dst_ip' : 'src_ip'
      const drill = { [ipKey]: ip }
      const range = params.get('range')
      if (VALID_RANGES.has(range)) drill.time_range = range
      setLogsDrill(drill)
      setActiveTab('logs')
      history.replaceState(null, '', window.location.pathname + window.location.search + '#logs')
    }
  }, [])

  // Listen for "Return from drill" — navigate back to source tab
  useEffect(() => {
    const handler = () => {
      if (drillSourceRef.current) {
        setActiveTab(drillSourceRef.current)
        setDrillSource(null)
      }
    }
    window.addEventListener('returnFromDrill', handler)
    return () => window.removeEventListener('returnFromDrill', handler)
  }, [])

  const maxFilterDays = useMemo(() => {
    if (!health) return 365
    if (health.oldest_log_at) {
      return Math.ceil((Date.now() - new Date(health.oldest_log_at).getTime()) / 86400e3)
    }
    // No logs yet — fall back to retention period
    return health.retention_days || 60
  }, [health])

  // Auth gates
  if (authState === 'loading') {
    return <LoadingSplash />
  }

  if (authState === 'login') {
    return (
      <Login
        isHttps={authStatus?.is_https}
        proxyTrusted={authStatus?.proxy_trusted}
        isEmbedded={isEmbedded}
        theme={theme}
        version={health?.version}
        onSuccess={() => setAuthState('authenticated')}
      />
    )
  }

  if (!configLoaded) {
    return <LoadingSplash />
  }

  // Show setup wizard if not configured
  if (showWizard) {
    return <SetupWizard onComplete={() => {
      reloadConfig().catch(() => {})
      setShowWizard(false)
    }} />
  }

  // Show settings overlay (also hosts reconfigure wizard)
  if (showSettings) {
    return <SettingsOverlay
      onClose={() => {
        reloadConfig().catch(() => {})
        setTheme(localStorage.getItem('ui_theme') || 'dark')
        setShowSettings(false)
        setSettingsReconfig(false)
        setSettingsInitialSection(null)
      }}
      startInReconfig={settingsReconfig}
      initialSection={settingsInitialSection}
      unlabeledVpn={unlabeledVpn}
      onVpnSaved={(cfg) => reloadConfig(cfg).catch(() => {})}
      version={health?.version}
      latestRelease={latestRelease}
      totalLogs={health?.total_logs}
      storage={health?.storage}
      onAuthEnabled={() => { bootstrapDoneRef.current = true; setAuthState('authenticated') }}
      onUiSettingsChanged={setUiSettings}
    />
  }

  return (
    <div className={`h-dvh flex flex-col bg-gray-950${logsPaused && activeTab === 'logs' ? ' paused-glow' : ''}`}>
      {/* Upgrade modal */}
      {showUpgradeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-950 border border-gray-700 rounded-xl p-6 max-w-md mx-4 shadow-2xl">
            <h2 className="text-lg font-semibold text-gray-200 mb-3">Welcome to v{health?.version || '2.0'}!</h2>
            <p className="text-sm text-gray-400 mb-4">UniFi API integration is now available:</p>
            <ul className="text-sm text-gray-300 space-y-1.5 mb-5">
              <li className="flex items-start gap-2">
                <span className="text-blue-400 mt-0.5">&#x2022;</span>
                Auto-detect WAN and network configuration
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 mt-0.5">&#x2022;</span>
                Manage firewall rule syslog from your dashboard
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 mt-0.5">&#x2022;</span>
                Device name resolution
              </li>
            </ul>
            <p className="text-sm text-gray-400 mb-5">
              Connect your UniFi controller to get started.
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setShowUpgradeModal(false); setSettingsReconfig(true); setShowSettings(true) }}
                className="flex-1 px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors"
              >
                Set Up Now
              </button>
              <button
                onClick={() => setShowUpgradeModal(false)}
                className="px-4 py-2 rounded-lg text-sm font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 transition-colors"
              >
                Later
              </button>
              <button
                onClick={() => {
                  setShowUpgradeModal(false)
                  dismissUpgradeModal().catch(() => {})
                }}
                className="px-4 py-2 rounded-lg text-xs text-gray-500 hover:text-gray-400 transition-colors"
              >
                Don't Show Again
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Migration banner */}
      {showMigrationBanner && (
        <div className="flex items-center justify-between px-4 py-2 bg-blue-500/10 border-b border-blue-500/30 text-xs text-blue-400">
          <span>
            Your network configuration was auto-detected with default settings. Click the
            <button
              onClick={() => { setShowMigrationBanner(false); setShowSettings(true) }}
              className="underline mx-1 hover:text-blue-300"
            >
              Settings
            </button>
            gear to review and customize interface labels.
          </span>
          <button
            onClick={() => {
              setShowMigrationBanner(false)
              localStorage.setItem('migration_banner_dismissed', '1')
            }}
            className="text-blue-400 hover:text-blue-300 ml-4"
          >
            &#x2715;
          </button>
        </div>
      )}

      {/* Reverse proxy not configured toast */}
      {showProxyToast && (
        <div className="flex items-center justify-between px-4 py-2 bg-amber-500/10 border-b border-amber-500/30 text-xs text-amber-400">
          <span>
            Reverse proxy trust is not configured &mdash; HTTPS detection and IP forwarding may not work.{' '}
            <button
              onClick={() => { setShowProxyToast(false); setSettingsInitialSection('security'); setShowSettings(true) }}
              className="underline hover:text-amber-300"
            >
              Configure in Settings &rarr; Security
            </button>
          </span>
          <button
            onClick={() => {
              setShowProxyToast(false)
              sessionStorage.setItem('proxy_toast_dismissed', '1')
            }}
            className="text-amber-400 hover:text-amber-300 ml-4"
          >
            &#x2715;
          </button>
        </div>
      )}

      {/* UniFi controller disconnected toast */}
      {showUnifiToast && (
        <div className="flex items-center justify-between px-4 py-2 bg-red-500/10 border-b border-red-500/30 text-xs text-red-400">
          <span>
            UniFi controller is not connected.{' '}
            <button
              onClick={() => { setShowUnifiToast(false); setShowSettings(true) }}
              className="underline hover:text-red-300"
            >
              Go to Settings to reconnect
            </button>
          </span>
          <button
            onClick={() => {
              setShowUnifiToast(false)
              sessionStorage.setItem('unifi_toast_dismissed', '1')
            }}
            className="text-red-400 hover:text-red-300 ml-4"
          >
            &#x2715;
          </button>
        </div>
      )}

      {/* WAN detection toast */}
      {showWanToast && (
        <div className="flex items-center justify-between px-4 py-2 bg-blue-500/10 border-b border-blue-500/30 text-xs text-blue-400">
          <span>
            Multiple WAN interfaces detected without IP mapping.{' '}
            <button
              onClick={() => { setShowWanToast(false); setSettingsReconfig(true); setShowSettings(true) }}
              className="underline hover:text-blue-300"
            >
              Reconfigure to resolve WAN IPs
            </button>
          </span>
          <button
            onClick={() => {
              setShowWanToast(false)
              localStorage.setItem('wan_toast_dismissed', String(Date.now()))
            }}
            className="text-blue-400 hover:text-blue-300 ml-4"
          >
            &#x2715;
          </button>
        </div>
      )}

      {/* VPN toast */}
      {showVpnToast && (
        <div className="flex items-center justify-between px-4 py-2 bg-teal-500/10 border-b border-teal-500/30 text-xs text-teal-400">
          <span>
            Unlabeled VPN networks found.{' '}
            <button
              onClick={() => { setShowVpnToast(false); setShowSettings(true) }}
              className="underline hover:text-teal-300"
            >
              Configure them here
            </button>
            {' | '}
            <button
              onClick={() => { setShowVpnToast(false); dismissVpnToast().catch(() => {}) }}
              className="underline hover:text-teal-300"
            >
              Dismiss
            </button>
          </span>
          <button
            onClick={() => setShowVpnToast(false)}
            className="text-teal-400 hover:text-teal-300 ml-4"
          >
            &#x2715;
          </button>
        </div>
      )}

      {/* Header */}
      <header className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-950 shrink-0">
        <div className="flex items-center gap-2 sm:gap-4 min-w-0 overflow-x-auto flex-nowrap [&::-webkit-scrollbar]:hidden" style={{ scrollbarWidth: 'none' }}>
          {/* Logo — hidden when embedded in UniFi controller iframe (tab already shows it) */}
          {!isEmbedded && (
            <div className="flex items-center gap-2 shrink-0">
              <svg viewBox="0 0 100 116" className="w-6 h-7 shrink-0" fill="none" role="img" aria-labelledby="app-logo-title">
                <title id="app-logo-title">Insights Plus</title>
                <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68 Z" fill="#14b8a6" fillOpacity="0.12"/>
                <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round" fill="none"/>
                <path d="M 28 34 A 18 18 0 0 1 44 22" stroke="#14b8a6" strokeWidth="4.8" strokeLinecap="round" fill="none" opacity="0.7"/>
                <line x1="28" y1="75" x2="72" y2="75" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
                <line x1="36" y1="84" x2="64" y2="84" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
                <text x="50" y="110" textAnchor="middle" fontFamily="-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif" fontWeight="800" fontSize="19" letterSpacing="0.16em" fill="#0d9488">PLUS</text>
              </svg>
              <span className="hidden sm:inline text-sm font-semibold text-gray-200">Insights Plus</span>
            </div>
          )}

          {/* Tabs */}
          <nav className="flex items-center gap-0.5 ml-0 sm:ml-4">
            {TABS.map(tab => (
              <button
                type="button"
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-2 sm:px-3 py-2 sm:py-1.5 rounded text-xs sm:text-sm font-medium transition-all min-h-[44px] sm:min-h-0 ${
                  activeTab === tab.id
                    ? 'bg-gray-800 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <span className="hidden sm:inline">{tab.label}</span>
                <span className="sm:hidden">{tab.shortLabel}</span>
              </button>
            ))}
          </nav>
        </div>

        {/* Status + Settings gear */}
        <div className="flex items-center gap-3">
          {health && (
            <>
              <div className="hidden md:flex items-center gap-3">
                <span className="text-xs text-gray-400">
                  AbuseIPDB: {formatAbuseIPDB(health.abuseipdb)}
                </span>
                <span className="text-xs text-gray-600">|</span>
                <span className="text-xs text-gray-400">
                  MaxMind: {formatShortDate(health.maxmind_last_update)}
                </span>
                <span className="text-xs text-gray-600">|</span>
                <span className="text-xs text-gray-400">
                  Next pull: {formatShortDate(health.maxmind_next_update)}
                </span>
                <span className="text-xs text-gray-600">|</span>
                <span className="text-xs text-gray-400">
                  {health.total_logs?.toLocaleString()} logs
                </span>
              </div>
              <div className="relative" ref={statusRef}>
                <button
                  type="button"
                  onClick={() => setShowStatusTooltip(v => !v)}
                  className="flex items-center justify-center w-6 h-6 -m-1"
                  aria-label="System status"
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    health.status === 'ok' ? 'bg-emerald-400' : 'bg-red-400'
                  }`} />
                </button>
                {showStatusTooltip && (
                  <div className="md:hidden absolute right-0 top-full mt-1 w-52 bg-gray-950 border border-gray-700 rounded-lg shadow-lg z-30 p-3">
                    <div className="text-xs text-gray-300 font-medium mb-2">System Status</div>
                    <div className="text-xs text-gray-400 space-y-1">
                      <div>AbuseIPDB: {formatAbuseIPDB(health.abuseipdb)}</div>
                      <div>MaxMind: {formatShortDate(health.maxmind_last_update)}</div>
                      <div>Next pull: {formatShortDate(health.maxmind_next_update)}</div>
                      <div>{health.total_logs?.toLocaleString()} logs</div>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
          <button
            onClick={toggleTheme}
            className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {theme === 'dark' ? (
              <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" />
              </svg>
            ) : (
              <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
              </svg>
            )}
          </button>
          {authState === 'authenticated' && (
            <button
              onClick={() => { authLogout().catch(() => { /* intentional: always proceed to login screen even if server unreachable */ }); setAuthState('login') }}
              className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
              title="Sign Out"
            >
              <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M3 3a1 1 0 00-1 1v12a1 1 0 102 0V4a1 1 0 00-1-1zm10.293 9.293a1 1 0 001.414 1.414l3-3a1 1 0 000-1.414l-3-3a1 1 0 10-1.414 1.414L14.586 9H7a1 1 0 100 2h7.586l-1.293 1.293z" clipRule="evenodd" />
              </svg>
            </button>
          )}
          <button
            onClick={() => setShowSettings(true)}
            className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
            title="Settings"
          >
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
              <line x1="3.5" y1="5" x2="20.5" y2="5" />
              <circle cx="9" cy="5" r="2" />
              <line x1="3.5" y1="12" x2="20.5" y2="12" />
              <circle cx="15" cy="12" r="2" />
              <line x1="3.5" y1="19" x2="20.5" y2="19" />
              <circle cx="7" cy="19" r="2" />
            </svg>
          </button>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 overflow-hidden">
        {activeTab === 'logs' && <LogStream version={health?.version} latestRelease={latestRelease} maxFilterDays={maxFilterDays} drillFilters={logsDrill} onDrillConsumed={clearLogsDrill} interfaces={allInterfaces} onPauseChange={onLogsPauseChange} uiSettings={uiSettings} />}
        <Suspense fallback={<DashboardSkeleton />}>
          {activeTab === 'dashboard' && <Dashboard maxFilterDays={maxFilterDays} />}
        </Suspense>
        <Suspense fallback={<FlowViewSkeleton />}>
          {(activeTab === 'flow-view' || drillSource === 'flow-view') && (
            <div className={activeTab !== 'flow-view' ? 'hidden' : 'contents'}>
              <FlowView maxFilterDays={maxFilterDays} />
            </div>
          )}
        </Suspense>
        <Suspense fallback={<ThreatMapSkeleton />}>
          {activeTab === 'threat-map' && <ThreatMap maxFilterDays={maxFilterDays} flyTo={mapFlyTo} onFlyToDone={clearMapFlyTo} />}
        </Suspense>
      </main>
    </div>
  )
}
