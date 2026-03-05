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
import { fetchHealth, fetchConfig, fetchLatestRelease, dismissUpgradeModal, dismissVpnToast, fetchInterfaces, updateUiSettings } from './api'
import { loadInterfaceLabels } from './utils'
import { isVpnInterface } from './vpnUtils'

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

export default function App() {
  const [activeTab, setActiveTab] = useState('logs')
  const [health, setHealth] = useState(null)
  const [latestRelease, setLatestRelease] = useState(null)
  const [showWizard, setShowWizard] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
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
  const [theme, setTheme] = useState(() => localStorage.getItem('ui_theme') || 'dark')
  const [showStatusTooltip, setShowStatusTooltip] = useState(false)
  const statusRef = useRef(null)

  useLayoutEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

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

  // Load config + interface labels in a single fetch
  useEffect(() => {
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
  }, [])

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => {})
    const interval = setInterval(() => {
      fetchHealth().then(setHealth).catch(() => {})
    }, 15000)
    return () => clearInterval(interval)
  }, [])

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
  }, [config, configLoaded])

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

  if (!configLoaded) {
    return (
      <div className="flex items-center justify-center h-dvh bg-gray-950 text-gray-300 text-sm">
        Loading configuration...
      </div>
    )
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
      }}
      startInReconfig={settingsReconfig}
      unlabeledVpn={unlabeledVpn}
      onVpnSaved={(cfg) => reloadConfig(cfg).catch(() => {})}
      version={health?.version}
      latestRelease={latestRelease}
      totalLogs={health?.total_logs}
      storage={health?.storage}
    />
  }

  return (
    <div className="h-dvh flex flex-col bg-gray-950">
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
          {/* Logo */}
          <div className="flex items-center gap-2 shrink-0">
            <svg viewBox="0 0 24 24" className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" role="img" aria-labelledby="app-logo-title">
              <title id="app-logo-title">UniFi Log Insight</title>
              <circle cx="12" cy="12" r="10.5" strokeWidth="1.5" strokeOpacity="0.4" />
              <path d="M8.5 7.5v5.5a3.5 3.5 0 0 0 7 0V7.5" strokeWidth="2.2" strokeLinecap="round" />
            </svg>
            <span className="hidden sm:inline text-sm font-semibold text-gray-200">UniFi Log Insight</span>
          </div>

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
        {activeTab === 'logs' && <LogStream version={health?.version} latestRelease={latestRelease} maxFilterDays={maxFilterDays} drillFilters={logsDrill} onDrillConsumed={clearLogsDrill} interfaces={allInterfaces} />}
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
