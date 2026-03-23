import { useState, useEffect } from 'react'
import { fetchConfig, fetchUniFiSettings, fetchUniFiNetworkConfig } from '../api'
import SettingsWanNetworks from './SettingsWanNetworks'
import SettingsFirewall from './SettingsFirewall'
import SettingsDataBackups from './SettingsDataBackups'
import SettingsUserInterface from './SettingsUserInterface'
import SettingsMCP from './SettingsMCP'
import SettingsSecurity from './SettingsSecurity'
import SettingsAPI from './SettingsAPI'
import SetupWizard from './SetupWizard'
import ReleaseNotesModal, { isNewerVersion } from './ReleaseNotesModal'

function getVlanId(iface) {
  if (iface === 'br0') return 1
  const match = iface.match(/^br(\d+)$/)
  return match ? parseInt(match[1]) : null
}

const BASE_SECTIONS = [
  {
    id: 'wan-networks',
    label: 'WAN & Networks',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM4.332 8.027a6.012 6.012 0 011.912-2.706C6.512 5.73 6.974 6 7.5 6A1.5 1.5 0 019 7.5V8a2 2 0 004 0 2 2 0 011.523-1.943A5.977 5.977 0 0116 10c0 .34-.028.675-.083 1H15a2 2 0 00-2 2v2.197A5.973 5.973 0 0110 16v-2a2 2 0 00-2-2 2 2 0 01-2-2 2 2 0 00-1.668-1.973z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'firewall',
    label: 'Firewall',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
        <path fillRule="evenodd" clipRule="evenodd" d="M8 5h4v2H8V5Zm5 2V5h4v2h-4Zm5 0h2V5h-2v2ZM7 5H4v2h3V5ZM4 8h1v2H4V8Zm2 2V8h4v2H6Zm5 0h4V8h-4v2Zm5 0V8h4v2h-4ZM3 7v12a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v2Zm5 6v-2h4v2H8Zm5 0v-2h4v2h-4Zm5 0v-2h2v2h-2ZM7 11H4v2h3v-2Zm-3 8v-2h3v2H4Zm4 0v-2h4v2H8Zm10 0h2v-2h-2v2Zm-1 0v-2h-4v2h4Zm3-5v2h-4v-2h4Zm-5 0v2h-4v-2h4Zm-5 0v2H6v-2h4Zm-5 0v2H4v-2h1Z" />
      </svg>
    ),
  },
  {
    id: 'data-backups',
    label: 'Data & Backups',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
        <path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z" />
        <path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z" />
      </svg>
    ),
  },
  {
    id: 'user-interface',
    label: 'User Interface',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path d="M5 4a1 1 0 00-2 0v7.268a2 2 0 000 3.464V16a1 1 0 102 0v-1.268a2 2 0 000-3.464V4zM11 4a1 1 0 10-2 0v1.268a2 2 0 000 3.464V16a1 1 0 102 0V8.732a2 2 0 000-3.464V4zM17 4a1 1 0 10-2 0v7.268a2 2 0 000 3.464V16a1 1 0 102 0v-1.268a2 2 0 000-3.464V4z" />
      </svg>
    ),
  },
  {
    id: 'security',
    label: 'Security',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'api',
    label: 'API',
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'mcp',
    label: 'MCP',
    icon: (
      <img src="/mcp-logo.png" alt="MCP" className="mcp-logo" />
    ),
  },
]

export default function SettingsOverlay({ onClose, startInReconfig, initialSection, unlabeledVpn = [], onVpnSaved: onVpnSavedApp, version, latestRelease, totalLogs, storage, onAuthEnabled, onUiSettingsChanged }) {
  const [config, setConfig] = useState(null)
  const [unifiSettings, setUnifiSettings] = useState(null)
  const [netConfig, setNetConfig] = useState(null)
  const [activeSection, setActiveSection] = useState(initialSection || 'wan-networks')
  const [reconfigMode, setReconfigMode] = useState(!!startInReconfig)
  const [wizardPath, setWizardPath] = useState(null)
  const [showNotes, setShowNotes] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const outdated = latestRelease && isNewerVersion(latestRelease.tag, version)

  useEffect(() => {
    fetchConfig().then(setConfig).catch(() => {})
    fetchUniFiSettings().then(data => {
      setUnifiSettings(data)
      if (data?.enabled) {
        fetchUniFiNetworkConfig().then(setNetConfig).catch(() => {})
      }
    }).catch(() => {})
  }, [])

  // Close mobile sidebar on Escape
  useEffect(() => {
    if (!sidebarOpen) return
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setSidebarOpen(false)
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [sidebarOpen])

  const sections = BASE_SECTIONS

  const savedWanInterfaces = config?.wan_interfaces || []
  const labels = config?.interface_labels || {}
  const unifiEnabled = unifiSettings?.enabled

  // Build WAN cards from ALL live WAN data (includes inactive WANs like WAN2)
  // Fall back to saved config if live data isn't available
  const liveWans = netConfig?.wan_interfaces || []
  const allWanPhysicals = new Set(savedWanInterfaces)
  for (const w of liveWans) allWanPhysicals.add(w.physical_interface)

  const wanCards = liveWans.length > 0
    ? liveWans.map(w => ({
        iface: w.physical_interface,
        name: w.name,
        wanIp: w.wan_ip || null,
        tunnelIp: w.tunnel_ip || null,
        active: w.active,
        type: w.type || null,
      }))
    : savedWanInterfaces.map(iface => ({
        iface,
        name: labels[iface] || iface,
        wanIp: (config?.wan_ip_by_iface || {})[iface] || null,
        active: null,
        type: null,
      }))

  // Network cards: only bridge interfaces (br*) belong in network segments
  const networkCards = Object.entries(labels)
    .filter(([iface]) => iface.startsWith('br'))
    .map(([iface, label]) => {
      const live = netConfig?.networks?.find(n => n.interface === iface)
      return {
        iface,
        label,
        vlanId: live?.vlan ?? getVlanId(iface),
        subnet: live?.ip_subnet || null,
      }
    })

  const handleRestartWizard = () => {
    setReconfigMode(true)
    setWizardPath(null)
    setActiveSection('wan-networks')
  }

  const reloadAll = () => {
    fetchConfig().then(setConfig).catch(() => {})
    fetchUniFiSettings().then(data => {
      setUnifiSettings(data)
      if (data?.enabled) fetchUniFiNetworkConfig().then(setNetConfig).catch(() => {})
    }).catch(() => {})
  }

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-950 shrink-0">
        <div className="flex items-center gap-2 sm:gap-4 min-w-0 overflow-x-auto flex-nowrap [&::-webkit-scrollbar]:hidden" style={{ scrollbarWidth: 'none' }}>
          {/* Mobile sidebar toggle */}
          <button
            type="button"
            onClick={() => setSidebarOpen(v => !v)}
            className="md:hidden p-1.5 -ml-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors min-h-[44px] sm:min-h-0 flex items-center"
            aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            aria-expanded={sidebarOpen}
          >
            <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M2 4.75A.75.75 0 012.75 4h14.5a.75.75 0 010 1.5H2.75A.75.75 0 012 4.75zm0 10.5a.75.75 0 01.75-.75h14.5a.75.75 0 010 1.5H2.75a.75.75 0 01-.75-.75zM2 10a.75.75 0 01.75-.75h14.5a.75.75 0 010 1.5H2.75A.75.75 0 012 10z" clipRule="evenodd" />
            </svg>
          </button>
          <div className="flex items-center gap-2 shrink-0">
            <svg viewBox="0 0 100 116" className="w-6 h-7 shrink-0" fill="none" aria-hidden="true">
              <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68 Z" fill="#14b8a6" fillOpacity="0.12"/>
              <path d="M 29 68 C 22 62, 16 53, 16 41 A 34 34 0 1 1 84 41 C 84 53, 78 62, 71 68" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round" fill="none"/>
              <path d="M 28 34 A 18 18 0 0 1 44 22" stroke="#14b8a6" strokeWidth="4.8" strokeLinecap="round" fill="none" opacity="0.7"/>
              <line x1="28" y1="75" x2="72" y2="75" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
              <line x1="36" y1="84" x2="64" y2="84" stroke="#14b8a6" strokeWidth="5.2" strokeLinecap="round"/>
              <text x="50" y="110" textAnchor="middle" fontFamily="-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif" fontWeight="800" fontSize="19" letterSpacing="0.16em" fill="#0d9488">PLUS</text>
            </svg>
            <span className="hidden sm:inline text-sm font-semibold text-gray-200">Insights Plus</span>
          </div>
          <span className="text-sm text-gray-400 flex items-center">
            <span className="hidden md:inline">Settings</span>
            <span className="md:hidden text-gray-200">{sections.find(s => s.id === activeSection)?.label || 'Settings'}</span>
            {reconfigMode && (
              <>
                <span className="hidden md:inline text-gray-600 mx-1">&rsaquo;</span>
                <span className="hidden md:inline">WAN &amp; Networks</span>
                <span className="text-gray-600 mx-1">&rsaquo;</span>
                <span className="text-gray-300">Reconfigure</span>
                {wizardPath === 'unifi_api' && (
                  <><span className="text-gray-600 mx-1">&rsaquo;</span><span className="text-gray-300">UniFi API</span></>
                )}
                {wizardPath === 'log_detection' && (
                  <><span className="text-gray-600 mx-1">&rsaquo;</span><span className="text-gray-300">Log Detection</span></>
                )}
              </>
            )}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <a
            href="https://insightsplus.dev/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 px-2 py-1.5 rounded text-sm text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors"
            aria-label="Documentation"
          >
            Docs
            <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
          </a>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
            aria-label="Close settings"
          >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5" aria-hidden="true">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
        </div>
      </header>

      {/* Sidebar + Content */}
      <main className="flex-1 flex overflow-hidden relative">
        {/* Mobile sidebar backdrop */}
        {sidebarOpen && (
          <div className="md:hidden fixed inset-0 z-40 bg-black/50" role="presentation" aria-hidden="true" onClick={() => setSidebarOpen(false)} />
        )}

        {/* Sidebar — always visible on desktop, slide-over on mobile */}
        {/* top-[41px] offsets below the fixed header (py-2 + content + border) */}
        <nav className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0 fixed md:static top-[41px] bottom-0 left-0 z-50 md:z-auto w-52 shrink-0 border-r border-gray-800 bg-gray-950 py-4 overflow-y-auto flex flex-col transition-transform duration-200 ease-in-out`}>
          {sections.map(section => (
            <button
              key={section.id}
              onClick={() => {
                if (reconfigMode) { setReconfigMode(false); setWizardPath(null) }
                setActiveSection(section.id)
                setSidebarOpen(false)
              }}
              className={`w-full flex items-center gap-3 px-5 py-2.5 text-sm transition-colors ${
                activeSection === section.id
                  ? 'bg-gray-800/60 text-white border-r-2 border-blue-500'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/30'
              }`}
            >
              {section.icon}
              {section.label}
            </button>
          ))}
          {version && (
            <div className="mt-auto border-t border-gray-800 flex items-center justify-center h-[42px]">
              <div className="flex items-center gap-1.5">
                <span className={`text-sm ${outdated ? 'text-amber-400' : 'text-gray-400'}`}>v{version}</span>
                {outdated ? (
                  <button
                    onClick={() => setShowNotes(true)}
                    className="flex items-center gap-1 text-sm text-amber-400 hover:text-amber-300 transition-colors"
                    title={`Update available: ${latestRelease.tag}`}
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-3 h-3">
                      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                    </svg>
                    Update available
                  </button>
                ) : latestRelease?.body && (
                  <button
                    onClick={() => setShowNotes(true)}
                    className="text-sm text-gray-500 hover:text-gray-200 transition-colors"
                  >
                    - Release Notes
                  </button>
                )}
              </div>
            </div>
          )}
        </nav>

        {/* Content */}
        <div className="flex-1 overflow-y-auto py-4 px-3 md:py-8 md:px-6">
          <div className="max-w-6xl mx-auto">
            {reconfigMode ? (
              <SetupWizard
                embedded
                reconfigMode
                onComplete={() => {
                  setReconfigMode(false)
                  setWizardPath(null)
                  reloadAll()
                }}
                onCancel={() => { setReconfigMode(false); setWizardPath(null) }}
                onPathChange={setWizardPath}
              />
            ) : (
              <>
                {activeSection === 'wan-networks' && (
                  <SettingsWanNetworks
                    unifiEnabled={unifiEnabled}
                    unifiSettings={unifiSettings}
                    wanCards={wanCards}
                    networkCards={networkCards}
                    onRestartWizard={handleRestartWizard}
                    vpnNetworks={config?.vpn_networks || {}}
                    interfaceLabels={config?.interface_labels || {}}
                    onVpnSaved={() => { fetchConfig().then(cfg => { setConfig(cfg); onVpnSavedApp?.(cfg) }).catch(() => {}) }}
                    unlabeledVpn={unlabeledVpn}
                  />
                )}
                {activeSection === 'firewall' && (
                  <SettingsFirewall
                    unifiEnabled={unifiEnabled}
                    supportsFirewall={unifiSettings?.supports_firewall !== false}
                    onRestartWizard={handleRestartWizard}
                  />
                )}
                {activeSection === 'data-backups' && (
                  <SettingsDataBackups totalLogs={totalLogs} storage={storage} />
                )}
                {activeSection === 'user-interface' && (
                  <SettingsUserInterface onSaved={onUiSettingsChanged} />
                )}
                {activeSection === 'security' && (
                  <SettingsSecurity onAuthEnabled={onAuthEnabled} />
                )}
                {activeSection === 'api' && (
                  <SettingsAPI />
                )}
                {activeSection === 'mcp' && (
                  <SettingsMCP />
                )}
              </>
            )}
          </div>
        </div>
      </main>
      {showNotes && latestRelease && (
        <ReleaseNotesModal latestRelease={latestRelease} onClose={() => setShowNotes(false)} currentVersion={version} />
      )}
    </div>
  )
}
