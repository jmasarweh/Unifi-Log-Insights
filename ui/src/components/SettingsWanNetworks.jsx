import { useState, useMemo } from 'react'
import { saveVpnNetworks } from '../api'
import { suggestVpnType, getIfaceDescription, BADGE_LABELS, BADGE_CHOICES } from '../vpnUtils'
import VpnNetworkTable from './VpnNetworkTable'

export default function SettingsWanNetworks({ unifiEnabled, unifiSettings, wanCards, networkCards, onRestartWizard, vpnNetworks, interfaceLabels, onVpnSaved, unlabeledVpn: rawUnlabeledVpn = [] }) {
  // Filter out interfaces already present in vpnNetworks to prevent duplicates
  const unlabeledVpn = rawUnlabeledVpn.filter(i => !vpnNetworks[i.name])
  const [imgLoaded, setImgLoaded] = useState(false)
  const gatewayImgUrl = unifiEnabled ? '/api/unifi/gateway-image' : null

  // VPN editing state
  const [editVpn, setEditVpn] = useState({})  // {iface: {badge, cidr, label}}
  const [editing, setEditing] = useState(false)
  const [editMode, setEditMode] = useState('edit') // 'edit' = all, 'configure' = unlabelled only
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState(null)

  // Build VPN list from configured networks only
  // Normalize type: if the stored value isn't a known BADGE_CHOICES key
  // (e.g. old format or missing), fall back to prefix-based detection.
  const vpnEntries = useMemo(() => {
    return Object.keys(vpnNetworks || {}).sort((a, b) => a.localeCompare(b)).map(iface => {
      const storedType = vpnNetworks[iface]?.type || ''
      return {
        iface,
        badge: vpnNetworks[iface]?.badge || '',
        cidr: vpnNetworks[iface]?.cidr || '',
        label: interfaceLabels?.[iface] || '',
        type: BADGE_CHOICES.includes(storedType) ? storedType : (suggestVpnType(iface) || ''),
      }
    })
  }, [vpnNetworks, interfaceLabels])

  const configureDiscovered = (ifaces) => {
    const init = {}
    // Always include existing entries so save doesn't wipe them
    for (const entry of vpnEntries) {
      init[entry.iface] = {
        badge: entry.badge || 'VPN',
        cidr: entry.cidr || '',
        label: entry.label || suggestVpnType(entry.iface) || '',
        type: entry.type || suggestVpnType(entry.iface) || '',
      }
    }
    for (const i of ifaces) {
      const type = suggestVpnType(i.name)
      init[i.name] = { badge: 'VPN', cidr: '', label: type || '', type }
    }
    setEditVpn(init)
    setEditMode(ifaces.length > 0 ? 'configure' : 'edit')
    setEditing(true)
    setSaveMsg(null)
  }

  const startEditing = () => configureDiscovered([])

  const cancelEditing = () => {
    setEditing(false)
    setEditVpn({})
    setSaveMsg(null)
  }

  const handleSave = async () => {
    setSaving(true)
    setSaveMsg(null)
    try {
      const vpn = {}
      const labels = {}
      for (const [iface, cfg] of Object.entries(editVpn)) {
        if (cfg.badge) {
          const cidr = cfg.cidr || ''
          if (cidr && !/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(cidr) && !/^[0-9a-fA-F:]+\/\d{1,3}$/.test(cidr)) {
            setSaveMsg(`Invalid CIDR for ${iface}: ${cidr}`)
            setSaving(false)
            return
          }
          vpn[iface] = { badge: cfg.badge, cidr, type: cfg.type || '' }
        }
        labels[iface] = cfg.label || ''
      }
      await saveVpnNetworks(vpn, labels)
      setEditing(false)
      setSaveMsg('Saved')
      if (onVpnSaved) onVpnSaved()
      setTimeout(() => setSaveMsg(null), 3000)
    } catch (err) {
      setSaveMsg(`Error: ${err.message}`)
    } finally {
      setSaving(false)
    }
  }

  // Build sorted entries for the shared table component
  // In 'configure' mode, only show the newly discovered interfaces
  const existingIfaceSet = useMemo(() => new Set(vpnEntries.map(e => e.iface)), [vpnEntries])
  const editEntries = useMemo(() => {
    const entries = Object.entries(editVpn)
      .filter(([iface]) => editMode === 'edit' || !existingIfaceSet.has(iface))
    return entries.sort(([a], [b]) => {
      const aIdx = vpnEntries.findIndex(e => e.iface === a)
      const bIdx = vpnEntries.findIndex(e => e.iface === b)
      if (aIdx >= 0 && bIdx >= 0) return aIdx - bIdx
      if (aIdx >= 0) return -1
      if (bIdx >= 0) return 1
      return a.localeCompare(b)
    }).map(([iface, cfg]) => ({
      iface,
      badge: cfg.badge || '',
      type: cfg.type || '',
      label: cfg.label || '',
      cidr: cfg.cidr || '',
    }))
  }, [editVpn, vpnEntries, editMode, existingIfaceSet])

  // Compute add form props
  const addFormProps = useMemo(() => {
    return {
      availableTypes: BADGE_CHOICES,
      existingInterfaces: Object.keys(editVpn),
      onAdd: (iface, cfg) => setEditVpn(prev => ({ ...prev, [iface]: cfg })),
    }
  }, [editVpn])

  return (
    <div className="space-y-8">
      {/* ── UniFi Gateway ─────────────────────────────────────── */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
            UniFi Gateway
          </h2>
          {unifiEnabled && (
            <button
              onClick={onRestartWizard}
              className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
            >
              Reconfigure
            </button>
          )}
        </div>
        {unifiEnabled ? (
          <div className="rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
            <div className="flex items-center gap-3">
              {gatewayImgUrl && (
                <img
                  src={gatewayImgUrl}
                  alt=""
                  className={`shrink-0${imgLoaded ? '' : ' hidden'}`}
                  width={48}
                  height={48}
                  onLoad={() => setImgLoaded(true)}
                  onError={() => setImgLoaded(false)}
                />
              )}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-200">
                    {unifiSettings?.host || 'UniFi Gateway'}
                  </span>
                  <span className="flex items-center gap-1.5 text-xs text-emerald-400 leading-none">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 block" />
                    Online
                  </span>
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  {unifiSettings?.controller_name
                    ? `${unifiSettings.controller_name}${unifiSettings.controller_version ? ` (v${unifiSettings.controller_version})` : ''}`
                    : 'Connected via API'}
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-500">Not configured</span>
              <button
                onClick={onRestartWizard}
                className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
              >
                Set up
              </button>
            </div>
          </div>
        )}
      </section>

      {/* ── WAN Interfaces ──────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          WAN Interfaces
        </h2>
        {wanCards.length > 0 ? (
          <div className="grid gap-3 grid-cols-1 sm:grid-cols-2">
            {wanCards.map(wan => (
              <div key={wan.iface} className="flex items-center justify-between rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-200 truncate">
                      {wan.name}
                    </span>
                    {wan.type && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30 shrink-0">
                        {wan.type}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs font-mono text-gray-500">{wan.iface}</span>
                    {wan.wanIp && (
                      <span className="text-xs font-mono text-gray-500">
                        {wan.wanIp}{wan.tunnelIp ? ` (tunnel: ${wan.tunnelIp})` : ''}
                      </span>
                    )}
                  </div>
                </div>
                {wan.active != null && (
                  <div className="shrink-0 ml-3">
                    {wan.active ? (
                      <span className="flex items-center gap-1.5 text-xs text-emerald-400 leading-none">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 block" />
                        Active
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-xs text-gray-500 leading-none">
                        <span className="w-1.5 h-1.5 rounded-full bg-gray-600 block" />
                        Inactive
                      </span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center text-sm text-gray-500">
            No WAN interfaces configured
          </div>
        )}
      </section>

      {/* ── Network Segments ─────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          Network Labels
        </h2>
        {networkCards.length > 0 ? (
          <div className="grid gap-2 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
            {networkCards.map(net => (
              <div key={net.iface} className="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-200 truncate">{net.label}</span>
                    {net.vlanId != null && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30 shrink-0">
                        VLAN {net.vlanId}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs font-mono text-gray-500">{net.iface}</span>
                    {net.subnet && (
                      <span className="text-xs font-mono text-gray-600">{net.subnet}</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center text-sm text-gray-500">
            No network labels configured
          </div>
        )}
      </section>

      {/* ── VPN Networks ──────────────────────────────────────── */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
              VPN Networks
            </h2>
            <div className="flex items-center gap-2">
              {saveMsg && (
                <span className={`text-xs ${saveMsg.startsWith('Error') ? 'text-red-400' : 'text-emerald-400'}`}>
                  {saveMsg}
                </span>
              )}
              {!editing ? (
                <button
                  onClick={startEditing}
                  className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
                >
                  Edit
                </button>
              ) : (
                <>
                  <button
                    onClick={cancelEditing}
                    disabled={saving}
                    className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={saving}
                    className="px-3 py-1.5 rounded text-xs font-medium bg-teal-600 hover:bg-teal-500 text-white disabled:opacity-50 transition-colors"
                  >
                    {saving ? 'Saving...' : 'Save'}
                  </button>
                </>
              )}
            </div>
          </div>
          {editing ? (
            <VpnNetworkTable
              entries={editEntries}
              showRemove={editMode === 'edit'}
              onBadgeChange={(iface, val) => setEditVpn(prev => ({
                ...prev, [iface]: { ...prev[iface], badge: val }
              }))}
              onTypeChange={(iface, val) => setEditVpn(prev => ({
                ...prev, [iface]: { ...prev[iface], type: val, badge: 'VPN', label: val }
              }))}
              onLabelChange={(iface, val) => setEditVpn(prev => ({
                ...prev, [iface]: { ...prev[iface], label: val }
              }))}
              onCidrChange={(iface, val) => setEditVpn(prev => ({
                ...prev, [iface]: { ...prev[iface], cidr: val }
              }))}
              onRemove={iface => setEditVpn(prev => {
                const next = { ...prev }
                delete next[iface]
                return next
              })}
              addForm={editMode === 'edit' ? addFormProps : null}
            />
          ) : (
            <>
              {vpnEntries.length > 0 && (
                <div className="grid gap-2 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
                  {vpnEntries.map(entry => {
                    const fullName = BADGE_LABELS[entry.type] || entry.iface
                    return (
                      <div key={entry.iface} className="flex items-center gap-3 rounded-lg border border-teal-500/20 bg-gray-950 px-4 py-3">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-gray-200 truncate">
                              {fullName}
                            </span>
                            {entry.badge && (
                              <span className="text-xs px-1.5 py-0.5 rounded bg-teal-500/15 text-teal-400 border border-teal-500/30 shrink-0">
                                {entry.badge}
                              </span>
                            )}
                            {!entry.badge && (
                              <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-500/15 text-yellow-400 border border-yellow-500/30 shrink-0">
                                No badge
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            {entry.label && <span className="text-xs text-gray-500">{entry.label}</span>}
                            <span className="text-xs font-mono text-gray-500">{entry.iface}</span>
                            {entry.cidr && (
                              <span className="text-xs font-mono text-gray-600">{entry.cidr}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}

              {/* Discovered but unconfigured VPN interfaces */}
              {unlabeledVpn.length > 0 && (
                <div className={vpnEntries.length > 0 ? 'mt-4' : ''}>
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <h3 className="text-xs font-medium text-gray-400 uppercase tracking-wider">Unlabelled</h3>
                      <p className="text-xs text-gray-500 mt-1">Auto-detected from your firewall logs. Labels have been pre-filled where possible — click Configure to review and save.</p>
                    </div>
                    <button
                      onClick={() => configureDiscovered(unlabeledVpn)}
                      className="px-3 py-1.5 rounded text-xs font-medium bg-teal-600 hover:bg-teal-500 text-white transition-colors"
                    >
                      Configure All ({unlabeledVpn.length})
                    </button>
                  </div>
                  <div className="grid gap-2 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
                    {[...unlabeledVpn].sort((a, b) => a.name.localeCompare(b.name)).map(i => {
                      const desc = getIfaceDescription(i.name)
                      const suggested = suggestVpnType(i.name)
                      return (
                        <div key={i.name} className="flex items-center gap-3 rounded-lg border border-dashed border-teal-500/30 bg-gray-950 px-4 py-3">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-gray-200 truncate">
                                {desc || i.name}
                              </span>
                              <span className="text-xs px-1.5 py-0.5 rounded bg-white/10 text-gray-100 border border-white/20 shrink-0">
                                New
                              </span>
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="text-xs font-mono text-gray-500">{i.name}</span>
                              {!suggested && (
                                <span className="text-xs text-yellow-400 italic">type needs verifying</span>
                              )}
                            </div>
                          </div>
                          <button
                            onClick={() => configureDiscovered([i])}
                            className="shrink-0 px-2.5 py-1 rounded text-xs font-medium border border-teal-500/40 text-teal-400 hover:bg-teal-500/10 transition-colors"
                          >
                            Configure
                          </button>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {vpnEntries.length === 0 && unlabeledVpn.length === 0 && (
                <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center text-sm text-gray-500">
                  No VPN networks configured
                </div>
              )}
            </>
          )}

          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2 mt-3">
            <p className="text-xs text-yellow-400">
              L2TP, Site Magic, and OpenVPN Client detection is based on tentative interface prefixes not yet confirmed on real gateways.
              If detection is incorrect, please report your interface names and prefix on{' '}
              <a href="https://github.com/jmasarweh/unifi-log-insight/issues" target="_blank" rel="noopener noreferrer" className="underline hover:text-yellow-300">GitHub</a> or{' '}
              <a href="https://www.reddit.com/r/Ubiquiti/comments/1r1wih9/an_enhanced_flow_insights_for_unifi_routers_geoip/" target="_blank" rel="noopener noreferrer" className="underline hover:text-yellow-300">r/Ubiquiti</a> or{' '}
              <a href="https://www.reddit.com/r/UNIFI/comments/1r1wmyv/an_enhanced_flow_insights_for_unifi_routers_geoip/" target="_blank" rel="noopener noreferrer" className="underline hover:text-yellow-300">r/Unifi</a>.
            </p>
          </div>
        </section>
    </div>
  )
}
