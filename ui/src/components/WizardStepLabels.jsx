import React, { useState, useEffect, useRef, useMemo } from 'react'
import { fetchNetworkSegments } from '../api'
import { suggestVpnType } from '../vpnUtils'
import VpnNetworkTable from './VpnNetworkTable'

const LABEL_REGEX = /[^a-zA-Z0-9 ._-]/g

function vlanIdToInterface(id) {
  if (id === 1) return 'br0'
  if (id >= 2 && id <= 4094) return `br${id}`
  return null
}

function getVlanId(iface) {
  if (iface === 'br0') return 1
  const match = iface.match(/^br(\d+)$/)
  return match ? parseInt(match[1]) : null
}

export default function WizardStepLabels({ wanInterfaces, labels, onUpdate, vpnConfigs, onVpnUpdate, onNext, onBack, nextLabel, disabled }) {
  const [segments, setSegments] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [vlanId, setVlanId] = useState('')
  const [vlanLabel, setVlanLabel] = useState('')
  const initializedRef = useRef(false)

  // Partition segments into WAN / VLAN / VPN
  const { wanSegments, vlanSegments, vpnSegments } = useMemo(() => {
    const wanSet = new Set(wanInterfaces || [])
    const wan = []
    const vlan = []
    const vpn = []
    for (const seg of segments) {
      if (wanSet.has(seg.interface)) wan.push(seg)
      else if (seg.is_vpn) vpn.push(seg)
      else vlan.push(seg)
    }
    // Sort VPN: configured (with CIDR) first, then alphabetical
    vpn.sort((a, b) => {
      const aCidr = !!(vpnConfigs || {})[a.interface]?.cidr
      const bCidr = !!(vpnConfigs || {})[b.interface]?.cidr
      if (aCidr !== bCidr) return bCidr - aCidr
      return a.interface.localeCompare(b.interface)
    })
    return { wanSegments: wan, vlanSegments: vlan, vpnSegments: vpn }
  }, [segments, wanInterfaces, vpnConfigs])

  useEffect(() => {
    if (initializedRef.current) return
    initializedRef.current = true
    fetchNetworkSegments(wanInterfaces || [])
      .then(data => {
        const segs = data.segments || []

        // Re-add manually-added interfaces from saved labels that the API didn't return
        const discoveredSet = new Set(segs.map(s => s.interface))
        const wanSet = new Set(wanInterfaces || [])
        for (const iface of Object.keys(labels)) {
          if (!discoveredSet.has(iface) && !wanSet.has(iface) && /^br\d+$/.test(iface)) {
            segs.push({ interface: iface, sample_local_ip: null, suggested_label: '', is_wan: false, manual: true })
          }
        }
        setSegments(segs)

        // Pre-populate labels with suggested values if not already set
        const initial = { ...labels }
        let changed = false
        for (const seg of segs) {
          if (!initial[seg.interface]) {
            if (seg.is_vpn) {
              // VPN interfaces: label = type abbreviation from backend or client-side detection
              initial[seg.interface] = seg.suggested_badge || suggestVpnType(seg.interface) || ''
            } else if (seg.suggested_label) {
              initial[seg.interface] = seg.suggested_label
            }
            if (initial[seg.interface]) changed = true
          }
        }
        if (changed) onUpdate(initial)

        // Initialize VPN configs for detected VPN interfaces
        if (onVpnUpdate) {
          const currentVpn = vpnConfigs || {}
          const vpnInit = { ...currentVpn }
          let vpnChanged = false
          for (const seg of segs) {
            if (seg.is_vpn && !vpnInit[seg.interface]) {
              vpnInit[seg.interface] = {
                badge: 'VPN',
                cidr: seg.suggested_cidr || '',
                type: seg.suggested_badge || suggestVpnType(seg.interface) || '',
              }
              vpnChanged = true
            }
          }
          if (vpnChanged) onVpnUpdate(vpnInit)
        }

        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [wanInterfaces, onUpdate])

  const handleLabelChange = (iface, value) => {
    const sanitized = value.replace(LABEL_REGEX, '')
    onUpdate({ ...labels, [iface]: sanitized })
  }

  const handleVpnTypeChange = (iface, newType) => {
    // VPN Type dropdown: store type in vpnConfigs and pre-fill badge + label
    if (onVpnUpdate) {
      const current = vpnConfigs || {}
      onVpnUpdate({ ...current, [iface]: { ...current[iface], type: newType, badge: 'VPN' } })
    }
    onUpdate({ ...labels, [iface]: newType })
  }

  const handleVpnBadgeChange = (iface, badge) => {
    if (!onVpnUpdate) return
    const current = vpnConfigs || {}
    onVpnUpdate({ ...current, [iface]: { ...current[iface], badge } })
  }

  const handleVpnCidrChange = (iface, cidr) => {
    if (!onVpnUpdate) return
    const current = vpnConfigs || {}
    onVpnUpdate({ ...current, [iface]: { ...current[iface], cidr } })
  }

  // Detect duplicate labels
  const duplicateLabels = useMemo(() => {
    const seen = {}
    const dupes = new Set()
    for (const [iface, label] of Object.entries(labels)) {
      if (!label || !label.trim()) continue
      const normalized = label.trim().toLowerCase()
      if (seen[normalized]) {
        dupes.add(seen[normalized])
        dupes.add(iface)
      } else {
        seen[normalized] = iface
      }
    }
    return dupes
  }, [labels])

  const handleAddVlan = () => {
    const id = parseInt(vlanId)
    const iface = vlanIdToInterface(id)
    if (!iface) return
    if (segments.some(s => s.interface === iface)) return
    setSegments(prev => [...prev, { interface: iface, sample_local_ip: null, suggested_label: '', is_wan: false, manual: true }])
    const trimmedLabel = vlanLabel.replace(LABEL_REGEX, '').trim()
    if (trimmedLabel) {
      onUpdate({ ...labels, [iface]: trimmedLabel })
    }
    setVlanId('')
    setVlanLabel('')
  }

  const isValidVlanId = () => {
    const id = parseInt(vlanId)
    if (isNaN(id) || id < 1 || id > 4094) return false
    const iface = vlanIdToInterface(id)
    return iface && !segments.some(s => s.interface === iface)
  }

  const handleRemoveManualInterface = (iface) => {
    setSegments(prev => prev.filter(s => s.interface !== iface))
    const updated = { ...labels }
    delete updated[iface]
    onUpdate(updated)
  }

  const hasValidationErrors = duplicateLabels.size > 0

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-200 mb-2">Label your network interfaces</h2>
        <p className="text-sm text-gray-300">
          Give each interface a friendly name so the UI shows "IoT" instead
          of "br20". Suggested labels are pre-filled. Edit or clear any field.
        </p>
      </div>

      {loading && (
        <div className="text-center py-12 text-gray-400">
          Discovering network interfaces...
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <p className="text-xs text-red-400">Failed to load network segments: {error}</p>
        </div>
      )}

      {!loading && !error && segments.length === 0 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
          <p className="text-xs text-yellow-400">No network interfaces found. Make sure logs are being received.</p>
        </div>
      )}

      {/* ── WAN Interfaces ──────────────────────────────────── */}
      {!loading && !error && wanSegments.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-gray-300 mb-2 uppercase tracking-wider">WAN Interfaces</h3>
          <div className="border border-gray-800 rounded-lg overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left text-xs font-medium text-gray-300 px-4 py-3 whitespace-nowrap">Interface</th>
                  <th className="text-left text-xs font-medium text-gray-300 px-4 py-3 whitespace-nowrap">Sample IP</th>
                  <th className="text-left text-xs font-medium text-gray-300 px-4 py-3 whitespace-nowrap">Network Label</th>
                </tr>
              </thead>
              <tbody>
                {wanSegments.map(seg => (
                  <tr key={seg.interface} className="border-b border-gray-800/50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-gray-300">{seg.interface}</span>
                        <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                          WAN
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-gray-400">{seg.sample_local_ip || '\u2014'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <input
                        type="text"
                        maxLength={11}
                        value={labels[seg.interface] || ''}
                        onChange={(e) => handleLabelChange(seg.interface, e.target.value)}
                        placeholder={seg.suggested_label || 'e.g., WAN 1'}
                        className={`w-full px-3 py-1.5 bg-gray-800 border rounded text-sm text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
                          duplicateLabels.has(seg.interface) ? 'border-yellow-500/50' : 'border-gray-700'
                        }`}
                      />
                      {duplicateLabels.has(seg.interface) && (
                        <p className="text-xs text-yellow-400 mt-1">Duplicate label</p>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── VLAN / Network Labels ──────────────────────────── */}
      {!loading && !error && vlanSegments.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-gray-300 mb-2 uppercase tracking-wider">Network Labels</h3>
          <div className="border border-gray-800 rounded-lg overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left text-xs font-medium text-gray-300 px-4 py-3 whitespace-nowrap">Interface</th>
                  <th className="text-left text-xs font-medium text-gray-300 px-4 py-3 whitespace-nowrap">Sample IP</th>
                  <th className="text-left text-xs font-medium text-gray-300 px-4 py-3 whitespace-nowrap">Network Label</th>
                </tr>
              </thead>
              <tbody>
                {vlanSegments.map(seg => (
                  <tr key={seg.interface} className="border-b border-gray-800/50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-gray-300">{seg.interface}</span>
                        {getVlanId(seg.interface) !== null && (
                          <span className="text-xs px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30">
                            VLAN {getVlanId(seg.interface)}
                          </span>
                        )}
                        {seg.manual && (
                          <button
                            onClick={() => handleRemoveManualInterface(seg.interface)}
                            className="text-gray-500 hover:text-red-400 text-xs transition-colors"
                            title="Remove"
                            aria-label={`Remove ${seg.interface}`}
                          >
                            ✕
                          </button>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-gray-400">{seg.sample_local_ip || '\u2014'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div>
                        <input
                          type="text"
                          maxLength={11}
                          value={labels[seg.interface] || ''}
                          onChange={(e) => handleLabelChange(seg.interface, e.target.value)}
                          placeholder={seg.suggested_label || 'e.g., Main LAN'}
                          className={`w-full px-3 py-1.5 bg-gray-800 border rounded text-sm text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
                            duplicateLabels.has(seg.interface) ? 'border-yellow-500/50' : 'border-gray-700'
                          }`}
                        />
                        {duplicateLabels.has(seg.interface) && (
                          <p className="text-xs text-yellow-400 mt-1">Duplicate label</p>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Add VLAN interface */}
      {!loading && !error && (
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-2">Add VLAN interface</h3>
          <p className="text-xs text-gray-400 mb-3">
            If a VLAN isn't listed above (no logs yet), enter its ID and label.
            VLAN 1 maps to br0, all others map to br&lt;ID&gt;.
          </p>
          <div className="flex items-center gap-3">
            <input
              type="number"
              min={1}
              max={4094}
              value={vlanId}
              onChange={(e) => setVlanId(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddVlan()}
              placeholder="VLAN ID"
              className="w-28 px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm font-mono text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            />
            {vlanId && vlanIdToInterface(parseInt(vlanId)) && (
              <span className="text-xs font-mono text-gray-400 shrink-0">
                {vlanIdToInterface(parseInt(vlanId))}
              </span>
            )}
            <input
              type="text"
              maxLength={20}
              value={vlanLabel}
              onChange={(e) => setVlanLabel(e.target.value.replace(LABEL_REGEX, ''))}
              onKeyDown={(e) => e.key === 'Enter' && handleAddVlan()}
              placeholder="Label (e.g., IoT, Guest)"
              className="flex-1 max-w-xs px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            />
            <button
              onClick={handleAddVlan}
              disabled={!isValidVlanId()}
              className={`px-4 py-1.5 rounded font-medium text-sm transition-all ${
                isValidVlanId()
                  ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              Add
            </button>
          </div>
        </div>
      )}

      {/* ── VPN Networks ────────────────────────────────────── */}
      {!loading && !error && vpnSegments.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-gray-300 mb-2 uppercase tracking-wider">
            VPN Networks
          </h3>
          <VpnNetworkTable
            entries={vpnSegments.map(seg => {
              const vpnCfg = (vpnConfigs || {})[seg.interface] || {}
              return {
                iface: seg.interface,
                sampleIp: seg.sample_local_ip,
                badge: vpnCfg.badge || '',
                type: vpnCfg.type || '',
                label: labels[seg.interface] || '',
                cidr: vpnCfg.cidr || '',
              }
            })}
            showSampleIp
            onBadgeChange={handleVpnBadgeChange}
            onTypeChange={handleVpnTypeChange}
            onLabelChange={handleLabelChange}
            onCidrChange={handleVpnCidrChange}
            borderColor="border-gray-800"
          />
        </section>
      )}

      {!loading && !error && (
        <div className="flex justify-between">
          <button
            onClick={onBack}
            className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
          >
            Back
          </button>
          <button
            onClick={onNext}
            disabled={hasValidationErrors || disabled}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              hasValidationErrors || disabled
                ? 'bg-gray-800 text-gray-400 cursor-not-allowed'
                : 'bg-teal-600 hover:bg-teal-500 text-white'
            }`}
          >
            {nextLabel || 'Next'}
          </button>
        </div>
      )}
    </div>
  )
}
