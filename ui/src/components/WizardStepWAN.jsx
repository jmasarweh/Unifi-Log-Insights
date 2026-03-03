import React, { useState, useEffect, useRef } from 'react'
import { fetchWANCandidates } from '../api'
import { IFACE_REGEX, validateVlanId } from '../utils'

const COMMON_WAN_INTERFACES = [
  { name: 'ppp0',  desc: 'PPPoE (DSL/Fiber)', note: 'Most Common' },
  { name: 'eth0',  desc: 'Direct Ethernet WAN' },
  { name: 'eth3',  desc: 'SFP+ Port 1' },
  { name: 'eth4',  desc: 'SFP+ Port 2' },
  { name: 'eth4.10', desc: 'VLAN-tagged WAN (e.g., ISP VLAN)' },
  { name: 'eth8',  desc: 'WAN Port (UDM models)' },
]

const LABEL_REGEX = /[^a-zA-Z0-9 _-]/g

export default function WizardStepWAN({ selected, onSelect, interfaceLabels, onUpdateLabels, onNext, onBack, reconfigMode }) {
  const [candidates, setCandidates] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [manualInput, setManualInput] = useState('')
  const [manualError, setManualError] = useState('')
  const [rescanning, setRescanning] = useState(false)
  const pollRef = useRef(null)

  useEffect(() => {
    fetchWANCandidates()
      .then(data => {
        setCandidates(data.candidates || [])
        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [])

  const handleRescan = () => {
    setRescanning(true)
    fetchWANCandidates()
      .then(data => {
        setCandidates(data.candidates || [])
        setRescanning(false)
      })
      .catch(() => setRescanning(false))
  }

  // Poll for new candidates while this step is mounted (user can rescan manually too)
  useEffect(() => {
    if (loading || error) {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
      return
    }
    pollRef.current = setInterval(() => {
      fetchWANCandidates()
        .then(data => {
          const c = data.candidates || []
          if (c.length > 0) setCandidates(c)
        })
        .catch(() => {})
    }, 5000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [loading, error])

  const handleToggle = (iface) => {
    if (selected.includes(iface)) {
      onSelect(selected.filter(i => i !== iface))
    } else {
      onSelect([...selected, iface])
    }
  }

  const handleAddManual = () => {
    const trimmed = manualInput.trim()
    if (!trimmed) return
    if (!IFACE_REGEX.test(trimmed)) {
      setManualError('Interface name must start with letters followed by a number, with optional VLAN tag (e.g., ppp0, eth4, eth4.10, sfp+0).')
      return
    }
    const vlanErr = validateVlanId(trimmed)
    if (vlanErr) {
      setManualError(vlanErr)
      return
    }
    setManualError('')
    if (!selected.includes(trimmed)) {
      onSelect([...selected, trimmed])
      setManualInput('')
    }
  }

  const handleWanLabelChange = (iface, value) => {
    const sanitized = value.replace(LABEL_REGEX, '')
    onUpdateLabels({ ...interfaceLabels, [iface]: sanitized })
  }

  const handleNextWithDefaults = () => {
    // Fill in default labels for any WAN interfaces left blank
    const updated = { ...interfaceLabels }
    let changed = false
    selected.forEach((iface, idx) => {
      if (!updated[iface] || !updated[iface].trim()) {
        updated[iface] = selected.length === 1 ? 'WAN' : `WAN ${idx + 1}`
        changed = true
      }
    })
    if (changed) onUpdateLabels(updated)
    onNext()
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-semibold text-gray-200 mb-2">
          Which interface connects to the internet?
        </h2>
        <p className="text-sm text-gray-300">
          Select your WAN interface so the system can classify traffic as
          inbound, outbound, or inter-VLAN. You can select more than one
          if you have a dual-WAN or failover setup.
        </p>
      </div>

      {loading && (
        <div className="text-center py-12 text-gray-400">
          Scanning your firewall logs...
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <p className="text-sm text-red-400">Failed to scan logs: {error}</p>
        </div>
      )}

      {/* Detected interfaces */}
      {!loading && !error && candidates.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-gray-300">
              Detected in your logs
            </h3>
            <button
              onClick={handleRescan}
              disabled={rescanning}
              className="text-xs px-3 py-1 rounded border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors disabled:opacity-50"
            >
              {rescanning ? 'Scanning...' : 'Rescan Logs'}
            </button>
          </div>
          <p className="text-xs text-gray-400 mb-3">
            Click on the interface that is your WAN. You can select multiple.
          </p>
          <div className="space-y-2">
            {candidates.map(c => (
              <div
                key={c.interface}
                onClick={() => handleToggle(c.interface)}
                className={`flex items-center justify-between px-4 py-3 rounded-lg border cursor-pointer transition-all ${
                  selected.includes(c.interface)
                    ? 'bg-blue-500/10 border-blue-500/40'
                    : 'border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    readOnly
                    checked={selected.includes(c.interface)}
                    className="ui-checkbox pointer-events-none"
                  />
                  <span className="text-sm font-mono font-semibold text-gray-200">
                    {c.interface}
                  </span>
                  {c.wan_ip && (
                    <span className="text-xs font-mono text-gray-400">{c.wan_ip}</span>
                  )}
                </div>
                <span className="text-xs text-gray-400">
                  {c.event_count?.toLocaleString()} events
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {!loading && !error && candidates.length === 0 && (
        <div className="border border-gray-700 rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="inline-block w-3 h-3 rounded-full bg-blue-400 animate-pulse" />
            <p className="text-sm text-gray-300">
              Waiting for syslog traffic... Select your WAN interface manually below, or
              wait for logs to arrive.
            </p>
          </div>
          {reconfigMode && (
            <button
              onClick={handleRescan}
              disabled={rescanning}
              className="text-xs px-3 py-1 rounded border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors disabled:opacity-50 ml-4 shrink-0"
            >
              {rescanning ? 'Scanning...' : 'Rescan'}
            </button>
          )}
        </div>
      )}

      {/* Common UniFi WAN interfaces */}
      {!loading && !error && (
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-2">
            Common UniFi WAN interfaces
          </h3>
          <p className="text-xs text-gray-400 mb-3">
            If your interface wasn't detected above, pick it from this list.
            You can select multiple.
          </p>
          <div className="space-y-2">
            {COMMON_WAN_INTERFACES.map(iface => (
              <div
                key={iface.name}
                onClick={() => handleToggle(iface.name)}
                className={`flex items-center justify-between px-4 py-3 rounded-lg border cursor-pointer transition-all ${
                  selected.includes(iface.name)
                    ? 'bg-blue-500/10 border-blue-500/40'
                    : 'border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    readOnly
                    checked={selected.includes(iface.name)}
                    className="ui-checkbox pointer-events-none"
                  />
                  <span className="text-sm font-mono font-semibold text-gray-200">
                    {iface.name}
                  </span>
                  <span className="text-xs text-gray-400">{iface.desc}</span>
                </div>
                {iface.note && (
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    {iface.note}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Manual entry */}
      {!loading && !error && (
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-2">
            Custom interface name
          </h3>
          <p className="text-xs text-gray-400 mb-3">
            If your WAN interface isn't listed above, type its name and press
            Enter or click Add. You can add multiple.
          </p>
          <div className="flex items-center gap-3">
            <input
              type="text"
              value={manualInput}
              onChange={(e) => { setManualInput(e.target.value); if (manualError) setManualError('') }}
              onKeyDown={(e) => e.key === 'Enter' && handleAddManual()}
              placeholder="e.g., eth5, eth4.10, wan0, enp3s0"
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm font-mono text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            />
            <button
              onClick={handleAddManual}
              disabled={!manualInput.trim()}
              className={`px-4 py-2 rounded-lg font-medium text-sm transition-all ${
                manualInput.trim()
                  ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              Add
            </button>
          </div>
          {manualError && (
            <p className="text-[11px] text-red-400 mt-1.5">{manualError}</p>
          )}
        </div>
      )}

      {/* Selected summary */}
      {!loading && !error && selected.length > 0 && (
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-blue-400 mb-2">
            Selected ({selected.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {selected.map(iface => (
              <div key={iface} className="flex items-center gap-2 px-3 py-1.5 bg-blue-500/20 rounded border border-blue-500/40">
                <span className="text-sm font-mono text-blue-300">{iface}</span>
                <button
                  onClick={() => handleToggle(iface)}
                  className="text-blue-400 hover:text-blue-300 text-xs"
                  title="Remove"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* WAN Interface Labels */}
      {!loading && !error && selected.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-2">
            Add a Label to your WAN Interfaces
          </h3>
          <p className="text-xs text-gray-400 mb-3">
            Give each WAN interface a friendly name, e.g. &quot;WAN Primary&quot; or &quot;WAN Backup&quot;.
          </p>
          <div className="space-y-2">
            {selected.map((iface, idx) => (
              <div key={iface} className="flex items-center gap-3 px-4 py-2.5 border border-gray-800 rounded-lg">
                <span className="text-sm font-mono text-gray-300 w-24 shrink-0">{iface}</span>
                <input
                  type="text"
                  maxLength={20}
                  value={interfaceLabels[iface] || ''}
                  onChange={(e) => handleWanLabelChange(iface, e.target.value)}
                  placeholder={selected.length === 1 ? 'e.g., WAN' : `e.g., WAN ${idx + 1}`}
                  className="flex-1 max-w-xs px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Multi-WAN warning */}
      {!loading && !error && selected.length > 1 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
          <p className="text-sm text-yellow-400">
            If your WAN interfaces change (failover, maintenance), update this
            configuration via Settings → Reconfigure to maintain accurate direction
            classification.
          </p>
        </div>
      )}

      {/* Navigation */}
      {!loading && !error && (
        <div className="flex justify-between pt-2">
          {onBack ? (
            <button
              onClick={onBack}
              className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
            >
              Back
            </button>
          ) : <div />}
          <button
            onClick={handleNextWithDefaults}
            disabled={selected.length === 0}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              selected.length > 0
                ? 'bg-teal-600 hover:bg-teal-500 text-white'
                : 'bg-gray-800 text-gray-400 cursor-not-allowed'
            }`}
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
