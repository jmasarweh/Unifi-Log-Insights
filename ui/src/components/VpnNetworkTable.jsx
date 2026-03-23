import { useState } from 'react'
import {
  getIfaceDescription, getMismatchWarning, generateVpnInterface,
  BADGE_LABELS, BADGE_CHOICES,
} from '../vpnUtils'

/**
 * Shared VPN network edit table used by:
 *  - Settings › WAN & Networks (edit mode)
 *  - Wizard › Label Interfaces step
 *
 * Props:
 *   entries       – [{ iface, sampleIp?, badge, type, label, cidr }]
 *   showSampleIp  – render the "Sample IP" column (wizard only)
 *   showRemove    – render ✕ remove button per row (settings only)
 *   onBadgeChange(iface, value)
 *   onTypeChange(iface, value)
 *   onLabelChange(iface, value)
 *   onCidrChange(iface, value)
 *   onRemove(iface)
 *   addForm       – { availableTypes, existingInterfaces, onAdd } or null
 *   borderColor   – tailwind border class (default "border-gray-700")
 */
export default function VpnNetworkTable({
  entries,
  showSampleIp = false,
  showRemove = false,
  onBadgeChange,
  onTypeChange,
  onLabelChange,
  onCidrChange,
  onRemove,
  addForm = null,
  borderColor = 'border-gray-700',
}) {
  return (
    <div className={`overflow-x-auto rounded-lg border ${borderColor}`}>
      <table className="w-full text-sm">
        <thead>
          <tr className={`text-sm text-gray-400 border-b ${borderColor}`}>
            <th className="px-4 py-2 text-left font-semibold whitespace-nowrap">Interface</th>
            {showSampleIp && <th className="px-4 py-2 text-left font-semibold whitespace-nowrap">Sample IP</th>}
            <th className="px-4 py-2 text-left font-semibold whitespace-nowrap">Badge</th>
            <th className="px-4 py-2 text-left font-semibold whitespace-nowrap">VPN Type</th>
            <th className="px-4 py-2 text-left font-semibold whitespace-nowrap">Network Label</th>
            <th className="px-4 py-2 text-left font-semibold whitespace-nowrap">
              <div>Network Pool / CIDR</div>
              <div className="font-normal text-xs text-gray-500 normal-case tracking-normal">First IP = VPN Gateway</div>
            </th>
            {showRemove && <th className="w-10"></th>}
          </tr>
        </thead>
        <tbody>
          {entries.map(entry => {
            const desc = getIfaceDescription(entry.iface)
            const warning = getMismatchWarning(entry.iface, entry.type)
            return (
              <tr key={entry.iface} className={`border-t border-gray-800`}>
                <td className="px-4 py-2.5">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-gray-300">{desc || entry.iface}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-teal-500/15 text-teal-400 border border-teal-500/30">
                        VPN
                      </span>
                    </div>
                    <span className="text-xs font-mono text-gray-500">{entry.iface}</span>
                  </div>
                </td>
                {showSampleIp && (
                  <td className="px-4 py-2.5">
                    <span className="text-sm font-mono text-gray-400">{entry.sampleIp || '\u2014'}</span>
                  </td>
                )}
                <td className="px-4 py-2.5">
                  <input
                    type="text"
                    maxLength={8}
                    value={entry.badge || ''}
                    onChange={e => onBadgeChange(entry.iface, e.target.value)}
                    placeholder="VPN"
                    className="w-24 px-2 py-1 rounded bg-black border border-gray-600 text-sm text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
                  />
                </td>
                <td className="px-4 py-2.5">
                  <div>
                    <select
                      value={entry.type || ''}
                      onChange={e => onTypeChange(entry.iface, e.target.value)}
                      className={`w-full px-2 py-1 bg-black border rounded text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20 ${
                        warning ? 'border-yellow-500/50' : 'border-gray-600'
                      }`}
                    >
                      <option value="">Select type...</option>
                      {BADGE_CHOICES.map(b => (
                        <option key={b} value={b}>{BADGE_LABELS[b]}</option>
                      ))}
                    </select>
                    {warning && (
                      <p className="text-sm text-yellow-400 mt-1">{warning}</p>
                    )}
                  </div>
                </td>
                <td className="px-4 py-2.5">
                  <input
                    type="text"
                    maxLength={11}
                    value={entry.label || ''}
                    onChange={e => onLabelChange(entry.iface, e.target.value)}
                    placeholder="VPN"
                    className="w-28 px-2 py-1 rounded bg-black border border-gray-600 text-sm text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
                  />
                </td>
                <td className="px-4 py-2.5">
                  <input
                    type="text"
                    value={entry.cidr || ''}
                    onChange={e => onCidrChange(entry.iface, e.target.value)}
                    placeholder="e.g., 10.10.70.0/24"
                    className="w-full px-2 py-1 rounded bg-black border border-gray-600 text-sm font-mono text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
                  />
                </td>
                {showRemove && (
                  <td className="px-2 py-2.5 text-center">
                    <button
                      onClick={() => onRemove(entry.iface)}
                      className="text-gray-500 hover:text-red-400 transition-colors text-sm"
                      title="Remove VPN network"
                    >
                      ✕
                    </button>
                  </td>
                )}
              </tr>
            )
          })}
        </tbody>
        {addForm && <AddRow {...addForm} showSampleIp={showSampleIp} />}
      </table>
    </div>
  )
}

/** "Add VPN Network" row rendered as <tfoot> so columns align with the table. */
function AddRow({ availableTypes, existingInterfaces, onAdd, showSampleIp }) {
  const [addType, setAddType] = useState('')
  const [addCidr, setAddCidr] = useState('')

  const addBadge = addType ? 'VPN' : ''
  const addLabel = addType || ''
  const canAdd = !!addType

  const handleAdd = () => {
    if (!canAdd) return
    const iface = generateVpnInterface(addType, existingInterfaces)
    if (!iface) return
    onAdd(iface, { badge: addBadge, cidr: addCidr, label: addLabel, type: addType })
    setAddType('')
    setAddCidr('')
  }

  if (availableTypes.length === 0) return null

  return (
    <tfoot>
      <tr className="border-t border-dashed border-gray-700 bg-gray-950/50">
        <td className="px-4 py-2.5">
          <span className="text-sm text-gray-500 italic">New entry</span>
        </td>
        {showSampleIp && <td className="px-4 py-2.5"></td>}
        <td className="px-4 py-2.5">
          <input
            type="text"
            readOnly
            value={addBadge}
            className="w-24 px-2 py-1 rounded bg-black/50 border border-gray-700 text-sm text-gray-400 cursor-default"
          />
        </td>
        <td className="px-4 py-2.5">
          <select
            value={addType}
            onChange={e => setAddType(e.target.value)}
            className="w-full px-2 py-1 bg-black border border-gray-600 rounded text-sm text-gray-200 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
          >
            <option value="">Select type...</option>
            {availableTypes.map(b => (
              <option key={b} value={b}>{BADGE_LABELS[b]}</option>
            ))}
          </select>
        </td>
        <td className="px-4 py-2.5">
          <input
            type="text"
            readOnly
            value={addLabel}
            className="w-28 px-2 py-1 rounded bg-black/50 border border-gray-700 text-sm text-gray-400 cursor-default"
          />
        </td>
        <td className="px-4 py-2.5">
          <input
            type="text"
            value={addCidr}
            onChange={e => setAddCidr(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAdd()}
            placeholder="e.g., 10.10.70.0/24"
            className="w-full px-2 py-1 rounded bg-black border border-gray-600 text-sm font-mono text-gray-200 placeholder-gray-500 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
          />
        </td>
        <td className="px-2 py-2.5 text-center">
          <button
            onClick={handleAdd}
            disabled={!canAdd}
            className="px-2 py-1 rounded text-sm font-medium bg-teal-600 hover:bg-teal-500 text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
          >
            + Add
          </button>
        </td>
      </tr>
    </tfoot>
  )
}
