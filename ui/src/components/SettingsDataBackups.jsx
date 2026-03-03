import { useState, useEffect, useRef } from 'react'
import {
  fetchRetentionConfig, updateRetentionConfig, runRetentionCleanup,
  exportConfig, importConfig
} from '../api'

const RETENTION_PRESETS = [30, 60, 90, 120, 180, 365]
const DISK_CRITICAL_BYTES = 512 * 1024 * 1024       // 512 MB
const DISK_WARNING_BYTES  = 2 * 1024 * 1024 * 1024  // 2 GB

function formatBytes(bytes) {
  if (bytes == null) return '—'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
}

export default function SettingsDataBackups({ totalLogs, storage }) {
  // Retention state
  const [retention, setRetention] = useState(null)
  const [retentionDays, setRetentionDays] = useState(60)
  const [dnsRetentionDays, setDnsRetentionDays] = useState(10)
  const [retentionSaving, setRetentionSaving] = useState(false)
  const [retentionMsg, setRetentionMsg] = useState(null)
  const [showCleanup, setShowCleanup] = useState(false)
  const [cleaningUp, setCleaningUp] = useState(false)

  // Export/Import state
  const [exporting, setExporting] = useState(false)
  const [importPreview, setImportPreview] = useState(null)
  const [importMsg, setImportMsg] = useState(null)
  const fileInputRef = useRef(null)

  useEffect(() => {
    fetchRetentionConfig().then(data => {
      setRetention(data)
      setRetentionDays(data.retention_days)
      setDnsRetentionDays(data.dns_retention_days)
    }).catch(err => console.error('Failed to load retention config:', err))
  }, [])

  // ── Retention handlers ──
  const retentionDirty = retention && (
    retentionDays !== retention.retention_days || dnsRetentionDays !== retention.dns_retention_days
  )

  async function saveRetention() {
    setRetentionSaving(true)
    setRetentionMsg(null)
    try {
      const wasLowered = retention && (
        retentionDays < retention.retention_days || dnsRetentionDays < retention.dns_retention_days
      )
      await updateRetentionConfig({ retention_days: retentionDays, dns_retention_days: dnsRetentionDays })
      setRetention(prev => ({ ...prev, retention_days: retentionDays, dns_retention_days: dnsRetentionDays }))
      setRetentionMsg({ type: 'success', text: 'Retention settings saved' })
      if (wasLowered) {
        setShowCleanup(true)
      } else {
        setShowCleanup(false)
        setTimeout(() => setRetentionMsg(null), 3000)
      }
    } catch (e) {
      setRetentionMsg({ type: 'error', text: e.message })
    } finally {
      setRetentionSaving(false)
    }
  }

  async function handleCleanupNow() {
    setCleaningUp(true)
    setRetentionMsg(null)
    try {
      const result = await runRetentionCleanup()
      setRetentionMsg({ type: 'success', text: `Cleanup complete — ${result.deleted.toLocaleString()} logs removed` })
      setShowCleanup(false)
      setTimeout(() => setRetentionMsg(null), 5000)
    } catch (e) {
      setRetentionMsg({ type: 'error', text: 'Cleanup failed: ' + e.message })
    } finally {
      setCleaningUp(false)
    }
  }

  // ── Export handlers ──
  async function handleExport(includeApiKey) {
    setExporting(true)
    try {
      const data = await exportConfig(includeApiKey)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      const date = new Date().toISOString().slice(0, 10)
      a.href = url
      a.download = `unifi-log-insight-config-${date}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert('Export failed: ' + e.message)
    } finally {
      setExporting(false)
    }
  }

  // ── Import handlers ──
  function handleImportFileSelect(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result)
        if (!data.config || typeof data.config !== 'object') {
          setImportMsg({ type: 'error', text: 'Invalid config file format' })
          setImportPreview(null)
          return
        }
        setImportPreview(data)
        setImportMsg(null)
      } catch {
        setImportMsg({ type: 'error', text: 'Failed to parse JSON file' })
        setImportPreview(null)
      }
    }
    reader.readAsText(file)
  }

  async function handleImportConfirm() {
    if (!importPreview) return
    setImportMsg(null)
    try {
      const result = await importConfig(importPreview)
      setImportMsg({ type: 'success', text: `Imported ${result.imported_keys.length} settings. Reloading...` })
      setTimeout(() => window.location.reload(), 1500)
    } catch (e) {
      setImportMsg({ type: 'error', text: 'Import failed: ' + e.message })
    }
  }

  function cancelImport() {
    setImportPreview(null)
    setImportMsg(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  return (
    <div className="space-y-8">
      {/* ── Data Retention ─────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          Data Retention
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-5">
            {/* General retention slider */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-gray-300">Log retention</label>
                <span className="text-sm font-mono font-semibold text-gray-200">{retentionDays} days</span>
              </div>
              <input
                type="range"
                min={1}
                max={365}
                value={retentionDays}
                onChange={e => setRetentionDays(Number(e.target.value))}
                className="w-full accent-blue-500"
              />
              <div className="flex flex-wrap gap-1.5 mt-2">
                {RETENTION_PRESETS.map(preset => (
                  <button
                    key={preset}
                    onClick={() => setRetentionDays(preset)}
                    className={`text-[11px] font-mono px-2 py-0.5 rounded border transition-colors ${
                      retentionDays === preset
                        ? 'border-blue-500 text-blue-400 bg-blue-500/10'
                        : 'border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {preset}d
                  </button>
                ))}
              </div>
              {retentionDays > 120 && (
                <div className="mt-2 flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                  <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <p className="text-xs text-yellow-400/90">
                    Extended retention may affect query performance on large datasets. Ensure you have enough disk space.
                  </p>
                </div>
              )}
            </div>

            {/* DNS retention input */}
            <div>
              <div className="flex items-center justify-between">
                <label className="text-sm text-gray-300">DNS log retention</label>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={dnsRetentionDays}
                    onChange={e => setDnsRetentionDays(Math.max(1, Math.min(365, parseInt(e.target.value) || 1)))}
                    className="w-16 px-2 py-1 rounded bg-gray-900 border border-gray-600 font-mono text-xs text-gray-200 text-right focus:border-blue-500 focus:outline-none"
                  />
                  <span className="text-xs text-gray-500">days</span>
                </div>
              </div>
            </div>

            {/* Info note */}
            <div className="flex items-start gap-2 bg-blue-500/10 border border-blue-500/30 rounded px-3 py-2">
              <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
              </svg>
              <p className="text-xs text-blue-400/90">
                Time range filters in Log Stream and Dashboard automatically adjust to
                show only ranges with available data. If logs from a previous retention
                period haven't been cleaned up yet, filters may extend beyond your
                current retention setting.
              </p>
            </div>
          </div>

          {/* Storage info */}
          {storage && storage.db_size_bytes != null && (() => {
            const dbSize = storage.db_size_bytes
            const volAvail = storage.volume_available_bytes
            const critical = volAvail != null && volAvail < DISK_CRITICAL_BYTES
            const warning = volAvail != null && volAvail < DISK_WARNING_BYTES
            return (
              <div className="px-5 pb-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-400">Database size</span>
                  <span className="text-xs text-gray-300 font-mono">{formatBytes(dbSize)}</span>
                </div>
                {volAvail != null && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-400">Disk space available</span>
                    <span className={`text-xs font-mono ${critical ? 'text-red-400' : warning ? 'text-yellow-400' : 'text-gray-300'}`}>{formatBytes(volAvail)}</span>
                  </div>
                )}
                {critical && (
                  <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded px-3 py-2">
                    <svg className="w-4 h-4 text-red-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                    </svg>
                    <p className="text-xs text-red-400/90">
                      Disk space is critically low. Reduce retention or free up space to prevent log ingestion from stopping.
                    </p>
                  </div>
                )}
                {warning && !critical && (
                  <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2">
                    <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                    </svg>
                    <p className="text-xs text-yellow-400/90">
                      Disk space is running low. Consider lowering retention days or increasing allocated disk space.
                    </p>
                  </div>
                )}
              </div>
            )
          })()}

          {/* Save + status */}
          <div className="border-t border-gray-800" />
          <div className="px-5 py-3 flex items-center justify-between">
            <p className="text-xs text-gray-500">
              {totalLogs != null && <>{totalLogs.toLocaleString()} logs stored · </>}Cleanup runs daily at 03:00 UTC
            </p>
            <div className="flex items-center gap-3">
              {retentionMsg && (
                <span className={`text-xs ${retentionMsg.type === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {retentionMsg.text}
                </span>
              )}
              {showCleanup && (
                <button
                  onClick={handleCleanupNow}
                  disabled={cleaningUp}
                  className="px-4 py-1.5 rounded text-xs font-medium border border-yellow-500/50 text-yellow-400 hover:bg-yellow-500/10 transition-colors disabled:opacity-50"
                >
                  {cleaningUp ? 'Cleaning up...' : 'Run Cleanup Now'}
                </button>
              )}
              <button
                onClick={saveRetention}
                disabled={!retentionDirty || retentionSaving}
                className={`px-4 py-1.5 rounded text-xs font-medium transition-colors ${
                  retentionDirty
                    ? 'bg-teal-600 text-white hover:bg-teal-500'
                    : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                }`}
              >
                {retentionSaving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ── External Database ────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          External Database
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          <div className="p-5 space-y-4">
            <p className="text-sm text-gray-300">
              You can point UniFi Log Insight at an existing PostgreSQL 14+ instance instead of using the embedded database.
              The schema is auto-provisioned on first boot — no need to run <code className="text-xs bg-gray-800 px-1 py-0.5 rounded">init.sql</code> manually.
            </p>

            {/* Migration steps */}
            <div className="flex items-start gap-2 bg-blue-500/10 border border-blue-500/30 rounded px-3 py-2.5">
              <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
              </svg>
              <div className="text-xs text-blue-400/90 space-y-1.5">
                <p className="font-medium text-blue-400">Migration Steps</p>
                <ol className="list-decimal list-inside space-y-1 ml-1">
                  <li>Export your configuration using Backup &amp; Restore below</li>
                  <li>Dump data: <code className="bg-blue-500/10 px-1 py-0.5 rounded">docker exec unifi-log-insight pg_dump -U unifi unifi_logs &gt; backup.sql</code></li>
                  <li>Create the target database and user on the external instance</li>
                  <li>Restore: <code className="bg-blue-500/10 px-1 py-0.5 rounded">psql -h &lt;host&gt; -U &lt;user&gt; -d &lt;dbname&gt; -f backup.sql</code></li>
                  <li>Update <code className="bg-blue-500/10 px-1 py-0.5 rounded">docker-compose.yml</code> with <code className="bg-blue-500/10 px-1 py-0.5 rounded">DB_HOST</code>, <code className="bg-blue-500/10 px-1 py-0.5 rounded">DB_PORT</code>, <code className="bg-blue-500/10 px-1 py-0.5 rounded">DB_NAME</code>, <code className="bg-blue-500/10 px-1 py-0.5 rounded">DB_USER</code>, <code className="bg-blue-500/10 px-1 py-0.5 rounded">DB_PASSWORD</code></li>
                  <li>Remove the <code className="bg-blue-500/10 px-1 py-0.5 rounded">pgdata</code> volume mount (old data will sit unused if left)</li>
                  <li>Restart: <code className="bg-blue-500/10 px-1 py-0.5 rounded">docker compose up -d</code></li>
                  <li>Import config backup via Backup &amp; Restore</li>
                </ol>
              </div>
            </div>

            {/* Important notes */}
            <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2.5">
              <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
              </svg>
              <div className="text-xs text-yellow-400/90 space-y-1">
                <p className="font-medium text-yellow-400">Important</p>
                <ul className="list-disc list-inside space-y-0.5 ml-1">
                  <li><code className="bg-yellow-500/10 px-1 py-0.5 rounded">POSTGRES_PASSWORD</code> is still required (used for API key encryption, not DB connection)</li>
                  <li>If <code className="bg-yellow-500/10 px-1 py-0.5 rounded">POSTGRES_PASSWORD</code> changes, stored API keys must be re-entered</li>
                  <li>PostgreSQL 14 or newer is required</li>
                  <li>The DB user needs CREATE TABLE, CREATE INDEX, CREATE FUNCTION privileges</li>
                </ul>
              </div>
            </div>

            <a
              href="https://github.com/jmasarweh/unifi-log-insight/wiki/External-Database"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              Full Guide
              <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
              </svg>
            </a>
          </div>
        </div>
      </section>

      {/* ── Export / Import Configuration ──────────────────────── */}
      <section>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          Backup &amp; Restore
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-950">
          {/* Export */}
          <div className="p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-2">Export Configuration</h3>
            <div className="space-y-2">
              <button
                onClick={() => handleExport(false)}
                disabled={exporting}
                className="w-full text-left rounded-lg border border-gray-700 hover:border-gray-500 p-3 transition-colors disabled:opacity-50"
              >
                <div className="text-sm font-medium text-gray-200">Everything without API Key</div>
                <p className="text-xs text-gray-500 mt-1">
                  WAN Config, Network Labels, UniFi Connection (Host, Site, SSL, Polling), Retention Settings, UI Preferences
                </p>
                <div className="flex items-start gap-2 mt-1.5 bg-blue-500/10 border border-blue-500/30 rounded px-2.5 py-1.5">
                  <svg className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
                  </svg>
                  <p className="text-xs text-blue-400/90">
                    You'll need to re-enter your UniFi API key after import, or regenerate one from your controller.
                    Self-hosted credentials (username/password) are never exported.
                  </p>
                </div>
              </button>
              <button
                onClick={() => handleExport(true)}
                disabled={exporting}
                className="w-full text-left rounded-lg border border-gray-700 hover:border-gray-500 p-3 transition-colors disabled:opacity-50"
              >
                <div className="text-sm font-medium text-gray-200">Everything + API Key</div>
                <p className="text-xs text-gray-500 mt-1">
                  All settings above plus your UniFi API key
                </p>
                <div className="flex items-start gap-2 mt-1.5 bg-yellow-500/10 border border-yellow-500/30 rounded px-2.5 py-1.5">
                  <svg className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <p className="text-xs text-yellow-400/90">
                    Your API key will be included in plaintext. Store this file securely.
                  </p>
                </div>
              </button>
            </div>
          </div>

          {/* Divider */}
          <div className="border-t border-gray-800" />

          {/* Import */}
          <div className="p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-2">Import Configuration</h3>
            <input
              ref={fileInputRef}
              type="file"
              accept=".json"
              onChange={handleImportFileSelect}
              className="hidden"
            />

            {importPreview ? (
              <div className="space-y-3">
                <div className="rounded border border-gray-700 bg-gray-900 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-gray-300">
                      Backup from {importPreview.exported_at ? new Date(importPreview.exported_at).toLocaleDateString() : 'unknown date'}
                    </span>
                    {importPreview.version && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">
                        v{importPreview.version}
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-gray-500">
                    <span className="font-medium text-gray-400">{Object.keys(importPreview.config).length} settings</span> will be imported:
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {Object.keys(importPreview.config).filter(k => k !== 'unifi_api_key').map(key => (
                      <span key={key} className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono">
                        {key}
                      </span>
                    ))}
                  </div>
                  {importPreview.includes_api_key || importPreview.config.unifi_api_key ? (
                    <div className="flex items-center gap-1.5 mt-2">
                      <span className="text-xs px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                        Includes API Key
                      </span>
                    </div>
                  ) : (
                    <p className="text-[11px] text-blue-400/70 mt-2">
                      No API key in this backup. Your existing key will be kept, or you can add one later in UniFi Settings.
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleImportConfirm}
                    className="px-4 py-1.5 rounded text-xs font-medium bg-teal-600 text-white hover:bg-teal-500 transition-colors"
                  >
                    Confirm Import
                  </button>
                  <button
                    onClick={cancelImport}
                    className="px-4 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
              >
                Import from File
              </button>
            )}

            {importMsg && (
              <div className={`mt-2 text-xs ${importMsg.type === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                {importMsg.text}
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
