/**
 * Component tests for the retention cleanup async job flow in SettingsDataBackups.
 *
 * Tests the polling, message, and count-refresh behavior by leveraging
 * the mount-time cleanup status detection (which sets showCleanup=true
 * when a running job is detected).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'

// ── Mocks ────────────────────────────────────────────────────────────────────

const mockFetchRetentionCleanupStatus = vi.fn()
const mockFetchLogCountsByType = vi.fn()

vi.mock('../api', () => ({
  fetchRetentionConfig: vi.fn(() => Promise.resolve({
    retention_days: 60, dns_retention_days: 10, retention_hour: 3,
  })),
  updateRetentionConfig: vi.fn(() => Promise.resolve({ success: true })),
  runRetentionCleanup: vi.fn(() => Promise.resolve({ success: true, status: 'running' })),
  fetchRetentionCleanupStatus: (...args) => mockFetchRetentionCleanupStatus(...args),
  exportConfig: vi.fn(() => Promise.resolve({})),
  importConfig: vi.fn(() => Promise.resolve({})),
  testMigrationConnection: vi.fn(() => Promise.resolve({ success: true })),
  startMigration: vi.fn(() => Promise.resolve({ success: true })),
  getMigrationStatus: vi.fn(() => Promise.resolve({ status: 'idle', is_external: false })),
  patchMigrationCompose: vi.fn(() => Promise.resolve({})),
  fetchLogCountsByType: (...args) => mockFetchLogCountsByType(...args),
  purgeLogsByType: vi.fn(() => Promise.resolve({})),
  fetchPurgeStatus: vi.fn(() => Promise.resolve({})),
  fetchUiSettings: vi.fn(() => Promise.resolve({
    wifi_processing_enabled: true, system_processing_enabled: true,
  })),
  updateUiSettings: vi.fn(() => Promise.resolve({})),
}))

vi.mock('../components/CopyButton', () => ({ default: (props) => <button>{props.text}</button> }))
vi.mock('../components/InfoTooltip', () => ({ default: () => <span /> }))
vi.mock('../components/SyslogToggle', () => ({ default: () => <div /> }))

import SettingsDataBackups from '../components/SettingsDataBackups'

const POLL_TIMEOUT = 10_000

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchLogCountsByType.mockResolvedValue({
    firewall: 1000, dns: 500, wifi: 200, system: 50,
  })
})


describe('Retention cleanup async job flow', () => {
  it('detects in-progress cleanup on mount and shows running button', async () => {
    mockFetchRetentionCleanupStatus.mockResolvedValue({
      status: 'running', deleted_so_far: 300, phase: 'non_dns',
    })

    await act(async () => {
      render(<SettingsDataBackups totalLogs={1750} storage={null} onSaved={() => {}} />)
    })

    expect(screen.getByText(/Cleaning up/)).toBeInTheDocument()
  })

  it('transitions from running to complete and refreshes log counts', async () => {
    let pollCount = 0
    mockFetchRetentionCleanupStatus.mockImplementation(() => {
      pollCount++
      // Mount check returns running, first poll still running, second poll complete
      if (pollCount <= 2) return Promise.resolve({ status: 'running', deleted_so_far: 100, phase: 'dns' })
      return Promise.resolve({ status: 'complete', deleted_so_far: 250, dns_deleted: 100, non_dns_deleted: 150 })
    })

    await act(async () => {
      render(<SettingsDataBackups totalLogs={1750} storage={null} onSaved={() => {}} />)
    })

    const countCallsBefore = mockFetchLogCountsByType.mock.calls.length

    // Wait for the complete message to appear via polling
    await waitFor(() => {
      expect(screen.getByText(/Cleanup complete/)).toBeInTheDocument()
    }, { timeout: POLL_TIMEOUT })

    expect(screen.getByText(/250/)).toBeInTheDocument()
    // Log counts must have been refreshed
    expect(mockFetchLogCountsByType.mock.calls.length).toBeGreaterThan(countCallsBefore)
  }, POLL_TIMEOUT + 5000)

  it('shows partial failure with deleted count and error', async () => {
    let pollCount = 0
    mockFetchRetentionCleanupStatus.mockImplementation(() => {
      pollCount++
      if (pollCount <= 1) return Promise.resolve({ status: 'running', deleted_so_far: 50, phase: 'dns' })
      return Promise.resolve({ status: 'partial', deleted_so_far: 75, error: 'disk full' })
    })

    await act(async () => {
      render(<SettingsDataBackups totalLogs={1750} storage={null} onSaved={() => {}} />)
    })

    await waitFor(() => {
      expect(screen.getByText(/partially done/i)).toBeInTheDocument()
    }, { timeout: POLL_TIMEOUT })

    // The message should contain both the count and the error
    expect(screen.getByText(/75.*removed.*disk full/)).toBeInTheDocument()
    // Partial deletes rows too — counts should refresh
    expect(mockFetchLogCountsByType.mock.calls.length).toBeGreaterThan(1)
  }, POLL_TIMEOUT + 5000)

  it('shows failure message on failed status', async () => {
    let pollCount = 0
    mockFetchRetentionCleanupStatus.mockImplementation(() => {
      pollCount++
      if (pollCount <= 1) return Promise.resolve({ status: 'running', deleted_so_far: 0, phase: 'dns' })
      return Promise.resolve({ status: 'failed', deleted_so_far: 0, error: 'connection lost' })
    })

    await act(async () => {
      render(<SettingsDataBackups totalLogs={1750} storage={null} onSaved={() => {}} />)
    })

    await waitFor(() => {
      expect(screen.getByText(/Cleanup failed/)).toBeInTheDocument()
    }, { timeout: POLL_TIMEOUT })

    expect(screen.getByText(/connection lost/)).toBeInTheDocument()
  }, POLL_TIMEOUT + 5000)
})
