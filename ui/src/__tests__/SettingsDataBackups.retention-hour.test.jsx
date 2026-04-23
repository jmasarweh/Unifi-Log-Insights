/**
 * Component tests for the cleanup-hour selector in SettingsDataBackups.
 * Covers: initial render matches saved value, dirty detection, save payload,
 * and footer reflects the saved (not pending) hour.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'

const mockUpdateRetentionConfig = vi.fn(() => Promise.resolve({ success: true }))

vi.mock('../api', () => ({
  fetchRetentionConfig: vi.fn(() => Promise.resolve({
    retention_days: 60, dns_retention_days: 10, retention_hour: 15,
  })),
  updateRetentionConfig: (...args) => mockUpdateRetentionConfig(...args),
  runRetentionCleanup: vi.fn(() => Promise.resolve({ success: true, status: 'running' })),
  fetchRetentionCleanupStatus: vi.fn(() => Promise.resolve({ status: 'idle' })),
  exportConfig: vi.fn(() => Promise.resolve({})),
  importConfig: vi.fn(() => Promise.resolve({})),
  testMigrationConnection: vi.fn(() => Promise.resolve({ success: true })),
  startMigration: vi.fn(() => Promise.resolve({ success: true })),
  getMigrationStatus: vi.fn(() => Promise.resolve({ status: 'idle', is_external: false })),
  patchMigrationCompose: vi.fn(() => Promise.resolve({})),
  fetchLogCountsByType: vi.fn(() => Promise.resolve({ firewall: 0, dns: 0, wifi: 0, system: 0 })),
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

beforeEach(() => {
  vi.clearAllMocks()
  mockUpdateRetentionConfig.mockResolvedValue({ success: true })
})

describe('retention hour selector', () => {
  it('selects the saved hour after initial load', async () => {
    render(<SettingsDataBackups totalLogs={0} storage={null} />)
    const select = await screen.findByLabelText(/cleanup hour/i)
    expect(select.value).toBe('15')
  })

  it('footer reflects the saved hour, not the pending one', async () => {
    render(<SettingsDataBackups totalLogs={0} storage={null} />)
    await screen.findByLabelText(/cleanup hour/i)
    // Initial footer matches the server value.
    expect(screen.getByText(/Cleanup runs daily at 15:00/)).toBeInTheDocument()

    // Change the selector without saving — footer must NOT update yet.
    fireEvent.change(screen.getByLabelText(/cleanup hour/i), { target: { value: '7' } })
    expect(screen.getByText(/Cleanup runs daily at 15:00/)).toBeInTheDocument()
    expect(screen.queryByText(/Cleanup runs daily at 07:00/)).not.toBeInTheDocument()
  })

  it('enables Save and sends the hour in the payload on save', async () => {
    render(<SettingsDataBackups totalLogs={0} storage={null} />)
    await screen.findByLabelText(/cleanup hour/i)

    // The panel has multiple "Save" buttons (one per section). The retention
    // Save lives in the same card as the hour selector — walk up to the card
    // and scope the query.
    const hourSelect = screen.getByLabelText(/cleanup hour/i)
    const card = hourSelect.closest('.rounded-lg')
    const saveBtn = Array.from(card.querySelectorAll('button'))
      .find(b => b.textContent.trim() === 'Save')
    expect(saveBtn).toBeDisabled()

    fireEvent.change(screen.getByLabelText(/cleanup hour/i), { target: { value: '7' } })
    expect(saveBtn).not.toBeDisabled()

    fireEvent.click(saveBtn)
    await waitFor(() => expect(mockUpdateRetentionConfig).toHaveBeenCalled())
    const payload = mockUpdateRetentionConfig.mock.calls[0][0]
    expect(payload).toMatchObject({
      retention_days: 60,
      dns_retention_days: 10,
      retention_hour: 7,
    })
  })
})
