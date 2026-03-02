import { useState } from 'react'
import { formatNumber } from '../utils'
import ReleaseNotesModal, { isNewerVersion } from './ReleaseNotesModal'

export default function Pagination({ page, pages, total, perPage, onChange, version, latestRelease }) {
  const start = (page - 1) * perPage + 1
  const end = Math.min(page * perPage, total)
  const outdated = latestRelease && isNewerVersion(latestRelease.tag, version)
  const [showNotes, setShowNotes] = useState(false)

  return (
    <>
      <div className="flex items-center justify-between px-3 py-2 border-t border-gray-800">
        <span className="text-[11px] text-gray-400">
          {total > 0 ? `${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(total)}` : 'No results'}
        </span>
        {version && (
          <div className="flex items-center gap-1.5">
            <span className={`hidden md:inline text-xs ${outdated ? 'text-amber-400' : 'text-white'}`}>v{version}</span>
            {outdated ? (
              <button
                onClick={() => setShowNotes(true)}
                className="hidden md:inline-flex items-center gap-1 text-xs text-amber-400 hover:text-amber-300 transition-colors"
                title={`Update available: ${latestRelease.tag}`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-3.5 h-3.5">
                  <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                </svg>
                Update available
              </button>
            ) : latestRelease?.body && (
              <button
                onClick={() => setShowNotes(true)}
                className="hidden md:inline text-xs text-gray-400 hover:text-gray-200 transition-colors"
              >
                - Release Notes
              </button>
            )}
          </div>
        )}
        <div className="flex items-center gap-1">
          <button
            disabled={page <= 1}
            onClick={() => onChange(1)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            ««
          </button>
          <button
            disabled={page <= 1}
            onClick={() => onChange(page - 1)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            «
          </button>
          <span className="px-3 py-1 text-xs text-gray-300">
            {page} / {pages || 1}
          </span>
          <button
            disabled={page >= pages}
            onClick={() => onChange(page + 1)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            »
          </button>
          <button
            disabled={page >= pages}
            onClick={() => onChange(pages)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            »»
          </button>
        </div>
      </div>

      {showNotes && latestRelease && (
        <ReleaseNotesModal latestRelease={latestRelease} onClose={() => setShowNotes(false)} currentVersion={version} />
      )}
    </>
  )
}
