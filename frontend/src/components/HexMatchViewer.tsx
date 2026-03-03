import { useState, useMemo, useEffect } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'

interface MatchInfo {
  offset: number
  identifier: string
  length: number
  threatNames: string[]
}

interface HexMatchViewerProps {
  fileData: ArrayBuffer
  matches: MatchInfo[]
  fileName: string
}

export default function HexMatchViewer({ fileData, matches, fileName }: HexMatchViewerProps) {
  const [currentMatchIndex, setCurrentMatchIndex] = useState(0)
  const [viewOffset, setViewOffset] = useState(0)
  const [bytesPerRow] = useState(16)
  const [rowsToShow] = useState(20)

  const bytes = useMemo(() => new Uint8Array(fileData), [fileData])

  // Create a map of offset -> match info for quick lookup
  const matchMap = useMemo(() => {
    const map = new Map<number, MatchInfo>()
    matches.forEach(match => {
      // Mark all bytes in the match range
      for (let i = 0; i < match.length; i++) {
        const existingMatch = map.get(match.offset + i)
        if (existingMatch) {
          // Merge threat names
          existingMatch.threatNames = [...new Set([...existingMatch.threatNames, ...match.threatNames])]
        } else {
          map.set(match.offset + i, { ...match, offset: match.offset + i })
        }
      }
    })
    return map
  }, [matches])

  // Get unique match start offsets for navigation
  const matchOffsets = useMemo(() => {
    return [...new Set(matches.map(m => m.offset))].sort((a, b) => a - b)
  }, [matches])

  // Jump to current match
  useEffect(() => {
    if (matchOffsets.length > 0 && currentMatchIndex < matchOffsets.length) {
      const matchOffset = matchOffsets[currentMatchIndex]
      // Center the match in the view
      const rowStart = Math.floor(matchOffset / bytesPerRow) - Math.floor(rowsToShow / 2)
      setViewOffset(Math.max(0, rowStart * bytesPerRow))
    }
  }, [currentMatchIndex, matchOffsets, bytesPerRow, rowsToShow])

  const goToNextMatch = () => {
    if (currentMatchIndex < matchOffsets.length - 1) {
      setCurrentMatchIndex(currentMatchIndex + 1)
    }
  }

  const goToPrevMatch = () => {
    if (currentMatchIndex > 0) {
      setCurrentMatchIndex(currentMatchIndex - 1)
    }
  }

  // Generate hex rows
  const hexRows = useMemo(() => {
    const rows = []
    const startOffset = viewOffset
    const endOffset = Math.min(startOffset + (rowsToShow * bytesPerRow), bytes.length)

    for (let offset = startOffset; offset < endOffset; offset += bytesPerRow) {
      const rowBytes = []
      const asciiChars = []

      for (let i = 0; i < bytesPerRow; i++) {
        const byteOffset = offset + i
        if (byteOffset < bytes.length) {
          const byte = bytes[byteOffset]
          const match = matchMap.get(byteOffset)

          rowBytes.push({
            byte,
            hex: byte.toString(16).padStart(2, '0').toUpperCase(),
            offset: byteOffset,
            isMatch: !!match,
            matchInfo: match,
          })

          // ASCII representation
          const char = byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.'
          asciiChars.push({
            char,
            isMatch: !!match,
          })
        } else {
          rowBytes.push({ byte: null, hex: '  ', offset: byteOffset, isMatch: false })
          asciiChars.push({ char: ' ', isMatch: false })
        }
      }

      rows.push({
        offset,
        offsetHex: offset.toString(16).padStart(8, '0').toUpperCase(),
        bytes: rowBytes,
        ascii: asciiChars,
      })
    }

    return rows
  }, [bytes, viewOffset, bytesPerRow, rowsToShow, matchMap])

  // Current match info
  const currentMatch = matchOffsets.length > 0 ? matches.find(m => m.offset === matchOffsets[currentMatchIndex]) : null

  return (
    <div className="bg-bg-surface border border-border-visible">
      {/* Header */}
      <div className="px-4 py-3 border-b border-border-dim flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-text-bright">Binary View</h3>
          <p className="text-xs text-text-muted">
            {fileName} • {bytes.length.toLocaleString()} bytes • {matches.length} matches
          </p>
        </div>

        {/* Match navigation */}
        {matchOffsets.length > 0 && (
          <div className="flex items-center gap-2">
            <button
              onClick={goToPrevMatch}
              disabled={currentMatchIndex === 0}
              className="p-1 hover:bg-bg-elevated disabled:opacity-30"
            >
              <ChevronLeft className="h-4 w-4 text-text-dim" />
            </button>
            <span className="text-xs text-text-normal min-w-[80px] text-center">
              Match {currentMatchIndex + 1} / {matchOffsets.length}
            </span>
            <button
              onClick={goToNextMatch}
              disabled={currentMatchIndex >= matchOffsets.length - 1}
              className="p-1 hover:bg-bg-elevated disabled:opacity-30"
            >
              <ChevronRight className="h-4 w-4 text-text-dim" />
            </button>
          </div>
        )}
      </div>

      {/* Current match info */}
      {currentMatch && (
        <div className="px-4 py-2 bg-amber/10 border-b border-amber/30">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-amber font-mono">
                Offset 0x{currentMatch.offset.toString(16).toUpperCase()}
              </span>
              <span className="text-xs text-text-muted ml-2">
                {currentMatch.identifier} ({currentMatch.length} bytes)
              </span>
            </div>
            <div className="text-xs text-text-dim">
              {currentMatch.threatNames.slice(0, 3).join(', ')}
              {currentMatch.threatNames.length > 3 && ` +${currentMatch.threatNames.length - 3} more`}
            </div>
          </div>
        </div>
      )}

      {/* Hex view */}
      <div className="overflow-x-auto">
        <div className="p-4 font-mono text-xs">
          {/* Header row */}
          <div className="flex text-text-muted mb-2 border-b border-border-dim pb-2">
            <span className="w-20 flex-shrink-0">OFFSET</span>
            <span className="flex-1">
              {Array.from({ length: bytesPerRow }, (_, i) => (
                <span key={i} className="inline-block w-7 text-center">
                  {i.toString(16).toUpperCase()}
                </span>
              ))}
            </span>
            <span className="w-4" />
            <span className="w-40">ASCII</span>
          </div>

          {/* Data rows */}
          {hexRows.map((row) => (
            <div key={row.offset} className="flex hover:bg-bg-elevated/50">
              {/* Offset */}
              <span className="w-20 flex-shrink-0 text-text-muted">
                {row.offsetHex}
              </span>

              {/* Hex bytes */}
              <span className="flex-1">
                {row.bytes.map((b, i) => (
                  <span
                    key={i}
                    className={`inline-block w-7 text-center ${
                      b.isMatch
                        ? 'bg-amber text-bg-deep font-bold'
                        : 'text-text-dim'
                    }`}
                    title={b.matchInfo ? `${b.matchInfo.identifier}: ${b.matchInfo.threatNames.join(', ')}` : undefined}
                  >
                    {b.hex}
                  </span>
                ))}
              </span>

              {/* Separator */}
              <span className="w-4 text-border-dim">│</span>

              {/* ASCII */}
              <span className="w-40">
                {row.ascii.map((a, i) => (
                  <span
                    key={i}
                    className={
                      a.isMatch
                        ? 'bg-amber text-bg-deep font-bold'
                        : 'text-text-dim'
                    }
                  >
                    {a.char}
                  </span>
                ))}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Scroll controls */}
      <div className="px-4 py-2 border-t border-border-dim flex items-center justify-between">
        <button
          onClick={() => setViewOffset(Math.max(0, viewOffset - (rowsToShow * bytesPerRow)))}
          disabled={viewOffset === 0}
          className="text-xs px-2 py-1 bg-bg-elevated text-text-dim hover:text-text-normal disabled:opacity-30"
        >
          ↑ Previous
        </button>

        <span className="text-xs text-text-muted">
          Showing 0x{viewOffset.toString(16).toUpperCase()} - 0x{Math.min(viewOffset + (rowsToShow * bytesPerRow), bytes.length).toString(16).toUpperCase()}
        </span>

        <button
          onClick={() => setViewOffset(Math.min(bytes.length - (rowsToShow * bytesPerRow), viewOffset + (rowsToShow * bytesPerRow)))}
          disabled={viewOffset + (rowsToShow * bytesPerRow) >= bytes.length}
          className="text-xs px-2 py-1 bg-bg-elevated text-text-dim hover:text-text-normal disabled:opacity-30"
        >
          ↓ Next
        </button>
      </div>

      {/* Legend */}
      <div className="px-4 py-2 border-t border-border-dim">
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1">
            <span className="inline-block w-4 h-4 bg-amber" />
            <span className="text-text-muted">YARA Match</span>
          </div>
        </div>
      </div>
    </div>
  )
}
