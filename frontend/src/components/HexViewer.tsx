import { useState, useMemo } from 'react'
import { Search, ChevronDown, ChevronRight, Zap, FileText, AlertTriangle } from 'lucide-react'
import type { SignatureAnalysis } from '../api/client'

interface HexViewerProps {
  analysis: SignatureAnalysis
  maxRows?: number
}

const BYTES_PER_ROW = 16

export function HexViewer({ analysis, maxRows = 32 }: HexViewerProps) {
  const [selectedOffset, setSelectedOffset] = useState<number | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedRegions, setExpandedRegions] = useState<Set<number>>(new Set())

  // Generate hex dump from analysis
  const hexDump = useMemo(() => {
    if (analysis.hex_dump) {
      return analysis.hex_dump.slice(0, maxRows)
    }
    // Parse from hex_preview if hex_dump not available
    const hexBytes = analysis.hex_preview.replace(' ...', '').split(' ')
    const rows = []
    for (let i = 0; i < hexBytes.length && rows.length < maxRows; i += BYTES_PER_ROW) {
      const rowBytes = hexBytes.slice(i, i + BYTES_PER_ROW)
      rows.push({
        offset: i,
        offset_hex: i.toString(16).toUpperCase().padStart(8, '0'),
        bytes: rowBytes.map(hex => ({
          byte: parseInt(hex, 16),
          hex,
        })),
        ascii: rowBytes.map(hex => {
          const b = parseInt(hex, 16)
          return b >= 32 && b < 127 ? String.fromCharCode(b) : '.'
        }).join(''),
      })
    }
    return rows
  }, [analysis, maxRows])

  // Find region for a given offset
  const getRegionForOffset = (offset: number) => {
    return analysis.regions.find(
      r => offset >= r.offset && offset < r.offset + r.length
    )
  }

  // Search functionality
  const searchResults = useMemo(() => {
    if (!searchQuery) return []
    const query = searchQuery.toLowerCase()
    const results: number[] = []

    // Search in hex values
    hexDump.forEach(row => {
      row.bytes.forEach((b, i) => {
        if (b.hex.toLowerCase().includes(query)) {
          results.push(row.offset + i)
        }
      })
    })

    // Search in strings
    analysis.strings.forEach(s => {
      if (s.string.toLowerCase().includes(query)) {
        for (let i = 0; i < s.length; i++) {
          results.push(s.offset + i)
        }
      }
    })

    return results
  }, [searchQuery, hexDump, analysis.strings])

  const isHighlighted = (offset: number) => searchResults.includes(offset)

  const toggleRegion = (index: number) => {
    const newExpanded = new Set(expandedRegions)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedRegions(newExpanded)
  }

  return (
    <div className="bg-surface rounded-lg border border-border overflow-hidden">
      {/* Header */}
      <div className="bg-surface-elevated px-4 py-3 border-b border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h3 className="font-medium text-text">Hex Viewer</h3>
            <span className="text-xs text-text-secondary">
              {analysis.size} bytes | Entropy: {analysis.entropy.toFixed(2)}
            </span>
          </div>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input
              type="text"
              placeholder="Search hex/string..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-3 py-1.5 text-sm bg-background border border-border rounded-md text-text placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>
        </div>
      </div>

      <div className="flex">
        {/* Hex dump area */}
        <div className="flex-1 overflow-auto">
          <div className="font-mono text-xs">
            {/* Column headers */}
            <div className="flex items-center bg-surface-elevated px-4 py-2 border-b border-border text-text-muted sticky top-0">
              <span className="w-20">Offset</span>
              <span className="flex-1">
                {Array.from({ length: BYTES_PER_ROW }, (_, i) => (
                  <span key={i} className="inline-block w-6 text-center">
                    {i.toString(16).toUpperCase()}
                  </span>
                ))}
              </span>
              <span className="w-36 ml-4">ASCII</span>
            </div>

            {/* Hex rows */}
            <div className="divide-y divide-border/50">
              {hexDump.map((row) => (
                <div
                  key={row.offset}
                  className="flex items-center px-4 py-1 hover:bg-surface-elevated transition-colors"
                >
                  <span className="w-20 text-text-muted">{row.offset_hex}</span>
                  <span className="flex-1">
                    {row.bytes.map((b, i) => {
                      const offset = row.offset + i
                      const region = getRegionForOffset(offset)
                      const highlighted = isHighlighted(offset)
                      const selected = selectedOffset === offset

                      return (
                        <span
                          key={i}
                          onClick={() => setSelectedOffset(offset)}
                          className={`
                            inline-block w-6 text-center cursor-pointer rounded
                            ${region ? `text-white` : 'text-text'}
                            ${highlighted ? 'ring-2 ring-yellow-500' : ''}
                            ${selected ? 'ring-2 ring-accent' : ''}
                            hover:bg-white/10
                          `}
                          style={region ? { backgroundColor: region.color } : undefined}
                          title={region ? `${region.type}: ${region.description}` : undefined}
                        >
                          {b.hex}
                        </span>
                      )
                    })}
                  </span>
                  <span className="w-36 ml-4 text-text-secondary">
                    {row.bytes.map((b, i) => {
                      const offset = row.offset + i
                      const region = getRegionForOffset(offset)
                      const char = b.byte !== null && b.byte >= 32 && b.byte < 127
                        ? String.fromCharCode(b.byte)
                        : '.'

                      return (
                        <span
                          key={i}
                          className={region ? 'font-bold' : ''}
                          style={region ? { color: region.color } : undefined}
                        >
                          {char}
                        </span>
                      )
                    })}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Sidebar - Regions & Info */}
        <div className="w-72 border-l border-border bg-surface-elevated overflow-auto">
          {/* Legend */}
          <div className="p-3 border-b border-border">
            <h4 className="text-xs font-medium text-text-muted uppercase mb-2">Legend</h4>
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded" style={{ backgroundColor: '#3b82f6' }} />
                <span className="text-text-secondary">Magic Bytes</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded" style={{ backgroundColor: '#22c55e' }} />
                <span className="text-text-secondary">Strings</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded" style={{ backgroundColor: '#f59e0b' }} />
                <span className="text-text-secondary">Patterns</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded" style={{ backgroundColor: '#6b7280' }} />
                <span className="text-text-secondary">Null Padding</span>
              </div>
            </div>
          </div>

          {/* Magic bytes */}
          {analysis.magic_bytes.length > 0 && (
            <div className="p-3 border-b border-border">
              <h4 className="text-xs font-medium text-text-muted uppercase mb-2 flex items-center gap-1">
                <Zap className="w-3 h-3" />
                Magic Bytes
              </h4>
              <div className="space-y-2">
                {analysis.magic_bytes.map((magic, i) => (
                  <div key={i} className="text-xs">
                    <div className="font-medium text-blue-400">{magic.meaning}</div>
                    <div className="text-text-muted">
                      @ 0x{magic.offset.toString(16).toUpperCase()} ({magic.signature_text})
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detected patterns */}
          {analysis.patterns.length > 0 && (
            <div className="p-3 border-b border-border">
              <h4 className="text-xs font-medium text-text-muted uppercase mb-2 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                Detected Patterns ({analysis.patterns.length})
              </h4>
              <div className="space-y-2 max-h-40 overflow-auto">
                {analysis.patterns.slice(0, 10).map((pattern, i) => (
                  <div key={i} className="text-xs">
                    <div className="font-medium text-amber-400">{pattern.description}</div>
                    <div className="text-text-muted font-mono">
                      "{pattern.pattern}" @ 0x{pattern.offset.toString(16).toUpperCase()}
                    </div>
                  </div>
                ))}
                {analysis.patterns.length > 10 && (
                  <div className="text-xs text-text-muted">
                    +{analysis.patterns.length - 10} more patterns
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Extracted strings */}
          {analysis.strings.length > 0 && (
            <div className="p-3">
              <h4 className="text-xs font-medium text-text-muted uppercase mb-2 flex items-center gap-1">
                <FileText className="w-3 h-3" />
                Strings ({analysis.strings.length})
              </h4>
              <div className="space-y-1 max-h-60 overflow-auto">
                {analysis.strings.slice(0, 20).map((str, i) => (
                  <div
                    key={i}
                    className="text-xs cursor-pointer hover:bg-white/5 rounded p-1"
                    onClick={() => toggleRegion(i)}
                  >
                    <div className="flex items-center gap-1">
                      {expandedRegions.has(i) ? (
                        <ChevronDown className="w-3 h-3 text-text-muted" />
                      ) : (
                        <ChevronRight className="w-3 h-3 text-text-muted" />
                      )}
                      <span className="text-green-400 font-mono truncate flex-1">
                        {str.string.length > 30 ? str.string.slice(0, 30) + '...' : str.string}
                      </span>
                    </div>
                    {expandedRegions.has(i) && (
                      <div className="mt-1 ml-4 text-text-muted">
                        <div>Offset: 0x{str.offset.toString(16).toUpperCase()}</div>
                        <div>Type: {str.classification}</div>
                        {str.context_before && (
                          <div className="font-mono text-[10px] mt-1">
                            Before: {str.context_before.slice(0, 24)}...
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
                {analysis.strings.length > 20 && (
                  <div className="text-xs text-text-muted p-1">
                    +{analysis.strings.length - 20} more strings
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default HexViewer
