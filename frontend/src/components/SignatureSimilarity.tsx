import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { GitBranch, Search, ChevronRight, Layers } from 'lucide-react'

interface SimilarSignature {
  id: number
  signatureId: number
  threatName: string
  category: string | null
  family: string | null
  similarity: number // 0-100
  matchType: 'exact' | 'high' | 'medium' | 'low'
  sharedStrings: string[]
  matchingBytes: number
}

interface SignatureSimilarityProps {
  signatures: SimilarSignature[]
  onClusterSelect?: (ids: number[]) => void
}

// Group signatures by similarity into clusters
function clusterSignatures(signatures: SimilarSignature[]): Map<string, SimilarSignature[]> {
  const clusters = new Map<string, SimilarSignature[]>()

  signatures.forEach(sig => {
    // Use family as primary cluster key, or category, or 'Unknown'
    const key = sig.family || sig.category || 'Unknown'
    const existing = clusters.get(key) || []
    existing.push(sig)
    clusters.set(key, existing)
  })

  return clusters
}

function getSimilarityColor(similarity: number): string {
  if (similarity >= 90) return 'text-red-500'
  if (similarity >= 70) return 'text-amber'
  if (similarity >= 50) return 'text-yellow-500'
  return 'text-text-dim'
}

function getSimilarityBg(similarity: number): string {
  if (similarity >= 90) return 'bg-red-500/20'
  if (similarity >= 70) return 'bg-amber/20'
  if (similarity >= 50) return 'bg-yellow-500/20'
  return 'bg-bg-elevated'
}

export default function SignatureSimilarity({ signatures, onClusterSelect }: SignatureSimilarityProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [minSimilarity, setMinSimilarity] = useState(50)
  const [expandedCluster, setExpandedCluster] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'clusters' | 'list'>('clusters')

  const filteredSignatures = useMemo(() => {
    return signatures.filter(sig => {
      if (sig.similarity < minSimilarity) return false
      if (searchQuery) {
        const query = searchQuery.toLowerCase()
        return (
          sig.threatName.toLowerCase().includes(query) ||
          sig.family?.toLowerCase().includes(query) ||
          sig.category?.toLowerCase().includes(query)
        )
      }
      return true
    })
  }, [signatures, searchQuery, minSimilarity])

  const clusters = useMemo(() => {
    return clusterSignatures(filteredSignatures)
  }, [filteredSignatures])

  const sortedClusters = useMemo(() => {
    return Array.from(clusters.entries())
      .sort((a, b) => b[1].length - a[1].length)
  }, [clusters])

  return (
    <div className="bg-bg-surface border border-border-visible rounded-lg">
      {/* Header */}
      <div className="p-4 border-b border-border-dim">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-amber" />
            <h3 className="text-lg font-semibold text-text-bright">Signature Similarity</h3>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setViewMode('clusters')}
              className={`px-3 py-1 text-xs rounded ${
                viewMode === 'clusters'
                  ? 'bg-amber text-bg-deep'
                  : 'bg-bg-elevated text-text-dim hover:text-text-normal'
              }`}
            >
              Clusters
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`px-3 py-1 text-xs rounded ${
                viewMode === 'list'
                  ? 'bg-amber text-bg-deep'
                  : 'bg-bg-elevated text-text-dim hover:text-text-normal'
              }`}
            >
              List
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search similar signatures..."
              className="w-full pl-10 pr-4 py-2 bg-bg-elevated border border-border-dim text-text-normal text-sm placeholder:text-text-muted focus:outline-none focus:border-amber"
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">Min similarity:</span>
            <select
              value={minSimilarity}
              onChange={(e) => setMinSimilarity(Number(e.target.value))}
              className="px-2 py-1.5 bg-bg-elevated border border-border-dim text-text-normal text-sm focus:outline-none focus:border-amber"
            >
              <option value={90}>90%+</option>
              <option value={70}>70%+</option>
              <option value={50}>50%+</option>
              <option value={30}>30%+</option>
              <option value={0}>All</option>
            </select>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="px-4 py-3 border-b border-border-dim bg-bg-elevated/50">
        <div className="flex items-center gap-6 text-xs">
          <span className="text-text-muted">
            {filteredSignatures.length} similar signatures
          </span>
          <span className="text-text-muted">
            {clusters.size} clusters
          </span>
          <span className="text-red-500">
            {filteredSignatures.filter(s => s.similarity >= 90).length} high similarity
          </span>
        </div>
      </div>

      {/* Content */}
      <div className="max-h-[500px] overflow-y-auto">
        {viewMode === 'clusters' ? (
          // Cluster View
          <div className="divide-y divide-border-dim">
            {sortedClusters.map(([clusterName, sigs]) => (
              <div key={clusterName}>
                <button
                  onClick={() => setExpandedCluster(expandedCluster === clusterName ? null : clusterName)}
                  className="w-full flex items-center justify-between p-4 hover:bg-bg-elevated transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <GitBranch className="h-4 w-4 text-amber" />
                    <span className="text-sm font-medium text-text-bright">{clusterName}</span>
                    <span className="px-2 py-0.5 bg-bg-elevated text-text-muted text-xs rounded">
                      {sigs.length} signatures
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs ${getSimilarityColor(Math.max(...sigs.map(s => s.similarity)))}`}>
                      Max: {Math.max(...sigs.map(s => s.similarity))}%
                    </span>
                    <ChevronRight className={`h-4 w-4 text-text-muted transition-transform ${
                      expandedCluster === clusterName ? 'rotate-90' : ''
                    }`} />
                  </div>
                </button>

                {expandedCluster === clusterName && (
                  <div className="bg-bg-deep px-4 pb-4">
                    <div className="space-y-2">
                      {sigs.sort((a, b) => b.similarity - a.similarity).map(sig => (
                        <Link
                          key={sig.id}
                          to={`/threats/${sig.signatureId}`}
                          className={`flex items-center justify-between p-3 ${getSimilarityBg(sig.similarity)} rounded hover:ring-1 hover:ring-amber/50`}
                        >
                          <div className="min-w-0 flex-1">
                            <div className="text-sm text-text-normal truncate">{sig.threatName}</div>
                            <div className="flex items-center gap-2 mt-1">
                              {sig.category && (
                                <span className="text-xs text-text-muted">{sig.category}</span>
                              )}
                              {sig.sharedStrings.length > 0 && (
                                <span className="text-xs text-text-muted">
                                  {sig.sharedStrings.length} shared strings
                                </span>
                              )}
                            </div>
                          </div>
                          <div className={`text-lg font-bold ${getSimilarityColor(sig.similarity)}`}>
                            {sig.similarity}%
                          </div>
                        </Link>
                      ))}
                    </div>
                    {onClusterSelect && (
                      <button
                        onClick={() => onClusterSelect(sigs.map(s => s.signatureId))}
                        className="mt-3 text-xs text-amber hover:text-amber-bright"
                      >
                        Select all in cluster →
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          // List View
          <div className="divide-y divide-border-dim">
            {filteredSignatures
              .sort((a, b) => b.similarity - a.similarity)
              .map(sig => (
                <Link
                  key={sig.id}
                  to={`/threats/${sig.signatureId}`}
                  className="flex items-center justify-between p-4 hover:bg-bg-elevated transition-colors"
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-text-bright truncate">{sig.threatName}</div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-text-muted">
                      {sig.category && <span>{sig.category}</span>}
                      {sig.family && <span>• {sig.family}</span>}
                      <span>• {sig.matchingBytes} matching bytes</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className={`w-24 h-2 bg-bg-elevated rounded-full overflow-hidden`}>
                      <div
                        className={`h-full ${
                          sig.similarity >= 90 ? 'bg-red-500' :
                          sig.similarity >= 70 ? 'bg-amber' :
                          sig.similarity >= 50 ? 'bg-yellow-500' : 'bg-text-muted'
                        }`}
                        style={{ width: `${sig.similarity}%` }}
                      />
                    </div>
                    <span className={`text-sm font-bold w-12 text-right ${getSimilarityColor(sig.similarity)}`}>
                      {sig.similarity}%
                    </span>
                    <ChevronRight className="h-4 w-4 text-text-muted" />
                  </div>
                </Link>
              ))}
          </div>
        )}

        {filteredSignatures.length === 0 && (
          <div className="p-8 text-center text-text-muted">
            <Layers className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No similar signatures found</p>
          </div>
        )}
      </div>
    </div>
  )
}
