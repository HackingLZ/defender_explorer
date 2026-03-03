import { Link } from 'react-router-dom'
import { GitBranch, ExternalLink, Hash, FileText } from 'lucide-react'
import type { RelatedThreat } from '../api/client'

interface RelatedThreatsProps {
  threats: RelatedThreat[]
  currentThreatId?: number
}

export function RelatedThreats({ threats }: RelatedThreatsProps) {
  if (threats.length === 0) {
    return (
      <div className="bg-surface rounded-lg border border-border p-6 text-center">
        <GitBranch className="w-8 h-8 mx-auto mb-2 text-text-muted opacity-50" />
        <p className="text-sm text-text-muted">No related threats found</p>
        <p className="text-xs text-text-muted mt-1">
          Related threats are detected based on signature similarity
        </p>
      </div>
    )
  }

  const getSimilarityColor = (score: number) => {
    if (score >= 0.8) return 'text-green-400'
    if (score >= 0.5) return 'text-amber-400'
    return 'text-text-secondary'
  }

  const getSimilarityBg = (score: number) => {
    if (score >= 0.8) return 'bg-green-500/20'
    if (score >= 0.5) return 'bg-amber-500/20'
    return 'bg-surface-elevated'
  }

  return (
    <div className="bg-surface rounded-lg border border-border overflow-hidden">
      {/* Header */}
      <div className="bg-surface-elevated px-4 py-3 border-b border-border">
        <div className="flex items-center justify-between">
          <h3 className="font-medium text-text flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-accent" />
            Related Threats ({threats.length})
          </h3>
        </div>
      </div>

      {/* List */}
      <div className="divide-y divide-border">
        {threats.map((threat) => (
          <Link
            key={threat.threat_id}
            to={`/threats/${threat.signature_id}`}
            className="block px-4 py-3 hover:bg-surface-elevated transition-colors"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-text truncate">
                    {threat.threat_name}
                  </span>
                  <ExternalLink className="w-3 h-3 text-text-muted flex-shrink-0" />
                </div>
                <div className="flex items-center gap-3 mt-1 text-xs text-text-muted">
                  {threat.category && (
                    <span className="px-1.5 py-0.5 bg-surface-elevated rounded">
                      {threat.category}
                    </span>
                  )}
                  {threat.family && (
                    <span>{threat.family}</span>
                  )}
                </div>

                {/* Similarity details */}
                <div className="flex items-center gap-3 mt-2">
                  {threat.similarity_types.map((type, i) => (
                    <span
                      key={i}
                      className="text-[10px] px-1.5 py-0.5 bg-accent/20 text-accent rounded"
                    >
                      {type.replace(/_/g, ' ')}
                    </span>
                  ))}
                  {threat.matching_bytes > 0 && (
                    <span className="text-[10px] text-text-muted flex items-center gap-1">
                      <Hash className="w-3 h-3" />
                      {threat.matching_bytes} bytes
                    </span>
                  )}
                </div>

                {/* Shared strings preview */}
                {threat.shared_strings.length > 0 && (
                  <div className="mt-2">
                    <div className="flex items-center gap-1 text-[10px] text-text-muted mb-1">
                      <FileText className="w-3 h-3" />
                      Shared strings:
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {threat.shared_strings.slice(0, 3).map((str, i) => (
                        <code
                          key={i}
                          className="text-[10px] px-1.5 py-0.5 bg-green-500/10 text-green-400 rounded truncate max-w-[150px]"
                        >
                          {str}
                        </code>
                      ))}
                      {threat.shared_strings.length > 3 && (
                        <span className="text-[10px] text-text-muted">
                          +{threat.shared_strings.length - 3} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Similarity score */}
              <div className={`text-right ${getSimilarityBg(threat.similarity_score)} px-2 py-1 rounded`}>
                <div className={`text-lg font-bold ${getSimilarityColor(threat.similarity_score)}`}>
                  {Math.round(threat.similarity_score * 100)}%
                </div>
                <div className="text-[10px] text-text-muted">similarity</div>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  )
}

export default RelatedThreats
