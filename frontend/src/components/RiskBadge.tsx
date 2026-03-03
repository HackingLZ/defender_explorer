import { AlertTriangle, AlertCircle, Info, CheckCircle } from 'lucide-react'

interface RiskBadgeProps {
  level: 'critical' | 'high' | 'medium' | 'low'
  showIcon?: boolean
  size?: 'sm' | 'md'
}

const riskConfig = {
  critical: {
    bg: 'bg-red-500/20',
    text: 'text-red-400',
    border: 'border-red-500/50',
    icon: AlertTriangle,
    label: 'Critical',
  },
  high: {
    bg: 'bg-orange-500/20',
    text: 'text-orange-400',
    border: 'border-orange-500/50',
    icon: AlertTriangle,
    label: 'High',
  },
  medium: {
    bg: 'bg-amber-500/20',
    text: 'text-amber-400',
    border: 'border-amber-500/50',
    icon: AlertCircle,
    label: 'Medium',
  },
  low: {
    bg: 'bg-green-500/20',
    text: 'text-green-400',
    border: 'border-green-500/50',
    icon: CheckCircle,
    label: 'Low',
  },
}

export function RiskBadge({ level, showIcon = true, size = 'sm' }: RiskBadgeProps) {
  const config = riskConfig[level]
  const Icon = config.icon

  const sizeClasses = size === 'sm'
    ? 'px-2 py-0.5 text-xs'
    : 'px-3 py-1 text-sm'

  const iconSize = size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'

  return (
    <span
      className={`inline-flex items-center gap-1 font-medium rounded ${config.bg} ${config.text} ${sizeClasses}`}
    >
      {showIcon && <Icon className={iconSize} />}
      {config.label}
    </span>
  )
}

interface ExclusionRiskCardProps {
  path: string
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
  reasons: string[]
  recommendations?: string[]
  compact?: boolean
}

export function ExclusionRiskCard({
  path,
  riskLevel,
  reasons,
  recommendations,
  compact = false,
}: ExclusionRiskCardProps) {
  const config = riskConfig[riskLevel]

  if (compact) {
    return (
      <div className={`flex items-center justify-between p-2 rounded ${config.bg} border ${config.border}`}>
        <code className="text-xs font-mono text-text truncate flex-1">{path}</code>
        <RiskBadge level={riskLevel} size="sm" />
      </div>
    )
  }

  return (
    <div className={`rounded-lg border ${config.border} overflow-hidden`}>
      <div className={`px-3 py-2 ${config.bg} flex items-center justify-between`}>
        <code className="text-sm font-mono text-text truncate">{path}</code>
        <RiskBadge level={riskLevel} size="sm" />
      </div>
      <div className="px-3 py-2 bg-surface space-y-2">
        {reasons.length > 0 && (
          <div>
            <p className="text-xs font-medium text-text-muted mb-1">Risk Factors:</p>
            <ul className="text-xs text-text-secondary space-y-0.5">
              {reasons.map((reason, i) => (
                <li key={i} className="flex items-start gap-1">
                  <span className={`w-1.5 h-1.5 rounded-full ${config.bg} mt-1.5`} />
                  {reason}
                </li>
              ))}
            </ul>
          </div>
        )}
        {recommendations && recommendations.length > 0 && (
          <div>
            <p className="text-xs font-medium text-text-muted mb-1">Recommendations:</p>
            <ul className="text-xs text-accent space-y-0.5">
              {recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-1">
                  <Info className="w-3 h-3 mt-0.5 flex-shrink-0" />
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

export default RiskBadge
