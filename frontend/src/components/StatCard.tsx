import { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: number | string
  icon: LucideIcon
  index?: number
}

function formatValue(value: number | string): string {
  if (typeof value !== 'number') return value

  if (value >= 1000000) {
    return (value / 1000000).toFixed(1) + 'M'
  }
  if (value >= 1000) {
    return (value / 1000).toFixed(1) + 'K'
  }
  return value.toLocaleString()
}

export default function StatCard({
  title,
  value,
  icon: _Icon,
  index = 1,
}: StatCardProps) {
  const formattedValue = formatValue(value)
  const numericPart = formattedValue.replace(/[^\d.]/g, '')
  const unitPart = formattedValue.replace(/[\d.]/g, '')

  return (
    <div className="bg-bg-surface p-8 text-center transition-colors hover:bg-bg-elevated">
      <div className="text-xs text-text-muted mb-6 tracking-wider">
        {String(index).padStart(2, '0')}
      </div>
      <div className="font-display text-4xl font-bold text-text-bright mb-3">
        {numericPart}
        {unitPart && <span className="text-amber text-2xl ml-0.5">{unitPart}</span>}
      </div>
      <div className="text-xs text-text-muted uppercase tracking-widest">
        {title}
      </div>
    </div>
  )
}
