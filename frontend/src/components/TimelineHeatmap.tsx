import { useMemo } from 'react'

interface TimelineHeatmapProps {
  data: { date: string; count: number }[]
  trackedSince: string
  title?: string
  onDateClick?: (date: string) => void
}

// Get color intensity based on count
function getIntensity(count: number, max: number): string {
  if (count === 0) return 'bg-bg-elevated'
  const ratio = count / max
  if (ratio > 0.75) return 'bg-red-500'
  if (ratio > 0.5) return 'bg-amber'
  if (ratio > 0.25) return 'bg-amber/60'
  return 'bg-amber/30'
}

// Zero-fill only the period covered by tracking; earlier history is unknown.
function generateCalendarGrid(data: { date: string; count: number }[], trackedSince: string) {
  const months: { name: string; days: { date: string; count: number; dayOfMonth: number }[] }[] = []
  const counts = new Map(data.map(item => [item.date, item.count]))
  const today = new Date().toISOString().slice(0, 10)
  const start = new Date(`${today}T00:00:00Z`)
  start.setUTCDate(start.getUTCDate() - 364)
  const firstTrackedDate = trackedSince.slice(0, 10)
  let previousMonth = ''
  for (const day = new Date(start); day.toISOString().slice(0, 10) <= today; day.setUTCDate(day.getUTCDate() + 1)) {
    const date = day.toISOString().slice(0, 10)
    if (date < firstTrackedDate) continue
    const month = date.slice(0, 7)
    if (month !== previousMonth) {
      months.push({ name: day.toLocaleDateString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' }), days: [] })
      previousMonth = month
    }
    months[months.length - 1].days.push({ date, count: counts.get(date) ?? 0, dayOfMonth: day.getUTCDate() })
  }

  return months
}

export default function TimelineHeatmap({ data, trackedSince, title = 'Activity Heatmap', onDateClick }: TimelineHeatmapProps) {
  const { months, maxCount, totalCount } = useMemo(() => {
    const months = generateCalendarGrid(data, trackedSince)
    const maxCount = Math.max(...data.map(d => d.count), 1)
    const totalCount = data.reduce((sum, d) => sum + d.count, 0)
    return { months, maxCount, totalCount }
  }, [data, trackedSince])

  return (
    <div className="bg-bg-surface border border-border-visible p-4 rounded-lg">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-text-bright">{title}</h3>
        <div className="flex items-center gap-4 text-xs text-text-muted">
          <span>{totalCount.toLocaleString()} total events</span>
          <div className="flex items-center gap-1">
            <span>Less</span>
            <div className="flex gap-0.5">
              <div className="w-3 h-3 bg-bg-elevated rounded-sm" />
              <div className="w-3 h-3 bg-amber/30 rounded-sm" />
              <div className="w-3 h-3 bg-amber/60 rounded-sm" />
              <div className="w-3 h-3 bg-amber rounded-sm" />
              <div className="w-3 h-3 bg-red-500 rounded-sm" />
            </div>
            <span>More</span>
          </div>
        </div>
      </div>

      {/* Calendar Grid */}
      <div className="overflow-x-auto">
        <div className="flex gap-1 min-w-max">
          {months.map((month, monthIndex) => (
            <div key={monthIndex} className="flex flex-col">
              <span className="text-xs text-text-muted mb-1 h-4">{month.name}</span>
              <div className="grid grid-rows-7 grid-flow-col gap-0.5">
                {month.days.map((day, dayIndex) => (
                  <button
                    key={dayIndex}
                    onClick={() => onDateClick?.(day.date)}
                    disabled={!onDateClick}
                    aria-label={`${day.date}: ${day.count} recorded changes`}
                    className={`w-3 h-3 rounded-sm ${getIntensity(day.count, maxCount)} hover:ring-1 hover:ring-amber transition-all`}
                    title={`${day.date}: ${day.count} events`}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Monthly Summary */}
      <div className="mt-4 pt-4 border-t border-border-dim">
        <h4 className="text-xs text-text-muted uppercase tracking-wider mb-2">Monthly Summary</h4>
        <div className="flex gap-2 flex-wrap">
          {months.map((month, index) => {
            const monthTotal = month.days.reduce((sum, d) => sum + d.count, 0)
            return (
              <div
                key={index}
                className="px-2 py-1 bg-bg-elevated rounded text-xs"
              >
                <span className="text-text-muted">{month.name}:</span>
                <span className="text-text-normal ml-1">{monthTotal}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
