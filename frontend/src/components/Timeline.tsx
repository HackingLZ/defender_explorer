import { useState } from 'react'
import { Clock, ChevronDown, ChevronRight, AlertCircle } from 'lucide-react'
import type { TimelineResponse } from '../api/client'

interface TimelineProps {
  timeline: TimelineResponse
  entityName?: string
}

const eventTypeColors: Record<string, { bg: string; text: string; icon: string }> = {
  created: { bg: 'bg-green-500/20', text: 'text-green-400', icon: '🆕' },
  updated: { bg: 'bg-blue-500/20', text: 'text-blue-400', icon: '📝' },
  deleted: { bg: 'bg-red-500/20', text: 'text-red-400', icon: '🗑️' },
}

export function Timeline({ timeline, entityName }: TimelineProps) {
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set())
  const [filter, setFilter] = useState<string>('all')

  const toggleEvent = (index: number) => {
    const newExpanded = new Set(expandedEvents)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedEvents(newExpanded)
  }

  const filteredEvents = filter === 'all'
    ? timeline.events
    : timeline.events.filter(e => e.type === filter)

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Unknown date'
    const date = new Date(dateStr)
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div className="bg-surface rounded-lg border border-border overflow-hidden">
      {/* Header */}
      <div className="bg-surface-elevated px-4 py-3 border-b border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-accent" />
            <h3 className="font-medium text-text">Timeline</h3>
            {entityName && (
              <span className="text-xs text-text-secondary">for {entityName}</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="text-xs bg-background border border-border rounded px-2 py-1 text-text focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="all">All Events</option>
              <option value="created">Created</option>
              <option value="updated">Updated</option>
              <option value="deleted">Deleted</option>
            </select>
          </div>
        </div>
      </div>

      {/* Message if tracking just started */}
      {timeline.message && (
        <div className="px-4 py-3 bg-amber-500/10 border-b border-border flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-amber-400" />
          <span className="text-xs text-amber-400">{timeline.message}</span>
        </div>
      )}

      {/* Timeline content */}
      <div className="p-4">
        {filteredEvents.length === 0 ? (
          <div className="text-center py-8 text-text-muted">
            <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No events found</p>
          </div>
        ) : (
          <div className="relative">
            {/* Vertical line */}
            <div className="absolute left-4 top-0 bottom-0 w-px bg-border" />

            {/* Events */}
            <div className="space-y-4">
              {filteredEvents.map((event, index) => {
                const colors = eventTypeColors[event.type] || eventTypeColors.updated
                const isExpanded = expandedEvents.has(index)

                return (
                  <div key={index} className="relative pl-10">
                    {/* Dot on timeline */}
                    <div
                      className={`absolute left-2 w-5 h-5 rounded-full border-2 border-background ${colors.bg} flex items-center justify-center`}
                    >
                      <span className="text-xs">{colors.icon}</span>
                    </div>

                    {/* Event card */}
                    <div
                      className={`bg-surface-elevated rounded-lg border border-border overflow-hidden cursor-pointer hover:border-accent/50 transition-colors`}
                      onClick={() => toggleEvent(index)}
                    >
                      <div className="px-3 py-2 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className={`text-xs font-medium ${colors.text} uppercase`}>
                            {event.type}
                          </span>
                          <span className="text-xs text-text-muted">
                            {formatDate(event.date)}
                          </span>
                          {event.vdm_version && (
                            <span className="text-xs bg-accent/20 text-accent px-1.5 py-0.5 rounded">
                              VDM {event.vdm_version}
                            </span>
                          )}
                        </div>
                        {event.details && (
                          isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-text-muted" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-text-muted" />
                          )
                        )}
                      </div>

                      {/* Changes summary */}
                      {event.changes.length > 0 && (
                        <div className="px-3 pb-2">
                          <ul className="text-xs text-text-secondary space-y-0.5">
                            {event.changes.slice(0, isExpanded ? undefined : 3).map((change, i) => (
                              <li key={i} className="flex items-center gap-1">
                                <span className="w-1 h-1 rounded-full bg-text-muted" />
                                {change}
                              </li>
                            ))}
                            {!isExpanded && event.changes.length > 3 && (
                              <li className="text-text-muted">
                                +{event.changes.length - 3} more changes
                              </li>
                            )}
                          </ul>
                        </div>
                      )}

                      {/* Expanded details */}
                      {isExpanded && event.details && (
                        <div className="px-3 pb-3 border-t border-border mt-2 pt-2">
                          <div className="grid grid-cols-2 gap-4">
                            {event.details.previous_data && Object.keys(event.details.previous_data).length > 0 && (
                              <div>
                                <h5 className="text-xs font-medium text-text-muted mb-1">Previous</h5>
                                <pre className="text-[10px] bg-background p-2 rounded overflow-auto max-h-32 text-text-secondary">
                                  {JSON.stringify(event.details.previous_data, null, 2)}
                                </pre>
                              </div>
                            )}
                            {event.details.current_data && Object.keys(event.details.current_data).length > 0 && (
                              <div>
                                <h5 className="text-xs font-medium text-text-muted mb-1">Current</h5>
                                <pre className="text-[10px] bg-background p-2 rounded overflow-auto max-h-32 text-text-secondary">
                                  {JSON.stringify(event.details.current_data, null, 2)}
                                </pre>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-border bg-surface-elevated">
        <span className="text-xs text-text-muted">
          {timeline.total_events} total event{timeline.total_events !== 1 ? 's' : ''}
        </span>
      </div>
    </div>
  )
}

export default Timeline
