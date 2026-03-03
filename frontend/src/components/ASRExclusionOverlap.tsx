import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Layers, ChevronDown, ChevronRight, Shield, FolderOpen, Cpu, FileText, AlertTriangle } from 'lucide-react'
import { ASRRule } from '../api/client'

interface ASRExclusionOverlapProps {
  rules: ASRRule[]
}

interface OverlapItem {
  value: string
  type: 'path' | 'process' | 'extension' | 'registry'
  rules: { guid: string; name: string }[]
}

interface OverlapGroup {
  type: 'path' | 'process' | 'extension' | 'registry'
  label: string
  icon: typeof FolderOpen
  items: OverlapItem[]
  totalOverlaps: number
}

function findOverlaps(rules: ASRRule[]): OverlapGroup[] {
  // Maps to track which rules contain each exclusion
  const pathMap = new Map<string, { guid: string; name: string }[]>()
  const processMap = new Map<string, { guid: string; name: string }[]>()
  const extensionMap = new Map<string, { guid: string; name: string }[]>()
  const registryMap = new Map<string, { guid: string; name: string }[]>()

  // Normalize paths for comparison (lowercase, forward slashes)
  const normalizePath = (path: string): string => {
    return path.toLowerCase().replace(/\\/g, '/').trim()
  }

  // Process each rule
  rules.forEach(rule => {
    const data = rule.extracted_data
    if (!data) return

    const ruleName = rule.short_name || rule.name || rule.guid
    const ruleRef = { guid: rule.guid, name: ruleName }

    // Exclusion paths
    data.exclusion_paths?.forEach(path => {
      const normalized = normalizePath(path)
      const existing = pathMap.get(normalized) || []
      existing.push(ruleRef)
      pathMap.set(normalized, existing)
    })

    // Process names
    data.process_names?.forEach(process => {
      const normalized = process.toLowerCase().trim()
      const existing = processMap.get(normalized) || []
      existing.push(ruleRef)
      processMap.set(normalized, existing)
    })

    // File extensions
    data.file_extensions?.forEach(ext => {
      const normalized = ext.toLowerCase().replace(/^\./, '').trim()
      const existing = extensionMap.get(normalized) || []
      existing.push(ruleRef)
      extensionMap.set(normalized, existing)
    })

    // Registry keys
    data.registry_keys?.forEach(key => {
      const normalized = key.toLowerCase().trim()
      const existing = registryMap.get(normalized) || []
      existing.push(ruleRef)
      registryMap.set(normalized, existing)
    })
  })

  // Convert maps to overlap items (only keep items shared by 2+ rules)
  const createOverlapItems = (
    map: Map<string, { guid: string; name: string }[]>,
    type: OverlapItem['type']
  ): OverlapItem[] => {
    const items: OverlapItem[] = []
    map.forEach((rules, value) => {
      if (rules.length >= 2) {
        // Deduplicate rules (same rule might add same path multiple times)
        const uniqueRules = Array.from(
          new Map(rules.map(r => [r.guid, r])).values()
        )
        if (uniqueRules.length >= 2) {
          items.push({ value, type, rules: uniqueRules })
        }
      }
    })
    // Sort by number of rules sharing (most shared first)
    return items.sort((a, b) => b.rules.length - a.rules.length)
  }

  const pathOverlaps = createOverlapItems(pathMap, 'path')
  const processOverlaps = createOverlapItems(processMap, 'process')
  const extensionOverlaps = createOverlapItems(extensionMap, 'extension')
  const registryOverlaps = createOverlapItems(registryMap, 'registry')

  const groups: OverlapGroup[] = [
    {
      type: 'path',
      label: 'Exclusion Paths',
      icon: FolderOpen,
      items: pathOverlaps,
      totalOverlaps: pathOverlaps.length,
    },
    {
      type: 'process',
      label: 'Process Names',
      icon: Cpu,
      items: processOverlaps,
      totalOverlaps: processOverlaps.length,
    },
    {
      type: 'extension',
      label: 'File Extensions',
      icon: FileText,
      items: extensionOverlaps,
      totalOverlaps: extensionOverlaps.length,
    },
    {
      type: 'registry',
      label: 'Registry Keys',
      icon: FileText,
      items: registryOverlaps,
      totalOverlaps: registryOverlaps.length,
    },
  ]

  return groups.filter(group => group.items.length > 0)
}

export default function ASRExclusionOverlap({ rules }: ASRExclusionOverlapProps) {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['path']))
  const [showAll, setShowAll] = useState(false)

  const overlapGroups = useMemo(() => findOverlaps(rules), [rules])

  const totalOverlaps = useMemo(() =>
    overlapGroups.reduce((sum, group) => sum + group.items.length, 0),
    [overlapGroups]
  )

  const toggleGroup = (type: string) => {
    const newExpanded = new Set(expandedGroups)
    if (newExpanded.has(type)) {
      newExpanded.delete(type)
    } else {
      newExpanded.add(type)
    }
    setExpandedGroups(newExpanded)
  }

  if (totalOverlaps === 0) {
    return (
      <div className="bg-bg-surface border border-border-visible rounded-lg p-6">
        <div className="flex items-center gap-2 mb-4">
          <Layers className="h-5 w-5 text-amber" />
          <h3 className="text-lg font-semibold text-text-bright">Exclusion Overlap Analysis</h3>
        </div>
        <div className="text-center py-8 text-text-muted">
          <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No overlapping exclusions found across ASR rules</p>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-bg-surface border border-border-visible rounded-lg overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-border-dim">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-amber" />
            <h3 className="text-lg font-semibold text-text-bright">Exclusion Overlap Analysis</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">
              {totalOverlaps} overlapping items found
            </span>
            <button
              onClick={() => setShowAll(!showAll)}
              className="text-xs text-amber hover:text-amber-bright"
            >
              {showAll ? 'Show less' : 'Show all'}
            </button>
          </div>
        </div>
        <p className="text-sm text-text-dim">
          Exclusion paths, processes, and other items shared between multiple ASR rules.
          Overlapping exclusions may indicate redundancy or potential security gaps.
        </p>
      </div>

      {/* Summary Stats */}
      <div className="px-4 py-3 bg-bg-elevated/50 border-b border-border-dim flex items-center gap-6 text-xs">
        {overlapGroups.map(group => (
          <span key={group.type} className="flex items-center gap-1">
            <group.icon className="h-3.5 w-3.5 text-text-muted" />
            <span className="text-text-muted">{group.label}:</span>
            <span className="text-amber font-medium">{group.items.length}</span>
          </span>
        ))}
      </div>

      {/* Overlap Groups */}
      <div className="divide-y divide-border-dim">
        {overlapGroups.map(group => (
          <div key={group.type}>
            {/* Group Header */}
            <button
              onClick={() => toggleGroup(group.type)}
              className="w-full flex items-center justify-between p-4 hover:bg-bg-elevated transition-colors"
            >
              <div className="flex items-center gap-3">
                <group.icon className="h-4 w-4 text-amber" />
                <span className="text-sm font-medium text-text-bright">{group.label}</span>
                <span className="px-2 py-0.5 bg-amber/20 text-amber text-xs rounded">
                  {group.items.length} overlaps
                </span>
              </div>
              {expandedGroups.has(group.type) ? (
                <ChevronDown className="h-4 w-4 text-text-muted" />
              ) : (
                <ChevronRight className="h-4 w-4 text-text-muted" />
              )}
            </button>

            {/* Group Items */}
            {expandedGroups.has(group.type) && (
              <div className="bg-bg-deep px-4 pb-4">
                <div className="space-y-3">
                  {(showAll ? group.items : group.items.slice(0, 10)).map((item, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-bg-surface border border-border-dim rounded"
                    >
                      {/* Overlap Value */}
                      <div className="flex items-start gap-2 mb-2">
                        <AlertTriangle className={`h-4 w-4 flex-shrink-0 mt-0.5 ${
                          item.rules.length >= 4 ? 'text-red-500' :
                          item.rules.length >= 3 ? 'text-amber' :
                          'text-yellow-500'
                        }`} />
                        <code className="text-sm text-text-normal break-all font-mono">
                          {item.value}
                        </code>
                      </div>

                      {/* Rules sharing this exclusion */}
                      <div className="ml-6">
                        <div className="text-xs text-text-muted mb-2">
                          Shared by {item.rules.length} rules:
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {item.rules.map(rule => (
                            <Link
                              key={rule.guid}
                              to={`/asr/${rule.guid}`}
                              className="inline-flex items-center gap-1 px-2 py-1 bg-bg-elevated text-xs text-text-dim hover:text-amber rounded transition-colors"
                            >
                              <Shield className="h-3 w-3" />
                              <span className="truncate max-w-[200px]">{rule.name}</span>
                            </Link>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}

                  {!showAll && group.items.length > 10 && (
                    <button
                      onClick={() => setShowAll(true)}
                      className="w-full text-center py-2 text-xs text-amber hover:text-amber-bright"
                    >
                      Show {group.items.length - 10} more {group.label.toLowerCase()}...
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Insights */}
      {totalOverlaps > 0 && (
        <div className="p-4 bg-amber/5 border-t border-amber/20">
          <div className="flex items-start gap-2">
            <AlertTriangle className="h-4 w-4 text-amber flex-shrink-0 mt-0.5" />
            <div className="text-sm text-text-dim">
              <strong className="text-text-normal">Insight:</strong> Rules with overlapping exclusions may benefit from consolidation.
              Shared exclusion paths could indicate opportunities to create more targeted rules or
              identify potentially risky paths that are excluded across multiple rules.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
