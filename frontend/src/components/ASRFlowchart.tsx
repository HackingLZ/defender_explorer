import { useState, useMemo } from 'react'
import { ChevronDown, ChevronRight, Circle, Diamond, Square, CheckCircle, XCircle } from 'lucide-react'
import type { ASRFlowchart as FlowchartData } from '../api/client'

interface ASRFlowchartProps {
  flowchart: FlowchartData
}

// Simple flowchart renderer without ReactFlow dependency
// Can be enhanced later when ReactFlow is installed

export function ASRFlowchart({ flowchart }: ASRFlowchartProps) {
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set())

  const toggleNode = (nodeId: string) => {
    const newExpanded = new Set(expandedNodes)
    if (newExpanded.has(nodeId)) {
      newExpanded.delete(nodeId)
    } else {
      newExpanded.add(nodeId)
    }
    setExpandedNodes(newExpanded)
  }

  // Build a tree structure from nodes and edges
  const nodeMap = useMemo(() => {
    const map = new Map<string, typeof flowchart.nodes[0]>()
    flowchart.nodes.forEach(node => map.set(node.id, node))
    return map
  }, [flowchart.nodes])

  const childrenMap = useMemo(() => {
    const map = new Map<string, { edge: typeof flowchart.edges[0]; child: string }[]>()
    flowchart.edges.forEach(edge => {
      const children = map.get(edge.source) || []
      children.push({ edge, child: edge.target })
      map.set(edge.source, children)
    })
    return map
  }, [flowchart.edges])

  // Find root nodes (nodes with no incoming edges)
  const rootNodes = useMemo(() => {
    const hasIncoming = new Set(flowchart.edges.map(e => e.target))
    return flowchart.nodes.filter(n => !hasIncoming.has(n.id))
  }, [flowchart])

  const getNodeIcon = (type: string, label: string) => {
    if (label.includes('BLOCK') || label.includes('🚫')) {
      return <XCircle className="w-5 h-5 text-red-400" />
    }
    if (label.includes('ALLOW') || label.includes('✅')) {
      return <CheckCircle className="w-5 h-5 text-green-400" />
    }
    if (type === 'input') {
      return <Circle className="w-5 h-5 text-green-400" />
    }
    if (type === 'output') {
      return <Circle className="w-5 h-5 text-text-muted" />
    }
    if (label.includes('?')) {
      return <Diamond className="w-5 h-5 text-blue-400" />
    }
    return <Square className="w-5 h-5 text-purple-400" />
  }

  const renderNode = (node: typeof flowchart.nodes[0], depth: number = 0, _isLast: boolean = true) => {
    const children = childrenMap.get(node.id) || []
    const isExpanded = expandedNodes.has(node.id)
    const hasDetails = node.data.expandable && node.data.details

    // Parse style colors
    const bgColor = node.style?.background as string || '#6366f1'

    return (
      <div key={node.id} className="relative">
        {/* Connector line from parent */}
        {depth > 0 && (
          <div className="absolute left-[-24px] top-4 w-6 border-t border-border" />
        )}

        {/* Node */}
        <div
          className={`
            relative rounded-lg border border-border overflow-hidden
            ${hasDetails ? 'cursor-pointer hover:border-accent/50' : ''}
          `}
          onClick={() => hasDetails && toggleNode(node.id)}
        >
          <div
            className="px-3 py-2 flex items-center gap-2"
            style={{ backgroundColor: bgColor + '20', borderLeftColor: bgColor, borderLeftWidth: 3 }}
          >
            {getNodeIcon(node.type, node.data.label)}
            <div className="flex-1">
              <div className="text-sm font-medium text-text">{node.data.label}</div>
              {node.data.description && (
                <div className="text-xs text-text-muted">{node.data.description}</div>
              )}
            </div>
            {hasDetails && (
              isExpanded ? <ChevronDown className="w-4 h-4 text-text-muted" /> : <ChevronRight className="w-4 h-4 text-text-muted" />
            )}
          </div>

          {/* Expanded details */}
          {hasDetails && isExpanded && node.data.details && (
            <div className="px-3 py-2 bg-surface-elevated border-t border-border">
              {Object.entries(node.data.details as Record<string, string[]>).map(([key, values]) => (
                values && values.length > 0 && (
                  <div key={key} className="mb-2 last:mb-0">
                    <div className="text-xs font-medium text-text-muted uppercase mb-1">
                      {key.replace(/_/g, ' ')}
                    </div>
                    <div className="space-y-0.5 max-h-24 overflow-auto">
                      {values.slice(0, 5).map((v, i) => (
                        <div key={i} className="text-xs font-mono text-text-secondary truncate">
                          {v}
                        </div>
                      ))}
                      {values.length > 5 && (
                        <div className="text-xs text-text-muted">
                          +{values.length - 5} more
                        </div>
                      )}
                    </div>
                  </div>
                )
              ))}
            </div>
          )}
        </div>

        {/* Children */}
        {children.length > 0 && (
          <div className="ml-8 mt-3 space-y-3 relative">
            {/* Vertical connector */}
            <div
              className="absolute left-[-24px] top-0 border-l border-border"
              style={{ height: 'calc(100% - 16px)' }}
            />

            {children.map((child, i) => {
              const childNode = nodeMap.get(child.child)
              if (!childNode) return null

              return (
                <div key={child.child} className="relative">
                  {/* Edge label */}
                  {child.edge.label && (
                    <div className="absolute left-[-60px] top-3 text-[10px] text-text-muted bg-surface px-1 rounded">
                      {child.edge.label}
                    </div>
                  )}
                  {renderNode(childNode, depth + 1, i === children.length - 1)}
                </div>
              )
            })}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="bg-surface rounded-lg border border-border overflow-hidden">
      {/* Header */}
      <div className="bg-surface-elevated px-4 py-3 border-b border-border">
        <h3 className="font-medium text-text">Rule Logic Flowchart</h3>
        <p className="text-xs text-text-muted mt-0.5">
          {flowchart.rule_name || flowchart.rule_guid}
        </p>
      </div>

      {/* Flowchart */}
      <div className="p-6 overflow-auto">
        <div className="space-y-4">
          {rootNodes.map(node => renderNode(node))}
        </div>
      </div>

      {/* Legend */}
      <div className="px-4 py-3 bg-surface-elevated border-t border-border">
        <div className="flex items-center gap-6 text-xs text-text-muted">
          <div className="flex items-center gap-1">
            <Circle className="w-3 h-3 text-green-400" />
            Start/End
          </div>
          <div className="flex items-center gap-1">
            <Diamond className="w-3 h-3 text-blue-400" />
            Decision
          </div>
          <div className="flex items-center gap-1">
            <Square className="w-3 h-3 text-purple-400" />
            Process
          </div>
          <div className="flex items-center gap-1">
            <CheckCircle className="w-3 h-3 text-green-400" />
            Allow
          </div>
          <div className="flex items-center gap-1">
            <XCircle className="w-3 h-3 text-red-400" />
            Block
          </div>
        </div>
      </div>
    </div>
  )
}

export default ASRFlowchart
