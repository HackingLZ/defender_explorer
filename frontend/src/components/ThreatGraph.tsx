import { useEffect, useRef, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'

interface GraphNode {
  id: number
  label: string
  category: string | null
  family: string | null
  signatureCount: number
  x?: number
  y?: number
  vx?: number
  vy?: number
}

interface GraphEdge {
  source: number
  target: number
  weight: number
  types: string[]
}

interface ThreatGraphProps {
  nodes: GraphNode[]
  edges: GraphEdge[]
  centerNodeId?: number
  onNodeClick?: (nodeId: number) => void
}

// Color mapping for categories
const CATEGORY_COLORS: Record<string, string> = {
  'Trojan': '#ef4444',
  'Backdoor': '#dc2626',
  'Worm': '#f97316',
  'Virus': '#ea580c',
  'Ransom': '#7c3aed',
  'HackTool': '#2563eb',
  'PUA': '#6b7280',
  'Spyware': '#0891b2',
  'default': '#f59e0b',
}

export default function ThreatGraph({ nodes, edges, centerNodeId, onNodeClick }: ThreatGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const animationRef = useRef<number>()
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const nodesRef = useRef<GraphNode[]>([])

  // Initialize node positions
  useEffect(() => {
    const width = containerRef.current?.clientWidth || 800
    const height = containerRef.current?.clientHeight || 600
    const centerX = width / 2
    const centerY = height / 2

    nodesRef.current = nodes.map((node) => ({
      ...node,
      x: node.id === centerNodeId
        ? centerX
        : centerX + (Math.random() - 0.5) * width * 0.8,
      y: node.id === centerNodeId
        ? centerY
        : centerY + (Math.random() - 0.5) * height * 0.8,
      vx: 0,
      vy: 0,
    }))
  }, [nodes, centerNodeId])

  // Force simulation
  const simulate = useCallback(() => {
    const width = containerRef.current?.clientWidth || 800
    const height = containerRef.current?.clientHeight || 600
    const currentNodes = nodesRef.current

    // Create node map for quick lookup
    const nodeMap = new Map(currentNodes.map(n => [n.id, n]))

    // Apply forces
    currentNodes.forEach(node => {
      if (!node.x || !node.y) return

      // Repulsion from other nodes
      currentNodes.forEach(other => {
        if (node.id === other.id || !other.x || !other.y) return
        const dx = node.x! - other.x!
        const dy = node.y! - other.y!
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const force = 2000 / (dist * dist)
        node.vx = (node.vx || 0) + (dx / dist) * force
        node.vy = (node.vy || 0) + (dy / dist) * force
      })

      // Center gravity
      const centerX = width / 2
      const centerY = height / 2
      node.vx = (node.vx || 0) + (centerX - node.x) * 0.001
      node.vy = (node.vy || 0) + (centerY - node.y) * 0.001
    })

    // Apply edge forces (attraction)
    edges.forEach(edge => {
      const source = nodeMap.get(edge.source)
      const target = nodeMap.get(edge.target)
      if (!source || !target || !source.x || !source.y || !target.x || !target.y) return

      const dx = target.x - source.x
      const dy = target.y - source.y
      const dist = Math.sqrt(dx * dx + dy * dy) || 1
      const force = (dist - 150) * 0.01 * edge.weight

      source.vx = (source.vx || 0) + (dx / dist) * force
      source.vy = (source.vy || 0) + (dy / dist) * force
      target.vx = (target.vx || 0) - (dx / dist) * force
      target.vy = (target.vy || 0) - (dy / dist) * force
    })

    // Apply velocity with damping
    currentNodes.forEach(node => {
      if (!node.x || !node.y) return
      node.vx = (node.vx || 0) * 0.9
      node.vy = (node.vy || 0) * 0.9
      node.x += node.vx || 0
      node.y += node.vy || 0

      // Keep in bounds
      node.x = Math.max(50, Math.min(width - 50, node.x))
      node.y = Math.max(50, Math.min(height - 50, node.y))
    })
  }, [edges])

  // Render loop
  const render = useCallback(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return

    const width = canvas.width
    const height = canvas.height
    const currentNodes = nodesRef.current

    // Clear
    ctx.fillStyle = 'var(--bg-deep)'
    ctx.fillRect(0, 0, width, height)

    // Apply transformations
    ctx.save()
    ctx.translate(pan.x + width / 2, pan.y + height / 2)
    ctx.scale(zoom, zoom)
    ctx.translate(-width / 2, -height / 2)

    // Create node map for quick lookup
    const nodeMap = new Map(currentNodes.map(n => [n.id, n]))

    // Draw edges
    edges.forEach(edge => {
      const source = nodeMap.get(edge.source)
      const target = nodeMap.get(edge.target)
      if (!source || !target || !source.x || !source.y || !target.x || !target.y) return

      ctx.beginPath()
      ctx.moveTo(source.x, source.y)
      ctx.lineTo(target.x, target.y)
      ctx.strokeStyle = `rgba(245, 158, 11, ${0.1 + edge.weight * 0.3})`
      ctx.lineWidth = 1 + edge.weight
      ctx.stroke()
    })

    // Draw nodes
    currentNodes.forEach(node => {
      if (!node.x || !node.y) return

      const color = CATEGORY_COLORS[node.category || 'default'] || CATEGORY_COLORS.default
      const radius = 8 + Math.sqrt(node.signatureCount) * 2
      const isCenter = node.id === centerNodeId
      const isHovered = hoveredNode?.id === node.id
      const isSelected = selectedNode?.id === node.id

      // Glow effect for center/hovered/selected
      if (isCenter || isHovered || isSelected) {
        ctx.beginPath()
        ctx.arc(node.x, node.y, radius + 8, 0, Math.PI * 2)
        ctx.fillStyle = `${color}33`
        ctx.fill()
      }

      // Node circle
      ctx.beginPath()
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2)
      ctx.fillStyle = color
      ctx.fill()

      if (isCenter) {
        ctx.strokeStyle = '#ffffff'
        ctx.lineWidth = 3
        ctx.stroke()
      }

      // Label
      if (zoom > 0.5 || isHovered || isSelected) {
        ctx.font = `${10 / zoom}px monospace`
        ctx.fillStyle = '#fafafa'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        const label = node.label.length > 20 ? node.label.slice(0, 20) + '...' : node.label
        ctx.fillText(label, node.x, node.y + radius + 4)
      }
    })

    ctx.restore()

    // Run simulation
    simulate()

    animationRef.current = requestAnimationFrame(render)
  }, [edges, centerNodeId, zoom, pan, hoveredNode, selectedNode, simulate])

  // Start/stop animation
  useEffect(() => {
    const canvas = canvasRef.current
    const container = containerRef.current
    if (!canvas || !container) return

    // Set canvas size
    const resizeCanvas = () => {
      canvas.width = container.clientWidth
      canvas.height = container.clientHeight
    }
    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)

    // Start animation
    animationRef.current = requestAnimationFrame(render)

    return () => {
      window.removeEventListener('resize', resizeCanvas)
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [render])

  // Mouse handlers
  const handleMouseMove = (e: React.MouseEvent) => {
    const canvas = canvasRef.current
    if (!canvas) return

    const rect = canvas.getBoundingClientRect()
    const x = (e.clientX - rect.left - pan.x - canvas.width / 2) / zoom + canvas.width / 2
    const y = (e.clientY - rect.top - pan.y - canvas.height / 2) / zoom + canvas.height / 2

    if (isDragging) {
      setPan({
        x: pan.x + e.movementX,
        y: pan.y + e.movementY,
      })
      return
    }

    // Check for node hover
    const node = nodesRef.current.find(n => {
      if (!n.x || !n.y) return false
      const dx = x - n.x
      const dy = y - n.y
      const radius = 8 + Math.sqrt(n.signatureCount) * 2
      return dx * dx + dy * dy < radius * radius
    })
    setHoveredNode(node || null)
  }

  const handleMouseDown = () => {
    if (hoveredNode) {
      setSelectedNode(hoveredNode)
      onNodeClick?.(hoveredNode.id)
    } else {
      setIsDragging(true)
    }
  }

  const handleMouseUp = () => {
    setIsDragging(false)
  }

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault()
    const delta = e.deltaY > 0 ? 0.9 : 1.1
    setZoom(Math.max(0.2, Math.min(3, zoom * delta)))
  }

  const resetView = () => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
    setSelectedNode(null)
  }

  return (
    <div className="relative bg-bg-deep border border-border-visible rounded-lg overflow-hidden">
      {/* Controls */}
      <div className="absolute top-4 right-4 z-10 flex flex-col gap-2">
        <button
          onClick={() => setZoom(z => Math.min(3, z * 1.2))}
          className="p-2 bg-bg-surface border border-border-dim rounded hover:border-amber"
          title="Zoom In"
        >
          <ZoomIn className="h-4 w-4 text-text-dim" />
        </button>
        <button
          onClick={() => setZoom(z => Math.max(0.2, z * 0.8))}
          className="p-2 bg-bg-surface border border-border-dim rounded hover:border-amber"
          title="Zoom Out"
        >
          <ZoomOut className="h-4 w-4 text-text-dim" />
        </button>
        <button
          onClick={resetView}
          className="p-2 bg-bg-surface border border-border-dim rounded hover:border-amber"
          title="Reset View"
        >
          <Maximize2 className="h-4 w-4 text-text-dim" />
        </button>
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-10 bg-bg-surface/90 border border-border-dim rounded p-3">
        <div className="text-xs text-text-muted uppercase tracking-wider mb-2">Categories</div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1">
          {Object.entries(CATEGORY_COLORS).filter(([k]) => k !== 'default').slice(0, 6).map(([name, color]) => (
            <div key={name} className="flex items-center gap-2 text-xs">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-text-dim">{name}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Node Info Panel */}
      {selectedNode && (
        <div className="absolute top-4 left-4 z-10 bg-bg-surface border border-border-visible rounded-lg p-4 w-64">
          <div className="flex items-start justify-between mb-2">
            <h4 className="text-sm font-semibold text-text-bright truncate">{selectedNode.label}</h4>
            <button onClick={() => setSelectedNode(null)} className="text-text-muted hover:text-text-bright">
              ×
            </button>
          </div>
          <div className="space-y-1 text-xs text-text-dim">
            {selectedNode.category && (
              <div>Category: <span className="text-text-normal">{selectedNode.category}</span></div>
            )}
            {selectedNode.family && (
              <div>Family: <span className="text-text-normal">{selectedNode.family}</span></div>
            )}
            <div>Signatures: <span className="text-text-normal">{selectedNode.signatureCount}</span></div>
          </div>
          <Link
            to={`/threats/${selectedNode.id}`}
            className="mt-3 inline-block text-xs text-amber hover:text-amber-bright"
          >
            View Details →
          </Link>
        </div>
      )}

      {/* Canvas */}
      <div ref={containerRef} className="w-full h-[500px]">
        <canvas
          ref={canvasRef}
          className="cursor-grab active:cursor-grabbing"
          onMouseMove={handleMouseMove}
          onMouseDown={handleMouseDown}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onWheel={handleWheel}
          style={{ cursor: hoveredNode ? 'pointer' : isDragging ? 'grabbing' : 'grab' }}
        />
      </div>

      {/* Stats */}
      <div className="absolute bottom-4 right-4 text-xs text-text-muted">
        {nodes.length} nodes • {edges.length} connections • {Math.round(zoom * 100)}% zoom
      </div>
    </div>
  )
}
