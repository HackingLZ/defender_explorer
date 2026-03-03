import { useState, useMemo } from 'react'
import { Code, AlertTriangle, Info, Search, ChevronDown, ChevronRight, Shield, Terminal, FileCode } from 'lucide-react'

interface LuaAnalysis {
  functions: LuaFunction[]
  variables: LuaVariable[]
  strings: LuaString[]
  patterns: LuaPattern[]
  riskScore: number
  summary: string
}

interface LuaFunction {
  name: string
  line: number
  params: string[]
  isLocal: boolean
  calls: string[]
}

interface LuaVariable {
  name: string
  line: number
  type: 'local' | 'global'
  value?: string
}

interface LuaString {
  value: string
  line: number
  encoding?: 'plain' | 'hex' | 'obfuscated'
}

interface LuaPattern {
  type: 'suspicious' | 'dangerous' | 'info'
  pattern: string
  description: string
  lines: number[]
}

interface LuaAnalyzerProps {
  content: string
  onAnalysisComplete?: (analysis: LuaAnalysis) => void
}

// Patterns to detect in Lua scripts
const DETECTION_PATTERNS = [
  { regex: /os\.execute/g, type: 'dangerous' as const, desc: 'System command execution' },
  { regex: /io\.popen/g, type: 'dangerous' as const, desc: 'Process pipe operation' },
  { regex: /loadstring/g, type: 'dangerous' as const, desc: 'Dynamic code execution' },
  { regex: /dofile/g, type: 'suspicious' as const, desc: 'External file execution' },
  { regex: /require\s*\(\s*["'][^"']+["']\s*\)/g, type: 'info' as const, desc: 'Module import' },
  { regex: /debug\.\w+/g, type: 'suspicious' as const, desc: 'Debug library usage' },
  { regex: /rawset|rawget/g, type: 'suspicious' as const, desc: 'Raw table manipulation' },
  { regex: /string\.dump/g, type: 'suspicious' as const, desc: 'Function bytecode dump' },
  { regex: /\[\[.*?\]\]/gs, type: 'info' as const, desc: 'Multi-line string' },
  { regex: /\\x[0-9a-fA-F]{2}/g, type: 'suspicious' as const, desc: 'Hex-encoded characters' },
  { regex: /getfenv|setfenv/g, type: 'dangerous' as const, desc: 'Environment manipulation' },
  { regex: /package\.loadlib/g, type: 'dangerous' as const, desc: 'Native library loading' },
  { regex: /coroutine\.\w+/g, type: 'info' as const, desc: 'Coroutine usage' },
  { regex: /socket\.\w+/g, type: 'suspicious' as const, desc: 'Network operations' },
  { regex: /http\.request/g, type: 'suspicious' as const, desc: 'HTTP request' },
]

function analyzeLuaScript(content: string): LuaAnalysis {
  const functions: LuaFunction[] = []
  const variables: LuaVariable[] = []
  const strings: LuaString[] = []
  const patterns: LuaPattern[] = []

  // Parse functions
  const funcRegex = /(local\s+)?function\s+(\w+)\s*\(([^)]*)\)/g
  let match: RegExpExecArray | null
  while ((match = funcRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length
    functions.push({
      name: match[2],
      line: lineNum,
      params: match[3].split(',').map(p => p.trim()).filter(Boolean),
      isLocal: !!match[1],
      calls: [],
    })
  }

  // Parse local variable assignments
  const localVarRegex = /local\s+(\w+)\s*=\s*(.+)/g
  while ((match = localVarRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length
    variables.push({
      name: match[1],
      line: lineNum,
      type: 'local',
      value: match[2].trim().substring(0, 50),
    })
  }

  // Parse strings
  const stringRegex = /["']([^"'\\]|\\.)*["']/g
  while ((match = stringRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length
    const value = match[0].slice(1, -1)
    let encoding: 'plain' | 'hex' | 'obfuscated' = 'plain'

    if (/\\x[0-9a-fA-F]{2}/.test(value)) {
      encoding = 'hex'
    } else if (/[^\x20-\x7E]/.test(value) || value.length > 100 && !/\s/.test(value)) {
      encoding = 'obfuscated'
    }

    if (value.length > 0) {
      strings.push({ value, line: lineNum, encoding })
    }
  }

  // Detect patterns
  DETECTION_PATTERNS.forEach(({ regex, type, desc }) => {
    const matches = content.matchAll(new RegExp(regex.source, regex.flags))
    const matchLines: number[] = []

    for (const m of matches) {
      const lineNum = content.substring(0, m.index).split('\n').length
      matchLines.push(lineNum)
    }

    if (matchLines.length > 0) {
      patterns.push({
        type,
        pattern: regex.source,
        description: desc,
        lines: matchLines,
      })
    }
  })

  // Calculate risk score
  let riskScore = 0
  patterns.forEach(p => {
    if (p.type === 'dangerous') riskScore += 30 * p.lines.length
    else if (p.type === 'suspicious') riskScore += 10 * p.lines.length
  })

  // Cap at 100
  riskScore = Math.min(100, riskScore)

  // Generate summary
  const dangerousCount = patterns.filter(p => p.type === 'dangerous').length
  const suspiciousCount = patterns.filter(p => p.type === 'suspicious').length

  let summary = ''
  if (dangerousCount > 0) {
    summary = `High risk: ${dangerousCount} dangerous pattern(s) detected including potential code execution or system access.`
  } else if (suspiciousCount > 0) {
    summary = `Medium risk: ${suspiciousCount} suspicious pattern(s) detected that may warrant further review.`
  } else {
    summary = 'Low risk: No dangerous patterns detected in this script.'
  }

  return {
    functions,
    variables,
    strings,
    patterns,
    riskScore,
    summary,
  }
}

export default function LuaAnalyzer({ content, onAnalysisComplete }: LuaAnalyzerProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['patterns', 'functions']))
  const [selectedLine, setSelectedLine] = useState<number | null>(null)

  const analysis = useMemo(() => {
    const result = analyzeLuaScript(content)
    onAnalysisComplete?.(result)
    return result
  }, [content, onAnalysisComplete])

  const lines = useMemo(() => content.split('\n'), [content])

  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections)
    if (newExpanded.has(section)) {
      newExpanded.delete(section)
    } else {
      newExpanded.add(section)
    }
    setExpandedSections(newExpanded)
  }

  const getRiskColor = (score: number): string => {
    if (score >= 70) return 'text-red-500'
    if (score >= 40) return 'text-amber'
    if (score >= 20) return 'text-yellow-500'
    return 'text-green-500'
  }

  const getRiskBg = (score: number): string => {
    if (score >= 70) return 'bg-red-500/20 border-red-500/30'
    if (score >= 40) return 'bg-amber/20 border-amber/30'
    if (score >= 20) return 'bg-yellow-500/20 border-yellow-500/30'
    return 'bg-green-500/20 border-green-500/30'
  }

  const getPatternIcon = (type: string) => {
    switch (type) {
      case 'dangerous': return <AlertTriangle className="h-4 w-4 text-red-500" />
      case 'suspicious': return <Shield className="h-4 w-4 text-amber" />
      default: return <Info className="h-4 w-4 text-blue-500" />
    }
  }

  const filteredFunctions = analysis.functions.filter(f =>
    f.name.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const filteredVariables = analysis.variables.filter(v =>
    v.name.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className="bg-bg-surface border border-border-visible rounded-lg overflow-hidden">
      {/* Header with Risk Score */}
      <div className="p-4 border-b border-border-dim">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="h-5 w-5 text-amber" />
            <h3 className="text-lg font-semibold text-text-bright">Lua Script Analysis</h3>
          </div>
          <div className={`px-4 py-2 rounded-lg border ${getRiskBg(analysis.riskScore)}`}>
            <span className="text-xs text-text-muted uppercase tracking-wider">Risk Score</span>
            <div className={`text-2xl font-bold ${getRiskColor(analysis.riskScore)}`}>
              {analysis.riskScore}
            </div>
          </div>
        </div>

        {/* Summary */}
        <div className={`p-3 rounded-lg border ${getRiskBg(analysis.riskScore)}`}>
          <p className="text-sm text-text-normal">{analysis.summary}</p>
        </div>

        {/* Search */}
        <div className="mt-4 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search functions, variables..."
            className="w-full pl-10 pr-4 py-2 bg-bg-elevated border border-border-dim text-text-normal text-sm placeholder:text-text-muted focus:outline-none focus:border-amber"
          />
        </div>
      </div>

      {/* Stats Bar */}
      <div className="px-4 py-3 bg-bg-elevated/50 border-b border-border-dim flex items-center gap-6 text-xs">
        <span className="text-text-muted">
          {analysis.functions.length} functions
        </span>
        <span className="text-text-muted">
          {analysis.variables.length} variables
        </span>
        <span className="text-text-muted">
          {analysis.strings.length} strings
        </span>
        <span className="text-red-500">
          {analysis.patterns.filter(p => p.type === 'dangerous').length} dangerous
        </span>
        <span className="text-amber">
          {analysis.patterns.filter(p => p.type === 'suspicious').length} suspicious
        </span>
      </div>

      <div className="flex">
        {/* Left Panel - Analysis */}
        <div className="w-1/2 border-r border-border-dim max-h-[500px] overflow-y-auto">
          {/* Patterns Section */}
          <div className="border-b border-border-dim">
            <button
              onClick={() => toggleSection('patterns')}
              className="w-full flex items-center justify-between p-3 hover:bg-bg-elevated"
            >
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber" />
                <span className="text-sm font-medium text-text-bright">Detected Patterns</span>
                <span className="px-2 py-0.5 bg-bg-elevated text-text-muted text-xs rounded">
                  {analysis.patterns.length}
                </span>
              </div>
              {expandedSections.has('patterns') ? (
                <ChevronDown className="h-4 w-4 text-text-muted" />
              ) : (
                <ChevronRight className="h-4 w-4 text-text-muted" />
              )}
            </button>
            {expandedSections.has('patterns') && (
              <div className="p-3 pt-0 space-y-2">
                {analysis.patterns.length === 0 ? (
                  <p className="text-sm text-text-muted py-2">No suspicious patterns detected</p>
                ) : (
                  analysis.patterns.map((pattern, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-bg-elevated rounded border border-border-dim"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        {getPatternIcon(pattern.type)}
                        <span className="text-sm text-text-normal">{pattern.description}</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-text-muted">
                        <code className="px-1 bg-bg-deep rounded">{pattern.pattern}</code>
                        <span>•</span>
                        <span>Lines: {pattern.lines.map(l => (
                          <button
                            key={l}
                            onClick={() => setSelectedLine(l)}
                            className="text-amber hover:underline mx-0.5"
                          >
                            {l}
                          </button>
                        ))}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {/* Functions Section */}
          <div className="border-b border-border-dim">
            <button
              onClick={() => toggleSection('functions')}
              className="w-full flex items-center justify-between p-3 hover:bg-bg-elevated"
            >
              <div className="flex items-center gap-2">
                <Code className="h-4 w-4 text-blue-500" />
                <span className="text-sm font-medium text-text-bright">Functions</span>
                <span className="px-2 py-0.5 bg-bg-elevated text-text-muted text-xs rounded">
                  {filteredFunctions.length}
                </span>
              </div>
              {expandedSections.has('functions') ? (
                <ChevronDown className="h-4 w-4 text-text-muted" />
              ) : (
                <ChevronRight className="h-4 w-4 text-text-muted" />
              )}
            </button>
            {expandedSections.has('functions') && (
              <div className="p-3 pt-0 space-y-1">
                {filteredFunctions.map((func, idx) => (
                  <button
                    key={idx}
                    onClick={() => setSelectedLine(func.line)}
                    className="w-full text-left p-2 bg-bg-elevated rounded hover:ring-1 hover:ring-amber/50"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`text-xs px-1 rounded ${func.isLocal ? 'bg-blue-500/20 text-blue-400' : 'bg-amber/20 text-amber'}`}>
                        {func.isLocal ? 'local' : 'global'}
                      </span>
                      <code className="text-sm text-text-normal">{func.name}</code>
                      <span className="text-xs text-text-muted">({func.params.join(', ')})</span>
                    </div>
                    <div className="text-xs text-text-muted mt-1">Line {func.line}</div>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Variables Section */}
          <div className="border-b border-border-dim">
            <button
              onClick={() => toggleSection('variables')}
              className="w-full flex items-center justify-between p-3 hover:bg-bg-elevated"
            >
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-text-bright">Variables</span>
                <span className="px-2 py-0.5 bg-bg-elevated text-text-muted text-xs rounded">
                  {filteredVariables.length}
                </span>
              </div>
              {expandedSections.has('variables') ? (
                <ChevronDown className="h-4 w-4 text-text-muted" />
              ) : (
                <ChevronRight className="h-4 w-4 text-text-muted" />
              )}
            </button>
            {expandedSections.has('variables') && (
              <div className="p-3 pt-0 space-y-1">
                {filteredVariables.slice(0, 50).map((variable, idx) => (
                  <button
                    key={idx}
                    onClick={() => setSelectedLine(variable.line)}
                    className="w-full text-left p-2 bg-bg-elevated rounded hover:ring-1 hover:ring-amber/50"
                  >
                    <div className="flex items-center gap-2">
                      <code className="text-sm text-text-normal">{variable.name}</code>
                      {variable.value && (
                        <span className="text-xs text-text-muted truncate max-w-[200px]">
                          = {variable.value}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-text-muted mt-1">Line {variable.line}</div>
                  </button>
                ))}
                {filteredVariables.length > 50 && (
                  <p className="text-xs text-text-muted py-2">
                    +{filteredVariables.length - 50} more variables
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Strings Section */}
          <div>
            <button
              onClick={() => toggleSection('strings')}
              className="w-full flex items-center justify-between p-3 hover:bg-bg-elevated"
            >
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-purple-500" />
                <span className="text-sm font-medium text-text-bright">Strings</span>
                <span className="px-2 py-0.5 bg-bg-elevated text-text-muted text-xs rounded">
                  {analysis.strings.length}
                </span>
              </div>
              {expandedSections.has('strings') ? (
                <ChevronDown className="h-4 w-4 text-text-muted" />
              ) : (
                <ChevronRight className="h-4 w-4 text-text-muted" />
              )}
            </button>
            {expandedSections.has('strings') && (
              <div className="p-3 pt-0 space-y-1">
                {analysis.strings.slice(0, 30).map((str, idx) => (
                  <button
                    key={idx}
                    onClick={() => setSelectedLine(str.line)}
                    className="w-full text-left p-2 bg-bg-elevated rounded hover:ring-1 hover:ring-amber/50"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`text-xs px-1 rounded ${
                        str.encoding === 'hex' ? 'bg-red-500/20 text-red-400' :
                        str.encoding === 'obfuscated' ? 'bg-amber/20 text-amber' :
                        'bg-bg-deep text-text-muted'
                      }`}>
                        {str.encoding}
                      </span>
                      <code className="text-xs text-text-normal truncate max-w-[250px]">
                        "{str.value.substring(0, 50)}{str.value.length > 50 ? '...' : ''}"
                      </code>
                    </div>
                  </button>
                ))}
                {analysis.strings.length > 30 && (
                  <p className="text-xs text-text-muted py-2">
                    +{analysis.strings.length - 30} more strings
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Panel - Code View */}
        <div className="w-1/2 max-h-[500px] overflow-y-auto bg-bg-deep">
          <div className="p-2">
            <pre className="text-xs font-mono">
              {lines.map((line, idx) => {
                const lineNum = idx + 1
                const isHighlighted = selectedLine === lineNum
                const hasPattern = analysis.patterns.some(p => p.lines.includes(lineNum))
                const patternType = analysis.patterns.find(p => p.lines.includes(lineNum))?.type

                return (
                  <div
                    key={idx}
                    className={`flex ${
                      isHighlighted ? 'bg-amber/20' :
                      patternType === 'dangerous' ? 'bg-red-500/10' :
                      patternType === 'suspicious' ? 'bg-amber/10' :
                      ''
                    }`}
                  >
                    <span className="w-10 text-right pr-3 text-text-muted select-none border-r border-border-dim mr-3">
                      {lineNum}
                    </span>
                    <code className={`flex-1 ${hasPattern ? 'text-text-bright' : 'text-text-normal'}`}>
                      {line || ' '}
                    </code>
                  </div>
                )
              })}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}
