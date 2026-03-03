import { useQuery } from '@tanstack/react-query'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, X, Download, FileText, Type, Binary, Shield, Globe, FolderOpen, Key, Terminal, AlertTriangle, Info, Copy, Check, GitBranch, Clock, Microscope, Network, Layers } from 'lucide-react'
import { getThreat, getSignature, getClassifiedSignatures, getSignatureDownloadUrl, getYaraDownloadUrl, getThreatAnalysis, getRelatedThreats, getThreatTimeline, getThreatReportUrl } from '../api/client'
import LoadingSpinner from '../components/LoadingSpinner'
import HexViewer from '../components/HexViewer'
import RelatedThreats from '../components/RelatedThreats'
import Timeline from '../components/Timeline'
import ThreatGraph from '../components/ThreatGraph'
import SignatureSimilarity from '../components/SignatureSimilarity'
import { useState, useMemo } from 'react'

// Signature type explanations
const SIG_TYPE_INFO: Record<string, { name: string; description: string; icon: typeof Shield }> = {
  'SIGNATURE_TYPE_PEHSTR': { name: 'PE Header String', description: 'String pattern found in PE file headers', icon: Type },
  'SIGNATURE_TYPE_PEHSTR_EXT': { name: 'PE Extended String', description: 'Extended string patterns in PE files with context', icon: Type },
  'INNOSCRIPT': { name: 'Inno Setup Script', description: 'Patterns in Inno Setup installer scripts', icon: FileText },
  'SIGNATURE_TYPE_THREAT_BEGIN': { name: 'Threat Begin', description: 'Start marker for threat definition block', icon: Shield },
  'SIGNATURE_TYPE_THREAT_END': { name: 'Threat End', description: 'End marker for threat definition block', icon: Shield },
  'SIGNATURE_TYPE_VSTRS': { name: 'Variable Strings', description: 'Variable-length string patterns', icon: Type },
  'SIGNATURE_TYPE_NSCRIPT': { name: 'NSIS Script', description: 'Patterns in NSIS installer scripts', icon: FileText },
  'SIGNATURE_TYPE_MACROHSTR': { name: 'Macro Header String', description: 'Strings in Office macro headers', icon: FileText },
  'SIGNATURE_TYPE_MACRO': { name: 'Macro Signature', description: 'VBA macro detection patterns', icon: FileText },
  'SIGNATURE_TYPE_JAVAHSTR': { name: 'Java Header String', description: 'Strings in Java class files', icon: FileText },
  'SIGNATURE_TYPE_STATIC': { name: 'Static Pattern', description: 'Fixed byte pattern signature', icon: Binary },
  'SIGNATURE_TYPE_ELFHSTR': { name: 'ELF Header String', description: 'Strings in Linux ELF binaries', icon: FileText },
  'SIGNATURE_TYPE_ELFHSTR_EXT': { name: 'ELF Extended String', description: 'Extended string patterns in ELF files', icon: Type },
  'SIGNATURE_TYPE_MACHOHSTR': { name: 'Mach-O Header String', description: 'Strings in macOS Mach-O binaries', icon: FileText },
  'SIGNATURE_TYPE_MACHOHSTR_EXT': { name: 'Mach-O Extended', description: 'Extended patterns in Mach-O files', icon: Type },
  'SIGNATURE_TYPE_LUASTANDALONE': { name: 'Lua Standalone', description: 'Standalone Lua script detection', icon: Terminal },
  'SIGNATURE_TYPE_AUTOITHSTR': { name: 'AutoIt String', description: 'Strings in AutoIt scripts', icon: FileText },
}

// Classify strings for display
function classifyString(str: string): { type: string; icon: typeof Shield; color: string } {
  const lower = str.toLowerCase()

  if (lower.includes('http://') || lower.includes('https://') || lower.includes('ftp://')) {
    return { type: 'URL', icon: Globe, color: 'text-blue-500' }
  }
  if (lower.includes('\\appdata\\') || lower.includes('\\users\\') || lower.includes('program files') ||
      lower.includes('\\roaming\\') || lower.includes('\\local\\')) {
    return { type: 'Path', icon: FolderOpen, color: 'text-orange-500' }
  }
  if (lower.includes('.dll') || lower.includes('.exe') || lower.includes('.sys')) {
    return { type: 'File', icon: FileText, color: 'text-purple-500' }
  }
  if (lower.includes('password') || lower.includes('credential') || lower.includes('cookie') ||
      lower.includes('token') || lower.includes('encrypted') || lower.includes('decrypt')) {
    return { type: 'Credential', icon: Key, color: 'text-red-500' }
  }
  if (lower.includes('chrome') || lower.includes('firefox') || lower.includes('opera') ||
      lower.includes('browser') || lower.includes('edge') || lower.includes('yandex')) {
    return { type: 'Browser', icon: Globe, color: 'text-green-500' }
  }
  if (lower.includes('hkey_') || lower.includes('\\software\\') || lower.includes('\\currentversion\\')) {
    return { type: 'Registry', icon: Terminal, color: 'text-yellow-500' }
  }

  return { type: 'String', icon: Type, color: 'text-gray-500' }
}

// Copy button
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button onClick={handleCopy} className="p-1 hover:bg-bg-elevated rounded">
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-text-muted" />}
    </button>
  )
}

export default function ThreatDetail() {
  const { sigId } = useParams<{ sigId: string }>()
  const [selectedSigId, setSelectedSigId] = useState<number | null>(null)
  const [viewMode, setViewMode] = useState<'all' | 'strings' | 'binary'>('all')

  // Parse sigId safely with NaN check
  const parsedSigId = sigId ? parseInt(sigId, 10) : NaN

  const { data, isLoading } = useQuery({
    queryKey: ['threat', sigId],
    queryFn: () => getThreat(parsedSigId),
    enabled: !!sigId && !isNaN(parsedSigId),
  })

  const { data: classifiedData } = useQuery({
    queryKey: ['classified', sigId],
    queryFn: () => getClassifiedSignatures(parsedSigId),
    enabled: !!sigId && !isNaN(parsedSigId),
  })

  const { data: sigData, isLoading: sigLoading } = useQuery({
    queryKey: ['signature', selectedSigId],
    queryFn: () => getSignature(selectedSigId!),
    enabled: !!selectedSigId,
  })

  // Extract all unique strings from all signatures for analysis
  const allExtractedStrings = useMemo(() => {
    if (!classifiedData?.data) return []

    const strings: string[] = []

    classifiedData.data.string_signatures?.forEach(sig => {
      if (sig.content) strings.push(sig.content)
    })

    classifiedData.data.binary_signatures?.forEach(sig => {
      if (sig.extracted_strings) {
        strings.push(...sig.extracted_strings)
      }
    })

    // Dedupe and filter short strings
    return [...new Set(strings)].filter(s => s.length > 4)
  }, [classifiedData])

  // Classify all strings
  const classifiedStrings = useMemo(() => {
    const classified: Record<string, string[]> = {}

    allExtractedStrings.forEach(str => {
      const { type } = classifyString(str)
      if (!classified[type]) classified[type] = []
      classified[type].push(str)
    })

    return classified
  }, [allExtractedStrings])

  // Group signatures by type
  const signaturesByType = useMemo(() => {
    if (!classifiedData?.data) return {}

    const grouped: Record<string, number> = {}

    classifiedData.data.binary_signatures?.forEach(sig => {
      const name = sig.sig_type_name || `Type 0x${sig.sig_type.toString(16)}`
      grouped[name] = (grouped[name] || 0) + 1
    })

    classifiedData.data.string_signatures?.forEach(sig => {
      const name = sig.sig_type_name || `Type 0x${sig.sig_type.toString(16)}`
      grouped[name] = (grouped[name] || 0) + 1
    })

    return grouped
  }, [classifiedData])

  // Handle invalid sigId
  if (!sigId || isNaN(parsedSigId)) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Invalid threat ID</p>
        <Link to="/threats" className="text-amber hover:underline mt-2 inline-block">
          Back to threats
        </Link>
      </div>
    )
  }

  if (isLoading) {
    return <LoadingSpinner />
  }

  const threat = data?.data

  if (!threat) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Threat not found</p>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <Link
          to="/threats"
          className="inline-flex items-center text-sm text-text-dim hover:text-amber mb-4"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to threats
        </Link>
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-xl sm:text-2xl font-bold text-text-bright break-words">{threat.threat_name}</h1>
            <div className="flex flex-wrap items-center gap-2 sm:gap-4 mt-2">
              {threat.category && (
                <span className="badge badge-amber">{threat.category}</span>
              )}
              {threat.family && (
                <span className="badge">{threat.family}</span>
              )}
              <span className="text-sm text-text-dim font-mono">
                {threat.signature_id} (0x{threat.signature_id.toString(16).toUpperCase().padStart(8, '0')})
              </span>
            </div>
          </div>
          {/* Download Buttons */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <a
              href={getSignatureDownloadUrl(threat.signature_id, 'hex')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 sm:px-3 sm:py-2 bg-bg-elevated border border-border-visible text-text-normal text-sm hover:bg-bg-surface transition-colors"
            >
              <Download className="h-4 w-4" />
              <span className="hidden sm:inline">Hex</span>
            </a>
            <a
              href={getSignatureDownloadUrl(threat.signature_id, 'c')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 sm:px-3 sm:py-2 bg-bg-elevated border border-border-visible text-text-normal text-sm hover:bg-bg-surface transition-colors"
            >
              <FileText className="h-4 w-4" />
              <span className="hidden sm:inline">C Array</span>
            </a>
            <a
              href={getYaraDownloadUrl(threat.signature_id)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 sm:px-3 sm:py-2 bg-amber text-bg-deep text-sm font-medium hover:bg-amber-light transition-colors"
            >
              <Download className="h-4 w-4" />
              YARA
            </a>
          </div>
        </div>
      </div>

      {/* Detection Summary - shows extracted strings analysis */}
      {allExtractedStrings.length > 0 && (
        <div className="mb-6 bg-bg-surface border border-border-visible p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="h-5 w-5 text-amber" />
            <h2 className="text-lg font-semibold text-text-bright">Detection Summary</h2>
          </div>
          <p className="text-sm text-text-dim mb-4">
            Analysis of {allExtractedStrings.length} extracted strings from signatures
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(classifiedStrings).map(([type, strings]) => {
              const { icon: Icon, color } = classifyString(strings[0])
              return (
                <div key={type} className="bg-bg-elevated p-4 border border-border-dim">
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className={`h-4 w-4 ${color}`} />
                    <h3 className="text-sm font-medium text-text-normal">{type} ({strings.length})</h3>
                  </div>
                  <ul className="space-y-1 max-h-32 overflow-y-auto">
                    {strings.slice(0, 10).map((str, idx) => (
                      <li key={idx} className="flex items-center gap-2 group">
                        <code className="text-xs font-mono text-text-dim truncate flex-1">{str}</code>
                        <CopyButton text={str} />
                      </li>
                    ))}
                    {strings.length > 10 && (
                      <li className="text-xs text-text-muted">+{strings.length - 10} more</li>
                    )}
                  </ul>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Stats and Signature Types Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-6">
        {/* Classification Stats */}
        <div className="bg-bg-surface border border-border-visible p-4">
          <div className="text-3xl font-bold text-text-bright">{classifiedData?.data?.total || 0}</div>
          <div className="text-xs text-text-muted uppercase tracking-wider">Total Signatures</div>
        </div>
        <div className="bg-bg-surface border border-border-visible p-4">
          <div className="text-3xl font-bold text-green-500">{classifiedData?.data?.string_count || 0}</div>
          <div className="text-xs text-text-muted uppercase tracking-wider">String Signatures</div>
        </div>
        <div className="bg-bg-surface border border-border-visible p-4">
          <div className="text-3xl font-bold text-blue-500">{classifiedData?.data?.binary_count || 0}</div>
          <div className="text-xs text-text-muted uppercase tracking-wider">Binary Signatures</div>
        </div>
        <div className="bg-bg-surface border border-border-visible p-4">
          <div className="text-3xl font-bold text-purple-500">{allExtractedStrings.length}</div>
          <div className="text-xs text-text-muted uppercase tracking-wider">Extracted Strings</div>
        </div>
      </div>

      {/* Signature Types with Explanations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="bg-bg-surface border border-border-visible p-6">
          <h2 className="text-lg font-semibold text-text-bright mb-4">Signature Types</h2>
          <div className="space-y-3">
            {Object.entries(signaturesByType).map(([type, count]) => {
              const info = SIG_TYPE_INFO[type]
              return (
                <div key={type} className="border-b border-border-dim pb-3 last:border-0 last:pb-0">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-text-normal">{info?.name || type}</span>
                    <span className="text-sm font-bold text-text-bright">{count}</span>
                  </div>
                  {info && (
                    <p className="text-xs text-text-muted mt-1">{info.description}</p>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Signatures List */}
        <div className="bg-bg-surface border border-border-visible p-6 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-text-bright">Signatures</h2>
            <div className="flex items-center gap-1 bg-bg-elevated p-1">
              <button
                onClick={() => setViewMode('all')}
                className={`px-3 py-1 text-xs font-medium transition-colors ${
                  viewMode === 'all' ? 'bg-amber text-bg-deep' : 'text-text-dim hover:text-text-normal'
                }`}
              >
                All
              </button>
              <button
                onClick={() => setViewMode('strings')}
                className={`px-3 py-1 text-xs font-medium transition-colors flex items-center gap-1 ${
                  viewMode === 'strings' ? 'bg-green-500 text-white' : 'text-text-dim hover:text-text-normal'
                }`}
              >
                <Type className="h-3 w-3" /> Strings
              </button>
              <button
                onClick={() => setViewMode('binary')}
                className={`px-3 py-1 text-xs font-medium transition-colors flex items-center gap-1 ${
                  viewMode === 'binary' ? 'bg-blue-500 text-white' : 'text-text-dim hover:text-text-normal'
                }`}
              >
                <Binary className="h-3 w-3" /> Binary
              </button>
            </div>
          </div>

          {/* String Signatures */}
          {(viewMode === 'all' || viewMode === 'strings') && classifiedData?.data?.string_signatures && classifiedData.data.string_signatures.length > 0 && (
            <div className="mb-4">
              {viewMode === 'all' && (
                <h3 className="text-xs text-green-500 uppercase tracking-wider mb-2 flex items-center gap-2">
                  <Type className="h-3 w-3" /> String Signatures ({classifiedData.data.string_count})
                </h3>
              )}
              <div className="max-h-64 overflow-y-auto space-y-1">
                {classifiedData.data.string_signatures.slice(0, 100).map((sig) => (
                  <button
                    key={sig.id}
                    onClick={() => setSelectedSigId(sig.id)}
                    className={`w-full text-left flex items-center justify-between py-2 px-3 transition-colors ${
                      selectedSigId === sig.id
                        ? 'bg-green-500/20 text-green-400 border-l-2 border-green-500'
                        : 'bg-bg-elevated hover:bg-bg-deep'
                    }`}
                  >
                    <div className="flex items-center flex-1 min-w-0">
                      <Type className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
                      <span className="text-sm font-mono truncate text-text-normal">"{sig.content}"</span>
                    </div>
                    <span className="text-xs text-text-muted ml-2">{sig.sig_type_name}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Binary Signatures */}
          {(viewMode === 'all' || viewMode === 'binary') && classifiedData?.data?.binary_signatures && classifiedData.data.binary_signatures.length > 0 && (
            <div>
              {viewMode === 'all' && (
                <h3 className="text-xs text-blue-500 uppercase tracking-wider mb-2 flex items-center gap-2">
                  <Binary className="h-3 w-3" /> Binary Signatures ({classifiedData.data.binary_count})
                </h3>
              )}
              <div className="max-h-64 overflow-y-auto space-y-1">
                {classifiedData.data.binary_signatures.slice(0, 100).map((sig) => (
                  <button
                    key={sig.id}
                    onClick={() => setSelectedSigId(sig.id)}
                    className={`w-full text-left flex items-center justify-between py-2 px-3 transition-colors ${
                      selectedSigId === sig.id
                        ? 'bg-blue-500/20 text-blue-400 border-l-2 border-blue-500'
                        : 'bg-bg-elevated hover:bg-bg-deep'
                    }`}
                  >
                    <div className="flex items-center flex-1 min-w-0">
                      <Binary className="h-4 w-4 text-blue-500 mr-2 flex-shrink-0" />
                      <span className="text-sm font-mono text-text-dim">
                        {sig.sig_type_name || `0x${sig.sig_type.toString(16)}`}
                      </span>
                      {sig.extracted_strings && sig.extracted_strings.length > 0 && (
                        <span className="ml-2 text-xs text-green-400 bg-green-500/20 px-1.5 py-0.5 rounded">
                          {sig.extracted_strings.length} strings
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-text-muted">{sig.size} bytes</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Empty state */}
          {(!classifiedData?.data?.string_signatures?.length && !classifiedData?.data?.binary_signatures?.length) && (
            <div className="text-center py-8 text-text-muted">
              <Info className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No signatures available</p>
            </div>
          )}
        </div>
      </div>

      {/* Signature Hex Viewer */}
      {selectedSigId && (
        <div className="bg-bg-surface border border-border-visible p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-text-bright">
                Signature Data
              </h2>
              {sigData?.data && (
                <p className="text-sm text-text-dim mt-1">
                  {sigData.data.sig_type_name} | {sigData.data.size} bytes
                </p>
              )}
            </div>
            <button
              onClick={() => setSelectedSigId(null)}
              className="p-1 hover:bg-bg-elevated"
            >
              <X className="h-5 w-5 text-text-muted" />
            </button>
          </div>

          {sigLoading ? (
            <div className="flex justify-center py-8">
              <LoadingSpinner />
            </div>
          ) : sigData?.data?.hex_dump ? (
            <div>
              {/* Show extracted strings if any */}
              {sigData.data.data_preview && (
                <div className="mb-4 p-3 bg-bg-elevated border border-border-dim">
                  <div className="text-xs text-text-muted uppercase tracking-wider mb-2">Preview</div>
                  <code className="text-sm text-green-400">{sigData.data.data_preview}</code>
                </div>
              )}
              <pre className="code-block font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre">
{sigData.data.hex_dump}
              </pre>
            </div>
          ) : (
            <p className="text-sm text-text-dim">No data available for this signature</p>
          )}
        </div>
      )}

      {/* Enhanced Analysis Tabs */}
      {!isNaN(parsedSigId) && (
        <ThreatAnalysisTabs sigId={parsedSigId} threatName={threat.threat_name} />
      )}
    </div>
  )
}

// Separate component for the analysis tabs to keep queries organized
function ThreatAnalysisTabs({ sigId, threatName }: { sigId: number; threatName: string }) {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<'analysis' | 'related' | 'timeline' | 'graph' | 'similarity'>('analysis')

  // Analysis query
  const { data: analysisData, isLoading: analysisLoading } = useQuery({
    queryKey: ['threat-analysis', sigId],
    queryFn: () => getThreatAnalysis(sigId).then(r => r.data),
    enabled: activeTab === 'analysis',
  })

  // Related threats query - fetch always since it's used by 3 tabs
  const { data: relatedData, isLoading: relatedLoading } = useQuery({
    queryKey: ['related-threats', sigId],
    queryFn: () => getRelatedThreats(sigId).then(r => r.data),
  })

  // Check if we have related data to show
  const hasRelatedThreats = relatedData && relatedData.related && relatedData.related.length > 0

  // Timeline query
  const { data: timelineData, isLoading: timelineLoading } = useQuery({
    queryKey: ['threat-timeline', sigId],
    queryFn: () => getThreatTimeline(sigId).then(r => r.data),
    enabled: activeTab === 'timeline',
  })

  // Tabs that require related data - show while loading, hide if loaded and empty
  const showRelatedTabs = relatedLoading || hasRelatedThreats
  const relatedTabs = showRelatedTabs ? [
    { id: 'graph' as const, label: 'Threat Graph', icon: Network },
    { id: 'similarity' as const, label: 'Similarity', icon: Layers },
    { id: 'related' as const, label: 'Related Threats', icon: GitBranch, count: relatedData?.total },
  ] : []

  const tabs = [
    { id: 'analysis' as const, label: 'Deep Analysis', icon: Microscope },
    ...relatedTabs,
    { id: 'timeline' as const, label: 'Timeline', icon: Clock },
  ]

  // Generate mock graph data from related threats
  const graphNodes = useMemo(() => {
    if (!relatedData) return []
    const nodes = [
      {
        id: sigId,
        label: threatName,
        category: null,
        family: null,
        signatureCount: 1,
      },
      ...relatedData.related.slice(0, 20).map((t) => ({
        id: t.signature_id,
        label: t.threat_name,
        category: t.category,
        family: t.family,
        signatureCount: 1,
      })),
    ]
    return nodes
  }, [relatedData, sigId, threatName])

  const graphEdges = useMemo(() => {
    if (!relatedData) return []
    return relatedData.related.slice(0, 20).map((t) => ({
      source: sigId,
      target: t.signature_id,
      weight: t.similarity_score / 100,
      types: t.similarity_types.length > 0 ? t.similarity_types : ['family'],
    }))
  }, [relatedData, sigId])

  // Generate similarity data from related threats
  const similarSignatures = useMemo(() => {
    if (!relatedData) return []
    return relatedData.related.slice(0, 15).map((t, i) => ({
      id: i,
      signatureId: t.signature_id,
      threatName: t.threat_name,
      category: t.category,
      family: t.family,
      similarity: t.similarity_score,
      matchType: (t.similarity_score >= 80 ? 'high' : t.similarity_score >= 50 ? 'medium' : 'low') as 'high' | 'medium' | 'low',
      sharedStrings: t.shared_strings,
      matchingBytes: t.matching_bytes,
    }))
  }, [relatedData])

  return (
    <div className="mt-6">
      {/* Tab headers */}
      <div className="flex items-center gap-1 mb-4 border-b border-border-dim overflow-x-auto scrollbar-hide">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 sm:gap-2 px-3 sm:px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap ${
              activeTab === tab.id
                ? 'text-amber border-amber'
                : 'text-text-dim border-transparent hover:text-text-normal hover:border-border-visible'
            }`}
          >
            <tab.icon className="w-4 h-4 flex-shrink-0" />
            <span className="hidden sm:inline">{tab.label}</span>
            <span className="sm:hidden">{tab.label.split(' ').pop()}</span>
          </button>
        ))}

        {/* Export button */}
        <div className="ml-auto flex items-center gap-2 pb-2 flex-shrink-0">
          <a
            href={getThreatReportUrl(sigId, 'html')}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs px-2 py-1 bg-bg-elevated text-text-dim hover:text-text-normal border border-border-dim rounded hidden sm:block"
          >
            Export HTML
          </a>
          <a
            href={getThreatReportUrl(sigId, 'pdf')}
            className="text-xs px-2 py-1 bg-amber text-bg-deep hover:bg-amber-light rounded"
          >
            <span className="hidden sm:inline">Export </span>PDF
          </a>
        </div>
      </div>

      {/* Tab content */}
      <div className="min-h-[400px]">
        {/* Deep Analysis Tab */}
        {activeTab === 'analysis' && (
          <div>
            {analysisLoading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : analysisData && analysisData.signatures.length > 0 ? (
              <div className="space-y-6">
                {/* Summary stats */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
                  <div className="bg-bg-surface border border-border-visible p-4">
                    <div className="text-2xl font-bold text-text-bright">{analysisData.total_size.toLocaleString()}</div>
                    <div className="text-xs text-text-muted uppercase">Total Bytes</div>
                  </div>
                  <div className="bg-bg-surface border border-border-visible p-4">
                    <div className="text-2xl font-bold text-green-500">{analysisData.unique_strings}</div>
                    <div className="text-xs text-text-muted uppercase">Unique Strings</div>
                  </div>
                  <div className="bg-bg-surface border border-border-visible p-4">
                    <div className="text-2xl font-bold text-amber">{analysisData.detected_patterns.length}</div>
                    <div className="text-xs text-text-muted uppercase">Detected Patterns</div>
                  </div>
                  <div className="bg-bg-surface border border-border-visible p-4">
                    <div className="text-2xl font-bold text-blue-500">{analysisData.signatures.length}</div>
                    <div className="text-xs text-text-muted uppercase">Analyzed Sigs</div>
                  </div>
                </div>

                {/* Detected patterns */}
                {analysisData.detected_patterns.length > 0 && (
                  <div className="bg-bg-surface border border-border-visible p-4">
                    <h3 className="text-sm font-semibold text-text-bright mb-3 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber" />
                      Detected Suspicious Patterns
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {analysisData.detected_patterns.map((pattern, i) => (
                        <span key={i} className="text-xs px-2 py-1 bg-amber/20 text-amber rounded">
                          {pattern}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Hex viewer for first signature with data */}
                {analysisData.signatures[0] && (
                  <HexViewer analysis={analysisData.signatures[0]} maxRows={24} />
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-text-muted">
                <Microscope className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No analysis data available</p>
              </div>
            )}
          </div>
        )}

        {/* Related Threats Tab */}
        {activeTab === 'related' && (
          <div>
            {relatedLoading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : relatedData ? (
              <RelatedThreats threats={relatedData.related} currentThreatId={sigId} />
            ) : null}
          </div>
        )}

        {/* Timeline Tab */}
        {activeTab === 'timeline' && (
          <div>
            {timelineLoading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : timelineData ? (
              <Timeline timeline={timelineData} entityName={threatName} />
            ) : null}
          </div>
        )}

        {/* Threat Graph Tab */}
        {activeTab === 'graph' && (
          <div>
            {relatedLoading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : graphNodes.length > 1 ? (
              <ThreatGraph
                nodes={graphNodes}
                edges={graphEdges}
                centerNodeId={sigId}
                onNodeClick={(nodeId) => {
                  if (nodeId !== sigId && /^\d+$/.test(String(nodeId))) {
                    navigate(`/threats/${nodeId}`)
                  }
                }}
              />
            ) : (
              <div className="text-center py-12 text-text-muted">
                <Network className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No relationship data available to display graph</p>
              </div>
            )}
          </div>
        )}

        {/* Similarity Tab */}
        {activeTab === 'similarity' && (
          <div>
            {relatedLoading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : similarSignatures.length > 0 ? (
              <SignatureSimilarity
                signatures={similarSignatures}
                onClusterSelect={(ids) => {
                  console.log('Selected cluster:', ids)
                }}
              />
            ) : (
              <div className="text-center py-12 text-text-muted">
                <Layers className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No similar signatures found</p>
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  )
}
