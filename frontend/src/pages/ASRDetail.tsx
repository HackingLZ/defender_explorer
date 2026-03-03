import { useQuery } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, Code, ExternalLink, Monitor, FileX, FileCheck, Cpu, FileType, Target, Database, Settings, Link2, Terminal, HardDrive, Globe, Copy, Check, Download, GitBranch, Clock, AlertTriangle, Activity, Shield, Zap } from 'lucide-react'
import { getASRRule, getASRScripts, getLuaScript, getASRRuleLogic, getASRFlowchart, getASRRelatedRules, getASRTimeline, getASRReportUrl, ExtractedPatterns, ASRRuleLogic } from '../api/client'
import LoadingSpinner from '../components/LoadingSpinner'
import ASRFlowchart from '../components/ASRFlowchart'
import Timeline from '../components/Timeline'
import { useState } from 'react'

// RMM Tools that are blocked by the RMM ASR rule (1081f0b6-3e1e-4f44-acce-816d65112d99)
const RMM_TOOLS = [
  { name: 'AnyDesk', category: 'Remote Desktop' },
  { name: 'TeamViewer', category: 'Remote Desktop' },
  { name: 'ScreenConnect (ConnectWise Control)', category: 'Remote Desktop' },
  { name: 'Splashtop', category: 'Remote Desktop' },
  { name: 'LogMeIn', category: 'Remote Desktop' },
  { name: 'GoToAssist', category: 'Remote Desktop' },
  { name: 'Bomgar (BeyondTrust)', category: 'Remote Desktop' },
  { name: 'DameWare', category: 'Remote Desktop' },
  { name: 'Supremo', category: 'Remote Desktop' },
  { name: 'RustDesk', category: 'Remote Desktop' },
  { name: 'Atera', category: 'RMM Platform' },
  { name: 'Datto RMM', category: 'RMM Platform' },
  { name: 'NinjaRMM', category: 'RMM Platform' },
  { name: 'ConnectWise Automate', category: 'RMM Platform' },
  { name: 'N-able (SolarWinds)', category: 'RMM Platform' },
  { name: 'Kaseya VSA', category: 'RMM Platform' },
  { name: 'Action1', category: 'RMM Platform' },
  { name: 'Syncro', category: 'RMM Platform' },
  { name: 'SimpleHelp', category: 'Remote Support' },
  { name: 'Remote Utilities', category: 'Remote Support' },
  { name: 'NetSupport Manager', category: 'Remote Support' },
  { name: 'ISL Online', category: 'Remote Support' },
  { name: 'Zoho Assist', category: 'Remote Support' },
  { name: 'Ammyy Admin', category: 'Remote Support' },
  { name: 'FleetDeck', category: 'RMM Platform' },
  { name: 'Level.io', category: 'RMM Platform' },
  { name: 'Mesh Agent (MeshCentral)', category: 'Remote Desktop' },
  { name: 'TightVNC', category: 'VNC' },
  { name: 'UltraVNC', category: 'VNC' },
  { name: 'RealVNC', category: 'VNC' },
]

const RMM_RULE_GUID = '1081f0b6-3e1e-4f44-acce-816d65112d99'

// Helper to check if extracted data has any content
function hasExtractedData(data: ExtractedPatterns | null | undefined): boolean {
  if (!data) return false
  return (
    (data.exclusion_paths?.length ?? 0) > 0 ||
    (data.detection_paths?.length ?? 0) > 0 ||
    (data.process_names?.length ?? 0) > 0 ||
    (data.file_extensions?.length ?? 0) > 0 ||
    (data.mitre_techniques?.length ?? 0) > 0 ||
    (data.registry_keys?.length ?? 0) > 0 ||
    (data.native_functions?.length ?? 0) > 0 ||
    (data.related_asr_guids?.length ?? 0) > 0 ||
    (data.command_patterns?.length ?? 0) > 0 ||
    (data.vulnerable_drivers?.length ?? 0) > 0 ||
    (data.domains?.length ?? 0) > 0 ||
    (data.rmm_file_paths?.length ?? 0) > 0 ||
    (data.rmm_version_info?.length ?? 0) > 0 ||
    (data.rmm_original_filenames?.length ?? 0) > 0
  )
}

// Count total patterns
function countPatterns(data: ExtractedPatterns | null | undefined): number {
  if (!data) return 0
  return (
    (data.exclusion_paths?.length ?? 0) +
    (data.detection_paths?.length ?? 0) +
    (data.process_names?.length ?? 0) +
    (data.file_extensions?.length ?? 0) +
    (data.mitre_techniques?.length ?? 0) +
    (data.registry_keys?.length ?? 0) +
    (data.native_functions?.length ?? 0) +
    (data.related_asr_guids?.length ?? 0) +
    (data.command_patterns?.length ?? 0) +
    (data.vulnerable_drivers?.length ?? 0) +
    (data.domains?.length ?? 0) +
    (data.rmm_file_paths?.length ?? 0) +
    (data.rmm_version_info?.length ?? 0) +
    (data.rmm_original_filenames?.length ?? 0)
  )
}

// Check if RMM data is available
function hasRmmData(data: ExtractedPatterns | null | undefined): boolean {
  if (!data) return false
  return (
    (data.rmm_file_paths?.length ?? 0) > 0 ||
    (data.rmm_version_info?.length ?? 0) > 0 ||
    (data.rmm_original_filenames?.length ?? 0) > 0
  )
}

// Copy button component
function CopyButton({ text, className = '' }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className={`p-1 rounded hover:bg-black/10 transition-colors ${className}`}
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="h-3 w-3 text-green-600" />
      ) : (
        <Copy className="h-3 w-3 opacity-50 hover:opacity-100" />
      )}
    </button>
  )
}

// Pattern section component with enhanced features
function PatternSection({
  title,
  description,
  items,
  icon: Icon,
  color = 'gray',
  isCode = false,
  linkType,
}: {
  title: string
  description: string
  items: string[]
  icon: React.ElementType
  color?: 'gray' | 'green' | 'red' | 'blue' | 'orange' | 'purple'
  isCode?: boolean
  linkType?: 'mitre' | 'asr' | 'process'
}) {
  const [copied, setCopied] = useState(false)

  if (items.length === 0) return null

  const colorClasses = {
    gray: 'bg-gray-50 text-gray-600',
    green: 'bg-green-50 text-green-700',
    red: 'bg-red-50 text-red-700',
    blue: 'bg-blue-50 text-blue-700',
    orange: 'bg-orange-50 text-orange-700',
    purple: 'bg-purple-50 text-purple-700',
  }

  const dotColors = {
    gray: 'bg-gray-400',
    green: 'bg-green-400',
    red: 'bg-red-400',
    blue: 'bg-blue-400',
    orange: 'bg-orange-400',
    purple: 'bg-purple-400',
  }

  const copyAll = async () => {
    await navigator.clipboard.writeText(items.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const renderItem = (item: string) => {
    if (linkType === 'mitre') {
      // Validate MITRE technique ID format before constructing URL
      if (/^T\d{4}(\.\d{3})?$/.test(item)) {
        const url = `https://attack.mitre.org/techniques/${item.replace('.', '/')}/`
        return (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-purple-700 hover:text-purple-900 hover:underline flex items-center gap-1"
          >
            {item}
            <ExternalLink className="h-3 w-3" />
          </a>
        )
      }
      return <span className="text-purple-700">{item}</span>
    }
    if (linkType === 'asr') {
      // Validate GUID format before constructing link
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item)) {
        return (
          <Link
            to={`/asr/${item}`}
            className="text-blue-600 hover:text-blue-800 hover:underline font-mono text-xs"
          >
            {item}
          </Link>
        )
      }
      return <span className="font-mono text-xs">{item}</span>
    }
    if (linkType === 'process') {
      // Link to threat search
      return (
        <Link
          to={`/threats?q=${encodeURIComponent(item)}`}
          className="text-blue-600 hover:text-blue-800 hover:underline"
        >
          {item}
        </Link>
      )
    }
    if (isCode) {
      return <code className="font-mono text-xs break-all">{item}</code>
    }
    return <span className="break-all">{item}</span>
  }

  return (
    <div className={`rounded-lg p-4 ${colorClasses[color]}`}>
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4" />
          <h3 className="text-sm font-medium">{title} ({items.length})</h3>
        </div>
        <button
          onClick={copyAll}
          className="p-1 rounded hover:bg-black/10 transition-colors"
          title="Copy all"
        >
          {copied ? (
            <Check className="h-3.5 w-3.5 text-green-600" />
          ) : (
            <Copy className="h-3.5 w-3.5 opacity-50 hover:opacity-100" />
          )}
        </button>
      </div>
      <p className="text-xs opacity-75 mb-3">{description}</p>
      <ul className="space-y-1.5 max-h-48 overflow-y-auto">
        {items.map((item, idx) => (
          <li key={idx} className="flex items-start gap-2 text-sm group">
            <span className={`w-1.5 h-1.5 ${dotColors[color]} rounded-full mt-1.5 flex-shrink-0`}></span>
            <span className="flex-1 min-w-0">{renderItem(item)}</span>
            <CopyButton text={item} className="opacity-0 group-hover:opacity-100" />
          </li>
        ))}
      </ul>
    </div>
  )
}

// Export functions
function exportAsJSON(rule: any, patterns: ExtractedPatterns | null | undefined) {
  try {
    const data = {
      guid: rule.guid,
      name: rule.name,
      short_name: rule.short_name,
      description: rule.description,
      patterns: patterns || {},
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `asr-${(rule.short_name || rule.guid).replace(/[^a-zA-Z0-9_\-]/g, '_')}.json`
    a.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    console.error('Failed to export JSON:', error)
    alert('Failed to export JSON. Please try again.')
  }
}

function exportAsCSV(rule: any, patterns: ExtractedPatterns | null | undefined) {
  if (!patterns) return

  try {
    const rows: string[][] = [['Category', 'Value']]

    const addRows = (category: string, items: string[] | undefined) => {
      items?.forEach(item => rows.push([category, item]))
    }

    addRows('Exclusion Path', patterns.exclusion_paths)
    addRows('Detection Path', patterns.detection_paths)
    addRows('Process Name', patterns.process_names)
    addRows('File Extension', patterns.file_extensions)
    addRows('MITRE Technique', patterns.mitre_techniques)
    addRows('Registry Key', patterns.registry_keys)
    addRows('Native Function', patterns.native_functions)
    addRows('Related ASR', patterns.related_asr_guids)
    addRows('Command Pattern', patterns.command_patterns)
    addRows('Vulnerable Driver', patterns.vulnerable_drivers)
    addRows('Domain', patterns.domains)

    const csv = rows.map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `asr-${(rule.short_name || rule.guid).replace(/[^a-zA-Z0-9_\-]/g, '_')}.csv`
    a.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    console.error('Failed to export CSV:', error)
    alert('Failed to export CSV. Please try again.')
  }
}

// Expandable Flow Item Component
function ExpandableFlowItem({
  step,
  items,
  color = 'blue'
}: {
  step: string;
  items?: string[];
  color?: 'blue' | 'green' | 'red' | 'amber'
}) {
  const [expanded, setExpanded] = useState(false)
  const hasItems = items && items.length > 0

  const colorClasses = {
    blue: 'text-blue-700 bg-blue-100',
    green: 'text-green-700 bg-green-100',
    red: 'text-red-700 bg-red-100',
    amber: 'text-amber-700 bg-amber-100',
  }

  return (
    <div>
      <div
        className={`text-sm font-mono whitespace-pre-wrap ${hasItems ? 'cursor-pointer hover:bg-blue-100 rounded px-1 -mx-1' : ''}`}
        onClick={() => hasItems && setExpanded(!expanded)}
      >
        {step}
        {hasItems && (
          <span className={`ml-2 text-xs px-1.5 py-0.5 rounded ${colorClasses[color]}`}>
            {expanded ? '▼' : '▶'} click to {expanded ? 'collapse' : 'expand'}
          </span>
        )}
      </div>
      {expanded && items && (
        <div className="ml-6 mt-1 mb-2 pl-3 border-l-2 border-blue-200">
          <ul className="space-y-0.5 max-h-48 overflow-y-auto">
            {items.map((item, idx) => (
              <li key={idx} className="text-xs text-blue-600 font-mono flex items-start gap-2">
                <span className="text-blue-400">•</span>
                <code className="break-all">{item}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// Rule Logic Summary Component
function RuleLogicSummary({ data, isLoading }: { data: ASRRuleLogic | undefined; isLoading: boolean }) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32 text-gray-400">
        <div className="text-center">
          <div className="animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-2" />
          <p className="text-sm">Analyzing rule logic...</p>
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="text-sm text-gray-500 p-4">
        Logic analysis not available
      </div>
    )
  }

  // Map flow steps to their expandable data
  const getExpandableItems = (step: string): string[] | undefined => {
    const s = step.toLowerCase()
    if (s.includes('exclusion') && s.includes('pattern')) return data.patterns.exclusion_paths
    if (s.includes('process') && s.includes('monitored')) return data.patterns.process_names
    if (s.includes('detection pattern')) return data.patterns.detection_paths
    if (s.includes('command line') && s.includes('regex')) return data.patterns.command_patterns
    if (s.includes('file extension')) return data.patterns.file_extensions
    if (s.includes('registry')) return data.patterns.registry_keys
    if (s.includes('vulnerable driver')) return data.patterns.vulnerable_drivers
    if (s.includes('rmm tool database')) {
      const all = [
        ...(data.patterns.rmm_file_paths || []).map(p => `[path] ${p}`),
        ...(data.patterns.rmm_original_filenames || []).map(p => `[filename] ${p}`),
      ]
      return all.length > 0 ? all.slice(0, 50) : undefined
    }
    return undefined
  }

  const { script_breakdown: sb } = data
  const totalScripts = data.script_count

  return (
    <div className="space-y-4">
      {/* Script Breakdown */}
      {totalScripts > 0 && (
        <div className="flex items-center gap-3 text-xs">
          <span className="text-gray-500">{totalScripts} script{totalScripts !== 1 ? 's' : ''} analyzed:</span>
          {sb.detection > 0 && (
            <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full">{sb.detection} detection</span>
          )}
          {sb.config > 0 && (
            <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded-full">{sb.config} config</span>
          )}
          {sb.helper > 0 && (
            <span className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded-full">{sb.helper} helper</span>
          )}
        </div>
      )}

      {/* Confidence Notes */}
      {data.confidence_notes?.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-amber-800 text-sm font-medium mb-1">
            <AlertTriangle className="w-4 h-4" />
            Analysis Notes
          </div>
          {data.confidence_notes.map((note, idx) => (
            <p key={idx} className="text-xs text-amber-700 mt-1">{note}</p>
          ))}
        </div>
      )}

      {/* Detection Flow */}
      {data.flow?.length > 0 && (
        <div className="bg-blue-50 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-blue-800 mb-2">Detection Flow</h3>
          <ol className="space-y-1.5 text-blue-700">
            {data.flow.map((step, idx) => (
              <li key={idx}>
                <ExpandableFlowItem
                  step={step}
                  items={getExpandableItems(step)}
                  color={step.toLowerCase().includes('exclusion') ? 'green' : step.includes('BLOCK') ? 'red' : step.toLowerCase().includes('outcome') ? 'amber' : 'blue'}
                />
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Detection Checks */}
        {data.checks?.length > 0 && (
          <div className="bg-amber-50 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-amber-800 mb-2 flex items-center gap-1.5">
              <Shield className="w-4 h-4" />
              Detection Checks
            </h3>
            <ul className="space-y-1">
              {data.checks.map((check, idx) => (
                <li key={idx} className="text-sm text-amber-700 flex items-start gap-2">
                  <span className="w-1.5 h-1.5 bg-amber-400 rounded-full mt-1.5 flex-shrink-0" />
                  {check}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Outcomes */}
        {data.outcomes?.length > 0 && (
          <div className="bg-red-50 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-red-800 mb-2 flex items-center gap-1.5">
              <Zap className="w-4 h-4" />
              Outcomes
            </h3>
            <ul className="space-y-1">
              {data.outcomes.map((outcome, idx) => (
                <li key={idx} className="text-sm text-red-700 flex items-start gap-2">
                  <span className="w-1.5 h-1.5 bg-red-400 rounded-full mt-1.5 flex-shrink-0" />
                  {outcome}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Telemetry & MITRE row */}
      {((data.telemetry_attributes?.length ?? 0) > 0 || (data.mitre_techniques?.length ?? 0) > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.telemetry_attributes?.length > 0 && (
            <div className="bg-indigo-50 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-indigo-800 mb-2 flex items-center gap-1.5">
                <Activity className="w-4 h-4" />
                Telemetry Attributes ({data.telemetry_attributes?.length})
              </h3>
              <ul className="space-y-1 max-h-32 overflow-y-auto">
                {data.telemetry_attributes?.map((attr, idx) => (
                  <li key={idx} className="text-xs text-indigo-700 font-mono flex items-start gap-2">
                    <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full mt-1 flex-shrink-0" />
                    {attr}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {data.mitre_techniques?.length > 0 && (
            <div className="bg-purple-50 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-purple-800 mb-2 flex items-center gap-1.5">
                <Target className="w-4 h-4" />
                MITRE ATT&CK Techniques
              </h3>
              <ul className="space-y-1">
                {data.mitre_techniques?.map((tech, idx) => (
                  <li key={idx} className="text-sm text-purple-700 flex items-start gap-2">
                    <span className="w-1.5 h-1.5 bg-purple-400 rounded-full mt-1.5 flex-shrink-0" />
                    {/^T\d{4}(\.\d{3})?$/.test(tech) ? (
                      <a
                        href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:underline flex items-center gap-1"
                      >
                        {tech}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span>{tech}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Referenced ASR Rules */}
      {data.referenced_asr_rules?.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-2 flex items-center gap-1.5">
            <Link2 className="w-4 h-4" />
            Cross-Referenced ASR Rules
          </h3>
          <ul className="space-y-1">
            {data.referenced_asr_rules.map((ref, idx) => (
              <li key={idx} className="text-sm flex items-start gap-2">
                <span className="w-1.5 h-1.5 bg-gray-400 rounded-full mt-1.5 flex-shrink-0" />
                <Link to={`/asr/${ref.guid}`} className="text-blue-600 hover:underline">
                  {ref.name}
                </Link>
                <code className="text-xs text-gray-400 font-mono">{ref.guid}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* API Calls */}
      {data.api_calls?.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-2 flex items-center gap-1.5">
            <Terminal className="w-4 h-4" />
            Defender API Calls
          </h3>
          <ul className="space-y-1">
            {data.api_calls.map((call, idx) => (
              <li key={idx} className="text-sm flex items-start gap-2">
                <span className="w-1.5 h-1.5 bg-gray-400 rounded-full mt-1.5 flex-shrink-0" />
                <code className="font-mono text-blue-600 text-xs">{call.api}</code>
                <span className="text-gray-500 text-xs">— {call.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Functions */}
      {data.functions?.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-2">
            Script Functions ({data.script_count} scripts)
          </h3>
          <ul className="space-y-1">
            {data.functions.map((func, idx) => (
              <li key={idx} className="text-sm flex items-start gap-2">
                <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${func.is_entry_point ? 'bg-red-400' : func.is_config ? 'bg-blue-400' : 'bg-gray-400'}`} />
                <code className="font-mono text-blue-600">{func.name}({func.params})</code>
                {func.description && (
                  <span className="text-gray-500 text-xs">— {func.description}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default function ASRDetail() {
  const { guid } = useParams<{ guid: string }>()
  const isValidGuid = guid ? /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(guid) : false
  const [selectedScriptId, setSelectedScriptId] = useState<number | null>(null)

  const { data: ruleData, isLoading: ruleLoading } = useQuery({
    queryKey: ['asr-rule', guid],
    queryFn: () => getASRRule(guid!),
    enabled: isValidGuid,
  })

  const { data: scriptsData, isLoading: scriptsLoading } = useQuery({
    queryKey: ['asr-scripts', guid],
    queryFn: () => getASRScripts(guid!),
    enabled: isValidGuid,
  })

  const { data: luaData } = useQuery({
    queryKey: ['lua', selectedScriptId],
    queryFn: () => getLuaScript(selectedScriptId!),
    enabled: !!selectedScriptId,
  })

  const { data: ruleLogicData, isLoading: ruleLogicLoading } = useQuery({
    queryKey: ['asr-rule-logic', guid],
    queryFn: () => getASRRuleLogic(guid!),
    enabled: isValidGuid,
  })

  if (!guid || !isValidGuid) {
    return (
      <div className="text-center py-12">
        <p className="text-red-400">Invalid ASR rule GUID</p>
      </div>
    )
  }

  if (ruleLoading || scriptsLoading) {
    return <LoadingSpinner />
  }

  const rule = ruleData?.data
  const scripts = scriptsData?.data || []

  if (!rule) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">ASR rule not found</p>
      </div>
    )
  }

  const totalPatterns = countPatterns(rule.extracted_data)

  return (
    <div>
      {/* Back link */}
      <Link
        to="/asr"
        className="inline-flex items-center text-sm text-text-dim hover:text-amber mb-4"
      >
        <ArrowLeft className="h-4 w-4 mr-1" />
        Back to ASR rules
      </Link>

      {/* Header Card */}
      <div className="mb-6 bg-bg-surface rounded-xl p-4 sm:p-6 border border-border-visible">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div className="flex-1 min-w-0">
            <h1 className="text-xl sm:text-2xl font-bold text-text-bright break-words">{rule.name}</h1>
            <div className="flex flex-wrap items-center gap-2 sm:gap-3 mt-3">
              <code className="font-mono text-xs sm:text-sm bg-bg-elevated text-text-dim px-2 sm:px-3 py-1 sm:py-1.5 rounded border border-border-dim break-all">
                {rule.guid}
              </code>
              {rule.short_name && (
                <span className="text-sm font-medium text-text-dim bg-bg-elevated px-3 py-1.5 rounded">
                  {rule.short_name}
                </span>
              )}
            </div>
            {rule.description && (
              <p className="mt-4 text-text-dim text-sm sm:text-base">{rule.description}</p>
            )}
          </div>
          <div className="flex flex-wrap gap-2 sm:flex-col flex-shrink-0">
            <a
              href={`https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#${rule.guid}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center text-sm text-amber hover:text-amber-bright bg-amber/10 px-3 py-1.5 rounded"
            >
              MS Docs
              <ExternalLink className="h-4 w-4 ml-1" />
            </a>
            {hasExtractedData(rule.extracted_data) && (
              <div className="flex gap-1">
                <button
                  onClick={() => exportAsJSON(rule, rule.extracted_data)}
                  className="inline-flex items-center text-xs text-text-dim hover:text-text-bright bg-bg-elevated px-2 py-1 rounded border border-border-dim"
                  title="Export as JSON"
                >
                  <Download className="h-3 w-3 mr-1" />
                  JSON
                </button>
                <button
                  onClick={() => exportAsCSV(rule, rule.extracted_data)}
                  className="inline-flex items-center text-xs text-text-dim hover:text-text-bright bg-bg-elevated px-2 py-1 rounded border border-border-dim"
                  title="Export as CSV"
                >
                  <Download className="h-3 w-3 mr-1" />
                  CSV
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 sm:gap-4 mt-4 pt-4 border-t border-border-dim">
          <div className="text-center">
            <div className="text-xl sm:text-2xl font-bold text-text-bright">{scripts.length}</div>
            <div className="text-xs text-text-muted">Scripts</div>
          </div>
          <div className="text-center">
            <div className="text-xl sm:text-2xl font-bold text-green-500">{rule.extracted_data?.exclusion_paths?.length ?? 0}</div>
            <div className="text-xs text-text-muted">Exclusions</div>
          </div>
          <div className="text-center">
            <div className="text-xl sm:text-2xl font-bold text-red-500">{rule.extracted_data?.detection_paths?.length ?? 0}</div>
            <div className="text-xs text-text-muted">Detections</div>
          </div>
          <div className="text-center">
            <div className="text-xl sm:text-2xl font-bold text-blue-500">{rule.extracted_data?.process_names?.length ?? 0}</div>
            <div className="text-xs text-text-muted">Processes</div>
          </div>
          <div className="text-center">
            <div className="text-xl sm:text-2xl font-bold text-purple-500">{rule.extracted_data?.mitre_techniques?.length ?? 0}</div>
            <div className="text-xs text-text-muted">MITRE</div>
          </div>
          <div className="text-center">
            <div className="text-xl sm:text-2xl font-bold text-text-dim">{totalPatterns}</div>
            <div className="text-xs text-text-muted">Total Patterns</div>
          </div>
        </div>
      </div>

      {/* Extracted Patterns */}
      {hasExtractedData(rule.extracted_data) && (
        <div className="mb-6 bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center gap-2 mb-4">
            <Settings className="h-5 w-5 text-blue-600" />
            <h2 className="text-lg font-semibold text-gray-900">
              Extracted Patterns
            </h2>
          </div>
          <p className="text-sm text-gray-600 mb-4">
            Patterns automatically extracted from decompiled Lua scripts. Click items to copy, or use the copy button to copy all in a section.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            <PatternSection
              title="Exclusion Paths"
              description="Paths where this rule does NOT apply (allowlisted)"
              items={rule.extracted_data?.exclusion_paths || []}
              icon={FileCheck}
              color="green"
              isCode
            />
            <PatternSection
              title="Detection Paths"
              description="Paths monitored for suspicious activity"
              items={rule.extracted_data?.detection_paths || []}
              icon={FileX}
              color="red"
              isCode
            />
            <PatternSection
              title="Process Names"
              description="Executables monitored by this rule"
              items={rule.extracted_data?.process_names || []}
              icon={Cpu}
              color="blue"
              linkType="process"
            />
            <PatternSection
              title="File Extensions"
              description="File types monitored or blocked"
              items={rule.extracted_data?.file_extensions || []}
              icon={FileType}
              color="orange"
            />
            <PatternSection
              title="MITRE Techniques"
              description="ATT&CK techniques detected or prevented"
              items={rule.extracted_data?.mitre_techniques || []}
              icon={Target}
              color="purple"
              linkType="mitre"
            />
            <PatternSection
              title="Registry Keys"
              description="Registry locations monitored for changes"
              items={rule.extracted_data?.registry_keys || []}
              icon={Database}
              color="gray"
              isCode
            />
            <PatternSection
              title="Native Functions"
              description="Windows API functions used for detection"
              items={rule.extracted_data?.native_functions || []}
              icon={Terminal}
              color="blue"
            />
            <PatternSection
              title="Related ASR Rules"
              description="Other ASR rules referenced by scripts"
              items={rule.extracted_data?.related_asr_guids || []}
              icon={Link2}
              color="gray"
              linkType="asr"
            />
            <PatternSection
              title="Vulnerable Drivers"
              description="Drivers blocked to prevent kernel exploitation"
              items={rule.extracted_data?.vulnerable_drivers || []}
              icon={HardDrive}
              color="red"
            />
            <PatternSection
              title="Command Patterns"
              description="Command-line patterns monitored"
              items={rule.extracted_data?.command_patterns || []}
              icon={Terminal}
              color="orange"
              isCode
            />
            <PatternSection
              title="Domains"
              description="Network domains monitored or blocked"
              items={rule.extracted_data?.domains || []}
              icon={Globe}
              color="purple"
              isCode
            />
          </div>
        </div>
      )}

      {/* Rule Logic Summary */}
      <div className="mb-6 bg-white rounded-xl p-6 shadow-sm border border-gray-100">
        <div className="flex items-center gap-2 mb-4">
          <Code className="h-5 w-5 text-purple-600" />
          <h2 className="text-lg font-semibold text-gray-900">
            Rule Logic Summary
          </h2>
        </div>
        <p className="text-sm text-gray-600 mb-4">
          High-level overview of how this ASR rule works, derived from analyzing all associated Lua scripts.
        </p>
        <RuleLogicSummary data={ruleLogicData?.data} isLoading={ruleLogicLoading} />
      </div>

      {/* RMM Tools List - Show extracted data if available, fallback to hardcoded list */}
      {guid?.toLowerCase() === RMM_RULE_GUID && (
        <div className="mb-6 bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="flex items-center gap-2 mb-4">
            <Monitor className="h-5 w-5 text-orange-600" />
            <h2 className="text-lg font-semibold text-gray-900">
              Blocked RMM Tools
              {hasRmmData(rule.extracted_data) ? (
                <span className="ml-2 text-sm font-normal text-gray-500">
                  ({(rule.extracted_data?.rmm_file_paths?.length ?? 0) +
                    (rule.extracted_data?.rmm_version_info?.length ?? 0) +
                    (rule.extracted_data?.rmm_original_filenames?.length ?? 0)} patterns extracted)
                </span>
              ) : (
                <span className="ml-2 text-sm font-normal text-gray-500">({RMM_TOOLS.length} known tools)</span>
              )}
            </h2>
          </div>
          <p className="text-sm text-gray-600 mb-4">
            This ASR rule blocks execution of files associated with Remote Monitoring and Management (RMM) tools.
            Detection is performed by native Defender functions: <code className="bg-gray-100 px-1 rounded">IsRmmToolFilePath</code>,{' '}
            <code className="bg-gray-100 px-1 rounded">IsRmmToolVersionInfo</code>, and{' '}
            <code className="bg-gray-100 px-1 rounded">IsRmmToolOFN</code>.
          </p>

          {/* Show extracted RMM data if available */}
          {hasRmmData(rule.extracted_data) ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {/* RMM File Paths */}
              {(rule.extracted_data?.rmm_file_paths?.length ?? 0) > 0 && (
                <div className="bg-orange-50 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-orange-700 mb-2">
                    File Path Patterns ({rule.extracted_data?.rmm_file_paths?.length})
                  </h3>
                  <p className="text-xs text-orange-600 mb-2">Detected via IsRmmToolFilePath</p>
                  <ul className="space-y-1 max-h-48 overflow-y-auto">
                    {rule.extracted_data?.rmm_file_paths?.map((path, idx) => (
                      <li key={idx} className="text-sm text-orange-700 flex items-start gap-2">
                        <span className="w-1.5 h-1.5 bg-orange-400 rounded-full mt-1.5 flex-shrink-0"></span>
                        <code className="font-mono text-xs break-all">{path}</code>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* RMM Version Info */}
              {(rule.extracted_data?.rmm_version_info?.length ?? 0) > 0 && (
                <div className="bg-blue-50 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-blue-700 mb-2">
                    Version Info Patterns ({rule.extracted_data?.rmm_version_info?.length})
                  </h3>
                  <p className="text-xs text-blue-600 mb-2">Detected via IsRmmToolVersionInfo</p>
                  <ul className="space-y-1 max-h-48 overflow-y-auto">
                    {rule.extracted_data?.rmm_version_info?.map((info, idx) => (
                      <li key={idx} className="text-sm text-blue-700 flex items-start gap-2">
                        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full mt-1.5 flex-shrink-0"></span>
                        <code className="font-mono text-xs break-all">{info}</code>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* RMM Original Filenames */}
              {(rule.extracted_data?.rmm_original_filenames?.length ?? 0) > 0 && (
                <div className="bg-purple-50 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-purple-700 mb-2">
                    Original Filenames ({rule.extracted_data?.rmm_original_filenames?.length})
                  </h3>
                  <p className="text-xs text-purple-600 mb-2">Detected via IsRmmToolOFN</p>
                  <ul className="space-y-1 max-h-48 overflow-y-auto">
                    {rule.extracted_data?.rmm_original_filenames?.map((name, idx) => (
                      <li key={idx} className="text-sm text-purple-700 flex items-start gap-2">
                        <span className="w-1.5 h-1.5 bg-purple-400 rounded-full mt-1.5 flex-shrink-0"></span>
                        <code className="font-mono text-xs break-all">{name}</code>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            /* Fallback to hardcoded list if no extracted data */
            <div>
              <p className="text-xs text-amber-600 mb-3 italic">
                Note: Run "Extract Patterns" from Admin panel to populate extracted RMM tool data from Lua scripts.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(
                  RMM_TOOLS.reduce((acc, tool) => {
                    if (!acc[tool.category]) acc[tool.category] = []
                    acc[tool.category].push(tool.name)
                    return acc
                  }, {} as Record<string, string[]>)
                ).map(([category, tools]) => (
                  <div key={category} className="bg-gray-50 rounded-lg p-4">
                    <h3 className="text-sm font-medium text-gray-700 mb-2">{category}</h3>
                    <ul className="space-y-1">
                      {tools.map((tool) => (
                        <li key={tool} className="text-sm text-gray-600 flex items-center gap-2">
                          <span className="w-1.5 h-1.5 bg-orange-400 rounded-full"></span>
                          {tool}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scripts and Source */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
        {/* Scripts List */}
        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Associated Scripts ({scripts.length})
          </h2>
          {scripts.length > 0 ? (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {scripts.map((script) => (
                <button
                  key={script.id}
                  onClick={() => setSelectedScriptId(script.id)}
                  className={`w-full text-left py-3 px-4 rounded-lg transition-colors ${
                    selectedScriptId === script.id
                      ? 'bg-blue-100 text-blue-700'
                      : 'bg-gray-50 hover:bg-gray-100'
                  }`}
                >
                  <div className="flex items-center">
                    <Code className="h-4 w-4 mr-2 flex-shrink-0" />
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">
                        {script.threat_name || 'Unknown threat'}
                      </p>
                      <p className="text-xs font-mono text-gray-500 truncate">
                        {script.bytecode_hash?.slice(0, 16)}...
                      </p>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500">
              No scripts found for this ASR rule
            </p>
          )}
        </div>

        {/* Script Details */}
        <div className="lg:col-span-2 bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          {luaData?.data ? (
            <>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-gray-900">
                  Script Source
                </h2>
                {luaData.data.threat_id && (
                  <Link
                    to={`/threats/${luaData.data.threat_id}`}
                    className="text-sm text-blue-600 hover:text-blue-700"
                  >
                    View Threat
                  </Link>
                )}
              </div>
              {luaData.data.decompiled_source ? (
                <>
                  <div className="mb-3 px-3 py-2 bg-amber-50 border border-amber-200 rounded text-xs text-amber-800">
                    Note: This source is automatically decompiled from Lua bytecode.
                    The decompiler may produce inverted conditions, unreachable code blocks,
                    or restructured control flow. Verify logic against the original bytecode.
                  </div>
                  <pre className="code-block whitespace-pre-wrap max-h-[600px] overflow-y-auto">
                    {luaData.data.decompiled_source}
                  </pre>
                </>
              ) : (
                <p className="text-sm text-gray-500">
                  Decompilation not available for this script
                </p>
              )}
            </>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-400">
              <div className="text-center">
                <Code className="h-12 w-12 mx-auto mb-4" />
                <p>Select a script to view its source</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Enhanced Analysis Tabs */}
      <ASRAnalysisTabs guid={guid!} ruleName={rule.name || rule.short_name || rule.guid} />
    </div>
  )
}

// Separate component for the analysis tabs
function ASRAnalysisTabs({ guid, ruleName }: { guid: string; ruleName: string }) {
  const [activeTab, setActiveTab] = useState<'flowchart' | 'related' | 'timeline'>('flowchart')

  // Flowchart query
  const { data: flowchartData, isLoading: flowchartLoading } = useQuery({
    queryKey: ['asr-flowchart', guid],
    queryFn: () => getASRFlowchart(guid).then(r => r.data),
    enabled: activeTab === 'flowchart',
  })

  // Related rules query
  const { data: relatedData, isLoading: relatedLoading } = useQuery({
    queryKey: ['asr-related', guid],
    queryFn: () => getASRRelatedRules(guid).then(r => r.data),
    enabled: activeTab === 'related',
  })

  // Timeline query
  const { data: timelineData, isLoading: timelineLoading } = useQuery({
    queryKey: ['asr-timeline', guid],
    queryFn: () => getASRTimeline(guid).then(r => r.data),
    enabled: activeTab === 'timeline',
  })

  const tabs = [
    { id: 'flowchart' as const, label: 'Visual Flowchart', icon: Code },
    { id: 'related' as const, label: 'Related Rules', icon: GitBranch },
    { id: 'timeline' as const, label: 'Timeline', icon: Clock },
  ]

  return (
    <div className="mt-6 bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
      {/* Tab headers */}
      <div className="flex items-center gap-1 px-4 border-b border-gray-200 bg-gray-50 overflow-x-auto scrollbar-hide">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 sm:gap-2 px-3 sm:px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap ${
              activeTab === tab.id
                ? 'text-blue-600 border-blue-600 bg-white'
                : 'text-gray-500 border-transparent hover:text-gray-700 hover:bg-gray-100'
            }`}
          >
            <tab.icon className="w-4 h-4 flex-shrink-0" />
            {tab.label}
          </button>
        ))}

        {/* Export button */}
        <div className="ml-auto flex items-center gap-2 py-2 flex-shrink-0">
          <a
            href={getASRReportUrl(guid, 'html')}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs px-2 py-1 bg-gray-100 text-gray-600 hover:text-gray-800 border border-gray-200 rounded hidden sm:block"
          >
            Export HTML
          </a>
          <a
            href={getASRReportUrl(guid, 'pdf')}
            className="text-xs px-2 py-1 bg-blue-600 text-white hover:bg-blue-700 rounded"
          >
            <span className="hidden sm:inline">Export </span>PDF
          </a>
        </div>
      </div>

      {/* Tab content */}
      <div className="p-6 min-h-[400px]">
        {/* Flowchart Tab */}
        {activeTab === 'flowchart' && (
          <div>
            {flowchartLoading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : flowchartData ? (
              <ASRFlowchart flowchart={flowchartData} />
            ) : (
              <div className="text-center py-12 text-gray-500">
                <Code className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No flowchart data available</p>
              </div>
            )}
          </div>
        )}

        {/* Related Rules Tab */}
        {activeTab === 'related' && (
          <div>
            {relatedLoading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : relatedData && relatedData.related_rules.length > 0 ? (
              <div className="space-y-3">
                <p className="text-sm text-gray-600 mb-4">
                  ASR rules that share exclusion paths or processes with this rule.
                </p>
                {relatedData.related_rules.map((rule) => (
                  <Link
                    key={rule.rule_guid}
                    to={`/asr/${rule.rule_guid}`}
                    className="block p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="font-medium text-gray-900">{rule.short_name || rule.rule_name}</div>
                        <code className="text-xs text-gray-500">{rule.rule_guid}</code>
                      </div>
                      <div className="text-right">
                        <div className="text-lg font-bold text-blue-600">{rule.total_shared}</div>
                        <div className="text-xs text-gray-500">shared items</div>
                      </div>
                    </div>
                    {(rule.shared_exclusions.length > 0 || rule.shared_processes.length > 0) && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {rule.shared_exclusions.slice(0, 3).map((excl, i) => (
                          <span key={i} className="text-xs px-2 py-0.5 bg-green-100 text-green-700 rounded">
                            {excl.length > 30 ? excl.slice(0, 30) + '...' : excl}
                          </span>
                        ))}
                        {rule.shared_processes.slice(0, 3).map((proc, i) => (
                          <span key={i} className="text-xs px-2 py-0.5 bg-blue-100 text-blue-700 rounded">
                            {proc}
                          </span>
                        ))}
                        {(rule.shared_exclusions.length + rule.shared_processes.length > 6) && (
                          <span className="text-xs text-gray-500">
                            +{rule.shared_exclusions.length + rule.shared_processes.length - 6} more
                          </span>
                        )}
                      </div>
                    )}
                  </Link>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <GitBranch className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No related rules found</p>
                <p className="text-sm mt-1">This rule doesn't share exclusions with other rules</p>
              </div>
            )}
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
              <Timeline timeline={timelineData} entityName={ruleName} />
            ) : null}
          </div>
        )}

      </div>
    </div>
  )
}
