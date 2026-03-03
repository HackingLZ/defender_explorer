import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Shield,
  ChevronRight,
  Code,
  Search,
  FileCheck,
  FileX,
  Cpu,
  Target,
  Download,
} from 'lucide-react'
import {
  getASRRules,
  ASRRule,
  ExtractedPatterns,
} from '../api/client'
import LoadingSpinner from '../components/LoadingSpinner'
import ASRExclusionOverlap from '../components/ASRExclusionOverlap'
import { useState, useMemo } from 'react'

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
    (data.domains?.length ?? 0)
  )
}

function exportAllASR(rules: ASRRule[]) {
  const data = rules.map(rule => ({
    guid: rule.guid,
    name: rule.name,
    short_name: rule.short_name,
    description: rule.description,
    script_count: rule.script_count,
    patterns: rule.extracted_data || {},
  }))
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'asr-rules-all.json'
  a.click()
  URL.revokeObjectURL(url)
}

export default function ASRBrowser() {
  const [searchQuery, setSearchQuery] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['asr-rules'],
    queryFn: () => getASRRules(),
  })

  const rules = data?.data || []

  // Calculate summary stats
  const stats = useMemo(() => {
    let totalExclusions = 0
    let totalDetections = 0
    let totalProcesses = 0
    let totalMitre = 0
    let rulesWithData = 0

    rules.forEach(rule => {
      if (rule.extracted_data) {
        totalExclusions += rule.extracted_data.exclusion_paths?.length ?? 0
        totalDetections += rule.extracted_data.detection_paths?.length ?? 0
        totalProcesses += rule.extracted_data.process_names?.length ?? 0
        totalMitre += rule.extracted_data.mitre_techniques?.length ?? 0
        if (countPatterns(rule.extracted_data) > 0) rulesWithData++
      }
    })

    return { totalExclusions, totalDetections, totalProcesses, totalMitre, rulesWithData }
  }, [rules])

  // Filter rules by search
  const filteredRules = useMemo(() => {
    if (!searchQuery) return rules
    const query = searchQuery.toLowerCase()
    return rules.filter(rule =>
      rule.name?.toLowerCase().includes(query) ||
      rule.short_name?.toLowerCase().includes(query) ||
      rule.guid.toLowerCase().includes(query)
    )
  }, [rules, searchQuery])

  if (isLoading) {
    return <LoadingSpinner />
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-text-bright">ASR Rules</h1>
            <p className="mt-2 text-text-dim">
              Attack Surface Reduction rules and extracted detection patterns
            </p>
          </div>
          <button
            onClick={() => exportAllASR(rules)}
            className="inline-flex items-center text-sm text-text-dim hover:text-text-bright bg-bg-elevated px-3 py-2 rounded border border-border-visible"
          >
            <Download className="h-4 w-4 mr-2" />
            Export All
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3 mb-6">
        <div className="bg-bg-surface rounded-lg p-3 border border-border-visible">
          <div className="text-xl font-bold text-text-bright">{rules.length}</div>
          <div className="text-xs text-text-muted">Rules</div>
        </div>
        <div className="bg-bg-surface rounded-lg p-3 border border-border-visible">
          <div className="text-xl font-bold text-blue-500">{stats.rulesWithData}</div>
          <div className="text-xs text-text-muted">With Data</div>
        </div>
        <div className="bg-bg-surface rounded-lg p-3 border border-border-visible">
          <div className="text-xl font-bold text-green-500">{stats.totalExclusions}</div>
          <div className="text-xs text-text-muted">Exclusions</div>
        </div>
        <div className="bg-bg-surface rounded-lg p-3 border border-border-visible">
          <div className="text-xl font-bold text-red-500">{stats.totalDetections}</div>
          <div className="text-xs text-text-muted">Detections</div>
        </div>
        <div className="bg-bg-surface rounded-lg p-3 border border-border-visible">
          <div className="text-xl font-bold text-blue-500">{stats.totalProcesses}</div>
          <div className="text-xs text-text-muted">Processes</div>
        </div>
        <div className="bg-bg-surface rounded-lg p-3 border border-border-visible">
          <div className="text-xl font-bold text-purple-500">{stats.totalMitre}</div>
          <div className="text-xs text-text-muted">MITRE</div>
        </div>
      </div>

      {/* Search */}
      <div className="bg-bg-surface rounded-xl border border-border-visible p-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
            <input
              type="text"
              placeholder="Search rules by name, GUID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-bg-elevated border border-border-dim rounded-lg text-text-normal placeholder:text-text-muted focus:outline-none focus:border-amber"
            />
          </div>
        </div>
      </div>

      {/* Rules List */}
      <div className="bg-bg-surface rounded-xl border border-border-visible overflow-hidden">
        <div className="px-6 py-4 border-b border-border-dim flex justify-between items-center">
          <p className="text-sm text-text-muted">{filteredRules.length} rules</p>
        </div>
        <div className="divide-y divide-border-dim">
          {filteredRules.map((rule) => (
            <Link
              key={rule.guid}
              to={`/asr/${rule.guid}`}
              className="flex items-center justify-between px-6 py-4 hover:bg-bg-elevated transition-colors"
            >
              <div className="flex items-center flex-1 min-w-0">
                <Shield className="h-5 w-5 text-blue-500 mr-4 flex-shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-text-bright truncate">
                    {rule.name || rule.guid}
                  </p>
                  {rule.short_name && (
                    <p className="text-sm text-text-muted mt-0.5">{rule.short_name}</p>
                  )}
                </div>
              </div>

              {/* Stats */}
              <div className="flex items-center gap-4 ml-4">
                <div className="hidden md:flex items-center gap-3 text-xs">
                  {(rule.extracted_data?.exclusion_paths?.length ?? 0) > 0 && (
                    <span className="flex items-center text-green-500" title="Exclusions">
                      <FileCheck className="h-3.5 w-3.5 mr-1" />
                      {rule.extracted_data?.exclusion_paths?.length}
                    </span>
                  )}
                  {(rule.extracted_data?.detection_paths?.length ?? 0) > 0 && (
                    <span className="flex items-center text-red-500" title="Detections">
                      <FileX className="h-3.5 w-3.5 mr-1" />
                      {rule.extracted_data?.detection_paths?.length}
                    </span>
                  )}
                  {(rule.extracted_data?.process_names?.length ?? 0) > 0 && (
                    <span className="flex items-center text-blue-500" title="Processes">
                      <Cpu className="h-3.5 w-3.5 mr-1" />
                      {rule.extracted_data?.process_names?.length}
                    </span>
                  )}
                  {(rule.extracted_data?.mitre_techniques?.length ?? 0) > 0 && (
                    <span className="flex items-center text-purple-500" title="MITRE Techniques">
                      <Target className="h-3.5 w-3.5 mr-1" />
                      {rule.extracted_data?.mitre_techniques?.length}
                    </span>
                  )}
                </div>
                <div className="flex items-center text-sm text-text-dim">
                  <Code className="h-4 w-4 mr-1" />
                  {rule.script_count}
                </div>
                <ChevronRight className="h-5 w-5 text-text-muted" />
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Exclusion Overlap Analysis */}
      {rules.length > 0 && (
        <div className="mt-6">
          <ASRExclusionOverlap rules={rules} />
        </div>
      )}
    </div>
  )
}
