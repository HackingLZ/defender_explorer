import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  Search,
  FileCode,
  Plus,
  X,
  Download,
  Copy,
  Check,
  Loader2,
  Trash2,
} from 'lucide-react'
import { searchThreats, getCategories, buildCombinedYaraRule, type Threat, type YaraBuildResult } from '../api/client'

export default function YaraBuilder() {
  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<string>('')
  const [selectedThreats, setSelectedThreats] = useState<Map<number, Threat>>(new Map())
  const [ruleName, setRuleName] = useState('combined_detection')
  const [generatedRule, setGeneratedRule] = useState<YaraBuildResult | null>(null)
  const [copied, setCopied] = useState(false)

  // Search threats - increased limit for bulk selection
  const { data: searchResults, isLoading: searchLoading } = useQuery({
    queryKey: ['threat-search', searchQuery, categoryFilter],
    queryFn: () => searchThreats({
      q: searchQuery || '*',
      page: 1,
      page_size: 200  // Get more results for bulk selection
    }).then(r => r.data),
    enabled: searchQuery.length >= 2 || categoryFilter !== '',
  })

  // Get categories for filter
  const { data: categoriesData } = useQuery({
    queryKey: ['categories'],
    queryFn: () => getCategories(),
  })
  const categories = categoriesData?.data || []

  // Build YARA mutation
  const buildMutation = useMutation({
    mutationFn: () => buildCombinedYaraRule(
      Array.from(selectedThreats.keys()),
      ruleName
    ).then(r => r.data),
    onSuccess: (data) => {
      setGeneratedRule(data)
    },
  })

  const addThreat = (threat: Threat) => {
    setSelectedThreats(prev => {
      const next = new Map(prev)
      next.set(threat.signature_id, threat)
      return next
    })
  }

  const removeThreat = (signatureId: number) => {
    setSelectedThreats(prev => {
      const next = new Map(prev)
      next.delete(signatureId)
      return next
    })
    // Clear generated rule if threats change
    if (generatedRule) {
      setGeneratedRule(null)
    }
  }

  const clearAll = () => {
    setSelectedThreats(new Map())
    setGeneratedRule(null)
  }

  const handleCopy = async () => {
    if (generatedRule) {
      await navigator.clipboard.writeText(generatedRule.rule_content)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleDownload = () => {
    if (generatedRule) {
      const blob = new Blob([generatedRule.rule_content], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${generatedRule.rule_name}.yar`
      a.click()
      URL.revokeObjectURL(url)
    }
  }

  // Validate rule name for YARA identifier format
  const isValidRuleName = (name: string): boolean => {
    // YARA identifiers must start with letter or underscore, followed by alphanumeric or underscores
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)
  }

  const ruleNameError = ruleName && !isValidRuleName(ruleName)
    ? 'Rule name must start with a letter/underscore and contain only letters, numbers, and underscores'
    : null

  // Filter search results to exclude already selected
  const filteredResults = useMemo(() => {
    const items = Array.isArray(searchResults?.items) ? searchResults!.items : []
    return items.filter(t => !selectedThreats.has(t.signature_id))
  }, [searchResults, selectedThreats])

  // Group selected threats by category
  const selectedByCategory = useMemo(() => {
    const groups: Record<string, Threat[]> = {}
    selectedThreats.forEach(threat => {
      const cat = threat.category || 'Unknown'
      if (!groups[cat]) groups[cat] = []
      groups[cat].push(threat)
    })
    return groups
  }, [selectedThreats])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-bright flex items-center gap-2">
          <FileCode className="h-6 w-6 text-amber" />
          YARA Rule Builder
        </h1>
        <p className="text-sm text-text-dim mt-1">
          Search and select multiple threats to generate a combined YARA rule
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Search and Select */}
        <div className="space-y-4">
          {/* Search */}
          <div className="bg-bg-surface border border-border-visible p-4">
            <h2 className="text-sm font-semibold text-text-bright mb-3">Search Threats</h2>

            <div className="flex gap-2 mb-3">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search threats (e.g., cobalt, mimikatz)..."
                  className="w-full pl-10 pr-4 py-2 bg-bg-elevated border border-border-dim text-text-normal text-sm placeholder:text-text-muted focus:outline-none focus:border-amber"
                />
              </div>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-3 py-2 bg-bg-elevated border border-border-dim text-text-normal text-sm focus:outline-none focus:border-amber"
              >
                <option value="">All Categories</option>
                {(Array.isArray(categories) ? categories : []).map(cat => (
                  <option key={cat.category} value={cat.category}>
                    {cat.category} ({cat.count})
                  </option>
                ))}
              </select>
            </div>

            {/* Select All / Results count */}
            {filteredResults.length > 0 && (
              <div className="flex items-center justify-between mb-2 py-2 border-b border-border-dim">
                <span className="text-xs text-text-muted">
                  {filteredResults.length} result{filteredResults.length !== 1 ? 's' : ''}
                  {searchResults && searchResults.total > filteredResults.length + selectedThreats.size && (
                    <span className="text-text-dim"> (of {searchResults.total} total)</span>
                  )}
                </span>
                <button
                  onClick={() => filteredResults.forEach(t => addThreat(t))}
                  className="text-xs px-2 py-1 bg-amber/20 text-amber hover:bg-amber/30 flex items-center gap-1"
                >
                  <Plus className="h-3 w-3" />
                  Select All ({filteredResults.length})
                </button>
              </div>
            )}

            {/* Search Results */}
            <div className="max-h-80 overflow-y-auto space-y-1">
              {searchLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 animate-spin text-text-muted" />
                </div>
              ) : filteredResults.length > 0 ? (
                filteredResults.map(threat => (
                  <button
                    key={threat.signature_id}
                    onClick={() => addThreat(threat)}
                    className="w-full text-left flex items-center justify-between p-2 bg-bg-elevated hover:bg-bg-deep border border-border-dim group"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-text-normal truncate">{threat.threat_name}</div>
                      <div className="text-xs text-text-muted">
                        {threat.category} • {threat.signature_count} signature{threat.signature_count !== 1 ? 's' : ''}
                      </div>
                    </div>
                    <Plus className="h-4 w-4 text-text-muted group-hover:text-green-500 flex-shrink-0 ml-2" />
                  </button>
                ))
              ) : searchQuery.length >= 2 ? (
                <div className="text-center py-8 text-text-muted text-sm">
                  No threats found matching "{searchQuery}"
                </div>
              ) : (
                <div className="text-center py-8 text-text-muted text-sm">
                  Enter at least 2 characters to search
                </div>
              )}
            </div>
          </div>

          {/* Selected Threats */}
          <div className="bg-bg-surface border border-border-visible p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-text-bright">
                Selected Threats ({selectedThreats.size})
              </h2>
              {selectedThreats.size > 0 && (
                <button
                  onClick={clearAll}
                  className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1"
                >
                  <Trash2 className="h-3 w-3" />
                  Clear All
                </button>
              )}
            </div>

            {selectedThreats.size === 0 ? (
              <div className="text-center py-8 text-text-muted text-sm">
                No threats selected. Search and add threats above.
              </div>
            ) : (
              <div className="max-h-64 overflow-y-auto space-y-3">
                {Object.entries(selectedByCategory).map(([category, threats]) => (
                  <div key={category}>
                    <div className="text-xs text-amber uppercase tracking-wider mb-1">
                      {category} ({threats.length})
                    </div>
                    <div className="space-y-1">
                      {threats.map(threat => (
                        <div
                          key={threat.signature_id}
                          className="flex items-center justify-between p-2 bg-bg-elevated border border-amber/30"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="text-sm text-text-normal truncate">{threat.threat_name}</div>
                            <div className="text-xs text-text-muted font-mono">
                              0x{threat.signature_id.toString(16).toUpperCase().padStart(8, '0')}
                            </div>
                          </div>
                          <button
                            onClick={() => removeThreat(threat.signature_id)}
                            className="p-1 hover:bg-red-500/20 rounded"
                          >
                            <X className="h-4 w-4 text-red-400" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: Generate and Test */}
        <div className="space-y-4">
          {/* Generate */}
          <div className="bg-bg-surface border border-border-visible p-4">
            <h2 className="text-sm font-semibold text-text-bright mb-3">Generate YARA Rule</h2>

            <div className="space-y-2 mb-4">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  placeholder="Rule name"
                  className={`flex-1 px-3 py-2 bg-bg-elevated border text-text-normal text-sm placeholder:text-text-muted focus:outline-none font-mono ${
                    ruleNameError ? 'border-red-500 focus:border-red-500' : 'border-border-dim focus:border-amber'
                  }`}
                />
                <button
                  onClick={() => buildMutation.mutate()}
                  disabled={selectedThreats.size === 0 || buildMutation.isPending || !!ruleNameError || !ruleName}
                  className="px-4 py-2 bg-amber text-bg-deep font-medium text-sm hover:bg-amber-light disabled:opacity-50 flex items-center gap-2"
                >
                  {buildMutation.isPending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Building...
                    </>
                  ) : (
                    <>
                      <FileCode className="h-4 w-4" />
                      Build Rule
                    </>
                  )}
                </button>
              </div>
              {ruleNameError && (
                <p className="text-xs text-red-400">{ruleNameError}</p>
              )}
            </div>

            {/* Generated Rule */}
            {generatedRule && (
              <div>
                {/* Stats */}
                <div className="grid grid-cols-3 gap-2 mb-3">
                  <div className="bg-bg-elevated p-2 text-center">
                    <div className="text-lg font-bold text-text-bright">{generatedRule.threat_count}</div>
                    <div className="text-xs text-text-muted">Threats</div>
                  </div>
                  <div className="bg-bg-elevated p-2 text-center">
                    <div className="text-lg font-bold text-green-500">{generatedRule.string_patterns}</div>
                    <div className="text-xs text-text-muted">Strings</div>
                  </div>
                  <div className="bg-bg-elevated p-2 text-center">
                    <div className="text-lg font-bold text-blue-500">{generatedRule.binary_patterns}</div>
                    <div className="text-xs text-text-muted">Binary</div>
                  </div>
                </div>

                {/* Rule content */}
                <div className="relative">
                  <pre className="bg-bg-deep p-3 text-xs font-mono text-text-dim max-h-64 overflow-auto border border-border-dim">
                    {generatedRule.rule_content}
                  </pre>
                  <div className="absolute top-2 right-2 flex gap-1">
                    <button
                      onClick={handleCopy}
                      className="p-1.5 bg-bg-elevated hover:bg-bg-surface border border-border-dim"
                      title="Copy to clipboard"
                    >
                      {copied ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4 text-text-muted" />
                      )}
                    </button>
                    <button
                      onClick={handleDownload}
                      className="p-1.5 bg-bg-elevated hover:bg-bg-surface border border-border-dim"
                      title="Download .yar file"
                    >
                      <Download className="h-4 w-4 text-text-muted" />
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  )
}
