import { useState } from 'react'
import { Search, Filter, X, Plus, ChevronDown } from 'lucide-react'

export interface SearchFilter {
  field: string
  operator: 'contains' | 'equals' | 'starts_with' | 'ends_with' | 'not_contains'
  value: string
}

// Alias for simpler usage
export type FilterCondition = SearchFilter

export interface AdvancedSearchProps {
  query: string
  onQueryChange: (query: string) => void
  filters: SearchFilter[]
  onFiltersChange: (filters: SearchFilter[]) => void
  onSearch: () => void
  categories?: { category: string; count: number }[]
  families?: { family: string; count: number }[]
  signatureTypes?: string[]
  placeholder?: string
}

const OPERATORS = [
  { value: 'contains', label: 'contains' },
  { value: 'equals', label: 'equals' },
  { value: 'starts_with', label: 'starts with' },
  { value: 'ends_with', label: 'ends with' },
  { value: 'not_contains', label: 'does not contain' },
]

const FIELDS = [
  { value: 'threat_name', label: 'Threat Name' },
  { value: 'category', label: 'Category' },
  { value: 'family', label: 'Family' },
  { value: 'signature_type', label: 'Signature Type' },
]

export default function AdvancedSearch({
  query,
  onQueryChange,
  filters,
  onFiltersChange,
  onSearch,
  categories = [],
  families = [],
  signatureTypes = [],
  placeholder = 'Search threats...',
}: AdvancedSearchProps) {
  const [showFilters, setShowFilters] = useState(false)
  const [showQuickFilters, setShowQuickFilters] = useState(false)

  const addFilter = () => {
    onFiltersChange([...filters, { field: 'threat_name', operator: 'contains', value: '' }])
  }

  const updateFilter = (index: number, updates: Partial<SearchFilter>) => {
    const newFilters = [...filters]
    newFilters[index] = { ...newFilters[index], ...updates }
    onFiltersChange(newFilters)
  }

  const removeFilter = (index: number) => {
    onFiltersChange(filters.filter((_, i) => i !== index))
  }

  const clearAllFilters = () => {
    onFiltersChange([])
    onQueryChange('')
  }

  const addQuickFilter = (field: string, value: string) => {
    onFiltersChange([...filters, { field, operator: 'equals', value }])
    setShowQuickFilters(false)
  }

  const hasActiveFilters = filters.length > 0 || query.length > 0

  return (
    <div className="bg-bg-surface border border-border-visible p-4 space-y-4">
      {/* Main Search Bar */}
      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
          <input
            type="text"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && onSearch()}
            placeholder={placeholder}
            className="w-full pl-10 pr-4 py-2 bg-bg-elevated border border-border-dim text-text-normal text-sm placeholder:text-text-muted focus:outline-none focus:border-amber"
          />
        </div>

        {/* Filter Toggle */}
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`p-2 border rounded transition-colors ${
            showFilters || filters.length > 0
              ? 'bg-amber/20 border-amber text-amber'
              : 'border-border-dim text-text-muted hover:text-text-bright hover:border-border-visible'
          }`}
          title="Advanced Filters"
        >
          <Filter className="h-4 w-4" />
          {filters.length > 0 && (
            <span className="ml-1 text-xs">{filters.length}</span>
          )}
        </button>

        {/* Quick Filters Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowQuickFilters(!showQuickFilters)}
            className={`p-2 border rounded transition-colors flex items-center gap-1 ${
              showQuickFilters
                ? 'bg-amber/20 border-amber text-amber'
                : 'border-border-dim text-text-muted hover:text-text-bright hover:border-border-visible'
            }`}
            title="Quick Filters"
          >
            <Plus className="h-4 w-4" />
            <ChevronDown className="h-3 w-3" />
          </button>

          {showQuickFilters && (
            <div className="absolute right-0 top-full mt-2 w-64 bg-bg-surface border border-border-visible rounded-lg shadow-xl z-50 max-h-80 overflow-y-auto">
              {/* Categories */}
              {categories.length > 0 && (
                <div className="p-2 border-b border-border-dim">
                  <div className="text-xs text-text-muted uppercase tracking-wider mb-2 px-2">Categories</div>
                  <div className="space-y-1">
                    {categories.slice(0, 10).map((cat) => (
                      <button
                        key={cat.category}
                        onClick={() => addQuickFilter('category', cat.category)}
                        className="w-full flex items-center justify-between px-2 py-1.5 text-sm text-text-normal hover:bg-bg-elevated rounded"
                      >
                        <span className="truncate">{cat.category}</span>
                        <span className="text-xs text-text-muted">{cat.count}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Families */}
              {families.length > 0 && (
                <div className="p-2 border-b border-border-dim">
                  <div className="text-xs text-text-muted uppercase tracking-wider mb-2 px-2">Top Families</div>
                  <div className="space-y-1">
                    {families.slice(0, 10).map((fam) => (
                      <button
                        key={fam.family}
                        onClick={() => addQuickFilter('family', fam.family)}
                        className="w-full flex items-center justify-between px-2 py-1.5 text-sm text-text-normal hover:bg-bg-elevated rounded"
                      >
                        <span className="truncate">{fam.family}</span>
                        <span className="text-xs text-text-muted">{fam.count}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Signature Types */}
              {signatureTypes.length > 0 && (
                <div className="p-2">
                  <div className="text-xs text-text-muted uppercase tracking-wider mb-2 px-2">Signature Types</div>
                  <div className="space-y-1">
                    {signatureTypes.map((type) => (
                      <button
                        key={type}
                        onClick={() => addQuickFilter('signature_type', type)}
                        className="w-full text-left px-2 py-1.5 text-sm text-text-normal hover:bg-bg-elevated rounded truncate"
                      >
                        {type}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Search Button */}
        <button
          onClick={onSearch}
          className="px-4 py-2 bg-amber text-bg-deep font-medium text-sm hover:bg-amber-bright"
        >
          Search
        </button>
      </div>

      {/* Active Filters Display */}
      {hasActiveFilters && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-text-muted">Active filters:</span>
          {query && (
            <span className="inline-flex items-center gap-1 px-2 py-1 bg-amber/20 text-amber text-xs rounded">
              query: "{query}"
              <button onClick={() => onQueryChange('')} className="hover:text-amber-bright">
                <X className="h-3 w-3" />
              </button>
            </span>
          )}
          {filters.map((filter, index) => (
            <span
              key={index}
              className="inline-flex items-center gap-1 px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded"
            >
              {filter.field} {filter.operator} "{filter.value}"
              <button onClick={() => removeFilter(index)} className="hover:text-blue-300">
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
          <button
            onClick={clearAllFilters}
            className="text-xs text-text-muted hover:text-red-400"
          >
            Clear all
          </button>
        </div>
      )}

      {/* Advanced Filter Builder */}
      {showFilters && (
        <div className="border-t border-border-dim pt-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-text-bright">Filter Builder</span>
            <button
              onClick={addFilter}
              className="text-xs text-amber hover:text-amber-bright flex items-center gap-1"
            >
              <Plus className="h-3 w-3" />
              Add Condition
            </button>
          </div>

          {filters.length === 0 ? (
            <p className="text-sm text-text-muted">No filters added. Click "Add Condition" to create one.</p>
          ) : (
            <div className="space-y-2">
              {filters.map((filter, index) => (
                <div key={index} className="flex items-center gap-2">
                  {index > 0 && (
                    <span className="text-xs text-text-muted w-8">AND</span>
                  )}
                  {index === 0 && <span className="w-8" />}

                  {/* Field Select */}
                  <select
                    value={filter.field}
                    onChange={(e) => updateFilter(index, { field: e.target.value })}
                    className="px-2 py-1.5 bg-bg-elevated border border-border-dim text-text-normal text-sm focus:outline-none focus:border-amber"
                  >
                    {FIELDS.map((f) => (
                      <option key={f.value} value={f.value}>{f.label}</option>
                    ))}
                  </select>

                  {/* Operator Select */}
                  <select
                    value={filter.operator}
                    onChange={(e) => updateFilter(index, { operator: e.target.value as SearchFilter['operator'] })}
                    className="px-2 py-1.5 bg-bg-elevated border border-border-dim text-text-normal text-sm focus:outline-none focus:border-amber"
                  >
                    {OPERATORS.map((op) => (
                      <option key={op.value} value={op.value}>{op.label}</option>
                    ))}
                  </select>

                  {/* Value Input */}
                  <input
                    type="text"
                    value={filter.value}
                    onChange={(e) => updateFilter(index, { value: e.target.value })}
                    placeholder="Value..."
                    className="flex-1 px-2 py-1.5 bg-bg-elevated border border-border-dim text-text-normal text-sm placeholder:text-text-muted focus:outline-none focus:border-amber"
                  />

                  {/* Remove Button */}
                  <button
                    onClick={() => removeFilter(index)}
                    className="p-1.5 text-text-muted hover:text-red-400"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
