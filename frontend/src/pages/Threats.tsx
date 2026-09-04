import { useState, useMemo, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  Folder,
  FolderOpen,
  FileText,
  Search,
  Filter,
  Calendar,
  CheckSquare,
  Square,
  PanelLeftOpen,
  X,
} from 'lucide-react'
import {
  getThreats,
  searchThreats,
  getCategories,
  getStats,
  browseFamilies,
  getActivity,
} from '../api/client'
import SearchInput from '../components/SearchInput'
import Pagination from '../components/Pagination'
import LoadingSpinner from '../components/LoadingSpinner'
import AdvancedSearch, { type SearchFilter } from '../components/AdvancedSearch'
import BulkExport from '../components/BulkExport'
import TimelineHeatmap from '../components/TimelineHeatmap'

export default function Threats() {
  const [searchParams, setSearchParams] = useSearchParams()
  const searchQuery = searchParams.get('q') || ''
  const parsedPage = parseInt(searchParams.get('page') || '1', 10)
  const page = isNaN(parsedPage) || parsedPage < 1 ? 1 : parsedPage
  const selectedCategory = searchParams.get('category') || ''
  const selectedFamily = searchParams.get('family') || ''
  const filtersParam = searchParams.get('filters') || ''
  const appliedFilters = useMemo<SearchFilter[]>(() => {
    try {
      const parsed: unknown = JSON.parse(filtersParam || '[]')
      return Array.isArray(parsed) ? parsed.filter((f): f is SearchFilter =>
        !!f && typeof f.field === 'string' && typeof f.operator === 'string' && typeof f.value === 'string'
      ).slice(0, 20) : []
    } catch { return [] }
  }, [filtersParam])
  const [draftQuery, setDraftQuery] = useState(searchQuery)
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    selectedCategory ? new Set([selectedCategory]) : new Set()
  )
  const [showAdvancedSearch, setShowAdvancedSearch] = useState(appliedFilters.length > 0)
  const [showHeatmap, setShowHeatmap] = useState(false)
  const [showMobileSidebar, setShowMobileSidebar] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [advancedFilters, setAdvancedFilters] = useState<SearchFilter[]>(appliedFilters)
  const [familyQuery, setFamilyQuery] = useState('')
  const [familyPage, setFamilyPage] = useState(1)
  const [selectedDate, setSelectedDate] = useState<string | null>(null)

  useEffect(() => { setDraftQuery(searchQuery) }, [searchQuery])
  useEffect(() => { setAdvancedFilters(appliedFilters) }, [appliedFilters])
  useEffect(() => {
    setExpandedCategories(selectedCategory ? new Set([selectedCategory]) : new Set())
    setFamilyPage(1)
    setFamilyQuery('')
  }, [selectedCategory])

  // Fetch categories
  const { data: statsData } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    staleTime: 60000,
  })
  const { data: categoriesData, isLoading: categoriesLoading, isError: categoriesError, refetch: retryCategories } = useQuery({
    queryKey: ['categories'],
    queryFn: () => getCategories(),
  })

  // Fetch families for expanded categories
  const { data: familiesData, isLoading: familiesLoading, isError: familiesError, refetch: retryFamilies } = useQuery({
    queryKey: ['families', selectedCategory, familyQuery, familyPage],
    queryFn: () => browseFamilies({ category: selectedCategory || undefined, q: familyQuery, page: familyPage, page_size: 25 }),
    enabled: !!selectedCategory,
  })

  // Fetch threats
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['threats', searchQuery, page, selectedCategory, selectedFamily, appliedFilters],
    queryFn: () =>
      searchQuery || appliedFilters.length
        ? searchThreats({ q: searchQuery, filters: JSON.stringify(appliedFilters), category: selectedCategory || undefined, family: selectedFamily || undefined, page, page_size: 50 })
        : getThreats({
            page,
            page_size: 50,
            category: selectedCategory || undefined,
            family: selectedFamily || undefined,
          }),
  })

  const handleSearch = () => {
    const params = new URLSearchParams(searchParams)
    params.delete('page')
    if (draftQuery.trim()) params.set('q', draftQuery.trim())
    else params.delete('q')
    setSearchParams(params)
  }

  const handlePageChange = (newPage: number) => {
    const params = new URLSearchParams(searchParams)
    params.set('page', newPage.toString())
    setSearchParams(params)
  }

  const toggleCategory = (category: string) => {
    const params = new URLSearchParams(searchParams)
    params.delete('page')
    params.delete('family')
    if (selectedCategory === category) params.delete('category')
    else params.set('category', category)
    setSearchParams(params)
  }

  const selectFamily = (family: string) => {
    const params = new URLSearchParams(searchParams)
    params.delete('page')
    params.set('family', family)
    setSearchParams(params)
  }

  const clearSelection = () => {
    setExpandedCategories(new Set())
    setDraftQuery('')
    setAdvancedFilters([])
    setSearchParams({})
  }

  const threats = data?.data
  const categories = categoriesData?.data || []
  const families = familiesData?.data.items || []
  const { data: activityData, isLoading: activityLoading, isError: activityError, refetch: retryActivity } = useQuery({
    queryKey: ['activity'], queryFn: getActivity, enabled: showHeatmap,
  })

  // Toggle selection for bulk export
  const toggleSelection = (id: number) => {
    const newSelected = new Set(selectedIds)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedIds(newSelected)
  }

  // Select/deselect all visible
  const toggleSelectAll = () => {
    if (!threats?.items) return
    const allIds = threats.items.map(t => t.signature_id)
    const allSelected = allIds.every(id => selectedIds.has(id))

    if (allSelected) {
      const newSelected = new Set(selectedIds)
      allIds.forEach(id => newSelected.delete(id))
      setSelectedIds(newSelected)
    } else {
      setSelectedIds(new Set([...selectedIds, ...allIds]))
    }
  }

  const handleAdvancedSearch = () => {
    const params = new URLSearchParams(searchParams)
    params.delete('page')
    if (draftQuery.trim()) params.set('q', draftQuery.trim())
    else params.delete('q')
    const filters = advancedFilters.filter(f => f.value.trim())
    if (filters.length) params.set('filters', JSON.stringify(filters))
    else params.delete('filters')
    setSearchParams(params)
  }

  // Build breadcrumb
  const breadcrumb = []
  if (selectedCategory) {
    breadcrumb.push(selectedCategory)
  }
  if (selectedFamily) {
    breadcrumb.push(selectedFamily)
  }

  return (
    <div className="flex gap-6 min-h-[calc(100vh-12rem)]">
      {/* Mobile sidebar overlay */}
      {showMobileSidebar && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setShowMobileSidebar(false)}
        />
      )}

      {/* Folder Tree Sidebar */}
      <div
        className={`
          fixed inset-y-0 left-0 z-50 w-72 bg-bg-deep transform transition-transform duration-200 lg:relative lg:transform-none lg:z-auto lg:bg-transparent
          ${showMobileSidebar ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          lg:flex-shrink-0
        `}
      >
        <div className="bg-bg-surface border border-border-visible sticky top-24 h-full lg:h-auto">
          <div className="px-4 py-3 border-b border-border-dim flex items-center justify-between">
            <h2 className="text-xs text-text-muted uppercase tracking-widest flex items-center gap-2">
              <Folder className="h-3.5 w-3.5" />
              Categories
            </h2>
            <button
              onClick={() => setShowMobileSidebar(false)}
              className="lg:hidden p-1 text-text-muted hover:text-text-bright"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="max-h-[calc(100vh-16rem)] overflow-y-auto">
            {categoriesLoading ? (
              <div className="p-4">
                <LoadingSpinner />
              </div>
            ) : categoriesError ? (
              <button onClick={() => retryCategories()} className="p-4 text-sm text-red-400">Categories unavailable. Retry</button>
            ) : (
              <div className="py-1">
                {/* Root - All Threats */}
                <button
                  onClick={clearSelection}
                  className={`w-full flex items-center gap-2 px-4 py-2 text-sm text-left transition-colors ${
                    !selectedCategory && !searchQuery
                      ? 'bg-bg-elevated text-amber'
                      : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
                  }`}
                >
                  <FolderOpen className="h-4 w-4 flex-shrink-0" />
                  <span className="truncate">All Threats</span>
                  <span className="ml-auto text-xs text-text-muted">
                    {statsData?.data.threat_count.toLocaleString() ?? '—'}
                  </span>
                </button>

                {/* Category Folders */}
                {categories.map((cat) => (
                  <div key={cat.category}>
                    <button
                      onClick={() => toggleCategory(cat.category)}
                      className={`w-full flex items-center gap-2 px-4 py-2 text-sm text-left transition-colors ${
                        selectedCategory === cat.category && !selectedFamily
                          ? 'bg-bg-elevated text-amber'
                          : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
                      }`}
                    >
                      {expandedCategories.has(cat.category) ? (
                        <ChevronDown className="h-3.5 w-3.5 flex-shrink-0" />
                      ) : (
                        <ChevronRight className="h-3.5 w-3.5 flex-shrink-0" />
                      )}
                      {expandedCategories.has(cat.category) ? (
                        <FolderOpen className="h-4 w-4 flex-shrink-0 text-amber" />
                      ) : (
                        <Folder className="h-4 w-4 flex-shrink-0" />
                      )}
                      <span className="truncate">{cat.category}</span>
                      <span className="ml-auto text-xs text-text-muted">
                        {cat.count.toLocaleString()}
                      </span>
                    </button>

                    {/* Expanded Families */}
                    {expandedCategories.has(cat.category) &&
                      selectedCategory === cat.category && (
                        <div className="bg-bg-deep">
                          <input
                            aria-label="Search families"
                            placeholder="Find a family..."
                            value={familyQuery}
                            onChange={e => { setFamilyQuery(e.target.value); setFamilyPage(1) }}
                            className="m-2 p-2 w-[calc(100%-1rem)] bg-bg-elevated border border-border-dim text-sm"
                          />
                          {familiesLoading ? (
                            <div className="pl-10 pr-4 py-2 text-xs text-text-muted">
                              Loading families...
                            </div>
                          ) : familiesError ? (
                            <button onClick={() => retryFamilies()} className="p-3 text-sm text-red-400">Families unavailable. Retry</button>
                          ) : families.length === 0 ? (
                            <p className="p-3 text-xs text-text-muted">No matching families</p>
                          ) : (
                            families.map((fam) => (
                              <button
                                key={fam.family}
                                onClick={() => selectFamily(fam.family)}
                                className={`w-full flex items-center gap-2 pl-10 pr-4 py-1.5 text-sm text-left transition-colors ${
                                  selectedFamily === fam.family
                                    ? 'bg-bg-elevated text-amber'
                                    : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
                                }`}
                              >
                                <FileText className="h-3.5 w-3.5 flex-shrink-0" />
                                <span className="truncate">{fam.family}</span>
                                <span className="ml-auto text-xs text-text-muted">
                                  {fam.count}
                                </span>
                              </button>
                            ))
                          )}
                          {familiesData && familiesData.data.pages > 1 && (
                            <div className="p-2 flex items-center justify-between gap-2 text-xs text-text-muted">
                              <button disabled={familyPage <= 1} onClick={() => setFamilyPage(familyPage - 1)} className="disabled:opacity-40">Previous</button>
                              <span>{familyPage} / {familiesData.data.pages}</span>
                              <button disabled={familyPage >= familiesData.data.pages} onClick={() => setFamilyPage(familyPage + 1)} className="disabled:opacity-40">Next</button>
                            </div>
                          )}
                        </div>
                      )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 min-w-0">
        {/* Header with Breadcrumb */}
        <div className="mb-6">
          <div className="flex items-center gap-2 text-sm text-text-muted mb-2">
            <button
              onClick={() => setShowMobileSidebar(true)}
              className="lg:hidden p-1 -ml-1 text-text-muted hover:text-amber transition-colors"
              title="Show categories"
            >
              <PanelLeftOpen className="h-4 w-4" />
            </button>
            <button
              onClick={clearSelection}
              className="hover:text-amber transition-colors"
            >
              Threats
            </button>
            {breadcrumb.map((item, i) => (
              <span key={i} className="flex items-center gap-2">
                <ChevronRight className="h-3.5 w-3.5" />
                <span className={i === breadcrumb.length - 1 ? 'text-text-bright' : ''}>
                  {item}
                </span>
              </span>
            ))}
          </div>
          <h1 className="font-display text-3xl font-bold text-text-bright">
            {selectedFamily || selectedCategory || 'All Threats'}
          </h1>
        </div>

        {/* Timeline Heatmap */}
        {showHeatmap && (
          <div className="mb-6">
            {activityLoading ? <LoadingSpinner /> : activityError ? (
              <button onClick={() => retryActivity()} className="text-red-400 text-sm">Activity unavailable. Retry</button>
            ) : !activityData?.data.tracked_since ? (
              <p className="p-4 border border-border-visible text-text-muted">Change history has not been recorded yet. Activity will appear after tracked imports.</p>
            ) : (
              <>
                <p className="mb-2 text-xs text-text-muted">Recorded definition changes since {new Date(activityData.data.tracked_since).toLocaleDateString()}. Earlier activity is unknown.</p>
                <TimelineHeatmap data={activityData.data.items} trackedSince={activityData.data.tracked_since} title="Recorded Definition Changes" onDateClick={setSelectedDate} />
                {selectedDate && <p className="mt-2 text-sm text-text-dim">{selectedDate}: {activityData.data.items.find(item => item.date === selectedDate)?.count ?? 0} recorded changes</p>}
              </>
            )}
          </div>
        )}

        {/* Search */}
        <div className="bg-bg-surface border border-border-visible p-4 mb-6 relative amber-bar-top">
          <div className="flex items-center gap-3">
            <Search className="h-4 w-4 text-text-muted" />
            <div className="flex-1">
              <SearchInput
                value={draftQuery}
                onChange={setDraftQuery}
                placeholder="Search threats by name..."
                onSubmit={handleSearch}
              />
            </div>
            {/* Advanced Search Toggle */}
            <button
              onClick={() => setShowAdvancedSearch(!showAdvancedSearch)}
              className={`p-2 border transition-colors ${
                showAdvancedSearch
                  ? 'bg-amber/20 border-amber text-amber'
                  : 'border-border-dim text-text-muted hover:text-text-bright hover:border-border-visible'
              }`}
              title="Advanced Search"
            >
              <Filter className="h-4 w-4" />
            </button>
            {/* Timeline Toggle */}
            <button
              onClick={() => setShowHeatmap(!showHeatmap)}
              className={`p-2 border transition-colors ${
                showHeatmap
                  ? 'bg-amber/20 border-amber text-amber'
                  : 'border-border-dim text-text-muted hover:text-text-bright hover:border-border-visible'
              }`}
              title="Show Timeline Heatmap"
            >
              <Calendar className="h-4 w-4" />
            </button>
          </div>
          {searchQuery && (
            <div className="mt-2 text-xs text-text-muted">
              {selectedCategory ? `Searching within ${selectedCategory}` : 'Searching across all categories'}
            </div>
          )}
        </div>

        {/* Advanced Search Panel */}
        {showAdvancedSearch && (
          <div className="mb-6">
            <AdvancedSearch
              query={draftQuery}
              onQueryChange={setDraftQuery}
              filters={advancedFilters}
              onFiltersChange={setAdvancedFilters}
              onSearch={handleAdvancedSearch}
              categories={categories}
              families={families}
            />
          </div>
        )}

        {/* Results */}
        {isLoading ? (
          <LoadingSpinner />
        ) : isError ? (
          <div role="alert" className="p-6 border border-red-500/30 text-red-400">
            <p>Unable to load threats. Check your filters and try again.</p>
            <button onClick={() => refetch()} className="mt-3 underline">Retry</button>
          </div>
        ) : (
          <>
            <div className="bg-bg-surface border border-border-visible">
              <div className="px-3 sm:px-6 py-4 border-b border-border-dim flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <button
                    onClick={toggleSelectAll}
                    className="p-1 text-text-muted hover:text-text-bright"
                    title={selectedIds.size > 0 ? 'Deselect all' : 'Select all'}
                  >
                    {threats?.items && threats.items.every(t => selectedIds.has(t.signature_id)) ? (
                      <CheckSquare className="h-4 w-4 text-amber" />
                    ) : (
                      <Square className="h-4 w-4" />
                    )}
                  </button>
                  <p className="text-xs text-text-muted uppercase tracking-wider">
                    {threats?.total.toLocaleString()} threats
                    {searchQuery && ` matching "${searchQuery}"`}
                    {selectedIds.size > 0 && ` (${selectedIds.size} selected)`}
                  </p>
                  {selectedIds.size > 0 && <button onClick={() => setSelectedIds(new Set())} className="text-xs text-amber">Clear selection</button>}
                </div>
                <BulkExport
                  threats={threats?.items || []}
                  selectedIds={selectedIds}
                />
              </div>
              <div className="divide-y divide-border-dim">
                {threats?.items.length === 0 ? (
                  <div className="px-6 py-12 text-center text-text-muted">
                    <AlertTriangle className="h-8 w-8 mx-auto mb-3 opacity-50" />
                    <p>No threats found</p>
                  </div>
                ) : (
                  threats?.items.map((threat) => (
                    <div
                      key={threat.id}
                      className="flex items-center px-3 sm:px-6 py-4 hover:bg-bg-elevated transition-colors group"
                    >
                      <button
                        onClick={(e) => {
                          e.preventDefault()
                          toggleSelection(threat.signature_id)
                        }}
                        className="mr-4 flex-shrink-0"
                      >
                        {selectedIds.has(threat.signature_id) ? (
                          <CheckSquare className="h-4 w-4 text-amber" />
                        ) : (
                          <Square className="h-4 w-4 text-text-muted group-hover:text-text-dim" />
                        )}
                      </button>
                      <Link
                        to={`/threats/${threat.signature_id}`}
                        className="flex-1 flex items-center justify-between min-w-0"
                      >
                        <div className="flex items-center min-w-0">
                          <AlertTriangle className="h-4 w-4 text-red-500 mr-4 flex-shrink-0" />
                          <div className="min-w-0">
                            <p className="font-medium text-text-bright group-hover:text-amber transition-colors truncate">
                              {threat.threat_name}
                            </p>
                            <div className="flex items-center mt-1 text-sm text-text-dim gap-3">
                              {threat.category && !selectedCategory && (
                                <span className="badge badge-amber">
                                  {threat.category}
                                </span>
                              )}
                              {threat.family && !selectedFamily && (
                                <span className="text-xs text-text-muted">
                                  {threat.family}
                                </span>
                              )}
                              <span className="text-xs">
                                {threat.signature_count} sig
                                {threat.signature_count !== 1 ? 's' : ''}
                              </span>
                            </div>
                          </div>
                        </div>
                        <ChevronRight className="h-4 w-4 text-text-muted group-hover:text-amber transition-colors flex-shrink-0" />
                      </Link>
                    </div>
                  ))
                )}
              </div>
            </div>

            {threats && threats.pages > 1 && (
              <div className="mt-6">
                <Pagination
                  page={page}
                  pages={threats.pages}
                  onPageChange={handlePageChange}
                />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
