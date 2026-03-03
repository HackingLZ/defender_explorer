import { useState, useMemo } from 'react'
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
  getFamilies,
} from '../api/client'
import SearchInput from '../components/SearchInput'
import Pagination from '../components/Pagination'
import LoadingSpinner from '../components/LoadingSpinner'
import AdvancedSearch, { type SearchFilter } from '../components/AdvancedSearch'
import BulkExport from '../components/BulkExport'
import TimelineHeatmap from '../components/TimelineHeatmap'

export default function Threats() {
  const [searchParams, setSearchParams] = useSearchParams()
  const initialQuery = searchParams.get('q') || ''
  const parsedPage = parseInt(searchParams.get('page') || '1', 10)
  const initialPage = isNaN(parsedPage) || parsedPage < 1 ? 1 : parsedPage
  const initialCategory = searchParams.get('category') || ''
  const initialFamily = searchParams.get('family') || ''

  const [searchQuery, setSearchQuery] = useState(initialQuery)
  const [page, setPage] = useState(initialPage)
  const [selectedCategory, setSelectedCategory] = useState(initialCategory)
  const [selectedFamily, setSelectedFamily] = useState(initialFamily)
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    initialCategory ? new Set([initialCategory]) : new Set()
  )
  const [showAdvancedSearch, setShowAdvancedSearch] = useState(false)
  const [showHeatmap, setShowHeatmap] = useState(false)
  const [showMobileSidebar, setShowMobileSidebar] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [advancedFilters, setAdvancedFilters] = useState<SearchFilter[]>([])

  // Fetch categories
  const { data: categoriesData, isLoading: categoriesLoading } = useQuery({
    queryKey: ['categories'],
    queryFn: () => getCategories(),
  })

  // Fetch families for expanded categories
  const { data: familiesData } = useQuery({
    queryKey: ['families', selectedCategory],
    queryFn: () => getFamilies(selectedCategory || undefined),
    enabled: !!selectedCategory,
  })

  // Fetch threats
  const { data, isLoading } = useQuery({
    queryKey: ['threats', searchQuery, page, selectedCategory, selectedFamily],
    queryFn: () =>
      searchQuery
        ? searchThreats({ q: searchQuery, page, page_size: 50 })
        : getThreats({
            page,
            page_size: 50,
            category: selectedCategory || undefined,
            family: selectedFamily || undefined,
          }),
  })

  const handleSearch = () => {
    setPage(1)
    setSelectedCategory('')
    setSelectedFamily('')
    setExpandedCategories(new Set())
    setSearchParams({
      ...(searchQuery && { q: searchQuery }),
    })
  }

  const handlePageChange = (newPage: number) => {
    setPage(newPage)
    setSearchParams({
      ...(searchQuery && { q: searchQuery }),
      ...(selectedCategory && { category: selectedCategory }),
      ...(selectedFamily && { family: selectedFamily }),
      page: newPage.toString(),
    })
  }

  const toggleCategory = (category: string) => {
    const newExpanded = new Set(expandedCategories)
    if (newExpanded.has(category)) {
      newExpanded.delete(category)
      if (selectedCategory === category) {
        setSelectedCategory('')
        setSelectedFamily('')
        setSearchParams({})
      }
    } else {
      newExpanded.add(category)
      setSelectedCategory(category)
      setSelectedFamily('')
      setPage(1)
      setSearchQuery('')
      setSearchParams({ category })
    }
    setExpandedCategories(newExpanded)
  }

  const selectFamily = (family: string) => {
    setSelectedFamily(family)
    setPage(1)
    setSearchQuery('')
    setSearchParams({
      category: selectedCategory,
      family,
    })
  }

  const clearSelection = () => {
    setSelectedCategory('')
    setSelectedFamily('')
    setExpandedCategories(new Set())
    setSearchQuery('')
    setPage(1)
    setSearchParams({})
  }

  const threats = data?.data
  const categories = categoriesData?.data || []
  const families = familiesData?.data || []

  // Placeholder heatmap data — no real timeline API exists yet
  const heatmapData = useMemo(() => {
    const data: { date: string; count: number }[] = []
    const today = new Date()
    for (let i = 364; i >= 0; i--) {
      const date = new Date(today)
      date.setDate(date.getDate() - i)
      data.push({ date: date.toISOString().split('T')[0], count: 0 })
    }
    return data
  }, [])

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
    // Build query from filters
    const searchParts: string[] = []
    advancedFilters.forEach(f => {
      if (f.field === 'threat_name' && f.value) {
        searchParts.push(f.value)
      }
    })
    const newQuery = searchParts.join(' ')
    setSearchQuery(newQuery)
    setPage(1)
    setSelectedCategory('')
    setSelectedFamily('')
    setExpandedCategories(new Set())
    setSearchParams({
      ...(newQuery && { q: newQuery }),
    })
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
                    {categories.reduce((sum, c) => sum + c.count, 0).toLocaleString()}
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
                          {families.length === 0 ? (
                            <div className="pl-10 pr-4 py-2 text-xs text-text-muted">
                              Loading families...
                            </div>
                          ) : (
                            families.slice(0, 50).map((fam) => (
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
                          {families.length > 50 && (
                            <div className="pl-10 pr-4 py-2 text-xs text-text-muted italic">
                              +{families.length - 50} more families
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
            <TimelineHeatmap
              data={heatmapData}
              title="Threat Activity"
              onDateClick={(date) => {
                console.log('Selected date:', date)
              }}
            />
          </div>
        )}

        {/* Search */}
        <div className="bg-bg-surface border border-border-visible p-4 mb-6 relative amber-bar-top">
          <div className="flex items-center gap-3">
            <Search className="h-4 w-4 text-text-muted" />
            <div className="flex-1">
              <SearchInput
                value={searchQuery}
                onChange={setSearchQuery}
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
              Searching across all categories
            </div>
          )}
        </div>

        {/* Advanced Search Panel */}
        {showAdvancedSearch && (
          <div className="mb-6">
            <AdvancedSearch
              query={searchQuery}
              onQueryChange={setSearchQuery}
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
