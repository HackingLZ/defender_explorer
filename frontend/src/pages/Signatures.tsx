import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import {
  Search,
  ChevronRight,
  ChevronDown,
  FileCode,
  Folder,
  FolderOpen,
  Hash,
  ExternalLink,
  PanelLeftOpen,
  X,
} from 'lucide-react'
import {
  getSignatureCategories,
  browseSignatures,
  searchSignatures,
  type CategoryCount,
  type SignatureBrowseResponse,
  type SignatureSearchResponse,
} from '../api/client'
import { type AxiosResponse } from 'axios'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import { useState, useMemo, useEffect } from 'react'

function CategoryIcon({ category }: { category: string }) {
  const topLevel = category.split('/')[0]
  switch (topLevel) {
    case 'PE':
      return <FileCode className="h-4 w-4 text-blue-500" />
    case 'Script':
      return <FileCode className="h-4 w-4 text-yellow-500" />
    case 'Persistence':
      return <Folder className="h-4 w-4 text-red-500" />
    case 'Network':
      return <ExternalLink className="h-4 w-4 text-green-500" />
    case 'Hash':
      return <Hash className="h-4 w-4 text-purple-500" />
    case 'Behavior':
      return <FileCode className="h-4 w-4 text-orange-500" />
    default:
      return <Folder className="h-4 w-4 text-text-muted" />
  }
}

function formatCount(count: number): string {
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`
  }
  if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`
  }
  return count.toString()
}

interface CategoryTreeProps {
  categories: CategoryCount[]
  selectedCategory: string | null
  selectedSubcategory: string | null
  onSelectCategory: (category: string | null, subcategory: string | null) => void
}

function CategoryTree({
  categories,
  selectedCategory,
  selectedSubcategory,
  onSelectCategory,
}: CategoryTreeProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(selectedCategory ? [selectedCategory.split('/')[0]] : [])
  )

  useEffect(() => {
    if (selectedCategory) {
      setExpandedCategories(previous => new Set([...previous, selectedCategory.split('/')[0]]))
    }
  }, [selectedCategory])

  // Group categories by top-level
  const groupedCategories = useMemo(() => {
    const groups: Record<string, CategoryCount[]> = {}
    categories.forEach((cat) => {
      const topLevel = cat.name.split('/')[0]
      if (!groups[topLevel]) {
        groups[topLevel] = []
      }
      groups[topLevel].push(cat)
    })
    return groups
  }, [categories])

  const toggleExpand = (topLevel: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev)
      if (next.has(topLevel)) {
        next.delete(topLevel)
      } else {
        next.add(topLevel)
      }
      return next
    })
  }

  return (
    <div className="space-y-1">
      {/* All Signatures option */}
      <button
        onClick={() => onSelectCategory(null, null)}
        className={`w-full flex items-center justify-between px-3 py-2 text-sm rounded-lg transition-colors ${
          !selectedCategory
            ? 'bg-amber/20 text-amber border border-amber/30'
            : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
        }`}
      >
        <span className="flex items-center">
          <Folder className="h-4 w-4 mr-2" />
          All Signatures
        </span>
      </button>

      {/* Category groups */}
      {Object.entries(groupedCategories).map(([topLevel, cats]) => {
        const isExpanded = expandedCategories.has(topLevel)
        const totalCount = cats.reduce((sum, c) => sum + c.count, 0)
        const isSelected = selectedCategory?.split('/')[0] === topLevel

        return (
          <div key={topLevel}>
            {/* Top-level category header */}
            <button
              onClick={() => toggleExpand(topLevel)}
              aria-expanded={isExpanded}
              className={`w-full flex items-center justify-between px-3 py-2 text-sm rounded-lg transition-colors ${
                isSelected
                  ? 'bg-bg-elevated text-text-bright'
                  : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
              }`}
            >
              <span className="flex items-center">
                {isExpanded ? (
                  <ChevronDown className="h-4 w-4 mr-1" />
                ) : (
                  <ChevronRight className="h-4 w-4 mr-1" />
                )}
                {isExpanded ? (
                  <FolderOpen className="h-4 w-4 mr-2 text-amber" />
                ) : (
                  <CategoryIcon category={topLevel} />
                )}
                {topLevel}
              </span>
              <span className="text-xs text-text-muted">{formatCount(totalCount)}</span>
            </button>

            {/* Subcategories */}
            {isExpanded && (
              <div className="ml-4 border-l border-border-dim pl-2 space-y-1 mt-1">
                {cats.map((cat) => {
                  const subName = cat.name.split('/')[1] || cat.name
                  const isSubSelected = selectedCategory === cat.name && !selectedSubcategory

                  return (
                    <div key={cat.name}>
                      <button
                        onClick={() => onSelectCategory(cat.name, null)}
                        aria-pressed={isSubSelected}
                        className={`w-full flex items-center justify-between px-3 py-1.5 text-sm rounded transition-colors ${
                          isSubSelected
                            ? 'bg-amber/20 text-amber'
                            : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
                        }`}
                      >
                        <span>{subName}</span>
                        <span className="text-xs text-text-muted">
                          {formatCount(cat.count)}
                        </span>
                      </button>

                      {/* Sub-subcategories if any */}
                      {cat.subcategories && cat.subcategories.length > 0 && selectedCategory === cat.name && (
                        <div className="ml-4 border-l border-border-dim pl-2 space-y-0.5 mt-1">
                          {cat.subcategories.map((sub) => (
                            <button
                              key={sub.name}
                              onClick={() => onSelectCategory(cat.name, sub.name)}
                              aria-pressed={selectedSubcategory === sub.name}
                              className={`w-full flex items-center justify-between px-2 py-1 text-xs rounded transition-colors ${
                                selectedSubcategory === sub.name
                                  ? 'bg-amber/20 text-amber'
                                  : 'text-text-muted hover:bg-bg-elevated hover:text-text-dim'
                              }`}
                            >
                              <span>{sub.name}</span>
                              <span className="text-text-muted">
                                {formatCount(sub.count)}
                              </span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

export default function Signatures() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [searchInput, setSearchInput] = useState(searchParams.get('q') || '')
  const [showMobileSidebar, setShowMobileSidebar] = useState(false)

  const searchQuery = (searchParams.get('q') || '').trim()
  const category = searchParams.get('category')
  const subcategory = searchParams.get('subcategory')
  const parsedPage = Number(searchParams.get('page') || '1')
  const page = Number.isSafeInteger(parsedPage) && parsedPage > 0 ? parsedPage : 1
  const invalidSearch = searchQuery.length > 0 && searchQuery.length < 2

  useEffect(() => { setSearchInput(searchQuery) }, [searchQuery])

  useEffect(() => {
    if (!showMobileSidebar) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setShowMobileSidebar(false)
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [showMobileSidebar])

  // Fetch categories
  const { data: categoriesData, isLoading: categoriesLoading, isError: categoriesError, refetch: retryCategories } = useQuery({
    queryKey: ['signature-categories'],
    queryFn: () => getSignatureCategories(),
  })

  // Fetch results - either search or browse
  const { data: resultsData, isLoading: resultsLoading, isFetching, isError: resultsError, refetch: retryResults } = useQuery<
    AxiosResponse<SignatureBrowseResponse | SignatureSearchResponse>
  >({
    queryKey: ['signatures', searchQuery, category, subcategory, page],
    queryFn: async () => {
      if (searchQuery) {
        return searchSignatures({ q: searchQuery, category: category || undefined, subcategory: subcategory || undefined, page })
      } else {
        return browseSignatures({
          category: category || undefined,
          subcategory: subcategory || undefined,
          page,
        })
      }
    },
    enabled: !invalidSearch,
  })

  const categories = categoriesData?.data?.categories || []
  const results = resultsData?.data

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchInput.trim()) {
      setSearchParams({ q: searchInput.trim(), ...(category && { category }), ...(subcategory && { subcategory }) })
    } else {
      // Clear search, keep category
      const params: Record<string, string> = {}
      if (category) params.category = category
      if (subcategory) params.subcategory = subcategory
      setSearchParams(params)
    }
  }

  const handleSelectCategory = (cat: string | null, subcat: string | null) => {
    const params: Record<string, string> = {}
    if (cat) params.category = cat
    if (subcat) params.subcategory = subcat
    if (searchQuery) params.q = searchQuery
    setSearchParams(params)
  }

  const handlePageChange = (newPage: number) => {
    const params: Record<string, string> = { page: newPage.toString() }
    if (searchQuery) params.q = searchQuery
    if (category) params.category = category
    if (subcategory) params.subcategory = subcategory
    setSearchParams(params)
  }

  const clearSearch = () => {
    setSearchInput('')
    const params: Record<string, string> = {}
    if (category) params.category = category
    if (subcategory) params.subcategory = subcategory
    setSearchParams(params)
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-text-bright">Signature Browser</h1>
        <p className="mt-2 text-text-dim">
          Browse and search {categoriesData ? `${formatCount(categoriesData.data.total)} signatures` : 'signatures'} by category
        </p>
      </div>

      {/* Search Bar */}
      <div className="bg-bg-surface rounded-xl border border-border-visible p-4 mb-6">
        <form onSubmit={handleSearch} className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[180px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
            <input
              type="text"
              aria-label="Search signature content"
              aria-describedby="signature-search-help"
              minLength={2}
              placeholder="Search signature content (e.g., powershell.exe, CurrentVersion\Run)..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-bg-elevated border border-border-dim rounded-lg text-text-normal placeholder:text-text-muted focus:outline-none focus:border-amber"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-amber text-bg-deep rounded-lg hover:bg-amber-bright transition-colors font-medium"
          >
            Search
          </button>
          {searchQuery && (
            <button
              type="button"
              onClick={clearSearch}
              className="px-4 py-2 border border-border-dim rounded-lg text-text-dim hover:text-text-bright hover:border-border-visible transition-colors"
            >
              Clear
            </button>
          )}
        </form>
        <p id="signature-search-help" className="mt-2 text-xs text-text-muted">Enter at least 2 characters. Search applies within the selected category and subcategory.</p>
      </div>

      <div className="flex gap-6 min-h-[calc(100vh-12rem)]">
        {/* Mobile sidebar overlay */}
        {showMobileSidebar && (
          <div
            className="fixed inset-0 bg-black/50 z-40 lg:hidden"
            onClick={() => setShowMobileSidebar(false)}
          />
        )}

        {/* Sidebar */}
        <div
          className={`
            fixed inset-y-0 left-0 z-50 w-72 bg-bg-deep transform transition-transform duration-200 lg:relative lg:transform-none lg:z-auto lg:bg-transparent
            ${showMobileSidebar ? 'translate-x-0 visible' : '-translate-x-full invisible lg:translate-x-0 lg:visible'}
            lg:w-64 lg:flex-shrink-0
          `}
        >
          <div className="bg-bg-surface rounded-xl border border-border-visible p-4 sticky top-24 h-full lg:h-auto">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-medium text-text-muted uppercase tracking-wider">
                Categories
              </h2>
              <button
                onClick={() => setShowMobileSidebar(false)}
                aria-label="Close signature categories"
                className="lg:hidden p-1 text-text-muted hover:text-text-bright"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="max-h-[calc(100vh-10rem)] overflow-y-auto">
              {categoriesLoading ? <LoadingSpinner /> : categoriesError ? (
                <div role="alert" className="text-sm text-red-400">
                  <p>Categories could not be loaded.</p>
                  <button onClick={() => retryCategories()} className="mt-2 underline">Retry categories</button>
                </div>
              ) : <CategoryTree
                categories={categories}
                selectedCategory={category}
                selectedSubcategory={subcategory}
                onSelectCategory={(cat, subcat) => {
                  handleSelectCategory(cat, subcat)
                  setShowMobileSidebar(false)
                }}
              />}
            </div>
          </div>
        </div>

        {/* Results */}
        <div className="flex-1 min-w-0">
          <div className="bg-bg-surface rounded-xl border border-border-visible overflow-hidden">
            {/* Results header */}
            <div className="px-4 sm:px-6 py-4 border-b border-border-dim flex flex-wrap justify-between items-center gap-2">
              <div className="flex flex-1 items-center gap-2 sm:gap-3 min-w-0">
                <button
                  onClick={() => setShowMobileSidebar(true)}
                  aria-label="Open signature categories"
                  aria-expanded={showMobileSidebar}
                  className="lg:hidden p-1.5 text-text-muted hover:text-text-bright border border-border-dim rounded flex-shrink-0"
                >
                  <PanelLeftOpen className="h-4 w-4" />
                </button>
                {searchQuery && (
                  <span className="text-sm text-text-bright break-all">
                    Results for "{searchQuery}"
                  </span>
                )}
                {category && !searchQuery && (
                  <span className="text-sm text-text-bright break-all">{category}</span>
                )}
                {subcategory && (
                  <span className="text-xs px-2 py-0.5 bg-amber/20 text-amber rounded break-all">
                    {subcategory}
                  </span>
                )}
              </div>
              <span className="w-full sm:w-auto shrink-0 text-sm text-text-muted" role="status">
                {resultsLoading ? 'Loading…' : resultsError || invalidSearch ? 'Results unavailable' : results ? `${results.total.toLocaleString()} ${results.total === 1 ? 'signature' : 'signatures'}` : ''}
              </span>
            </div>

            {/* Results list */}
            {invalidSearch ? (
              <div role="alert" className="p-8 text-center text-amber">Enter at least 2 characters to search signature content.</div>
            ) : resultsError ? (
              <div role="alert" className="p-8 text-center">
                <p className="text-red-400">Signatures could not be loaded. Please try again.</p>
                <button onClick={() => retryResults()} disabled={isFetching} className="mt-3 text-amber underline disabled:opacity-50">
                  {isFetching ? 'Retrying…' : 'Retry signatures'}
                </button>
              </div>
            ) : resultsLoading ? (
              <div className="p-8">
                <LoadingSpinner />
              </div>
            ) : results && results.items.length > 0 ? (
              <div className="divide-y divide-border-dim">
                {results.items.map((item: { id: number; sig_type_name: string | null; size?: number | null; preview: string | null; threat_id: number | null; threat_name: string | null }) => (
                  <Link
                    key={item.id}
                    to={`/signatures/${item.id}`}
                    state={{ from: `/signatures?${searchParams.toString()}` }}
                    className="flex items-start justify-between px-6 py-4 hover:bg-bg-elevated transition-colors group"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs px-2 py-0.5 bg-bg-elevated border border-border-dim rounded text-text-muted">
                          {item.sig_type_name || 'Unknown'}
                        </span>
                        {item.size && (
                          <span className="text-xs text-text-muted">
                            {item.size} bytes
                          </span>
                        )}
                      </div>
                      {item.preview && (
                        <p className="text-sm text-text-dim font-mono truncate mb-1 group-hover:text-text-normal">
                          {item.preview}
                        </p>
                      )}
                      {item.threat_name && (
                        <p className="text-xs text-amber truncate">
                          {item.threat_name}
                        </p>
                      )}
                    </div>
                    <ChevronRight className="h-5 w-5 text-text-muted flex-shrink-0 ml-4 group-hover:text-text-bright" />
                  </Link>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-text-muted">
                <p>{page > 1 ? 'No signatures on this page.' : searchQuery
                  ? 'No signatures found matching your search.'
                  : 'No signatures found in this selection.'}</p>
                {page > 1 ? (
                  <button onClick={() => handlePageChange(1)} className="mt-3 text-amber underline">Go to first page</button>
                ) : (searchQuery || category || subcategory) && (
                  <button onClick={() => setSearchParams({})} className="mt-3 text-amber underline">Clear search and filters</button>
                )}
              </div>
            )}

            {/* Pagination */}
            {!resultsError && !invalidSearch && results && results.items.length > 0 && results.pages > 1 && (
              <div className="px-6 py-4 border-t border-border-dim">
                <Pagination
                  page={results.page}
                  pages={results.pages}
                  onPageChange={handlePageChange}
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
