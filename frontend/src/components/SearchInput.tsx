import { Search } from 'lucide-react'

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  onSubmit?: () => void
}

export default function SearchInput({
  value,
  onChange,
  placeholder = 'Search...',
  onSubmit,
}: SearchInputProps) {
  return (
    <div className="relative">
      <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && onSubmit) {
            onSubmit()
          }
        }}
        placeholder={placeholder}
        className="w-full pl-12 pr-4 py-3 bg-bg-elevated border border-border-visible text-text-normal placeholder-text-muted text-sm focus:ring-1 focus:ring-amber focus:border-amber transition-all"
      />
      {onSubmit && (
        <button
          onClick={onSubmit}
          className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-1.5 bg-amber text-bg-deep text-xs font-semibold uppercase tracking-wider hover:bg-amber-bright transition-colors"
        >
          Search
        </button>
      )}
    </div>
  )
}
