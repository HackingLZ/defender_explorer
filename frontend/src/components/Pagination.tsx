import { ChevronLeft, ChevronRight } from 'lucide-react'
import { clsx } from 'clsx'

interface PaginationProps {
  page: number
  pages: number
  onPageChange: (page: number) => void
}

export default function Pagination({ page, pages, onPageChange }: PaginationProps) {
  if (pages <= 1) return null

  const getPageNumbers = () => {
    const pageNumbers: (number | string)[] = []
    const showPages = 5

    if (pages <= showPages) {
      for (let i = 1; i <= pages; i++) {
        pageNumbers.push(i)
      }
    } else {
      if (page <= 3) {
        for (let i = 1; i <= 4; i++) {
          pageNumbers.push(i)
        }
        pageNumbers.push('...')
        pageNumbers.push(pages)
      } else if (page >= pages - 2) {
        pageNumbers.push(1)
        pageNumbers.push('...')
        for (let i = pages - 3; i <= pages; i++) {
          pageNumbers.push(i)
        }
      } else {
        pageNumbers.push(1)
        pageNumbers.push('...')
        for (let i = page - 1; i <= page + 1; i++) {
          pageNumbers.push(i)
        }
        pageNumbers.push('...')
        pageNumbers.push(pages)
      }
    }

    return pageNumbers
  }

  return (
    <div className="flex items-center justify-center gap-1">
      <button
        onClick={() => onPageChange(page - 1)}
        disabled={page === 1}
        className={clsx(
          'p-2 border border-border-visible transition-colors',
          page === 1
            ? 'text-text-muted cursor-not-allowed opacity-50'
            : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
        )}
      >
        <ChevronLeft className="h-4 w-4" />
      </button>

      {getPageNumbers().map((pageNum, idx) =>
        typeof pageNum === 'number' ? (
          <button
            key={idx}
            onClick={() => onPageChange(pageNum)}
            className={clsx(
              'min-w-[36px] px-3 py-2 text-xs font-medium uppercase tracking-wider border transition-colors',
              pageNum === page
                ? 'bg-amber text-bg-deep border-amber'
                : 'text-text-dim border-border-visible hover:bg-bg-elevated hover:text-text-bright'
            )}
          >
            {pageNum}
          </button>
        ) : (
          <span key={idx} className="px-2 text-text-muted">
            {pageNum}
          </span>
        )
      )}

      <button
        onClick={() => onPageChange(page + 1)}
        disabled={page === pages}
        className={clsx(
          'p-2 border border-border-visible transition-colors',
          page === pages
            ? 'text-text-muted cursor-not-allowed opacity-50'
            : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright'
        )}
      >
        <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  )
}
