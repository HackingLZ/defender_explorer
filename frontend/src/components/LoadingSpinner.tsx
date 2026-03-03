export default function LoadingSpinner() {
  return (
    <div className="flex flex-col items-center justify-center py-16">
      <div className="w-8 h-8 border-2 border-amber border-t-transparent animate-spin mb-4" />
      <span className="text-xs text-text-muted uppercase tracking-widest">
        Loading...
      </span>
    </div>
  )
}
