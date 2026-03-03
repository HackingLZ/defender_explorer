import { Link, useLocation } from 'react-router-dom'
import { clsx } from 'clsx'
import {
  Shield,
  AlertTriangle,
  Home,
  Menu,
  X,
  FileCode,
  Binary,
} from 'lucide-react'
import { useState } from 'react'

const navigation = [
  { name: 'Dashboard', href: '/', icon: Home },
  { name: 'Threats', href: '/threats', icon: AlertTriangle },
  { name: 'Signatures', href: '/signatures', icon: Binary },
  { name: 'ASR Rules', href: '/asr', icon: Shield },
  { name: 'YARA Builder', href: '/yara-builder', icon: FileCode },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen bg-bg-deep noise-overlay scanlines">
      {/* Mobile menu button */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 bg-bg-surface border border-border-visible text-text-dim hover:text-text-bright"
      >
        {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </button>

      {/* Sidebar */}
      <div
        className={clsx(
          'fixed inset-y-0 left-0 w-64 bg-bg-surface border-r border-border-dim z-40 transform transition-transform duration-200 lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-6 border-b border-border-dim">
          <div className="w-8 h-8 border-2 border-amber flex items-center justify-center relative">
            <div className="w-2 h-2 bg-amber" style={{ boxShadow: '0 0 12px #f59e0b' }} />
          </div>
          <span className="ml-4 font-display text-sm font-bold text-text-bright uppercase tracking-wider">
            Defender Explorer
          </span>
        </div>

        {/* Navigation */}
        <nav className="mt-6 px-3">
          {navigation.map((item) => {
            const isActive =
              item.href === '/'
                ? location.pathname === '/'
                : location.pathname.startsWith(item.href)
            return (
              <Link
                key={item.name}
                to={item.href}
                onClick={() => setSidebarOpen(false)}
                className={clsx(
                  'flex items-center px-4 py-3 my-1 text-xs font-medium uppercase tracking-wider transition-all duration-200 relative',
                  isActive
                    ? 'bg-bg-elevated text-amber border-l-2 border-amber'
                    : 'text-text-dim hover:bg-bg-elevated hover:text-text-bright border-l-2 border-transparent'
                )}
              >
                <item.icon className="h-4 w-4 mr-3" />
                {item.name}
              </Link>
            )
          })}
        </nav>

        {/* Footer */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-border-dim">
          <div className="flex items-center gap-2 text-xs text-text-muted uppercase tracking-wider">
            <span className="status-dot" />
            <span>Systems Operational</span>
          </div>
        </div>
      </div>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <header className="h-16 bg-bg-surface/80 backdrop-blur-xl border-b border-border-dim sticky top-0 z-20">
          <div className="h-full px-8 flex items-center justify-between">
            <div className="lg:hidden w-8" /> {/* Spacer for mobile menu button */}
            <div className="hidden lg:block" />
            <div />
          </div>
        </header>

        {/* Page content */}
        <main className="p-6 lg:p-8">{children}</main>

        {/* Footer */}
        <footer className="border-t border-border-dim mt-auto">
          <div className="px-8 py-6 flex flex-col sm:flex-row justify-between items-center gap-4">
            <span className="text-xs text-text-muted uppercase tracking-wider">
              &copy; 2026 Defender Explorer
            </span>
            <span className="text-xs text-text-muted uppercase tracking-wider">
              Defender Definition Analysis
            </span>
          </div>
        </footer>
      </div>
    </div>
  )
}
