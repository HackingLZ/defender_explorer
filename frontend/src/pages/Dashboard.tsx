import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  FileCode,
  Shield,
  Clock,
  ArrowRight,
} from 'lucide-react'
import { getStats } from '../api/client'
import StatCard from '../components/StatCard'
import SearchInput from '../components/SearchInput'
import LoadingSpinner from '../components/LoadingSpinner'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

export default function Dashboard() {
  const [searchQuery, setSearchQuery] = useState('')
  const navigate = useNavigate()

  const { data: statsData, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: () => getStats(),
  })

  const handleSearch = () => {
    if (searchQuery.trim()) {
      navigate(`/threats?q=${encodeURIComponent(searchQuery)}`)
    }
  }

  if (isLoading) {
    return <LoadingSpinner />
  }

  const stats = statsData?.data

  return (
    <div>
      {/* Hero Section */}
      <div className="mb-10">
        <div className="flex items-center gap-3 mb-6">
          <span className="status-dot" />
          <span className="text-xs text-text-muted uppercase tracking-widest">
            Systems Operational
          </span>
        </div>
        <h1 className="font-display text-4xl lg:text-5xl font-bold text-text-bright leading-tight">
          Defender<br />
          <span className="text-amber">Explorer</span>
        </h1>
      </div>

      {/* Quick Search */}
      <div className="bg-bg-surface border border-border-visible p-6 mb-10 relative amber-bar-top">
        <h2 className="text-xs text-text-muted uppercase tracking-widest mb-4">
          Quick Search
        </h2>
        <div className="max-w-2xl">
          <SearchInput
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search threats by name (e.g., Cobalt, Mimikatz)..."
            onSubmit={handleSearch}
          />
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px bg-border-dim border border-border-dim mb-10">
        <StatCard
          title="Total Threats"
          value={stats?.threat_count || 0}
          icon={AlertTriangle}
          index={1}
        />
        <StatCard
          title="Signatures"
          value={stats?.signature_count || 0}
          icon={FileCode}
          index={2}
        />
        <StatCard
          title="ASR Rules"
          value={stats?.asr_rule_count || 0}
          icon={Shield}
          index={3}
        />
      </div>

      {/* Last Sync */}
      {stats?.last_sync && (
        <div className="bg-bg-surface border border-border-visible p-4 mb-10">
          <div className="flex items-center text-text-dim text-sm">
            <Clock className="h-4 w-4 mr-3 text-text-muted" />
            <span className="text-xs uppercase tracking-wider">
              Last synced: {new Date(stats.last_sync).toLocaleString()}
            </span>
          </div>
        </div>
      )}

      {/* Quick Links */}
      <div className="mb-6">
        <h2 className="text-xs text-text-muted uppercase tracking-widest mb-4 flex items-center gap-3">
          <span className="w-6 h-px bg-amber" />
          Quick Actions
        </h2>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-border-dim border border-border-dim">
        <Link
          to="/threats"
          className="bg-bg-surface p-6 hover:bg-bg-elevated transition-colors group feature-card"
        >
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-text-muted block mb-2">01</span>
              <h3 className="font-display text-lg font-semibold text-text-bright mb-1">
                Browse Threats
              </h3>
              <p className="text-sm text-text-dim">
                Explore all threat definitions
              </p>
            </div>
            <ArrowRight className="h-5 w-5 text-text-muted group-hover:text-amber transition-colors" />
          </div>
        </Link>

        <Link
          to="/asr"
          className="bg-bg-surface p-6 hover:bg-bg-elevated transition-colors group feature-card"
        >
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-text-muted block mb-2">02</span>
              <h3 className="font-display text-lg font-semibold text-text-bright mb-1">
                ASR Rules
              </h3>
              <p className="text-sm text-text-dim">
                Attack Surface Reduction rules
              </p>
            </div>
            <ArrowRight className="h-5 w-5 text-text-muted group-hover:text-amber transition-colors" />
          </div>
        </Link>

        <Link
          to="/yara-builder"
          className="bg-bg-surface p-6 hover:bg-bg-elevated transition-colors group feature-card"
        >
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-text-muted block mb-2">03</span>
              <h3 className="font-display text-lg font-semibold text-text-bright mb-1">
                YARA Builder
              </h3>
              <p className="text-sm text-text-dim">
                Build YARA rules
              </p>
            </div>
            <ArrowRight className="h-5 w-5 text-text-muted group-hover:text-amber transition-colors" />
          </div>
        </Link>
      </div>
    </div>
  )
}
