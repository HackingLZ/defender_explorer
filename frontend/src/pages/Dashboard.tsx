import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  FileCode,
  Shield,
  Clock,
  ArrowRight,
} from 'lucide-react'
import { getStats, getServiceStatus } from '../api/client'
import StatCard from '../components/StatCard'
import SearchInput from '../components/SearchInput'
import LoadingSpinner from '../components/LoadingSpinner'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

export default function Dashboard() {
  const [searchQuery, setSearchQuery] = useState('')
  const navigate = useNavigate()

  const { data: statusData, isError: statusError, refetch: retryStatus } = useQuery({
    queryKey: ['service-status'],
    queryFn: getServiceStatus,
    refetchInterval: query => ['running', 'initializing'].includes(query.state.data?.data.status || '') ? 5000 : 60000,
  })
  const status = statusData?.data
  const syncing = status?.status === 'running' || status?.status === 'initializing'
  const { data: statsData, isLoading, isError: statsError, refetch: retryStats } = useQuery({
    queryKey: ['stats'],
    queryFn: () => getStats(),
    refetchInterval: syncing ? 30000 : 60000,
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
  const lastSync = status?.last_sync || stats?.last_sync
  const stale = !!lastSync && Date.now() - new Date(lastSync).getTime() > 48 * 60 * 60 * 1000
  const statusLabel = statusError || statsError ? 'Service status unavailable'
    : !status ? 'Checking service status'
    : status.status === 'initializing' ? 'Preparing initial definitions'
    : status.status === 'running' ? 'Syncing definitions'
    : status.status === 'failed' ? 'Last definition sync failed'
    : stale ? 'Definitions need attention' : 'Definitions ready'

  return (
    <div>
      {/* Hero Section */}
      <div className="mb-10">
        <div className="flex items-center gap-3 mb-6">
          <span className={`h-2 w-2 rounded-full ${statusError || statsError || status?.status === 'failed' ? 'bg-red-500' : syncing || stale || !status ? 'bg-amber' : 'bg-green-500'}`} />
          <span className="text-xs text-text-muted uppercase tracking-widest">
            {statusLabel}
          </span>
        </div>
        <h1 className="font-display text-4xl lg:text-5xl font-bold text-text-bright leading-tight">
          Defender<br />
          <span className="text-amber">Explorer</span>
        </h1>
      </div>

      {(statsError || statusError) && (
        <div role="alert" className="p-4 mb-6 border border-red-500/30 text-red-400 text-sm">
          <p>Some service data could not be loaded. Displayed values may be out of date.</p>
          <button onClick={() => { retryStats(); retryStatus() }} className="mt-2 underline">Retry</button>
        </div>
      )}
      {syncing && (
        <div role="status" className="p-4 mb-6 border border-border-visible text-text-dim text-sm">
          <p>{status?.status === 'initializing' ? 'Initial definitions are not ready yet.' : 'A definition update is in progress.'} This page refreshes automatically.</p>
          {status?.sync_started_at && <p className="mt-1">Started {new Date(status.sync_started_at).toLocaleString()}</p>}
          <p className="mt-1">{status?.threats_added ?? 0} added · {status?.threats_updated ?? 0} updated · {status?.threats_removed ?? 0} removed</p>
        </div>
      )}
      {status?.status === 'failed' && <p role="alert" className="mb-6 text-sm text-red-400">The last update did not complete. Existing definitions may still be browsed; an administrator should check the sync logs.</p>}
      {stale && <p className="mb-6 text-sm text-amber">The last successful sync was over 48 hours ago.</p>}

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
          value={stats?.threat_count ?? 'Unavailable'}
          icon={AlertTriangle}
          index={1}
        />
        <StatCard
          title="Signatures"
          value={stats?.signature_count ?? 'Unavailable'}
          icon={FileCode}
          index={2}
        />
        <StatCard
          title="ASR Rules"
          value={stats?.asr_rule_count ?? 'Unavailable'}
          icon={Shield}
          index={3}
        />
      </div>

      {/* Last Sync */}
      {lastSync && (
        <div className="bg-bg-surface border border-border-visible p-4 mb-10">
          <div className="flex items-center text-text-dim text-sm">
            <Clock className="h-4 w-4 mr-3 text-text-muted" />
            <span className="text-xs uppercase tracking-wider">
              Last synced: {new Date(lastSync).toLocaleString()}
            </span>
          </div>
        </div>
      )}
      {status?.current_version && <p className="mb-6 text-xs text-text-muted break-all">Current definition version: {status.current_version}</p>}

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
