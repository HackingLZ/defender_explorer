import { useState } from 'react'
import { Download, FileText, Table, FileCode, Loader2, Check, AlertCircle } from 'lucide-react'
import { api, Threat } from '../api/client'

export type ExportFormat = 'json' | 'csv' | 'yara'

interface BulkExportProps {
  threats: Threat[]
  selectedIds?: Set<number>
  onExportStart?: () => void
  onExportComplete?: () => void
}

interface ExportOption {
  format: ExportFormat
  label: string
  description: string
  icon: typeof FileText
}

const EXPORT_OPTIONS: ExportOption[] = [
  {
    format: 'json',
    label: 'JSON',
    description: 'Full threat data with signatures',
    icon: FileCode,
  },
  {
    format: 'csv',
    label: 'CSV',
    description: 'Spreadsheet-compatible format',
    icon: Table,
  },
  {
    format: 'yara',
    label: 'YARA Rules',
    description: 'Combined YARA rule file',
    icon: FileText,
  },
]

export default function BulkExport({ threats, selectedIds, onExportStart, onExportComplete }: BulkExportProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [selectedFormat, setSelectedFormat] = useState<ExportFormat>('json')
  const [includeSignatures, setIncludeSignatures] = useState(true)
  const [isExporting, setIsExporting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const threatsToExport = selectedIds && selectedIds.size > 0
    ? threats.filter(t => selectedIds.has(t.signature_id))
    : threats

  const exportJSON = async () => {
    const data = threatsToExport.map(t => ({
      signature_id: t.signature_id,
      threat_name: t.threat_name,
      category: t.category,
      family: t.family,
      signature_count: t.signature_count,
      created_at: t.created_at,
    }))

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    downloadBlob(blob, `threats-export-${Date.now()}.json`)
  }

  const exportCSV = async () => {
    const headers = ['Signature ID', 'Threat Name', 'Category', 'Family', 'Signature Count', 'Created At']
    const rows = threatsToExport.map(t => [
      t.signature_id,
      `"${t.threat_name.replace(/"/g, '""')}"`,
      t.category || '',
      t.family || '',
      t.signature_count,
      t.created_at,
    ])

    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    downloadBlob(blob, `threats-export-${Date.now()}.csv`)
  }

  const exportYARA = async () => {
    try {
      const response = await api.post('/yara/build', {
        threat_ids: threatsToExport.map(t => t.signature_id),
        rule_name: `bulk_export_${Date.now()}`,
      })

      const blob = new Blob([response.data.rule_content], { type: 'text/plain' })
      downloadBlob(blob, `threats-export-${Date.now()}.yar`)
    } catch (err) {
      throw new Error('Failed to generate YARA rules')
    }
  }

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleExport = async () => {
    setIsExporting(true)
    setError(null)
    setSuccess(false)
    onExportStart?.()

    try {
      switch (selectedFormat) {
        case 'json':
          await exportJSON()
          break
        case 'csv':
          await exportCSV()
          break
        case 'yara':
          await exportYARA()
          break
      }
      setSuccess(true)
      setTimeout(() => setSuccess(false), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed')
    } finally {
      setIsExporting(false)
      onExportComplete?.()
    }
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`inline-flex items-center gap-2 px-3 py-2 text-sm border rounded transition-colors ${
          isOpen
            ? 'bg-amber/20 border-amber text-amber'
            : 'border-border-dim text-text-dim hover:text-text-bright hover:border-border-visible'
        }`}
      >
        <Download className="h-4 w-4" />
        Export
        {selectedIds && selectedIds.size > 0 && (
          <span className="px-1.5 py-0.5 bg-amber text-bg-deep text-xs rounded-full">
            {selectedIds.size}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-bg-surface border border-border-visible rounded-lg shadow-xl z-50">
          <div className="p-4 border-b border-border-dim">
            <h3 className="text-sm font-semibold text-text-bright mb-1">Bulk Export</h3>
            <p className="text-xs text-text-muted">
              Export {threatsToExport.length} threat{threatsToExport.length !== 1 ? 's' : ''}
            </p>
          </div>

          <div className="p-4 space-y-4">
            {/* Format Selection */}
            <div>
              <label className="text-xs text-text-muted uppercase tracking-wider block mb-2">
                Format
              </label>
              <div className="space-y-2">
                {EXPORT_OPTIONS.map((option) => (
                  <button
                    key={option.format}
                    onClick={() => setSelectedFormat(option.format)}
                    className={`w-full flex items-center gap-3 p-3 rounded border transition-colors ${
                      selectedFormat === option.format
                        ? 'border-amber bg-amber/10'
                        : 'border-border-dim hover:border-border-visible'
                    }`}
                  >
                    <option.icon className={`h-5 w-5 ${
                      selectedFormat === option.format ? 'text-amber' : 'text-text-muted'
                    }`} />
                    <div className="text-left">
                      <div className={`text-sm font-medium ${
                        selectedFormat === option.format ? 'text-amber' : 'text-text-normal'
                      }`}>
                        {option.label}
                      </div>
                      <div className="text-xs text-text-muted">{option.description}</div>
                    </div>
                    {selectedFormat === option.format && (
                      <Check className="h-4 w-4 text-amber ml-auto" />
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Options */}
            {selectedFormat === 'json' && (
              <div className="flex items-center justify-between">
                <label className="text-sm text-text-normal">Include signatures</label>
                <button
                  onClick={() => setIncludeSignatures(!includeSignatures)}
                  className={`w-10 h-6 rounded-full transition-colors ${
                    includeSignatures ? 'bg-amber' : 'bg-bg-elevated'
                  }`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white transform transition-transform ${
                    includeSignatures ? 'translate-x-5' : 'translate-x-1'
                  }`} />
                </button>
              </div>
            )}

            {/* Error/Success Messages */}
            {error && (
              <div className="flex items-center gap-2 p-2 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
                <AlertCircle className="h-4 w-4" />
                {error}
              </div>
            )}
            {success && (
              <div className="flex items-center gap-2 p-2 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400">
                <Check className="h-4 w-4" />
                Export complete!
              </div>
            )}

            {/* Export Button */}
            <button
              onClick={handleExport}
              disabled={isExporting || threatsToExport.length === 0}
              className="w-full px-4 py-2 bg-amber text-bg-deep font-medium text-sm hover:bg-amber-bright disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isExporting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Exporting...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4" />
                  Export {selectedFormat.toUpperCase()}
                </>
              )}
            </button>
          </div>

          {/* Close Button */}
          <div className="px-4 py-2 border-t border-border-dim">
            <button
              onClick={() => setIsOpen(false)}
              className="text-xs text-text-muted hover:text-text-bright"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
