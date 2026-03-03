import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getSignature, getSingleSignatureDownloadUrl, getSingleSignatureYaraUrl } from '../api/client'
import LoadingSpinner from '../components/LoadingSpinner'
import { ArrowLeft, AlertTriangle, Hash, Download, FileText } from 'lucide-react'

export default function SignatureDetail() {
  const { signatureId } = useParams()
  const parsedId = signatureId ? Number(signatureId) : NaN

  const {
    data: sigData,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ['signature', parsedId],
    queryFn: () => getSignature(parsedId).then(r => r.data),
    enabled: !isNaN(parsedId),
  })

  if (isNaN(parsedId)) {
    return (
      <div className="p-6">
        <div className="bg-bg-surface border border-border-visible p-6 text-text-dim">
          Invalid signature ID.
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="p-8 flex justify-center">
        <LoadingSpinner />
      </div>
    )
  }

  if (isError || !sigData) {
    return (
      <div className="p-6">
        <div className="bg-bg-surface border border-border-visible p-6 text-text-dim">
          Failed to load signature.
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link
            to="/signatures"
            className="inline-flex items-center gap-2 text-text-dim hover:text-text-bright"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Signatures
          </Link>
        </div>
      </div>

      <div className="bg-bg-surface border border-border-visible p-6">
        <div className="flex items-start justify-between gap-6">
          <div>
            <h1 className="text-2xl font-bold text-text-bright">
              Signature #{sigData.id}
            </h1>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-text-dim">
              <span className="inline-flex items-center gap-1 bg-bg-elevated border border-border-dim px-2 py-0.5 rounded font-mono">
                {sigData.sig_type_name || `0x${sigData.sig_type.toString(16)}`}
              </span>
              {sigData.size != null && (
                <span>{sigData.size} bytes</span>
              )}
              {sigData.data_hash && (
                <span className="inline-flex items-center gap-1">
                  <Hash className="h-3.5 w-3.5" />
                  {sigData.data_hash.slice(0, 12)}...
                </span>
              )}
            </div>
          </div>

          {sigData.threat_signature_id ? (
            <Link
              to={`/threats/${sigData.threat_signature_id}`}
              className="text-xs px-3 py-1.5 bg-amber/10 text-amber border border-amber/30 rounded"
            >
              View Threat: {sigData.threat_name || sigData.threat_signature_id}
            </Link>
          ) : (
            <div className="text-xs px-3 py-1.5 bg-bg-elevated text-text-muted border border-border-dim rounded">
              Standalone signature
            </div>
          )}
        </div>
        {/* Download Buttons */}
        <div className="flex items-center gap-2 mt-4">
          <a
            href={getSingleSignatureDownloadUrl(sigData.id, 'hex')}
            className="inline-flex items-center gap-2 px-3 py-2 bg-bg-elevated border border-border-visible text-text-normal text-sm hover:bg-bg-surface transition-colors"
          >
            <Download className="h-4 w-4" />
            Hex
          </a>
          <a
            href={getSingleSignatureDownloadUrl(sigData.id, 'c')}
            className="inline-flex items-center gap-2 px-3 py-2 bg-bg-elevated border border-border-visible text-text-normal text-sm hover:bg-bg-surface transition-colors"
          >
            <FileText className="h-4 w-4" />
            C Array
          </a>
          <a
            href={getSingleSignatureYaraUrl(sigData.id)}
            className="inline-flex items-center gap-2 px-3 py-2 bg-amber text-bg-deep text-sm font-medium hover:bg-amber-light transition-colors"
          >
            <Download className="h-4 w-4" />
            YARA
          </a>
        </div>
      </div>

      <div className="bg-bg-surface border border-border-visible p-6">
        <h2 className="text-lg font-semibold text-text-bright mb-4">
          Signature Data
        </h2>

        {sigData.data_preview && (
          <div className="mb-4 p-3 bg-bg-elevated border border-border-dim">
            <div className="text-xs text-text-muted uppercase tracking-wider mb-2">Preview</div>
            <code className="text-sm text-green-400">{sigData.data_preview}</code>
          </div>
        )}

        {sigData.hex_dump ? (
          <pre className="code-block font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre">
{sigData.hex_dump}
          </pre>
        ) : (
          <div className="flex items-center gap-2 text-sm text-text-dim">
            <AlertTriangle className="h-4 w-4 text-amber" />
            No data available for this signature.
          </div>
        )}
      </div>
    </div>
  )
}
