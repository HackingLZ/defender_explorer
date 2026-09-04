import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || ''

export const api = axios.create({
  baseURL: `${API_URL}/api`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface Stats {
  threat_count: number
  signature_count: number
  lua_script_count: number
  asr_rule_count: number
  last_sync: string | null
}

export interface Threat {
  id: number
  signature_id: number
  threat_name: string
  category: string | null
  family: string | null
  signature_count: number
  created_at: string
  updated_at: string
}

export interface ThreatDetail extends Threat {
  signatures: SignatureSummary[]
  lua_scripts: LuaScriptSummary[]
  signature_types: Record<string, number>
}

export interface SignatureSummary {
  id: number
  sig_type: number
  sig_type_name: string | null
  size: number | null
}

export interface SignatureDetail extends SignatureSummary {
  threat_id: number | null
  threat_name: string | null
  threat_signature_id: number | null
  data_hash: string | null
  data_hex: string | null
  data_preview: string | null
  hex_dump: string | null
}

export interface LuaScriptSummary {
  id: number
  bytecode_hash: string | null
  asr_guids: string[]
  has_source: boolean
}

export interface LuaScript {
  id: number
  signature_id: number | null
  threat_id: number | null
  bytecode_hash: string | null
  asr_guids: string[]
  mitre_techniques: string[]
  has_source: boolean
  decompiled_source: string | null
  threat_name: string | null
}

export interface ExtractedPatterns {
  exclusion_paths: string[]
  detection_paths: string[]
  process_names: string[]
  file_extensions: string[]
  mitre_techniques: string[]
  registry_keys: string[]
  native_functions: string[]
  related_asr_guids: string[]
  domains: string[]
  command_patterns: string[]
  vulnerable_drivers: string[]
  // RMM tool detection data (from IsRmmTool* functions)
  rmm_file_paths?: string[]
  rmm_version_info?: string[]
  rmm_original_filenames?: string[]
}

export interface ASRRule {
  guid: string
  name: string | null
  short_name: string | null
  description: string | null
  script_count: number
  extracted_data?: ExtractedPatterns | null
}

export interface ASRScriptSummary {
  id: number
  threat_id: number | null
  threat_name: string | null
  bytecode_hash: string | null
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  pages: number
}

// API functions
export const getStats = () => api.get<Stats>('/stats')

export const getThreats = (params: {
  page?: number
  page_size?: number
  category?: string
  family?: string
}) => api.get<PaginatedResponse<Threat>>('/threats', { params })

export const searchThreats = (params: {
  q?: string
  filters?: string
  category?: string
  family?: string
  page?: number
  page_size?: number
}) => api.get<PaginatedResponse<Threat>>('/threats/search', { params })

export const getThreat = (sigId: number) =>
  api.get<ThreatDetail>(`/threats/${sigId}`)

export interface ClassifiedSignatures {
  threat_name: string
  signature_id: number
  total: number
  string_signatures: {
    id: number
    sig_type: number
    sig_type_name: string | null
    size: number | null
    classification: string
    is_string: boolean
    content: string
  }[]
  binary_signatures: {
    id: number
    sig_type: number
    sig_type_name: string | null
    size: number | null
    classification: string
    is_string: boolean
    extracted_strings: string[]
  }[]
  string_count: number
  binary_count: number
}

export const getClassifiedSignatures = (sigId: number) =>
  api.get<ClassifiedSignatures>(`/threats/${sigId}/signatures/classified`)

export const getSignatureDownloadUrl = (sigId: number, format: 'hex' | 'c' | 'raw' = 'hex') =>
  `${API_URL}/api/threats/${sigId}/signatures/download?format=${format}`

export const getYaraDownloadUrl = (sigId: number) =>
  `${API_URL}/api/threats/${sigId}/signatures/yara`

export const getSingleSignatureDownloadUrl = (signatureId: number, format: 'hex' | 'c' | 'raw' = 'hex') =>
  `${API_URL}/api/signatures/${signatureId}/download?format=${format}`

export const getSingleSignatureYaraUrl = (signatureId: number) =>
  `${API_URL}/api/signatures/${signatureId}/yara`

export const getCategories = () =>
  api.get<{ category: string; count: number }[]>('/threats/categories/list')

export const browseFamilies = (params: { category?: string; q?: string; page?: number; page_size?: number }) =>
  api.get<PaginatedResponse<{ family: string; count: number }>>('/threats/families/list', { params })

export const exportThreats = (threatIds: number[], includeSignatures: boolean) =>
  api.post<{ items: (Threat & { signatures?: unknown[] })[] }>('/threats/export', {
    threat_ids: threatIds,
    include_signatures: includeSignatures,
  })

export interface ServiceStatus {
  status: 'initializing' | 'running' | 'failed' | 'ready'
  last_sync: string | null
  current_version: string | null
  sync_started_at: string | null
  threats_added: number
  threats_updated: number
  threats_removed: number
}

export const getServiceStatus = () => api.get<ServiceStatus>('/status')
export const getActivity = () => api.get<{ items: { date: string; count: number }[]; tracked_since: string | null }>('/activity', { params: { days: 365 } })

export const getLuaScript = (id: number) => api.get<LuaScript>(`/lua/${id}`)

export const getSignature = (id: number) => api.get<SignatureDetail>(`/signatures/${id}`)

export const getASRRules = () => api.get<ASRRule[]>('/asr')

export const getASRRule = (guid: string) => api.get<ASRRule>(`/asr/${guid}`)

export const getASRScripts = (guid: string) =>
  api.get<ASRScriptSummary[]>(`/asr/${guid}/scripts`)

export interface ASRRuleLogic {
  rule_name: string | null
  rule_guid: string
  short_name: string | null
  script_count: number
  script_breakdown: { config: number; detection: number; helper: number }
  entry_points: string[]
  trigger_types: string[]
  functions: { name: string; params: string; description: string | null; is_config?: boolean; is_entry_point?: boolean }[]
  checks: string[]
  outcomes: string[]
  telemetry_attributes: string[]
  mitre_techniques: string[]
  referenced_asr_rules: { guid: string; name: string }[]
  api_calls: { api: string; description: string }[]
  flow: string[]
  confidence_notes: string[]
  patterns: {
    exclusion_paths: string[]
    detection_paths: string[]
    process_names: string[]
    command_patterns: string[]
    file_extensions: string[]
    mitre_techniques: string[]
    registry_keys: string[]
    native_functions: string[]
    vulnerable_drivers: string[]
    rmm_file_paths: string[]
    rmm_version_info: string[]
    rmm_original_filenames: string[]
  }
}

export const getASRRuleLogic = (guid: string) =>
  api.get<ASRRuleLogic>(`/asr/${guid}/logic`)

// ============= New Types for Explorer Features =============

// Signature Analysis Types
export interface SignatureRegion {
  type: string
  offset: number
  length: number
  value: string
  description: string
  color: string
}

export interface SignatureAnalysis {
  signature_id: number
  size: number
  data_hash: string
  hex_preview: string
  entropy: number
  regions: SignatureRegion[]
  magic_bytes: {
    offset: number
    signature: string
    signature_text: string
    meaning: string
    length: number
  }[]
  strings: {
    string: string
    offset: number
    length: number
    context_before: string
    context_after: string
    classification: string
  }[]
  patterns: {
    offset: number
    pattern: string
    pattern_hex: string
    type: string
    description: string
    length: number
  }[]
  hex_dump?: {
    offset: number
    offset_hex: string
    bytes: { byte: number | null; hex: string }[]
    ascii: string
  }[]
  sig_type?: number
  sig_type_name?: string | null
}

export interface ThreatAnalysis {
  threat_id: number
  signature_id: number
  threat_name: string
  category: string | null
  family: string | null
  signatures: SignatureAnalysis[]
  total_size: number
  unique_strings: number
  detected_patterns: string[]
}

// Related Threats Types
export interface RelatedThreat {
  threat_id: number
  signature_id: number
  threat_name: string
  category: string | null
  family: string | null
  similarity_score: number
  similarity_types: string[]
  shared_strings: string[]
  matching_bytes: number
}

export interface RelatedThreatsResponse {
  threat_id: number
  signature_id: number
  threat_name: string
  related: RelatedThreat[]
  total: number
}

// Timeline Types
export interface TimelineEvent {
  date: string | null
  type: string
  vdm_version: string | null
  changes: string[]
  details?: {
    previous_data?: Record<string, unknown>
    current_data?: Record<string, unknown>
  } | null
}

export interface TimelineResponse {
  entity_type: string
  entity_id: string
  events: TimelineEvent[]
  total_events: number
  message?: string
}

// ASR Flowchart Types
export interface FlowchartNode {
  id: string
  type: string
  data: {
    label: string
    description?: string
    expandable?: boolean
    details?: Record<string, unknown>
  }
  position: { x: number; y: number }
  style?: Record<string, string | number>
}

export interface FlowchartEdge {
  id: string
  source: string
  target: string
  label?: string
  style?: Record<string, string>
}

export interface ASRFlowchart {
  rule_guid: string
  rule_name: string | null
  nodes: FlowchartNode[]
  edges: FlowchartEdge[]
}

// Related ASR Rules
export interface RelatedASRRule {
  rule_guid: string
  rule_name: string | null
  short_name: string | null
  shared_exclusions: string[]
  shared_processes: string[]
  total_shared: number
}


// ============= New API Functions =============

// Threat Analysis
export const getThreatAnalysis = (sigId: number) =>
  api.get<ThreatAnalysis>(`/threats/${sigId}/analysis`)

export const getRelatedThreats = (sigId: number, limit = 20) =>
  api.get<RelatedThreatsResponse>(`/threats/${sigId}/related`, { params: { limit } })

export const getThreatTimeline = (sigId: number, limit = 50) =>
  api.get<TimelineResponse>(`/threats/${sigId}/timeline`, { params: { limit } })

export const getThreatReportUrl = (sigId: number, format: 'html' | 'pdf' = 'html') =>
  `${API_URL}/api/threats/${sigId}/report?format=${format}`

// ASR Enhancements
export const getASRFlowchart = (guid: string) =>
  api.get<ASRFlowchart>(`/asr/${guid}/flowchart`)

export const getASRRelatedRules = (guid: string) =>
  api.get<{ rule_guid: string; rule_name: string | null; related_rules: RelatedASRRule[]; total: number }>(`/asr/${guid}/related-rules`)

export const getASRTimeline = (guid: string, limit = 50) =>
  api.get<TimelineResponse>(`/asr/${guid}/timeline`, { params: { limit } })

export const getASRReportUrl = (guid: string, format: 'html' | 'pdf' = 'html') =>
  `${API_URL}/api/asr/${guid}/report?format=${format}`

// YARA Building

export interface YaraBuildResult {
  rule_name: string
  rule_content: string
  threat_count: number
  pattern_count: number
  string_patterns: number
  binary_patterns: number
  threats: { id: number; name: string }[]
  categories: string[]
  families: string[]
  pattern_map: Record<string, string[]>  // var_name -> threat names
}

export const buildCombinedYaraRule = (threatIds: number[], ruleName: string = 'combined_detection') => {
  return api.post<YaraBuildResult>('/yara/build', {
    threat_ids: threatIds,
    rule_name: ruleName,
  })
}

// ============= Signature Browser Types =============

export interface SubcategoryCount {
  name: string
  count: number
}

export interface CategoryCount {
  name: string
  count: number
  subcategories?: SubcategoryCount[] | null
}

export interface CategoriesResponse {
  categories: CategoryCount[]
  total: number
}

export interface SignatureBrowseItem {
  id: number
  sig_type_name: string | null
  size: number | null
  preview: string | null
  threat_id: number | null
  threat_name: string | null
  category: string | null
  subcategory: string | null
}

export interface SignatureBrowseResponse {
  items: SignatureBrowseItem[]
  total: number
  page: number
  pages: number
}

export interface SignatureSearchItem {
  id: number
  sig_type_name: string | null
  size?: number | null
  preview: string | null
  match_highlight: string | null
  threat_id: number | null
  threat_name: string | null
  category: string | null
  subcategory?: string | null
}

export interface SignatureSearchResponse {
  items: SignatureSearchItem[]
  total: number
  query: string
  page: number
  pages: number
}

// ============= Signature Browser API =============

export const getSignatureCategories = () =>
  api.get<CategoriesResponse>('/signatures/categories')

export const browseSignatures = (params: {
  category?: string
  subcategory?: string
  page?: number
  page_size?: number
}) => api.get<SignatureBrowseResponse>('/signatures/browse', { params })

export const searchSignatures = (params: {
  q: string
  category?: string
  page?: number
  page_size?: number
}) => api.get<SignatureSearchResponse>('/signatures/search', { params })
