-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Threats table
CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    signature_id BIGINT UNIQUE NOT NULL,
    threat_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    family VARCHAR(100),
    signature_count INTEGER DEFAULT 0,
    content_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    search_vector TSVECTOR
);
CREATE INDEX IF NOT EXISTS idx_threats_search ON threats USING GIN(search_vector);
CREATE INDEX IF NOT EXISTS idx_threats_name_trgm ON threats USING GIN(threat_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_threats_signature_id ON threats(signature_id);
CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);
CREATE INDEX IF NOT EXISTS idx_threats_family ON threats(family);

-- Signatures table
CREATE TABLE IF NOT EXISTS signatures (
    id SERIAL PRIMARY KEY,
    threat_id INTEGER REFERENCES threats(id) ON DELETE CASCADE,
    sig_type INTEGER NOT NULL,
    sig_type_name VARCHAR(50),
    size INTEGER,
    data_hash VARCHAR(64),
    data BYTEA,
    category VARCHAR(50),
    subcategory VARCHAR(100),
    extracted_text TEXT
);
CREATE INDEX IF NOT EXISTS idx_signatures_threat_id ON signatures(threat_id);
CREATE INDEX IF NOT EXISTS idx_signatures_sig_type ON signatures(sig_type);
CREATE INDEX IF NOT EXISTS idx_signatures_data_hash ON signatures(data_hash);
CREATE INDEX IF NOT EXISTS idx_signatures_category ON signatures(category);
CREATE INDEX IF NOT EXISTS idx_signatures_subcategory ON signatures(subcategory);
CREATE INDEX IF NOT EXISTS idx_signatures_text_trgm ON signatures USING GIN(extracted_text gin_trgm_ops);

-- Lua scripts
CREATE TABLE IF NOT EXISTS lua_scripts (
    id SERIAL PRIMARY KEY,
    signature_id INTEGER REFERENCES signatures(id) ON DELETE CASCADE,
    threat_id INTEGER REFERENCES threats(id) ON DELETE CASCADE,
    bytecode_hash VARCHAR(64) UNIQUE,
    bytecode BYTEA,  -- Raw bytecode for lazy decompilation
    decompiled_source TEXT,
    decompilation_status VARCHAR(20) DEFAULT 'pending',  -- pending, completed, failed
    is_asr_script BOOLEAN DEFAULT FALSE,  -- Flag for ASR-related scripts
    asr_guids TEXT[],
    mitre_techniques TEXT[]
);
CREATE INDEX IF NOT EXISTS idx_lua_scripts_threat_id ON lua_scripts(threat_id);
CREATE INDEX IF NOT EXISTS idx_lua_scripts_bytecode_hash ON lua_scripts(bytecode_hash);
CREATE INDEX IF NOT EXISTS idx_lua_scripts_asr_guids ON lua_scripts USING GIN(asr_guids);
CREATE INDEX IF NOT EXISTS idx_lua_scripts_decompilation_status ON lua_scripts(decompilation_status);
CREATE INDEX IF NOT EXISTS idx_lua_scripts_is_asr ON lua_scripts(is_asr_script) WHERE is_asr_script = TRUE;

-- Hashes
CREATE TABLE IF NOT EXISTS hashes (
    id SERIAL PRIMARY KEY,
    hash_type VARCHAR(20) NOT NULL,
    hash_value VARCHAR(128) NOT NULL,
    is_friendly BOOLEAN DEFAULT FALSE,
    threat_ids INTEGER[],
    UNIQUE(hash_type, hash_value)
);
CREATE INDEX IF NOT EXISTS idx_hashes_value ON hashes(hash_value);
CREATE INDEX IF NOT EXISTS idx_hashes_type ON hashes(hash_type);
CREATE INDEX IF NOT EXISTS idx_hashes_friendly ON hashes(is_friendly);

-- IOCs
CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    threat_ids INTEGER[],
    UNIQUE(ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs USING GIN(value gin_trgm_ops);

-- ASR Rules
CREATE TABLE IF NOT EXISTS asr_rules (
    guid VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255),
    short_name VARCHAR(50),
    description TEXT,
    script_count INTEGER DEFAULT 0,
    extracted_data JSONB DEFAULT '{}'::jsonb
);

-- Function Definitions (for cross-script function resolution)
CREATE TABLE IF NOT EXISTS function_definitions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    source_script VARCHAR(512),
    body TEXT,
    data_entries TEXT[],
    entry_count INTEGER DEFAULT 0,
    category VARCHAR(50) DEFAULT 'unknown',
    is_mapped VARCHAR(1) DEFAULT 'N',
    mapped_field VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    vdm_version VARCHAR(50)
);
CREATE INDEX IF NOT EXISTS idx_function_definitions_name ON function_definitions(name);
CREATE INDEX IF NOT EXISTS idx_function_definitions_category ON function_definitions(category);

-- VDM Versions (for delta tracking)
CREATE TABLE IF NOT EXISTS vdm_versions (
    id SERIAL PRIMARY KEY,
    version_hash VARCHAR(64) UNIQUE,
    download_timestamp TIMESTAMP DEFAULT NOW(),
    threat_count INTEGER,
    signature_count INTEGER,
    is_current BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_vdm_versions_current ON vdm_versions(is_current);

-- Sync status tracking
CREATE TABLE IF NOT EXISTS sync_status (
    id SERIAL PRIMARY KEY,
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'running',
    threats_added INTEGER DEFAULT 0,
    threats_updated INTEGER DEFAULT 0,
    threats_removed INTEGER DEFAULT 0,
    error_message TEXT
);

-- Function to update search vector
CREATE OR REPLACE FUNCTION update_threat_search_vector()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        COALESCE(NEW.threat_name, '') || ' ' ||
        COALESCE(NEW.category, '') || ' ' ||
        COALESCE(NEW.family, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for search vector
DROP TRIGGER IF EXISTS threat_search_vector_update ON threats;
CREATE TRIGGER threat_search_vector_update
    BEFORE INSERT OR UPDATE ON threats
    FOR EACH ROW
    EXECUTE FUNCTION update_threat_search_vector();
