"""Transactional, metadata-only change recording for all import paths."""

from sqlalchemy import text


async def install_history_tracking(conn):
    await conn.execute(text("ALTER TABLE entity_history ADD COLUMN IF NOT EXISTS vdm_version_hash VARCHAR(64)"))
    await conn.execute(text("""
        CREATE OR REPLACE FUNCTION record_explorer_change() RETURNS TRIGGER AS $$
        DECLARE
            before_data JSONB := '{}'::jsonb;
            after_data JSONB := '{}'::jsonb;
            row_data JSONB;
            entity_kind TEXT;
            entity_key TEXT;
            version_hash TEXT := NULLIF(current_setting('app.vdm_version_hash', true), '');
        BEGIN
            IF TG_OP <> 'INSERT' THEN before_data := to_jsonb(OLD); END IF;
            IF TG_OP <> 'DELETE' THEN after_data := to_jsonb(NEW); END IF;
            row_data := CASE WHEN TG_OP = 'DELETE' THEN before_data ELSE after_data END;
            IF TG_TABLE_NAME = 'threats' THEN
                entity_kind := 'threat';
                entity_key := row_data->>'signature_id';
                before_data := before_data - ARRAY['id', 'created_at', 'updated_at', 'search_vector'];
                after_data := after_data - ARRAY['id', 'created_at', 'updated_at', 'search_vector'];
            ELSE
                entity_kind := 'asr_rule';
                entity_key := row_data->>'guid';
                -- Retain metadata and a fingerprint, not repeated large extracted payloads.
                IF before_data <> '{}'::jsonb THEN
                    before_data := (before_data - 'extracted_data') || jsonb_build_object(
                        'extracted_data_hash', md5(COALESCE((before_data->'extracted_data')::text, '{}')));
                END IF;
                IF after_data <> '{}'::jsonb THEN
                    after_data := (after_data - 'extracted_data') || jsonb_build_object(
                        'extracted_data_hash', md5(COALESCE((after_data->'extracted_data')::text, '{}')));
                END IF;
            END IF;
            IF before_data IS DISTINCT FROM after_data THEN
                INSERT INTO entity_history
                    (entity_type, entity_id, change_type, changed_at, previous_data, current_data,
                     diff_summary, vdm_version_hash)
                VALUES (entity_kind, entity_key,
                    CASE TG_OP WHEN 'INSERT' THEN 'created' WHEN 'DELETE' THEN 'deleted' ELSE 'updated' END,
                    timezone('UTC', clock_timestamp()), before_data, after_data,
                    CASE TG_OP WHEN 'INSERT' THEN 'Entity created' WHEN 'DELETE' THEN 'Entity deleted'
                        ELSE 'Definition metadata changed' END, version_hash);
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql
    """))
    for table in ("threats", "asr_rules"):
        # Table names are constants, never request input.
        await conn.execute(text(f"DROP TRIGGER IF EXISTS explorer_history ON {table}"))
        await conn.execute(text(f"""
            CREATE TRIGGER explorer_history AFTER INSERT OR UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION record_explorer_change()
        """))
    await conn.execute(text("""
        INSERT INTO app_settings (key, value)
        VALUES ('history_tracked_since', to_char(timezone('UTC', clock_timestamp()),
                'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        ON CONFLICT (key) DO NOTHING
    """))
