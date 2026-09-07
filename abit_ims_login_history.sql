-- PostgreSQL login history for the current AMS backend.
-- Prerequisite: public.users(user_id). Uses the database selected in .env.
-- Re-running preserves existing records; this is not a legacy-schema migration.
BEGIN;

CREATE TABLE IF NOT EXISTS public.login_history (
    login_history_id BIGSERIAL PRIMARY KEY,
    -- Unknown usernames can generate failed attempts without a user record.
    user_id BIGINT REFERENCES public.users(user_id) ON DELETE SET NULL,
    username TEXT NOT NULL,
    login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logout_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    browser_name VARCHAR(100),
    operating_system VARCHAR(100),
    device_type VARCHAR(50),
    -- SHA-256 digest only; never store the raw session token here.
    session_token_hash VARCHAR(64),
    login_status VARCHAR(30) NOT NULL,
    login_success BOOLEAN NOT NULL,
    failure_reason TEXT,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logout_type VARCHAR(30)
);

CREATE INDEX IF NOT EXISTS login_history_login_at_idx
    ON public.login_history (login_at DESC);
CREATE INDEX IF NOT EXISTS login_history_user_id_idx
    ON public.login_history (user_id);

COMMIT;
