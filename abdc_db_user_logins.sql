BEGIN;

CREATE SCHEMA IF NOT EXISTS "ABDC_DB";

CREATE TABLE IF NOT EXISTS "ABDC_DB".user_logins (
  user_id BIGSERIAL PRIMARY KEY,
  login_id VARCHAR(100) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  user_type VARCHAR(20) NOT NULL
    CHECK (user_type IN ('SUPER_ADMIN', 'ADMIN', 'SUB_ADMIN', 'USER')),
  employee_id BIGINT,
  student_id BIGINT,
  display_name VARCHAR(150),
  photo_path TEXT,
  account_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
    CHECK (account_status IN ('ACTIVE', 'INACTIVE', 'LOCKED')),
  force_password_change BOOLEAN NOT NULL DEFAULT TRUE,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  last_login_at TIMESTAMP,
  created_by BIGINT
    REFERENCES "ABDC_DB".user_logins(user_id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP,
  CONSTRAINT chk_login_person
    CHECK (NOT (employee_id IS NOT NULL AND student_id IS NOT NULL))
);

COMMIT;
