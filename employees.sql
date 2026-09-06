-- Core employee table required by the AMS backend.
-- This script is safe to run more than once.

CREATE SCHEMA IF NOT EXISTS public;

CREATE TABLE IF NOT EXISTS public.employees (
  employee_id BIGSERIAL PRIMARY KEY,
  user_id BIGINT UNIQUE,
  institution_id BIGINT NOT NULL,
  department_id BIGINT,
  designation_id BIGINT,
  campus_id BIGINT,
  reporting_employee_id BIGINT REFERENCES public.employees(employee_id) ON DELETE SET NULL,

  employee_code VARCHAR(30) NOT NULL UNIQUE,
  first_name VARCHAR(100) NOT NULL,
  middle_name VARCHAR(100),
  last_name VARCHAR(100),
  gender VARCHAR(20),
  date_of_birth DATE,
  date_of_joining DATE,
  employment_type VARCHAR(40),
  employee_category VARCHAR(40),

  official_email VARCHAR(150) UNIQUE,
  personal_email VARCHAR(150),
  mobile VARCHAR(20),
  alternate_mobile VARCHAR(20),
  address TEXT,
  permanent_address TEXT,
  blood_group VARCHAR(10),
  marital_status VARCHAR(20),
  aadhaar_number VARCHAR(20),
  pan_number VARCHAR(20),
  photo_url TEXT,

  bank_name VARCHAR(150),
  bank_account_number VARCHAR(50),
  bank_ifsc VARCHAR(20),
  bank_branch VARCHAR(150),
  document_names JSONB NOT NULL DEFAULT '[]'::JSONB,

  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS employees_institution_id_idx
  ON public.employees (institution_id);

CREATE INDEX IF NOT EXISTS employees_department_id_idx
  ON public.employees (department_id);

CREATE INDEX IF NOT EXISTS employees_designation_id_idx
  ON public.employees (designation_id);

CREATE INDEX IF NOT EXISTS employees_status_idx
  ON public.employees (status);

COMMENT ON TABLE public.employees IS 'Employee master records used by the AMS application.';
