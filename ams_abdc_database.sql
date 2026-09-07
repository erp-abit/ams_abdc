-- AMS ABDC PostgreSQL bootstrap schema
-- Run this file once against the database configured by DB_NAME in .env.
-- The backend safely creates the remaining feature-specific tables on startup.

BEGIN;

CREATE SCHEMA IF NOT EXISTS public;
CREATE SCHEMA IF NOT EXISTS academics;
CREATE SCHEMA IF NOT EXISTS permission_management;
CREATE SCHEMA IF NOT EXISTS communication;
CREATE SCHEMA IF NOT EXISTS mentoring;
CREATE SCHEMA IF NOT EXISTS "ABDC_DB";

CREATE TABLE IF NOT EXISTS public.institutions (
  institution_id BIGSERIAL PRIMARY KEY,
  institution_code VARCHAR(30) NOT NULL UNIQUE,
  institution_name VARCHAR(200) NOT NULL,
  address_line1 TEXT,
  address_line2 TEXT,
  city VARCHAR(100), district VARCHAR(100), state VARCHAR(100),
  postal_code VARCHAR(20), phone VARCHAR(20), email VARCHAR(150), website TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.campuses (
  campus_id BIGSERIAL PRIMARY KEY,
  institution_id BIGINT NOT NULL REFERENCES public.institutions(institution_id) ON DELETE CASCADE,
  campus_code VARCHAR(30) NOT NULL,
  campus_name VARCHAR(150) NOT NULL,
  address TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (institution_id, campus_code)
);

CREATE TABLE IF NOT EXISTS public.designations (
  designation_id BIGSERIAL PRIMARY KEY,
  designation_code VARCHAR(30) UNIQUE,
  designation_name VARCHAR(150) NOT NULL UNIQUE,
  short_name VARCHAR(50),
  category VARCHAR(50),
  designation_type VARCHAR(30) NOT NULL DEFAULT 'TEACHING',
  designation_level INTEGER,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS public.departments (
  department_id BIGSERIAL PRIMARY KEY,
  institution_id BIGINT NOT NULL REFERENCES public.institutions(institution_id) ON DELETE CASCADE,
  department_code VARCHAR(30) NOT NULL,
  department_name VARCHAR(150) NOT NULL,
  department_alias VARCHAR(150),
  department_type VARCHAR(50),
  hod_employee_id BIGINT,
  official_email VARCHAR(150),
  phone VARCHAR(20),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (institution_id, department_code)
);

CREATE TABLE IF NOT EXISTS public.buildings (
  building_id BIGSERIAL PRIMARY KEY,
  campus_id BIGINT NOT NULL REFERENCES public.campuses(campus_id) ON DELETE CASCADE,
  building_code VARCHAR(30) NOT NULL,
  building_name VARCHAR(150) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (campus_id, building_code)
);

CREATE TABLE IF NOT EXISTS public.users (
  user_id BIGSERIAL PRIMARY KEY,
  username VARCHAR(80) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email VARCHAR(150) UNIQUE,
  mobile VARCHAR(20),
  display_name VARCHAR(150),
  full_name VARCHAR(150),
  user_type VARCHAR(30) NOT NULL,
  user_type_id BIGINT,
  employee_id BIGINT,
  student_id BIGINT,
  photo_path TEXT,
  user_status VARCHAR(20) DEFAULT 'Active',
  remarks TEXT,
  must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
  password_changed_at TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  failed_login_count INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by BIGINT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.employees (
  employee_id BIGSERIAL PRIMARY KEY,
  user_id BIGINT UNIQUE REFERENCES public.users(user_id) ON DELETE SET NULL,
  institution_id BIGINT NOT NULL REFERENCES public.institutions(institution_id),
  department_id BIGINT REFERENCES public.departments(department_id),
  designation_id BIGINT REFERENCES public.designations(designation_id),
  campus_id BIGINT REFERENCES public.campuses(campus_id),
  reporting_employee_id BIGINT REFERENCES public.employees(employee_id) ON DELETE SET NULL,
  employee_code VARCHAR(30) NOT NULL UNIQUE,
  first_name VARCHAR(100) NOT NULL,
  middle_name VARCHAR(100), last_name VARCHAR(100), gender VARCHAR(20),
  date_of_birth DATE, date_of_joining DATE, employment_type VARCHAR(40),
  employee_category VARCHAR(40), official_email VARCHAR(150) UNIQUE,
  personal_email VARCHAR(150), mobile VARCHAR(20), alternate_mobile VARCHAR(20),
  address TEXT, permanent_address TEXT, blood_group VARCHAR(10),
  marital_status VARCHAR(20), aadhaar_number VARCHAR(20), pan_number VARCHAR(20),
  photo_url TEXT, bank_name VARCHAR(150), bank_account_number VARCHAR(50),
  bank_ifsc VARCHAR(20), bank_branch VARCHAR(150),
  document_names JSONB NOT NULL DEFAULT '[]'::JSONB,
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.departments DROP CONSTRAINT IF EXISTS departments_hod_employee_fk;
ALTER TABLE public.departments ADD CONSTRAINT departments_hod_employee_fk
  FOREIGN KEY (hod_employee_id) REFERENCES public.employees(employee_id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS public.academic_years (
  academic_year_id BIGSERIAL PRIMARY KEY,
  institution_id BIGINT NOT NULL REFERENCES public.institutions(institution_id),
  year_label VARCHAR(30) NOT NULL,
  academic_year_name VARCHAR(120),
  start_date DATE NOT NULL, end_date DATE NOT NULL,
  admission_start_date DATE, admission_end_date DATE,
  is_current BOOLEAN NOT NULL DEFAULT FALSE,
  allow_data_entry BOOLEAN NOT NULL DEFAULT TRUE,
  allow_previous_year_edit BOOLEAN NOT NULL DEFAULT FALSE,
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (institution_id, year_label)
);

CREATE TABLE IF NOT EXISTS public.programmes (
  programme_id BIGSERIAL PRIMARY KEY,
  institution_id BIGINT NOT NULL REFERENCES public.institutions(institution_id),
  department_id BIGINT REFERENCES public.departments(department_id),
  programme_code VARCHAR(30) NOT NULL,
  programme_name VARCHAR(150) NOT NULL,
  programme_short_name VARCHAR(50),
  programme_level VARCHAR(50), programme_type VARCHAR(50),
  duration_years NUMERIC(4,1), duration_semesters INTEGER,
  intake_capacity INTEGER, status VARCHAR(20) DEFAULT 'ACTIVE',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (institution_id, programme_code)
);

CREATE TABLE IF NOT EXISTS public.admission_batches (
  batch_id BIGSERIAL PRIMARY KEY,
  programme_id BIGINT NOT NULL REFERENCES public.programmes(programme_id),
  academic_year_id BIGINT REFERENCES public.academic_years(academic_year_id),
  batch_code VARCHAR(40), batch_name VARCHAR(100),
  start_year INTEGER, end_year INTEGER, intake_capacity INTEGER,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (programme_id, batch_code)
);

CREATE TABLE IF NOT EXISTS public.semesters (
  semester_id BIGSERIAL PRIMARY KEY,
  programme_id BIGINT NOT NULL REFERENCES public.programmes(programme_id),
  semester_number INTEGER NOT NULL,
  semester_name VARCHAR(100),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (programme_id, semester_number)
);

CREATE TABLE IF NOT EXISTS public.academic_terms (
  term_id BIGSERIAL PRIMARY KEY,
  academic_year_id BIGINT NOT NULL REFERENCES public.academic_years(academic_year_id),
  term_name VARCHAR(100) NOT NULL, term_type VARCHAR(30),
  start_date DATE, end_date DATE, status VARCHAR(20) DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS public.section_masters (
  section_master_id BIGSERIAL PRIMARY KEY,
  section_master_code VARCHAR(30) UNIQUE,
  section_master_name VARCHAR(100) NOT NULL UNIQUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS public.sections (
  section_id BIGSERIAL PRIMARY KEY,
  batch_id BIGINT NOT NULL REFERENCES public.admission_batches(batch_id),
  semester_id BIGINT NOT NULL REFERENCES public.semesters(semester_id),
  term_id BIGINT REFERENCES public.academic_terms(term_id),
  section_master_id BIGINT REFERENCES public.section_masters(section_master_id),
  section_name VARCHAR(100) NOT NULL,
  strength_limit INTEGER DEFAULT 60,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS public.students (
  student_id BIGSERIAL PRIMARY KEY,
  user_id BIGINT UNIQUE REFERENCES public.users(user_id) ON DELETE SET NULL,
  institution_id BIGINT NOT NULL REFERENCES public.institutions(institution_id),
  academic_year_id BIGINT REFERENCES public.academic_years(academic_year_id),
  programme_id BIGINT NOT NULL REFERENCES public.programmes(programme_id),
  batch_id BIGINT REFERENCES public.admission_batches(batch_id),
  semester_id BIGINT REFERENCES public.semesters(semester_id),
  section_id BIGINT REFERENCES public.sections(section_id),
  student_code VARCHAR(40) UNIQUE,
  registration_number VARCHAR(50) UNIQUE,
  registration_no VARCHAR(50), roll_number VARCHAR(50),
  first_name VARCHAR(100) NOT NULL, middle_name VARCHAR(100), last_name VARCHAR(100),
  gender VARCHAR(20), date_of_birth DATE,
  email VARCHAR(150), mobile VARCHAR(20), mobile_number VARCHAR(20),
  profile_photo_url TEXT, photo_url TEXT, student_group VARCHAR(30),
  status VARCHAR(20) DEFAULT 'ACTIVE', is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.student_parents (
  student_parent_id BIGSERIAL PRIMARY KEY,
  student_id BIGINT NOT NULL REFERENCES public.students(student_id) ON DELETE CASCADE,
  father_name VARCHAR(150), mother_name VARCHAR(150), guardian_name VARCHAR(150),
  guardian_mobile VARCHAR(20), guardian_email VARCHAR(150)
);

CREATE TABLE IF NOT EXISTS public.student_addresses (
  student_address_id BIGSERIAL PRIMARY KEY,
  student_id BIGINT NOT NULL REFERENCES public.students(student_id) ON DELETE CASCADE,
  address_type VARCHAR(30) NOT NULL, address TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "ABDC_DB".user_logins (
  user_login_id BIGSERIAL PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name VARCHAR(150), email VARCHAR(150), role VARCHAR(50) NOT NULL DEFAULT 'USER',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS employees_institution_id_idx ON public.employees(institution_id);
CREATE INDEX IF NOT EXISTS employees_department_id_idx ON public.employees(department_id);
CREATE INDEX IF NOT EXISTS employees_status_idx ON public.employees(status);
CREATE INDEX IF NOT EXISTS students_programme_id_idx ON public.students(programme_id);
CREATE INDEX IF NOT EXISTS students_section_id_idx ON public.students(section_id);

COMMIT;
