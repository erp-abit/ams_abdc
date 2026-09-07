-- PostgreSQL timetable module matching the current server/index.js.
-- Prerequisites: public.users, academic_years, programmes, admission_batches,
-- semesters, sections, subject_masters; import the classroom module first.
-- Does not migrate the incompatible legacy src/abit_ims_academics_module.sql tables.
BEGIN;
CREATE SCHEMA IF NOT EXISTS academics;
DO $$
BEGIN
 IF to_regclass('academics.academic_periods') IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM information_schema.columns WHERE table_schema='academics'
   AND table_name='academic_periods' AND column_name='time_configuration_id'
 ) THEN
  RAISE EXCEPTION 'Legacy academics.academic_periods detected. Migrate the legacy academics schema before importing this module.';
 END IF;
 IF to_regclass('academics.timetable_headers') IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM information_schema.columns WHERE table_schema='academics'
   AND table_name='timetable_headers' AND column_name='time_configuration_id'
 ) THEN
  RAISE EXCEPTION 'Legacy academics.timetable_headers detected. Migrate the legacy academics schema before importing this module.';
 END IF;
END $$;
CREATE TABLE IF NOT EXISTS academics.week_days (
 week_day_id BIGSERIAL PRIMARY KEY, day_number INTEGER NOT NULL UNIQUE CHECK(day_number BETWEEN 1 AND 7),
 day_name VARCHAR(20) NOT NULL UNIQUE, is_active BOOLEAN NOT NULL DEFAULT TRUE
);
INSERT INTO academics.week_days(day_number,day_name) VALUES
 (1,'Monday'),(2,'Tuesday'),(3,'Wednesday'),(4,'Thursday'),(5,'Friday'),(6,'Saturday'),(7,'Sunday')
 ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS academics.academic_time_configurations (
 time_configuration_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES public.academic_years(academic_year_id),
 configuration_name VARCHAR(150) NOT NULL,
 college_start_time TIME NOT NULL, college_end_time TIME NOT NULL,
 teaching_period_minutes INTEGER NOT NULL CHECK(teaching_period_minutes > 0),
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 created_by BIGINT REFERENCES public.users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_by BIGINT REFERENCES public.users(user_id), updated_at TIMESTAMPTZ,
 UNIQUE(academic_year_id,configuration_name), CHECK(college_end_time > college_start_time)
);
CREATE TABLE IF NOT EXISTS academics.academic_time_configuration_days (
 time_configuration_id BIGINT NOT NULL REFERENCES academics.academic_time_configurations(time_configuration_id) ON DELETE CASCADE,
 week_day_id BIGINT NOT NULL REFERENCES academics.week_days(week_day_id),
 PRIMARY KEY(time_configuration_id,week_day_id)
);
CREATE TABLE IF NOT EXISTS academics.academic_breaks (
 academic_break_id BIGSERIAL PRIMARY KEY,
 time_configuration_id BIGINT NOT NULL REFERENCES academics.academic_time_configurations(time_configuration_id) ON DELETE CASCADE,
 break_name VARCHAR(100) NOT NULL, break_type VARCHAR(40) NOT NULL,
 start_time TIME NOT NULL, end_time TIME NOT NULL, display_order INTEGER NOT NULL,
 created_by BIGINT REFERENCES public.users(user_id), CHECK(end_time > start_time)
);
CREATE TABLE IF NOT EXISTS academics.academic_periods (
 period_id BIGSERIAL PRIMARY KEY,
 time_configuration_id BIGINT NOT NULL REFERENCES academics.academic_time_configurations(time_configuration_id) ON DELETE CASCADE,
 period_code VARCHAR(40) NOT NULL, period_name VARCHAR(100) NOT NULL,
 start_time TIME NOT NULL, end_time TIME NOT NULL,
 duration_minutes INTEGER NOT NULL CHECK(duration_minutes > 0),
 period_type VARCHAR(40) NOT NULL, display_order INTEGER NOT NULL,
 is_teaching_period BOOLEAN NOT NULL DEFAULT TRUE, is_active BOOLEAN NOT NULL DEFAULT TRUE,
 UNIQUE(time_configuration_id,period_code), CHECK(end_time > start_time)
);
CREATE TABLE IF NOT EXISTS academics.timetable_headers (
 timetable_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES public.academic_years(academic_year_id),
 programme_id BIGINT NOT NULL REFERENCES public.programmes(programme_id),
 programme_batch_id BIGINT NOT NULL REFERENCES public.admission_batches(batch_id),
 semester_id BIGINT NOT NULL REFERENCES public.semesters(semester_id),
 programme_section_id BIGINT NOT NULL REFERENCES public.sections(section_id),
 group_id BIGINT,
 time_configuration_id BIGINT NOT NULL REFERENCES academics.academic_time_configurations(time_configuration_id),
 timetable_name VARCHAR(200) NOT NULL, effective_from DATE NOT NULL, effective_to DATE,
 timetable_status VARCHAR(30) NOT NULL DEFAULT 'Draft', version_number INTEGER NOT NULL DEFAULT 1,
 remarks TEXT, created_by BIGINT REFERENCES public.users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_by BIGINT REFERENCES public.users(user_id), updated_at TIMESTAMPTZ,
 published_by BIGINT REFERENCES public.users(user_id), published_at TIMESTAMPTZ,
 CHECK(effective_to IS NULL OR effective_to >= effective_from),
 UNIQUE(academic_year_id,programme_batch_id,semester_id,programme_section_id,version_number)
);
CREATE TABLE IF NOT EXISTS academics.timetable_working_days (
 timetable_id BIGINT NOT NULL REFERENCES academics.timetable_headers(timetable_id) ON DELETE CASCADE,
 week_day_id BIGINT NOT NULL REFERENCES academics.week_days(week_day_id),
 is_working_day BOOLEAN NOT NULL DEFAULT TRUE, display_order INTEGER NOT NULL,
 PRIMARY KEY(timetable_id,week_day_id)
);
CREATE TABLE IF NOT EXISTS academics.timetable_entries (
 timetable_entry_id BIGSERIAL PRIMARY KEY,
 timetable_id BIGINT NOT NULL REFERENCES academics.timetable_headers(timetable_id) ON DELETE CASCADE,
 week_day_id BIGINT NOT NULL REFERENCES academics.week_days(week_day_id),
 period_id BIGINT NOT NULL REFERENCES academics.academic_periods(period_id),
 subject_id BIGINT REFERENCES public.subject_masters(subject_master_id),
 classroom_id BIGINT REFERENCES public.classrooms(classroom_id),
 entry_type VARCHAR(40) NOT NULL, display_text TEXT,
 created_by BIGINT REFERENCES public.users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(timetable_id,week_day_id,period_id)
);
CREATE TABLE IF NOT EXISTS academics.timetable_change_logs (
 timetable_change_log_id BIGSERIAL PRIMARY KEY,
 timetable_id BIGINT NOT NULL REFERENCES academics.timetable_headers(timetable_id) ON DELETE CASCADE,
 action_type VARCHAR(50) NOT NULL, old_value JSONB, new_value JSONB, change_reason TEXT,
 changed_by BIGINT REFERENCES public.users(user_id), changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMIT;
