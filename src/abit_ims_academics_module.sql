-- ABIT IMS - ACADEMICS MODULE (PostgreSQL)
-- Assumes existing master tables: users, students, employees, academic_years,
-- programme_batches, semesters, programme_sections, section_groups, subjects,
-- departments and campus_rooms.

BEGIN;
CREATE SCHEMA IF NOT EXISTS academics;

CREATE TABLE IF NOT EXISTS academics.academic_periods (
 academic_period_id BIGSERIAL PRIMARY KEY,
 period_name VARCHAR(50) NOT NULL,
 period_order INT NOT NULL CHECK(period_order>0),
 start_time TIME NOT NULL,
 end_time TIME NOT NULL,
 is_break BOOLEAN NOT NULL DEFAULT FALSE,
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 UNIQUE(period_order), CHECK(end_time>start_time)
);

CREATE TABLE IF NOT EXISTS academics.attendance_sessions (
 attendance_session_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
 programme_batch_id BIGINT NOT NULL REFERENCES programme_batches(programme_batch_id),
 semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
 programme_section_id BIGINT NOT NULL REFERENCES programme_sections(programme_section_id),
 section_group_id BIGINT REFERENCES section_groups(section_group_id) ON DELETE SET NULL,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id),
 faculty_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 academic_period_id BIGINT REFERENCES academics.academic_periods(academic_period_id),
 attendance_date DATE NOT NULL,
 class_mode VARCHAR(20) NOT NULL DEFAULT 'Offline' CHECK(class_mode IN('Offline','Online')),
 topic_covered TEXT,
 session_status VARCHAR(20) NOT NULL DEFAULT 'Draft' CHECK(session_status IN('Draft','Submitted','Locked','Cancelled')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 UNIQUE(programme_section_id,section_group_id,subject_id,attendance_date,academic_period_id)
);

CREATE TABLE IF NOT EXISTS academics.student_attendance (
 student_attendance_id BIGSERIAL PRIMARY KEY,
 attendance_session_id BIGINT NOT NULL REFERENCES academics.attendance_sessions(attendance_session_id) ON DELETE CASCADE,
 student_id BIGINT NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
 attendance_status VARCHAR(15) NOT NULL DEFAULT 'Present' CHECK(attendance_status IN('Present','Absent','Late','Leave','On Duty')),
 remarks TEXT,
 marked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 marked_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 UNIQUE(attendance_session_id,student_id)
);

CREATE TABLE IF NOT EXISTS academics.attendance_corrections (
 attendance_correction_id BIGSERIAL PRIMARY KEY,
 student_attendance_id BIGINT NOT NULL REFERENCES academics.student_attendance(student_attendance_id) ON DELETE CASCADE,
 old_status VARCHAR(15) NOT NULL,
 new_status VARCHAR(15) NOT NULL,
 correction_reason TEXT NOT NULL,
 correction_status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK(correction_status IN('Pending','Approved','Rejected')),
 requested_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 approved_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 decided_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS academics.examination_types (
 examination_type_id BIGSERIAL PRIMARY KEY,
 examination_type_code VARCHAR(30) NOT NULL UNIQUE,
 examination_type_name VARCHAR(100) NOT NULL UNIQUE,
 exam_scope VARCHAR(20) NOT NULL DEFAULT 'Internal' CHECK(exam_scope IN('Internal','External','University','Practical')),
 is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS academics.examinations (
 examination_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
 programme_batch_id BIGINT NOT NULL REFERENCES programme_batches(programme_batch_id),
 semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
 examination_type_id BIGINT NOT NULL REFERENCES academics.examination_types(examination_type_id),
 examination_name VARCHAR(150) NOT NULL,
 start_date DATE,
 end_date DATE,
 result_status VARCHAR(20) NOT NULL DEFAULT 'Not Published' CHECK(result_status IN('Not Published','Published','Withheld')),
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 CHECK(end_date IS NULL OR start_date IS NULL OR end_date>=start_date)
);

CREATE TABLE IF NOT EXISTS academics.examination_subjects (
 examination_subject_id BIGSERIAL PRIMARY KEY,
 examination_id BIGINT NOT NULL REFERENCES academics.examinations(examination_id) ON DELETE CASCADE,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id),
 exam_date DATE,
 maximum_marks NUMERIC(7,2) NOT NULL CHECK(maximum_marks>0),
 pass_marks NUMERIC(7,2) NOT NULL CHECK(pass_marks>=0 AND pass_marks<=maximum_marks),
 marks_entry_deadline TIMESTAMPTZ,
 marks_lock_status VARCHAR(20) NOT NULL DEFAULT 'Open' CHECK(marks_lock_status IN('Open','Closed','Locked')),
 UNIQUE(examination_id,subject_id)
);

CREATE TABLE IF NOT EXISTS academics.student_marks (
 student_mark_id BIGSERIAL PRIMARY KEY,
 examination_subject_id BIGINT NOT NULL REFERENCES academics.examination_subjects(examination_subject_id) ON DELETE CASCADE,
 student_id BIGINT NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
 marks_obtained NUMERIC(7,2),
 attendance_status VARCHAR(15) NOT NULL DEFAULT 'Present' CHECK(attendance_status IN('Present','Absent','Malpractice','Withheld')),
 result_status VARCHAR(15) CHECK(result_status IN('Pass','Fail','Absent','Withheld')),
 remarks TEXT,
 entered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 entered_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 UNIQUE(examination_subject_id,student_id)
);

CREATE TABLE IF NOT EXISTS academics.university_marks_imports (
 university_marks_import_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
 programme_batch_id BIGINT NOT NULL REFERENCES programme_batches(programme_batch_id),
 semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
 source_file_name VARCHAR(255),
 import_status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK(import_status IN('Pending','Processing','Completed','Failed')),
 total_rows INT NOT NULL DEFAULT 0,
 successful_rows INT NOT NULL DEFAULT 0,
 failed_rows INT NOT NULL DEFAULT 0,
 error_log TEXT,
 imported_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 imported_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS academics.student_backpapers (
 student_backpaper_id BIGSERIAL PRIMARY KEY,
 student_id BIGINT NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id),
 semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
 attempt_number INT NOT NULL DEFAULT 1 CHECK(attempt_number>0),
 registration_status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK(registration_status IN('Pending','Registered','Appeared','Cleared','Failed','Cancelled')),
 examination_id BIGINT REFERENCES academics.examinations(examination_id) ON DELETE SET NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(student_id,subject_id,attempt_number)
);

CREATE TABLE IF NOT EXISTS academics.lesson_plans (
 lesson_plan_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
 programme_batch_id BIGINT NOT NULL REFERENCES programme_batches(programme_batch_id),
 semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
 programme_section_id BIGINT NOT NULL REFERENCES programme_sections(programme_section_id),
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id),
 faculty_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 plan_title VARCHAR(200) NOT NULL,
 planned_start_date DATE,
 planned_end_date DATE,
 total_planned_periods INT NOT NULL DEFAULT 0 CHECK(total_planned_periods>=0),
 plan_status VARCHAR(20) NOT NULL DEFAULT 'Draft' CHECK(plan_status IN('Draft','Submitted','Approved','Rejected','Completed')),
 approved_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 approved_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 CHECK(planned_end_date IS NULL OR planned_start_date IS NULL OR planned_end_date>=planned_start_date)
);

CREATE TABLE IF NOT EXISTS academics.lesson_plan_units (
 lesson_plan_unit_id BIGSERIAL PRIMARY KEY,
 lesson_plan_id BIGINT NOT NULL REFERENCES academics.lesson_plans(lesson_plan_id) ON DELETE CASCADE,
 unit_number INT NOT NULL CHECK(unit_number>0),
 unit_title VARCHAR(200) NOT NULL,
 topics TEXT NOT NULL,
 planned_periods INT NOT NULL DEFAULT 0,
 completed_periods INT NOT NULL DEFAULT 0,
 planned_date DATE,
 completion_date DATE,
 completion_status VARCHAR(20) NOT NULL DEFAULT 'Not Started' CHECK(completion_status IN('Not Started','In Progress','Completed','Deferred')),
 UNIQUE(lesson_plan_id,unit_number)
);

CREATE TABLE IF NOT EXISTS academics.course_outcomes (
 course_outcome_id BIGSERIAL PRIMARY KEY,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id) ON DELETE CASCADE,
 co_code VARCHAR(20) NOT NULL,
 co_statement TEXT NOT NULL,
 bloom_level VARCHAR(10),
 target_percentage NUMERIC(5,2) CHECK(target_percentage BETWEEN 0 AND 100),
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 UNIQUE(subject_id,co_code)
);

CREATE TABLE IF NOT EXISTS academics.lesson_plan_co_mapping (
 lesson_plan_unit_id BIGINT NOT NULL REFERENCES academics.lesson_plan_units(lesson_plan_unit_id) ON DELETE CASCADE,
 course_outcome_id BIGINT NOT NULL REFERENCES academics.course_outcomes(course_outcome_id) ON DELETE CASCADE,
 PRIMARY KEY(lesson_plan_unit_id,course_outcome_id)
);

CREATE TABLE IF NOT EXISTS academics.preferred_books (
 preferred_book_id BIGSERIAL PRIMARY KEY,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id) ON DELETE CASCADE,
 book_title VARCHAR(255) NOT NULL,
 author_name VARCHAR(200),
 publisher_name VARCHAR(200),
 edition VARCHAR(50),
 isbn VARCHAR(30),
 preference_type VARCHAR(20) NOT NULL DEFAULT 'Text Book' CHECK(preference_type IN('Text Book','Reference Book','Supplementary')),
 display_order INT NOT NULL DEFAULT 1,
 is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS academics.lecture_notes (
 lecture_note_id BIGSERIAL PRIMARY KEY,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id) ON DELETE CASCADE,
 faculty_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 title VARCHAR(255) NOT NULL,
 unit_number INT,
 file_name VARCHAR(255),
 file_path TEXT,
 note_url TEXT,
 description TEXT,
 publish_status VARCHAR(20) NOT NULL DEFAULT 'Draft' CHECK(publish_status IN('Draft','Published','Archived')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS academics.video_lectures (
 video_lecture_id BIGSERIAL PRIMARY KEY,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id) ON DELETE CASCADE,
 faculty_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 title VARCHAR(255) NOT NULL,
 unit_number INT,
 video_url TEXT NOT NULL,
 duration_minutes INT CHECK(duration_minutes IS NULL OR duration_minutes>=0),
 description TEXT,
 publish_status VARCHAR(20) NOT NULL DEFAULT 'Draft' CHECK(publish_status IN('Draft','Published','Archived')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS academics.ppt_presentations (
 ppt_presentation_id BIGSERIAL PRIMARY KEY,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id) ON DELETE CASCADE,
 faculty_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 title VARCHAR(255) NOT NULL,
 unit_number INT,
 file_name VARCHAR(255),
 file_path TEXT,
 presentation_status VARCHAR(20) NOT NULL DEFAULT 'Submitted' CHECK(presentation_status IN('Draft','Submitted','Under Review','Approved','Revision Required','Rejected')),
 submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS academics.ppt_reviewers (
 ppt_reviewer_id BIGSERIAL PRIMARY KEY,
 employee_id BIGINT NOT NULL REFERENCES employees(employee_id) ON DELETE CASCADE,
 department_id BIGINT REFERENCES departments(department_id) ON DELETE SET NULL,
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 UNIQUE(employee_id,department_id)
);

CREATE TABLE IF NOT EXISTS academics.ppt_reviews (
 ppt_review_id BIGSERIAL PRIMARY KEY,
 ppt_presentation_id BIGINT NOT NULL REFERENCES academics.ppt_presentations(ppt_presentation_id) ON DELETE CASCADE,
 reviewer_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 review_status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK(review_status IN('Pending','Approved','Revision Required','Rejected')),
 score NUMERIC(5,2) CHECK(score IS NULL OR score BETWEEN 0 AND 100),
 comments TEXT,
 reviewed_at TIMESTAMPTZ,
 UNIQUE(ppt_presentation_id,reviewer_employee_id)
);

CREATE TABLE IF NOT EXISTS academics.subject_teacher_allocations (
 subject_teacher_allocation_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
 programme_batch_id BIGINT NOT NULL REFERENCES programme_batches(programme_batch_id),
 semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
 programme_section_id BIGINT NOT NULL REFERENCES programme_sections(programme_section_id),
 section_group_id BIGINT REFERENCES section_groups(section_group_id) ON DELETE SET NULL,
 subject_id BIGINT NOT NULL REFERENCES subjects(subject_id),
 employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 allocation_role VARCHAR(20) NOT NULL DEFAULT 'Primary' CHECK(allocation_role IN('Primary','Co-Teacher','Practical','Tutorial')),
 workload_hours NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK(workload_hours>=0),
 effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
 effective_to DATE,
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
 CHECK(effective_to IS NULL OR effective_to>=effective_from)
);

CREATE TABLE IF NOT EXISTS academics.class_teacher_allocations (
 class_teacher_allocation_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
 programme_section_id BIGINT NOT NULL REFERENCES programme_sections(programme_section_id),
 employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
 effective_to DATE,
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(effective_to IS NULL OR effective_to>=effective_from)
);

CREATE TABLE IF NOT EXISTS academics.substitute_teacher_allocations (
 substitute_teacher_allocation_id BIGSERIAL PRIMARY KEY,
 subject_teacher_allocation_id BIGINT NOT NULL REFERENCES academics.subject_teacher_allocations(subject_teacher_allocation_id),
 original_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 substitute_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
 substitution_date DATE NOT NULL,
 academic_period_id BIGINT REFERENCES academics.academic_periods(academic_period_id),
 reason TEXT,
 status VARCHAR(20) NOT NULL DEFAULT 'Assigned' CHECK(status IN('Assigned','Completed','Cancelled','Restored')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(original_employee_id<>substitute_employee_id)
);

CREATE TABLE IF NOT EXISTS academics.teacher_allocation_history (
 teacher_allocation_history_id BIGSERIAL PRIMARY KEY,
 allocation_type VARCHAR(30) NOT NULL CHECK(allocation_type IN('Subject Teacher','Class Teacher','Substitute Teacher')),
 allocation_record_id BIGINT NOT NULL,
 action_type VARCHAR(20) NOT NULL CHECK(action_type IN('Created','Updated','Deactivated','Restored')),
 old_employee_id BIGINT REFERENCES employees(employee_id) ON DELETE SET NULL,
 new_employee_id BIGINT REFERENCES employees(employee_id) ON DELETE SET NULL,
 reason TEXT,
 action_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 action_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS academics.timetable_headers (
 timetable_id BIGSERIAL PRIMARY KEY,
 academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
 programme_batch_id BIGINT NOT NULL REFERENCES programme_batches(programme_batch_id),
 semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
 programme_section_id BIGINT NOT NULL REFERENCES programme_sections(programme_section_id),
 timetable_name VARCHAR(150) NOT NULL,
 timetable_type VARCHAR(20) NOT NULL DEFAULT 'Offline' CHECK(timetable_type IN('Offline','Online','Hybrid')),
 effective_from DATE NOT NULL,
 effective_to DATE,
 status VARCHAR(20) NOT NULL DEFAULT 'Draft' CHECK(status IN('Draft','Published','Archived')),
 published_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(effective_to IS NULL OR effective_to>=effective_from)
);

CREATE TABLE IF NOT EXISTS academics.timetable_entries (
 timetable_entry_id BIGSERIAL PRIMARY KEY,
 timetable_id BIGINT NOT NULL REFERENCES academics.timetable_headers(timetable_id) ON DELETE CASCADE,
 day_of_week SMALLINT NOT NULL CHECK(day_of_week BETWEEN 1 AND 7),
 academic_period_id BIGINT NOT NULL REFERENCES academics.academic_periods(academic_period_id),
 subject_id BIGINT REFERENCES subjects(subject_id) ON DELETE SET NULL,
 employee_id BIGINT REFERENCES employees(employee_id) ON DELETE SET NULL,
 room_id BIGINT REFERENCES campus_rooms(room_id) ON DELETE SET NULL,
 section_group_id BIGINT REFERENCES section_groups(section_group_id) ON DELETE SET NULL,
 online_meeting_url TEXT,
 entry_type VARCHAR(20) NOT NULL DEFAULT 'Class' CHECK(entry_type IN('Class','Laboratory','Tutorial','Break','Activity')),
 remarks TEXT,
 UNIQUE(timetable_id,day_of_week,academic_period_id,section_group_id)
);

CREATE TABLE IF NOT EXISTS academics.timetable_change_log (
 timetable_change_log_id BIGSERIAL PRIMARY KEY,
 timetable_entry_id BIGINT NOT NULL REFERENCES academics.timetable_entries(timetable_entry_id) ON DELETE CASCADE,
 change_type VARCHAR(20) NOT NULL CHECK(change_type IN('Created','Updated','Deleted','Substituted')),
 old_values JSONB,
 new_values JSONB,
 changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 changed_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS academics.report_runs (
 report_run_id BIGSERIAL PRIMARY KEY,
 report_code VARCHAR(80) NOT NULL,
 report_name VARCHAR(150) NOT NULL,
 filter_json JSONB,
 generated_format VARCHAR(10) NOT NULL DEFAULT 'PDF' CHECK(generated_format IN('PDF','XLSX','CSV','HTML')),
 file_path TEXT,
 row_count INT NOT NULL DEFAULT 0,
 generated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 generated_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE OR REPLACE VIEW academics.vw_student_attendance_summary AS
SELECT sa.student_id, ats.academic_year_id, ats.semester_id, ats.subject_id,
 COUNT(*) total_classes,
 COUNT(*) FILTER(WHERE sa.attendance_status='Present') present_classes,
 COUNT(*) FILTER(WHERE sa.attendance_status='Absent') absent_classes,
 ROUND(100.0*COUNT(*) FILTER(WHERE sa.attendance_status='Present')/NULLIF(COUNT(*),0),2) attendance_percentage
FROM academics.student_attendance sa
JOIN academics.attendance_sessions ats ON ats.attendance_session_id=sa.attendance_session_id
WHERE ats.session_status IN('Submitted','Locked')
GROUP BY sa.student_id,ats.academic_year_id,ats.semester_id,ats.subject_id;

CREATE OR REPLACE VIEW academics.vw_student_marks_summary AS
SELECT sm.student_id,e.academic_year_id,e.programme_batch_id,e.semester_id,
 es.subject_id,e.examination_id,es.maximum_marks,es.pass_marks,
 sm.marks_obtained,sm.attendance_status,sm.result_status
FROM academics.student_marks sm
JOIN academics.examination_subjects es ON es.examination_subject_id=sm.examination_subject_id
JOIN academics.examinations e ON e.examination_id=es.examination_id;

CREATE OR REPLACE VIEW academics.vw_faculty_academic_load AS
SELECT employee_id,academic_year_id,semester_id,
 COUNT(DISTINCT subject_id) subjects_assigned,
 COUNT(DISTINCT programme_section_id) sections_assigned,
 COALESCE(SUM(workload_hours),0) total_workload_hours
FROM academics.subject_teacher_allocations
WHERE is_active=TRUE
GROUP BY employee_id,academic_year_id,semester_id;

CREATE OR REPLACE VIEW academics.vw_course_coverage AS
SELECT lp.lesson_plan_id,lp.subject_id,lp.faculty_employee_id,lp.programme_section_id,
 lp.total_planned_periods,COALESCE(SUM(lpu.completed_periods),0) completed_periods,
 ROUND(100.0*COALESCE(SUM(lpu.completed_periods),0)/NULLIF(lp.total_planned_periods,0),2) coverage_percentage
FROM academics.lesson_plans lp
LEFT JOIN academics.lesson_plan_units lpu ON lpu.lesson_plan_id=lp.lesson_plan_id
GROUP BY lp.lesson_plan_id,lp.subject_id,lp.faculty_employee_id,lp.programme_section_id,lp.total_planned_periods;

CREATE INDEX IF NOT EXISTS idx_attendance_session_date ON academics.attendance_sessions(attendance_date);
CREATE INDEX IF NOT EXISTS idx_student_attendance_student ON academics.student_attendance(student_id);
CREATE INDEX IF NOT EXISTS idx_student_marks_student ON academics.student_marks(student_id);
CREATE INDEX IF NOT EXISTS idx_subject_teacher_employee ON academics.subject_teacher_allocations(employee_id);
CREATE INDEX IF NOT EXISTS idx_timetable_section ON academics.timetable_headers(programme_section_id);

INSERT INTO academics.examination_types(examination_type_code,examination_type_name,exam_scope) VALUES
('IA1','Internal Assessment 1','Internal'),
('IA2','Internal Assessment 2','Internal'),
('SEM','Semester Examination','University'),
('PRAC','Practical Examination','Practical')
ON CONFLICT(examination_type_code) DO NOTHING;

COMMIT;
