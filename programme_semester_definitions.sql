CREATE TABLE IF NOT EXISTS programme_semester_definitions (
  programme_semester_id BIGSERIAL PRIMARY KEY,
  course_id BIGINT NOT NULL REFERENCES programmes(programme_id),
  programme_batch_id BIGINT NOT NULL REFERENCES admission_batches(batch_id),
  semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
  class_type VARCHAR(20) NOT NULL CHECK (class_type IN ('SECTION', 'HOUSE')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  consider_for_accounting BOOLEAN NOT NULL DEFAULT FALSE,
  created_by BIGINT REFERENCES users(user_id),
  updated_by BIGINT REFERENCES users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ,
  CONSTRAINT uq_programme_semester_definition
    UNIQUE (course_id, programme_batch_id, semester_id, class_type)
);

CREATE INDEX IF NOT EXISTS idx_programme_semester_course
  ON programme_semester_definitions(course_id);

CREATE INDEX IF NOT EXISTS idx_programme_semester_batch
  ON programme_semester_definitions(programme_batch_id);

CREATE INDEX IF NOT EXISTS idx_programme_semester_semester
  ON programme_semester_definitions(semester_id);
