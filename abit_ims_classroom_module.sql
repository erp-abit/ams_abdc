-- PostgreSQL classroom module for server/index.js.
-- Prerequisites: public.campuses, public.buildings, public.users.
BEGIN;
CREATE TABLE IF NOT EXISTS public.classroom_types (
 classroom_type_id BIGSERIAL PRIMARY KEY,
 classroom_type_code VARCHAR(40) NOT NULL UNIQUE,
 classroom_type_name VARCHAR(100) NOT NULL UNIQUE,
 is_active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS public.classroom_facility_masters (
 facility_id BIGSERIAL PRIMARY KEY,
 facility_code VARCHAR(40) NOT NULL UNIQUE,
 facility_name VARCHAR(100) NOT NULL UNIQUE,
 is_active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS public.classrooms (
 classroom_id BIGSERIAL PRIMARY KEY,
 campus_id BIGINT NOT NULL REFERENCES public.campuses(campus_id),
 building_id BIGINT NOT NULL REFERENCES public.buildings(building_id),
 classroom_type_id BIGINT NOT NULL REFERENCES public.classroom_types(classroom_type_id),
 room_no VARCHAR(50) NOT NULL, room_name VARCHAR(150), floor_name VARCHAR(50),
 student_capacity INTEGER NOT NULL CHECK(student_capacity >= 0), description TEXT,
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 created_by BIGINT REFERENCES public.users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_by BIGINT REFERENCES public.users(user_id), updated_at TIMESTAMPTZ,
 UNIQUE(building_id,room_no)
);
CREATE TABLE IF NOT EXISTS public.classroom_facilities (
 classroom_id BIGINT NOT NULL REFERENCES public.classrooms(classroom_id) ON DELETE CASCADE,
 facility_id BIGINT NOT NULL REFERENCES public.classroom_facility_masters(facility_id),
 PRIMARY KEY(classroom_id,facility_id)
);
CREATE TABLE IF NOT EXISTS public.classroom_unavailability (
 classroom_unavailability_id BIGSERIAL PRIMARY KEY,
 classroom_id BIGINT NOT NULL REFERENCES public.classrooms(classroom_id) ON DELETE CASCADE,
 start_at TIMESTAMPTZ NOT NULL, end_at TIMESTAMPTZ NOT NULL,
 reason TEXT, created_by BIGINT REFERENCES public.users(user_id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK(end_at > start_at)
);
INSERT INTO public.classroom_types(classroom_type_code,classroom_type_name) VALUES
 ('CLASSROOM','Classroom'),('LABORATORY','Laboratory'),('SEMINAR_HALL','Seminar Hall')
 ON CONFLICT DO NOTHING;
INSERT INTO public.classroom_facility_masters(facility_code,facility_name) VALUES
 ('PROJECTOR','Projector'),('WHITEBOARD','Whiteboard'),('COMPUTERS','Computers'),('AC','Air Conditioning')
 ON CONFLICT DO NOTHING;
COMMIT;
