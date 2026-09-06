import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { saveAccountPassword } from './change-password.js';

dotenv.config();
const scrypt = promisify(scryptCallback);
const app = express();
app.use(cors());
app.use(express.json({ limit: '3mb' }));

const port = process.env.PORT || 5000;
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres'
});

const sessions = new Map();
const SESSION_MS = 8 * 60 * 60 * 1000;

app.get('/api/health', async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT current_database() AS database_name,
        EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name='ABDC_DB') AS schema_ready`
    );
    res.json({ ok:true, database:'connected', ...result.rows[0] });
  } catch (error) {
    console.error('Database health check failed:', error.message);
    res.status(503).json({ ok:false, database:'disconnected' });
  }
});

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `scrypt:${salt}:${Buffer.from(derived).toString('hex')}`;
}

async function verifyPassword(password, stored) {
  const [algorithm, salt, key] = String(stored).split(':');
  if (algorithm !== 'scrypt' || !salt || !key) return false;
  const derived = Buffer.from(await scrypt(password, salt, 64));
  const saved = Buffer.from(key, 'hex');
  return saved.length === derived.length && timingSafeEqual(saved, derived);
}

async function findLoginUser(username) {
  const superAdminResult = await pool.query(
    `SELECT a.user_id AS abdc_user_id,a.login_id AS username,a.password_hash,a.display_name,
      a.user_type,a.photo_path,a.account_status,a.force_password_change,a.failed_login_attempts,
      u.user_id AS legacy_user_id
     FROM "ABDC_DB".user_logins a
     LEFT JOIN users u ON LOWER(u.username)=LOWER(a.login_id)
     WHERE LOWER(a.login_id)=LOWER($1) AND a.user_type='SUPER_ADMIN'
     LIMIT 1`,
    [username]
  );
  if (superAdminResult.rowCount) {
    const row = superAdminResult.rows[0];
    return {
      ...row,
      user_id: row.legacy_user_id,
      is_active: row.account_status === 'ACTIVE',
      locked_until: row.account_status === 'LOCKED' ? new Date('9999-12-31') : null,
      auth_source: 'ABDC_DB'
    };
  }

  const result = await pool.query(
    `SELECT u.user_id,u.username,u.password_hash,u.display_name,u.user_type,u.is_active,u.locked_until,
      COALESCE(NULLIF(u.photo_path,''),
        (SELECT NULLIF(up.file_path,'') FROM user_photos up WHERE up.user_id=u.user_id AND up.is_current=TRUE ORDER BY up.uploaded_at DESC,up.user_photo_id DESC LIMIT 1),
        NULLIF(e.photo_url,''),NULLIF(st.profile_photo_url,''),NULLIF(st.photo_url,'')) AS photo_path
     FROM users u
     LEFT JOIN employees e ON e.employee_id=u.employee_id
     LEFT JOIN students st ON st.student_id=u.student_id
     WHERE LOWER(u.username)=LOWER($1) LIMIT 1`,
    [username]
  );
  if(result.rows[0])return { ...result.rows[0], auth_source: 'LEGACY' };

  const employeeAccount=(await pool.query(`SELECT ua.login_id AS username,ua.password_hash,ua.account_status,
      e.employee_id,e.user_id AS legacy_user_id,e.employee_code,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS display_name,
      e.photo_url AS photo_path,e.status AS employee_status
    FROM user_accounts ua JOIN employees e ON e.employee_id=ua.employee_id
    WHERE LOWER(ua.login_id)=LOWER($1) LIMIT 1`,[username])).rows[0];
  if(!employeeAccount)return null;
  const active=employeeAccount.account_status==='ACTIVE'&&String(employeeAccount.employee_status).toUpperCase()==='ACTIVE';
  const linked=employeeAccount.legacy_user_id?(await pool.query(`UPDATE users SET username=$1,password_hash=$2,
      display_name=$3,user_type='EMPLOYEE',must_change_password=TRUE,is_active=$4,employee_id=$5,
      failed_login_count=0,locked_until=NULL,updated_at=NOW() WHERE user_id=$6
    RETURNING user_id,username,password_hash,display_name,user_type,is_active,locked_until`,[
      employeeAccount.username,employeeAccount.password_hash,employeeAccount.display_name,active,
      employeeAccount.employee_id,employeeAccount.legacy_user_id])).rows[0]:(await pool.query(`INSERT INTO users
      (username,password_hash,display_name,user_type,must_change_password,is_active,employee_id)
    VALUES ($1,$2,$3,'EMPLOYEE',TRUE,$4,$5)
    ON CONFLICT (username) DO UPDATE SET password_hash=EXCLUDED.password_hash,
      display_name=EXCLUDED.display_name,user_type='EMPLOYEE',is_active=EXCLUDED.is_active,
      employee_id=EXCLUDED.employee_id,updated_at=NOW()
    RETURNING user_id,username,password_hash,display_name,user_type,is_active,locked_until`,[
      employeeAccount.username,employeeAccount.password_hash,employeeAccount.display_name,active,employeeAccount.employee_id
    ])).rows[0];
  await pool.query('UPDATE employees SET user_id=$1 WHERE employee_id=$2 AND user_id IS DISTINCT FROM $1',[linked.user_id,employeeAccount.employee_id]);
  return {...linked,photo_path:employeeAccount.photo_path,auth_source:'LEGACY'};
}

async function initialiseAuthentication() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    user_id BIGSERIAL PRIMARY KEY, username VARCHAR(80) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, email VARCHAR(150) UNIQUE, mobile VARCHAR(20),
    display_name VARCHAR(150), user_type VARCHAR(30) NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE, last_login_at TIMESTAMPTZ,
    failed_login_count INTEGER NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS user_types (
    user_type_id SMALLSERIAL PRIMARY KEY,
    user_type_code VARCHAR(30) NOT NULL UNIQUE,
    user_type_name VARCHAR(100) NOT NULL,
    display_order INTEGER NOT NULL DEFAULT 0
  )`);
  await pool.query(`INSERT INTO user_types (user_type_code,user_type_name,display_order) VALUES
    ('ADMIN','Admin',1),('EMPLOYEE','Employee',2),('STUDENT','Student',3)
    ON CONFLICT (user_type_code) DO UPDATE SET
      user_type_name=EXCLUDED.user_type_name,
      display_order=EXCLUDED.display_order`);
  await pool.query(`CREATE TABLE IF NOT EXISTS login_logs (
    login_log_id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(user_id),
    username_attempted VARCHAR(80), login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logout_at TIMESTAMPTZ, login_status VARCHAR(20) NOT NULL,
    ip_address INET, user_agent TEXT
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS user_accounts (
    user_id BIGSERIAL PRIMARY KEY,
    employee_id BIGINT UNIQUE REFERENCES employees(employee_id) ON DELETE CASCADE,
    login_id VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    default_login BOOLEAN DEFAULT TRUE,
    account_status VARCHAR(20) DEFAULT 'ACTIVE',
    failed_login_attempts INT DEFAULT 0,
    last_login TIMESTAMP,
    password_changed_at TIMESTAMP,
    created_by BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT,
    updated_at TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS employee_login_history (
    history_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES user_accounts(user_id),
    employee_id BIGINT REFERENCES employees(employee_id),
    old_login_id VARCHAR(100),
    new_login_id VARCHAR(100),
    changed_by BIGINT,
    changed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    remarks TEXT
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS password_reset_history (
    reset_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES user_accounts(user_id),
    reset_by BIGINT,
    reset_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    temporary_password BOOLEAN DEFAULT TRUE,
    remarks TEXT
  )`);
  await pool.query('CREATE SCHEMA IF NOT EXISTS permission_management');
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.system_modules (
    module_id BIGSERIAL PRIMARY KEY,module_code VARCHAR(50) UNIQUE NOT NULL,module_name VARCHAR(100) NOT NULL,
    module_icon VARCHAR(100),display_order INTEGER DEFAULT 0,status BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.system_menus (
    menu_id BIGSERIAL PRIMARY KEY,module_id BIGINT NOT NULL REFERENCES permission_management.system_modules(module_id) ON DELETE CASCADE,
    parent_menu_id BIGINT REFERENCES permission_management.system_menus(menu_id) ON DELETE CASCADE,menu_code VARCHAR(80) UNIQUE NOT NULL,
    menu_name VARCHAR(120) NOT NULL,menu_path VARCHAR(250),menu_icon VARCHAR(100),display_order INTEGER DEFAULT 0,
    status BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.permissions (
    permission_id BIGSERIAL PRIMARY KEY,permission_code VARCHAR(40) UNIQUE NOT NULL,
    permission_name VARCHAR(80) NOT NULL,description VARCHAR(250),status BOOLEAN NOT NULL DEFAULT TRUE
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.roles (
    role_id BIGSERIAL PRIMARY KEY,role_code VARCHAR(50) UNIQUE NOT NULL,role_name VARCHAR(100) NOT NULL,
    description VARCHAR(300),is_system_role BOOLEAN NOT NULL DEFAULT FALSE,status BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.role_permissions (
    role_permission_id BIGSERIAL PRIMARY KEY,role_id BIGINT NOT NULL REFERENCES permission_management.roles(role_id) ON DELETE CASCADE,
    menu_id BIGINT NOT NULL REFERENCES permission_management.system_menus(menu_id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permission_management.permissions(permission_id) ON DELETE CASCADE,
    is_allowed BOOLEAN NOT NULL DEFAULT TRUE,granted_by BIGINT,granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id,menu_id,permission_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.user_roles (
    user_role_id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES user_accounts(user_id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES permission_management.roles(role_id) ON DELETE CASCADE,department_id BIGINT,
    valid_from DATE DEFAULT CURRENT_DATE,valid_to DATE,status BOOLEAN NOT NULL DEFAULT TRUE,
    assigned_by BIGINT REFERENCES user_accounts(user_id),assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id,role_id,department_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.user_permissions (
    user_permission_id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES user_accounts(user_id) ON DELETE CASCADE,
    menu_id BIGINT NOT NULL REFERENCES permission_management.system_menus(menu_id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permission_management.permissions(permission_id) ON DELETE CASCADE,is_allowed BOOLEAN NOT NULL,
    valid_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP,valid_to TIMESTAMP,remarks VARCHAR(500),
    granted_by BIGINT REFERENCES user_accounts(user_id),granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id,menu_id,permission_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS permission_management.permission_change_history (
    history_id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES user_accounts(user_id),
    role_id BIGINT REFERENCES permission_management.roles(role_id),menu_id BIGINT REFERENCES permission_management.system_menus(menu_id),
    permission_id BIGINT REFERENCES permission_management.permissions(permission_id),old_value BOOLEAN,new_value BOOLEAN,
    action_type VARCHAR(30) NOT NULL CHECK(action_type IN ('GRANT','REVOKE','ROLE_ASSIGN','ROLE_REMOVE')),
    changed_by BIGINT REFERENCES user_accounts(user_id),changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    remarks VARCHAR(500)
  )`);
  await pool.query(`INSERT INTO permission_management.system_modules(module_code,module_name,display_order) VALUES
    ('DASHBOARD','Dashboard',1),('STUDENT','Student',2),('ACADEMICS','Academics',3),
    ('EMPLOYEE','Employee',4),('LIBRARY','Library',5),('STUDENT_MENTORING','Student Mentoring',6),
    ('CONFIGURATION','Configuration',7),('COURSE','Course',8),('ADMINISTRATION','Administration',9),
    ('DASHBOARD_SETTING','Dashboard Setting',10),('OBE','OBE',11)
    ON CONFLICT(module_code) DO UPDATE SET module_name=EXCLUDED.module_name,display_order=EXCLUDED.display_order`);
  await pool.query(`INSERT INTO permission_management.system_menus(module_id,menu_code,menu_name,display_order)
    SELECT m.module_id,v.code,v.name,v.ord FROM permission_management.system_modules m JOIN (VALUES
      ('DASHBOARD','DASHBOARD','Dashboard',1),('STUDENT','STUDENT_MASTER','Student Master',1),
      ('ACADEMICS','COURSES','Courses',1),('ACADEMICS','ATTENDANCE','Attendance',2),
      ('EMPLOYEE','EMPLOYEE_MASTER','Employee Master',1),('LIBRARY','BOOK_ISSUE','Book Issue',1)
    ) v(module_code,code,name,ord) ON v.module_code=m.module_code
    ON CONFLICT(menu_code) DO UPDATE SET menu_name=EXCLUDED.menu_name,display_order=EXCLUDED.display_order`);
  await pool.query(`INSERT INTO permission_management.system_menus(module_id,menu_code,menu_name,display_order)
    SELECT module_id,'MENTOR_ACTIVITY','Mentor Activity',1 FROM permission_management.system_modules
    WHERE module_code='STUDENT_MENTORING' ON CONFLICT(menu_code) DO UPDATE SET menu_name=EXCLUDED.menu_name,module_id=EXCLUDED.module_id`);
  await pool.query(`INSERT INTO permission_management.permissions(permission_code,permission_name) VALUES
    ('VIEW','View'),('ADD','Add'),('EDIT','Edit'),('DELETE','Delete'),('APPROVE','Approve'),
    ('EXPORT','Export'),('PRINT','Print'),('ADD_MENTOR','Add Mentor') ON CONFLICT(permission_code) DO UPDATE SET permission_name=EXCLUDED.permission_name`);
  const permissionMenuHierarchy=[
    ['ACADEMICS','ATTENDANCE_MENU','Attendance',['Take Attendance','Student Attendance','Calendar Setting']],
    ['ACADEMICS','EXAMINATION_AND_MARKS_MENU','Examination & Marks',['Examination & Marks','Student Marks Entry','Import University Marks','Student Back Paper','Set Mark Entry Deadline','Student Marks Report','University Marks Report']],
    ['ACADEMICS','LESSON_PLAN_MENU','Lesson Plan',['Preferred Books','Course Outcome','Lesson Plan','View Lesson Plans','Material Upload','Course Coverage Report','Lesson Plan Report']],
    ['ACADEMICS','FACULTY_ALLOCATION_MENU','Faculty Allocation',['Assign Subject Teacher','Assign Class Teacher','Allot Substitute Teacher','Restore Subject Teacher','Restore Teacher Allotments','Faculty Academic Load','Faculty Performance Report']],
    ['ACADEMICS','TIMETABLE_MENU','Timetable',['Manage Classroom','Manage Timetable','Time Configuration','Break / Lunch Configuration','Timetable Entry','Faculty Timetable','Class Timetable','Room Timetable','Timetable Validation','Publish Timetable','Timetable Revision','Timetable Reports']],
    ['STUDENT_MENTORING','MENTORING_MENU','Mentoring',['Existing Student','1st Reviewer Remarks','All Counselling & Reviews','Reviewer Allotment']],
    ['STUDENT_MENTORING','MENTOR_ALLOTMENT_MENU','Mentor Allotment',['Existing Student','Prospective Student','Mentor Allotment Report']],
    ['COURSE','COURSE_MANAGEMENT_MENU','Course Management',['Programme','Manage Programme Sections','Merge Programme Sections','Split Programme Section','Section Master','Manage Subjects']],
    ['EMPLOYEE','EMPLOYEE_MANAGEMENT_MENU','Employee Management',['Add Employee','Manage Employee','Designation','Reset Login','Reset Password','Restore Employee']],
    ['STUDENT','STUDENT_MANAGEMENT_MENU','Student Management',['Add Student','Add Student Section & Group','Manage Students','Reset Registration No.','Reset Password','Restore Student']],
    ['ADMINISTRATION','ADMINISTRATION_MENU','Administration',['Users Setting','Permissions','Login History']]
  ];
  const menuCode=value=>value.toUpperCase().replace(/&/g,'AND').replace(/[^A-Z0-9]+/g,'_').replace(/^_|_$/g,'');
  for(const [moduleCode,parentCode,parentName,children] of permissionMenuHierarchy){
    const module=(await pool.query('SELECT module_id FROM permission_management.system_modules WHERE module_code=$1',[moduleCode])).rows[0];
    if(!module)continue;
    const parent=(await pool.query(`INSERT INTO permission_management.system_menus(module_id,menu_code,menu_name,display_order)
      VALUES($1,$2,$3,10) ON CONFLICT(menu_code) DO UPDATE SET module_id=EXCLUDED.module_id,menu_name=EXCLUDED.menu_name,status=TRUE RETURNING menu_id`,[module.module_id,parentCode,parentName])).rows[0];
    for(let index=0;index<children.length;index++){
      const name=children[index],code=parentCode==='MENTORING_MENU'&&name==='Existing Student'?'MENTOR_ACTIVITY':`${parentCode}_${menuCode(name)}`;
      await pool.query(`INSERT INTO permission_management.system_menus(module_id,parent_menu_id,menu_code,menu_name,menu_path,display_order)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(menu_code) DO UPDATE SET module_id=EXCLUDED.module_id,parent_menu_id=EXCLUDED.parent_menu_id,menu_name=EXCLUDED.menu_name,menu_path=EXCLUDED.menu_path,status=TRUE`,
        [module.module_id,parent.menu_id,code,name,`${moduleCode}::${parentName}::${name}`,index+1]);
    }
  }
  await pool.query(`UPDATE permission_management.system_menus child SET menu_name='Existing Student',parent_menu_id=parent.menu_id,
    module_id=parent.module_id,menu_path='Student Mentoring::Mentoring::Existing Student'
    FROM permission_management.system_menus parent WHERE child.menu_code='MENTOR_ACTIVITY' AND parent.menu_code='MENTORING_MENU'`);
  await pool.query(`INSERT INTO permission_management.roles(role_code,role_name,description,is_system_role) VALUES
    ('ADMIN','Administrator','Full system access',TRUE),('FACULTY','Faculty','Teaching faculty access',TRUE),
    ('EMPLOYEE','Employee','Standard employee access',TRUE),('HOD','Department Head','Department management access',TRUE)
    ON CONFLICT(role_code) DO UPDATE SET role_name=EXCLUDED.role_name,description=EXCLUDED.description`);
  await pool.query(`INSERT INTO permission_management.role_permissions(role_id,menu_id,permission_id,is_allowed)
    SELECT r.role_id,m.menu_id,p.permission_id,
      CASE WHEN r.role_code='ADMIN' THEN TRUE
        WHEN p.permission_code='VIEW' THEN TRUE
        WHEN r.role_code IN ('FACULTY','HOD') AND p.permission_code IN ('ADD','EDIT','EXPORT','PRINT') AND m.menu_code IN ('STUDENT_MASTER','ATTENDANCE','BOOK_ISSUE') THEN TRUE
        ELSE FALSE END
    FROM permission_management.roles r CROSS JOIN permission_management.system_menus m CROSS JOIN permission_management.permissions p
    WHERE r.role_code IN ('ADMIN','FACULTY','EMPLOYEE','HOD')
    ON CONFLICT(role_id,menu_id,permission_id) DO NOTHING`);
  await pool.query(`CREATE TABLE IF NOT EXISTS building_departments (
    building_id BIGINT NOT NULL REFERENCES buildings(building_id) ON DELETE CASCADE,
    department_id BIGINT NOT NULL REFERENCES departments(department_id) ON DELETE CASCADE,
    PRIMARY KEY (building_id, department_id)
  )`);
  await pool.query('ALTER TABLE departments ADD COLUMN IF NOT EXISTS department_alias VARCHAR(150)');
  await pool.query('ALTER TABLE departments ADD COLUMN IF NOT EXISTS official_email VARCHAR(150)');
  await pool.query('ALTER TABLE departments ADD COLUMN IF NOT EXISTS phone VARCHAR(20)');
  await pool.query('ALTER TABLE academic_years ADD COLUMN IF NOT EXISTS academic_year_name VARCHAR(120)');
  await pool.query('ALTER TABLE academic_years ADD COLUMN IF NOT EXISTS admission_start_date DATE');
  await pool.query('ALTER TABLE academic_years ADD COLUMN IF NOT EXISTS admission_end_date DATE');
  await pool.query('ALTER TABLE academic_years ADD COLUMN IF NOT EXISTS allow_data_entry BOOLEAN NOT NULL DEFAULT TRUE');
  await pool.query('ALTER TABLE academic_years ADD COLUMN IF NOT EXISTS allow_previous_year_edit BOOLEAN NOT NULL DEFAULT FALSE');
  await pool.query("ALTER TABLE academic_years ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'");
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS blood_group VARCHAR(10)');
  await pool.query('ALTER TABLE students ADD COLUMN IF NOT EXISTS student_group VARCHAR(30)');
  await pool.query(`CREATE TABLE IF NOT EXISTS subject_masters (
    subject_master_id BIGSERIAL PRIMARY KEY,
    subject_code VARCHAR(30) NOT NULL UNIQUE,
    subject_name VARCHAR(200) NOT NULL,
    subject_short_name VARCHAR(50),
    subject_type VARCHAR(30) NOT NULL DEFAULT 'Theory',
    subject_category VARCHAR(80) NOT NULL,
    department_id BIGINT NOT NULL REFERENCES departments(department_id),
    credit NUMERIC(5,2) NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_by BIGINT,
    updated_at TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS subject_teacher_allocations (
    subject_teacher_allocation_id BIGSERIAL PRIMARY KEY,
    academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
    batch_id BIGINT NOT NULL REFERENCES admission_batches(batch_id),
    semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
    section_id BIGINT NOT NULL REFERENCES sections(section_id),
    subject_master_id BIGINT NOT NULL REFERENCES subject_masters(subject_master_id),
    employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
    allocation_role VARCHAR(30) NOT NULL DEFAULT 'PRIMARY',
    workload_hours NUMERIC(5,2) NOT NULL CHECK (workload_hours > 0),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_by BIGINT REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ,
    UNIQUE (academic_year_id,batch_id,semester_id,section_id,subject_master_id,employee_id,allocation_role)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS class_teacher_allocations (
    class_teacher_allocation_id BIGSERIAL PRIMARY KEY,
    academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
    programme_id BIGINT NOT NULL REFERENCES programmes(programme_id),
    batch_id BIGINT NOT NULL REFERENCES admission_batches(batch_id),
    semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
    section_id BIGINT NOT NULL REFERENCES sections(section_id),
    student_group VARCHAR(30) NOT NULL DEFAULT 'ALL',
    employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
    teacher_type VARCHAR(20) NOT NULL DEFAULT 'MAIN',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_by BIGINT REFERENCES users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by BIGINT REFERENCES users(user_id), updated_at TIMESTAMPTZ,
    UNIQUE (academic_year_id,batch_id,semester_id,section_id,student_group)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS substitute_teacher_allocations (
    substitute_teacher_allocation_id BIGSERIAL PRIMARY KEY,
    subject_teacher_allocation_id BIGINT NOT NULL REFERENCES subject_teacher_allocations(subject_teacher_allocation_id) ON DELETE CASCADE,
    original_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
    substitute_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
    from_date DATE NOT NULL,
    to_date DATE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_by BIGINT REFERENCES users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by BIGINT REFERENCES users(user_id), updated_at TIMESTAMPTZ,
    CHECK (to_date >= from_date), CHECK (original_employee_id <> substitute_employee_id),
    UNIQUE (subject_teacher_allocation_id,from_date,to_date)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS student_attendance_entries (
    attendance_entry_id BIGSERIAL PRIMARY KEY,
    subject_teacher_allocation_id BIGINT NOT NULL REFERENCES subject_teacher_allocations(subject_teacher_allocation_id),
    attendance_date DATE NOT NULL,start_time TIME NOT NULL,end_time TIME NOT NULL,
    topic_covered TEXT NOT NULL,student_group VARCHAR(30) NOT NULL DEFAULT 'ALL',
    strength INTEGER NOT NULL DEFAULT 0,present_count INTEGER NOT NULL DEFAULT 0,absent_count INTEGER NOT NULL DEFAULT 0,
    created_by BIGINT REFERENCES users(user_id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK(end_time>start_time),CHECK(present_count>=0),CHECK(absent_count>=0),
    UNIQUE(subject_teacher_allocation_id,attendance_date,start_time)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS student_attendance_entry_students (
    attendance_entry_id BIGINT NOT NULL REFERENCES student_attendance_entries(attendance_entry_id) ON DELETE CASCADE,
    student_id BIGINT NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
    attendance_status VARCHAR(15) NOT NULL DEFAULT 'ABSENT' CHECK(attendance_status IN ('PRESENT','ABSENT')),
    created_by BIGINT REFERENCES users(user_id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(attendance_entry_id,student_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.attendance_calendar_settings (
    attendance_calendar_setting_id BIGSERIAL PRIMARY KEY,
    academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
    programme_id BIGINT REFERENCES programmes(programme_id),
    programme_batch_id BIGINT REFERENCES admission_batches(batch_id),semester_id BIGINT REFERENCES semesters(semester_id),
    programme_section_id BIGINT REFERENCES sections(section_id),
    permission_type VARCHAR(20) NOT NULL CHECK(permission_type IN ('Single Day','Date Range','Selected Dates','Weekly Pattern','All Working Days')),
    start_date DATE,end_date DATE,allow_attendance BOOLEAN NOT NULL DEFAULT TRUE,
    attendance_open_time TIME,attendance_close_time TIME,is_active BOOLEAN NOT NULL DEFAULT TRUE,
    remarks TEXT,created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMPTZ
  )`);
  await pool.query(`ALTER TABLE academics.attendance_calendar_settings ADD COLUMN IF NOT EXISTS programme_id BIGINT REFERENCES programmes(programme_id)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.attendance_calendar_weekdays (
    attendance_calendar_weekday_id BIGSERIAL PRIMARY KEY,
    attendance_calendar_setting_id BIGINT NOT NULL REFERENCES academics.attendance_calendar_settings(attendance_calendar_setting_id) ON DELETE CASCADE,
    day_of_week SMALLINT NOT NULL CHECK(day_of_week BETWEEN 1 AND 7),is_permitted BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(attendance_calendar_setting_id,day_of_week)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.attendance_calendar_dates (
    attendance_calendar_date_id BIGSERIAL PRIMARY KEY,
    attendance_calendar_setting_id BIGINT NOT NULL REFERENCES academics.attendance_calendar_settings(attendance_calendar_setting_id) ON DELETE CASCADE,
    attendance_date DATE NOT NULL,is_permitted BOOLEAN NOT NULL DEFAULT TRUE,open_time TIME,close_time TIME,remarks TEXT,
    UNIQUE(attendance_calendar_setting_id,attendance_date)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS preferred_books (
    preferred_book_id BIGSERIAL PRIMARY KEY,
    subject_master_id BIGINT NOT NULL REFERENCES subject_masters(subject_master_id),
    book_title VARCHAR(250) NOT NULL,
    author_name VARCHAR(200) NOT NULL,
    publisher_name VARCHAR(200),
    edition VARCHAR(50),
    isbn VARCHAR(30),
    book_type VARCHAR(30) NOT NULL DEFAULT 'TEXT_BOOK',
    display_order INTEGER NOT NULL DEFAULT 1 CHECK (display_order > 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by BIGINT REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ,
    UNIQUE (subject_master_id,book_title,edition)
  )`);
  await pool.query('CREATE SCHEMA IF NOT EXISTS academics');
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.course_outcome_codes (
    co_code_id BIGSERIAL PRIMARY KEY,
    co_code VARCHAR(20) NOT NULL UNIQUE,
    co_number INTEGER NOT NULL UNIQUE CHECK (co_number > 0),
    display_order INTEGER NOT NULL CHECK (display_order > 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query(`INSERT INTO academics.course_outcome_codes (co_code,co_number,display_order)
    SELECT 'CO-'||number,number,number FROM generate_series(1,12) number
    ON CONFLICT (co_code) DO NOTHING`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.course_outcomes (
    course_outcome_id BIGSERIAL PRIMARY KEY,
    subject_master_id BIGINT NOT NULL REFERENCES subject_masters(subject_master_id),
    co_code_id BIGINT NOT NULL REFERENCES academics.course_outcome_codes(co_code_id),
    co_description TEXT NOT NULL,
    faculty_employee_id BIGINT REFERENCES employees(employee_id),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_by BIGINT REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ,
    UNIQUE (subject_master_id,co_code_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.faculty_subject_assignments (
    faculty_subject_assignment_id BIGSERIAL PRIMARY KEY,
    academic_year_id BIGINT NOT NULL REFERENCES academic_years(academic_year_id),
    programme_batch_id BIGINT REFERENCES admission_batches(batch_id),
    semester_id BIGINT REFERENCES semesters(semester_id),
    programme_section_id BIGINT REFERENCES sections(section_id),
    subject_id BIGINT NOT NULL REFERENCES subject_masters(subject_master_id),
    faculty_employee_id BIGINT NOT NULL REFERENCES employees(employee_id),
    assignment_status VARCHAR(20) NOT NULL DEFAULT 'Active'
      CHECK (assignment_status IN ('Active','Inactive','Completed')),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by BIGINT REFERENCES users(user_id),
    UNIQUE (academic_year_id,programme_batch_id,semester_id,programme_section_id,subject_id,faculty_employee_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.lesson_plan_headers (
    lesson_plan_id BIGSERIAL PRIMARY KEY,
    faculty_subject_assignment_id BIGINT NOT NULL UNIQUE
      REFERENCES academics.faculty_subject_assignments(faculty_subject_assignment_id) ON DELETE CASCADE,
    lesson_plan_title VARCHAR(200),
    plan_status VARCHAR(20) NOT NULL DEFAULT 'Draft'
      CHECK (plan_status IN ('Draft','Submitted','Approved','Rejected','Completed')),
    total_planned_topics INTEGER NOT NULL DEFAULT 0,
    total_planned_periods INTEGER NOT NULL DEFAULT 0,
    submitted_at TIMESTAMPTZ,approved_at TIMESTAMPTZ,approved_by BIGINT REFERENCES users(user_id),
    rejection_reason TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT REFERENCES users(user_id),updated_at TIMESTAMPTZ,updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.lesson_plan_books (
    lesson_plan_book_id BIGSERIAL PRIMARY KEY,
    lesson_plan_id BIGINT NOT NULL REFERENCES academics.lesson_plan_headers(lesson_plan_id) ON DELETE CASCADE,
    preferred_book_id BIGINT REFERENCES preferred_books(preferred_book_id),
    book_title VARCHAR(255) NOT NULL,author_name VARCHAR(255),publisher_name VARCHAR(255),
    edition VARCHAR(80),isbn VARCHAR(30),book_sequence INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT REFERENCES users(user_id),UNIQUE (lesson_plan_id,book_sequence)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.lesson_plan_topics (
    lesson_plan_topic_id BIGSERIAL PRIMARY KEY,
    lesson_plan_id BIGINT NOT NULL REFERENCES academics.lesson_plan_headers(lesson_plan_id) ON DELETE CASCADE,
    lesson_number INTEGER NOT NULL,topic_description TEXT NOT NULL,
    course_outcome_id BIGINT NOT NULL REFERENCES academics.course_outcomes(course_outcome_id),
    lesson_plan_book_id BIGINT REFERENCES academics.lesson_plan_books(lesson_plan_book_id),
    page_from VARCHAR(20),page_to VARCHAR(20),planned_periods INTEGER NOT NULL DEFAULT 1,
    planned_date DATE,completion_date DATE,topic_status VARCHAR(20) NOT NULL DEFAULT 'Planned'
      CHECK (topic_status IN ('Planned','In Progress','Completed','Deferred')),
    remarks TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT REFERENCES users(user_id),updated_at TIMESTAMPTZ,updated_by BIGINT REFERENCES users(user_id),
    UNIQUE (lesson_plan_id,lesson_number)
  )`);
  await pool.query(`ALTER TABLE academics.lesson_plan_topics
    ADD COLUMN IF NOT EXISTS ppt_required BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE academics.lesson_plan_topics
    ADD COLUMN IF NOT EXISTS video_url TEXT`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.lesson_plan_topic_outcomes (
    lesson_plan_topic_id BIGINT NOT NULL REFERENCES academics.lesson_plan_topics(lesson_plan_topic_id) ON DELETE CASCADE,
    course_outcome_id BIGINT NOT NULL REFERENCES academics.course_outcomes(course_outcome_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT REFERENCES users(user_id),
    PRIMARY KEY (lesson_plan_topic_id,course_outcome_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS academics.lecture_notes (
    lecture_note_id BIGSERIAL PRIMARY KEY,
    subject_master_id BIGINT NOT NULL REFERENCES subject_masters(subject_master_id),
    unit_name VARCHAR(80) NOT NULL,
    note_title VARCHAR(250) NOT NULL,
    file_name VARCHAR(255),
    file_mime_type VARCHAR(120),
    file_size BIGINT,
    file_data BYTEA,
    note_url TEXT,
    description TEXT,
    publish_status VARCHAR(20) NOT NULL DEFAULT 'Draft'
      CHECK (publish_status IN ('Draft','Published','Submitted')),
    created_by BIGINT REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ,
    CHECK (file_data IS NOT NULL OR note_url IS NOT NULL)
  )`);
  await pool.query(`ALTER TABLE academics.lecture_notes ADD COLUMN IF NOT EXISTS material_type
    VARCHAR(20) NOT NULL DEFAULT 'LECTURE_NOTE'`);
  await pool.query('ALTER TABLE academics.lecture_notes ADD COLUMN IF NOT EXISTS duration_minutes INTEGER');
  await pool.query(`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='lecture_notes_duration_check') THEN
      ALTER TABLE academics.lecture_notes ADD CONSTRAINT lecture_notes_duration_check
        CHECK (duration_minutes IS NULL OR duration_minutes > 0);
    END IF;
  END $$`);
  await pool.query(`ALTER TABLE academics.lecture_notes DROP CONSTRAINT IF EXISTS lecture_notes_publish_status_check`);
  await pool.query(`ALTER TABLE academics.lecture_notes ADD CONSTRAINT lecture_notes_publish_status_check
    CHECK (publish_status IN ('Draft','Published','Submitted'))`);
  await pool.query(`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='lecture_notes_material_type_check') THEN
      ALTER TABLE academics.lecture_notes ADD CONSTRAINT lecture_notes_material_type_check
        CHECK (material_type IN ('LECTURE_NOTE','VIDEO_LECTURE','PPT'));
    END IF;
  END $$`);
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS marital_status VARCHAR(20)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS alternate_mobile VARCHAR(20)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS permanent_address TEXT');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS aadhaar_number VARCHAR(20)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS pan_number VARCHAR(20)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS employee_category VARCHAR(40)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS campus_id BIGINT REFERENCES campuses(campus_id)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS reporting_employee_id BIGINT REFERENCES employees(employee_id)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_name VARCHAR(150)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_account_number VARCHAR(50)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_ifsc VARCHAR(20)');
  await pool.query('ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_branch VARCHAR(150)');
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS document_names JSONB NOT NULL DEFAULT '[]'::jsonb");
  await pool.query('ALTER TABLE designations ADD COLUMN IF NOT EXISTS short_name VARCHAR(50)');
  await pool.query("ALTER TABLE designations ADD COLUMN IF NOT EXISTS designation_type VARCHAR(30) NOT NULL DEFAULT 'TEACHING'");
  await pool.query('ALTER TABLE designations ADD COLUMN IF NOT EXISTS designation_level INTEGER');
  await pool.query('ALTER TABLE designations ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE');
  await pool.query(`CREATE TABLE IF NOT EXISTS common_master_types (
    master_type_id BIGSERIAL PRIMARY KEY,
    institute_id BIGINT NOT NULL REFERENCES institutions(institution_id),
    master_type_code VARCHAR(50) NOT NULL, master_type_name VARCHAR(150) NOT NULL,
    description TEXT, used_in VARCHAR(300), is_system BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT REFERENCES users(user_id), updated_at TIMESTAMPTZ,
    updated_by BIGINT REFERENCES users(user_id), UNIQUE(institute_id,master_type_code)
  )`);
  await pool.query(`INSERT INTO common_master_types (institute_id,master_type_code,master_type_name)
    SELECT i.institution_id,v.code,v.name FROM
      (VALUES ('BLOOD_GROUP','Blood Group'),('MARITAL_STATUS','Marital Status'),
       ('EMPLOYEE_CATEGORY','Employee Category'),('EMPLOYEE_TYPE','Employee Type'),
       ('DOCUMENT_TYPE','Document Type'),('RELIGION','Religion'),('NATIONALITY','Nationality')) v(code,name)
    CROSS JOIN LATERAL (SELECT institution_id FROM institutions WHERE is_active=TRUE ORDER BY institution_id LIMIT 1) i
    ON CONFLICT (institute_id,master_type_code) DO NOTHING`);
  await pool.query(`CREATE TABLE IF NOT EXISTS common_master_values (
    master_value_id BIGSERIAL PRIMARY KEY,
    master_type_id BIGINT NOT NULL REFERENCES common_master_types(master_type_id) ON DELETE CASCADE,
    value_code VARCHAR(50) NOT NULL, value_name VARCHAR(200) NOT NULL, short_name VARCHAR(100),
    display_order INTEGER DEFAULT 0, is_default BOOLEAN DEFAULT FALSE, is_active BOOLEAN DEFAULT TRUE,
    remarks TEXT, created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT REFERENCES users(user_id), updated_at TIMESTAMPTZ,
    updated_by BIGINT REFERENCES users(user_id),
    UNIQUE (master_type_id,value_code), UNIQUE (master_type_id,value_name)
  )`);
  await pool.query('ALTER TABLE common_master_values ADD COLUMN IF NOT EXISTS master_type_id BIGINT REFERENCES common_master_types(master_type_id) ON DELETE CASCADE');
  await pool.query('ALTER TABLE common_master_values ADD COLUMN IF NOT EXISTS short_name VARCHAR(100)');
  await pool.query('ALTER TABLE common_master_values ADD COLUMN IF NOT EXISTS is_default BOOLEAN DEFAULT FALSE');
  await pool.query('ALTER TABLE common_master_values ADD COLUMN IF NOT EXISTS remarks TEXT');
  await pool.query('ALTER TABLE common_master_values ADD COLUMN IF NOT EXISTS created_by BIGINT REFERENCES users(user_id)');
  await pool.query('ALTER TABLE common_master_values ADD COLUMN IF NOT EXISTS updated_by BIGINT REFERENCES users(user_id)');
  await pool.query('ALTER TABLE common_master_values ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ');
  await pool.query(`DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='common_master_values' AND column_name='master_type') THEN
      INSERT INTO common_master_types (institute_id,master_type_code,master_type_name)
        SELECT i.institution_id,v.master_type,INITCAP(REPLACE(v.master_type,'_',' '))
        FROM (SELECT DISTINCT master_type FROM common_master_values WHERE master_type IS NOT NULL) v
        CROSS JOIN LATERAL (SELECT institution_id FROM institutions WHERE is_active=TRUE ORDER BY institution_id LIMIT 1) i
        ON CONFLICT (institute_id,master_type_code) DO NOTHING;
      UPDATE common_master_values v SET master_type_id=t.master_type_id
        FROM common_master_types t WHERE v.master_type_id IS NULL AND t.master_type_code=v.master_type;
      ALTER TABLE common_master_values DROP COLUMN master_type;
    END IF;
  END $$`);
  await pool.query('ALTER TABLE common_master_values ALTER COLUMN master_type_id SET NOT NULL');
  await pool.query('ALTER TABLE common_master_values ALTER COLUMN value_code TYPE VARCHAR(50)');
  await pool.query('ALTER TABLE common_master_values ALTER COLUMN value_name TYPE VARCHAR(200)');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS uq_common_master_type_code ON common_master_values(master_type_id,value_code)');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS uq_common_master_type_name ON common_master_values(master_type_id,value_name)');
  await pool.query(`CREATE TABLE IF NOT EXISTS libraries (
    library_id BIGSERIAL PRIMARY KEY,
    institution_id BIGINT NOT NULL REFERENCES institutions(institution_id) ON DELETE CASCADE,
    campus_id BIGINT REFERENCES campuses(campus_id) ON DELETE SET NULL,
    library_code VARCHAR(30) NOT NULL,
    library_name VARCHAR(150) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (institution_id, library_code),
    UNIQUE (institution_id, library_name)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_almiras (
    almira_id BIGSERIAL PRIMARY KEY,
    library_id BIGINT NOT NULL REFERENCES libraries(library_id) ON DELETE CASCADE,
    room_id BIGINT REFERENCES rooms(room_id) ON DELETE SET NULL,
    almira_code VARCHAR(30) NOT NULL,
    almira_name VARCHAR(120) NOT NULL,
    number_of_shelves INTEGER NOT NULL CHECK (number_of_shelves > 0),
    capacity INTEGER NOT NULL CHECK (capacity > 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (library_id, almira_code)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_authors (
    author_id BIGSERIAL PRIMARY KEY, author_code VARCHAR(30) UNIQUE, author_name VARCHAR(200) NOT NULL,
    alias VARCHAR(120), is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id),
    UNIQUE (author_name)
  )`);
  await pool.query('ALTER TABLE library_authors ADD COLUMN IF NOT EXISTS author_code VARCHAR(30)');
  await pool.query(`UPDATE library_authors SET author_code='AUTH'||LPAD(author_id::text,4,'0') WHERE author_code IS NULL`);
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS uq_library_authors_code ON library_authors(author_code)');
  await pool.query(`CREATE TABLE IF NOT EXISTS library_titles (
    title_id BIGSERIAL PRIMARY KEY, title_code VARCHAR(30) UNIQUE,
    title_name VARCHAR(250) NOT NULL UNIQUE, short_name VARCHAR(120), subtitle VARCHAR(250),
    language VARCHAR(80), description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query('ALTER TABLE library_titles ADD COLUMN IF NOT EXISTS subtitle VARCHAR(250)');
  await pool.query('ALTER TABLE library_titles ADD COLUMN IF NOT EXISTS language VARCHAR(80)');
  await pool.query('ALTER TABLE library_titles ADD COLUMN IF NOT EXISTS description TEXT');
  await pool.query(`UPDATE library_titles SET title_code='TIT'||LPAD(title_id::text,4,'0') WHERE title_code IS NULL`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_categories (
    category_id BIGSERIAL PRIMARY KEY, category_code VARCHAR(30) UNIQUE NOT NULL,
    category_name VARCHAR(200) UNIQUE NOT NULL,
    parent_category_id BIGINT REFERENCES library_categories(category_id) ON DELETE SET NULL,
    issue_allowed BOOLEAN NOT NULL DEFAULT TRUE, is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_subjects (
    subject_id BIGSERIAL PRIMARY KEY, subject_code VARCHAR(30) UNIQUE NOT NULL,
    subject_name VARCHAR(200) NOT NULL, subject_alias VARCHAR(120),
    department_id BIGINT NOT NULL REFERENCES departments(department_id),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id),
    UNIQUE (department_id, subject_name)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_publishers (
    publisher_id BIGSERIAL PRIMARY KEY, publisher_code VARCHAR(30) UNIQUE NOT NULL,
    publisher_name VARCHAR(250) UNIQUE NOT NULL, contact_person VARCHAR(150),
    phone VARCHAR(30), email VARCHAR(150), website VARCHAR(250), address TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by BIGINT REFERENCES users(user_id), updated_at TIMESTAMPTZ,
    updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_suppliers (
    supplier_id BIGSERIAL PRIMARY KEY, supplier_code VARCHAR(30) UNIQUE NOT NULL,
    supplier_name VARCHAR(200) UNIQUE NOT NULL, contact_person VARCHAR(150),
    phone VARCHAR(30), email VARCHAR(150), gst_number VARCHAR(30), pan_number VARCHAR(20),
    address TEXT, payment_terms VARCHAR(250), is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_books (
    book_id BIGSERIAL PRIMARY KEY, isbn VARCHAR(30) UNIQUE NOT NULL,
    title_id BIGINT NOT NULL REFERENCES library_titles(title_id),
    author_id BIGINT NOT NULL REFERENCES library_authors(author_id),
    publisher_id BIGINT NOT NULL REFERENCES library_publishers(publisher_id),
    category_id BIGINT NOT NULL REFERENCES library_categories(category_id),
    subject_id BIGINT NOT NULL REFERENCES library_subjects(subject_id),
    edition VARCHAR(50), publication_year INTEGER CHECK (publication_year BETWEEN 1000 AND 9999),
    language VARCHAR(80), pages INTEGER CHECK (pages > 0), book_type VARCHAR(50) NOT NULL,
    description TEXT, is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS title_id BIGINT REFERENCES library_titles(title_id)');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS author_id BIGINT REFERENCES library_authors(author_id)');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS publisher_id BIGINT REFERENCES library_publishers(publisher_id)');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES library_categories(category_id)');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS subject_id BIGINT REFERENCES library_subjects(subject_id)');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS pages INTEGER');
  await pool.query("ALTER TABLE library_books ADD COLUMN IF NOT EXISTS book_type VARCHAR(50) NOT NULL DEFAULT 'Text Book'");
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS description TEXT');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS created_by BIGINT REFERENCES users(user_id)');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE library_books ADD COLUMN IF NOT EXISTS updated_by BIGINT REFERENCES users(user_id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS library_purchase_orders (
    purchase_order_id BIGSERIAL PRIMARY KEY, po_number VARCHAR(40) UNIQUE NOT NULL,
    supplier_id BIGINT NOT NULL REFERENCES library_suppliers(supplier_id),
    order_date DATE NOT NULL DEFAULT CURRENT_DATE, status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS expected_delivery DATE');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS delivery_address TEXT');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS terms_conditions TEXT');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS subtotal NUMERIC(14,2) NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS discount_total NUMERIC(14,2) NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS tax_total NUMERIC(14,2) NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS grand_total NUMERIC(14,2) NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE library_purchase_orders ADD COLUMN IF NOT EXISTS approved_by BIGINT REFERENCES users(user_id)');
  await pool.query("ALTER TABLE library_purchase_orders ALTER COLUMN status SET DEFAULT 'DRAFT'");
  await pool.query(`CREATE TABLE IF NOT EXISTS library_purchase_order_items (
    purchase_order_item_id BIGSERIAL PRIMARY KEY,
    purchase_order_id BIGINT NOT NULL REFERENCES library_purchase_orders(purchase_order_id) ON DELETE CASCADE,
    item_type VARCHAR(30) NOT NULL, book_id BIGINT REFERENCES library_books(book_id),
    item_name VARCHAR(250) NOT NULL, quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price NUMERIC(12,2) NOT NULL CHECK (unit_price >= 0),
    discount NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (discount >= 0),
    tax NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (tax >= 0),
    line_total NUMERIC(14,2) NOT NULL CHECK (line_total >= 0)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_purchase_invoices (
    invoice_id BIGSERIAL PRIMARY KEY, invoice_number VARCHAR(50) UNIQUE NOT NULL,
    invoice_date DATE NOT NULL, supplier_id BIGINT NOT NULL REFERENCES library_suppliers(supplier_id),
    purchase_order_id BIGINT REFERENCES library_purchase_orders(purchase_order_id),
    payment_status VARCHAR(30) NOT NULL DEFAULT 'PENDING', invoice_file_name VARCHAR(250),
    stock_status VARCHAR(20) NOT NULL DEFAULT 'DRAFT', invoice_total NUMERIC(14,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    posted_at TIMESTAMPTZ, posted_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_purchase_invoice_items (
    invoice_item_id BIGSERIAL PRIMARY KEY,
    invoice_id BIGINT NOT NULL REFERENCES library_purchase_invoices(invoice_id) ON DELETE CASCADE,
    book_id BIGINT NOT NULL REFERENCES library_books(book_id),
    ordered_quantity INTEGER NOT NULL CHECK (ordered_quantity >= 0),
    received_quantity INTEGER NOT NULL CHECK (received_quantity > 0),
    unit_price NUMERIC(12,2) NOT NULL CHECK (unit_price >= 0),
    line_total NUMERIC(14,2) NOT NULL CHECK (line_total >= 0)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_book_stock (
    book_id BIGINT PRIMARY KEY REFERENCES library_books(book_id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_study_materials (
    study_material_id BIGSERIAL PRIMARY KEY, material_code VARCHAR(30) UNIQUE NOT NULL,
    material_name VARCHAR(200) UNIQUE NOT NULL, is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query("ALTER TABLE library_study_materials ADD COLUMN IF NOT EXISTS material_type VARCHAR(50) NOT NULL DEFAULT 'OTHER'");
  await pool.query('ALTER TABLE library_study_materials ADD COLUMN IF NOT EXISTS subject_id BIGINT REFERENCES library_subjects(subject_id)');
  await pool.query('ALTER TABLE library_study_materials ADD COLUMN IF NOT EXISTS academic_year_id BIGINT REFERENCES academic_years(academic_year_id)');
  await pool.query('ALTER TABLE library_study_materials ADD COLUMN IF NOT EXISTS current_stock INTEGER NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE library_study_materials ADD COLUMN IF NOT EXISTS minimum_stock INTEGER NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE library_study_materials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE library_study_materials ADD COLUMN IF NOT EXISTS updated_by BIGINT REFERENCES users(user_id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS library_study_material_prices (
    price_id BIGSERIAL PRIMARY KEY,
    study_material_id BIGINT NOT NULL REFERENCES library_study_materials(study_material_id),
    effective_from DATE NOT NULL, purchase_price NUMERIC(12,2) NOT NULL CHECK (purchase_price >= 0),
    selling_price NUMERIC(12,2) NOT NULL CHECK (selling_price >= 0),
    student_price NUMERIC(12,2) NOT NULL CHECK (student_price >= 0),
    staff_price NUMERIC(12,2) NOT NULL CHECK (staff_price >= 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id),
    UNIQUE (study_material_id,effective_from)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_study_material_issues (
    material_issue_id BIGSERIAL PRIMARY KEY,
    study_material_id BIGINT NOT NULL REFERENCES library_study_materials(study_material_id),
    department_id BIGINT REFERENCES departments(department_id),
    recipient_code VARCHAR(50) NOT NULL, recipient_name VARCHAR(200) NOT NULL,
    recipient_type VARCHAR(30) NOT NULL, quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (unit_price >= 0),
    amount NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (amount >= 0),
    issued_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query('ALTER TABLE library_study_material_issues ADD COLUMN IF NOT EXISTS issue_number VARCHAR(40)');
  await pool.query('ALTER TABLE library_study_material_issues ADD COLUMN IF NOT EXISTS programme VARCHAR(150)');
  await pool.query("ALTER TABLE library_study_material_issues ADD COLUMN IF NOT EXISTS payment_status VARCHAR(20) NOT NULL DEFAULT 'PENDING'");
  await pool.query('ALTER TABLE library_study_material_issues ADD COLUMN IF NOT EXISTS remarks TEXT');
  await pool.query(`UPDATE library_study_material_issues SET issue_number='SMI-'||LPAD(material_issue_id::text,6,'0') WHERE issue_number IS NULL`);
  await pool.query('ALTER TABLE library_study_material_issues ALTER COLUMN issue_number SET NOT NULL');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS uq_library_study_material_issue_number ON library_study_material_issues(issue_number)');
  await pool.query(`CREATE TABLE IF NOT EXISTS library_issue_types (
    issue_type_id BIGSERIAL PRIMARY KEY, issue_type_code VARCHAR(30) UNIQUE NOT NULL,
    issue_type_name VARCHAR(150) UNIQUE NOT NULL, member_type VARCHAR(30) NOT NULL,
    maximum_books INTEGER NOT NULL CHECK (maximum_books > 0),
    issue_duration_days INTEGER NOT NULL CHECK (issue_duration_days > 0),
    fine_per_day NUMERIC(10,2) NOT NULL DEFAULT 0 CHECK (fine_per_day >= 0),
    renewal_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    maximum_renewals INTEGER NOT NULL DEFAULT 0 CHECK (maximum_renewals >= 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS student_branches (
    branch_id BIGSERIAL PRIMARY KEY, department_id BIGINT NOT NULL REFERENCES departments(department_id),
    programme_id BIGINT NOT NULL REFERENCES programmes(programme_id), branch_code VARCHAR(30) NOT NULL,
    branch_name VARCHAR(150) NOT NULL, is_active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (programme_id,branch_code), UNIQUE (programme_id,branch_name)
  )`);
  await pool.query('ALTER TABLE programmes ADD COLUMN IF NOT EXISTS programme_alias VARCHAR(100)');
  await pool.query("ALTER TABLE programmes ADD COLUMN IF NOT EXISTS programme_type VARCHAR(40) NOT NULL DEFAULT 'UNDERGRADUATE'");
  await pool.query("ALTER TABLE programmes ADD COLUMN IF NOT EXISTS award_type VARCHAR(40) NOT NULL DEFAULT 'DEGREE'");
  await pool.query('ALTER TABLE programmes ADD COLUMN IF NOT EXISTS affiliating_university VARCHAR(200)');
  await pool.query("ALTER TABLE programmes ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'");
  await pool.query('ALTER TABLE admission_batches ADD COLUMN IF NOT EXISTS batch_alias VARCHAR(50)');
  await pool.query('ALTER TABLE admission_batches ADD COLUMN IF NOT EXISTS approved_intake INTEGER NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE admission_batches ADD COLUMN IF NOT EXISTS lateral_entry_intake INTEGER NOT NULL DEFAULT 0');
  await pool.query("ALTER TABLE admission_batches ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'");
  await pool.query('ALTER TABLE students ADD COLUMN IF NOT EXISTS branch_id BIGINT REFERENCES student_branches(branch_id)');
  await pool.query("ALTER TABLE students ADD COLUMN IF NOT EXISTS student_profile_details JSONB NOT NULL DEFAULT '{}'::jsonb");
  await pool.query(`CREATE TABLE IF NOT EXISTS section_masters (
    section_master_id BIGSERIAL PRIMARY KEY, section_master_code VARCHAR(30) UNIQUE NOT NULL,
    section_master_name VARCHAR(100) UNIQUE NOT NULL, is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ, updated_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query('ALTER TABLE sections ADD COLUMN IF NOT EXISTS section_master_id BIGINT REFERENCES section_masters(section_master_id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS programme_section_merges (
    merge_id BIGSERIAL PRIMARY KEY, programme_id BIGINT NOT NULL REFERENCES programmes(programme_id),
    batch_id BIGINT NOT NULL REFERENCES admission_batches(batch_id), semester_id BIGINT NOT NULL REFERENCES semesters(semester_id),
    target_section_id BIGINT REFERENCES sections(section_id), source_sections TEXT NOT NULL,
    target_section_name VARCHAR(100) NOT NULL, total_students INTEGER NOT NULL DEFAULT 0,
    target_capacity INTEGER NOT NULL, effective_date DATE NOT NULL, merge_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS section_merge_groups (
    merge_group_id BIGSERIAL PRIMARY KEY,
    first_section_id BIGINT NOT NULL REFERENCES sections(section_id),
    second_section_id BIGINT NOT NULL REFERENCES sections(section_id),
    merged_section_name VARCHAR(150) NOT NULL,
    total_students INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by BIGINT REFERENCES users(user_id),
    updated_at TIMESTAMPTZ,
    updated_by BIGINT REFERENCES users(user_id),
    CHECK (first_section_id <> second_section_id),
    CHECK (status IN ('ACTIVE','INACTIVE'))
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_book_copies (
    book_copy_id BIGSERIAL PRIMARY KEY, book_id BIGINT NOT NULL REFERENCES library_books(book_id),
    accession_number VARCHAR(50) UNIQUE NOT NULL, copy_status VARCHAR(30) NOT NULL DEFAULT 'AVAILABLE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS library_book_issues (
    book_issue_id BIGSERIAL PRIMARY KEY, book_copy_id BIGINT NOT NULL REFERENCES library_book_copies(book_copy_id),
    issue_type_id BIGINT NOT NULL REFERENCES library_issue_types(issue_type_id),
    member_code VARCHAR(50) NOT NULL, member_name VARCHAR(200) NOT NULL,
    member_type VARCHAR(30) NOT NULL, department_id BIGINT REFERENCES departments(department_id),
    contact_number VARCHAR(30), issue_date DATE NOT NULL, due_date DATE NOT NULL,
    returned_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by BIGINT REFERENCES users(user_id)
  )`);
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS designation VARCHAR(150)');
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS programme VARCHAR(150)');
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS semester VARCHAR(50)');
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS issue_remarks TEXT');
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS fine_amount NUMERIC(12,2) NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS book_condition VARCHAR(30)');
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS return_remarks TEXT');
  await pool.query('ALTER TABLE library_book_issues ADD COLUMN IF NOT EXISTS issue_number VARCHAR(40)');
  await pool.query(`UPDATE library_book_issues SET issue_number='ISS-'||LPAD(book_issue_id::text,6,'0') WHERE issue_number IS NULL`);
  await pool.query('ALTER TABLE library_book_issues ALTER COLUMN issue_number SET NOT NULL');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS uq_library_book_issues_number ON library_book_issues(issue_number)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_library_book_issues_pending ON library_book_issues(due_date) WHERE returned_at IS NULL');
  await pool.query(`CREATE TABLE IF NOT EXISTS library_student_members (
    student_member_id BIGSERIAL PRIMARY KEY, roll_number VARCHAR(50) UNIQUE NOT NULL,
    student_name VARCHAR(200) NOT NULL, programme VARCHAR(150) NOT NULL,
    department_id BIGINT REFERENCES departments(department_id), semester VARCHAR(50),
    contact_number VARCHAR(30), is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`INSERT INTO libraries (institution_id,campus_id,library_code,library_name)
    SELECT i.institution_id,c.campus_id,'CENTRAL','Central Library'
    FROM institutions i LEFT JOIN LATERAL (
      SELECT campus_id FROM campuses WHERE institution_id=i.institution_id ORDER BY campus_id LIMIT 1
    ) c ON TRUE
    WHERE NOT EXISTS (SELECT 1 FROM libraries WHERE institution_id=i.institution_id)
    ORDER BY i.institution_id LIMIT 1`);

  await pool.query('CREATE SCHEMA IF NOT EXISTS communication');
  await pool.query(`CREATE TABLE IF NOT EXISTS communication.sms_templates (
    sms_template_id BIGSERIAL PRIMARY KEY,
    template_name VARCHAR(150) NOT NULL,
    template_code VARCHAR(50) NOT NULL UNIQUE,
    recipient_type VARCHAR(20) NOT NULL CHECK (recipient_type IN ('Student','Guardian','Employee','General')),
    template_message TEXT NOT NULL,
    language_code VARCHAR(10) NOT NULL DEFAULT 'en',
    is_unicode BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS communication.sms_batches (
    sms_batch_id BIGSERIAL PRIMARY KEY,
    batch_reference VARCHAR(50) NOT NULL UNIQUE,
    recipient_category VARCHAR(30) NOT NULL,
    sms_template_id BIGINT REFERENCES communication.sms_templates(sms_template_id) ON DELETE SET NULL,
    message_text TEXT NOT NULL,
    language_code VARCHAR(10) NOT NULL DEFAULT 'en',
    sender_id VARCHAR(30) NOT NULL DEFAULT 'ABITCLG',
    send_type VARCHAR(20) NOT NULL CHECK (send_type IN ('Immediate','Scheduled')),
    scheduled_at TIMESTAMPTZ,
    batch_status VARCHAR(25) NOT NULL DEFAULT 'Queued',
    total_recipients INTEGER NOT NULL DEFAULT 0,
    created_by BIGINT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMPTZ,
    CHECK (send_type='Immediate' OR scheduled_at IS NOT NULL)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS communication.sms_recipients (
    sms_recipient_id BIGSERIAL PRIMARY KEY,
    sms_batch_id BIGINT NOT NULL REFERENCES communication.sms_batches(sms_batch_id) ON DELETE CASCADE,
    recipient_type VARCHAR(20) NOT NULL CHECK (recipient_type IN ('Student','Guardian','Employee')),
    student_id BIGINT REFERENCES students(student_id) ON DELETE SET NULL,
    employee_id BIGINT REFERENCES employees(employee_id) ON DELETE SET NULL,
    recipient_name VARCHAR(200) NOT NULL,
    mobile_number VARCHAR(20) NOT NULL,
    personalized_message TEXT NOT NULL,
    sms_parts SMALLINT NOT NULL DEFAULT 1 CHECK (sms_parts > 0),
    recipient_status VARCHAR(25) NOT NULL DEFAULT 'Queued',
    sent_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (student_id IS NOT NULL OR employee_id IS NOT NULL)
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS idx_sms_batches_created_at ON communication.sms_batches(created_at DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_sms_recipients_batch ON communication.sms_recipients(sms_batch_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_sms_recipients_status ON communication.sms_recipients(recipient_status)');
  await pool.query(`INSERT INTO communication.sms_templates
    (template_name,template_code,recipient_type,template_message)
    VALUES ('Attendance Alert','ATTENDANCE_ALERT','Student','Dear {{student_name}}, your attendance is {{attendance_percentage}}%.'),
      ('Staff Meeting','STAFF_MEETING','Employee','Dear {{employee_name}}, a faculty meeting is scheduled. Please attend on time.')
    ON CONFLICT (template_code) DO NOTHING`);

  const existing = await pool.query("SELECT 1 FROM users WHERE user_type IN ('ADMIN','SUPER_ADMIN','INSTITUTE_ADMIN') LIMIT 1");
  if (!existing.rowCount) {
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'ABIT@123';
    const passwordHash = await hashPassword(password);
    await pool.query(
      `INSERT INTO users (username,password_hash,email,display_name,user_type,must_change_password)
       VALUES ($1,$2,$3,$4,'ADMIN',FALSE) ON CONFLICT (username) DO NOTHING`,
      [username, passwordHash, process.env.ADMIN_EMAIL || null, 'Administrator']
    );
    console.log(`Initial admin account created for username "${username}". Set ADMIN_PASSWORD in .env to change the initial password.`);
  }
}

function getClientIp(req) {
  const ip = req.ip?.replace('::ffff:', '');
  return ip === '::1' ? '127.0.0.1' : ip || null;
}

function getClientDetails(req){
  const userAgent=String(req.get('user-agent')||'');
  const browserName=/Edg\//.test(userAgent)?'Microsoft Edge':/OPR\//.test(userAgent)?'Opera':
    /Chrome\//.test(userAgent)?'Google Chrome':/Firefox\//.test(userAgent)?'Mozilla Firefox':
    /Safari\//.test(userAgent)?'Safari':'Unknown';
  const operatingSystem=/Windows NT/.test(userAgent)?'Windows':/Android/.test(userAgent)?'Android':
    /iPhone|iPad/.test(userAgent)?'iOS':/Mac OS X/.test(userAgent)?'macOS':
    /Linux/.test(userAgent)?'Linux':'Unknown';
  const deviceType=/Tablet|iPad/i.test(userAgent)?'Tablet':/Mobile|Android|iPhone/i.test(userAgent)?'Mobile':'Desktop';
  return {userAgent,browserName,operatingSystem,deviceType};
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token && session) {
      sessions.delete(token);
      if(session.loginHistoryId)pool.query(`UPDATE login_history SET logout_at=NOW(),last_activity_at=NOW(),
        login_status='Session Expired',logout_type='Session Expired' WHERE login_history_id=$1 AND login_status='Active'`,
        [session.loginHistoryId]).catch(()=>{});
    }
    return res.status(401).json({ ok: false, message: 'Your session has expired. Please sign in again.' });
  }
  req.auth = { token, ...session };
  if(session.loginHistoryId)pool.query('UPDATE login_history SET last_activity_at=NOW() WHERE login_history_id=$1',[session.loginHistoryId]).catch(()=>{});
  next();
}

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ status: 'ok', database: 'connected' }); }
  catch { res.status(503).json({ status: 'error', database: 'unavailable' }); }
});

app.get('/api/dashboard-counts', authenticate, async (_req,res)=>{
  try{const [students,employees,departments,subjects,books,departmentCapacity,programmeIntakes,messages,notices,birthdayEmployees]=await Promise.all([
    pool.query(`SELECT COUNT(*)::INTEGER AS count FROM students WHERE is_active=TRUE AND COALESCE(is_deleted,FALSE)=FALSE`),
    pool.query(`SELECT COUNT(*)::INTEGER AS count FROM employees WHERE UPPER(COALESCE(status,''))='ACTIVE'`),
    pool.query(`SELECT COUNT(*)::INTEGER AS count FROM departments WHERE is_active=TRUE`),
    pool.query(`SELECT COUNT(*)::INTEGER AS count FROM subject_masters WHERE is_active=TRUE`),
    pool.query(`SELECT COUNT(*)::INTEGER AS count FROM library_books WHERE is_active=TRUE`),
    pool.query(`SELECT d.department_id AS id,d.department_code AS code,d.department_name AS name,
        COALESCE(SUM(p.intake_capacity),0)::INTEGER AS capacity
      FROM departments d
      LEFT JOIN programmes p ON p.department_id=d.department_id AND p.is_active=TRUE
      WHERE d.is_active=TRUE
        AND (d.department_name ILIKE '%ENGINEER%' OR d.department_name ILIKE '%TECHNOLOGY%')
      GROUP BY d.department_id,d.department_code,d.department_name
      HAVING COALESCE(SUM(p.intake_capacity),0)>0
      ORDER BY capacity DESC,d.department_name
      LIMIT 6`),
    pool.query(`SELECT programme_id AS id,programme_code AS code,programme_name AS name,
        COALESCE(intake_capacity,0)::INTEGER AS intake
      FROM programmes WHERE is_active=TRUE
      ORDER BY programme_name LIMIT 8`),
    pool.query(`SELECT dashboard_message_id AS id,message_title AS title,message_text AS message,
        priority,display_style,display_from,display_to
      FROM dashboard_messages
      WHERE show_on_dashboard=TRUE AND status='Active'
        AND display_from<=CURRENT_DATE
        AND (display_to IS NULL OR display_to>=CURRENT_DATE)
        AND audience_type IN ('All Users','Administrators')
      ORDER BY display_order,CASE priority WHEN 'Urgent' THEN 1 WHEN 'High' THEN 2 WHEN 'Normal' THEN 3 ELSE 4 END,created_at DESC`),
    pool.query(`SELECT notice_id AS id,notice_number,notice_title,notice_description,
        notice_category,notice_date,priority,is_pinned,requires_acknowledgment,
        attachment_path,external_link,publish_from,publish_to,
        (publish_from<=CURRENT_TIMESTAMP AND (publish_to IS NULL OR publish_to>=CURRENT_TIMESTAMP)) AS is_current
      FROM dashboard_notices
      WHERE notice_status='Published'
      ORDER BY (publish_from<=CURRENT_TIMESTAMP AND (publish_to IS NULL OR publish_to>=CURRENT_TIMESTAMP)) DESC,
        is_pinned DESC,
        CASE priority WHEN 'Urgent' THEN 1 WHEN 'High' THEN 2 WHEN 'Normal' THEN 3 ELSE 4 END,
        notice_date DESC,created_at DESC`),
    pool.query(`SELECT e.employee_id AS id,e.employee_code,
        TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,
        e.date_of_birth,e.photo_url,d.department_name,dg.designation_name
      FROM employees e
      LEFT JOIN departments d ON d.department_id=e.department_id
      LEFT JOIN designations dg ON dg.designation_id=e.designation_id
      WHERE e.date_of_birth IS NOT NULL AND UPPER(COALESCE(e.status,'ACTIVE'))='ACTIVE'
      ORDER BY
        CASE WHEN TO_CHAR(e.date_of_birth,'MMDD')>=TO_CHAR(CURRENT_DATE,'MMDD') THEN 0 ELSE 1 END,
        TO_CHAR(e.date_of_birth,'MMDD'),e.employee_code
      LIMIT 5`)
  ]);res.json({ok:true,activeStudents:students.rows[0].count,activeEmployees:employees.rows[0].count,activeDepartments:departments.rows[0].count,activeSubjects:subjects.rows[0].count,activeBooks:books.rows[0].count,
    departmentSeatCapacity:departmentCapacity.rows,programmeIntakes:programmeIntakes.rows,dashboardMessages:messages.rows,
    dashboardNotices:notices.rows,birthdayEmployees:birthdayEmployees.rows});}
  catch(error){res.status(500).json({ok:false,message:'Unable to load dashboard counts.'});}
});

app.get('/api/dashboard-messages', authenticate, async (_req,res)=>{
  try{
    const [departments,programmes,messages]=await Promise.all([
      pool.query(`SELECT department_id AS id,department_code AS code,department_name AS name
        FROM departments WHERE is_active=TRUE ORDER BY department_name`),
      pool.query(`SELECT programme_id AS id,department_id,programme_code AS code,programme_name AS name
        FROM programmes WHERE is_active=TRUE ORDER BY programme_name`),
      pool.query(`SELECT dm.dashboard_message_id AS id,dm.message_title AS title,dm.message_text AS message,
          dm.audience_type,dm.department_id,dm.programme_id,dm.display_from,dm.display_to,
          dm.priority,dm.display_style,dm.show_on_dashboard,dm.status,dm.display_order,
          d.department_name,p.programme_name
        FROM dashboard_messages dm
        LEFT JOIN departments d ON d.department_id=dm.department_id
        LEFT JOIN programmes p ON p.programme_id=dm.programme_id
        ORDER BY dm.created_at DESC`)
    ]);
    res.json({ok:true,departments:departments.rows,programmes:programmes.rows,messages:messages.rows});
  }catch(error){
    console.error('Dashboard messages query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load dashboard messages.'});
  }
});

app.post('/api/dashboard-messages', authenticate, async (req,res)=>{
  const data=req.body||{};
  if(!String(data.title||'').trim()||!String(data.message||'').trim()||!data.displayFrom)
    return res.status(400).json({ok:false,message:'Message title, message, and display start date are required.'});
  if(data.displayTo&&data.displayTo<data.displayFrom)
    return res.status(400).json({ok:false,message:'Display To cannot be earlier than Display From.'});
  const audience=String(data.audience||'All Users');
  const departmentId=audience==='Specific Department'&&data.departmentId?Number(data.departmentId):null;
  const programmeId=audience==='Specific Programme'&&data.programmeId?Number(data.programmeId):null;
  if(audience==='Specific Department'&&!departmentId)
    return res.status(400).json({ok:false,message:'Select a department for this audience.'});
  if(audience==='Specific Programme'&&!programmeId)
    return res.status(400).json({ok:false,message:'Select a programme for this audience.'});
  try{
    const result=await pool.query(`INSERT INTO dashboard_messages
      (message_title,message_text,audience_type,department_id,programme_id,display_from,display_to,
       priority,display_style,show_on_dashboard,status,display_order,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING dashboard_message_id`,[
        data.title.trim(),data.message.trim(),audience,departmentId,programmeId,data.displayFrom,
        data.displayTo||null,data.priority||'Normal',data.displayStyle||'Information',
        data.showOnDashboard!==false,data.status||'Active',Number(data.displayOrder)||1,req.auth.userId
      ]);
    res.status(201).json({ok:true,id:result.rows[0].dashboard_message_id,message:'Dashboard message created successfully.'});
  }catch(error){
    console.error('Dashboard message save error:',error.message);
    res.status(error.code==='23514'?400:500).json({ok:false,message:error.code==='23514'?error.message:'Unable to create dashboard message.'});
  }
});

app.delete('/api/dashboard-messages/:id', authenticate, async (req,res)=>{
  try{
    const result=await pool.query('DELETE FROM dashboard_messages WHERE dashboard_message_id=$1 RETURNING dashboard_message_id',[Number(req.params.id)]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Dashboard message not found.'});
    res.json({ok:true,message:'Dashboard message deleted successfully.'});
  }catch(error){res.status(500).json({ok:false,message:'Unable to delete dashboard message.'});}
});

app.get('/api/dashboard-notices', authenticate, async (_req,res)=>{
  try{
    const [academicYears,departments,programmes,semesters,notices]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(academic_year_name,year_label) AS name
        FROM academic_years WHERE is_active=TRUE ORDER BY start_date DESC`),
      pool.query(`SELECT department_id AS id,department_code AS code,department_name AS name
        FROM departments WHERE is_active=TRUE ORDER BY department_name`),
      pool.query(`SELECT programme_id AS id,department_id,programme_code AS code,programme_name AS name
        FROM programmes WHERE is_active=TRUE ORDER BY programme_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_number,semester_name AS name
        FROM semesters WHERE is_active=TRUE ORDER BY programme_id,semester_number`),
      pool.query(`SELECT n.notice_id AS id,n.academic_year_id,n.notice_number,n.notice_title,
          n.notice_category,n.notice_date,n.notice_description,n.audience_type,n.department_id,
          n.programme_id,n.semester_id,n.publish_from,n.publish_to,n.attachment_path,n.external_link,
          n.priority,n.is_pinned,n.requires_acknowledgment,n.send_notification,n.notice_status,
          d.department_name,p.programme_name,s.semester_name
        FROM dashboard_notices n
        LEFT JOIN departments d ON d.department_id=n.department_id
        LEFT JOIN programmes p ON p.programme_id=n.programme_id
        LEFT JOIN semesters s ON s.semester_id=n.semester_id
        ORDER BY n.is_pinned DESC,n.notice_date DESC,n.created_at DESC`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,departments:departments.rows,
      programmes:programmes.rows,semesters:semesters.rows,notices:notices.rows});
  }catch(error){
    console.error('Dashboard notices query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load dashboard notices.'});
  }
});

function noticeTarget(data){
  const audience=String(data.audience||'All Users');
  return {
    audience,
    departmentId:audience==='Specific Department'&&data.departmentId?Number(data.departmentId):null,
    programmeId:audience==='Specific Programme'&&data.programmeId?Number(data.programmeId):null,
    semesterId:audience==='Specific Semester'&&data.semesterId?Number(data.semesterId):null
  };
}

async function saveDashboardNotice(client,data,userId,id=null){
  const target=noticeTarget(data);
  if(data.publishTo&&new Date(data.publishTo)<new Date(data.publishFrom))throw Object.assign(new Error('Publish To cannot be earlier than Publish From.'),{code:'NOTICE_INPUT'});
  if((data.status||'Draft')==='Published'&&data.publishTo&&new Date(data.publishTo)<new Date())throw Object.assign(new Error('A published notice cannot use an expired Publish To date.'),{code:'NOTICE_INPUT'});
  if(target.audience==='Specific Department'&&!target.departmentId)throw Object.assign(new Error('Select a department for this audience.'),{code:'NOTICE_INPUT'});
  if(target.audience==='Specific Programme'&&!target.programmeId)throw Object.assign(new Error('Select a programme for this audience.'),{code:'NOTICE_INPUT'});
  if(target.audience==='Specific Semester'&&!target.semesterId)throw Object.assign(new Error('Select a semester for this audience.'),{code:'NOTICE_INPUT'});
  const values=[
    data.academicYearId?Number(data.academicYearId):null,String(data.noticeNumber||'').trim().toUpperCase(),
    String(data.title||'').trim(),data.category||'General',data.noticeDate,
    String(data.description||'').trim(),target.audience,target.departmentId,target.programmeId,target.semesterId,
    data.publishFrom,data.publishTo||null,String(data.attachmentPath||'').trim()||null,
    String(data.externalLink||'').trim()||null,data.priority||'Normal',Boolean(data.isPinned),
    Boolean(data.requiresAcknowledgment),data.sendNotification!==false,data.status||'Draft'
  ];
  let noticeId;
  if(id){
    const result=await client.query(`UPDATE dashboard_notices SET academic_year_id=$1,notice_number=$2,
      notice_title=$3,notice_category=$4,notice_date=$5,notice_description=$6,audience_type=$7,
      department_id=$8,programme_id=$9,semester_id=$10,publish_from=$11,publish_to=$12,
      attachment_path=$13,external_link=$14,priority=$15,is_pinned=$16,requires_acknowledgment=$17,
      send_notification=$18,notice_status=$19::VARCHAR,published_by=CASE WHEN $19::VARCHAR='Published' THEN $20::BIGINT ELSE published_by END,
      published_at=CASE WHEN $19::VARCHAR='Published' THEN COALESCE(published_at,NOW()) ELSE published_at END,
      updated_by=$20::BIGINT,updated_at=NOW() WHERE notice_id=$21 RETURNING notice_id`,[...values,userId,id]);
    if(!result.rowCount)throw Object.assign(new Error('Notice not found.'),{code:'NOTICE_NOT_FOUND'});
    noticeId=result.rows[0].notice_id;
    await client.query('DELETE FROM dashboard_notice_audiences WHERE notice_id=$1',[noticeId]);
  }else{
    noticeId=(await client.query(`INSERT INTO dashboard_notices
      (academic_year_id,notice_number,notice_title,notice_category,notice_date,notice_description,
       audience_type,department_id,programme_id,semester_id,publish_from,publish_to,attachment_path,
       external_link,priority,is_pinned,requires_acknowledgment,send_notification,notice_status,
       published_by,published_at,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::VARCHAR,
        CASE WHEN $19::VARCHAR='Published' THEN $20::BIGINT ELSE NULL END,CASE WHEN $19::VARCHAR='Published' THEN NOW() ELSE NULL END,$20::BIGINT)
      RETURNING notice_id`,[...values,userId])).rows[0].notice_id;
  }
  const audienceRow=target.departmentId?['Department',target.departmentId,null,null]:
    target.programmeId?['Programme',null,target.programmeId,null]:
    target.semesterId?['Semester',null,null,target.semesterId]:null;
  if(audienceRow)await client.query(`INSERT INTO dashboard_notice_audiences
    (notice_id,audience_type,department_id,programme_id,semester_id) VALUES ($1,$2,$3,$4,$5)`,[noticeId,...audienceRow]);
  return noticeId;
}

app.post('/api/dashboard-notices', authenticate, async (req,res)=>{
  const data=req.body||{};
  if(!String(data.noticeNumber||'').trim()||!String(data.title||'').trim()||!data.noticeDate||
     !String(data.description||'').trim()||!data.publishFrom)
    return res.status(400).json({ok:false,message:'Notice number, title, date, description, and Publish From are required.'});
  if(data.publishTo&&data.publishTo<data.publishFrom)
    return res.status(400).json({ok:false,message:'Publish To cannot be earlier than Publish From.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');const id=await saveDashboardNotice(client,data,req.auth.userId);
    await client.query('COMMIT');res.status(201).json({ok:true,id,message:'Notice created successfully.'});
  }catch(error){
    await client.query('ROLLBACK');console.error('Dashboard notice save error:',error.message);
    res.status(error.code==='23505'?409:error.code==='NOTICE_INPUT'?400:500).json({ok:false,message:error.code==='23505'?'This notice number already exists.':error.code==='NOTICE_INPUT'?error.message:'Unable to create notice.'});
  }finally{client.release();}
});

app.put('/api/dashboard-notices/:id', authenticate, async (req,res)=>{
  const client=await pool.connect();
  try{
    await client.query('BEGIN');await saveDashboardNotice(client,req.body||{},req.auth.userId,Number(req.params.id));
    await client.query('COMMIT');res.json({ok:true,message:'Notice updated successfully.'});
  }catch(error){
    await client.query('ROLLBACK');console.error('Dashboard notice update error:',error.message);
    res.status(error.code==='23505'?409:error.code==='NOTICE_INPUT'?400:error.code==='NOTICE_NOT_FOUND'?404:500).json({ok:false,message:error.code==='23505'?'This notice number already exists.':error.message||'Unable to update notice.'});
  }finally{client.release();}
});

app.delete('/api/dashboard-notices/:id', authenticate, async (req,res)=>{
  try{
    const result=await pool.query('DELETE FROM dashboard_notices WHERE notice_id=$1 RETURNING notice_id',[Number(req.params.id)]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Notice not found.'});
    res.json({ok:true,message:'Notice deleted successfully.'});
  }catch(error){res.status(500).json({ok:false,message:'Unable to delete notice.'});}
});

app.post('/api/auth/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!username || !password) return res.status(400).json({ ok: false, message: 'Username and password are required.' });
  try {
    const clientDetails=getClientDetails(req);
    const user = await findLoginUser(username);
    const locked = user?.locked_until && new Date(user.locked_until) > new Date();
    const valid = user && user.is_active && !locked && await verifyPassword(password, user.password_hash);
    if (!valid) {
      if (user && !locked && user.auth_source === 'ABDC_DB') {
        await pool.query(`UPDATE "ABDC_DB".user_logins
          SET failed_login_attempts=failed_login_attempts+1,
              account_status=CASE WHEN failed_login_attempts>=4 THEN 'LOCKED' ELSE account_status END,
              updated_at=NOW()
          WHERE user_id=$1`, [user.abdc_user_id]);
      } else if (user && !locked) {
        await pool.query(`UPDATE users SET failed_login_count=failed_login_count+1, locked_until=CASE WHEN failed_login_count>=4 THEN NOW()+INTERVAL '15 minutes' ELSE locked_until END WHERE user_id=$1`, [user.user_id]);
      }
      await pool.query('INSERT INTO login_logs (user_id,username_attempted,login_status,ip_address,user_agent) VALUES ($1,$2,$3,$4,$5)', [user?.user_id || null, username, locked ? 'LOCKED' : 'FAILED', getClientIp(req), req.get('user-agent')]);
      await pool.query(`INSERT INTO login_history
        (user_id,username,ip_address,user_agent,browser_name,operating_system,device_type,
         login_status,login_success,failure_reason,last_activity_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,$9,NOW())`,[
        user?.user_id||null,username,getClientIp(req),clientDetails.userAgent,clientDetails.browserName,
        clientDetails.operatingSystem,clientDetails.deviceType,locked?'Locked':'Failed Login',
        locked?'Account temporarily locked.':'Invalid username or password.'
      ]);
      return res.status(401).json({ ok: false, message: locked ? 'Account temporarily locked. Try again later.' : 'Invalid username or password.' });
    }
    if (user.auth_source === 'ABDC_DB') {
      const legacyUser = (await pool.query(
        `INSERT INTO users (username,password_hash,display_name,user_type,must_change_password,is_active)
         VALUES ($1,$2,$3,'SUPER_ADMIN',$4,TRUE)
         ON CONFLICT (username) DO UPDATE SET password_hash=EXCLUDED.password_hash,
           display_name=EXCLUDED.display_name,user_type='SUPER_ADMIN',
           must_change_password=EXCLUDED.must_change_password,is_active=TRUE,updated_at=NOW()
         RETURNING user_id`,
        [user.username,user.password_hash,user.display_name,user.force_password_change !== false]
      )).rows[0];
      user.user_id = legacyUser.user_id;
      await pool.query(`UPDATE "ABDC_DB".user_logins
        SET failed_login_attempts=0,last_login_at=NOW(),updated_at=NOW() WHERE user_id=$1`, [user.abdc_user_id]);
    } else {
      await pool.query('UPDATE users SET failed_login_count=0,locked_until=NULL,last_login_at=NOW() WHERE user_id=$1', [user.user_id]);
    }
    await pool.query('INSERT INTO login_logs (user_id,username_attempted,login_status,ip_address,user_agent) VALUES ($1,$2,$3,$4,$5)', [user.user_id, username, 'SUCCESS', getClientIp(req), req.get('user-agent')]);
    const token = randomBytes(32).toString('hex');
    const tokenHash=createHash('sha256').update(token).digest('hex');
    const history=(await pool.query(`INSERT INTO login_history
      (user_id,username,ip_address,user_agent,browser_name,operating_system,device_type,
       session_token_hash,login_status,login_success,last_activity_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'Active',TRUE,NOW()) RETURNING login_history_id`,[
      user.user_id,user.username,getClientIp(req),clientDetails.userAgent,clientDetails.browserName,
      clientDetails.operatingSystem,clientDetails.deviceType,tokenHash
    ])).rows[0];
    const session = { userId:user.user_id, abdcUserId:user.abdc_user_id||null, authSource:user.auth_source,
      username:user.username, name:user.display_name || user.username, role:user.user_type,
      photo:user.photo_path||'', loginHistoryId:history.login_history_id, expiresAt:Date.now()+SESSION_MS };
    sessions.set(token, session);
    res.json({ ok:true, token, user:{ username:session.username, name:session.name, role:session.role, photo:session.photo } });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ ok:false, message:'Unable to validate login. Check the database connection.' });
  }
});

app.get('/api/auth/me', authenticate, (req, res) => res.json({ ok:true, user:{ username:req.auth.username, name:req.auth.name, role:req.auth.role, photo:req.auth.photo||'' } }));
app.get('/api/auth/navigation-access', authenticate, async (req,res)=>{
  if(['ADMIN','SUPER_ADMIN','INSTITUTE_ADMIN'].includes(req.auth.role))return res.json({ok:true,isAdmin:true,moduleCodes:[],menuCodes:[]});
  try{
    const account=(await pool.query(`SELECT ua.user_id FROM user_accounts ua
      JOIN employees e ON e.employee_id=ua.employee_id WHERE e.user_id=$1 LIMIT 1`,[req.auth.userId])).rows[0];
    if(!account)return res.json({ok:true,isAdmin:false,moduleCodes:[],menuCodes:[]});
    const result=await pool.query(`SELECT DISTINCT sm.module_code,smn.menu_code
      FROM permission_management.system_menus smn
      JOIN permission_management.system_modules sm ON sm.module_id=smn.module_id
      JOIN permission_management.permissions p ON p.permission_code IN ('VIEW','ADD_MENTOR') AND p.status=TRUE
      LEFT JOIN permission_management.user_permissions up ON up.user_id=$1
        AND up.menu_id=smn.menu_id AND up.permission_id=p.permission_id
      LEFT JOIN permission_management.user_roles ur ON ur.user_id=$1 AND ur.status=TRUE
        AND (ur.valid_to IS NULL OR ur.valid_to>=CURRENT_DATE)
      LEFT JOIN permission_management.role_permissions rp ON rp.role_id=ur.role_id
        AND rp.menu_id=smn.menu_id AND rp.permission_id=p.permission_id
      WHERE sm.status=TRUE AND smn.status=TRUE
        AND ((smn.menu_code='MENTOR_ACTIVITY' AND p.permission_code='ADD_MENTOR') OR (smn.menu_code<>'MENTOR_ACTIVITY' AND p.permission_code='VIEW'))
        AND COALESCE(up.is_allowed,rp.is_allowed,FALSE)=TRUE`,[account.user_id]);
    res.json({ok:true,isAdmin:false,moduleCodes:[...new Set(result.rows.map(row=>row.module_code))],
      menuCodes:result.rows.map(row=>row.menu_code)});
  }catch(error){console.error('Navigation permission error:',error.message);res.status(500).json({ok:false,message:'Unable to load navigation permissions.'});}
});
app.put('/api/auth/change-password', authenticate, async (req,res)=>{
  const newPassword=String(req.body.newPassword||'');
  if(!newPassword)return res.status(400).json({ok:false,message:'New password is required.'});
  if(newPassword.length<8)return res.status(400).json({ok:false,message:'New password must contain at least 8 characters.'});
  let client;
  try{
    const passwordHash=await hashPassword(newPassword);
    client=await pool.connect();
    await client.query('BEGIN');
    await saveAccountPassword(client,req.auth,passwordHash);
    await client.query('COMMIT');
    res.json({ok:true,message:'Password changed successfully.'});
  }catch(error){if(client)await client.query('ROLLBACK').catch(()=>{});console.error('Password change error:',error.message);res.status(500).json({ok:false,message:'Unable to save password. No password changes were applied. Please sign in again and retry.'});}
  finally{client?.release();}
});
app.post('/api/auth/logout', authenticate, async (req, res) => {
  sessions.delete(req.auth.token);
  if(req.auth.loginHistoryId)await pool.query(`UPDATE login_history SET logout_at=NOW(),last_activity_at=NOW(),
    login_status='Logged Out',logout_type='Manual' WHERE login_history_id=$1`,[req.auth.loginHistoryId]);
  res.json({ ok:true });
});

app.get('/api/login-history', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT login_history_id AS id,user_id,username,login_at,logout_at,
      host(ip_address) AS ip_address,user_agent,browser_name,operating_system,device_type,
      login_status,login_success,failure_reason,last_activity_at,logout_type
      FROM login_history ORDER BY login_at DESC LIMIT 1000`);
    res.json({ok:true,history:result.rows});
  }catch(error){console.error('Login History query error:',error.message);res.status(500).json({ok:false,message:'Unable to load Login History.'});}
});

app.post('/api/login-history/:id/terminate', authenticate, async (req,res)=>{
  const id=Number(req.params.id);
  try{
    const result=await pool.query(`UPDATE login_history SET logout_at=NOW(),last_activity_at=NOW(),
      login_status='Terminated',logout_type='Administrator'
      WHERE login_history_id=$1 AND login_status='Active' RETURNING login_history_id`,[id]);
    if(!result.rowCount)return res.status(409).json({ok:false,message:'This session is no longer active.'});
    for(const [token,session] of sessions)if(Number(session.loginHistoryId)===id)sessions.delete(token);
    res.json({ok:true,message:'Session terminated successfully.'});
  }catch(error){res.status(500).json({ok:false,message:'Unable to terminate the session.'});}
});

function normalizeDateInput(value,label){
  const text=String(value??'').trim();
  if(!text)return null;
  if(/^\d{5}(\.\d+)?$/.test(text)){
    const date=new Date(Date.UTC(1899,11,30)+Number(text)*86400000);
    return date.toISOString().slice(0,10);
  }
  let match=text.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/);
  if(match){
    const [,year,month,day]=match;
    const iso=`${year}-${month.padStart(2,'0')}-${day.padStart(2,'0')}`;
    if(!Number.isNaN(Date.parse(`${iso}T00:00:00Z`)))return iso;
  }
  match=text.match(/^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$/);
  if(match){
    const [,day,month,year]=match;
    const iso=`${year}-${month.padStart(2,'0')}-${day.padStart(2,'0')}`;
    if(!Number.isNaN(Date.parse(`${iso}T00:00:00Z`)))return iso;
  }
  throw new Error(`${label} "${text}" is invalid. Use YYYY-MM-DD or DD-MM-YYYY.`);
}

async function insertStudent(client,data,userId){
  const admissionDate=normalizeDateInput(data.admissionDate,'Admission Date');
  const dateOfBirth=normalizeDateInput(data.dateOfBirth,'Date of Birth');
  const institutionId=(await client.query('SELECT institution_id FROM institutions WHERE is_active=TRUE ORDER BY institution_id LIMIT 1')).rows[0]?.institution_id;
  if(!institutionId)throw new Error('Create an active institution before adding students.');
  const academicYear=(await client.query('SELECT year_label,start_date FROM academic_years WHERE academic_year_id=$1',[Number(data.academicYearId)])).rows[0];
  const programme=(await client.query('SELECT programme_id,department_id FROM programmes WHERE programme_id=$1 AND is_active=TRUE',[Number(data.programmeId)])).rows[0];
  if(!academicYear||!programme||Number(programme.department_id)!==Number(data.departmentId))throw new Error('Academic year, department, or programme is invalid.');
  const academicStartYear=academicYear.start_date instanceof Date?academicYear.start_date.getFullYear():Number(String(academicYear.start_date||'').slice(0,4));
  const admissionYear=academicStartYear||Number(String(admissionDate||'').slice(0,4));
  if(!admissionYear)throw new Error('The selected Academic Year has no valid start year.');
  let batchId=(await client.query('SELECT batch_id FROM admission_batches WHERE programme_id=$1 AND admission_year=$2 LIMIT 1',[programme.programme_id,admissionYear])).rows[0]?.batch_id;
  if(!batchId)batchId=(await client.query(`INSERT INTO admission_batches
    (programme_id,admission_year,batch_name,start_date,is_active) VALUES ($1,$2,$3,$4,TRUE)
    RETURNING batch_id`,[programme.programme_id,admissionYear,`${programme.programme_id}-${admissionYear}`,academicYear.start_date])).rows[0].batch_id;
  const id=Number((await client.query(`SELECT nextval(pg_get_serial_sequence('students','student_id')) AS id`)).rows[0].id);
  const serial=String(id).padStart(5,'0'),year=String(admissionYear);
  const registrationNumber=data.registrationNumber?.trim()||`REG-${year}-${serial}`;
  const rollNumber=data.rollNumber?.trim()||`ROLL-${year}-${serial}`;
  const studentCode=`STU-${year}-${serial}`;
  const nameParts=String(data.studentName||'').trim().split(/\s+/);const firstName=nameParts.shift();const lastName=nameParts.length>1?nameParts.pop():null;const middleName=nameParts.join(' ')||null;
  const activeStatus=(await client.query(`SELECT student_status_id FROM student_statuses WHERE institute_id=$1 AND status_code='ACTIVE' LIMIT 1`,[institutionId])).rows[0]?.student_status_id||null;
  await client.query(`INSERT INTO students
    (student_id,institution_id,institute_id,programme_id,batch_id,section_id,department_id,branch_id,
     academic_year_id,semester_id,admission_category_id,student_status_id,registration_no,roll_no,
     admission_no,registration_number,roll_number,admission_number,student_code,first_name,middle_name,
     last_name,gender,date_of_birth,category,blood_group,mobile,email,current_address,permanent_address,
     admission_date,admission_type,profile_photo_name,profile_photo_mime_type,profile_photo_size,
     status,is_active,is_deleted,created_by)
    VALUES ($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$12,$13,$14,$15,$16,$17,$18,$19,$20,
      $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,'ACTIVE',TRUE,FALSE,$32)`,
    [id,institutionId,programme.programme_id,batchId,data.sectionId?Number(data.sectionId):null,Number(data.departmentId),data.branchId?Number(data.branchId):null,
      Number(data.academicYearId),data.semesterId?Number(data.semesterId):null,data.admissionCategoryId?Number(data.admissionCategoryId):null,activeStatus,
      registrationNumber,rollNumber,data.admissionNumber.trim(),studentCode,firstName,middleName,lastName,data.gender||null,dateOfBirth,
      data.category||null,data.bloodGroup||null,data.mobile?.trim()||null,data.email?.trim()||null,data.presentAddress?.trim()||null,
      data.permanentAddress?.trim()||null,admissionDate,data.admissionType||null,data.photoName||null,data.photoMimeType||null,
      data.photoSize?Number(data.photoSize):null,userId]);
  await client.query(`INSERT INTO student_parents
    (student_id,father_name,mother_name,guardian_mobile) VALUES ($1,$2,$3,$4)`,
    [id,data.fatherName?.trim()||null,data.motherName?.trim()||null,data.guardianMobile?.trim()||null]);
  await client.query('UPDATE students SET student_profile_details=$1::jsonb WHERE student_id=$2',[JSON.stringify(data),id]);
  for(const [type,address] of [['Present',data.presentAddress],['Permanent',data.permanentAddress]])if(address?.trim())await client.query(`INSERT INTO student_addresses
    (student_id,address_type,address_line1) VALUES ($1,$2,$3)`,[id,type,address.trim()]);
  return {id,registrationNumber,rollNumber,studentCode};
}

const sectionMasterCode=name=>{
  const cleaned=String(name||'').trim().toUpperCase().replace(/^SECTION\s+/,'').replace(/[^A-Z0-9]+/g,'-').replace(/^-|-$/g,'');
  return `SEC-${cleaned||'SECTION'}`;
};

app.get('/api/subject-masters', authenticate, async (_req,res)=>{
  try{
    const [subjects,departments]=await Promise.all([
      pool.query(`SELECT sm.subject_master_id AS id,sm.subject_code AS code,sm.subject_name AS name,
        sm.subject_short_name AS short_name,sm.subject_type AS type,sm.subject_category AS category,
        sm.department_id,d.department_code,d.department_name,sm.credit,sm.is_active
        FROM subject_masters sm JOIN departments d ON d.department_id=sm.department_id
        ORDER BY sm.subject_code`),
      pool.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE ORDER BY department_name')
    ]);
    res.json({ok:true,subjects:subjects.rows,departments:departments.rows});
  }catch(error){console.error('Subject Master query error:',error.message);res.status(500).json({ok:false,message:'Unable to load Subject Masters.'});}
});

app.post('/api/subject-masters', authenticate, async (req,res)=>{
  const data=req.body;
  if(!data.code?.trim()||!data.name?.trim()||!data.category?.trim()||!Number(data.departmentId)||Number(data.credit)<0)return res.status(400).json({ok:false,message:'Complete all required Subject Master fields.'});
  try{
    const result=await pool.query(`INSERT INTO subject_masters
      (subject_code,subject_name,subject_short_name,subject_type,subject_category,department_id,credit,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING subject_master_id`,
      [data.code.trim().toUpperCase(),data.name.trim(),data.shortName?.trim().toUpperCase()||null,data.type||'Theory',data.category.trim(),Number(data.departmentId),Number(data.credit)||0,req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].subject_master_id,message:'Subject saved successfully.'});
  }catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Subject Code already exists.':'Unable to save Subject.'});}
});

app.post('/api/subject-masters/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 Subject rows.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const department=(await client.query('SELECT department_id FROM departments WHERE is_active=TRUE ORDER BY department_id LIMIT 1')).rows[0];
    if(!department)throw new Error('Create an active Department before importing Subjects.');
    for(let index=0;index<rows.length;index++){
      const row=rows[index],code=String(row.code||'').trim().toUpperCase(),name=String(row.name||'').trim();
      if(!code||!name)throw new Error(`Row ${index+2}: Subject Code and Subject Name are required.`);
      const credit=Number(row.credit);if(!Number.isFinite(credit)||credit<0)throw new Error(`Row ${index+2}: Credit is invalid.`);
      await client.query(`INSERT INTO subject_masters
        (subject_code,subject_name,subject_short_name,subject_type,subject_category,department_id,credit,created_by)
        VALUES ($1,$2,$3,$4,'Professional Core',$5,$6,$7)
        ON CONFLICT (subject_code) DO UPDATE SET subject_name=EXCLUDED.subject_name,
          subject_short_name=EXCLUDED.subject_short_name,subject_type=EXCLUDED.subject_type,
          credit=EXCLUDED.credit,updated_by=EXCLUDED.created_by,updated_at=NOW()`,
        [code,name,String(row.alias||'').trim().toUpperCase()||null,String(row.type||'Theory').trim(),department.department_id,credit,req.auth.userId]);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} Subjects imported successfully.`});
  }catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}finally{client.release();}
});

app.put('/api/subject-masters/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body;
  if(!id||!data.code?.trim()||!data.name?.trim()||!data.category?.trim()||!Number(data.departmentId)||Number(data.credit)<0)return res.status(400).json({ok:false,message:'Complete all required Subject Master fields.'});
  try{
    const result=await pool.query(`UPDATE subject_masters SET subject_code=$1,subject_name=$2,
      subject_short_name=$3,subject_type=$4,subject_category=$5,department_id=$6,credit=$7,
      updated_by=$8,updated_at=NOW() WHERE subject_master_id=$9 RETURNING subject_master_id`,
      [data.code.trim().toUpperCase(),data.name.trim(),data.shortName?.trim().toUpperCase()||null,data.type||'Theory',data.category.trim(),Number(data.departmentId),Number(data.credit)||0,req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Subject not found.'});
    res.json({ok:true,message:'Subject updated successfully.'});
  }catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Subject Code already exists.':'Unable to update Subject.'});}
});

app.delete('/api/subject-masters/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid Subject.'});
  try{const result=await pool.query('DELETE FROM subject_masters WHERE subject_master_id=$1 RETURNING subject_master_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Subject not found.'});res.json({ok:true,message:'Subject deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This Subject is in use and cannot be deleted.':'Unable to delete Subject.'});}
});

app.get('/api/course-outcomes', authenticate, async (req,res)=>{
  try{
    const employeeId=await authenticatedEmployeeId(req);
    const [subjects,codes,faculty,outcomes]=await Promise.all([
      pool.query(`SELECT DISTINCT sm.subject_master_id AS id,sm.subject_code AS code,sm.subject_name AS name
        FROM subject_masters sm
        LEFT JOIN academics.faculty_subject_assignments fsa ON fsa.subject_id=sm.subject_master_id
          AND fsa.assignment_status='Active'
        WHERE sm.is_active=TRUE AND ($1::bigint IS NULL OR fsa.faculty_employee_id=$1)
        ORDER BY sm.subject_name`,[employeeId]),
      pool.query(`SELECT co_code_id AS id,co_code AS code,co_number,display_order
        FROM academics.course_outcome_codes WHERE is_active=TRUE ORDER BY display_order`),
      pool.query(`SELECT employee_id AS id,employee_code AS code,
        TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM employees WHERE status='ACTIVE' AND ($1::bigint IS NULL OR employee_id=$1)
        ORDER BY first_name,last_name`,[employeeId]),
      pool.query(`SELECT co.course_outcome_id AS id,co.subject_master_id,co.co_code_id,
        co.co_description,co.faculty_employee_id,co.status,sm.subject_code,sm.subject_name,
        cc.co_code,TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS faculty_name
        FROM academics.course_outcomes co JOIN subject_masters sm ON sm.subject_master_id=co.subject_master_id
        JOIN academics.course_outcome_codes cc ON cc.co_code_id=co.co_code_id
        LEFT JOIN employees e ON e.employee_id=co.faculty_employee_id
        WHERE $1::bigint IS NULL OR EXISTS (SELECT 1 FROM academics.faculty_subject_assignments fsa
          WHERE fsa.subject_id=co.subject_master_id AND fsa.faculty_employee_id=$1
          AND fsa.assignment_status='Active')
        ORDER BY sm.subject_name,cc.display_order`,[employeeId])
    ]);
    res.json({ok:true,canViewAllFaculty:employeeId===null,employeeId,subjects:subjects.rows,codes:codes.rows,faculty:faculty.rows,outcomes:outcomes.rows});
  }catch(error){console.error('Course outcome query error:',error.message);res.status(500).json({ok:false,message:'Unable to load course outcomes.'});}
});

app.post('/api/course-outcomes', authenticate, async (req,res)=>{
  const data=req.body,coCodes=[...new Set((Array.isArray(data.coCodes)?data.coCodes:[data.coCode]).map(value=>String(value||'').trim().toUpperCase()).filter(Boolean))];
  if(!Number(data.subjectId)||coCodes.length!==1||coCodes.some(code=>!/^CO-[1-6]$/.test(code))||!data.description?.trim())return res.status(400).json({ok:false,message:'Subject, one CO from CO-1 to CO-6, and CO Description are required.'});
  const client=await pool.connect();
  try{
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null){const allowed=await client.query(`SELECT 1 FROM academics.faculty_subject_assignments
      WHERE subject_id=$1 AND faculty_employee_id=$2 AND assignment_status='Active' LIMIT 1`,[Number(data.subjectId),employeeId]);
      if(!allowed.rowCount)return res.status(403).json({ok:false,message:'You can create Course Outcomes only for subjects assigned to your employee account.'});}
    const facultyId=employeeId===null?(data.facultyId?Number(data.facultyId):null):Number(employeeId);
    await client.query('BEGIN');
    const ids=[];
    for(const coCode of coCodes){const result=await client.query(`INSERT INTO academics.course_outcomes
      (subject_master_id,co_code_id,co_description,faculty_employee_id,status,created_by)
      SELECT $1,cc.co_code_id,$3,$4,$5,$6 FROM academics.course_outcome_codes cc
      WHERE cc.co_code=$2 AND cc.is_active=TRUE RETURNING course_outcome_id`,
      [Number(data.subjectId),coCode,data.description.trim(),facultyId,data.status||'ACTIVE',req.auth.userId]);
      if(!result.rowCount)throw new Error(`${coCode} is not configured in the CO Code master.`);ids.push(result.rows[0].course_outcome_id);}
    await client.query('COMMIT');
    res.status(201).json({ok:true,ids,message:`${ids.length} Course Outcome${ids.length===1?'':'s'} created successfully.`});}
  catch(error){await client.query('ROLLBACK').catch(()=>{});res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'One or more selected COs are already defined for this subject.':error.code==='23503'?'A selected master record is invalid.':error.message||'Unable to create Course Outcomes.'});}
  finally{client.release();}
});

app.put('/api/course-outcomes/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body,coCode=String(data.coCode||'').trim().toUpperCase(),
    coCodes=[...new Set((Array.isArray(data.coCodes)?data.coCodes:[coCode]).map(value=>String(value||'').trim().toUpperCase()).filter(Boolean))];
  if(!id||!Number(data.subjectId)||coCodes.length!==1||coCodes.some(code=>!/^CO-[1-6]$/.test(code))||!data.description?.trim())return res.status(400).json({ok:false,message:'Subject, one CO from CO-1 to CO-6, and CO Description are required.'});
  const client=await pool.connect();
  try{
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null){const allowed=await client.query(`SELECT 1 FROM academics.faculty_subject_assignments
      WHERE subject_id=$1 AND faculty_employee_id=$2 AND assignment_status='Active' LIMIT 1`,[Number(data.subjectId),employeeId]);
      if(!allowed.rowCount)return res.status(403).json({ok:false,message:'You can update Course Outcomes only for subjects assigned to your employee account.'});}
    const facultyId=employeeId===null?(data.facultyId?Number(data.facultyId):null):Number(employeeId);
    await client.query('BEGIN');
    const result=await client.query(`UPDATE academics.course_outcomes SET subject_master_id=$1,
    co_code_id=(SELECT co_code_id FROM academics.course_outcome_codes WHERE co_code=$2 AND is_active=TRUE),
    co_description=$3,faculty_employee_id=$4,status=$5,updated_by=$6,updated_at=NOW()
    WHERE course_outcome_id=$7 AND EXISTS (SELECT 1 FROM academics.course_outcome_codes WHERE co_code=$2 AND is_active=TRUE)
    RETURNING course_outcome_id`,
    [Number(data.subjectId),coCode,data.description.trim(),facultyId,
      data.status||'ACTIVE',req.auth.userId,id]);
    if(!result.rowCount)throw new Error('Course Outcome not found.');
    let added=0;
    for(const additionalCode of coCodes.filter(code=>code!==coCode)){const inserted=await client.query(`INSERT INTO academics.course_outcomes
      (subject_master_id,co_code_id,co_description,faculty_employee_id,status,created_by)
      SELECT $1,cc.co_code_id,$3,$4,$5,$6 FROM academics.course_outcome_codes cc
      WHERE cc.co_code=$2 AND cc.is_active=TRUE RETURNING course_outcome_id`,
      [Number(data.subjectId),additionalCode,data.description.trim(),facultyId,data.status||'ACTIVE',req.auth.userId]);
      if(!inserted.rowCount)throw new Error(`${additionalCode} is not configured in the CO Code master.`);added++;}
    await client.query('COMMIT');res.json({ok:true,message:`Course Outcome updated${added?` and ${added} additional CO${added===1?' was':'s were'} created`:''} successfully.`});}
  catch(error){await client.query('ROLLBACK').catch(()=>{});res.status(error.code==='23505'?409:error.message==='Course Outcome not found.'?404:500).json({ok:false,message:error.code==='23505'?'One or more selected COs are already defined for this subject.':error.message||'Unable to update Course Outcomes.'});}
  finally{client.release();}
});

app.get('/api/lesson-plans', authenticate, async (req,res)=>{
  try{
    const employeeId=await authenticatedEmployeeId(req);
    await pool.query(`INSERT INTO academics.faculty_subject_assignments
      (academic_year_id,programme_batch_id,semester_id,programme_section_id,subject_id,faculty_employee_id,assignment_status,assigned_by)
      SELECT academic_year_id,batch_id,semester_id,section_id,subject_master_id,employee_id,
        CASE WHEN status='ACTIVE' THEN 'Active' ELSE 'Inactive' END,created_by
      FROM subject_teacher_allocations ON CONFLICT DO NOTHING`);
    const [academicYears,semesters,faculty,assignments]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,year_label AS name FROM academic_years
        WHERE is_active=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT DISTINCT semester_number AS id,semester_name AS name FROM semesters
        WHERE is_active=TRUE ORDER BY semester_number`),
      pool.query(`SELECT employee_id AS id,employee_code AS code,
        TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM employees WHERE status='ACTIVE' AND ($1::bigint IS NULL OR employee_id=$1)
        ORDER BY first_name,last_name`,[employeeId]),
      pool.query(`SELECT fsa.faculty_subject_assignment_id AS id,fsa.academic_year_id,
        fsa.semester_id,se.semester_number,fsa.faculty_employee_id,ay.year_label AS academic_year,
        COALESCE(se.semester_name,'—') AS semester_name,
        COALESCE(sec.section_name,'—') AS section_name,
        COALESCE(ab.batch_name,'—') AS programme_batch,
        sm.subject_code,sm.subject_name,TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS faculty_name,
        COALESCE(lp.plan_status,'Draft') AS status,
        (SELECT COUNT(*)::integer FROM academics.lesson_plan_topics t WHERE t.lesson_plan_id=lp.lesson_plan_id) AS lesson_count
        FROM academics.faculty_subject_assignments fsa
        JOIN academic_years ay ON ay.academic_year_id=fsa.academic_year_id
        JOIN subject_masters sm ON sm.subject_master_id=fsa.subject_id
        LEFT JOIN semesters se ON se.semester_id=fsa.semester_id
        LEFT JOIN sections sec ON sec.section_id=fsa.programme_section_id
        LEFT JOIN admission_batches ab ON ab.batch_id=fsa.programme_batch_id
        JOIN employees e ON e.employee_id=fsa.faculty_employee_id
        LEFT JOIN academics.lesson_plan_headers lp ON lp.faculty_subject_assignment_id=fsa.faculty_subject_assignment_id
        WHERE fsa.assignment_status='Active' AND ($1::bigint IS NULL OR fsa.faculty_employee_id=$1)
        ORDER BY sm.subject_code`,[employeeId])
    ]);
    res.json({ok:true,canViewAllFaculty:employeeId===null,employeeId,academicYears:academicYears.rows,
      semesters:semesters.rows,faculty:faculty.rows,assignments:assignments.rows});
  }catch(error){console.error('Lesson plan query error:',error.message);res.status(500).json({ok:false,message:'Unable to load Lesson Plans.'});}
});

app.get('/api/view-lesson-plans', authenticate, async (_req,res)=>{
  try{
    const [academicYears,departments,faculty,subjects,plans]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,year_label AS name FROM academic_years
        WHERE is_active=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT department_id AS id,department_code AS code,department_name AS name
        FROM departments WHERE is_active=TRUE ORDER BY department_name`),
      pool.query(`SELECT employee_id AS id,employee_code AS code,
        TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM employees WHERE status='ACTIVE' ORDER BY first_name,last_name`),
      pool.query(`SELECT subject_master_id AS id,subject_code AS code,subject_name AS name,department_id
        FROM subject_masters WHERE is_active=TRUE ORDER BY subject_name`),
      pool.query(`SELECT lp.lesson_plan_id AS id,fsa.faculty_subject_assignment_id AS assignment_id,
        fsa.academic_year_id,fsa.faculty_employee_id,sm.department_id,fsa.subject_id,
        COALESCE(NULLIF(lp.lesson_plan_title,''),sm.subject_name||' Plan') AS plan_title,
        sm.subject_code,sm.subject_name,TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS faculty_name,
        lp.total_planned_periods AS periods,lp.plan_status AS status,
        CASE WHEN COUNT(t.lesson_plan_topic_id)=0 THEN 0 ELSE
          ROUND(100.0*COUNT(t.lesson_plan_topic_id) FILTER (WHERE t.topic_status='Completed')/COUNT(t.lesson_plan_topic_id)) END AS coverage
        FROM academics.lesson_plan_headers lp
        JOIN academics.faculty_subject_assignments fsa ON fsa.faculty_subject_assignment_id=lp.faculty_subject_assignment_id
        JOIN subject_masters sm ON sm.subject_master_id=fsa.subject_id
        JOIN employees e ON e.employee_id=fsa.faculty_employee_id
        LEFT JOIN academics.lesson_plan_topics t ON t.lesson_plan_id=lp.lesson_plan_id
        GROUP BY lp.lesson_plan_id,fsa.faculty_subject_assignment_id,fsa.academic_year_id,
          fsa.faculty_employee_id,sm.department_id,fsa.subject_id,sm.subject_code,sm.subject_name,
          e.first_name,e.middle_name,e.last_name ORDER BY sm.subject_code`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,departments:departments.rows,faculty:faculty.rows,
      subjects:subjects.rows,plans:plans.rows});
  }catch(error){console.error('View lesson plans query error:',error.message);res.status(500).json({ok:false,message:'Unable to load published Lesson Plans.'});}
});

app.get('/api/course-coverage-report', authenticate, async (_req,res)=>{
  try{
    const [academicYears,batches,semesters,subjects,faculty,rows]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,year_label AS name FROM academic_years
        WHERE is_active=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT b.batch_id AS id,b.programme_id,b.batch_name AS name,p.programme_name
        FROM admission_batches b JOIN programmes p ON p.programme_id=b.programme_id
        WHERE b.is_active=TRUE ORDER BY b.admission_year DESC,p.programme_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_number,semester_name AS name
        FROM semesters WHERE is_active=TRUE ORDER BY semester_number`),
      pool.query(`SELECT subject_master_id AS id,subject_code AS code,subject_name AS name
        FROM subject_masters WHERE is_active=TRUE ORDER BY subject_name`),
      pool.query(`SELECT employee_id AS id,employee_code AS code,
        TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM employees WHERE status='ACTIVE' ORDER BY first_name,last_name`),
      pool.query(`SELECT lp.lesson_plan_id AS id,fsa.academic_year_id,fsa.programme_batch_id,
        fsa.semester_id,fsa.subject_id,fsa.faculty_employee_id,sm.subject_code,sm.subject_name,
        TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS faculty_name,
        COALESCE(SUM(t.planned_periods),0)::int AS planned_periods,
        COALESCE(SUM(t.planned_periods) FILTER (WHERE t.topic_status='Completed'),0)::int AS completed_periods,
        CASE WHEN COALESCE(SUM(t.planned_periods),0)=0 THEN 0 ELSE
          ROUND(100.0*COALESCE(SUM(t.planned_periods) FILTER (WHERE t.topic_status='Completed'),0)/SUM(t.planned_periods),2) END AS coverage
        FROM academics.lesson_plan_headers lp
        JOIN academics.faculty_subject_assignments fsa ON fsa.faculty_subject_assignment_id=lp.faculty_subject_assignment_id
        JOIN subject_masters sm ON sm.subject_master_id=fsa.subject_id
        JOIN employees e ON e.employee_id=fsa.faculty_employee_id
        LEFT JOIN academics.lesson_plan_topics t ON t.lesson_plan_id=lp.lesson_plan_id
        GROUP BY lp.lesson_plan_id,fsa.academic_year_id,fsa.programme_batch_id,fsa.semester_id,
          fsa.subject_id,fsa.faculty_employee_id,sm.subject_code,sm.subject_name,e.first_name,e.middle_name,e.last_name
        ORDER BY sm.subject_code`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,batches:batches.rows,semesters:semesters.rows,
      subjects:subjects.rows,faculty:faculty.rows,rows:rows.rows});
  }catch(error){console.error('Course coverage report error:',error.message);res.status(500).json({ok:false,message:'Unable to load Course Coverage Report.'});}
});

app.get('/api/lesson-plan-report', authenticate, async (_req,res)=>{
  try{
    const [academicYears,departments,faculty,subjects,rows]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,year_label AS name FROM academic_years
        WHERE is_active=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT department_id AS id,department_code AS code,department_name AS name
        FROM departments WHERE is_active=TRUE ORDER BY department_name`),
      pool.query(`SELECT employee_id AS id,employee_code AS code,
        TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM employees WHERE status='ACTIVE' ORDER BY first_name,last_name`),
      pool.query(`SELECT subject_master_id AS id,subject_code AS code,subject_name AS name,department_id
        FROM subject_masters WHERE is_active=TRUE ORDER BY subject_name`),
      pool.query(`SELECT lp.lesson_plan_id AS id,fsa.academic_year_id,sm.department_id,
        fsa.faculty_employee_id,fsa.subject_id,ay.year_label AS academic_year,
        d.department_code,sm.subject_code,sm.subject_name,
        TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS faculty_name,
        lp.plan_status AS status,lp.total_planned_topics,lp.total_planned_periods,
        lp.created_at,lp.updated_at
        FROM academics.lesson_plan_headers lp
        JOIN academics.faculty_subject_assignments fsa ON fsa.faculty_subject_assignment_id=lp.faculty_subject_assignment_id
        JOIN academic_years ay ON ay.academic_year_id=fsa.academic_year_id
        JOIN subject_masters sm ON sm.subject_master_id=fsa.subject_id
        JOIN departments d ON d.department_id=sm.department_id
        JOIN employees e ON e.employee_id=fsa.faculty_employee_id ORDER BY sm.subject_code`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,departments:departments.rows,
      faculty:faculty.rows,subjects:subjects.rows,rows:rows.rows});
  }catch(error){console.error('Lesson plan report error:',error.message);res.status(500).json({ok:false,message:'Unable to load Lesson Plan Report.'});}
});

app.get('/api/lecture-notes', authenticate, async (_req,res)=>{
  try{
    const [subjects,notes]=await Promise.all([
      pool.query(`SELECT subject_master_id AS id,subject_code AS code,subject_name AS name
        FROM subject_masters WHERE is_active=TRUE ORDER BY subject_name`),
      pool.query(`SELECT n.lecture_note_id AS id,n.subject_master_id,sm.subject_code,sm.subject_name,
        n.material_type,n.unit_name,n.note_title,n.file_name,n.file_mime_type,n.file_size,n.note_url,n.duration_minutes,
        n.description,n.publish_status,n.created_at,
        TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS faculty_name
        FROM academics.lecture_notes n JOIN subject_masters sm ON sm.subject_master_id=n.subject_master_id
        LEFT JOIN employees e ON e.user_id=n.created_by
        ORDER BY n.created_at DESC`)
    ]);
    res.json({ok:true,subjects:subjects.rows,notes:notes.rows});
  }catch(error){console.error('Lecture notes query error:',error.message);res.status(500).json({ok:false,message:'Unable to load Lecture Notes.'});}
});

app.post('/api/lecture-notes', authenticate, async (req,res)=>{
  const data=req.body,file=data.file||null,url=String(data.url||'').trim();
  if(!Number(data.subjectId)||!data.unit?.trim()||!data.title?.trim()||(!file?.data&&!url)||!['Draft','Published','Submitted'].includes(data.status)||!['LECTURE_NOTE','VIDEO_LECTURE','PPT'].includes(data.materialType))return res.status(400).json({ok:false,message:'Material Type, Subject, Unit, Title, a file or URL, and Publish Status are required.'});
  if(data.materialType==='PPT'&&(!file?.data||!/\.(ppt|pptx)$/i.test(file.name||'')))return res.status(400).json({ok:false,message:'Select a valid PPT or PPTX file.'});
  if(url&&!/^https?:\/\/\S+$/i.test(url))return res.status(400).json({ok:false,message:'Note URL must start with http:// or https://.'});
  if(data.materialType==='VIDEO_LECTURE'&&(!url||Number(data.durationMinutes)<=0))return res.status(400).json({ok:false,message:'Video URL and a valid duration in minutes are required.'});
  if(file?.data&&Number(file.size)>2*1024*1024)return res.status(400).json({ok:false,message:'Upload a file of 2 MB or less.'});
  try{
    const buffer=file?.data?Buffer.from(String(file.data).replace(/^data:[^;]+;base64,/,''),'base64'):null;
    const result=await pool.query(`INSERT INTO academics.lecture_notes
      (subject_master_id,material_type,unit_name,note_title,file_name,file_mime_type,file_size,file_data,
       note_url,duration_minutes,description,publish_status,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING lecture_note_id`,
      [Number(data.subjectId),data.materialType,data.unit.trim(),data.title.trim(),file?.name||null,file?.type||null,
        file?.size?Number(file.size):null,buffer,url||null,data.durationMinutes?Number(data.durationMinutes):null,
        data.description?.trim()||null,data.status,req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].lecture_note_id,message:'Lecture Note uploaded successfully.'});
  }catch(error){res.status(error.code==='23503'?400:500).json({ok:false,message:error.code==='23503'?'Selected Subject is invalid.':'Unable to upload Lecture Note.'});}
});

app.get('/api/lecture-notes/:id/download', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid Lecture Note.'});
  try{const note=(await pool.query(`SELECT file_name,file_mime_type,file_data FROM academics.lecture_notes
    WHERE lecture_note_id=$1`,[id])).rows[0];if(!note||!note.file_data)return res.status(404).json({ok:false,message:'Lecture Note file not found.'});
    res.setHeader('Content-Type',note.file_mime_type||'application/octet-stream');
    res.setHeader('Content-Disposition',`attachment; filename="${String(note.file_name||'lecture-note').replaceAll('"','')}"`);
    res.send(note.file_data);
  }catch(error){res.status(500).json({ok:false,message:'Unable to download Lecture Note.'});}
});

app.delete('/api/lecture-notes/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid Lecture Note.'});
  try{const result=await pool.query('DELETE FROM academics.lecture_notes WHERE lecture_note_id=$1 RETURNING lecture_note_id',[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Lecture Note not found.'});res.json({ok:true,message:'Lecture Note deleted successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to delete Lecture Note.'});}
});

app.get('/api/lesson-plans/:assignmentId', authenticate, async (req,res)=>{
  const id=Number(req.params.assignmentId);if(!id)return res.status(400).json({ok:false,message:'Invalid faculty subject assignment.'});
  try{
    const assignment=(await pool.query(`SELECT fsa.*,ay.year_label AS academic_year,sm.subject_code,sm.subject_name,
      TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS faculty_name,lp.lesson_plan_id,COALESCE(lp.plan_status,'Draft') AS status
      FROM academics.faculty_subject_assignments fsa JOIN academic_years ay ON ay.academic_year_id=fsa.academic_year_id
      JOIN subject_masters sm ON sm.subject_master_id=fsa.subject_id JOIN employees e ON e.employee_id=fsa.faculty_employee_id
      LEFT JOIN academics.lesson_plan_headers lp ON lp.faculty_subject_assignment_id=fsa.faculty_subject_assignment_id
      WHERE fsa.faculty_subject_assignment_id=$1`,[id])).rows[0];
    if(!assignment)return res.status(404).json({ok:false,message:'Faculty subject assignment not found.'});
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null&&Number(employeeId)!==Number(assignment.faculty_employee_id))
      return res.status(403).json({ok:false,message:'You can only open Lesson Plans assigned to your employee account.'});
    const [books,outcomes,topics,materials]=await Promise.all([
      pool.query(`SELECT preferred_book_id AS id,book_title,author_name,publisher_name,edition,isbn,display_order
        FROM preferred_books WHERE subject_master_id=$1 AND is_active=TRUE ORDER BY display_order`,[assignment.subject_id]),
      pool.query(`SELECT co.course_outcome_id AS id,cc.co_code AS code,co.co_description
        FROM academics.course_outcomes co JOIN academics.course_outcome_codes cc ON cc.co_code_id=co.co_code_id
        WHERE co.subject_master_id=$1 AND co.status='ACTIVE' ORDER BY cc.display_order`,[assignment.subject_id]),
      assignment.lesson_plan_id?pool.query(`SELECT t.lesson_plan_topic_id AS id,t.lesson_number,t.topic_description,
        t.course_outcome_id,co.co_code,
        CASE WHEN EXISTS (SELECT 1 FROM academics.lesson_plan_topic_outcomes m WHERE m.lesson_plan_topic_id=t.lesson_plan_topic_id)
          THEN ARRAY(SELECT m.course_outcome_id FROM academics.lesson_plan_topic_outcomes m JOIN academics.course_outcomes mo ON mo.course_outcome_id=m.course_outcome_id JOIN academics.course_outcome_codes mc ON mc.co_code_id=mo.co_code_id WHERE m.lesson_plan_topic_id=t.lesson_plan_topic_id ORDER BY mc.display_order)
          ELSE ARRAY[t.course_outcome_id] END AS course_outcome_ids,
        CASE WHEN EXISTS (SELECT 1 FROM academics.lesson_plan_topic_outcomes m WHERE m.lesson_plan_topic_id=t.lesson_plan_topic_id)
          THEN ARRAY(SELECT mc.co_code FROM academics.lesson_plan_topic_outcomes m JOIN academics.course_outcomes mo ON mo.course_outcome_id=m.course_outcome_id JOIN academics.course_outcome_codes mc ON mc.co_code_id=mo.co_code_id WHERE m.lesson_plan_topic_id=t.lesson_plan_topic_id ORDER BY mc.display_order)
          ELSE ARRAY[co.co_code] END AS co_codes,
        t.page_from,t.page_to,t.planned_periods,t.ppt_required,t.video_url,t.topic_status,
        b.preferred_book_id,b.book_title FROM academics.lesson_plan_topics t
        JOIN academics.course_outcomes o ON o.course_outcome_id=t.course_outcome_id
        JOIN academics.course_outcome_codes co ON co.co_code_id=o.co_code_id
        LEFT JOIN academics.lesson_plan_books b ON b.lesson_plan_book_id=t.lesson_plan_book_id
        WHERE t.lesson_plan_id=$1 ORDER BY t.lesson_number`,[assignment.lesson_plan_id]):Promise.resolve({rows:[]}),
      pool.query(`SELECT lecture_note_id AS id,material_type,unit_name,note_title,file_name,note_url,publish_status
        FROM academics.lecture_notes WHERE subject_master_id=$1 AND material_type IN ('PPT','VIDEO_LECTURE')
        ORDER BY created_at DESC`,[assignment.subject_id])
    ]);
    res.json({ok:true,assignment,books:books.rows,outcomes:outcomes.rows,topics:topics.rows,materials:materials.rows});
  }catch(error){console.error('Lesson plan detail query error:',error.message);res.status(500).json({ok:false,message:'Unable to load Lesson Plan details.'});}
});

app.put('/api/lesson-plans/:assignmentId/topics', authenticate, async (req,res)=>{
  const assignmentId=Number(req.params.assignmentId),topics=Array.isArray(req.body.topics)?req.body.topics:[];
  if(!assignmentId||!topics.length||topics.some((item,index)=>!item.description?.trim()||!(Array.isArray(item.courseOutcomeIds)?item.courseOutcomeIds:[item.courseOutcomeId]).some(Number)||!Number(item.preferredBookId)||Number(item.lessonNumber)!==index+1||(item.videoUrl&&!/^https?:\/\/\S+$/i.test(item.videoUrl))))return res.status(400).json({ok:false,message:'Add topics in lesson order, select one or more COs and a Book, and enter a valid Video URL when provided.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const assignment=(await client.query('SELECT subject_id,faculty_employee_id FROM academics.faculty_subject_assignments WHERE faculty_subject_assignment_id=$1 AND assignment_status=$2',[assignmentId,'Active'])).rows[0];
    if(!assignment)throw new Error('Faculty subject assignment is not active.');
    const employeeId=await authenticatedEmployeeId(req,client);
    if(employeeId!==null&&Number(employeeId)!==Number(assignment.faculty_employee_id)){
      await client.query('ROLLBACK');
      return res.status(403).json({ok:false,message:'You can only update Lesson Plans assigned to your employee account.'});
    }
    const preferred=(await client.query(`SELECT preferred_book_id,book_title,author_name,publisher_name,edition,isbn,display_order
      FROM preferred_books WHERE subject_master_id=$1 AND is_active=TRUE ORDER BY display_order`,[assignment.subject_id])).rows;
    if(!preferred.length)throw new Error('Add at least one Preferred Book before creating a Lesson Plan.');
    let plan=(await client.query(`INSERT INTO academics.lesson_plan_headers
      (faculty_subject_assignment_id,lesson_plan_title,created_by) VALUES ($1,'Subject Lesson Plan',$2)
      ON CONFLICT (faculty_subject_assignment_id) DO UPDATE SET updated_by=EXCLUDED.created_by,updated_at=NOW()
      RETURNING lesson_plan_id`,[assignmentId,req.auth.userId])).rows[0];
    await client.query('DELETE FROM academics.lesson_plan_topics WHERE lesson_plan_id=$1',[plan.lesson_plan_id]);
    await client.query('DELETE FROM academics.lesson_plan_books WHERE lesson_plan_id=$1',[plan.lesson_plan_id]);
    const bookIds=new Map();
    for(const book of preferred){const saved=(await client.query(`INSERT INTO academics.lesson_plan_books
      (lesson_plan_id,preferred_book_id,book_title,author_name,publisher_name,edition,isbn,book_sequence,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING lesson_plan_book_id`,
      [plan.lesson_plan_id,book.preferred_book_id,book.book_title,book.author_name,book.publisher_name,book.edition,book.isbn,book.display_order,req.auth.userId])).rows[0];bookIds.set(String(book.preferred_book_id),saved.lesson_plan_book_id);}
    for(const item of topics){const outcomeIds=[...new Set((Array.isArray(item.courseOutcomeIds)?item.courseOutcomeIds:[item.courseOutcomeId]).map(Number).filter(Boolean))];const savedTopic=await client.query(`INSERT INTO academics.lesson_plan_topics
      (lesson_plan_id,lesson_number,topic_description,course_outcome_id,lesson_plan_book_id,page_from,page_to,planned_periods,ppt_required,video_url,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING lesson_plan_topic_id`,
      [plan.lesson_plan_id,Number(item.lessonNumber),item.description.trim(),outcomeIds[0],bookIds.get(String(item.preferredBookId)),item.pageFrom?.trim()||null,item.pageTo?.trim()||null,Number(item.plannedPeriods)||1,Boolean(item.pptRequired),item.videoUrl?.trim()||null,req.auth.userId]);
      for(const outcomeId of outcomeIds)await client.query(`INSERT INTO academics.lesson_plan_topic_outcomes
        (lesson_plan_topic_id,course_outcome_id,created_by) VALUES ($1,$2,$3)`,[savedTopic.rows[0].lesson_plan_topic_id,outcomeId,req.auth.userId]);}
    await client.query(`UPDATE academics.lesson_plan_headers SET total_planned_topics=$1,
      total_planned_periods=$2,updated_by=$3,updated_at=NOW() WHERE lesson_plan_id=$4`,
      [topics.length,topics.reduce((sum,item)=>sum+(Number(item.plannedPeriods)||1),0),req.auth.userId,plan.lesson_plan_id]);
    await client.query('COMMIT');res.json({ok:true,message:'Lesson Plan topics updated successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}finally{client.release();}
});

app.get('/api/attendance-calendar-settings', authenticate, async (_req,res)=>{
  try{const [academicYears,programmes,batches,semesters,sections,settings]=await Promise.all([
    pool.query(`SELECT academic_year_id AS id,year_label AS name,start_date,end_date,is_current FROM academic_years WHERE is_active=TRUE ORDER BY is_current DESC,start_date DESC`),
    pool.query(`SELECT programme_id AS id,programme_code AS code,programme_name AS name FROM programmes WHERE is_active=TRUE ORDER BY programme_name`),
    pool.query(`SELECT b.batch_id AS id,b.programme_id,b.batch_name AS name FROM admission_batches b WHERE b.is_active=TRUE ORDER BY b.admission_year DESC,b.batch_name`),
    pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name,semester_number FROM semesters WHERE is_active=TRUE ORDER BY programme_id,semester_number`),
    pool.query(`SELECT s.section_id AS id,s.batch_id,s.semester_id,COALESCE(sm.section_master_name,s.section_name) AS name FROM sections s LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id WHERE s.is_active=TRUE ORDER BY name`),
    pool.query(`SELECT cs.attendance_calendar_setting_id AS id,cs.permission_type,cs.start_date,cs.end_date,cs.allow_attendance,cs.attendance_close_time,cs.created_at,ay.year_label AS academic_year,COALESCE(p.programme_name,'All Courses') AS programme,COALESCE(b.batch_name,'All Batches') AS batch,COALESCE(se.semester_name,'All Semesters') AS semester,COALESCE(sm.section_master_name,s.section_name,'All Sections') AS section FROM academics.attendance_calendar_settings cs JOIN academic_years ay ON ay.academic_year_id=cs.academic_year_id LEFT JOIN programmes p ON p.programme_id=cs.programme_id LEFT JOIN admission_batches b ON b.batch_id=cs.programme_batch_id LEFT JOIN semesters se ON se.semester_id=cs.semester_id LEFT JOIN sections s ON s.section_id=cs.programme_section_id LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id WHERE cs.is_active=TRUE ORDER BY cs.created_at DESC LIMIT 20`)
  ]);res.json({ok:true,academicYears:academicYears.rows,programmes:programmes.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows,settings:settings.rows});}
  catch(error){console.error('Attendance calendar settings query error:',error.message);res.status(500).json({ok:false,message:'Unable to load attendance calendar settings.'});}
});

app.post('/api/attendance-calendar-settings', authenticate, async (req,res)=>{
  const d=req.body||{},types=['Single Day','Date Range','Selected Dates','Weekly Pattern','All Working Days'],type=d.permissionType,dates=[...new Set((Array.isArray(d.selectedDates)?d.selectedDates:[]).filter(Boolean))],weekdays=[...new Set((Array.isArray(d.weekdays)?d.weekdays:[]).map(Number).filter(day=>day>=1&&day<=7))];
  if(!Number(d.academicYearId)||!types.includes(type))return res.status(400).json({ok:false,message:'Academic Year and Attendance Permission Type are required.'});
  if(type==='Single Day'&&!d.startDate)return res.status(400).json({ok:false,message:'Attendance Date is required.'});
  if(['Date Range','Weekly Pattern','All Working Days'].includes(type)&&(!d.startDate||!d.endDate||d.endDate<d.startDate))return res.status(400).json({ok:false,message:'Enter a valid From Date and To Date.'});
  if(type==='Selected Dates'&&!dates.length)return res.status(400).json({ok:false,message:'Select at least one attendance date.'});
  const client=await pool.connect();try{await client.query('BEGIN');const startDate=type==='Selected Dates'?dates[0]:d.startDate||null,endDate=type==='Selected Dates'?dates[dates.length-1]:(type==='Single Day'?d.startDate:d.endDate)||null;
    const saved=await client.query(`INSERT INTO academics.attendance_calendar_settings (academic_year_id,programme_id,programme_batch_id,semester_id,programme_section_id,permission_type,start_date,end_date,allow_attendance,attendance_open_time,attendance_close_time,remarks,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING attendance_calendar_setting_id`,[Number(d.academicYearId),d.programmeId?Number(d.programmeId):null,d.batchId?Number(d.batchId):null,d.semesterId?Number(d.semesterId):null,d.sectionId?Number(d.sectionId):null,type,startDate,endDate,d.allowAttendance!==false,d.openTime||null,d.closeTime||null,String(d.remarks||'').trim()||null,req.auth.userId]),settingId=saved.rows[0].attendance_calendar_setting_id;
    for(const day of weekdays)await client.query(`INSERT INTO academics.attendance_calendar_weekdays (attendance_calendar_setting_id,day_of_week,is_permitted) VALUES ($1,$2,TRUE)`,[settingId,day]);
    for(const date of dates)await client.query(`INSERT INTO academics.attendance_calendar_dates (attendance_calendar_setting_id,attendance_date,is_permitted,open_time,close_time) VALUES ($1,$2,$3,$4,$5)`,[settingId,date,d.allowAttendance!==false,d.openTime||null,d.closeTime||null]);
    await client.query('COMMIT');res.status(201).json({ok:true,message:'Attendance calendar setting saved successfully.'});
  }catch(error){await client.query('ROLLBACK').catch(()=>{});console.error('Attendance calendar setting save error:',error.message);res.status(500).json({ok:false,message:'Unable to save attendance calendar setting.'});}finally{client.release();}
});

app.get('/api/subject-wise-attendance-report', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT a.subject_teacher_allocation_id AS id,p.programme_code,
      b.batch_name,se.semester_name,COALESCE(sec.section_master_name,s.section_name) AS section_name,
      sm.subject_code,sm.subject_name,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS faculty_name
      FROM subject_teacher_allocations a
      JOIN admission_batches b ON b.batch_id=a.batch_id JOIN programmes p ON p.programme_id=b.programme_id
      JOIN semesters se ON se.semester_id=a.semester_id JOIN sections s ON s.section_id=a.section_id
      LEFT JOIN section_masters sec ON sec.section_master_id=s.section_master_id
      JOIN subject_masters sm ON sm.subject_master_id=a.subject_master_id
      LEFT JOIN employees e ON e.employee_id=a.employee_id
      WHERE a.status='ACTIVE' OR EXISTS (SELECT 1 FROM student_attendance_entries ae WHERE ae.subject_teacher_allocation_id=a.subject_teacher_allocation_id)
      ORDER BY p.programme_code,b.batch_name,se.semester_number,sm.subject_name,a.subject_teacher_allocation_id`);
    res.json({ok:true,rows:result.rows});
  }catch(error){console.error('Subject attendance report error:',error.message);res.status(500).json({ok:false,message:'Unable to load Subject-wise Attendance Report.'});}
});

app.get('/api/subject-wise-attendance-report/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isSafeInteger(id)||id<=0)return res.status(400).json({ok:false,message:'Select a valid subject allocation.'});
  try{
    const result=await pool.query(`SELECT ae.attendance_entry_id AS entry_id,ae.attendance_date::text AS date,
      ae.start_time,ae.end_time,d.student_id,d.attendance_status,
      COALESCE(NULLIF(st.registration_number,''),NULLIF(st.registration_no,''),st.student_code) AS registration_no,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS name
      FROM student_attendance_entries ae
      LEFT JOIN student_attendance_entry_students d ON d.attendance_entry_id=ae.attendance_entry_id
      LEFT JOIN students st ON st.student_id=d.student_id
      WHERE ae.subject_teacher_allocation_id=$1
      ORDER BY ae.attendance_date,ae.start_time,ae.attendance_entry_id,registration_no`,[id]);
    const sessions=new Map(),students=new Map();
    for(const row of result.rows){
      sessions.set(row.entry_id,{id:row.entry_id,date:row.date,startTime:row.start_time,endTime:row.end_time});
      if(!row.student_id)continue;
      if(!students.has(row.student_id))students.set(row.student_id,{id:row.student_id,registration_no:row.registration_no,name:row.name,attendance:{},present:0,total:0});
      const student=students.get(row.student_id);
      student.attendance[row.entry_id]=row.attendance_status;
      student.total++;
      if(row.attendance_status==='PRESENT')student.present++;
    }
    res.json({ok:true,sessions:[...sessions.values()],students:[...students.values()].sort((a,b)=>String(a.registration_no).localeCompare(String(b.registration_no))).map(student=>({...student,percentage:student.total?Math.round(100*student.present/student.total):0}))});
  }catch(error){console.error('Subject attendance detail error:',error.message);res.status(500).json({ok:false,message:'Unable to load subject attendance details.'});}
});

app.get('/api/student-attendance-report', authenticate, async (req,res)=>{
  const q=req.query,course=Number(q.course),batch=String(q.batch||'').split(':'),comparison=String(q.comparison||'');
  const validDate=value=>!value||(typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString().slice(0,10)===value&&value>='0001-01-01');
  const validId=value=>!value||(Number.isSafeInteger(Number(value))&&Number(value)>0);
  if(!course||!validId(q.course)||!validDate(q.from)||!validDate(q.to)||(q.from&&q.to&&q.from>q.to)||!validId(q.section)||!validId(q.subject)||(q.batch&&(batch.length!==2||!batch.every(x=>x&&validId(x))))||!['','lt','lte','eq','gte','gt'].includes(comparison)||(comparison&&(q.percentage===undefined||q.percentage===''||!Number.isFinite(Number(q.percentage))||Number(q.percentage)<0||Number(q.percentage)>100)))return res.status(400).json({ok:false,message:'Select a course and valid date, batch and percentage filters.'});
  try{
    const result=await pool.query(`SELECT st.student_id AS id,
      COALESCE(NULLIF(st.registration_number,''),NULLIF(st.registration_no,''),st.student_code) AS registration_no,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS name,
      COUNT(*)::int AS total,COUNT(*) FILTER(WHERE d.attendance_status='PRESENT')::int AS present,
      COUNT(*) FILTER(WHERE d.attendance_status='ABSENT')::int AS absent,
      ROUND(100.0*COUNT(*) FILTER(WHERE d.attendance_status='PRESENT')/COUNT(*),2) AS percentage
      FROM student_attendance_entry_students d
      JOIN student_attendance_entries ae ON ae.attendance_entry_id=d.attendance_entry_id
      JOIN subject_teacher_allocations a ON a.subject_teacher_allocation_id=ae.subject_teacher_allocation_id
      JOIN admission_batches b ON b.batch_id=a.batch_id
      JOIN subject_masters sm ON sm.subject_master_id=a.subject_master_id
      JOIN students st ON st.student_id=d.student_id
      WHERE b.programme_id=$1 AND ($2::date IS NULL OR ae.attendance_date >= $2)
      AND ($3::date IS NULL OR ae.attendance_date <= $3)
      AND ($4::bigint IS NULL OR a.batch_id=$4) AND ($5::bigint IS NULL OR a.semester_id=$5)
      AND ($6::bigint IS NULL OR a.section_id=$6) AND ($7::text IS NULL OR sm.subject_type=$7)
      AND ($8::bigint IS NULL OR a.subject_master_id=$8) AND COALESCE(st.is_deleted,FALSE)=FALSE
      GROUP BY st.student_id ORDER BY name,st.student_id`,[course,q.from||null,q.to||null,q.batch?Number(batch[0]):null,q.batch?Number(batch[1]):null,q.section?Number(q.section):null,q.type||null,q.subject?Number(q.subject):null]);
    const threshold=Number(q.percentage),matches=value=>({lt:value<threshold,lte:value<=threshold,eq:value===threshold,gte:value>=threshold,gt:value>threshold})[comparison];
    res.json({ok:true,rows:result.rows.filter(row=>!comparison||matches(Number(row.percentage)))});
  }catch(error){console.error('Student attendance report error:',error.message);res.status(500).json({ok:false,message:'Unable to generate student attendance report.'});}
});

app.get('/api/student-attendance', authenticate, async (_req,res)=>{
  try{const [entries,programmes,batches,semesters,sections,subjects,groups]=await Promise.all([
    pool.query(`SELECT ae.attendance_entry_id AS id,ae.attendance_date::text AS attendance_date,ae.start_time,ae.end_time,ae.topic_covered,ae.student_group,ae.strength,ae.present_count,ae.absent_count,p.programme_id,p.programme_code,b.batch_id,b.batch_name,se.semester_id,se.semester_name,s.section_id,COALESCE(sec.section_master_name,s.section_name) AS section_name,sm.subject_master_id,sm.subject_code,sm.subject_name,sm.subject_type,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS faculty_name FROM student_attendance_entries ae JOIN subject_teacher_allocations a ON a.subject_teacher_allocation_id=ae.subject_teacher_allocation_id JOIN admission_batches b ON b.batch_id=a.batch_id JOIN programmes p ON p.programme_id=b.programme_id JOIN semesters se ON se.semester_id=a.semester_id JOIN sections s ON s.section_id=a.section_id LEFT JOIN section_masters sec ON sec.section_master_id=s.section_master_id JOIN subject_masters sm ON sm.subject_master_id=a.subject_master_id LEFT JOIN employees e ON e.employee_id=a.employee_id ORDER BY ae.attendance_date DESC,ae.start_time DESC`),
    pool.query(`SELECT programme_id AS id,programme_code AS code,programme_name AS name FROM programmes WHERE is_active=TRUE ORDER BY programme_name`),
    pool.query(`SELECT batch_id AS id,programme_id,batch_name AS name FROM admission_batches WHERE is_active=TRUE ORDER BY admission_year DESC,batch_name`),
    pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name FROM semesters WHERE is_active=TRUE ORDER BY programme_id,semester_number`),
    pool.query(`SELECT s.section_id AS id,s.batch_id,s.semester_id,COALESCE(sm.section_master_name,s.section_name) AS name FROM sections s LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id WHERE s.is_active=TRUE ORDER BY name`),
    pool.query(`SELECT subject_master_id AS id,subject_code AS code,subject_name AS name,subject_type AS type FROM subject_masters WHERE is_active=TRUE ORDER BY subject_name`),
    pool.query(`SELECT DISTINCT UPPER(TRIM(student_group)) AS name FROM students WHERE NULLIF(TRIM(student_group),'') IS NOT NULL AND COALESCE(is_deleted,FALSE)=FALSE ORDER BY name`)
  ]);res.json({ok:true,entries:entries.rows,programmes:programmes.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows,subjects:subjects.rows,groups:groups.rows});}catch(error){console.error('Student attendance query error:',error.message);res.status(500).json({ok:false,message:'Unable to load student attendance.'});}
});

app.patch('/api/student-attendance/:id/date', authenticate, async (req,res)=>{
  const id=Number(req.params.id),date=req.body.date;
  if(!Number.isSafeInteger(id)||id<=0||typeof date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(Date.parse(date))||new Date(date).toISOString().slice(0,10)!==date||date<'0001-01-01')return res.status(400).json({ok:false,message:'Select a valid attendance date and entry.'});
  try{
    const result=await pool.query('UPDATE student_attendance_entries SET attendance_date=$1 WHERE attendance_entry_id=$2 RETURNING attendance_date::text AS date',[date,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Attendance entry not found.'});
    res.json({ok:true,date:result.rows[0].date});
  }catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Attendance already exists for this course, date and start time.':'Unable to update attendance date.'});}
});

app.get('/api/student-attendance/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Select a valid attendance entry.'});
  try{const entry=(await pool.query(`SELECT ae.attendance_entry_id AS id,ae.attendance_date,ae.start_time,ae.end_time,
      ae.topic_covered,p.programme_code,b.batch_name,se.semester_name,COALESCE(sec.section_master_name,s.section_name) AS section_name,
      sm.subject_code,sm.subject_name FROM student_attendance_entries ae
      JOIN subject_teacher_allocations a ON a.subject_teacher_allocation_id=ae.subject_teacher_allocation_id
      JOIN admission_batches b ON b.batch_id=a.batch_id JOIN programmes p ON p.programme_id=b.programme_id
      JOIN semesters se ON se.semester_id=a.semester_id JOIN sections s ON s.section_id=a.section_id
      LEFT JOIN section_masters sec ON sec.section_master_id=s.section_master_id
      JOIN subject_masters sm ON sm.subject_master_id=a.subject_master_id WHERE ae.attendance_entry_id=$1`,[id])).rows[0];
    if(!entry)return res.status(404).json({ok:false,message:'Attendance entry not found.'});
    const students=(await pool.query(`SELECT st.student_id AS id,
      COALESCE(NULLIF(st.registration_number,''),NULLIF(st.registration_no,''),st.student_code) AS registration_no,
      COALESCE(NULLIF(st.roll_number,''),NULLIF(st.roll_no,''),st.registration_number,st.student_code) AS attendance_serial_no,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS name,
      COALESCE(d.attendance_status,'ABSENT') AS status
      FROM student_attendance_entries ae JOIN subject_teacher_allocations a ON a.subject_teacher_allocation_id=ae.subject_teacher_allocation_id
      JOIN students st ON st.section_id=a.section_id AND COALESCE(st.is_deleted,FALSE)=FALSE AND st.is_active=TRUE
      LEFT JOIN student_attendance_entry_students d ON d.attendance_entry_id=ae.attendance_entry_id AND d.student_id=st.student_id
      WHERE ae.attendance_entry_id=$1 ORDER BY attendance_serial_no,st.student_id`,[id])).rows;
    res.json({ok:true,entry,students});
  }catch(error){console.error('Attendance detail query error:',error.message);res.status(500).json({ok:false,message:'Unable to load attendance details.'});}
});

app.put('/api/student-attendance/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body||{},startTime=String(data.startTime||''),endTime=String(data.endTime||''),statuses=Array.isArray(data.students)?data.students:[];
  if(!id||!startTime||!endTime||endTime<=startTime)return res.status(400).json({ok:false,message:'Enter a valid starting and ending time.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const entry=await client.query(`UPDATE student_attendance_entries SET start_time=$1,end_time=$2 WHERE attendance_entry_id=$3 RETURNING attendance_entry_id`,[startTime,endTime,id]);if(!entry.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Attendance entry not found.'});}
    for(const item of statuses){const studentId=Number(item.id),status=item.status==='PRESENT'?'PRESENT':'ABSENT';if(studentId)await client.query(`INSERT INTO student_attendance_entry_students (attendance_entry_id,student_id,attendance_status,created_by) VALUES ($1,$2,$3,$4) ON CONFLICT (attendance_entry_id,student_id) DO UPDATE SET attendance_status=EXCLUDED.attendance_status`,[id,studentId,status,req.auth.userId]);}
    const totals=(await client.query(`SELECT COUNT(*)::int AS strength,COUNT(*) FILTER (WHERE attendance_status='PRESENT')::int AS present FROM student_attendance_entry_students WHERE attendance_entry_id=$1`,[id])).rows[0];
    await client.query(`UPDATE student_attendance_entries SET strength=$1,present_count=$2,absent_count=$3 WHERE attendance_entry_id=$4`,[totals.strength,totals.present,totals.strength-totals.present,id]);
    await client.query('COMMIT');res.json({ok:true,message:'Attendance changes saved successfully.'});
  }catch(error){await client.query('ROLLBACK').catch(()=>{});res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Another attendance entry already uses this start time.':'Unable to update attendance.'});}finally{client.release();}
});

app.get('/api/subject-teacher-allocations/:id/attendance-options', authenticate, async (req,res)=>{
  const id=Number(req.params.id);
  if(!id)return res.status(400).json({ok:false,message:'Select a valid course.'});
  try{
    const allocation=(await pool.query(`SELECT a.academic_year_id,a.batch_id,a.semester_id,a.section_id,
      a.subject_master_id,a.employee_id FROM subject_teacher_allocations a
      WHERE a.subject_teacher_allocation_id=$1 AND a.status='ACTIVE'`,[id])).rows[0];
    if(!allocation)return res.status(404).json({ok:false,message:'The selected course allocation is not active.'});
    const [topics,students]=await Promise.all([
      pool.query(`SELECT t.lesson_plan_topic_id AS id,t.lesson_number,t.topic_description AS name,
        EXISTS (SELECT 1 FROM student_attendance_entries ae WHERE ae.subject_teacher_allocation_id=$7
          AND LOWER(TRIM(ae.topic_covered))=LOWER(TRIM(t.topic_description))) AS attendance_taken
        FROM academics.lesson_plan_topics t
        JOIN academics.lesson_plan_headers lp ON lp.lesson_plan_id=t.lesson_plan_id
        JOIN academics.faculty_subject_assignments fsa ON fsa.faculty_subject_assignment_id=lp.faculty_subject_assignment_id
        WHERE fsa.academic_year_id=$1 AND fsa.programme_batch_id=$2 AND fsa.semester_id=$3
          AND fsa.programme_section_id=$4 AND fsa.subject_id=$5 AND fsa.faculty_employee_id=$6
          AND fsa.assignment_status='Active' ORDER BY t.lesson_number`,[allocation.academic_year_id,allocation.batch_id,
          allocation.semester_id,allocation.section_id,allocation.subject_master_id,allocation.employee_id,id]),
      pool.query(`SELECT st.student_id AS id,
        COALESCE(NULLIF(st.registration_number,''),NULLIF(st.registration_no,''),st.student_code) AS code,
        TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS name
        FROM students st WHERE st.section_id=$1 AND COALESCE(st.is_deleted,FALSE)=FALSE AND st.is_active=TRUE
        ORDER BY COALESCE(NULLIF(st.roll_number,''),NULLIF(st.roll_no,''),st.registration_number,st.student_code),st.student_id`,[allocation.section_id])
    ]);
    res.json({ok:true,topics:topics.rows,students:students.rows});
  }catch(error){console.error('Attendance options query error:',error.message);res.status(500).json({ok:false,message:'Unable to load topics and students for this course.'});}
});

app.post('/api/student-attendance', authenticate, async (req,res)=>{
  const d=req.body,id=Number(d.subjectAllocationId);
  if(!id||!d.date||!d.startTime||!d.endTime||d.endTime<=d.startTime||!d.topic?.trim())return res.status(400).json({ok:false,message:'Complete all attendance fields with a valid time range.'});
  const presentIds=[...new Set((Array.isArray(d.presentStudentIds)?d.presentStudentIds:[]).map(Number).filter(Boolean))],client=await pool.connect();
  try{await client.query('BEGIN');const alreadyTaken=await client.query(`SELECT 1 FROM student_attendance_entries WHERE subject_teacher_allocation_id=$1 AND LOWER(TRIM(topic_covered))=LOWER(TRIM($2)) LIMIT 1`,[id,d.topic]);if(alreadyTaken.rowCount){await client.query('ROLLBACK');return res.status(409).json({ok:false,message:'Attendance Already Taken'});}const students=(await client.query(`SELECT st.student_id AS id FROM students st JOIN subject_teacher_allocations a ON a.section_id=st.section_id WHERE a.subject_teacher_allocation_id=$1 AND COALESCE(st.is_deleted,FALSE)=FALSE AND st.is_active=TRUE ORDER BY st.student_id`,[id])).rows,validIds=students.map(x=>Number(x.id)),validSet=new Set(validIds),selected=presentIds.filter(studentId=>validSet.has(studentId)),strength=validIds.length,present=selected.length,absent=strength-present;
    const entry=await client.query(`INSERT INTO student_attendance_entries (subject_teacher_allocation_id,attendance_date,start_time,end_time,topic_covered,strength,present_count,absent_count,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING attendance_entry_id`,[id,d.date,d.startTime,d.endTime,d.topic.trim(),strength,present,absent,req.auth.userId]);
    if(validIds.length)await client.query(`INSERT INTO student_attendance_entry_students (attendance_entry_id,student_id,attendance_status,created_by) SELECT $1,x,CASE WHEN x=ANY($2::bigint[]) THEN 'PRESENT' ELSE 'ABSENT' END,$3 FROM UNNEST($4::bigint[]) x`,[entry.rows[0].attendance_entry_id,selected,req.auth.userId,validIds]);
    await client.query('COMMIT');res.status(201).json({ok:true,message:'Student attendance saved successfully.'});
  }catch(error){await client.query('ROLLBACK').catch(()=>{});res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Attendance is already entered for this class and start time.':'Unable to save student attendance.'});}finally{client.release();}
});

app.get('/api/preferred-books', authenticate, async (req,res)=>{
  try{
    const employeeId=await authenticatedEmployeeId(req);
    const [subjects,books]=await Promise.all([
      pool.query(`SELECT DISTINCT sm.subject_master_id AS id,sm.subject_code AS code,sm.subject_name AS name
        FROM subject_masters sm
        LEFT JOIN academics.faculty_subject_assignments fsa ON fsa.subject_id=sm.subject_master_id
          AND fsa.assignment_status='Active'
        WHERE sm.is_active=TRUE AND ($1::bigint IS NULL OR fsa.faculty_employee_id=$1)
        ORDER BY sm.subject_name`,[employeeId]),
      pool.query(`SELECT pb.preferred_book_id AS id,pb.subject_master_id,sm.subject_code,sm.subject_name,
        pb.book_title,pb.author_name,pb.publisher_name,pb.edition,pb.isbn,pb.book_type,
        pb.display_order,pb.is_active FROM preferred_books pb
        JOIN subject_masters sm ON sm.subject_master_id=pb.subject_master_id
        WHERE $1::bigint IS NULL OR EXISTS (SELECT 1 FROM academics.faculty_subject_assignments fsa
          WHERE fsa.subject_id=pb.subject_master_id AND fsa.faculty_employee_id=$1
          AND fsa.assignment_status='Active')
        ORDER BY sm.subject_name,pb.display_order,pb.book_title`,[employeeId])
    ]);
    res.json({ok:true,subjects:subjects.rows,books:books.rows});
  }catch(error){console.error('Preferred books query error:',error.message);res.status(500).json({ok:false,message:'Unable to load preferred books.'});}
});

app.post('/api/preferred-books', authenticate, async (req,res)=>{
  const data=req.body;
  if(!Number(data.subjectId)||!data.title?.trim()||!data.author?.trim()||!['TEXT_BOOK','REFERENCE_BOOK','E_BOOK'].includes(data.bookType))return res.status(400).json({ok:false,message:'Subject, title, author, and book type are required.'});
  try{
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null){const allowed=await pool.query(`SELECT 1 FROM academics.faculty_subject_assignments
      WHERE subject_id=$1 AND faculty_employee_id=$2 AND assignment_status='Active' LIMIT 1`,[Number(data.subjectId),employeeId]);
      if(!allowed.rowCount)return res.status(403).json({ok:false,message:'You can add Preferred Books only for subjects assigned to your employee account.'});}
    const result=await pool.query(`INSERT INTO preferred_books
    (subject_master_id,book_title,author_name,publisher_name,edition,isbn,book_type,display_order,created_by)
    SELECT $1,$2,$3,$4,$5,$6,$7,COALESCE(MAX(display_order),0)+1,$8
    FROM preferred_books WHERE subject_master_id=$1 RETURNING preferred_book_id`,
    [Number(data.subjectId),data.title.trim(),data.author.trim(),data.publisher?.trim()||null,data.edition?.trim()||null,
      data.isbn?.trim()||null,data.bookType,req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].preferred_book_id,message:'Preferred book added successfully.'});}
  catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'This preferred book already exists for the selected subject.':error.code==='23503'?'Selected subject is invalid.':'Unable to add preferred book.'});}
});

app.put('/api/preferred-books/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body;
  if(!id||!Number(data.subjectId)||!data.title?.trim()||!data.author?.trim()||!['TEXT_BOOK','REFERENCE_BOOK','E_BOOK'].includes(data.bookType)||Number(data.displayOrder)<=0)return res.status(400).json({ok:false,message:'Complete all required preferred book fields.'});
  try{
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null){const allowed=await pool.query(`SELECT 1 FROM academics.faculty_subject_assignments
      WHERE subject_id=$1 AND faculty_employee_id=$2 AND assignment_status='Active' LIMIT 1`,[Number(data.subjectId),employeeId]);
      if(!allowed.rowCount)return res.status(403).json({ok:false,message:'You can edit Preferred Books only for subjects assigned to your employee account.'});}
    const result=await pool.query(`UPDATE preferred_books SET subject_master_id=$1,book_title=$2,
    author_name=$3,publisher_name=$4,edition=$5,isbn=$6,book_type=$7,display_order=$8,
    is_active=TRUE,updated_by=$9,updated_at=NOW() WHERE preferred_book_id=$10 RETURNING preferred_book_id`,
    [Number(data.subjectId),data.title.trim(),data.author.trim(),data.publisher?.trim()||null,data.edition?.trim()||null,
      data.isbn?.trim()||null,data.bookType,Number(data.displayOrder),req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Preferred book not found.'});res.json({ok:true,message:'Preferred book updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This preferred book already exists.':'Unable to update preferred book.'});}
});

app.delete('/api/preferred-books/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid preferred book.'});
  try{
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null){const allowed=await pool.query(`SELECT 1 FROM preferred_books pb
      JOIN academics.faculty_subject_assignments fsa ON fsa.subject_id=pb.subject_master_id
      WHERE pb.preferred_book_id=$1 AND fsa.faculty_employee_id=$2 AND fsa.assignment_status='Active' LIMIT 1`,[id,employeeId]);
      if(!allowed.rowCount)return res.status(403).json({ok:false,message:'You can remove Preferred Books only for subjects assigned to your employee account.'});}
    const result=await pool.query('DELETE FROM preferred_books WHERE preferred_book_id=$1 RETURNING preferred_book_id',[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Preferred book not found.'});res.json({ok:true,message:'Preferred book removed successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to remove preferred book.'});}
});

app.get('/api/subject-teacher-allocations', authenticate, async (_req,res)=>{
  try{
    const [academicYears,batches,semesters,sections,subjects,teachers,allocations]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,year_label AS name,is_current FROM academic_years
        WHERE is_active=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT b.batch_id AS id,b.programme_id,b.batch_name AS name,p.programme_code,p.programme_name
        FROM admission_batches b JOIN programmes p ON p.programme_id=b.programme_id
        WHERE b.is_active=TRUE AND p.is_active=TRUE ORDER BY b.admission_year DESC,p.programme_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name,semester_number
        FROM semesters WHERE is_active=TRUE ORDER BY programme_id,semester_number`),
      pool.query(`SELECT s.section_id AS id,s.batch_id,s.semester_id,
        COALESCE(sm.section_master_name,s.section_name) AS name
        FROM sections s LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
        WHERE s.is_active=TRUE ORDER BY s.batch_id,s.section_name`),
      pool.query(`SELECT subject_master_id AS id,subject_code AS code,subject_name AS name,department_id
        FROM subject_masters WHERE is_active=TRUE ORDER BY subject_name`),
      pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,
        TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS name,e.department_id
        FROM employees e LEFT JOIN designations d ON d.designation_id=e.designation_id
        WHERE e.status='ACTIVE' AND COALESCE(d.designation_type,'TEACHING')='TEACHING'
        ORDER BY e.first_name,e.last_name`),
      pool.query(`SELECT a.subject_teacher_allocation_id AS id,a.academic_year_id,a.batch_id,a.semester_id,
        a.section_id,a.subject_master_id,a.employee_id,a.allocation_role,a.workload_hours,a.status,
        ay.year_label AS academic_year,p.programme_name,b.batch_name,se.semester_name,
        COALESCE(sec.section_master_name,s.section_name) AS section_name,
        sm.subject_code,sm.subject_name,TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS teacher_name
        FROM subject_teacher_allocations a
        JOIN academic_years ay ON ay.academic_year_id=a.academic_year_id
        JOIN admission_batches b ON b.batch_id=a.batch_id JOIN programmes p ON p.programme_id=b.programme_id
        JOIN semesters se ON se.semester_id=a.semester_id JOIN sections s ON s.section_id=a.section_id
        LEFT JOIN section_masters sec ON sec.section_master_id=s.section_master_id
        JOIN subject_masters sm ON sm.subject_master_id=a.subject_master_id
        JOIN employees e ON e.employee_id=a.employee_id ORDER BY a.created_at DESC`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,batches:batches.rows,semesters:semesters.rows,
      sections:sections.rows,subjects:subjects.rows,teachers:teachers.rows,allocations:allocations.rows});
  }catch(error){console.error('Subject teacher allocation query error:',error.message);res.status(500).json({ok:false,message:'Unable to load subject teacher allocations.'});}
});

app.post('/api/subject-teacher-allocations', authenticate, async (req,res)=>{
  const data=req.body,ids=[data.academicYearId,data.batchId,data.semesterId,data.sectionId,data.subjectId,data.employeeId];
  if(!ids.every(value=>Number(value))||!['PRIMARY','CO_TEACHER','LAB'].includes(data.role)||Number(data.hours)<=0)return res.status(400).json({ok:false,message:'Select all allocation fields and enter valid workload hours.'});
  try{
    const result=await pool.query(`INSERT INTO subject_teacher_allocations
      (academic_year_id,batch_id,semester_id,section_id,subject_master_id,employee_id,allocation_role,workload_hours,created_by)
      SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9
      WHERE EXISTS (SELECT 1 FROM sections s JOIN admission_batches b ON b.batch_id=s.batch_id
        JOIN semesters se ON se.semester_id=s.semester_id
        WHERE s.section_id=$4 AND b.batch_id=$2 AND se.semester_id=$3 AND b.programme_id=se.programme_id)
      RETURNING subject_teacher_allocation_id`,
      [...ids.map(Number),data.role,Number(data.hours),req.auth.userId]);
    if(!result.rowCount)return res.status(400).json({ok:false,message:'The selected batch, semester, and section do not belong together.'});
    res.status(201).json({ok:true,message:'Subject teacher assigned successfully.'});
  }catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'This teacher allocation already exists.':error.code==='23503'?'One of the selected records is invalid.':'Unable to assign subject teacher.'});}
});

app.put('/api/subject-teacher-allocations/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body,ids=[data.academicYearId,data.batchId,data.semesterId,data.sectionId,data.subjectId,data.employeeId];
  if(!id||!ids.every(value=>Number(value))||!['PRIMARY','CO_TEACHER','LAB'].includes(data.role)||Number(data.hours)<=0)return res.status(400).json({ok:false,message:'Select all allocation fields and enter valid workload hours.'});
  try{const result=await pool.query(`UPDATE subject_teacher_allocations SET academic_year_id=$1,batch_id=$2,
    semester_id=$3,section_id=$4,subject_master_id=$5,employee_id=$6,allocation_role=$7,
    workload_hours=$8,status='ACTIVE',updated_by=$9,updated_at=NOW() WHERE subject_teacher_allocation_id=$10
    RETURNING subject_teacher_allocation_id`,[...ids.map(Number),data.role,Number(data.hours),req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Allocation not found.'});res.json({ok:true,message:'Subject teacher allocation updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This teacher allocation already exists.':'Unable to update subject teacher allocation.'});}
});

app.delete('/api/subject-teacher-allocations/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid allocation.'});
  try{const result=await pool.query(`UPDATE subject_teacher_allocations SET status='INACTIVE',
    updated_by=$1,updated_at=NOW() WHERE subject_teacher_allocation_id=$2 AND status<>'INACTIVE'
    RETURNING subject_teacher_allocation_id`,[req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Allocation not found or already deleted.'});
    res.json({ok:true,message:'Subject teacher allocation deleted successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to delete subject teacher allocation.'});}
});

app.post('/api/subject-teacher-allocations/:id/restore', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid allocation.'});
  try{const result=await pool.query(`UPDATE subject_teacher_allocations SET status='ACTIVE',updated_by=$1,
    updated_at=NOW() WHERE subject_teacher_allocation_id=$2 RETURNING subject_teacher_allocation_id`,[req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Allocation not found.'});res.json({ok:true,message:'Allocation restored successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to restore allocation.'});}
});

app.get('/api/class-teacher-allocations', authenticate, async (_req,res)=>{
  try{
    const [academicYears,programmes,batches,semesters,sections,groups,teachers,allocations]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,year_label AS name,is_current FROM academic_years WHERE is_active=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT programme_id AS id,programme_code AS code,programme_name AS name FROM programmes WHERE is_active=TRUE ORDER BY programme_name`),
      pool.query(`SELECT batch_id AS id,programme_id,batch_name AS name FROM admission_batches WHERE is_active=TRUE ORDER BY admission_year DESC,batch_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name,semester_number FROM semesters WHERE is_active=TRUE ORDER BY programme_id,semester_number`),
      pool.query(`SELECT s.section_id AS id,s.batch_id,s.semester_id,COALESCE(sm.section_master_name,s.section_name) AS name FROM sections s LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id WHERE s.is_active=TRUE ORDER BY name`),
      pool.query(`SELECT DISTINCT UPPER(TRIM(student_group)) AS name FROM students WHERE NULLIF(TRIM(student_group),'') IS NOT NULL AND COALESCE(is_deleted,FALSE)=FALSE ORDER BY name`),
      pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name FROM employees e LEFT JOIN designations d ON d.designation_id=e.designation_id WHERE e.status='ACTIVE' AND COALESCE(d.designation_type,'TEACHING')='TEACHING' ORDER BY name`),
      pool.query(`SELECT a.class_teacher_allocation_id AS id,a.academic_year_id,a.programme_id,a.batch_id,a.semester_id,a.section_id,a.student_group,a.employee_id,a.teacher_type,a.status,ay.year_label AS academic_year,p.programme_code,p.programme_name,b.batch_name,se.semester_name,COALESCE(sm.section_master_name,s.section_name) AS section_name,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS teacher_name,(SELECT COUNT(*)::int FROM students st WHERE st.section_id=a.section_id AND COALESCE(st.is_deleted,FALSE)=FALSE AND (a.student_group='ALL' OR UPPER(COALESCE(st.student_group,''))=a.student_group)) AS student_count FROM class_teacher_allocations a JOIN academic_years ay ON ay.academic_year_id=a.academic_year_id JOIN programmes p ON p.programme_id=a.programme_id JOIN admission_batches b ON b.batch_id=a.batch_id JOIN semesters se ON se.semester_id=a.semester_id JOIN sections s ON s.section_id=a.section_id LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id JOIN employees e ON e.employee_id=a.employee_id ORDER BY a.created_at DESC`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,programmes:programmes.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows,groups:groups.rows,teachers:teachers.rows,allocations:allocations.rows});
  }catch(error){console.error('Class teacher allocation query error:',error.message);res.status(500).json({ok:false,message:'Unable to load class teacher allocations.'});}
});

app.post('/api/class-teacher-allocations', authenticate, async (req,res)=>{
  const d=req.body,ids=[d.academicYearId,d.programmeId,d.batchId,d.semesterId,d.sectionId,d.employeeId],group=String(d.studentGroup||'ALL').trim().toUpperCase();
  if(!ids.every(Number)||!['MAIN','ASSISTANT'].includes(d.teacherType)||!group)return res.status(400).json({ok:false,message:'Select all required class teacher fields.'});
  try{const result=await pool.query(`INSERT INTO class_teacher_allocations (academic_year_id,programme_id,batch_id,semester_id,section_id,student_group,employee_id,teacher_type,created_by) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 WHERE EXISTS (SELECT 1 FROM sections s JOIN admission_batches b ON b.batch_id=s.batch_id JOIN semesters se ON se.semester_id=s.semester_id WHERE s.section_id=$5 AND b.batch_id=$3 AND b.programme_id=$2 AND se.semester_id=$4 AND se.programme_id=$2) ON CONFLICT (academic_year_id,batch_id,semester_id,section_id,student_group) DO UPDATE SET employee_id=EXCLUDED.employee_id,teacher_type=EXCLUDED.teacher_type,programme_id=EXCLUDED.programme_id,status='ACTIVE',updated_by=$9,updated_at=NOW() RETURNING class_teacher_allocation_id`,[...ids.slice(0,5).map(Number),group,Number(d.employeeId),d.teacherType,req.auth.userId]);if(!result.rowCount)return res.status(400).json({ok:false,message:'The selected course, batch, semester, and section do not belong together.'});res.status(201).json({ok:true,message:'Class teacher assigned successfully.'});}
  catch(error){res.status(error.code==='23503'?400:500).json({ok:false,message:error.code==='23503'?'One of the selected records is invalid.':'Unable to assign class teacher.'});}
});

app.put('/api/class-teacher-allocations/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),d=req.body,ids=[d.academicYearId,d.programmeId,d.batchId,d.semesterId,d.sectionId,d.employeeId],group=String(d.studentGroup||'ALL').trim().toUpperCase();
  if(!id||!ids.every(Number)||!['MAIN','ASSISTANT'].includes(d.teacherType)||!group)return res.status(400).json({ok:false,message:'Select all required class teacher fields.'});
  try{const result=await pool.query(`UPDATE class_teacher_allocations SET academic_year_id=$1,programme_id=$2,batch_id=$3,semester_id=$4,section_id=$5,student_group=$6,employee_id=$7,teacher_type=$8,status='ACTIVE',updated_by=$9,updated_at=NOW() WHERE class_teacher_allocation_id=$10 RETURNING class_teacher_allocation_id`,[...ids.slice(0,5).map(Number),group,Number(d.employeeId),d.teacherType,req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Class teacher allocation not found.'});res.json({ok:true,message:'Class teacher allocation updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'A class teacher is already assigned to this class and group.':'Unable to update class teacher.'});}
});

app.delete('/api/class-teacher-allocations/:id', authenticate, async (req,res)=>{
  try{const result=await pool.query(`UPDATE class_teacher_allocations SET status='INACTIVE',updated_by=$1,updated_at=NOW() WHERE class_teacher_allocation_id=$2 RETURNING class_teacher_allocation_id`,[req.auth.userId,Number(req.params.id)]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Class teacher allocation not found.'});res.json({ok:true,message:'Class teacher allocation removed successfully.'});}catch(error){res.status(500).json({ok:false,message:'Unable to remove class teacher allocation.'});}
});

app.get('/api/substitute-teacher-allocations', authenticate, async (_req,res)=>{
  try{
    const [teachers,allocations]=await Promise.all([
      pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name FROM employees e LEFT JOIN designations d ON d.designation_id=e.designation_id WHERE e.status='ACTIVE' AND COALESCE(d.designation_type,'TEACHING')='TEACHING' ORDER BY name`),
      pool.query(`SELECT a.subject_teacher_allocation_id AS id,p.programme_code,b.batch_name,se.semester_name,COALESCE(sec.section_master_name,s.section_name) AS section_name,'ALL' AS student_group,sm.subject_code,sm.subject_name,a.employee_id,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS faculty_name,sub.substitute_teacher_allocation_id AS substitute_id,sub.substitute_employee_id,TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name)) AS substitute_name,sub.from_date,sub.to_date,sub.status AS configured_status,CASE WHEN sub.substitute_teacher_allocation_id IS NULL THEN 'NOT ALLOTTED' WHEN sub.status='ACTIVE' AND CURRENT_DATE BETWEEN sub.from_date AND sub.to_date THEN 'ACTIVE' ELSE 'INACTIVE' END AS effective_status FROM subject_teacher_allocations a JOIN admission_batches b ON b.batch_id=a.batch_id JOIN programmes p ON p.programme_id=b.programme_id JOIN semesters se ON se.semester_id=a.semester_id JOIN sections s ON s.section_id=a.section_id LEFT JOIN section_masters sec ON sec.section_master_id=s.section_master_id JOIN subject_masters sm ON sm.subject_master_id=a.subject_master_id JOIN employees e ON e.employee_id=a.employee_id LEFT JOIN LATERAL (SELECT x.* FROM substitute_teacher_allocations x WHERE x.subject_teacher_allocation_id=a.subject_teacher_allocation_id ORDER BY x.updated_at DESC NULLS LAST,x.created_at DESC LIMIT 1) sub ON TRUE LEFT JOIN employees re ON re.employee_id=sub.substitute_employee_id WHERE a.status='ACTIVE' ORDER BY a.created_at DESC`)
    ]);
    res.json({ok:true,teachers:teachers.rows,allocations:allocations.rows});
  }catch(error){console.error('Substitute teacher query error:',error.message);res.status(500).json({ok:false,message:'Unable to load substitute teacher allocations.'});}
});

app.post('/api/substitute-teacher-allocations/:subjectAllocationId', authenticate, async (req,res)=>{
  const subjectId=Number(req.params.subjectAllocationId),d=req.body,employeeId=Number(d.employeeId),substituteId=Number(d.substituteId||0);
  if(!subjectId||!employeeId||!d.fromDate||!d.toDate||d.toDate<d.fromDate)return res.status(400).json({ok:false,message:'Select a substitute teacher and a valid date range.'});
  try{
    const original=(await pool.query('SELECT employee_id FROM subject_teacher_allocations WHERE subject_teacher_allocation_id=$1 AND status=\'ACTIVE\'',[subjectId])).rows[0];
    if(!original)return res.status(404).json({ok:false,message:'Subject teacher allocation not found.'});
    if(Number(original.employee_id)===employeeId)return res.status(400).json({ok:false,message:'The substitute must be different from the assigned faculty.'});
    if(substituteId){const result=await pool.query(`UPDATE substitute_teacher_allocations SET substitute_employee_id=$1,from_date=$2,to_date=$3,status='ACTIVE',updated_by=$4,updated_at=NOW() WHERE substitute_teacher_allocation_id=$5 AND subject_teacher_allocation_id=$6 RETURNING substitute_teacher_allocation_id`,[employeeId,d.fromDate,d.toDate,req.auth.userId,substituteId,subjectId]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Substitute allocation not found.'});}
    else await pool.query(`INSERT INTO substitute_teacher_allocations (subject_teacher_allocation_id,original_employee_id,substitute_employee_id,from_date,to_date,created_by) VALUES ($1,$2,$3,$4,$5,$6)`,[subjectId,original.employee_id,employeeId,d.fromDate,d.toDate,req.auth.userId]);
    res.json({ok:true,message:'Substitute teacher allotted successfully.'});
  }catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'A substitute already exists for this date range.':'Unable to allot substitute teacher.'});}
});

app.patch('/api/substitute-teacher-allocations/:id/status', authenticate, async (req,res)=>{
  const id=Number(req.params.id),status=req.body.status;
  if(!id||!['ACTIVE','INACTIVE'].includes(status))return res.status(400).json({ok:false,message:'Invalid substitute status.'});
  try{const result=await pool.query(`UPDATE substitute_teacher_allocations SET status=$1,updated_by=$2,updated_at=NOW() WHERE substitute_teacher_allocation_id=$3 RETURNING substitute_teacher_allocation_id`,[status,req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Substitute allocation not found.'});res.json({ok:true,message:`Substitute allocation marked ${status.toLowerCase()}.`});}catch(error){res.status(500).json({ok:false,message:'Unable to update substitute status.'});}
});

app.get('/api/programme-semester-definitions', authenticate, async (_req,res)=>{
  try{
    const [courses,batches,semesters,definitions]=await Promise.all([
      pool.query(`SELECT programme_id AS id,programme_code AS code,programme_name AS name
        FROM programmes WHERE is_active=TRUE ORDER BY programme_code`),
      pool.query(`SELECT batch_id AS id,programme_id AS course_id,batch_name AS name,admission_year
        FROM admission_batches WHERE is_active=TRUE ORDER BY admission_year DESC,batch_name`),
      pool.query(`SELECT semester_id AS id,programme_id AS course_id,semester_number AS number,semester_name AS name
        FROM semesters WHERE is_active=TRUE ORDER BY programme_id,semester_number`),
      pool.query(`SELECT psd.programme_semester_id AS id,psd.course_id,psd.programme_batch_id,
        psd.semester_id,psd.class_type,psd.is_active,psd.consider_for_accounting,
        p.programme_code AS course_code,p.programme_name AS course_name,
        b.batch_name,se.semester_number,se.semester_name
        FROM programme_semester_definitions psd
        JOIN programmes p ON p.programme_id=psd.course_id
        JOIN admission_batches b ON b.batch_id=psd.programme_batch_id
        JOIN semesters se ON se.semester_id=psd.semester_id
        ORDER BY p.programme_code,b.admission_year DESC,se.semester_number,psd.class_type`)
    ]);
    res.json({ok:true,courses:courses.rows,batches:batches.rows,semesters:semesters.rows,definitions:definitions.rows});
  }catch(error){console.error('Programme semester query error:',error.message);res.status(500).json({ok:false,message:'Unable to load semester definitions.'});}
});

async function validateProgrammeSemesterDefinition(client,data){
  const courseId=Number(data.courseId),batchId=Number(data.programmeBatchId),semesterId=Number(data.semesterId);
  const classType=String(data.classType||'').toUpperCase();
  if(!courseId||!batchId||!semesterId||!['SECTION','HOUSE'].includes(classType))throw new Error('Course, Batch, Semester, and Class Type are required.');
  const [batch,semester]=await Promise.all([
    client.query('SELECT batch_id FROM admission_batches WHERE batch_id=$1 AND programme_id=$2 AND is_active=TRUE',[batchId,courseId]),
    client.query('SELECT semester_id FROM semesters WHERE semester_id=$1 AND programme_id=$2 AND is_active=TRUE',[semesterId,courseId])
  ]);
  if(!batch.rowCount)throw new Error('Selected Batch does not belong to the selected Course.');
  if(!semester.rowCount)throw new Error('Selected Semester is not configured for the selected Course.');
  return {courseId,batchId,semesterId,classType,isActive:data.isActive!==false,considerForAccounting:Boolean(data.considerForAccounting)};
}

app.post('/api/programme-semester-definitions', authenticate, async (req,res)=>{
  const client=await pool.connect();
  try{const data=await validateProgrammeSemesterDefinition(client,req.body);const result=await client.query(`INSERT INTO programme_semester_definitions
    (course_id,programme_batch_id,semester_id,class_type,is_active,consider_for_accounting,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING programme_semester_id`,[data.courseId,data.batchId,data.semesterId,data.classType,data.isActive,data.considerForAccounting,req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].programme_semester_id,message:'Semester definition created successfully.'});
  }catch(error){res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'This Course, Batch, Semester, and Class Type combination already exists.':error.message});}finally{client.release();}
});

app.put('/api/programme-semester-definitions/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),client=await pool.connect();
  try{if(!id)throw new Error('Invalid semester definition.');const data=await validateProgrammeSemesterDefinition(client,req.body);const result=await client.query(`UPDATE programme_semester_definitions SET
    course_id=$1,programme_batch_id=$2,semester_id=$3,class_type=$4,is_active=$5,
    consider_for_accounting=$6,updated_by=$7,updated_at=NOW() WHERE programme_semester_id=$8 RETURNING programme_semester_id`,
    [data.courseId,data.batchId,data.semesterId,data.classType,data.isActive,data.considerForAccounting,req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Semester definition not found.'});res.json({ok:true,message:'Semester definition updated successfully.'});
  }catch(error){res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'This Course, Batch, Semester, and Class Type combination already exists.':error.message});}finally{client.release();}
});

app.delete('/api/programme-semester-definitions/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid semester definition.'});
  try{const result=await pool.query('DELETE FROM programme_semester_definitions WHERE programme_semester_id=$1 RETURNING programme_semester_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Semester definition not found.'});res.json({ok:true,message:'Semester definition deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This semester definition is in use and cannot be deleted.':'Unable to delete semester definition.'});}
});

app.get('/api/programmes-management', authenticate, async (_req,res)=>{
  try{
    const [programmes,departments,sectionMasters]=await Promise.all([
      pool.query(`SELECT p.programme_id AS id,p.programme_code AS code,p.programme_name AS name,
        p.programme_alias AS alias,p.programme_type,p.department_id,d.department_code,d.department_name,
        p.duration_years,p.total_semesters,p.award_type,p.affiliating_university,p.intake_capacity,
        p.status,p.is_active,COALESCE(b.approved_intake,p.intake_capacity,0) AS approved_intake,
        sec.section_master_id,sec.strength_limit AS section_capacity
        FROM programmes p JOIN departments d ON d.department_id=p.department_id
        LEFT JOIN LATERAL (SELECT approved_intake FROM admission_batches WHERE programme_id=p.programme_id
          ORDER BY admission_year DESC LIMIT 1) b ON TRUE
        LEFT JOIN LATERAL (SELECT s.section_master_id,s.strength_limit FROM sections s
          JOIN admission_batches ab ON ab.batch_id=s.batch_id WHERE ab.programme_id=p.programme_id
          ORDER BY ab.admission_year DESC,s.section_id LIMIT 1) sec ON TRUE ORDER BY p.programme_name`),
      pool.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE ORDER BY department_name'),
      pool.query('SELECT section_master_id AS id,section_master_code AS code,section_master_name AS name FROM section_masters WHERE is_active=TRUE ORDER BY section_master_name')
    ]);
    res.json({ok:true,programmes:programmes.rows,departments:departments.rows,sectionMasters:sectionMasters.rows});
  }catch(error){console.error('Programme management query error:',error.message);res.status(500).json({ok:false,message:'Unable to load programmes.'});}
});

app.post('/api/programmes-management', authenticate, async (req,res)=>{
  const data=req.body;
  if(!data.name?.trim()||!data.code?.trim()||!Number(data.departmentId)||Number(data.durationYears)<=0||Number(data.durationSemesters)<=0||!data.batchName?.trim()||!Number(data.admissionYear)||!data.startDate||!data.endDate||!Number(data.sectionMasterId)||Number(data.sectionCapacity)<=0)return res.status(400).json({ok:false,message:'Complete all required programme, batch, and section fields.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const programme=(await client.query(`INSERT INTO programmes
      (department_id,programme_code,programme_name,programme_alias,programme_level,programme_type,
       duration_years,total_semesters,intake_capacity,award_type,affiliating_university,status,is_active)
      VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (department_id,programme_code) DO UPDATE SET
        programme_name=EXCLUDED.programme_name,programme_alias=EXCLUDED.programme_alias,
        programme_level=EXCLUDED.programme_level,programme_type=EXCLUDED.programme_type,
        duration_years=EXCLUDED.duration_years,total_semesters=EXCLUDED.total_semesters,
        intake_capacity=EXCLUDED.intake_capacity,award_type=EXCLUDED.award_type,
        affiliating_university=EXCLUDED.affiliating_university,status=EXCLUDED.status,is_active=EXCLUDED.is_active
      RETURNING programme_id`,
      [Number(data.departmentId),data.code.trim().toUpperCase(),data.name.trim(),data.alias?.trim()||null,
       String(data.programmeType||'UNDERGRADUATE').toUpperCase(),Number(data.durationYears),Number(data.durationSemesters),
       Number(data.approvedIntake)||0,String(data.awardType||'DEGREE').toUpperCase(),data.affiliatingUniversity?.trim()||null,
       String(data.status||'ACTIVE').toUpperCase(),data.status!=='INACTIVE'])).rows[0];
    for(let number=1;number<=Number(data.durationSemesters);number++)await client.query(`INSERT INTO semesters
      (programme_id,semester_number,semester_name,year_number,is_active) VALUES ($1,$2,$3,$4,TRUE)
      ON CONFLICT (programme_id,semester_number) DO NOTHING`,[programme.programme_id,number,`Semester ${number}`,Math.ceil(number/2)]);
    const batch=(await client.query(`INSERT INTO admission_batches
      (programme_id,admission_year,batch_name,batch_alias,start_date,expected_end_date,
       approved_intake,lateral_entry_intake,status,is_active)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'ACTIVE',TRUE)
      ON CONFLICT (programme_id,admission_year) DO UPDATE SET
        batch_name=EXCLUDED.batch_name,batch_alias=EXCLUDED.batch_alias,start_date=EXCLUDED.start_date,
        expected_end_date=EXCLUDED.expected_end_date,approved_intake=EXCLUDED.approved_intake,
        lateral_entry_intake=EXCLUDED.lateral_entry_intake,status='ACTIVE',is_active=TRUE
      RETURNING batch_id`,
      [programme.programme_id,Number(data.admissionYear),data.batchName.trim(),data.batchAlias?.trim()||null,
       data.startDate,data.endDate,Number(data.approvedIntake)||0,Number(data.lateralEntryIntake)||0])).rows[0];
    if(data.sectionMasterId&&Number(data.sectionCapacity)>0){
      const academicYear=(await client.query(`SELECT academic_year_id FROM academic_years
        WHERE EXTRACT(YEAR FROM start_date)=$1 ORDER BY academic_year_id LIMIT 1`,[Number(data.admissionYear)])).rows[0];
      if(!academicYear)throw new Error(`Create Academic Year ${data.admissionYear}-${String(Number(data.admissionYear)+1).slice(-2)} before creating an initial section.`);
      const semester=(await client.query('SELECT semester_id FROM semesters WHERE programme_id=$1 AND semester_number=1',[programme.programme_id])).rows[0];
      let term=(await client.query(`SELECT term_id FROM academic_terms WHERE academic_year_id=$1 ORDER BY term_id LIMIT 1`,[academicYear.academic_year_id])).rows[0];
      if(!term)term=(await client.query(`INSERT INTO academic_terms
        (academic_year_id,term_name,term_type,start_date,end_date,status) VALUES ($1,'Semester 1','SEMESTER',$2,$3,'ACTIVE') RETURNING term_id`,
        [academicYear.academic_year_id,data.startDate,data.endDate])).rows[0];
      const sectionMaster=(await client.query('SELECT section_master_name FROM section_masters WHERE section_master_id=$1 AND is_active=TRUE',[Number(data.sectionMasterId)])).rows[0];
      if(!sectionMaster)throw new Error('Section Master is invalid.');
      await client.query(`INSERT INTO sections
        (batch_id,semester_id,term_id,section_name,strength_limit,section_master_id,is_active)
        VALUES ($1,$2,$3,$4,$5,$6,TRUE)
        ON CONFLICT (batch_id,semester_id,term_id,section_name) DO UPDATE SET
          strength_limit=EXCLUDED.strength_limit,section_master_id=EXCLUDED.section_master_id,is_active=TRUE`,
        [batch.batch_id,semester.semester_id,term.term_id,sectionMaster.section_master_name,Number(data.sectionCapacity),Number(data.sectionMasterId)]);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,id:programme.programme_id,message:'Programme, batch, semesters, and initial section saved successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'Programme, batch, or section already exists.':error.message});}finally{client.release();}
});

app.put('/api/programmes-management/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body;if(!id||!data.name?.trim()||!data.code?.trim()||!Number(data.departmentId)||Number(data.durationYears)<=0||Number(data.durationSemesters)<=0||!Number(data.sectionMasterId)||Number(data.sectionCapacity)<=0)return res.status(400).json({ok:false,message:'Complete all required programme and section fields.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const result=await client.query(`UPDATE programmes SET department_id=$1,programme_code=$2,
      programme_name=$3,programme_alias=$4,programme_level=$5,programme_type=$5,duration_years=$6,
      total_semesters=$7,award_type=$8,affiliating_university=$9,status=$10,is_active=$11
      WHERE programme_id=$12 RETURNING programme_id`,
      [Number(data.departmentId),data.code.trim().toUpperCase(),data.name.trim(),data.alias?.trim()||null,
       String(data.programmeType||'UNDERGRADUATE').toUpperCase(),Number(data.durationYears),Number(data.durationSemesters),
       String(data.awardType||'DEGREE').toUpperCase(),data.affiliatingUniversity?.trim()||null,String(data.status||'ACTIVE').toUpperCase(),data.status!=='INACTIVE',id]);
    if(!result.rowCount)throw new Error('Programme not found.');
    const sectionMaster=(await client.query('SELECT section_master_name FROM section_masters WHERE section_master_id=$1 AND is_active=TRUE',[Number(data.sectionMasterId)])).rows[0];
    if(!sectionMaster)throw new Error('Section Master is invalid.');
    const existingSection=(await client.query(`SELECT s.section_id FROM sections s JOIN admission_batches b
      ON b.batch_id=s.batch_id WHERE b.programme_id=$1 ORDER BY b.admission_year DESC,s.section_id LIMIT 1`,[id])).rows[0];
    if(existingSection)await client.query(`UPDATE sections SET section_master_id=$1,section_name=$2,
      strength_limit=$3 WHERE section_id=$4`,[Number(data.sectionMasterId),sectionMaster.section_master_name,Number(data.sectionCapacity),existingSection.section_id]);
    else{
      const batch=(await client.query('SELECT batch_id,admission_year,start_date,expected_end_date FROM admission_batches WHERE programme_id=$1 ORDER BY admission_year DESC LIMIT 1',[id])).rows[0];
      const semester=(await client.query('SELECT semester_id FROM semesters WHERE programme_id=$1 AND semester_number=1',[id])).rows[0];
      if(!batch||!semester)throw new Error('Create a batch and first semester before adding a section.');
      const academicYear=(await client.query('SELECT academic_year_id FROM academic_years WHERE EXTRACT(YEAR FROM start_date)=$1 ORDER BY academic_year_id LIMIT 1',[batch.admission_year])).rows[0];
      if(!academicYear)throw new Error('Matching Academic Year is required to add the section.');
      let term=(await client.query('SELECT term_id FROM academic_terms WHERE academic_year_id=$1 ORDER BY term_id LIMIT 1',[academicYear.academic_year_id])).rows[0];
      if(!term)term=(await client.query(`INSERT INTO academic_terms
        (academic_year_id,term_name,term_type,start_date,end_date,status) VALUES ($1,'Semester 1','SEMESTER',$2,$3,'ACTIVE') RETURNING term_id`,
        [academicYear.academic_year_id,batch.start_date,batch.expected_end_date])).rows[0];
      await client.query(`INSERT INTO sections
        (batch_id,semester_id,term_id,section_name,strength_limit,section_master_id,is_active)
        VALUES ($1,$2,$3,$4,$5,$6,TRUE)`,
        [batch.batch_id,semester.semester_id,term.term_id,sectionMaster.section_master_name,Number(data.sectionCapacity),Number(data.sectionMasterId)]);
    }
    await client.query('COMMIT');res.json({ok:true,message:'Programme and section updated successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'Programme code or section already exists.':error.message});}finally{client.release();}
});

app.post('/api/programmes-management/:id/deactivate', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid programme.'});
  try{const result=await pool.query(`UPDATE programmes SET is_active=FALSE,status='INACTIVE' WHERE programme_id=$1 RETURNING programme_id`,[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Programme not found.'});res.json({ok:true,message:'Programme deactivated successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to deactivate programme.'});}
});

app.delete('/api/programmes-management/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid programme.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const programme=(await client.query('SELECT programme_id FROM programmes WHERE programme_id=$1 FOR UPDATE',[id])).rows[0];
    if(!programme){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Programme not found.'});}
    await client.query('DELETE FROM sections WHERE batch_id IN (SELECT batch_id FROM admission_batches WHERE programme_id=$1)',[id]);
    await client.query('DELETE FROM admission_batches WHERE programme_id=$1',[id]);
    await client.query('DELETE FROM semesters WHERE programme_id=$1',[id]);
    await client.query('DELETE FROM programmes WHERE programme_id=$1',[id]);
    await client.query('COMMIT');
    res.json({ok:true,message:'Programme removed successfully.'});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Programme delete error:',error.message);
    res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This programme contains student or academic records and cannot be removed. Deactivate it instead.':'Unable to remove programme.'});
  }finally{client.release();}
});

app.get('/api/programmes-management/:id/details', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid programme.'});
  try{const [batches,sections]=await Promise.all([
    pool.query(`SELECT batch_name,batch_alias,admission_year,start_date,expected_end_date,
      approved_intake,lateral_entry_intake,status FROM admission_batches WHERE programme_id=$1 ORDER BY admission_year DESC`,[id]),
    pool.query(`SELECT s.section_name,s.strength_limit,sm.section_master_code,b.batch_name,se.semester_name
      FROM sections s JOIN admission_batches b ON b.batch_id=s.batch_id JOIN semesters se ON se.semester_id=s.semester_id
      LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id WHERE b.programme_id=$1 ORDER BY b.admission_year DESC,s.section_name`,[id])
  ]);res.json({ok:true,batches:batches.rows,sections:sections.rows});}
  catch(error){res.status(500).json({ok:false,message:'Unable to load programme details.'});}
});

app.get('/api/programme-sections', authenticate, async (_req,res)=>{
  try{
    const [sections,programmes,batches,semesters,sectionMasters]=await Promise.all([
      pool.query(`SELECT s.section_id AS id,p.programme_id,p.programme_name,b.batch_id,b.batch_name,s.semester_id,
        s.section_master_id,COALESCE(sm.section_master_name,s.section_name) AS section_name,
        s.strength_limit AS capacity,s.is_active
        FROM sections s JOIN admission_batches b ON b.batch_id=s.batch_id
        JOIN programmes p ON p.programme_id=b.programme_id
        LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
        ORDER BY p.programme_name,b.admission_year DESC,s.section_name`),
      pool.query('SELECT programme_id AS id,programme_code AS code,programme_name AS name FROM programmes ORDER BY programme_name'),
      pool.query('SELECT batch_id AS id,programme_id,batch_name AS name FROM admission_batches ORDER BY admission_year DESC,batch_name'),
      pool.query('SELECT semester_id AS id,programme_id,semester_name AS name,semester_number FROM semesters WHERE is_active=TRUE ORDER BY semester_number'),
      pool.query('SELECT section_master_id AS id,section_master_code AS code,section_master_name AS name FROM section_masters WHERE is_active=TRUE ORDER BY section_master_name')
    ]);
    res.json({ok:true,sections:sections.rows,programmes:programmes.rows,batches:batches.rows,semesters:semesters.rows,sectionMasters:sectionMasters.rows});
  }catch(error){console.error('Programme sections query error:',error.message);res.status(500).json({ok:false,message:'Unable to load programme sections.'});}
});

app.post('/api/programme-sections', authenticate, async (req,res)=>{
  const batchId=Number(req.body.batchId),semesterId=Number(req.body.semesterId),items=Array.isArray(req.body.sections)?req.body.sections:[];
  if(!batchId||!semesterId||!items.length||items.some(item=>!Number(item.sectionMasterId)||Number(item.capacity)<=0))return res.status(400).json({ok:false,message:'Select a programme, batch, semester, and one or more sections with capacity.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const batch=(await client.query(`SELECT b.batch_id,b.programme_id,b.admission_year,b.start_date,b.expected_end_date
      FROM admission_batches b WHERE b.batch_id=$1`,[batchId])).rows[0];
    if(!batch)throw new Error('Selected batch is invalid.');
    const semester=(await client.query('SELECT semester_id FROM semesters WHERE semester_id=$1 AND programme_id=$2',[semesterId,batch.programme_id])).rows[0];
    if(!semester)throw new Error('Selected Semester is not configured for this programme.');
    const academicYear=(await client.query('SELECT academic_year_id FROM academic_years WHERE EXTRACT(YEAR FROM start_date)=$1 ORDER BY academic_year_id LIMIT 1',[batch.admission_year])).rows[0];
    if(!academicYear)throw new Error('Matching Academic Year is required before adding sections.');
    let term=(await client.query('SELECT term_id FROM academic_terms WHERE academic_year_id=$1 ORDER BY term_id LIMIT 1',[academicYear.academic_year_id])).rows[0];
    if(!term)term=(await client.query(`INSERT INTO academic_terms
      (academic_year_id,term_name,term_type,start_date,end_date,status) VALUES ($1,'Semester 1','SEMESTER',$2,$3,'ACTIVE') RETURNING term_id`,
      [academicYear.academic_year_id,batch.start_date,batch.expected_end_date])).rows[0];
    for(const item of items){
      const master=(await client.query('SELECT section_master_name FROM section_masters WHERE section_master_id=$1 AND is_active=TRUE',[Number(item.sectionMasterId)])).rows[0];
      if(!master)throw new Error('One of the selected Section Masters is invalid.');
      await client.query(`INSERT INTO sections
        (batch_id,semester_id,term_id,section_name,strength_limit,section_master_id,is_active)
        VALUES ($1,$2,$3,$4,$5,$6,TRUE)`,
        [batchId,semester.semester_id,term.term_id,master.section_master_name,Number(item.capacity),Number(item.sectionMasterId)]);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,message:`${items.length} programme section${items.length===1?'':'s'} added successfully.`});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'One or more selected sections already exist for this batch.':error.message});}finally{client.release();}
});

app.put('/api/programme-sections/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {sectionMasterId,capacity,status}=req.body;
  if(!id||!Number(sectionMasterId)||Number(capacity)<=0)return res.status(400).json({ok:false,message:'Section Master and Capacity are required.'});
  try{
    const master=(await pool.query('SELECT section_master_name FROM section_masters WHERE section_master_id=$1 AND is_active=TRUE',[Number(sectionMasterId)])).rows[0];
    if(!master)return res.status(400).json({ok:false,message:'Section Master is invalid.'});
    const result=await pool.query(`UPDATE sections SET section_master_id=$1,section_name=$2,
      strength_limit=$3,is_active=$4 WHERE section_id=$5 RETURNING section_id`,
      [Number(sectionMasterId),master.section_master_name,Number(capacity),status!=='INACTIVE',id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Programme section not found.'});res.json({ok:true,message:'Programme section updated successfully.'});
  }catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This section already exists in the batch.':'Unable to update programme section.'});}
});

app.delete('/api/programme-sections/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid programme section.'});
  try{const result=await pool.query('DELETE FROM sections WHERE section_id=$1 RETURNING section_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Programme section not found.'});res.json({ok:true,message:'Programme section deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This section is assigned to students or academic records and cannot be deleted.':'Unable to delete programme section.'});}
});

app.get('/api/programme-section-tools', authenticate, async (_req,res)=>{
  try{
    const [academicYears,programmes,batches,semesters,sections,sectionMasters,employees,students,merges]=await Promise.all([
      pool.query('SELECT academic_year_id AS id,year_label AS name FROM academic_years WHERE is_active=TRUE ORDER BY start_date DESC'),
      pool.query('SELECT programme_id AS id,programme_name AS name FROM programmes WHERE is_active=TRUE ORDER BY programme_name'),
      pool.query('SELECT batch_id AS id,programme_id,batch_name AS name,admission_year FROM admission_batches WHERE is_active=TRUE ORDER BY admission_year DESC'),
      pool.query('SELECT semester_id AS id,programme_id,semester_name AS name,semester_number FROM semesters WHERE is_active=TRUE ORDER BY semester_number'),
      pool.query(`SELECT s.section_id AS id,s.batch_id,s.semester_id,s.term_id,s.section_master_id,
        COALESCE(sm.section_master_name,s.section_name) AS name,s.strength_limit AS capacity,s.class_coordinator_id,s.is_active,
        COUNT(st.student_id)::INTEGER AS student_count
        FROM sections s LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
        LEFT JOIN students st ON st.section_id=s.section_id AND COALESCE(st.is_deleted,FALSE)=FALSE
        GROUP BY s.section_id,sm.section_master_name ORDER BY s.section_name`),
      pool.query('SELECT section_master_id AS id,section_master_name AS name FROM section_masters WHERE is_active=TRUE ORDER BY section_master_name'),
      pool.query(`SELECT employee_id AS id,TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM employees WHERE status='ACTIVE' ORDER BY first_name,last_name`),
      pool.query(`SELECT student_id AS id,section_id,student_code AS code,
        TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM students WHERE COALESCE(is_deleted,FALSE)=FALSE AND is_active=TRUE ORDER BY first_name,last_name`),
      pool.query(`SELECT m.merge_group_id AS id,m.first_section_id,m.second_section_id,
        m.merged_section_name,m.total_students,m.status,m.created_at,
        b1.batch_name,
        COALESCE(sm1.section_master_name,s1.section_name) AS first_section_name,
        COALESCE(sm2.section_master_name,s2.section_name) AS second_section_name
        FROM section_merge_groups m
        JOIN sections s1 ON s1.section_id=m.first_section_id
        JOIN sections s2 ON s2.section_id=m.second_section_id
        JOIN admission_batches b1 ON b1.batch_id=s1.batch_id
        LEFT JOIN section_masters sm1 ON sm1.section_master_id=s1.section_master_id
        LEFT JOIN section_masters sm2 ON sm2.section_master_id=s2.section_master_id
        ORDER BY m.created_at DESC LIMIT 100`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,programmes:programmes.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows,sectionMasters:sectionMasters.rows,employees:employees.rows,students:students.rows,merges:merges.rows});
  }catch(error){console.error('Programme section tools error:',error.message);res.status(500).json({ok:false,message:'Unable to load programme section options.'});}
});

app.post('/api/programme-sections/merge', authenticate, async (req,res)=>{
  const data=req.body,sourceIds=[...new Set((data.sourceSectionIds||[]).map(Number).filter(Boolean))];
  const name=String(data.mergedSectionName||'').trim(),status=String(data.status||'ACTIVE').toUpperCase();
  if(sourceIds.length!==2||!name||!['ACTIVE','INACTIVE'].includes(status))return res.status(400).json({ok:false,message:'Select exactly two sections and enter a valid merged section name and status.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const sources=(await client.query(`SELECT section_id,is_active FROM sections
      WHERE section_id=ANY($1::bigint[]) FOR UPDATE`,[sourceIds])).rows;
    if(sources.length!==2)throw new Error('Both selected sections must exist.');
    if(sources.some(row=>row.is_active===false))throw new Error('Both selected sections must be active.');
    const totalStudents=Number((await client.query(`SELECT COUNT(*) AS count FROM students
      WHERE section_id=ANY($1::bigint[]) AND COALESCE(is_deleted,FALSE)=FALSE`,[sourceIds])).rows[0].count);
    await client.query(`INSERT INTO section_merge_groups
      (first_section_id,second_section_id,merged_section_name,total_students,status,created_by)
      VALUES ($1,$2,$3,$4,$5,$6)`,[sourceIds[0],sourceIds[1],name,totalStudents,status,req.auth.userId]);
    await client.query('COMMIT');res.json({ok:true,message:'Sections merged successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}finally{client.release();}
});

app.put('/api/programme-sections/merge/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),name=String(req.body.mergedSectionName||'').trim(),status=String(req.body.status||'').toUpperCase();
  if(!id||!name||!['ACTIVE','INACTIVE'].includes(status))return res.status(400).json({ok:false,message:'Enter a valid merged section name and status.'});
  try{
    const result=await pool.query(`UPDATE section_merge_groups SET merged_section_name=$1,status=$2,
      updated_at=NOW(),updated_by=$3 WHERE merge_group_id=$4 RETURNING merge_group_id`,
      [name,status,req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Merged section not found.'});
    res.json({ok:true,message:'Merged section updated successfully.'});
  }catch(error){res.status(500).json({ok:false,message:'Unable to update merged section.'});}
});

app.delete('/api/programme-sections/merge/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid merged section.'});
  try{
    const result=await pool.query('DELETE FROM section_merge_groups WHERE merge_group_id=$1 RETURNING merge_group_id',[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Merged section not found.'});
    res.json({ok:true,message:'Merged section deleted successfully.'});
  }catch(error){res.status(500).json({ok:false,message:'Unable to delete merged section.'});}
});

app.post('/api/programme-sections/merge/:id/split', authenticate, async (req,res)=>{
  const id=Number(req.params.id),status=String(req.body.status||'INACTIVE').toUpperCase();
  const restoreIds=[...new Set((req.body.restoreSectionIds||[]).map(Number).filter(Boolean))];
  if(!id||!['ACTIVE','INACTIVE'].includes(status))return res.status(400).json({ok:false,message:'Enter valid split options.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const merged=(await client.query(`SELECT first_section_id,second_section_id FROM section_merge_groups
      WHERE merge_group_id=$1 FOR UPDATE`,[id])).rows[0];
    if(!merged)throw new Error('Merged section not found.');
    const originals=[Number(merged.first_section_id),Number(merged.second_section_id)];
    if(restoreIds.length!==2||originals.some(sectionId=>!restoreIds.includes(sectionId)))throw new Error('Both original sections must be selected.');
    await client.query('UPDATE sections SET is_active=TRUE WHERE section_id=ANY($1::bigint[])',[originals]);
    await client.query(`UPDATE section_merge_groups SET status=$1,updated_at=NOW(),updated_by=$2
      WHERE merge_group_id=$3`,[status,req.auth.userId,id]);
    await client.query('COMMIT');
    res.json({ok:true,message:'Merged section split successfully. Students remain in their original sections.'});
  }catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}
  finally{client.release();}
});

app.post('/api/programme-sections/split', authenticate, async (req,res)=>{
  const data=req.body,sourceId=Number(data.sourceSectionId),newSections=Array.isArray(data.newSections)?data.newSections:[];
  if(!sourceId||newSections.length<2||newSections.some(item=>!Number(item.sectionMasterId)||Number(item.capacity)<=0)||!data.effectiveDate)return res.status(400).json({ok:false,message:'Select a source and provide at least two valid new sections.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const source=(await client.query('SELECT * FROM sections WHERE section_id=$1 FOR UPDATE',[sourceId])).rows[0];
    if(!source)throw new Error('Source section not found.');
    const created=[];
    for(const item of newSections){
      const master=(await client.query('SELECT section_master_name FROM section_masters WHERE section_master_id=$1 AND is_active=TRUE',[Number(item.sectionMasterId)])).rows[0];
      if(!master)throw new Error('One of the new Section Masters is invalid.');
      let section;
      if(master.section_master_name===source.section_name)section=(await client.query(`UPDATE sections SET
        strength_limit=$1,class_coordinator_id=$2,section_master_id=$3,is_active=TRUE WHERE section_id=$4 RETURNING section_id`,
        [Number(item.capacity),item.classTeacherId?Number(item.classTeacherId):null,Number(item.sectionMasterId),sourceId])).rows[0];
      else section=(await client.query(`INSERT INTO sections
          (batch_id,semester_id,term_id,section_name,strength_limit,class_coordinator_id,section_master_id,is_active)
          VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE) RETURNING section_id`,
        [source.batch_id,source.semester_id,source.term_id,master.section_master_name,Number(item.capacity),item.classTeacherId?Number(item.classTeacherId):null,Number(item.sectionMasterId)])).rows[0];
      created.push(section.section_id);
    }
    const students=(await client.query('SELECT student_id FROM students WHERE section_id=$1 ORDER BY student_id FOR UPDATE',[sourceId])).rows;
    for(let index=0;index<students.length;index++)await client.query('UPDATE students SET section_id=$1 WHERE student_id=$2',[created[index%created.length],students[index].student_id]);
    if(data.deactivateSource!==false&&!created.some(id=>Number(id)===sourceId))await client.query('UPDATE sections SET is_active=FALSE WHERE section_id=$1',[sourceId]);
    await client.query('COMMIT');res.json({ok:true,message:'Programme section split successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'One of the new sections already exists for this semester.':error.message});}finally{client.release();}
});

app.get('/api/section-masters', authenticate, async (_req,res)=>{
  try{const result=await pool.query(`SELECT section_master_id AS id,section_master_code AS code,
    section_master_name AS name,is_active FROM section_masters ORDER BY section_master_name`);
    res.json({ok:true,sections:result.rows});}
  catch(error){res.status(500).json({ok:false,message:'Unable to load section masters.'});}
});

app.post('/api/section-masters', authenticate, async (req,res)=>{
  const name=req.body.name?.trim();if(!name)return res.status(400).json({ok:false,message:'Section Master Name is required.'});
  try{const result=await pool.query(`INSERT INTO section_masters
    (section_master_code,section_master_name,created_by) VALUES ($1,$2,$3) RETURNING section_master_id,section_master_code`,
    [sectionMasterCode(name),name,req.auth.userId]);res.status(201).json({ok:true,id:result.rows[0].section_master_id,code:result.rows[0].section_master_code,message:'Section Master created successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Section Master code or name already exists.':'Unable to create Section Master.'});}
});

app.put('/api/section-masters/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),name=req.body.name?.trim();if(!id||!name)return res.status(400).json({ok:false,message:'Section Master Name is required.'});
  try{const result=await pool.query(`UPDATE section_masters SET section_master_code=$1,
    section_master_name=$2,updated_at=NOW(),updated_by=$3 WHERE section_master_id=$4 RETURNING section_master_id`,
    [sectionMasterCode(name),name,req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Section Master not found.'});res.json({ok:true,message:'Section Master updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Section Master code or name already exists.':'Unable to update Section Master.'});}
});

app.delete('/api/section-masters/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid Section Master.'});
  try{const result=await pool.query('DELETE FROM section_masters WHERE section_master_id=$1 RETURNING section_master_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Section Master not found.'});res.json({ok:true,message:'Section Master deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This Section Master is in use and cannot be deleted.':'Unable to delete Section Master.'});}
});

app.get('/api/students/form-options', authenticate, async (_req,res)=>{
  try{
    const [departments,programmes,branches,academicYears,batches,semesters,sections,categories]=await Promise.all([
      pool.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE ORDER BY department_name'),
      pool.query('SELECT programme_id AS id,department_id,programme_code AS code,programme_name AS name FROM programmes WHERE is_active=TRUE ORDER BY programme_name'),
      pool.query('SELECT branch_id AS id,department_id,programme_id,branch_code AS code,branch_name AS name FROM student_branches WHERE is_active=TRUE ORDER BY branch_name'),
      pool.query('SELECT academic_year_id AS id,year_label AS code,COALESCE(academic_year_name,year_label) AS name FROM academic_years WHERE is_active=TRUE ORDER BY start_date DESC'),
      pool.query('SELECT batch_id AS id,programme_id,batch_name AS name,admission_year FROM admission_batches WHERE is_active=TRUE ORDER BY admission_year DESC'),
      pool.query('SELECT semester_id AS id,programme_id,semester_number AS number,semester_name AS name FROM semesters WHERE is_active=TRUE ORDER BY semester_number'),
      pool.query('SELECT section_id AS id,semester_id,section_name AS name FROM sections WHERE is_active=TRUE ORDER BY section_name'),
      pool.query('SELECT admission_category_id AS id,category_code AS code,category_name AS name FROM admission_categories WHERE is_active=TRUE ORDER BY category_name')
    ]);
    res.json({ok:true,departments:departments.rows,programmes:programmes.rows,branches:branches.rows,academicYears:academicYears.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows,categories:categories.rows});
  }catch(error){console.error('Student options error:',error.message);res.status(500).json({ok:false,message:'Unable to load student form options.'});}
});

app.get('/api/student-section-groups/options', authenticate, async (_req,res)=>{
  try{
    const [academicYears,batches,semesters,sections,sectionMasters]=await Promise.all([
      pool.query('SELECT academic_year_id AS id,year_label AS code,COALESCE(academic_year_name,year_label) AS name FROM academic_years WHERE is_active=TRUE ORDER BY start_date DESC'),
      pool.query(`SELECT b.batch_id AS id,b.programme_id,b.batch_name AS name,p.programme_name
        FROM admission_batches b JOIN programmes p ON p.programme_id=b.programme_id
        WHERE b.is_active=TRUE AND p.is_active=TRUE ORDER BY b.admission_year DESC,p.programme_name`),
      pool.query('SELECT semester_id AS id,programme_id,semester_number AS number,semester_name AS name FROM semesters WHERE is_active=TRUE ORDER BY semester_number'),
      pool.query(`SELECT s.section_id AS id,s.batch_id,s.semester_id,COALESCE(sm.section_master_name,s.section_name) AS name
        FROM sections s LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
        WHERE s.is_active=TRUE ORDER BY name`),
      pool.query(`SELECT section_master_id AS id,section_master_name AS name
        FROM section_masters WHERE is_active=TRUE ORDER BY section_master_name`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows,sectionMasters:sectionMasters.rows});
  }catch(error){console.error('Student section/group options error:',error.message);res.status(500).json({ok:false,message:'Unable to load section and group options.'});}
});

app.get('/api/student-section-groups/students', authenticate, async (req,res)=>{
  const academicYearId=Number(req.query.academicYearId),batchId=Number(req.query.batchId),semesterId=Number(req.query.semesterId);
  const start=String(req.query.start||'').trim(),end=String(req.query.end||'').trim();
  if(!academicYearId||!batchId||!semesterId||!start||!end)return res.status(400).json({ok:false,message:'Select Academic Year, Programme Batch, Semester, and enter the Student ID range.'});
  try{
    const result=await pool.query(`SELECT st.student_id AS id,COALESCE(st.admission_number,st.registration_number,st.student_code) AS student_id,
      st.admission_number,st.registration_number,st.student_code,st.roll_number,
      TRIM(CONCAT(st.first_name,' ',st.middle_name,' ',st.last_name)) AS student_name,
      COALESCE(sm.section_master_name,s.section_name) AS current_section,st.student_group AS current_group
      FROM students st LEFT JOIN sections s ON s.section_id=st.section_id
      LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
      WHERE st.academic_year_id=$1
      AND st.programme_id=(SELECT programme_id FROM admission_batches WHERE batch_id=$2)
      AND (st.semester_id=$3 OR st.semester_id IS NULL)
      AND COALESCE(st.is_deleted,FALSE)=FALSE AND st.is_active=TRUE
      ORDER BY COALESCE(st.registration_number,st.student_code),st.student_id`,[academicYearId,batchId,semesterId]);
    const numeric=value=>{const match=String(value||'').match(/(\d+)\D*$/);return match?Number(match[1]):null;};
    const startNumber=numeric(start),endNumber=numeric(end);
    const students=result.rows.filter(item=>{const numbers=[item.id,item.student_id,item.admission_number,item.registration_number,item.student_code,item.roll_number].map(numeric).filter(value=>value!==null);const low=Math.min(startNumber,endNumber),high=Math.max(startNumber,endNumber);return startNumber!==null&&endNumber!==null&&numbers.some(number=>number>=low&&number<=high);});
    res.json({ok:true,students});
  }catch(error){console.error('Student section/group list error:',error.message);res.status(500).json({ok:false,message:'Unable to load students for this range.'});}
});

app.post('/api/student-section-groups/assign', authenticate, async (req,res)=>{
  const studentIds=Array.isArray(req.body.studentIds)?req.body.studentIds.map(Number).filter(Boolean):[];
  let sectionId=Number(req.body.sectionId),sectionMasterId=Number(req.body.sectionMasterId),batchId=Number(req.body.batchId),semesterId=Number(req.body.semesterId),academicYearId=Number(req.body.academicYearId),group=String(req.body.group||'').trim();
  if(!studentIds.length||(!sectionId&&!sectionMasterId)||!batchId||!semesterId||!['Group -1','Group -2'].includes(group))return res.status(400).json({ok:false,message:'Select students, a Programme Batch, Semester, Section, and Group -1 or Group -2.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');
    let section=sectionId?(await client.query('SELECT section_id FROM sections WHERE section_id=$1 AND batch_id=$2 AND semester_id=$3 AND is_active=TRUE',[sectionId,batchId,semesterId])).rows[0]:null;
    if(!section&&sectionMasterId){
      const master=(await client.query('SELECT section_master_name FROM section_masters WHERE section_master_id=$1 AND is_active=TRUE',[sectionMasterId])).rows[0];
      if(!master)throw new Error('Selected Section Master is not active.');
      section=(await client.query(`SELECT section_id FROM sections WHERE batch_id=$1 AND semester_id=$2 AND section_master_id=$3 LIMIT 1`,[batchId,semesterId,sectionMasterId])).rows[0];
      if(section)await client.query('UPDATE sections SET is_active=TRUE WHERE section_id=$1',[section.section_id]);
      else{
        let term=(await client.query(`SELECT term_id FROM academic_terms WHERE academic_year_id=$1 AND term_type='SEMESTER' ORDER BY term_id LIMIT 1`,[academicYearId])).rows[0];
        if(!term){const year=(await client.query('SELECT start_date,end_date FROM academic_years WHERE academic_year_id=$1',[academicYearId])).rows[0];if(!year)throw new Error('Selected Academic Year is invalid.');term=(await client.query(`INSERT INTO academic_terms (academic_year_id,term_name,term_type,start_date,end_date,status) VALUES ($1,$2,'SEMESTER',$3,$4,'ACTIVE') RETURNING term_id`,[academicYearId,`Semester ${semesterId}`,year.start_date,year.end_date])).rows[0];}
        section=(await client.query(`INSERT INTO sections (batch_id,semester_id,term_id,section_name,strength_limit,section_master_id,is_active) VALUES ($1,$2,$3,$4,60,$5,TRUE) RETURNING section_id`,[batchId,semesterId,term.term_id,master.section_master_name,sectionMasterId])).rows[0];
      }
      sectionId=Number(section.section_id);
    }
    if(!section)throw new Error('Selected Section is not valid for this Programme Batch and Semester.');
    const result=await client.query(`UPDATE students SET batch_id=$1,semester_id=$2,section_id=$3,student_group=$4,updated_at=NOW(),updated_by=$5
      WHERE student_id=ANY($6::bigint[]) AND COALESCE(is_deleted,FALSE)=FALSE RETURNING student_id`,
      [batchId,semesterId,sectionId,group,req.auth.userId,studentIds]);
    if(!result.rowCount)throw new Error('No selected students were updated. Reload the student range and try again.');
    await client.query('COMMIT');
    res.json({ok:true,message:`Section and ${group} assigned to ${result.rowCount} students.`});
  }catch(error){await client.query('ROLLBACK');console.error('Student section/group assignment error:',error.message);res.status(400).json({ok:false,message:error.message});}finally{client.release();}
});

app.post('/api/students', authenticate, async (req,res)=>{
  const data=req.body;if(!data.admissionNumber?.trim()||!data.admissionDate||!data.studentName?.trim()||!Number(data.departmentId)||!Number(data.programmeId)||!Number(data.academicYearId)||!Number(data.semesterId))return res.status(400).json({ok:false,message:'Complete all required admission, academic, and personal fields.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const created=await insertStudent(client,data,req.auth.userId);await client.query('COMMIT');res.status(201).json({ok:true,...created,message:`Student saved. Registration: ${created.registrationNumber}, Roll: ${created.rollNumber}.`});}
  catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'Admission, registration, or roll number already exists.':error.message});}finally{client.release();}
});

app.post('/api/students/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 student rows.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const normalize=value=>String(value??'').trim().toLowerCase().replace(/[^a-z0-9]/g,'');
    const [departmentRows,programmeRows,academicYearRows,semesterRows,categoryRows]=await Promise.all([
      client.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE'),
      client.query('SELECT programme_id AS id,department_id,programme_code AS code,programme_name AS name FROM programmes WHERE is_active=TRUE'),
      client.query('SELECT academic_year_id AS id,year_label AS code,academic_year_name AS name,start_date,end_date FROM academic_years WHERE is_active=TRUE'),
      client.query('SELECT semester_id AS id,programme_id,semester_number AS number,semester_name AS name FROM semesters WHERE is_active=TRUE'),
      client.query('SELECT admission_category_id AS id,category_code AS code,category_name AS name FROM admission_categories WHERE is_active=TRUE')
    ]);
    const match=(items,value,keys=['code','name'])=>{const wanted=normalize(value);return wanted?items.find(item=>keys.some(key=>normalize(item[key])===wanted)):null;};
    for(let index=0;index<rows.length;index++){
      const row=rows[index],rowNumber=index+2;
      if(!String(row.admissionNumber||'').trim())throw new Error(`Row ${rowNumber}: Admission No is required.`);
      if(!String(row.studentName||'').trim())throw new Error(`Row ${rowNumber}: Student Name is required.`);
      let admissionDate,dateOfBirth;
      try{
        admissionDate=normalizeDateInput(row.admissionDate,'Admission Date');
        dateOfBirth=normalizeDateInput(row.dateOfBirth,'Date of Birth');
      }catch(error){throw new Error(`Row ${rowNumber}: ${error.message}`);}
      const department=match(departmentRows.rows,row.department);
      if(!department)throw new Error(`Row ${rowNumber}: Department "${row.department||'(blank)'}" was not found. Use an active department code or exact name.`);
      const departmentProgrammes=programmeRows.rows.filter(item=>Number(item.department_id)===Number(department.id));
      let programme=match(departmentProgrammes,row.programme);
      if(!programme){
        const wanted=normalize(row.programme);
        const partialMatches=wanted?departmentProgrammes.filter(item=>normalize(item.code).startsWith(wanted)||normalize(item.name).startsWith(wanted)):[];
        if(partialMatches.length===1)programme=partialMatches[0];
      }
      if(!programme)throw new Error(`Row ${rowNumber}: Programme "${row.programme||'(blank)'}" was not found under department "${row.department}". Use an active programme code or exact name.`);
      const academicWanted=normalize(row.academicYear);
      const academicYear=academicYearRows.rows.find(item=>{
        const yearOf=value=>value instanceof Date?String(value.getFullYear()):String(value||'').slice(0,4);
        const startYear=yearOf(item.start_date),endYear=yearOf(item.end_date);
        const yearAliases=[item.code,item.name,`${startYear}-${endYear}`,`${startYear}-${endYear.slice(-2)}`];
        return yearAliases.some(value=>normalize(value)===academicWanted);
      });
      if(!academicYear)throw new Error(`Row ${rowNumber}: Academic Year "${row.academicYear||'(blank)'}" was not found. Use the configured academic-year code or name.`);
      const semesterValue=String(row.semester||'').trim();
      const semesterNumber=(semesterValue.match(/\d+/)||[])[0];
      const semester=semesterValue?semesterRows.rows.find(item=>Number(item.programme_id)===Number(programme.id)&&(normalize(item.name)===normalize(semesterValue)||(semesterNumber&&Number(item.number)===Number(semesterNumber)))):null;
      if(semesterValue&&!semester)throw new Error(`Row ${rowNumber}: Semester "${row.semester}" was not found for programme "${row.programme}". Leave it blank to configure separately, or use a configured semester number/name.`);
      const category=row.admissionCategory?match(categoryRows.rows,row.admissionCategory):null;
      if(row.admissionCategory&&!category)throw new Error(`Row ${rowNumber}: Admission Category "${row.admissionCategory}" was not found.`);
      const departmentId=department.id,programmeId=programme.id,academicYearId=academicYear.id,semesterId=semester?.id||null,categoryId=category?.id||null;
      await insertStudent(client,{...row,admissionDate,dateOfBirth,departmentId,programmeId,academicYearId,semesterId,admissionCategoryId:categoryId},req.auth.userId);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} students imported successfully.`});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains a duplicate student number.':error.message});}finally{client.release();}
});

app.get('/api/students-management', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT st.student_id AS id,st.registration_number,st.student_code,
      TRIM(CONCAT(st.first_name,' ',st.middle_name,' ',st.last_name)) AS student_name,
      st.mobile_number,st.mobile,p.programme_name,
      CASE WHEN COALESCE(ab.admission_year,0)>0 THEN ab.batch_name ELSE COALESCE(ay.academic_year_name,ay.year_label,ab.batch_name) END AS batch_name,
      COALESCE(sm.section_master_name,s.section_name) AS section_name,
      ac.category_name,st.student_group,st.blood_group,st.status,st.is_active,st.email,st.admission_number
      FROM students st JOIN programmes p ON p.programme_id=st.programme_id
      JOIN admission_batches ab ON ab.batch_id=st.batch_id
      LEFT JOIN academic_years ay ON ay.academic_year_id=st.academic_year_id
      LEFT JOIN sections s ON s.section_id=st.section_id
      LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
      LEFT JOIN admission_categories ac ON ac.admission_category_id=st.admission_category_id
      WHERE COALESCE(st.is_deleted,FALSE)=FALSE
      ORDER BY NULLIF(REGEXP_REPLACE(COALESCE(st.registration_number,st.student_code,''),'[^0-9]','','g'),'')::NUMERIC ASC,
        COALESCE(st.registration_number,st.student_code) ASC,st.student_id ASC`);
    res.json({ok:true,students:result.rows});
  }catch(error){console.error('Manage students error:',error.message);res.status(500).json({ok:false,message:'Unable to load students.'});}
});

app.get('/api/students-management/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid student.'});
  try{
    const result=await pool.query(`SELECT st.*,st.student_profile_details,
      TRIM(CONCAT(st.first_name,' ',st.middle_name,' ',st.last_name)) AS student_name,
      p.programme_name,p.programme_code,
      CASE WHEN COALESCE(ab.admission_year,0)>0 THEN ab.batch_name ELSE COALESCE(ay.academic_year_name,ay.year_label,ab.batch_name) END AS batch_name,
      COALESCE(sm.section_master_name,s.section_name) AS section_name,ac.category_name,
      sp.father_name,sp.mother_name,sp.guardian_mobile
      FROM students st JOIN programmes p ON p.programme_id=st.programme_id
      JOIN admission_batches ab ON ab.batch_id=st.batch_id
      LEFT JOIN academic_years ay ON ay.academic_year_id=st.academic_year_id
      LEFT JOIN sections s ON s.section_id=st.section_id LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
      LEFT JOIN admission_categories ac ON ac.admission_category_id=st.admission_category_id
      LEFT JOIN student_parents sp ON sp.student_id=st.student_id
      WHERE st.student_id=$1 AND COALESCE(st.is_deleted,FALSE)=FALSE`,[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Student not found.'});
    res.json({ok:true,student:result.rows[0]});
  }catch(error){console.error('Student detail error:',error.message);res.status(500).json({ok:false,message:'Unable to load student details.'});}
});

app.put('/api/students-management/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),name=String(req.body.studentName||'').trim(),mobile=String(req.body.mobile||'').trim(),email=String(req.body.email||'').trim();
  if(!id||!name)return res.status(400).json({ok:false,message:'Student name is required.'});
  const parts=name.split(/\s+/),first=parts.shift(),last=parts.length>1?parts.pop():null,middle=parts.join(' ')||null;
  try{const profile=req.body.profileDetails||{};const result=await pool.query(`UPDATE students SET first_name=$1,middle_name=$2,last_name=$3,
    mobile=$4,mobile_number=$4,email=$5,gender=COALESCE($6,gender),date_of_birth=COALESCE($7,date_of_birth),
    blood_group=COALESCE($8,blood_group),student_profile_details=student_profile_details||$9::jsonb,
    updated_at=NOW(),updated_by=$10 WHERE student_id=$11 AND COALESCE(is_deleted,FALSE)=FALSE RETURNING student_id`,
    [first,middle,last,mobile||null,email||null,profile.gender||null,profile.dateOfBirth||null,profile.bloodGroup||null,JSON.stringify(profile),req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Student not found.'});res.json({ok:true,message:'Student updated successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to update student.'});}
});

app.post('/api/students-management/:id/status', authenticate, async (req,res)=>{
  const id=Number(req.params.id),active=req.body.active===true;
  try{const result=await pool.query(`UPDATE students SET is_active=$1,status=$2,updated_at=NOW(),updated_by=$3
    WHERE student_id=$4 AND COALESCE(is_deleted,FALSE)=FALSE RETURNING student_id`,[active,active?'ACTIVE':'INACTIVE',req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Student not found.'});res.json({ok:true,message:`Student ${active?'activated':'deactivated'} successfully.`});}
  catch(error){res.status(500).json({ok:false,message:'Unable to update student status.'});}
});

app.delete('/api/students-management/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);
  try{const result=await pool.query(`UPDATE students SET is_deleted=TRUE,is_active=FALSE,status='INACTIVE',
    deleted_at=NOW(),deleted_by=$1 WHERE student_id=$2 AND COALESCE(is_deleted,FALSE)=FALSE RETURNING student_id`,[req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Student not found.'});res.json({ok:true,message:'Student deleted successfully.'});}
  catch(error){console.error('Delete student error:',error.message);res.status(500).json({ok:false,message:`Unable to delete student: ${error.message}`});}
});

app.get('/api/students-registration-reset', authenticate, async (_req,res)=>{
  try{const result=await pool.query(`SELECT st.student_id AS id,st.student_code,st.first_name,st.middle_name,st.last_name,
    st.registration_number,p.programme_name,
    CASE WHEN COALESCE(ab.admission_year,0)>0 THEN ab.batch_name ELSE COALESCE(ay.academic_year_name,ay.year_label,ab.batch_name) END AS batch_name,
    COALESCE(sm.section_master_name,s.section_name) AS section_name,
    COALESCE(u.username,st.student_profile_details->>'loginId',st.registration_number) AS login_id FROM students st JOIN programmes p ON p.programme_id=st.programme_id
    JOIN admission_batches ab ON ab.batch_id=st.batch_id LEFT JOIN academic_years ay ON ay.academic_year_id=st.academic_year_id LEFT JOIN sections s ON s.section_id=st.section_id
    LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id LEFT JOIN users u ON u.user_id=st.user_id
    WHERE COALESCE(st.is_deleted,FALSE)=FALSE ORDER BY st.first_name,st.last_name`);
    res.json({ok:true,students:result.rows});}
  catch(error){console.error('Registration reset query error:',error.message);res.status(500).json({ok:false,message:'Unable to load student registration records.'});}
});

app.put('/api/students-registration-reset/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),registration=String(req.body.registrationNumber||'').trim(),login=registration;
  if(!id||!registration)return res.status(400).json({ok:false,message:'Registration number is required.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const student=(await client.query(`UPDATE students SET registration_number=$1,registration_no=$1,
    student_profile_details=student_profile_details||jsonb_build_object('loginId',$2::text),
    updated_at=NOW(),updated_by=$3 WHERE student_id=$4 AND COALESCE(is_deleted,FALSE)=FALSE RETURNING user_id`,[registration,login||registration,req.auth.userId,id])).rows[0];
    if(!student)throw new Error('Student not found.');if(student.user_id)await client.query('UPDATE users SET username=$1 WHERE user_id=$2',[login||registration,student.user_id]);
    await client.query('COMMIT');res.json({ok:true,message:'Student registration number updated successfully.'});}
  catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'Registration number or login ID already exists.':error.message});}
  finally{client.release();}
});

app.post('/api/students-password-reset/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid student.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const student=(await client.query(`SELECT st.user_id,
    COALESCE(u.username,st.student_profile_details->>'loginId',st.registration_number) AS login_id,
    TRIM(CONCAT(st.first_name,' ',st.middle_name,' ',st.last_name)) AS student_name,st.email,st.mobile_number,st.mobile
    FROM students st LEFT JOIN users u ON u.user_id=st.user_id WHERE st.student_id=$1 AND COALESCE(st.is_deleted,FALSE)=FALSE FOR UPDATE OF st`,[id])).rows[0];
    if(!student||!student.login_id)throw new Error('Student User Login ID is not available.');
    const temporaryPassword=`${student.login_id}@123`,passwordHash=await hashPassword(temporaryPassword);
    if(student.user_id)await client.query(`UPDATE users SET password_hash=$1,must_change_password=TRUE,
      failed_login_count=0,locked_until=NULL,is_active=TRUE,updated_at=NOW() WHERE user_id=$2`,[passwordHash,student.user_id]);
    else{const user=(await client.query(`INSERT INTO users (username,password_hash,email,mobile,display_name,user_type,must_change_password)
      VALUES ($1,$2,$3,$4,$5,'STUDENT',TRUE) RETURNING user_id`,[student.login_id,passwordHash,student.email||null,student.mobile_number||student.mobile||null,student.student_name])).rows[0];
      await client.query('UPDATE students SET user_id=$1,updated_at=NOW(),updated_by=$2 WHERE student_id=$3',[user.user_id,req.auth.userId,id]);}
    await client.query('COMMIT');res.json({ok:true,message:'Student password reset successfully.',temporaryPassword});}
  catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The User Login ID is already assigned to another account.':error.message});}
  finally{client.release();}
});

app.get('/api/students-restore', authenticate, async (_req,res)=>{
  try{const result=await pool.query(`SELECT st.student_id AS id,COALESCE(st.registration_number,st.student_code) AS student_code,
    st.first_name,st.last_name,COALESCE(sm.section_master_name,s.section_name) AS section_name,
    ab.batch_name,p.programme_name,st.deleted_at,st.deletion_reason
    FROM students st JOIN programmes p ON p.programme_id=st.programme_id
    JOIN admission_batches ab ON ab.batch_id=st.batch_id LEFT JOIN sections s ON s.section_id=st.section_id
    LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id
    WHERE COALESCE(st.is_deleted,FALSE)=TRUE ORDER BY st.deleted_at DESC NULLS LAST,st.first_name`);
    res.json({ok:true,students:result.rows});}
  catch(error){console.error('Restore students query error:',error.message);res.status(500).json({ok:false,message:'Unable to load deleted students.'});}
});

app.post('/api/students-restore/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid student.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const result=await client.query(`UPDATE students SET is_deleted=FALSE,is_active=TRUE,
    status='ACTIVE',deleted_at=NULL,deleted_by=NULL,deletion_reason=NULL,updated_at=NOW(),updated_by=$1
    WHERE student_id=$2 AND COALESCE(is_deleted,FALSE)=TRUE RETURNING student_id`,[req.auth.userId,id]);
    if(!result.rowCount)throw new Error('Deleted student not found.');
    await client.query(`INSERT INTO student_restore_history (student_id,restored_by,restored_at,restore_reason)
      VALUES ($1,$2,NOW(),$3)`,[id,req.auth.userId,String(req.body.reason||'Restored from Restore Students').trim()]);
    await client.query('COMMIT');res.json({ok:true,message:'Student restored successfully.'});}
  catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}
  finally{client.release();}
});

app.get('/api/classrooms', authenticate, async (_req,res)=>{
  try{
    const [campuses,buildings,types,facilityMasters,rooms]=await Promise.all([
      pool.query(`SELECT campus_id AS id,campus_code AS code,campus_name AS name
        FROM campuses WHERE is_active=TRUE ORDER BY campus_name`),
      pool.query(`SELECT building_id AS id,campus_id,building_code AS code,building_name AS name
        FROM buildings ORDER BY building_name`),
      pool.query(`SELECT classroom_type_id AS id,classroom_type_code AS code,classroom_type_name AS name
        FROM classroom_types WHERE is_active=TRUE ORDER BY classroom_type_name`),
      pool.query(`SELECT facility_id AS id,facility_code AS code,facility_name AS name
        FROM classroom_facility_masters WHERE is_active=TRUE ORDER BY facility_name`),
      pool.query(`SELECT r.classroom_id AS id,r.campus_id,r.building_id,r.room_no AS room_number,r.room_name,
          ct.classroom_type_name AS suitable_for,r.student_capacity AS capacity,r.floor_name AS floor_level,
          r.description,COALESCE(jsonb_agg(fm.facility_name ORDER BY fm.facility_name)
            FILTER (WHERE fm.facility_id IS NOT NULL),'[]'::jsonb) AS facilities,
          r.is_active,CASE WHEN r.is_active THEN 'Active' ELSE 'Inactive' END AS status,
          b.building_name,c.campus_name
        FROM classrooms r
        JOIN classroom_types ct ON ct.classroom_type_id=r.classroom_type_id
        LEFT JOIN buildings b ON b.building_id=r.building_id
        LEFT JOIN campuses c ON c.campus_id=r.campus_id
        LEFT JOIN classroom_facilities cf ON cf.classroom_id=r.classroom_id
        LEFT JOIN classroom_facility_masters fm ON fm.facility_id=cf.facility_id
        GROUP BY r.classroom_id,ct.classroom_type_name,b.building_name,c.campus_name
        ORDER BY r.room_no`)
    ]);
    res.json({ok:true,campuses:campuses.rows,buildings:buildings.rows,types:types.rows,
      facilityMasters:facilityMasters.rows,rooms:rooms.rows});
  }catch(error){
    console.error('Classroom query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load classrooms.'});
  }
});

function classroomValues(data){
  return [
    Number(data.campusId),Number(data.buildingId),String(data.suitableFor||'Theory Class').trim(),
    String(data.roomNumber||'').trim().toUpperCase(),String(data.roomName||'').trim(),
    String(data.floor||'').trim()||null,Number(data.capacity),
    String(data.description||'').trim()||null,data.status!=='Inactive'
  ];
}

app.post('/api/classrooms', authenticate, async (req,res)=>{
  const values=classroomValues(req.body);
  if(!values[0]||!values[1]||!values[3]||!values[4]||!Number.isInteger(values[6])||values[6]<1)
    return res.status(400).json({ok:false,message:'Campus, building, room number, room name, and a valid capacity are required.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const type=(await client.query(`SELECT classroom_type_id FROM classroom_types
      WHERE LOWER(classroom_type_name)=LOWER($1) AND is_active=TRUE`,[values[2]])).rows[0];
    if(!type){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'Select a valid classroom type.'});}
    const result=await client.query(`INSERT INTO classrooms
      (campus_id,building_id,classroom_type_id,room_no,room_name,floor_name,student_capacity,description,is_active,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING classroom_id`,
      [values[0],values[1],type.classroom_type_id,...values.slice(3),req.auth.userId]);
    const id=result.rows[0].classroom_id;
    for(const name of [...new Set(Array.isArray(req.body.facilities)?req.body.facilities:[])])
      await client.query(`INSERT INTO classroom_facilities (classroom_id,facility_id)
        SELECT $1,facility_id FROM classroom_facility_masters WHERE facility_name=$2 AND is_active=TRUE
        ON CONFLICT DO NOTHING`,[id,name]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,id,message:'Classroom created successfully.'});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Classroom save error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This room number already exists in the selected building.':'Unable to create classroom.'});
  }finally{client.release();}
});

app.put('/api/classrooms/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),values=classroomValues(req.body);
  if(!id||!values[0]||!values[1]||!values[3]||!values[4]||!Number.isInteger(values[6])||values[6]<1)
    return res.status(400).json({ok:false,message:'Campus, building, room number, room name, and a valid capacity are required.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const type=(await client.query(`SELECT classroom_type_id FROM classroom_types
      WHERE LOWER(classroom_type_name)=LOWER($1) AND is_active=TRUE`,[values[2]])).rows[0];
    if(!type){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'Select a valid classroom type.'});}
    const result=await client.query(`UPDATE classrooms SET campus_id=$1,building_id=$2,classroom_type_id=$3,
      room_no=$4,room_name=$5,floor_name=$6,student_capacity=$7,description=$8,is_active=$9,
      updated_by=$10,updated_at=NOW() WHERE classroom_id=$11 RETURNING classroom_id`,
      [values[0],values[1],type.classroom_type_id,...values.slice(3),req.auth.userId,id]);
    if(!result.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Classroom not found.'});}
    await client.query('DELETE FROM classroom_facilities WHERE classroom_id=$1',[id]);
    for(const name of [...new Set(Array.isArray(req.body.facilities)?req.body.facilities:[])])
      await client.query(`INSERT INTO classroom_facilities (classroom_id,facility_id)
        SELECT $1,facility_id FROM classroom_facility_masters WHERE facility_name=$2 AND is_active=TRUE
        ON CONFLICT DO NOTHING`,[id,name]);
    await client.query('COMMIT');
    res.json({ok:true,message:'Classroom updated successfully.'});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Classroom update error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This room number already exists in the selected building.':'Unable to update classroom.'});
  }finally{client.release();}
});

app.delete('/api/classrooms/:id', authenticate, async (req,res)=>{
  try{
    const result=await pool.query('DELETE FROM classrooms WHERE classroom_id=$1 RETURNING classroom_id',[Number(req.params.id)]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Classroom not found.'});
    res.json({ok:true,message:'Classroom deleted successfully.'});
  }catch(error){
    console.error('Classroom delete error:',error.message);
    res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This classroom is used by a timetable or another module and cannot be deleted.':'Unable to delete classroom.'});
  }
});

app.get('/api/campuses', authenticate, async (_req, res) => {
  try {
    const [institutions, campuses, buildings, departments] = await Promise.all([
      pool.query(`SELECT institution_id AS id,institution_code AS code,institution_name AS name FROM institutions WHERE is_active=TRUE ORDER BY institution_name`),
      pool.query(`SELECT c.campus_id AS id,c.campus_code AS code,c.campus_name AS name,
        'Campus' AS type,COUNT(DISTINCT d.department_id)::int AS department_count,
        i.city,CASE WHEN c.is_active THEN 'Active' ELSE 'Inactive' END AS status,
        c.address,i.address_line1,i.address_line2,i.district,i.state,i.postal_code,
        i.phone,i.email
        FROM campuses c JOIN institutions i ON i.institution_id=c.institution_id
        LEFT JOIN departments d ON d.institution_id=c.institution_id AND d.is_active=TRUE
        GROUP BY c.campus_id,i.institution_id ORDER BY c.campus_code`),
      pool.query(`SELECT b.building_id AS id,b.building_code AS code,b.building_name AS name,
        'Building' AS type,c.campus_id,c.campus_name,i.city,'Active' AS status
        FROM buildings b JOIN campuses c ON c.campus_id=b.campus_id
        JOIN institutions i ON i.institution_id=c.institution_id ORDER BY b.building_code`),
      pool.query(`SELECT d.department_id AS id,d.department_code AS code,d.department_name AS name,
        d.is_active,bd.building_id FROM departments d LEFT JOIN building_departments bd ON bd.department_id=d.department_id ORDER BY d.department_name`)
    ]);
    res.json({ ok:true, institutions:institutions.rows, campuses:campuses.rows, buildings:buildings.rows, departments:departments.rows });
  } catch (error) {
    console.error('Campus query error:', error.message);
    res.status(500).json({ ok:false, message:'Unable to load campus information from the database.' });
  }
});

app.post('/api/campuses', authenticate, async (req, res) => {
  const { entity, code, name, address, campusId, buildingId, departmentId, instituteProfile } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (entity === 'campus') {
      if (!code?.trim() || !name?.trim()) return res.status(400).json({ ok:false, message:'Campus code and name are required.' });
      let institutionId = Number(req.body.institutionId) || null;
      if (!institutionId) {
        const existing = await client.query('SELECT institution_id FROM institutions WHERE is_active=TRUE ORDER BY institution_id LIMIT 1');
        institutionId = existing.rows[0]?.institution_id;
      }
      if (!institutionId && instituteProfile?.instituteCode && instituteProfile?.instituteName) {
        const created = await client.query(`INSERT INTO institutions (institution_code,institution_name,address_line1,address_line2,city,district,state,postal_code,phone,email,website)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING institution_id`,[instituteProfile.instituteCode,instituteProfile.instituteName,instituteProfile.addressLine1||null,instituteProfile.addressLine2||null,instituteProfile.city||null,instituteProfile.district||null,instituteProfile.state||null,instituteProfile.pinCode||null,instituteProfile.phoneNumber||null,instituteProfile.officialEmail||null,instituteProfile.website||null]);
        institutionId=created.rows[0].institution_id;
      }
      if (!institutionId) return res.status(400).json({ ok:false, message:'Save Institute Profile before adding a campus.' });
      await client.query('INSERT INTO campuses (institution_id,campus_code,campus_name,address,is_active) VALUES ($1,$2,$3,$4,$5)',[institutionId,code.trim(),name.trim(),address?.trim()||null,req.body.isActive!==false]);
    } else if (entity === 'building') {
      if (!campusId || !code?.trim() || !name?.trim()) return res.status(400).json({ ok:false, message:'Campus, building code and building name are required.' });
      await client.query('INSERT INTO buildings (campus_id,building_code,building_name) VALUES ($1,$2,$3)',[campusId,code.trim(),name.trim()]);
    } else if (entity === 'assignment') {
      if (!buildingId || !departmentId) return res.status(400).json({ ok:false, message:'Building and department are required.' });
      await client.query('INSERT INTO building_departments (building_id,department_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',[buildingId,departmentId]);
    } else return res.status(400).json({ ok:false, message:'Invalid campus entry type.' });
    await client.query('COMMIT');
    res.status(201).json({ ok:true, message:'Information saved successfully.' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Campus save error:', error.message);
    res.status(error.code==='23505'?409:500).json({ ok:false, message:error.code==='23505'?'This code already exists.':'Unable to save information.' });
  } finally { client.release(); }
});

app.put('/api/campuses/:entity/:id', authenticate, async (req, res) => {
  const {entity}=req.params;
  const id=Number(req.params.id);
  const {code,name,address,campusId,isActive}=req.body;
  if(!id||!code?.trim()||!name?.trim()) return res.status(400).json({ok:false,message:'Code and name are required.'});
  try{
    let result;
    if(entity==='campus') result=await pool.query(`UPDATE campuses SET campus_code=$1,campus_name=$2,address=$3,is_active=$4 WHERE campus_id=$5 RETURNING campus_id`,[code.trim(),name.trim(),address?.trim()||null,isActive!==false,id]);
    else if(entity==='building'){
      if(!campusId) return res.status(400).json({ok:false,message:'Campus is required.'});
      result=await pool.query(`UPDATE buildings SET campus_id=$1,building_code=$2,building_name=$3 WHERE building_id=$4 RETURNING building_id`,[campusId,code.trim(),name.trim(),id]);
    }else return res.status(400).json({ok:false,message:'Invalid campus entry type.'});
    if(!result.rowCount) return res.status(404).json({ok:false,message:'Campus or building not found.'});
    res.json({ok:true,message:`${entity==='campus'?'Campus':'Building'} updated successfully.`});
  }catch(error){
    console.error('Campus update error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This code already exists.':'Unable to update information.'});
  }
});

app.delete('/api/campuses/:entity/:id', authenticate, async (req, res) => {
  const {entity}=req.params;
  const id=Number(req.params.id);
  if(!id||!['campus','building'].includes(entity)) return res.status(400).json({ok:false,message:'Invalid campus or building.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let result;
    if(entity==='campus'){
      await client.query(`DELETE FROM building_departments WHERE building_id IN (SELECT building_id FROM buildings WHERE campus_id=$1)`,[id]);
      await client.query(`DELETE FROM rooms WHERE building_id IN (SELECT building_id FROM buildings WHERE campus_id=$1)`,[id]);
      await client.query('DELETE FROM buildings WHERE campus_id=$1',[id]);
      result=await client.query('DELETE FROM campuses WHERE campus_id=$1 RETURNING campus_id',[id]);
    }else{
      await client.query('DELETE FROM building_departments WHERE building_id=$1',[id]);
      await client.query('DELETE FROM rooms WHERE building_id=$1',[id]);
      result=await client.query('DELETE FROM buildings WHERE building_id=$1 RETURNING building_id',[id]);
    }
    if(!result.rowCount) return res.status(404).json({ok:false,message:'Campus or building not found.'});
    await client.query('COMMIT');
    res.json({ok:true,message:`${entity==='campus'?'Campus':'Building'} deleted successfully.`});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Campus delete error:',error.message);
    res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This record is used by other academic information and cannot be deleted.':'Unable to delete information.'});
  }finally{client.release();}
});

app.get('/api/departments', authenticate, async (_req, res) => {
  try {
    const [departments, employees] = await Promise.all([
      pool.query(`SELECT d.department_id AS id,d.department_code AS code,d.department_name AS name,
        d.department_alias AS alias,d.department_type AS type,d.hod_employee_id AS hod_id,
        d.official_email,d.phone,d.is_active,
        TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS hod_name
        FROM departments d LEFT JOIN employees e ON e.employee_id=d.hod_employee_id
        ORDER BY d.department_name`),
      pool.query(`SELECT employee_id AS id,employee_code AS code,
        TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)) AS name
        FROM employees WHERE status='ACTIVE' ORDER BY first_name,last_name`)
    ]);
    res.json({ ok:true, departments:departments.rows, employees:employees.rows });
  } catch (error) {
    console.error('Department query error:', error.message);
    res.status(500).json({ ok:false, message:'Unable to load departments from the database.' });
  }
});

app.post('/api/departments', authenticate, async (req, res) => {
  const { code,name,alias,type,hodId,officialEmail,phone,isActive,instituteProfile }=req.body;
  if(!code?.trim()||!name?.trim()) return res.status(400).json({ok:false,message:'Department code and name are required.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let institutionId=(await client.query('SELECT institution_id FROM institutions WHERE is_active=TRUE ORDER BY institution_id LIMIT 1')).rows[0]?.institution_id;
    if(!institutionId&&instituteProfile?.instituteCode&&instituteProfile?.instituteName){
      const created=await client.query(`INSERT INTO institutions (institution_code,institution_name,address_line1,address_line2,city,district,state,postal_code,phone,email,website)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING institution_id`,[instituteProfile.instituteCode,instituteProfile.instituteName,instituteProfile.addressLine1||null,instituteProfile.addressLine2||null,instituteProfile.city||null,instituteProfile.district||null,instituteProfile.state||null,instituteProfile.pinCode||null,instituteProfile.phoneNumber||null,instituteProfile.officialEmail||null,instituteProfile.website||null]);
      institutionId=created.rows[0].institution_id;
    }
    if(!institutionId){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'Save Institute Profile before adding a department.'});}
    await client.query(`INSERT INTO departments (institution_id,department_code,department_name,department_alias,department_type,hod_employee_id,official_email,phone,is_active)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[institutionId,code.trim(),name.trim(),alias?.trim()||null,type||'ACADEMIC',hodId||null,officialEmail?.trim()||null,phone?.trim()||null,isActive!==false]);
    await client.query('COMMIT');res.status(201).json({ok:true,message:'Department saved successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Department save error:',error.message);res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Department code already exists.':'Unable to save department.'});}finally{client.release();}
});

app.put('/api/departments/:id', authenticate, async (req, res) => {
  const id=Number(req.params.id);
  const {code,name,alias}=req.body;
  if(!id||!code?.trim()||!name?.trim()) return res.status(400).json({ok:false,message:'Department code and name are required.'});
  try{
    const result=await pool.query(`UPDATE departments SET department_code=$1,department_name=$2,department_alias=$3
      WHERE department_id=$4 RETURNING department_id`,[code.trim(),name.trim(),alias?.trim()||null,id]);
    if(!result.rowCount) return res.status(404).json({ok:false,message:'Department not found.'});
    res.json({ok:true,message:'Department updated successfully.'});
  }catch(error){
    console.error('Department update error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Department code already exists.':'Unable to update department.'});
  }
});

app.delete('/api/departments/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);
  if(!id)return res.status(400).json({ok:false,message:'Invalid department.'});
  try{
    const result=await pool.query('DELETE FROM departments WHERE department_id=$1 RETURNING department_id',[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Department not found.'});
    res.json({ok:true,message:'Department deleted successfully.'});
  }catch(error){
    console.error('Department delete error:',error.message);
    res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This department is assigned to existing records and cannot be deleted. Remove its assignments first.':'Unable to delete department.'});
  }
});

app.get('/api/academic-years', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT academic_year_id AS id,year_label AS code,
      COALESCE(academic_year_name,'Academic Year '||year_label) AS name,start_date,end_date,
      admission_start_date,admission_end_date,is_current,allow_data_entry,
      allow_previous_year_edit,status,is_active FROM academic_years ORDER BY start_date DESC`);
    res.json({ok:true,academicYears:result.rows});
  }catch(error){console.error('Academic year query error:',error.message);res.status(500).json({ok:false,message:'Unable to load academic years.'});}
});

app.post('/api/academic-years', authenticate, async (req,res)=>{
  const {code,name,startDate,endDate,admissionStartDate,admissionEndDate,isCurrent,allowDataEntry,allowPreviousYearEdit,status,instituteProfile}=req.body;
  if(!code?.trim()||!name?.trim()||!startDate||!endDate) return res.status(400).json({ok:false,message:'Code, name, start date and end date are required.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let institutionId=(await client.query('SELECT institution_id FROM institutions WHERE is_active=TRUE ORDER BY institution_id LIMIT 1')).rows[0]?.institution_id;
    if(!institutionId&&instituteProfile?.instituteCode&&instituteProfile?.instituteName){const created=await client.query(`INSERT INTO institutions (institution_code,institution_name,city,state,email) VALUES ($1,$2,$3,$4,$5) RETURNING institution_id`,[instituteProfile.instituteCode,instituteProfile.instituteName,instituteProfile.city||null,instituteProfile.state||null,instituteProfile.officialEmail||null]);institutionId=created.rows[0].institution_id;}
    if(!institutionId){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'Save Institute Profile before adding an academic year.'});}
    if(isCurrent) await client.query('UPDATE academic_years SET is_current=FALSE WHERE institution_id=$1',[institutionId]);
    await client.query(`INSERT INTO academic_years (institution_id,year_label,academic_year_name,start_date,end_date,admission_start_date,admission_end_date,is_current,allow_data_entry,allow_previous_year_edit,status,is_active)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[institutionId,code.trim(),name.trim(),startDate,endDate,admissionStartDate||null,admissionEndDate||null,Boolean(isCurrent),allowDataEntry!==false,Boolean(allowPreviousYearEdit),status||'ACTIVE',status!=='INACTIVE']);
    await client.query('COMMIT');res.status(201).json({ok:true,message:'Academic year saved successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Academic year save error:',error.message);res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Academic year code already exists.':'Unable to save academic year.'});}finally{client.release();}
});

app.put('/api/academic-years/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,startDate,endDate,admissionStartDate,admissionEndDate,isCurrent,allowDataEntry,allowPreviousYearEdit,status}=req.body;
  if(!id||!code?.trim()||!name?.trim()||!startDate||!endDate) return res.status(400).json({ok:false,message:'Required academic year information is missing.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const current=await client.query('SELECT institution_id FROM academic_years WHERE academic_year_id=$1',[id]);if(!current.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Academic year not found.'});}if(isCurrent)await client.query('UPDATE academic_years SET is_current=FALSE WHERE institution_id=$1',[current.rows[0].institution_id]);await client.query(`UPDATE academic_years SET year_label=$1,academic_year_name=$2,start_date=$3,end_date=$4,admission_start_date=$5,admission_end_date=$6,is_current=$7,allow_data_entry=$8,allow_previous_year_edit=$9,status=$10,is_active=$11 WHERE academic_year_id=$12`,[code.trim(),name.trim(),startDate,endDate,admissionStartDate||null,admissionEndDate||null,Boolean(isCurrent),allowDataEntry!==false,Boolean(allowPreviousYearEdit),status||'ACTIVE',status!=='INACTIVE',id]);await client.query('COMMIT');res.json({ok:true,message:'Academic year updated successfully.'});}catch(error){await client.query('ROLLBACK');console.error('Academic year update error:',error.message);res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Academic year code already exists.':'Unable to update academic year.'});}finally{client.release();}
});

app.get('/api/employees-next-code', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT 'ABITEMP'||LPAD((
      COALESCE(MAX((REGEXP_MATCH(employee_code,'^ABITEMP([0-9]+)$'))[1]::INTEGER),0)+1
    )::TEXT,4,'0') AS employee_code FROM employees`);
    res.json({ok:true,employeeCode:result.rows[0].employee_code});
  }catch(error){res.status(500).json({ok:false,message:'Unable to generate the next employee code.'});}
});

app.post('/api/employees', authenticate, async (req,res)=>{
  const data=req.body;
  if(!data.firstName?.trim()||!data.gender||!data.department?.trim()||!data.designation?.trim()||!data.joiningDate||!data.mobile?.trim()){
    return res.status(400).json({ok:false,message:'Complete all required employee fields before saving.'});
  }
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query("SELECT pg_advisory_xact_lock(hashtext('abit_employee_code'))");
    const employeeCode=(await client.query(`SELECT 'ABITEMP'||LPAD((
      COALESCE(MAX((REGEXP_MATCH(employee_code,'^ABITEMP([0-9]+)$'))[1]::INTEGER),0)+1
    )::TEXT,4,'0') AS employee_code FROM employees`)).rows[0].employee_code;
    const institutionId=(await client.query('SELECT institution_id FROM institutions WHERE is_active=TRUE ORDER BY institution_id LIMIT 1')).rows[0]?.institution_id;
    if(!institutionId){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'Create an active institute before adding an employee.'});}
    const departmentId=(await client.query('SELECT department_id FROM departments WHERE institution_id=$1 AND LOWER(department_name)=LOWER($2) LIMIT 1',[institutionId,data.department.trim()])).rows[0]?.department_id;
    if(!departmentId){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'The selected department does not exist in the database.'});}
    const designationId=(await client.query('SELECT designation_id FROM designations WHERE LOWER(designation_name)=LOWER($1) LIMIT 1',[data.designation.trim()])).rows[0]?.designation_id||null;
    const campusId=data.campus?.trim()?(await client.query('SELECT campus_id FROM campuses WHERE institution_id=$1 AND LOWER(campus_name)=LOWER($2) LIMIT 1',[institutionId,data.campus.trim()])).rows[0]?.campus_id||null:null;
    const reportingId=data.reportingEmployee?.trim()?(await client.query(`SELECT employee_id FROM employees WHERE institution_id=$1 AND LOWER(TRIM(CONCAT(first_name,' ',middle_name,' ',last_name)))=LOWER($2) LIMIT 1`,[institutionId,data.reportingEmployee.trim()])).rows[0]?.employee_id||null:null;
    let userId=null;let temporaryPassword=null;
    if(data.createLogin){
      if(!data.username?.trim()||!data.role?.trim()){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'Username and role are required when Create Login is enabled.'});}
      temporaryPassword=`${employeeCode}@123`;
      const passwordHash=await hashPassword(temporaryPassword);
      const userResult=await client.query(`INSERT INTO users (username,password_hash,email,mobile,display_name,user_type,must_change_password)
        VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING user_id`,[data.username.trim(),passwordHash,data.officialEmail?.trim()||null,data.mobile.trim(),[data.firstName,data.middleName,data.lastName].filter(Boolean).join(' '),data.role.trim().toUpperCase().replaceAll(' ','_'),data.forcePasswordChange!==false]);
      userId=userResult.rows[0].user_id;
    }
    const result=await client.query(`INSERT INTO employees
      (user_id,institution_id,department_id,designation_id,employee_code,first_name,middle_name,last_name,gender,date_of_birth,date_of_joining,employment_type,official_email,personal_email,mobile,address,photo_url,status,blood_group,marital_status,alternate_mobile,permanent_address,aadhaar_number,pan_number,employee_category,campus_id,reporting_employee_id,bank_name,bank_account_number,bank_ifsc,bank_branch,document_names)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32) RETURNING employee_id`,
      [userId,institutionId,departmentId,designationId,employeeCode,data.firstName.trim(),data.middleName?.trim()||null,data.lastName?.trim()||null,data.gender,data.dateOfBirth||null,data.joiningDate,data.employeeType||null,data.officialEmail?.trim()||null,data.personalEmail?.trim()||null,data.mobile.trim(),data.presentAddress?.trim()||null,data.photoUrl||null,String(data.employmentStatus||'Active').toUpperCase().replaceAll(' ','_'),data.bloodGroup||null,data.maritalStatus||null,data.alternateMobile?.trim()||null,data.permanentAddress?.trim()||null,data.aadhaar?.trim()||null,data.pan?.trim().toUpperCase()||null,data.category||null,campusId,reportingId,data.bankName?.trim()||null,data.accountNumber?.trim()||null,data.ifsc?.trim().toUpperCase()||null,data.branch?.trim()||null,JSON.stringify(data.documentNames||[])]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,employeeId:result.rows[0].employee_id,employeeCode,message:`Employee ${employeeCode} saved successfully.`,temporaryPassword});
  }catch(error){
    await client.query('ROLLBACK');console.error('Employee save error:',error.message);
    const duplicate=error.code==='23505';
    res.status(duplicate?409:500).json({ok:false,message:duplicate?'Employee code, username or email already exists. Either delete or restore the existing employee.':'Unable to save employee to the database.'});
  }finally{client.release();}
});

app.get('/api/employees', authenticate, async (req,res)=>{
  try{
    const result=await pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,
      TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,
      d.department_name AS department,d.department_code AS department_code,
      dg.designation_name AS designation,e.employee_category AS category,
      e.employment_type AS employee_type,e.status,e.mobile,e.official_email,e.photo_url
      FROM employees e
      LEFT JOIN departments d ON d.department_id=e.department_id
      LEFT JOIN designations dg ON dg.designation_id=e.designation_id
      WHERE UPPER(COALESCE(e.status,'ACTIVE'))<>'DELETED'
      ORDER BY e.employee_code`);
    res.json({ok:true,employees:result.rows});
  }catch(error){
    console.error('Employee query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load employees from the database.'});
  }
});

app.get('/api/employee-logins', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT e.employee_id AS id,e.employee_code AS employee_id,
      e.first_name,e.last_name,
      TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS employee_name,
      e.photo_url,
      COALESCE(d.department_code,d.department_name,'—') AS department,
      COALESCE(dg.designation_name,'—') AS designation,
      COALESCE(ua.login_id,e.employee_code) AS login_id,
      COALESCE(ua.default_login,TRUE) AS default_login,
      COALESCE(ua.account_status,CASE WHEN e.status='ACTIVE' THEN 'ACTIVE' ELSE 'INACTIVE' END) AS status,
      ua.user_id AS account_id
      FROM employees e
      LEFT JOIN departments d ON d.department_id=e.department_id
      LEFT JOIN designations dg ON dg.designation_id=e.designation_id
      LEFT JOIN user_accounts ua ON ua.employee_id=e.employee_id
      ORDER BY e.employee_code`);
    res.json({ok:true,employees:result.rows});
  }catch(error){console.error('Employee login query error:',error.message);res.status(500).json({ok:false,message:'Unable to load employee login accounts.'});}
});

app.put('/api/employee-logins/:employeeId', authenticate, async (req,res)=>{
  const employeeId=Number(req.params.employeeId),loginId=String(req.body.loginId||'').trim(),defaultLogin=Boolean(req.body.defaultLogin);
  if(!employeeId||!loginId)return res.status(400).json({ok:false,message:'Employee and Login ID are required.'});
  if(loginId.length>100)return res.status(400).json({ok:false,message:'Login ID must not exceed 100 characters.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const employee=(await client.query(`SELECT e.employee_code,e.user_id,
      TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS employee_name
      FROM employees e WHERE e.employee_id=$1 FOR UPDATE`,[employeeId])).rows[0];
    if(!employee){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Employee not found.'});}
    const old=(await client.query('SELECT user_id,login_id FROM user_accounts WHERE employee_id=$1 FOR UPDATE',[employeeId])).rows[0];
    let accountId;
    if(old){
      accountId=(await client.query(`UPDATE user_accounts SET login_id=$1,default_login=$2,
        updated_by=$3,updated_at=NOW() WHERE employee_id=$4 RETURNING user_id`,
        [loginId,defaultLogin,req.auth.userId,employeeId])).rows[0].user_id;
    }else{
      const temporaryPassword=`${employee.employee_code}@123`;
      accountId=(await client.query(`INSERT INTO user_accounts
        (employee_id,login_id,password_hash,default_login,account_status,created_by)
        VALUES ($1,$2,$3,$4,'ACTIVE',$5) RETURNING user_id`,
        [employeeId,loginId,await hashPassword(temporaryPassword),defaultLogin,req.auth.userId])).rows[0].user_id;
    }
    await client.query(`INSERT INTO employee_login_history
      (user_id,employee_id,old_login_id,new_login_id,changed_by,remarks)
      VALUES ($1,$2,$3,$4,$5,$6)`,
      [accountId,employeeId,old?.login_id||null,loginId,req.auth.userId,old?'Employee login ID updated.':'Employee login account created.']);
    if(employee.user_id)await client.query('UPDATE users SET username=$1,updated_at=NOW() WHERE user_id=$2',[loginId,employee.user_id]);
    await client.query('COMMIT');
    res.json({ok:true,message:`Login ID for ${employee.employee_name} updated successfully.`});
  }catch(error){
    await client.query('ROLLBACK');console.error('Employee login update error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This Login ID is already assigned to another user.':'Unable to update employee login.'});
  }finally{client.release();}
});

app.put('/api/employee-passwords/:employeeId', authenticate, async (req,res)=>{
  const employeeId=Number(req.params.employeeId),newPassword=String(req.body.newPassword||''),temporaryPassword=req.body.temporaryPassword!==false;
  if(!employeeId||!newPassword)return res.status(400).json({ok:false,message:'Employee and new password are required.'});
  if(newPassword.length<8)return res.status(400).json({ok:false,message:'Password must contain at least 8 characters.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const employee=(await client.query(`SELECT e.employee_code,e.user_id,
      TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS employee_name
      FROM employees e WHERE e.employee_id=$1 FOR UPDATE`,[employeeId])).rows[0];
    if(!employee){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Employee not found.'});}
    const passwordHash=await hashPassword(newPassword);
    let account=(await client.query('SELECT user_id FROM user_accounts WHERE employee_id=$1 FOR UPDATE',[employeeId])).rows[0];
    if(account){
      await client.query(`UPDATE user_accounts SET password_hash=$1,password_changed_at=NOW(),
        failed_login_attempts=0,account_status='ACTIVE',updated_by=$2,updated_at=NOW() WHERE user_id=$3`,
        [passwordHash,req.auth.userId,account.user_id]);
    }else{
      account=(await client.query(`INSERT INTO user_accounts
        (employee_id,login_id,password_hash,default_login,account_status,password_changed_at,created_by)
        VALUES ($1,$2,$3,TRUE,'ACTIVE',NOW(),$4) RETURNING user_id`,
        [employeeId,employee.employee_code,passwordHash,req.auth.userId])).rows[0];
    }
    if(employee.user_id)await client.query(`UPDATE users SET password_hash=$1,must_change_password=$2,
      failed_login_count=0,locked_until=NULL,updated_at=NOW() WHERE user_id=$3`,
      [passwordHash,temporaryPassword,employee.user_id]);
    await client.query(`INSERT INTO password_reset_history
      (user_id,reset_by,temporary_password,remarks) VALUES ($1,$2,$3,$4)`,
      [account.user_id,req.auth.userId,temporaryPassword,`Password reset for ${employee.employee_name}.`]);
    await client.query('COMMIT');
    res.json({ok:true,message:`Password for ${employee.employee_name} reset successfully.`});
  }catch(error){
    await client.query('ROLLBACK');console.error('Employee password reset error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Unable to create the employee account because its Login ID is already used.':'Unable to reset employee password.'});
  }finally{client.release();}
});

async function ensureEmployeeAccount(client,employeeId,createdBy){
  let account=(await client.query('SELECT user_id,login_id FROM user_accounts WHERE employee_id=$1',[employeeId])).rows[0];
  if(account)return account;
  const employee=(await client.query('SELECT employee_code FROM employees WHERE employee_id=$1',[employeeId])).rows[0];
  if(!employee)return null;
  const passwordHash=await hashPassword(`${employee.employee_code}@123`);
  account=(await client.query(`INSERT INTO user_accounts(employee_id,login_id,password_hash,default_login,created_by)
    VALUES($1,$2,$3,TRUE,$4) ON CONFLICT(employee_id) DO UPDATE SET employee_id=EXCLUDED.employee_id
    RETURNING user_id,login_id`,[employeeId,employee.employee_code,passwordHash,createdBy])).rows[0];
  return account;
}

app.get('/api/permission-management/options', authenticate, async (_req,res)=>{
  try{
    const [users,roles,modules,menus,permissions,rolePermissions]=await Promise.all([
      pool.query(`SELECT e.employee_id AS id,e.employee_code,
        TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS employee_name,
        COALESCE(d.department_code,d.department_name,'—') AS department,
        COALESCE(dg.designation_name,'—') AS designation,e.photo_url
        FROM employees e LEFT JOIN departments d ON d.department_id=e.department_id
        LEFT JOIN designations dg ON dg.designation_id=e.designation_id
        WHERE UPPER(COALESCE(e.status,'ACTIVE'))='ACTIVE' ORDER BY e.employee_code`),
      pool.query('SELECT role_id AS id,role_code AS code,role_name AS name FROM permission_management.roles WHERE status=TRUE ORDER BY role_name'),
      pool.query('SELECT module_id AS id,module_code AS code,module_name AS name FROM permission_management.system_modules WHERE status=TRUE ORDER BY display_order,module_name'),
      pool.query(`SELECT m.menu_id AS id,m.module_id,m.parent_menu_id,m.menu_code AS code,m.menu_name AS name,
        parent.menu_name AS parent_name,m.menu_path FROM permission_management.system_menus m
        LEFT JOIN permission_management.system_menus parent ON parent.menu_id=m.parent_menu_id
        WHERE m.status=TRUE ORDER BY m.module_id,COALESCE(parent.display_order,m.display_order),m.parent_menu_id NULLS FIRST,m.display_order,m.menu_name`),
      pool.query('SELECT permission_id AS id,permission_code AS code,permission_name AS name FROM permission_management.permissions WHERE status=TRUE ORDER BY permission_id'),
      pool.query('SELECT role_id,menu_id,permission_id,is_allowed FROM permission_management.role_permissions')
    ]);
    res.json({ok:true,userTypes:[{code:'EMPLOYEE',name:'Employee'}],users:users.rows,roles:roles.rows,
      modules:modules.rows,menus:menus.rows,permissions:permissions.rows,rolePermissions:rolePermissions.rows});
  }catch(error){console.error('Permission options error:',error.message);res.status(500).json({ok:false,message:'Unable to load permission options.'});}
});

app.get('/api/permission-management/:employeeId', authenticate, async (req,res)=>{
  const employeeId=Number(req.params.employeeId);if(!employeeId)return res.status(400).json({ok:false,message:'Select a valid employee.'});
  const client=await pool.connect();
  try{
    const account=await ensureEmployeeAccount(client,employeeId,req.auth.userId);
    if(!account)return res.status(404).json({ok:false,message:'Employee not found.'});
    const role=(await client.query(`SELECT ur.role_id FROM permission_management.user_roles ur WHERE ur.user_id=$1 AND ur.status=TRUE
      AND (ur.valid_to IS NULL OR ur.valid_to>=CURRENT_DATE) ORDER BY ur.assigned_at DESC LIMIT 1`,[account.user_id])).rows[0];
    const values=(await client.query(`SELECT m.menu_id,p.permission_id,
      COALESCE(up.is_allowed,rp.is_allowed,FALSE) AS is_allowed
      FROM permission_management.system_menus m CROSS JOIN permission_management.permissions p
      LEFT JOIN permission_management.user_permissions up ON up.user_id=$1 AND up.menu_id=m.menu_id AND up.permission_id=p.permission_id
      LEFT JOIN permission_management.role_permissions rp ON rp.role_id=$2 AND rp.menu_id=m.menu_id AND rp.permission_id=p.permission_id
      WHERE m.status=TRUE AND p.status=TRUE`,[account.user_id,role?.role_id||null])).rows;
    res.json({ok:true,roleId:role?.role_id||null,permissions:values});
  }catch(error){console.error('Permission load error:',error.message);res.status(500).json({ok:false,message:'Unable to load user permissions.'});}
  finally{client.release();}
});

app.put('/api/permission-management/:employeeId', authenticate, async (req,res)=>{
  const employeeId=Number(req.params.employeeId),roleId=Number(req.body.roleId),values=Array.isArray(req.body.permissions)?req.body.permissions:[];
  if(!employeeId||!roleId)return res.status(400).json({ok:false,message:'Select an employee and assigned role.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const account=await ensureEmployeeAccount(client,employeeId,req.auth.userId);
    if(!account){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Employee not found.'});}
    const actor=(await client.query(`SELECT ua.user_id FROM user_accounts ua JOIN employees e ON e.employee_id=ua.employee_id
      WHERE e.user_id=$1 LIMIT 1`,[req.auth.userId])).rows[0]?.user_id||null;
    const previousRole=(await client.query('SELECT role_id FROM permission_management.user_roles WHERE user_id=$1 AND status=TRUE ORDER BY assigned_at DESC LIMIT 1',[account.user_id])).rows[0]?.role_id;
    await client.query('UPDATE permission_management.user_roles SET status=FALSE WHERE user_id=$1',[account.user_id]);
    await client.query(`INSERT INTO permission_management.user_roles(user_id,role_id,department_id,status,assigned_by)
      SELECT $1,$2,e.department_id,TRUE,$3 FROM employees e WHERE e.employee_id=$4
      ON CONFLICT(user_id,role_id,department_id) DO UPDATE SET status=TRUE,assigned_by=EXCLUDED.assigned_by,assigned_at=NOW()`,
      [account.user_id,roleId,actor,employeeId]);
    if(Number(previousRole)!==roleId)await client.query(`INSERT INTO permission_management.permission_change_history
      (user_id,role_id,action_type,changed_by,remarks) VALUES($1,$2,'ROLE_ASSIGN',$3,'Assigned role updated.')`,
      [account.user_id,roleId,actor]);
    for(const value of values){
      const menuId=Number(value.menuId),permissionId=Number(value.permissionId),allowed=Boolean(value.isAllowed);
      if(!menuId||!permissionId)continue;
      const old=(await client.query('SELECT is_allowed FROM permission_management.user_permissions WHERE user_id=$1 AND menu_id=$2 AND permission_id=$3',
        [account.user_id,menuId,permissionId])).rows[0]?.is_allowed;
      await client.query(`INSERT INTO permission_management.user_permissions(user_id,menu_id,permission_id,is_allowed,remarks,granted_by)
        VALUES($1,$2,$3,$4,'User permission management',$5)
        ON CONFLICT(user_id,menu_id,permission_id) DO UPDATE SET is_allowed=EXCLUDED.is_allowed,
        remarks=EXCLUDED.remarks,granted_by=EXCLUDED.granted_by,granted_at=NOW()`,
        [account.user_id,menuId,permissionId,allowed,actor]);
      if(old===undefined||old!==allowed)await client.query(`INSERT INTO permission_management.permission_change_history
        (user_id,role_id,menu_id,permission_id,old_value,new_value,action_type,changed_by,remarks)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'User permission changed.')`,
        [account.user_id,roleId,menuId,permissionId,old??null,allowed,allowed?'GRANT':'REVOKE',actor]);
    }
    await client.query('COMMIT');res.json({ok:true,message:'User permissions saved successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Permission save error:',error.message);res.status(500).json({ok:false,message:'Unable to save user permissions.'});}
  finally{client.release();}
});

app.get('/api/employees-restore', authenticate, async (_req,res)=>{
  try{const result=await pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,e.first_name,e.last_name,
    d.department_name AS department,dg.designation_name AS designation,e.deleted_at
    FROM employees e LEFT JOIN departments d ON d.department_id=e.department_id
    LEFT JOIN designations dg ON dg.designation_id=e.designation_id
    WHERE UPPER(COALESCE(e.status,'ACTIVE'))='DELETED' ORDER BY e.deleted_at DESC NULLS LAST,e.employee_code`);
    res.json({ok:true,employees:result.rows});
  }catch(error){console.error('Employee restore query error:',error.message);res.status(500).json({ok:false,message:'Unable to load deleted employees.'});}
});

app.post('/api/employees-restore/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid employee.'});
  try{const result=await pool.query(`UPDATE employees SET status='ACTIVE',deleted_at=NULL WHERE employee_id=$1 AND UPPER(COALESCE(status,'ACTIVE'))='DELETED' RETURNING employee_id`,[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Deleted employee not found.'});
    res.json({ok:true,message:'Employee restored successfully.'});
  }catch(error){console.error('Employee restore error:',error.message);res.status(500).json({ok:false,message:'Unable to restore employee.'});}
});

app.get('/api/employees/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid employee.'});
  try{const result=await pool.query(`SELECT e.*,e.employee_id AS id,e.employee_code AS code,
    TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,
    d.department_name AS department,d.department_code,dg.designation_name AS designation,
    c.campus_name FROM employees e LEFT JOIN departments d ON d.department_id=e.department_id
    LEFT JOIN designations dg ON dg.designation_id=e.designation_id
    LEFT JOIN campuses c ON c.campus_id=e.campus_id WHERE e.employee_id=$1`,[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Employee not found.'});res.json({ok:true,employee:result.rows[0]});}
  catch(error){res.status(500).json({ok:false,message:'Unable to load employee details.'});}
});

app.put('/api/employees/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body;if(!id||!String(data.firstName||'').trim())return res.status(400).json({ok:false,message:'First name is required.'});
  try{const result=await pool.query(`UPDATE employees SET first_name=$1,middle_name=$2,last_name=$3,gender=$4,
    date_of_birth=$5,date_of_joining=$6,blood_group=$7,marital_status=$8,mobile=$9,official_email=$10,
    personal_email=$11,address=$12,permanent_address=$13,employee_category=$14,status=$15,photo_url=COALESCE($16,photo_url) WHERE employee_id=$17 RETURNING employee_id`,
    [data.firstName.trim(),data.middleName?.trim()||null,data.lastName?.trim()||null,data.gender||null,data.dateOfBirth||null,
      data.joiningDate||null,data.bloodGroup||null,data.maritalStatus||null,data.mobile?.trim()||null,data.officialEmail?.trim()||null,
      data.personalEmail?.trim()||null,data.address?.trim()||null,data.permanentAddress?.trim()||null,data.category||null,data.status||'ACTIVE',data.photoUrl||null,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Employee not found.'});res.json({ok:true,message:'Employee updated successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to update employee.'});}
});

app.delete('/api/employees/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid employee.'});
  try{const result=await pool.query(`UPDATE employees SET status='DELETED',deleted_at=NOW() WHERE employee_id=$1 AND UPPER(COALESCE(status,'ACTIVE'))<>'DELETED' RETURNING employee_id`,[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Employee not found.'});res.json({ok:true,message:'Employee deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This employee is referenced by other records and cannot be deleted.':'Unable to delete employee.'});}
});

app.get('/api/designations', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT designation_id AS id,designation_code AS code,
      designation_name AS name,short_name,designation_type AS type,
      designation_level AS level,sort_order,is_active
      FROM designations ORDER BY sort_order,designation_level,designation_name`);
    res.json({ok:true,designations:result.rows});
  }catch(error){
    console.error('Designation query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load designations from the database.'});
  }
});

app.post('/api/designations', authenticate, async (req,res)=>{
  const {code,name,shortName,type,level,displayOrder,status}=req.body;
  if(!code?.trim()||!name?.trim()) return res.status(400).json({ok:false,message:'Designation code and name are required.'});
  try{
    const result=await pool.query(`INSERT INTO designations
      (designation_code,designation_name,short_name,designation_type,designation_level,sort_order,is_active)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING designation_id`,
      [code.trim().toUpperCase(),name.trim(),shortName?.trim()||null,type||'TEACHING',Number(level)||null,Number(displayOrder)||0,status!=='INACTIVE']);
    res.status(201).json({ok:true,id:result.rows[0].designation_id,message:'Designation saved successfully.'});
  }catch(error){
    console.error('Designation save error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Designation code already exists.':'Unable to save designation.'});
  }
});

app.put('/api/designations/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),{code,name,shortName,type,status}=req.body;
  if(!id||!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Designation code and name are required.'});
  try{const result=await pool.query(`UPDATE designations SET designation_code=$1,designation_name=$2,
    short_name=$3,designation_type=$4,is_active=$5 WHERE designation_id=$6 RETURNING designation_id`,
    [code.trim().toUpperCase(),name.trim(),shortName?.trim()||null,type||'TEACHING',status!=='INACTIVE',id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Designation not found.'});res.json({ok:true,message:'Designation updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Designation code already exists.':'Unable to update designation.'});}
});

app.delete('/api/designations/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid designation.'});
  try{const result=await pool.query('DELETE FROM designations WHERE designation_id=$1 RETURNING designation_id',[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Designation not found.'});res.json({ok:true,message:'Designation deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This designation is assigned to employees and cannot be deleted.':'Unable to delete designation.'});}
});

app.get('/api/library/almiras', authenticate, async (_req,res)=>{
  try{
    const [almiras,libraries,rooms]=await Promise.all([
      pool.query(`SELECT a.almira_id AS id,a.almira_code AS code,a.almira_name AS name,
        a.number_of_shelves AS shelves,a.capacity,a.is_active,
        l.library_name AS library,r.room_name,r.room_number
        FROM library_almiras a JOIN libraries l ON l.library_id=a.library_id
        LEFT JOIN rooms r ON r.room_id=a.room_id ORDER BY a.almira_code`),
      pool.query(`SELECT library_id AS id,library_name AS name FROM libraries
        WHERE is_active=TRUE ORDER BY library_name`),
      pool.query(`SELECT room_id AS id,COALESCE(room_name,room_number) AS name,room_number
        FROM rooms WHERE is_active=TRUE ORDER BY COALESCE(room_name,room_number)`)
    ]);
    res.json({ok:true,almiras:almiras.rows,libraries:libraries.rows,rooms:rooms.rows});
  }catch(error){
    console.error('Almira query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load Almira records.'});
  }
});

app.post('/api/library/almiras', authenticate, async (req,res)=>{
  const {code,name,libraryId,roomId,shelves,capacity,status}=req.body;
  if(!code?.trim()||!name?.trim()||!libraryId||!Number(shelves)||!Number(capacity)){
    return res.status(400).json({ok:false,message:'Complete all required Almira fields.'});
  }
  try{
    const result=await pool.query(`INSERT INTO library_almiras
      (library_id,room_id,almira_code,almira_name,number_of_shelves,capacity,is_active)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING almira_id`,
      [libraryId,roomId||null,code.trim().toUpperCase(),name.trim(),Number(shelves),Number(capacity),status!=='INACTIVE']);
    res.status(201).json({ok:true,id:result.rows[0].almira_id,message:'Almira created successfully.'});
  }catch(error){
    console.error('Almira save error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Almira code already exists in this library.':'Unable to create Almira.'});
  }
});

app.post('/api/library/almiras/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];
  if(!rows.length||rows.length>500) return res.status(400).json({ok:false,message:'Upload between 1 and 500 Almira rows.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    for(let index=0;index<rows.length;index++){
      const row=rows[index];
      if(!row.code?.trim()||!row.name?.trim()||!row.library?.trim()||!Number(row.shelves)||!Number(row.capacity)) throw new Error(`Row ${index+2} has missing required values.`);
      const library=(await client.query('SELECT library_id FROM libraries WHERE LOWER(library_name)=LOWER($1) AND is_active=TRUE LIMIT 1',[row.library.trim()])).rows[0];
      if(!library) throw new Error(`Row ${index+2}: library "${row.library}" was not found.`);
      const room=row.room?.trim()?(await client.query('SELECT room_id FROM rooms WHERE LOWER(COALESCE(room_name,room_number))=LOWER($1) AND is_active=TRUE LIMIT 1',[row.room.trim()])).rows[0]:null;
      if(row.room?.trim()&&!room) throw new Error(`Row ${index+2}: room "${row.room}" was not found.`);
      await client.query(`INSERT INTO library_almiras
        (library_id,room_id,almira_code,almira_name,number_of_shelves,capacity,is_active)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,[library.library_id,room?.room_id||null,row.code.trim().toUpperCase(),row.name.trim(),Number(row.shelves),Number(row.capacity),String(row.status||'ACTIVE').toUpperCase()!=='INACTIVE']);
    }
    await client.query('COMMIT');
    res.status(201).json({ok:true,message:`${rows.length} Almira records imported successfully.`});
  }catch(error){
    await client.query('ROLLBACK');console.error('Almira bulk import error:',error.message);
    res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains an Almira code that already exists.':error.message});
  }finally{client.release();}
});

app.get('/api/library/authors', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT author_id AS id,author_code AS code,author_name AS name,alias,is_active
      FROM library_authors ORDER BY author_name`);
    res.json({ok:true,authors:result.rows});
  }catch(error){
    console.error('Author query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load library authors.'});
  }
});

app.post('/api/library/authors', authenticate, async (req,res)=>{
  const {name,alias}=req.body;
  if(!name?.trim()) return res.status(400).json({ok:false,message:'Author name is required.'});
  try{
    const result=await pool.query(`WITH created AS (
      INSERT INTO library_authors (author_name,alias,created_by) VALUES ($1,$2,$3) RETURNING author_id
    ) UPDATE library_authors a SET author_code='AUTH'||LPAD(a.author_id::text,4,'0')
      FROM created c WHERE a.author_id=c.author_id RETURNING a.author_id`,
      [name.trim(),alias?.trim()||null,req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].author_id,message:'Author created successfully.'});
  }catch(error){
    console.error('Author save error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This author already exists.':'Unable to create author.'});
  }
});

app.post('/api/library/authors/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];
  if(!rows.length||rows.length>500) return res.status(400).json({ok:false,message:'Upload between 1 and 500 author rows.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    for(let index=0;index<rows.length;index++){
      const row=rows[index];
      if(!row.name?.trim()) throw new Error(`Row ${index+2}: Author Name is required.`);
      await client.query(`WITH created AS (
        INSERT INTO library_authors (author_name,alias,created_by) VALUES ($1,$2,$3) RETURNING author_id
      ) UPDATE library_authors a SET author_code='AUTH'||LPAD(a.author_id::text,4,'0')
        FROM created c WHERE a.author_id=c.author_id`,[row.name.trim(),row.alias?.trim()||null,req.auth.userId]);
    }
    await client.query('COMMIT');
    res.status(201).json({ok:true,message:`${rows.length} authors imported successfully.`});
  }catch(error){
    await client.query('ROLLBACK');console.error('Author bulk import error:',error.message);
    res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains an author that already exists.':error.message});
  }finally{client.release();}
});

app.put('/api/library/authors/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {name,alias}=req.body;
  if(!id||!name?.trim()) return res.status(400).json({ok:false,message:'A valid author and name are required.'});
  try{
    const result=await pool.query(`UPDATE library_authors SET author_name=$1,alias=$2,
      updated_at=NOW(),updated_by=$3 WHERE author_id=$4 RETURNING author_id`,
      [name.trim(),alias?.trim()||null,req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Author not found.'});
    res.json({ok:true,message:'Author updated successfully.'});
  }catch(error){
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This author already exists.':'Unable to update author.'});
  }
});

app.delete('/api/library/authors/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);
  if(!id)return res.status(400).json({ok:false,message:'Invalid author.'});
  try{
    const result=await pool.query('DELETE FROM library_authors WHERE author_id=$1 RETURNING author_id',[id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Author not found.'});
    res.json({ok:true,message:'Author deleted successfully.'});
  }catch(error){
    res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This author is assigned to a book and cannot be deleted.':'Unable to delete author.'});
  }
});

app.get('/api/library/circulation/options', authenticate, async (_req,res)=>{
  try{
    const [staff,students,copies,issueTypes]=await Promise.all([
      pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,
        TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS name,
        d.department_id,d.department_name AS department,dg.designation_name AS designation,e.mobile AS contact
        FROM employees e LEFT JOIN departments d ON d.department_id=e.department_id
        LEFT JOIN designations dg ON dg.designation_id=e.designation_id WHERE e.status='ACTIVE' ORDER BY e.first_name,e.last_name`),
      pool.query(`SELECT s.student_member_id AS id,s.roll_number AS code,s.student_name AS name,
        s.programme,s.department_id,d.department_name AS department,s.semester,s.contact_number AS contact
        FROM library_student_members s LEFT JOIN departments d ON d.department_id=s.department_id
        WHERE s.is_active=TRUE ORDER BY s.student_name`),
      pool.query(`SELECT c.book_copy_id AS id,c.accession_number,b.book_id,t.title_name AS book_title,c.copy_status
        FROM library_book_copies c JOIN library_books b ON b.book_id=c.book_id
        JOIN library_titles t ON t.title_id=b.title_id ORDER BY c.accession_number`),
      pool.query(`SELECT issue_type_id AS id,issue_type_code AS code,issue_type_name AS name,
        member_type,issue_duration_days,maximum_books,fine_per_day
        FROM library_issue_types WHERE is_active=TRUE ORDER BY issue_type_name`)
    ]);
    res.json({ok:true,staff:staff.rows,students:students.rows,copies:copies.rows,issueTypes:issueTypes.rows});
  }catch(error){console.error('Circulation options error:',error.message);res.status(500).json({ok:false,message:'Unable to load circulation options.'});}
});

app.post('/api/library/circulation/issues', authenticate, async (req,res)=>{
  const {memberType,memberId,bookCopyId,issueTypeId,issueDate,dueDate,remarks}=req.body;
  const type=String(memberType||'').toUpperCase();
  if(!['STUDENT','STAFF'].includes(type)||!Number(memberId)||!Number(bookCopyId)||!Number(issueTypeId)||!issueDate||!dueDate)return res.status(400).json({ok:false,message:'Member, accession number, issue type, issue date, and due date are required.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let member;
    if(type==='STAFF')member=(await client.query(`SELECT e.employee_code AS code,
      TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS name,e.department_id,
      d.department_name AS department,dg.designation_name AS designation,e.mobile AS contact
      FROM employees e LEFT JOIN departments d ON d.department_id=e.department_id
      LEFT JOIN designations dg ON dg.designation_id=e.designation_id WHERE e.employee_id=$1 AND e.status='ACTIVE'`,[Number(memberId)])).rows[0];
    else member=(await client.query(`SELECT s.roll_number AS code,s.student_name AS name,s.department_id,
      d.department_name AS department,s.programme,s.semester,s.contact_number AS contact
      FROM library_student_members s LEFT JOIN departments d ON d.department_id=s.department_id
      WHERE s.student_member_id=$1 AND s.is_active=TRUE`,[Number(memberId)])).rows[0];
    if(!member)throw new Error('The selected member was not found.');
    const copy=(await client.query(`SELECT c.copy_status,t.title_name FROM library_book_copies c
      JOIN library_books b ON b.book_id=c.book_id JOIN library_titles t ON t.title_id=b.title_id
      WHERE c.book_copy_id=$1 FOR UPDATE OF c`,[Number(bookCopyId)])).rows[0];
    if(!copy||copy.copy_status!=='AVAILABLE')throw new Error('The selected accession number is not available.');
    const issueType=(await client.query('SELECT member_type,maximum_books FROM library_issue_types WHERE issue_type_id=$1 AND is_active=TRUE',[Number(issueTypeId)])).rows[0];
    if(!issueType)throw new Error('The selected issue type is invalid.');
    const activeCount=Number((await client.query('SELECT COUNT(*) AS count FROM library_book_issues WHERE member_code=$1 AND returned_at IS NULL',[member.code])).rows[0].count);
    if(activeCount>=Number(issueType.maximum_books))throw new Error(`This member has reached the maximum of ${issueType.maximum_books} books.`);
    const id=Number((await client.query(`SELECT nextval(pg_get_serial_sequence('library_book_issues','book_issue_id')) AS id`)).rows[0].id);
    const issueNumber=`ISS-${String(id).padStart(6,'0')}`;
    await client.query(`INSERT INTO library_book_issues
      (book_issue_id,issue_number,book_copy_id,issue_type_id,member_code,member_name,member_type,
       department_id,contact_number,designation,programme,semester,issue_date,due_date,issue_remarks,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [id,issueNumber,Number(bookCopyId),Number(issueTypeId),member.code,member.name,type,member.department_id||null,member.contact||null,member.designation||null,member.programme||null,member.semester||null,issueDate,dueDate,remarks?.trim()||null,req.auth.userId]);
    await client.query(`UPDATE library_book_copies SET copy_status='ISSUED' WHERE book_copy_id=$1`,[Number(bookCopyId)]);
    await client.query('COMMIT');res.status(201).json({ok:true,id,issueNumber,message:`Book issued successfully as ${issueNumber}.`});
  }catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}finally{client.release();}
});

app.get('/api/library/circulation/return-search', authenticate, async (req,res)=>{
  const search=String(req.query.search||'').trim();if(!search)return res.status(400).json({ok:false,message:'Enter an issue number or accession number.'});
  try{const result=await pool.query(`SELECT i.book_issue_id AS id,i.issue_number,i.member_code,i.member_name,
    i.member_type,d.department_name AS department,c.book_copy_id,c.accession_number,t.title_name AS book_title,
    i.issue_date,i.due_date,it.fine_per_day,GREATEST(CURRENT_DATE-i.due_date,0)::int AS overdue_days
    FROM library_book_issues i JOIN library_book_copies c ON c.book_copy_id=i.book_copy_id
    JOIN library_books b ON b.book_id=c.book_id JOIN library_titles t ON t.title_id=b.title_id
    JOIN library_issue_types it ON it.issue_type_id=i.issue_type_id
    LEFT JOIN departments d ON d.department_id=i.department_id
    WHERE i.returned_at IS NULL AND (LOWER(i.issue_number)=LOWER($1) OR LOWER(c.accession_number)=LOWER($1)) LIMIT 1`,[search]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'No pending issue found for that number.'});res.json({ok:true,issue:result.rows[0]});}
  catch(error){res.status(500).json({ok:false,message:'Unable to search the issue.'});}
});

app.post('/api/library/circulation/returns', authenticate, async (req,res)=>{
  const {issueId,returnDate,fineAmount,bookCondition,remarks}=req.body;
  if(!Number(issueId)||!returnDate||Number(fineAmount)<0||!bookCondition)return res.status(400).json({ok:false,message:'Return date, fine, and book condition are required.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const issue=(await client.query('SELECT book_copy_id,returned_at FROM library_book_issues WHERE book_issue_id=$1 FOR UPDATE',[Number(issueId)])).rows[0];
    if(!issue||issue.returned_at)throw new Error('This issue is not pending return.');
    await client.query(`UPDATE library_book_issues SET returned_at=$1::date,fine_amount=$2,
      book_condition=$3,return_remarks=$4 WHERE book_issue_id=$5`,[returnDate,Number(fineAmount),bookCondition,remarks?.trim()||null,Number(issueId)]);
    await client.query(`UPDATE library_book_copies SET copy_status='AVAILABLE' WHERE book_copy_id=$1`,[issue.book_copy_id]);
    await client.query('COMMIT');res.json({ok:true,message:'Book returned successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}finally{client.release();}
});

app.get('/api/library/study-material-issue-options', authenticate, async (_req,res)=>{
  try{
    const [materials,staff,students]=await Promise.all([
      pool.query(`SELECT m.study_material_id AS id,m.material_code AS code,m.material_name AS name,m.current_stock,
        p.student_price,p.staff_price FROM library_study_materials m LEFT JOIN LATERAL (
          SELECT student_price,staff_price FROM library_study_material_prices
          WHERE study_material_id=m.study_material_id AND is_active=TRUE AND effective_from<=CURRENT_DATE
          ORDER BY effective_from DESC LIMIT 1) p ON TRUE WHERE m.is_active=TRUE ORDER BY m.material_name`),
      pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,
        TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS name,
        e.department_id,d.department_name AS department,e.mobile AS contact
        FROM employees e LEFT JOIN departments d ON d.department_id=e.department_id WHERE e.status='ACTIVE' ORDER BY e.first_name,e.last_name`),
      pool.query(`SELECT s.student_member_id AS id,s.roll_number AS code,s.student_name AS name,
        s.programme,s.department_id,d.department_name AS department,s.contact_number AS contact
        FROM library_student_members s LEFT JOIN departments d ON d.department_id=s.department_id
        WHERE s.is_active=TRUE ORDER BY s.student_name`)
    ]);
    res.json({ok:true,materials:materials.rows,staff:staff.rows,students:students.rows});
  }catch(error){res.status(500).json({ok:false,message:'Unable to load study material issue options.'});}
});

app.post('/api/library/study-material-issues', authenticate, async (req,res)=>{
  const {recipientType,recipientId,studyMaterialId,quantity,issueDate,paymentStatus,remarks}=req.body;
  const type=String(recipientType||'').toUpperCase(),payment=String(paymentStatus||'PENDING').toUpperCase();
  if(!['STUDENT','STAFF'].includes(type)||!Number(recipientId)||!Number(studyMaterialId)||Number(quantity)<=0||!issueDate||!['PAID','PENDING','FREE'].includes(payment))return res.status(400).json({ok:false,message:'Complete all required study material issue fields.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let recipient;
    if(type==='STAFF')recipient=(await client.query(`SELECT e.employee_code AS code,
      TRIM(CONCAT(e.first_name,' ',e.middle_name,' ',e.last_name)) AS name,e.department_id,e.mobile AS contact
      FROM employees e WHERE e.employee_id=$1 AND e.status='ACTIVE'`,[Number(recipientId)])).rows[0];
    else recipient=(await client.query(`SELECT roll_number AS code,student_name AS name,department_id,
      programme,contact_number AS contact FROM library_student_members WHERE student_member_id=$1 AND is_active=TRUE`,[Number(recipientId)])).rows[0];
    if(!recipient)throw new Error('The selected recipient was not found.');
    const material=(await client.query('SELECT current_stock FROM library_study_materials WHERE study_material_id=$1 AND is_active=TRUE FOR UPDATE',[Number(studyMaterialId)])).rows[0];
    if(!material||Number(material.current_stock)<Number(quantity))throw new Error('Insufficient study material stock.');
    const price=(await client.query(`SELECT student_price,staff_price FROM library_study_material_prices
      WHERE study_material_id=$1 AND is_active=TRUE AND effective_from<=$2::date ORDER BY effective_from DESC LIMIT 1`,[Number(studyMaterialId),issueDate])).rows[0];
    if(!price&&payment!=='FREE')throw new Error('No effective price is configured for this study material.');
    const unitPrice=payment==='FREE'?0:Number(type==='STUDENT'?price.student_price:price.staff_price),amount=unitPrice*Number(quantity);
    const id=Number((await client.query(`SELECT nextval(pg_get_serial_sequence('library_study_material_issues','material_issue_id')) AS id`)).rows[0].id);
    const issueNumber=`SMI-${String(id).padStart(6,'0')}`;
    await client.query(`INSERT INTO library_study_material_issues
      (material_issue_id,issue_number,study_material_id,department_id,recipient_code,recipient_name,
       recipient_type,programme,quantity,unit_price,amount,issued_date,payment_status,remarks,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [id,issueNumber,Number(studyMaterialId),recipient.department_id||null,recipient.code,recipient.name,type,recipient.programme||null,Number(quantity),unitPrice,amount,issueDate,payment,remarks?.trim()||null,req.auth.userId]);
    await client.query('UPDATE library_study_materials SET current_stock=current_stock-$1 WHERE study_material_id=$2',[Number(quantity),Number(studyMaterialId)]);
    await client.query('COMMIT');res.status(201).json({ok:true,issueNumber,unitPrice,amount,message:`Study material issued successfully as ${issueNumber}.`});
  }catch(error){await client.query('ROLLBACK');res.status(400).json({ok:false,message:error.message});}finally{client.release();}
});

app.get('/api/library/reports/study-material', authenticate, async (req,res)=>{
  const dateFrom=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.dateFrom||''))?String(req.query.dateFrom):'1900-01-01';
  const dateTo=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.dateTo||''))?String(req.query.dateTo):new Date().toISOString().slice(0,10);
  const values=[dateFrom,dateTo];const filters=[`i.issued_date BETWEEN $1::date AND $2::date`];
  const mappings=[['materialId','i.study_material_id',Number],['departmentId','i.department_id',Number]];
  for(const [key,column,cast] of mappings)if(cast(req.query[key])){values.push(cast(req.query[key]));filters.push(`${column}=$${values.length}`);}
  for(const [key,column] of [['recipientType','i.recipient_type'],['programme','i.programme'],['paymentStatus','i.payment_status']])if(req.query[key]){values.push(String(req.query[key]).toUpperCase());filters.push(`UPPER(${column})=$${values.length}`);}
  try{
    const [report,materials,departments,programmes]=await Promise.all([
      pool.query(`SELECT i.issue_number,i.issued_date,i.recipient_code,i.recipient_name,m.material_name,
        i.quantity,i.unit_price,i.amount,i.payment_status FROM library_study_material_issues i
        JOIN library_study_materials m ON m.study_material_id=i.study_material_id
        WHERE ${filters.join(' AND ')} ORDER BY i.issued_date DESC,i.issue_number`,values),
      pool.query('SELECT study_material_id AS id,material_code AS code,material_name AS name FROM library_study_materials WHERE is_active=TRUE ORDER BY material_name'),
      pool.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE ORDER BY department_name'),
      pool.query(`SELECT DISTINCT programme FROM library_student_members WHERE programme IS NOT NULL AND programme<>'' ORDER BY programme`)
    ]);
    res.json({ok:true,rows:report.rows,materials:materials.rows,departments:departments.rows,programmes:programmes.rows.map(row=>row.programme)});
  }catch(error){res.status(500).json({ok:false,message:'Unable to load the study material report.'});}
});

app.get('/api/library/reports/study-material-datewise', authenticate, async (req,res)=>{
  const fromDate=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.fromDate||''))?String(req.query.fromDate):'1900-01-01';
  const toDate=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.toDate||''))?String(req.query.toDate):new Date().toISOString().slice(0,10);
  const values=[fromDate,toDate];const filters=[`i.issued_date BETWEEN $1::date AND $2::date`];
  if(Number(req.query.materialId)){values.push(Number(req.query.materialId));filters.push(`i.study_material_id=$${values.length}`);}
  if(Number(req.query.departmentId)){values.push(Number(req.query.departmentId));filters.push(`i.department_id=$${values.length}`);}
  try{
    const [report,materials,departments]=await Promise.all([
      pool.query(`SELECT i.issued_date,m.material_code,m.material_name,i.recipient_code,
        i.recipient_name,i.recipient_type,d.department_name,i.quantity,i.unit_price,i.amount
        FROM library_study_material_issues i JOIN library_study_materials m
        ON m.study_material_id=i.study_material_id LEFT JOIN departments d ON d.department_id=i.department_id
        WHERE ${filters.join(' AND ')} ORDER BY i.issued_date DESC,m.material_name,i.recipient_name`,values),
      pool.query(`SELECT study_material_id AS id,material_code AS code,material_name AS name
        FROM library_study_materials WHERE is_active=TRUE ORDER BY material_name`),
      pool.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE ORDER BY department_name')
    ]);
    res.json({ok:true,rows:report.rows,materials:materials.rows,departments:departments.rows});
  }catch(error){console.error('Study material datewise report error:',error.message);res.status(500).json({ok:false,message:'Unable to load the study material datewise report.'});}
});

app.get('/api/library/reports/book-issues', authenticate, async (req,res)=>{
  const dateFrom=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.dateFrom||''))?String(req.query.dateFrom):'1900-01-01';
  const dateTo=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.dateTo||''))?String(req.query.dateTo):new Date().toISOString().slice(0,10);
  const values=[dateFrom,dateTo];const filters=[`i.issue_date BETWEEN $1::date AND $2::date`];
  if(req.query.memberType){values.push(String(req.query.memberType).toUpperCase());filters.push(`i.member_type=$${values.length}`);}
  if(Number(req.query.departmentId)){values.push(Number(req.query.departmentId));filters.push(`i.department_id=$${values.length}`);}
  if(Number(req.query.issueTypeId)){values.push(Number(req.query.issueTypeId));filters.push(`i.issue_type_id=$${values.length}`);}
  if(Number(req.query.bookId)){values.push(Number(req.query.bookId));filters.push(`b.book_id=$${values.length}`);}
  const issueStatus=String(req.query.issueStatus||'').toUpperCase();
  if(issueStatus==='RETURNED')filters.push('i.returned_at IS NOT NULL');
  if(issueStatus==='ISSUED')filters.push('i.returned_at IS NULL AND i.due_date>=CURRENT_DATE');
  if(issueStatus==='OVERDUE')filters.push('i.returned_at IS NULL AND i.due_date<CURRENT_DATE');
  try{
    const [report,departments,issueTypes,books]=await Promise.all([
      pool.query(`SELECT i.issue_number,c.accession_number,t.title_name AS book_title,
        i.member_code,i.member_name,i.member_type,i.issue_date,i.due_date,i.returned_at::date AS return_date,
        CASE WHEN i.returned_at IS NOT NULL THEN 'RETURNED'
          WHEN i.due_date<CURRENT_DATE THEN 'OVERDUE' ELSE 'ISSUED' END AS status
        FROM library_book_issues i JOIN library_book_copies c ON c.book_copy_id=i.book_copy_id
        JOIN library_books b ON b.book_id=c.book_id JOIN library_titles t ON t.title_id=b.title_id
        WHERE ${filters.join(' AND ')} ORDER BY i.issue_date DESC,i.issue_number`,values),
      pool.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE ORDER BY department_name'),
      pool.query('SELECT issue_type_id AS id,issue_type_code AS code,issue_type_name AS name FROM library_issue_types WHERE is_active=TRUE ORDER BY issue_type_name'),
      pool.query(`SELECT b.book_id AS id,b.isbn,t.title_name AS name FROM library_books b
        JOIN library_titles t ON t.title_id=b.title_id WHERE b.is_active=TRUE ORDER BY t.title_name`)
    ]);
    res.json({ok:true,rows:report.rows,departments:departments.rows,issueTypes:issueTypes.rows,books:books.rows});
  }catch(error){console.error('Book issue report error:',error.message);res.status(500).json({ok:false,message:'Unable to load the book issue report.'});}
});

app.get('/api/library/reports/return-pending', authenticate, async (req,res)=>{
  const asOn=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.asOn||''))?String(req.query.asOn):new Date().toISOString().slice(0,10);
  const values=[asOn];const filters=[`i.issue_date<=$1::date`,`(i.returned_at IS NULL OR i.returned_at::date>$1::date)`];
  if(req.query.memberType){values.push(String(req.query.memberType).toUpperCase());filters.push(`i.member_type=$${values.length}`);}
  if(Number(req.query.departmentId)){values.push(Number(req.query.departmentId));filters.push(`i.department_id=$${values.length}`);}
  if(Number(req.query.issueTypeId)){values.push(Number(req.query.issueTypeId));filters.push(`i.issue_type_id=$${values.length}`);}
  if(String(req.query.overdueOnly)==='true')filters.push(`i.due_date<$1::date`);
  try{
    const [report,departments,issueTypes]=await Promise.all([
      pool.query(`SELECT i.member_code,i.member_name,t.title_name AS book,c.accession_number,
        i.issue_date,i.due_date,GREATEST($1::date-i.due_date,0)::int AS pending_days,
        (GREATEST($1::date-i.due_date,0)*it.fine_per_day)::numeric(12,2) AS estimated_fine,
        i.contact_number,i.member_type,d.department_name,it.issue_type_name
        FROM library_book_issues i JOIN library_book_copies c ON c.book_copy_id=i.book_copy_id
        JOIN library_books b ON b.book_id=c.book_id JOIN library_titles t ON t.title_id=b.title_id
        JOIN library_issue_types it ON it.issue_type_id=i.issue_type_id
        LEFT JOIN departments d ON d.department_id=i.department_id
        WHERE ${filters.join(' AND ')} ORDER BY i.due_date,i.member_name`,values),
      pool.query('SELECT department_id AS id,department_code AS code,department_name AS name FROM departments WHERE is_active=TRUE ORDER BY department_name'),
      pool.query('SELECT issue_type_id AS id,issue_type_code AS code,issue_type_name AS name FROM library_issue_types WHERE is_active=TRUE ORDER BY issue_type_name')
    ]);
    res.json({ok:true,rows:report.rows,departments:departments.rows,issueTypes:issueTypes.rows,asOn});
  }catch(error){console.error('Return pending report error:',error.message);res.status(500).json({ok:false,message:'Unable to load the return pending report.'});}
});

app.get('/api/library/study-materials', authenticate, async (_req,res)=>{
  try{
    const [materials,subjects,academicYears]=await Promise.all([
      pool.query(`SELECT m.study_material_id AS id,m.material_code AS code,m.material_name AS name,
        m.material_type,m.subject_id,s.subject_name,m.academic_year_id,a.year_label AS academic_year,
        m.current_stock,m.minimum_stock,m.is_active FROM library_study_materials m
        LEFT JOIN library_subjects s ON s.subject_id=m.subject_id
        LEFT JOIN academic_years a ON a.academic_year_id=m.academic_year_id ORDER BY m.material_name`),
      pool.query(`SELECT subject_id AS id,subject_code AS code,subject_name AS name
        FROM library_subjects WHERE is_active=TRUE ORDER BY subject_name`),
      pool.query(`SELECT academic_year_id AS id,year_label AS code,COALESCE(academic_year_name,year_label) AS name
        FROM academic_years WHERE is_active=TRUE ORDER BY start_date DESC`)
    ]);
    res.json({ok:true,materials:materials.rows,subjects:subjects.rows,academicYears:academicYears.rows});
  }catch(error){console.error('Study material query error:',error.message);res.status(500).json({ok:false,message:'Unable to load study materials.'});}
});

app.post('/api/library/study-materials', authenticate, async (req,res)=>{
  const {code,name,materialType,subjectId,academicYearId,currentStock,minimumStock,status}=req.body;
  if(!code?.trim()||!name?.trim()||!materialType||!Number(subjectId)||!Number(academicYearId)||Number(currentStock)<0||Number(minimumStock)<0)return res.status(400).json({ok:false,message:'Complete all required material fields with valid stock values.'});
  try{const result=await pool.query(`INSERT INTO library_study_materials
    (material_code,material_name,material_type,subject_id,academic_year_id,current_stock,minimum_stock,is_active,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING study_material_id`,
    [code.trim().toUpperCase(),name.trim(),String(materialType).toUpperCase(),Number(subjectId),Number(academicYearId),Number(currentStock)||0,Number(minimumStock)||0,status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].study_material_id,message:'Study material saved successfully.'});}
  catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'Material code or name already exists.':error.code==='23503'?'Subject or academic year is invalid.':'Unable to save study material.'});}
});

app.put('/api/library/study-materials/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,materialType,subjectId,academicYearId,currentStock,minimumStock,status}=req.body;
  if(!id||!code?.trim()||!name?.trim()||!materialType||!Number(subjectId)||!Number(academicYearId)||Number(currentStock)<0||Number(minimumStock)<0)return res.status(400).json({ok:false,message:'Complete all required material fields with valid stock values.'});
  try{const result=await pool.query(`UPDATE library_study_materials SET material_code=$1,
    material_name=$2,material_type=$3,subject_id=$4,academic_year_id=$5,current_stock=$6,
    minimum_stock=$7,is_active=$8,updated_at=NOW(),updated_by=$9 WHERE study_material_id=$10 RETURNING study_material_id`,
    [code.trim().toUpperCase(),name.trim(),String(materialType).toUpperCase(),Number(subjectId),Number(academicYearId),Number(currentStock)||0,Number(minimumStock)||0,status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Study material not found.'});res.json({ok:true,message:'Study material updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'Material code or name already exists.':'Unable to update study material.'});}
});

app.delete('/api/library/study-materials/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid study material.'});
  try{const result=await pool.query('DELETE FROM library_study_materials WHERE study_material_id=$1 RETURNING study_material_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Study material not found.'});res.json({ok:true,message:'Study material deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This study material has pricing or issue records and cannot be deleted.':'Unable to delete study material.'});}
});

app.get('/api/library/issue-types', authenticate, async (_req,res)=>{
  try{const result=await pool.query(`SELECT issue_type_id AS id,issue_type_code AS code,
    issue_type_name AS name,member_type,maximum_books,issue_duration_days,fine_per_day,
    renewal_allowed,maximum_renewals,is_active FROM library_issue_types ORDER BY issue_type_name`);
    res.json({ok:true,issueTypes:result.rows});}
  catch(error){console.error('Issue type query error:',error.message);res.status(500).json({ok:false,message:'Unable to load issue types.'});}
});

app.post('/api/library/issue-types', authenticate, async (req,res)=>{
  const {code,name,memberType,maximumBooks,issueDurationDays,finePerDay,renewalAllowed,maximumRenewals,status}=req.body;
  if(!code?.trim()||!name?.trim()||!memberType||Number(maximumBooks)<=0||Number(issueDurationDays)<=0||Number(finePerDay)<0||Number(maximumRenewals)<0)return res.status(400).json({ok:false,message:'Complete all required issue rules with valid values.'});
  try{const result=await pool.query(`INSERT INTO library_issue_types
    (issue_type_code,issue_type_name,member_type,maximum_books,issue_duration_days,fine_per_day,
     renewal_allowed,maximum_renewals,is_active,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING issue_type_id`,
    [code.trim().toUpperCase(),name.trim(),String(memberType).toUpperCase(),Number(maximumBooks),Number(issueDurationDays),Number(finePerDay),renewalAllowed!==false,renewalAllowed===false?0:Number(maximumRenewals),status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].issue_type_id,message:'Issue type saved successfully.'});}
  catch(error){res.status(error.code==='23505'?409:error.code==='23514'?400:500).json({ok:false,message:error.code==='23505'?'Issue type code or name already exists.':error.code==='23514'?'An issue-rule value is invalid.':'Unable to save issue type.'});}
});

app.put('/api/library/issue-types/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,memberType,maximumBooks,issueDurationDays,finePerDay,renewalAllowed,maximumRenewals,status}=req.body;
  if(!id||!code?.trim()||!name?.trim()||!memberType||Number(maximumBooks)<=0||Number(issueDurationDays)<=0||Number(finePerDay)<0||Number(maximumRenewals)<0)return res.status(400).json({ok:false,message:'Complete all required issue rules with valid values.'});
  try{const result=await pool.query(`UPDATE library_issue_types SET issue_type_code=$1,issue_type_name=$2,
    member_type=$3,maximum_books=$4,issue_duration_days=$5,fine_per_day=$6,renewal_allowed=$7,
    maximum_renewals=$8,is_active=$9,updated_at=NOW(),updated_by=$10 WHERE issue_type_id=$11 RETURNING issue_type_id`,
    [code.trim().toUpperCase(),name.trim(),String(memberType).toUpperCase(),Number(maximumBooks),Number(issueDurationDays),Number(finePerDay),renewalAllowed!==false,renewalAllowed===false?0:Number(maximumRenewals),status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Issue type not found.'});res.json({ok:true,message:'Issue type updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:error.code==='23514'?400:500).json({ok:false,message:error.code==='23505'?'Issue type code or name already exists.':'Unable to update issue type.'});}
});

app.delete('/api/library/issue-types/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid issue type.'});
  try{const result=await pool.query('DELETE FROM library_issue_types WHERE issue_type_id=$1 RETURNING issue_type_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Issue type not found.'});res.json({ok:true,message:'Issue type deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This issue type is in use and cannot be deleted.':'Unable to delete issue type.'});}
});

app.get('/api/library/study-material-prices', authenticate, async (_req,res)=>{
  try{
    const [prices,materials]=await Promise.all([
      pool.query(`SELECT p.price_id AS id,p.study_material_id,m.material_code,m.material_name,
        p.effective_from,p.purchase_price,p.selling_price,p.student_price,p.staff_price,p.is_active
        FROM library_study_material_prices p JOIN library_study_materials m
        ON m.study_material_id=p.study_material_id ORDER BY p.effective_from DESC,m.material_name`),
      pool.query(`SELECT study_material_id AS id,material_code AS code,material_name AS name
        FROM library_study_materials WHERE is_active=TRUE ORDER BY material_name`)
    ]);
    res.json({ok:true,prices:prices.rows,materials:materials.rows});
  }catch(error){console.error('Study material price query error:',error.message);res.status(500).json({ok:false,message:'Unable to load study material prices.'});}
});

app.post('/api/library/study-material-prices', authenticate, async (req,res)=>{
  const {studyMaterialId,effectiveFrom,purchasePrice,sellingPrice,studentPrice,staffPrice,status}=req.body;
  const values=[purchasePrice,sellingPrice,studentPrice,staffPrice];
  if(!Number(studyMaterialId)||!effectiveFrom||values.some(value=>value===''||Number(value)<0))return res.status(400).json({ok:false,message:'Study material, effective date, and valid prices are required.'});
  try{const result=await pool.query(`INSERT INTO library_study_material_prices
    (study_material_id,effective_from,purchase_price,selling_price,student_price,staff_price,is_active,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING price_id`,
    [Number(studyMaterialId),effectiveFrom,Number(purchasePrice),Number(sellingPrice),Number(studentPrice),Number(staffPrice),status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].price_id,message:'Study material price saved successfully.'});}
  catch(error){res.status(error.code==='23505'?409:error.code==='23503'||error.code==='23514'?400:500).json({ok:false,message:error.code==='23505'?'A price already exists for this material and effective date.':error.code==='23503'||error.code==='23514'?'Study material or price is invalid.':'Unable to save study material price.'});}
});

app.put('/api/library/study-material-prices/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {studyMaterialId,effectiveFrom,purchasePrice,sellingPrice,studentPrice,staffPrice,status}=req.body;const values=[purchasePrice,sellingPrice,studentPrice,staffPrice];
  if(!id||!Number(studyMaterialId)||!effectiveFrom||values.some(value=>value===''||Number(value)<0))return res.status(400).json({ok:false,message:'Study material, effective date, and valid prices are required.'});
  try{const result=await pool.query(`UPDATE library_study_material_prices SET study_material_id=$1,
    effective_from=$2,purchase_price=$3,selling_price=$4,student_price=$5,staff_price=$6,
    is_active=$7,updated_at=NOW(),updated_by=$8 WHERE price_id=$9 RETURNING price_id`,
    [Number(studyMaterialId),effectiveFrom,Number(purchasePrice),Number(sellingPrice),Number(studentPrice),Number(staffPrice),status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Study material price not found.'});res.json({ok:true,message:'Study material price updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:error.code==='23503'||error.code==='23514'?400:500).json({ok:false,message:error.code==='23505'?'A price already exists for this material and effective date.':'Unable to update study material price.'});}
});

app.delete('/api/library/study-material-prices/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid price record.'});
  try{const result=await pool.query('DELETE FROM library_study_material_prices WHERE price_id=$1 RETURNING price_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Study material price not found.'});res.json({ok:true,message:'Study material price deleted successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to delete study material price.'});}
});

app.get('/api/library/purchase-orders', authenticate, async (_req,res)=>{
  try{
    const [orders,suppliers,books]=await Promise.all([
      pool.query(`SELECT po.purchase_order_id AS id,po.po_number,po.order_date,po.expected_delivery,
        po.delivery_address,po.terms_conditions,po.subtotal,po.discount_total,po.tax_total,
        po.grand_total,po.status,s.supplier_name,COUNT(i.purchase_order_item_id)::int AS item_count
        FROM library_purchase_orders po JOIN library_suppliers s ON s.supplier_id=po.supplier_id
        LEFT JOIN library_purchase_order_items i ON i.purchase_order_id=po.purchase_order_id
        GROUP BY po.purchase_order_id,s.supplier_name ORDER BY po.order_date DESC,po.purchase_order_id DESC`),
      pool.query('SELECT supplier_id AS id,supplier_code AS code,supplier_name AS name FROM library_suppliers WHERE is_active=TRUE ORDER BY supplier_name'),
      pool.query(`SELECT b.book_id AS id,b.isbn,t.title_name AS name FROM library_books b
        JOIN library_titles t ON t.title_id=b.title_id WHERE b.is_active=TRUE ORDER BY t.title_name`)
    ]);
    res.json({ok:true,orders:orders.rows,suppliers:suppliers.rows,books:books.rows});
  }catch(error){console.error('Purchase order query error:',error.message);res.status(500).json({ok:false,message:'Unable to load purchase orders.'});}
});

app.post('/api/library/purchase-orders', authenticate, async (req,res)=>{
  const {poNumber,poDate,supplierId,expectedDelivery,deliveryAddress,termsConditions,items}=req.body;
  if(!poNumber?.trim()||!poDate||!Number(supplierId))return res.status(400).json({ok:false,message:'PO number, PO date, and supplier are required.'});
  if(!Array.isArray(items)||!items.length)return res.status(400).json({ok:false,message:'Add at least one purchase-order item.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let subtotal=0,discountTotal=0,taxTotal=0;
    const prepared=[];
    for(let index=0;index<items.length;index++){
      const item=items[index];const type=String(item.itemType||'BOOK').toUpperCase();const quantity=Number(item.quantity),unitPrice=Number(item.unitPrice),discount=Number(item.discount)||0,tax=Number(item.tax)||0;
      let itemName=item.itemName?.trim()||'',bookId=null;
      if(type==='BOOK'){bookId=Number(item.bookId);const book=(await client.query(`SELECT t.title_name FROM library_books b JOIN library_titles t ON t.title_id=b.title_id WHERE b.book_id=$1`,[bookId])).rows[0];if(!book)throw new Error(`Item ${index+1}: Select a valid book.`);itemName=book.title_name;}
      if(!itemName||quantity<=0||unitPrice<0||discount<0||tax<0)throw new Error(`Item ${index+1}: item, quantity, price, discount, and tax are invalid.`);
      const base=quantity*unitPrice,lineTotal=base-discount+tax;if(lineTotal<0)throw new Error(`Item ${index+1}: discount cannot exceed the item value plus tax.`);
      subtotal+=base;discountTotal+=discount;taxTotal+=tax;prepared.push({type,bookId,itemName,quantity,unitPrice,discount,tax,lineTotal});
    }
    const grandTotal=subtotal-discountTotal+taxTotal;
    const order=(await client.query(`INSERT INTO library_purchase_orders
      (po_number,supplier_id,order_date,expected_delivery,delivery_address,terms_conditions,status,
       subtotal,discount_total,tax_total,grand_total,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,'DRAFT',$7,$8,$9,$10,$11) RETURNING purchase_order_id`,
      [poNumber.trim(),Number(supplierId),poDate,expectedDelivery||null,deliveryAddress?.trim()||null,termsConditions?.trim()||null,subtotal,discountTotal,taxTotal,grandTotal,req.auth.userId])).rows[0];
    for(const item of prepared)await client.query(`INSERT INTO library_purchase_order_items
      (purchase_order_id,item_type,book_id,item_name,quantity,unit_price,discount,tax,line_total)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[order.purchase_order_id,item.type,item.bookId,item.itemName,item.quantity,item.unitPrice,item.discount,item.tax,item.lineTotal]);
    await client.query('COMMIT');res.status(201).json({ok:true,id:order.purchase_order_id,message:'Purchase order saved as draft.'});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:error.code==='23503'||error.code==='23514'?400:400).json({ok:false,message:error.code==='23505'?'This PO number already exists.':error.code==='23503'||error.code==='23514'?'A purchase-order value is invalid.':error.message});}finally{client.release();}
});

app.post('/api/library/purchase-orders/:id/approve', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid purchase order.'});
  try{const result=await pool.query(`UPDATE library_purchase_orders SET status='APPROVED',
    approved_at=NOW(),approved_by=$1 WHERE purchase_order_id=$2 AND status='DRAFT' RETURNING purchase_order_id`,[req.auth.userId,id]);
    if(!result.rowCount)return res.status(409).json({ok:false,message:'Only draft purchase orders can be approved.'});res.json({ok:true,message:'Purchase order approved successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to approve purchase order.'});}
});

app.delete('/api/library/purchase-orders/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid purchase order.'});
  try{const result=await pool.query(`DELETE FROM library_purchase_orders WHERE purchase_order_id=$1 AND status='DRAFT' RETURNING purchase_order_id`,[id]);if(!result.rowCount)return res.status(409).json({ok:false,message:'Only draft purchase orders can be deleted.'});res.json({ok:true,message:'Purchase order deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This purchase order is connected to an invoice.':'Unable to delete purchase order.'});}
});

app.get('/api/library/purchase-invoices', authenticate, async (_req,res)=>{
  try{
    const [invoices,suppliers,purchaseOrders,books]=await Promise.all([
      pool.query(`SELECT i.invoice_id AS id,i.invoice_number,i.invoice_date,i.payment_status,
        i.invoice_file_name,i.stock_status,i.invoice_total,s.supplier_name,
        po.po_number,COUNT(ii.invoice_item_id)::int AS item_count
        FROM library_purchase_invoices i JOIN library_suppliers s ON s.supplier_id=i.supplier_id
        LEFT JOIN library_purchase_orders po ON po.purchase_order_id=i.purchase_order_id
        LEFT JOIN library_purchase_invoice_items ii ON ii.invoice_id=i.invoice_id
        GROUP BY i.invoice_id,s.supplier_name,po.po_number ORDER BY i.invoice_date DESC,i.invoice_id DESC`),
      pool.query('SELECT supplier_id AS id,supplier_code AS code,supplier_name AS name FROM library_suppliers WHERE is_active=TRUE ORDER BY supplier_name'),
      pool.query(`SELECT po.purchase_order_id AS id,po.po_number,po.supplier_id,s.supplier_name
        FROM library_purchase_orders po JOIN library_suppliers s ON s.supplier_id=po.supplier_id
        WHERE po.status IN ('APPROVED','OPEN','PARTIAL') ORDER BY po.order_date DESC,po.po_number`),
      pool.query(`SELECT b.book_id AS id,b.isbn,t.title_name AS name,COALESCE(st.quantity,0) AS stock
        FROM library_books b JOIN library_titles t ON t.title_id=b.title_id
        LEFT JOIN library_book_stock st ON st.book_id=b.book_id WHERE b.is_active=TRUE ORDER BY t.title_name`)
    ]);
    res.json({ok:true,invoices:invoices.rows,suppliers:suppliers.rows,purchaseOrders:purchaseOrders.rows,books:books.rows});
  }catch(error){console.error('Purchase invoice query error:',error.message);res.status(500).json({ok:false,message:'Unable to load purchase invoices.'});}
});

app.post('/api/library/purchase-invoices', authenticate, async (req,res)=>{
  const {invoiceNumber,invoiceDate,supplierId,purchaseOrderId,paymentStatus,invoiceFileName,items}=req.body;
  if(!invoiceNumber?.trim()||!invoiceDate||!Number(supplierId))return res.status(400).json({ok:false,message:'Invoice number, date, and supplier are required.'});
  if(!Array.isArray(items)||!items.length)return res.status(400).json({ok:false,message:'Add at least one invoice item.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    if(purchaseOrderId){
      const order=(await client.query('SELECT supplier_id FROM library_purchase_orders WHERE purchase_order_id=$1',[Number(purchaseOrderId)])).rows[0];
      if(!order||Number(order.supplier_id)!==Number(supplierId))throw new Error('The selected purchase order does not belong to this supplier.');
    }
    let total=0;
    for(let index=0;index<items.length;index++){const item=items[index];if(!Number(item.bookId)||Number(item.ordered)<0||Number(item.received)<=0||Number(item.price)<0)throw new Error(`Item ${index+1}: book, received quantity, and a valid price are required.`);total+=Number(item.received)*Number(item.price);}
    const invoice=(await client.query(`INSERT INTO library_purchase_invoices
      (invoice_number,invoice_date,supplier_id,purchase_order_id,payment_status,invoice_file_name,invoice_total,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING invoice_id`,
      [invoiceNumber.trim(),invoiceDate,Number(supplierId),purchaseOrderId?Number(purchaseOrderId):null,String(paymentStatus||'PENDING').toUpperCase(),invoiceFileName?.trim()||null,total,req.auth.userId])).rows[0];
    for(const item of items)await client.query(`INSERT INTO library_purchase_invoice_items
      (invoice_id,book_id,ordered_quantity,received_quantity,unit_price,line_total)
      VALUES ($1,$2,$3,$4,$5,$6)`,[invoice.invoice_id,Number(item.bookId),Number(item.ordered)||0,Number(item.received),Number(item.price),Number(item.received)*Number(item.price)]);
    await client.query('COMMIT');res.status(201).json({ok:true,id:invoice.invoice_id,message:'Purchase invoice saved successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:error.code==='23503'||error.code==='23514'?400:400).json({ok:false,message:error.code==='23505'?'This invoice number already exists.':error.code==='23503'||error.code==='23514'?'An invoice item contains invalid data.':error.message});}finally{client.release();}
});

app.post('/api/library/purchase-invoices/:id/post', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid invoice.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const invoice=(await client.query('SELECT stock_status FROM library_purchase_invoices WHERE invoice_id=$1 FOR UPDATE',[id])).rows[0];
    if(!invoice){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Invoice not found.'});}
    if(invoice.stock_status==='POSTED'){await client.query('ROLLBACK');return res.status(409).json({ok:false,message:'Stock has already been posted for this invoice.'});}
    const items=(await client.query('SELECT book_id,received_quantity FROM library_purchase_invoice_items WHERE invoice_id=$1',[id])).rows;
    for(const item of items)await client.query(`INSERT INTO library_book_stock (book_id,quantity) VALUES ($1,$2)
      ON CONFLICT (book_id) DO UPDATE SET quantity=library_book_stock.quantity+EXCLUDED.quantity,updated_at=NOW()`,[item.book_id,item.received_quantity]);
    await client.query(`UPDATE library_purchase_invoices SET stock_status='POSTED',posted_at=NOW(),posted_by=$1 WHERE invoice_id=$2`,[req.auth.userId,id]);
    await client.query('COMMIT');res.json({ok:true,message:'Invoice stock posted successfully.'});
  }catch(error){await client.query('ROLLBACK');res.status(500).json({ok:false,message:'Unable to post invoice stock.'});}finally{client.release();}
});

app.delete('/api/library/purchase-invoices/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid invoice.'});
  try{const result=await pool.query(`DELETE FROM library_purchase_invoices WHERE invoice_id=$1 AND stock_status='DRAFT' RETURNING invoice_id`,[id]);if(!result.rowCount)return res.status(409).json({ok:false,message:'Only unposted invoices can be deleted.'});res.json({ok:true,message:'Purchase invoice deleted successfully.'});}
  catch(error){res.status(500).json({ok:false,message:'Unable to delete purchase invoice.'});}
});

app.get('/api/library/suppliers', authenticate, async (_req,res)=>{
  try{const result=await pool.query(`SELECT supplier_id AS id,supplier_code AS code,supplier_name AS name,
    contact_person,phone,email,gst_number,pan_number,address,payment_terms,is_active
    FROM library_suppliers ORDER BY supplier_name`);res.json({ok:true,suppliers:result.rows});}
  catch(error){console.error('Supplier query error:',error.message);res.status(500).json({ok:false,message:'Unable to load library suppliers.'});}
});

app.post('/api/library/suppliers', authenticate, async (req,res)=>{
  const {code,name,contactPerson,phone,email,gstNumber,panNumber,address,paymentTerms,status}=req.body;
  if(!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Supplier code and supplier name are required.'});
  try{const result=await pool.query(`INSERT INTO library_suppliers
    (supplier_code,supplier_name,contact_person,phone,email,gst_number,pan_number,address,payment_terms,is_active,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING supplier_id`,
    [code.trim().toUpperCase(),name.trim(),contactPerson?.trim()||null,phone?.trim()||null,email?.trim()||null,gstNumber?.trim().toUpperCase()||null,panNumber?.trim().toUpperCase()||null,address?.trim()||null,paymentTerms?.trim()||null,status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].supplier_id,message:'Supplier created successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Supplier code or name already exists.':'Unable to create supplier.'});}
});

app.post('/api/library/suppliers/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 supplier rows.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');for(let index=0;index<rows.length;index++){const row=rows[index];if(!row.code?.trim()||!row.name?.trim())throw new Error(`Row ${index+2}: Supplier Code and Supplier Name are required.`);await client.query(`INSERT INTO library_suppliers
    (supplier_code,supplier_name,contact_person,phone,email,gst_number,pan_number,address,payment_terms,is_active,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[row.code.trim().toUpperCase(),row.name.trim(),row.contactPerson?.trim()||null,row.phone?.trim()||null,row.email?.trim()||null,row.gstNumber?.trim().toUpperCase()||null,row.panNumber?.trim().toUpperCase()||null,row.address?.trim()||null,row.paymentTerms?.trim()||null,String(row.status||'ACTIVE').toUpperCase()!=='INACTIVE',req.auth.userId]);}await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} suppliers imported successfully.`});}
  catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains a duplicate supplier code or name.':error.message});}finally{client.release();}
});

app.put('/api/library/suppliers/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,contactPerson,phone,email,gstNumber,panNumber,address,paymentTerms,status}=req.body;
  if(!id||!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Supplier code and supplier name are required.'});
  try{const result=await pool.query(`UPDATE library_suppliers SET supplier_code=$1,supplier_name=$2,
    contact_person=$3,phone=$4,email=$5,gst_number=$6,pan_number=$7,address=$8,payment_terms=$9,
    is_active=$10,updated_at=NOW(),updated_by=$11 WHERE supplier_id=$12 RETURNING supplier_id`,
    [code.trim().toUpperCase(),name.trim(),contactPerson?.trim()||null,phone?.trim()||null,email?.trim()||null,gstNumber?.trim().toUpperCase()||null,panNumber?.trim().toUpperCase()||null,address?.trim()||null,paymentTerms?.trim()||null,status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Supplier not found.'});res.json({ok:true,message:'Supplier updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Supplier code or name already exists.':'Unable to update supplier.'});}
});

app.delete('/api/library/suppliers/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid supplier.'});
  try{const result=await pool.query('DELETE FROM library_suppliers WHERE supplier_id=$1 RETURNING supplier_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Supplier not found.'});res.json({ok:true,message:'Supplier deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This supplier is in use and cannot be deleted.':'Unable to delete supplier.'});}
});

app.get('/api/library/books', authenticate, async (_req,res)=>{
  try{
    const [books,titles,authors,publishers,categories,subjects]=await Promise.all([
      pool.query(`SELECT b.book_id AS id,b.isbn,b.title_id,t.title_name AS title_name,
        b.author_id,a.author_name AS author_name,b.publisher_id,p.publisher_name AS publisher_name,
        b.category_id,c.category_name AS category_name,b.subject_id,s.subject_name AS subject_name,
        b.edition,b.publication_year,b.language,b.pages,b.book_type,b.description,b.is_active
        FROM library_books b JOIN library_titles t ON t.title_id=b.title_id
        JOIN library_authors a ON a.author_id=b.author_id
        JOIN library_publishers p ON p.publisher_id=b.publisher_id
        JOIN library_categories c ON c.category_id=b.category_id
        JOIN library_subjects s ON s.subject_id=b.subject_id ORDER BY t.title_name,b.isbn`),
      pool.query('SELECT title_id AS id,title_code AS code,title_name AS name FROM library_titles WHERE is_active=TRUE ORDER BY title_name'),
      pool.query('SELECT author_id AS id,author_code AS code,author_name AS name FROM library_authors WHERE is_active=TRUE ORDER BY author_name'),
      pool.query('SELECT publisher_id AS id,publisher_code AS code,publisher_name AS name FROM library_publishers WHERE is_active=TRUE ORDER BY publisher_name'),
      pool.query('SELECT category_id AS id,category_code AS code,category_name AS name FROM library_categories WHERE is_active=TRUE ORDER BY category_name'),
      pool.query('SELECT subject_id AS id,subject_code AS code,subject_name AS name FROM library_subjects WHERE is_active=TRUE ORDER BY subject_name')
    ]);
    res.json({ok:true,books:books.rows,titles:titles.rows,authors:authors.rows,publishers:publishers.rows,categories:categories.rows,subjects:subjects.rows});
  }catch(error){console.error('Book query error:',error.message);res.status(500).json({ok:false,message:'Unable to load library books.'});}
});

app.post('/api/library/books', authenticate, async (req,res)=>{
  const {isbn,titleId,authorId,publisherId,categoryId,subjectId,edition,publicationYear,language,pages,bookType,description,status}=req.body;
  if(!isbn?.trim()||![titleId,authorId,publisherId,categoryId,subjectId].every(value=>Number(value))||!bookType?.trim())return res.status(400).json({ok:false,message:'ISBN, title, author, publisher, category, subject, and book type are required.'});
  try{
    const result=await pool.query(`INSERT INTO library_books
      (isbn,title_id,author_id,publisher_id,category_id,subject_id,edition,publication_year,language,pages,book_type,description,is_active,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING book_id`,
      [isbn.trim(),Number(titleId),Number(authorId),Number(publisherId),Number(categoryId),Number(subjectId),edition?.trim()||null,publicationYear?Number(publicationYear):null,language?.trim()||null,pages?Number(pages):null,bookType.trim(),description?.trim()||null,status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].book_id,message:'Book saved successfully.'});
  }catch(error){res.status(error.code==='23505'?409:error.code==='23503'||error.code==='23514'?400:500).json({ok:false,message:error.code==='23505'?'This ISBN already exists.':error.code==='23503'?'A selected library master record is invalid.':error.code==='23514'?'Publication year or pages is invalid.':'Unable to save book.'});}
});

app.post('/api/library/books/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 book rows.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const find=async(table,idColumn,codeColumn,nameColumn,value)=>(await client.query(`SELECT ${idColumn} AS id FROM ${table} WHERE LOWER(${codeColumn})=LOWER($1) OR LOWER(${nameColumn})=LOWER($1) LIMIT 1`,[value.trim()])).rows[0]?.id;
    for(let index=0;index<rows.length;index++){
      const row=rows[index];if(!row.isbn?.trim()||!row.title?.trim()||!row.author?.trim()||!row.publisher?.trim()||!row.category?.trim()||!row.subject?.trim()||!row.bookType?.trim())throw new Error(`Row ${index+2}: ISBN and all library selections are required.`);
      const [titleId,authorId,publisherId,categoryId,subjectId]=await Promise.all([
        find('library_titles','title_id','title_code','title_name',row.title),find('library_authors','author_id','author_code','author_name',row.author),
        find('library_publishers','publisher_id','publisher_code','publisher_name',row.publisher),find('library_categories','category_id','category_code','category_name',row.category),
        find('library_subjects','subject_id','subject_code','subject_name',row.subject)
      ]);
      if(!titleId||!authorId||!publisherId||!categoryId||!subjectId)throw new Error(`Row ${index+2}: One or more selected master records were not found.`);
      await client.query(`INSERT INTO library_books
        (isbn,title_id,author_id,publisher_id,category_id,subject_id,edition,publication_year,language,pages,book_type,description,is_active,created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [row.isbn.trim(),titleId,authorId,publisherId,categoryId,subjectId,row.edition?.trim()||null,row.publicationYear?Number(row.publicationYear):null,row.language?.trim()||null,row.pages?Number(row.pages):null,row.bookType.trim(),row.description?.trim()||null,String(row.status||'ACTIVE').toUpperCase()!=='INACTIVE',req.auth.userId]);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} books imported successfully.`});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains an ISBN that already exists.':error.message});}finally{client.release();}
});

app.put('/api/library/books/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {isbn,titleId,authorId,publisherId,categoryId,subjectId,edition,publicationYear,language,pages,bookType,description,status}=req.body;
  if(!id||!isbn?.trim()||![titleId,authorId,publisherId,categoryId,subjectId].every(value=>Number(value))||!bookType?.trim())return res.status(400).json({ok:false,message:'ISBN, title, author, publisher, category, subject, and book type are required.'});
  try{
    const result=await pool.query(`UPDATE library_books SET isbn=$1,title_id=$2,author_id=$3,publisher_id=$4,
      category_id=$5,subject_id=$6,edition=$7,publication_year=$8,language=$9,pages=$10,book_type=$11,
      description=$12,is_active=$13,updated_at=NOW(),updated_by=$14 WHERE book_id=$15 RETURNING book_id`,
      [isbn.trim(),Number(titleId),Number(authorId),Number(publisherId),Number(categoryId),Number(subjectId),edition?.trim()||null,publicationYear?Number(publicationYear):null,language?.trim()||null,pages?Number(pages):null,bookType.trim(),description?.trim()||null,status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Book not found.'});res.json({ok:true,message:'Book updated successfully.'});
  }catch(error){res.status(error.code==='23505'?409:error.code==='23503'||error.code==='23514'?400:500).json({ok:false,message:error.code==='23505'?'This ISBN already exists.':'Unable to update book.'});}
});

app.delete('/api/library/books/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid book.'});
  try{const result=await pool.query('DELETE FROM library_books WHERE book_id=$1 RETURNING book_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Book not found.'});res.json({ok:true,message:'Book deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This book is in use and cannot be deleted.':'Unable to delete book.'});}
});

app.get('/api/library/subjects', authenticate, async (_req,res)=>{
  try{
    const [subjects,departments]=await Promise.all([
      pool.query(`SELECT s.subject_id AS id,s.subject_code AS code,s.subject_name AS name,
        s.subject_alias AS alias,s.department_id,d.department_name AS department_name,s.is_active
        FROM library_subjects s JOIN departments d ON d.department_id=s.department_id
        ORDER BY s.subject_name`),
      pool.query(`SELECT department_id AS id,department_code AS code,department_name AS name
        FROM departments WHERE is_active=TRUE ORDER BY department_name`)
    ]);
    res.json({ok:true,subjects:subjects.rows,departments:departments.rows});
  }catch(error){console.error('Subject query error:',error.message);res.status(500).json({ok:false,message:'Unable to load library subjects.'});}
});

app.post('/api/library/subjects', authenticate, async (req,res)=>{
  const {code,name,alias,departmentId,status}=req.body;
  if(!code?.trim()||!name?.trim()||!Number(departmentId))return res.status(400).json({ok:false,message:'Subject code, subject name, and department are required.'});
  try{
    const result=await pool.query(`INSERT INTO library_subjects
      (subject_code,subject_name,subject_alias,department_id,is_active,created_by)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING subject_id`,
      [code.trim().toUpperCase(),name.trim(),alias?.trim()||null,Number(departmentId),status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].subject_id,message:'Subject created successfully.'});
  }catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'Subject code or department subject name already exists.':error.code==='23503'?'Department is invalid.':'Unable to create subject.'});}
});

app.post('/api/library/subjects/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 subject rows.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    for(let index=0;index<rows.length;index++){
      const row=rows[index];if(!row.code?.trim()||!row.name?.trim()||!row.department?.trim())throw new Error(`Row ${index+2}: Subject Code, Subject Name, and Department are required.`);
      const department=(await client.query(`SELECT department_id FROM departments
        WHERE is_active=TRUE AND (LOWER(department_code)=LOWER($1) OR LOWER(department_name)=LOWER($1)) LIMIT 1`,[row.department.trim()])).rows[0];
      if(!department)throw new Error(`Row ${index+2}: Department "${row.department}" was not found.`);
      await client.query(`INSERT INTO library_subjects
        (subject_code,subject_name,subject_alias,department_id,is_active,created_by)
        VALUES ($1,$2,$3,$4,$5,$6)`,[row.code.trim().toUpperCase(),row.name.trim(),row.alias?.trim()||null,department.department_id,String(row.status||'ACTIVE').toUpperCase()!=='INACTIVE',req.auth.userId]);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} subjects imported successfully.`});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains a duplicate subject code or department subject name.':error.message});}finally{client.release();}
});

app.put('/api/library/subjects/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,alias,departmentId,status}=req.body;
  if(!id||!code?.trim()||!name?.trim()||!Number(departmentId))return res.status(400).json({ok:false,message:'Subject code, subject name, and department are required.'});
  try{
    const result=await pool.query(`UPDATE library_subjects SET subject_code=$1,subject_name=$2,
      subject_alias=$3,department_id=$4,is_active=$5,updated_at=NOW(),updated_by=$6
      WHERE subject_id=$7 RETURNING subject_id`,
      [code.trim().toUpperCase(),name.trim(),alias?.trim()||null,Number(departmentId),status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Subject not found.'});
    res.json({ok:true,message:'Subject updated successfully.'});
  }catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'Subject code or department subject name already exists.':error.code==='23503'?'Department is invalid.':'Unable to update subject.'});}
});

app.delete('/api/library/subjects/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid subject.'});
  try{const result=await pool.query('DELETE FROM library_subjects WHERE subject_id=$1 RETURNING subject_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Subject not found.'});res.json({ok:true,message:'Subject deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This subject is in use and cannot be deleted.':'Unable to delete subject.'});}
});

app.get('/api/library/categories', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT c.category_id AS id,c.category_code AS code,c.category_name AS name,
      c.parent_category_id,p.category_name AS parent_name,c.issue_allowed,c.is_active
      FROM library_categories c LEFT JOIN library_categories p ON p.category_id=c.parent_category_id
      ORDER BY c.category_name`);
    res.json({ok:true,categories:result.rows});
  }catch(error){console.error('Category query error:',error.message);res.status(500).json({ok:false,message:'Unable to load library categories.'});}
});

app.post('/api/library/categories', authenticate, async (req,res)=>{
  const {code,name,parentCategoryId,issueAllowed,status}=req.body;
  if(!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Category code and category name are required.'});
  try{
    const result=await pool.query(`INSERT INTO library_categories
      (category_code,category_name,parent_category_id,issue_allowed,is_active,created_by)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING category_id`,
      [code.trim().toUpperCase(),name.trim(),parentCategoryId?Number(parentCategoryId):null,issueAllowed!==false,status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].category_id,message:'Category created successfully.'});
  }catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'Category code or name already exists.':error.code==='23503'?'Parent category is invalid.':'Unable to create category.'});}
});

app.post('/api/library/categories/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 category rows.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    for(let index=0;index<rows.length;index++){
      const row=rows[index];if(!row.code?.trim()||!row.name?.trim())throw new Error(`Row ${index+2}: Category Code and Category Name are required.`);
      let parentId=null;
      if(row.parentCategory?.trim()){
        const parent=(await client.query(`SELECT category_id FROM library_categories
          WHERE LOWER(category_code)=LOWER($1) OR LOWER(category_name)=LOWER($1) LIMIT 1`,[row.parentCategory.trim()])).rows[0];
        if(!parent)throw new Error(`Row ${index+2}: Parent Category "${row.parentCategory}" was not found. Place parent rows before their children.`);
        parentId=parent.category_id;
      }
      await client.query(`INSERT INTO library_categories
        (category_code,category_name,parent_category_id,issue_allowed,is_active,created_by)
        VALUES ($1,$2,$3,$4,$5,$6)`,[row.code.trim().toUpperCase(),row.name.trim(),parentId,String(row.issueAllowed||'YES').toUpperCase()!=='NO',String(row.status||'ACTIVE').toUpperCase()!=='INACTIVE',req.auth.userId]);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} categories imported successfully.`});
  }catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains a duplicate category code or name.':error.message});}finally{client.release();}
});

app.put('/api/library/categories/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,parentCategoryId,issueAllowed,status}=req.body;
  const parentId=parentCategoryId?Number(parentCategoryId):null;
  if(!id||!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Category code and category name are required.'});
  if(parentId===id)return res.status(400).json({ok:false,message:'A category cannot be its own parent.'});
  try{
    const result=await pool.query(`UPDATE library_categories SET category_code=$1,category_name=$2,
      parent_category_id=$3,issue_allowed=$4,is_active=$5,updated_at=NOW(),updated_by=$6
      WHERE category_id=$7 RETURNING category_id`,
      [code.trim().toUpperCase(),name.trim(),parentId,issueAllowed!==false,status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Category not found.'});
    res.json({ok:true,message:'Category updated successfully.'});
  }catch(error){res.status(error.code==='23505'?409:error.code==='23503'?400:500).json({ok:false,message:error.code==='23505'?'Category code or name already exists.':error.code==='23503'?'Parent category is invalid.':'Unable to update category.'});}
});

app.delete('/api/library/categories/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid category.'});
  try{const result=await pool.query('DELETE FROM library_categories WHERE category_id=$1 RETURNING category_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Category not found.'});res.json({ok:true,message:'Category deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This category is in use and cannot be deleted.':'Unable to delete category.'});}
});

app.get('/api/library/titles', authenticate, async (_req,res)=>{
  try{
    const result=await pool.query(`SELECT title_id AS id,title_code AS code,title_name AS name,
      subtitle,language,description,is_active FROM library_titles ORDER BY title_name`);
    res.json({ok:true,titles:result.rows});
  }catch(error){console.error('Title query error:',error.message);res.status(500).json({ok:false,message:'Unable to load library titles.'});}
});

app.post('/api/library/titles', authenticate, async (req,res)=>{
  const {code,name,subtitle,language,description,status}=req.body;if(!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Title code and book title are required.'});
  try{
    const result=await pool.query(`INSERT INTO library_titles
      (title_code,title_name,subtitle,language,description,is_active,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING title_id`,
      [code.trim().toUpperCase(),name.trim(),subtitle?.trim()||null,language?.trim()||null,description?.trim()||null,status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].title_id,message:'Title created successfully.'});
  }catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This title already exists.':'Unable to create title.'});}
});

app.post('/api/library/titles/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 title rows.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');for(let index=0;index<rows.length;index++){const row=rows[index];if(!row.code?.trim()||!row.name?.trim())throw new Error(`Row ${index+2}: Title Code and Book Title are required.`);await client.query(`INSERT INTO library_titles
    (title_code,title_name,subtitle,language,description,is_active,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [row.code.trim().toUpperCase(),row.name.trim(),row.subtitle?.trim()||null,row.language?.trim()||null,row.description?.trim()||null,String(row.status||'ACTIVE').toUpperCase()!=='INACTIVE',req.auth.userId]);}await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} titles imported successfully.`});}
  catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains a title that already exists.':error.message});}finally{client.release();}
});

app.put('/api/library/titles/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,subtitle,language,description,status}=req.body;if(!id||!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'A valid title code and book title are required.'});
  try{const result=await pool.query(`UPDATE library_titles SET title_code=$1,title_name=$2,subtitle=$3,
    language=$4,description=$5,is_active=$6,updated_at=NOW(),updated_by=$7 WHERE title_id=$8 RETURNING title_id`,
    [code.trim().toUpperCase(),name.trim(),subtitle?.trim()||null,language?.trim()||null,description?.trim()||null,status!=='INACTIVE',req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Title not found.'});res.json({ok:true,message:'Title updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This title already exists.':'Unable to update title.'});}
});

app.delete('/api/library/titles/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid title.'});
  try{const result=await pool.query('DELETE FROM library_titles WHERE title_id=$1 RETURNING title_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Title not found.'});res.json({ok:true,message:'Title deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This title is assigned to a book and cannot be deleted.':'Unable to delete title.'});}
});

app.get('/api/library/publishers', authenticate, async (_req,res)=>{
  try{const result=await pool.query(`SELECT publisher_id AS id,publisher_code AS code,
    publisher_name AS name,contact_person,phone,email,website,address,is_active
    FROM library_publishers ORDER BY publisher_name`);res.json({ok:true,publishers:result.rows});}
  catch(error){console.error('Publisher query error:',error.message);res.status(500).json({ok:false,message:'Unable to load library publishers.'});}
});

app.post('/api/library/publishers', authenticate, async (req,res)=>{
  const {code,name,contactPerson,phone,email,website,address,status}=req.body;
  if(!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Publisher code and publisher name are required.'});
  try{const result=await pool.query(`INSERT INTO library_publishers
    (publisher_code,publisher_name,contact_person,phone,email,website,address,is_active,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING publisher_id`,
    [code.trim().toUpperCase(),name.trim(),contactPerson?.trim()||null,phone?.trim()||null,email?.trim()||null,website?.trim()||null,address?.trim()||null,status!=='INACTIVE',req.auth.userId]);
    res.status(201).json({ok:true,id:result.rows[0].publisher_id,message:'Publisher created successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Publisher code or name already exists.':'Unable to create publisher.'});}
});

app.post('/api/library/publishers/bulk', authenticate, async (req,res)=>{
  const rows=Array.isArray(req.body.rows)?req.body.rows:[];if(!rows.length||rows.length>500)return res.status(400).json({ok:false,message:'Upload between 1 and 500 publisher rows.'});
  const client=await pool.connect();
  try{await client.query('BEGIN');for(let index=0;index<rows.length;index++){const row=rows[index];if(!row.code?.trim()||!row.name?.trim())throw new Error(`Row ${index+2}: Publisher Code and Publisher Name are required.`);await client.query(`INSERT INTO library_publishers
    (publisher_code,publisher_name,contact_person,phone,email,website,address,is_active,created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[row.code.trim().toUpperCase(),row.name.trim(),row.contactPerson?.trim()||null,row.phone?.trim()||null,row.email?.trim()||null,row.website?.trim()||null,row.address?.trim()||null,String(row.status||'ACTIVE').toUpperCase()!=='INACTIVE',req.auth.userId]);}await client.query('COMMIT');res.status(201).json({ok:true,message:`${rows.length} publishers imported successfully.`});}
  catch(error){await client.query('ROLLBACK');res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'The file contains a duplicate publisher code or name.':error.message});}finally{client.release();}
});

app.put('/api/library/publishers/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);const {code,name,contactPerson,phone,email,website,address,status}=req.body;
  if(!id||!code?.trim()||!name?.trim())return res.status(400).json({ok:false,message:'Publisher code and publisher name are required.'});
  try{const result=await pool.query(`UPDATE library_publishers SET publisher_code=$1,publisher_name=$2,
    contact_person=$3,phone=$4,email=$5,website=$6,address=$7,is_active=$8,updated_at=NOW(),updated_by=$9
    WHERE publisher_id=$10 RETURNING publisher_id`,[code.trim().toUpperCase(),name.trim(),contactPerson?.trim()||null,phone?.trim()||null,email?.trim()||null,website?.trim()||null,address?.trim()||null,status!=='INACTIVE',req.auth.userId,id]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Publisher not found.'});res.json({ok:true,message:'Publisher updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Publisher code or name already exists.':'Unable to update publisher.'});}
});

app.delete('/api/library/publishers/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid publisher.'});
  try{const result=await pool.query('DELETE FROM library_publishers WHERE publisher_id=$1 RETURNING publisher_id',[id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Publisher not found.'});res.json({ok:true,message:'Publisher deleted successfully.'});}
  catch(error){res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This publisher is assigned to a book and cannot be deleted.':'Unable to delete publisher.'});}
});

app.get('/api/common-masters', authenticate, async (_req,res)=>{
  try{
    const [types,values]=await Promise.all([
      pool.query(`SELECT master_type_id AS id,master_type_code AS code,master_type_name AS name,
        description,0 AS display_order,is_active FROM common_master_types ORDER BY master_type_name`),
      pool.query(`SELECT v.master_value_id AS id,t.master_type_code AS type,v.master_type_id,
        v.value_code AS code,v.value_name AS name,v.short_name,v.display_order,
        v.is_default,v.is_active,v.remarks
        FROM common_master_values v JOIN common_master_types t ON t.master_type_id=v.master_type_id
        ORDER BY t.master_type_name,v.display_order,v.value_name`)
    ]);
    res.json({ok:true,types:types.rows,values:values.rows});
  }catch(error){
    console.error('Common masters query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load common masters.'});
  }
});

app.post('/api/common-masters', authenticate, async (req,res)=>{
  const {type,code,name,shortName,displayOrder,status,isDefault,remarks}=req.body;
  if(!type?.trim()||!code?.trim()||!name?.trim()) return res.status(400).json({ok:false,message:'Master type, code and name are required.'});
  try{
    const masterType=(await pool.query('SELECT master_type_id FROM common_master_types WHERE master_type_code=$1 AND is_active=TRUE ORDER BY master_type_id LIMIT 1',[type.trim().toUpperCase()])).rows[0];
    if(!masterType) return res.status(400).json({ok:false,message:'The selected common master type does not exist or is inactive.'});
    await pool.query(`INSERT INTO common_master_values
      (master_type_id,value_code,value_name,short_name,display_order,is_default,is_active,remarks,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [masterType.master_type_id,code.trim().toUpperCase(),name.trim(),shortName?.trim()||null,Number(displayOrder)||0,Boolean(isDefault),status!=='INACTIVE',remarks?.trim()||null,req.auth.userId]);
    res.status(201).json({ok:true,message:'Master value saved successfully.'});
  }catch(error){
    console.error('Common master save error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'This code already exists for the selected master.':'Unable to save master value.'});
  }
});

app.get('/api/timetable/manage', authenticate, async (_req,res)=>{
  try{
    const [academicYears,programmes,batches,semesters,sections,configurations,timetables]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(academic_year_name,year_label) AS name
        FROM academic_years WHERE is_active=TRUE ORDER BY start_date DESC`),
      pool.query(`SELECT programme_id AS id,programme_code AS code,programme_name AS name
        FROM programmes WHERE is_active=TRUE ORDER BY programme_name`),
      pool.query(`SELECT batch_id AS id,programme_id,batch_name AS name
        FROM admission_batches WHERE is_active=TRUE ORDER BY admission_year DESC,batch_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_number,semester_name AS name
        FROM semesters WHERE is_active=TRUE ORDER BY programme_id,semester_number`),
      pool.query(`SELECT section_id AS id,batch_id,semester_id,section_name AS name
        FROM sections WHERE is_active=TRUE ORDER BY section_name`),
      pool.query(`SELECT time_configuration_id AS id,academic_year_id,configuration_name AS name,
          college_start_time::text,college_end_time::text,teaching_period_minutes
        FROM academics.academic_time_configurations WHERE is_active=TRUE ORDER BY configuration_name`),
      pool.query(`SELECT th.timetable_id AS id,th.academic_year_id,th.programme_id,
          th.programme_batch_id AS batch_id,th.semester_id,th.programme_section_id AS section_id,
          COALESCE(ay.academic_year_name,ay.year_label) AS academic_year,
          p.programme_name AS programme,b.batch_name AS batch,
          s.semester_number,s.semester_name AS semester,se.section_name AS section,
          th.timetable_status AS status,th.timetable_name,th.version_number
        FROM academics.timetable_headers th
        JOIN academic_years ay ON ay.academic_year_id=th.academic_year_id
        JOIN programmes p ON p.programme_id=th.programme_id
        JOIN admission_batches b ON b.batch_id=th.programme_batch_id
        JOIN semesters s ON s.semester_id=th.semester_id
        JOIN sections se ON se.section_id=th.programme_section_id
        ORDER BY th.created_at DESC,th.timetable_id DESC`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,programmes:programmes.rows,
      batches:batches.rows,semesters:semesters.rows,sections:sections.rows,
      configurations:configurations.rows,timetables:timetables.rows});
  }catch(error){
    console.error('Manage timetable query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load timetables.'});
  }
});

app.post('/api/timetable/manage', authenticate, async (req,res)=>{
  const data=req.body||{};
  const required=['academicYearId','programmeId','batchId','semesterId','sectionId','timeConfigurationId','timetableName','effectiveFrom'];
  if(required.some(key=>!String(data[key]??'').trim()))
    return res.status(400).json({ok:false,message:'Complete all required timetable fields.'});
  if(data.effectiveTo&&data.effectiveTo<data.effectiveFrom)
    return res.status(400).json({ok:false,message:'Effective To cannot be earlier than Effective From.'});
  const status=['Draft','Under Review'].includes(data.status)?data.status:'Draft';
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const related=(await client.query(`SELECT 1
      FROM admission_batches b
      JOIN semesters sm ON sm.programme_id=b.programme_id
      JOIN sections se ON se.batch_id=b.batch_id AND se.semester_id=sm.semester_id
      JOIN academics.academic_time_configurations tc ON tc.academic_year_id=$1
      WHERE b.batch_id=$2 AND b.programme_id=$3 AND sm.semester_id=$4
        AND se.section_id=$5 AND tc.time_configuration_id=$6`,
      [Number(data.academicYearId),Number(data.batchId),Number(data.programmeId),Number(data.semesterId),Number(data.sectionId),Number(data.timeConfigurationId)])).rowCount;
    if(!related){await client.query('ROLLBACK');return res.status(400).json({ok:false,message:'The selected programme, batch, semester, section, or time configuration does not match.'});}
    const timetable=(await client.query(`INSERT INTO academics.timetable_headers
      (academic_year_id,programme_id,programme_batch_id,semester_id,programme_section_id,group_id,
       time_configuration_id,timetable_name,effective_from,effective_to,timetable_status,remarks,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING timetable_id`,[
        Number(data.academicYearId),Number(data.programmeId),Number(data.batchId),Number(data.semesterId),
        Number(data.sectionId),data.groupId?Number(data.groupId):null,Number(data.timeConfigurationId),
        data.timetableName.trim(),data.effectiveFrom,data.effectiveTo||null,status,data.remarks?.trim()||null,req.auth.userId
      ])).rows[0];
    await client.query(`INSERT INTO academics.timetable_working_days
      (timetable_id,week_day_id,is_working_day,display_order)
      SELECT $1,d.week_day_id,TRUE,wd.day_number
      FROM academics.academic_time_configuration_days d
      JOIN academics.week_days wd ON wd.week_day_id=d.week_day_id
      WHERE d.time_configuration_id=$2 ORDER BY wd.day_number`,[timetable.timetable_id,Number(data.timeConfigurationId)]);
    await client.query(`INSERT INTO academics.timetable_change_logs
      (timetable_id,action_type,new_value,change_reason,changed_by)
      VALUES ($1,'Created',$2::jsonb,'Timetable created',$3)`,
      [timetable.timetable_id,JSON.stringify({name:data.timetableName,status}),req.auth.userId]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,id:timetable.timetable_id,message:'Timetable created successfully.'});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Create timetable error:',error.message);
    res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'A timetable version already exists for this academic year, batch, semester and section.':'Unable to create timetable.'});
  }finally{client.release();}
});

app.delete('/api/timetable/manage/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid timetable.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const timetable=(await client.query(`SELECT timetable_id,timetable_status FROM academics.timetable_headers
      WHERE timetable_id=$1 FOR UPDATE`,[id])).rows[0];
    if(!timetable){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Timetable not found.'});}
    if(timetable.timetable_status!=='Draft'){await client.query('ROLLBACK');return res.status(409).json({ok:false,message:'Only Draft timetables can be removed.'});}
    await client.query('DELETE FROM academics.timetable_entries WHERE timetable_id=$1',[id]);
    await client.query('DELETE FROM academics.timetable_working_days WHERE timetable_id=$1',[id]);
    await client.query('DELETE FROM academics.timetable_change_logs WHERE timetable_id=$1',[id]);
    await client.query('DELETE FROM academics.timetable_headers WHERE timetable_id=$1',[id]);
    await client.query('COMMIT');res.json({ok:true,message:'Draft timetable removed successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Timetable delete error:',error.message);res.status(error.code==='23503'?409:500).json({ok:false,message:error.code==='23503'?'This timetable is used by other academic records and cannot be removed.':'Unable to remove timetable.'});}
  finally{client.release();}
});

app.get('/api/timetable/entry', authenticate, async (req,res)=>{
  try{
    const timetableId=Number(req.query.timetableId)||null;
    const timetables=await pool.query(`SELECT th.timetable_id AS id,th.timetable_name AS name,
      th.timetable_status AS status,th.programme_batch_id AS batch_id,th.semester_id,th.programme_section_id AS section_id,
      COALESCE(ay.academic_year_name,ay.year_label) AS academic_year,p.programme_name,s.semester_name,se.section_name
      FROM academics.timetable_headers th
      JOIN academic_years ay ON ay.academic_year_id=th.academic_year_id
      JOIN programmes p ON p.programme_id=th.programme_id
      JOIN semesters s ON s.semester_id=th.semester_id
      JOIN sections se ON se.section_id=th.programme_section_id
      ORDER BY th.created_at DESC`);
    const selected=timetableId?await pool.query(`SELECT timetable_id,time_configuration_id,programme_batch_id,semester_id,programme_section_id
      FROM academics.timetable_headers WHERE timetable_id=$1`,[timetableId]):{rows:[]};
    if(timetableId&&!selected.rowCount)return res.status(404).json({ok:false,message:'Timetable not found.'});
    let days=[],periods=[],entries=[];
    if(selected.rowCount){
      [days,periods,entries]=await Promise.all([
        pool.query(`SELECT wd.week_day_id AS id,wd.day_name AS name,wd.day_number
          FROM academics.timetable_working_days twd JOIN academics.week_days wd ON wd.week_day_id=twd.week_day_id
          WHERE twd.timetable_id=$1 AND twd.is_working_day=TRUE ORDER BY twd.display_order`,[timetableId]),
        pool.query(`SELECT period_id AS id,period_code AS code,period_name AS name,start_time::text,end_time::text,
          duration_minutes,period_type AS type,display_order,is_teaching_period
          FROM academics.academic_periods WHERE time_configuration_id=$1 AND is_active=TRUE ORDER BY display_order`,
          [selected.rows[0].time_configuration_id]),
        pool.query(`SELECT timetable_entry_id AS id,week_day_id,period_id,subject_id,classroom_id AS room_id,entry_type,display_text
          FROM academics.timetable_entries WHERE timetable_id=$1`,[timetableId])
      ]);
    }
    const [subjects,rooms]=await Promise.all([
      pool.query(`SELECT subject_master_id AS id,subject_code AS code,subject_name AS name
        FROM subject_masters WHERE is_active=TRUE ORDER BY subject_code`),
      pool.query(`SELECT classroom_id AS id,COALESCE(room_name,room_no) AS name,room_no AS room_number
        FROM classrooms WHERE is_active=TRUE ORDER BY room_no`)
    ]);
    res.json({ok:true,timetables:timetables.rows,subjects:subjects.rows,rooms:rooms.rows,
      days:days.rows||[],periods:periods.rows||[],entries:entries.rows||[]});
  }catch(error){
    console.error('Timetable entry query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load timetable entry.'});
  }
});

app.post('/api/timetable/entry/:id', authenticate, async (req,res)=>{
  const timetableId=Number(req.params.id);
  const entries=Array.isArray(req.body.entries)?req.body.entries:[];
  if(!timetableId)return res.status(400).json({ok:false,message:'Select a valid timetable.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const timetable=(await client.query(`SELECT timetable_id,timetable_status FROM academics.timetable_headers
      WHERE timetable_id=$1 FOR UPDATE`,[timetableId])).rows[0];
    if(!timetable){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Timetable not found.'});}
    if(timetable.timetable_status==='Published'){await client.query('ROLLBACK');return res.status(409).json({ok:false,message:'Published timetables cannot be edited. Create a revision first.'});}
    await client.query('DELETE FROM academics.timetable_entries WHERE timetable_id=$1',[timetableId]);
    for(const item of entries){
      if(!Number(item.weekDayId)||!Number(item.periodId)||!Number(item.subjectId))continue;
      const subject=(await client.query('SELECT subject_code FROM subject_masters WHERE subject_master_id=$1 AND is_active=TRUE',[Number(item.subjectId)])).rows[0];
      if(!subject)throw Object.assign(new Error('Invalid subject selection.'),{code:'TT_VALIDATION'});
      await client.query(`INSERT INTO academics.timetable_entries
        (timetable_id,week_day_id,period_id,subject_id,classroom_id,entry_type,display_text,created_by)
        VALUES ($1,$2,$3,$4,$5,'Theory',$6,$7)`,
        [timetableId,Number(item.weekDayId),Number(item.periodId),Number(item.subjectId),item.roomId?Number(item.roomId):null,subject.subject_code,req.auth.userId]);
    }
    await client.query(`UPDATE academics.timetable_headers SET timetable_status='Draft',updated_by=$1,updated_at=NOW() WHERE timetable_id=$2`,[req.auth.userId,timetableId]);
    await client.query('COMMIT');
    res.json({ok:true,message:'Timetable draft saved successfully.'});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Timetable entry save error:',error.message);
    res.status(error.code==='TT_VALIDATION'?400:409).json({ok:false,message:error.code==='TT_VALIDATION'?error.message:error.message.includes('already')?error.message:'Unable to save timetable entries.'});
  }finally{client.release();}
});

async function timetableValidation(timetableId){
  const summary=(await pool.query(`SELECT
    (SELECT COUNT(*) FROM academics.timetable_working_days WHERE timetable_id=$1 AND is_working_day=TRUE) AS day_count,
    (SELECT COUNT(*) FROM academics.academic_periods ap JOIN academics.timetable_headers th ON th.time_configuration_id=ap.time_configuration_id WHERE th.timetable_id=$1 AND ap.is_active=TRUE AND ap.is_teaching_period=TRUE) AS period_count,
    (SELECT COUNT(*) FROM academics.timetable_entries WHERE timetable_id=$1) AS entry_count`,[timetableId])).rows[0];
  if(!summary)return null;
  const required=Number(summary.day_count)*Number(summary.period_count),assigned=Number(summary.entry_count);
  return {required,assigned,missing:Math.max(0,required-assigned),valid:required>0&&assigned>=required};
}

app.post('/api/timetable/entry/:id/validate', authenticate, async (req,res)=>{
  try{
    const validation=await timetableValidation(Number(req.params.id));
    if(!validation)return res.status(404).json({ok:false,message:'Timetable not found.'});
    res.json({ok:true,...validation,message:validation.valid?'Timetable validation passed.':`${validation.missing} teaching slots are still unassigned.`});
  }catch(error){res.status(500).json({ok:false,message:'Unable to validate timetable.'});}
});

app.post('/api/timetable/entry/:id/publish', authenticate, async (req,res)=>{
  const timetableId=Number(req.params.id);
  try{
    const validation=await timetableValidation(timetableId);
    if(!validation?.valid)return res.status(400).json({ok:false,...validation,message:validation?`${validation.missing} teaching slots must be assigned before publishing.`:'Timetable not found.'});
    const result=await pool.query(`UPDATE academics.timetable_headers SET timetable_status='Published',
      published_by=$1,published_at=NOW(),updated_by=$1,updated_at=NOW() WHERE timetable_id=$2 RETURNING timetable_id`,
      [req.auth.userId,timetableId]);
    if(!result.rowCount)return res.status(404).json({ok:false,message:'Timetable not found.'});
    await pool.query(`INSERT INTO academics.timetable_change_logs
      (timetable_id,action_type,new_value,change_reason,changed_by)
      VALUES ($1,'Published',$2::jsonb,'Timetable validation passed',$3)`,
      [timetableId,JSON.stringify({status:'Published'}),req.auth.userId]);
    res.json({ok:true,message:'Timetable published successfully.'});
  }catch(error){
    console.error('Timetable publish error:',error.message);
    res.status(500).json({ok:false,message:'Unable to publish timetable.'});
  }
});

app.get('/api/timetable/time-configuration', authenticate, async (req,res)=>{
  try{
    const academicYearId=Number(req.query.academicYearId)||null;
    const [academicYears,weekDays,configuration]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(academic_year_name,year_label) AS name
        FROM academic_years WHERE is_active=TRUE ORDER BY start_date DESC`),
      pool.query(`SELECT week_day_id AS id,day_name AS name,day_number
        FROM academics.week_days WHERE is_active=TRUE ORDER BY day_number`),
      academicYearId?pool.query(`SELECT * FROM academics.academic_time_configurations
        WHERE academic_year_id=$1 AND is_active=TRUE ORDER BY updated_at DESC NULLS LAST,created_at DESC LIMIT 1`,[academicYearId]):Promise.resolve({rows:[]})
    ]);
    const config=configuration.rows[0]||null;
    let days=[],breaks=[],periods=[];
    if(config){
      [days,breaks,periods]=await Promise.all([
        pool.query(`SELECT week_day_id AS id FROM academics.academic_time_configuration_days WHERE time_configuration_id=$1`,[config.time_configuration_id]),
        pool.query(`SELECT academic_break_id AS id,break_name AS name,break_type AS type,
          start_time::text,end_time::text,EXTRACT(EPOCH FROM (end_time-start_time))/60 AS duration
          FROM academics.academic_breaks WHERE time_configuration_id=$1 ORDER BY start_time`,[config.time_configuration_id]),
        pool.query(`SELECT period_id AS id,period_code AS code,period_name AS name,start_time::text,end_time::text,
          duration_minutes,period_type AS type,display_order,is_teaching_period
          FROM academics.academic_periods WHERE time_configuration_id=$1 ORDER BY display_order`,[config.time_configuration_id])
      ]);
    }
    res.json({ok:true,academicYears:academicYears.rows,weekDays:weekDays.rows,configuration:config,
      workingDayIds:days.rows?.map(row=>row.id)||[],breaks:breaks.rows||[],periods:periods.rows||[]});
  }catch(error){
    console.error('Time configuration query error:',error.message);
    res.status(500).json({ok:false,message:'Unable to load academic time configuration.'});
  }
});

function timetableMinutes(value){
  const match=String(value||'').match(/^(\d{1,2}):(\d{2})/);
  return match?Number(match[1])*60+Number(match[2]):NaN;
}

function timetableTime(minutes){
  return `${String(Math.floor(minutes/60)).padStart(2,'0')}:${String(minutes%60).padStart(2,'0')}:00`;
}

app.post('/api/timetable/time-configuration', authenticate, async (req,res)=>{
  const data=req.body||{};
  const start=timetableMinutes(data.collegeStartTime),end=timetableMinutes(data.collegeEndTime);
  const duration=Number(data.teachingPeriodMinutes);
  if(!Number(data.academicYearId)||!String(data.configurationName||'').trim()||!Number.isFinite(start)||!Number.isFinite(end)||end<=start||!Number.isInteger(duration)||duration<1)
    return res.status(400).json({ok:false,message:'Academic year, configuration name, valid times, and teaching period are required.'});
  if(!Array.isArray(data.workingDayIds)||!data.workingDayIds.length)
    return res.status(400).json({ok:false,message:'Select at least one working day.'});
  const breaks=(Array.isArray(data.breaks)?data.breaks:[]).map((item,index)=>({
    name:String(item.name||'').trim(),type:String(item.type||'Other'),
    start:timetableMinutes(item.startTime),end:timetableMinutes(item.endTime),order:index+1
  })).sort((a,b)=>a.start-b.start);
  if(breaks.some(item=>!item.name||!Number.isFinite(item.start)||!Number.isFinite(item.end)||item.start<start||item.end>end||item.end<=item.start))
    return res.status(400).json({ok:false,message:'Every break needs a name and valid times within college hours.'});
  if(breaks.some((item,index)=>index>0&&item.start<breaks[index-1].end))
    return res.status(400).json({ok:false,message:'Break times cannot overlap.'});

  const periods=[];
  let cursor=start,teachingNumber=1,displayOrder=1,lunchNumber=0;
  for(const item of [...breaks,{start:end,end,type:null,name:null}]){
    while(cursor<item.start){
      const periodEnd=Math.min(cursor+duration,item.start);
      periods.push({code:`P${teachingNumber}`,name:`Period ${teachingNumber}`,start:cursor,end:periodEnd,
        duration:periodEnd-cursor,type:'Teaching',order:displayOrder++,teaching:true});
      teachingNumber+=1;cursor=periodEnd;
    }
    if(item.type){
      if(item.type==='Lunch')lunchNumber+=1;
      const code=item.type==='Lunch'?(lunchNumber===1?'LUNCH':`LUNCH${lunchNumber}`):`B${item.order}`;
      const periodType=item.type==='Tea Break'?'Break':item.type;
      periods.push({code,name:item.name,start:item.start,end:item.end,duration:item.end-item.start,
        type:periodType,order:displayOrder++,teaching:false});
      cursor=item.end;
    }
  }

  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const existing=(await client.query(`SELECT time_configuration_id FROM academics.academic_time_configurations
      WHERE academic_year_id=$1 AND configuration_name=$2`,[Number(data.academicYearId),data.configurationName.trim()])).rows[0];
    let id;
    if(existing){
      id=existing.time_configuration_id;
      await client.query(`UPDATE academics.academic_time_configurations SET college_start_time=$1,college_end_time=$2,
        teaching_period_minutes=$3,is_active=TRUE,updated_by=$4,updated_at=NOW() WHERE time_configuration_id=$5`,
        [timetableTime(start),timetableTime(end),duration,req.auth.userId,id]);
      await client.query('DELETE FROM academics.academic_periods WHERE time_configuration_id=$1',[id]);
      await client.query('DELETE FROM academics.academic_breaks WHERE time_configuration_id=$1',[id]);
      await client.query('DELETE FROM academics.academic_time_configuration_days WHERE time_configuration_id=$1',[id]);
    }else{
      id=(await client.query(`INSERT INTO academics.academic_time_configurations
        (academic_year_id,configuration_name,college_start_time,college_end_time,teaching_period_minutes,created_by)
        VALUES ($1,$2,$3,$4,$5,$6) RETURNING time_configuration_id`,
        [Number(data.academicYearId),data.configurationName.trim(),timetableTime(start),timetableTime(end),duration,req.auth.userId])).rows[0].time_configuration_id;
    }
    for(const dayId of [...new Set(data.workingDayIds.map(Number))])
      await client.query(`INSERT INTO academics.academic_time_configuration_days (time_configuration_id,week_day_id) VALUES ($1,$2)`,[id,dayId]);
    for(const item of breaks)
      await client.query(`INSERT INTO academics.academic_breaks
        (time_configuration_id,break_name,break_type,start_time,end_time,display_order,created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,[id,item.name,item.type,timetableTime(item.start),timetableTime(item.end),item.order,req.auth.userId]);
    for(const item of periods)
      await client.query(`INSERT INTO academics.academic_periods
        (time_configuration_id,period_code,period_name,start_time,end_time,duration_minutes,period_type,display_order,is_teaching_period)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,item.code,item.name,timetableTime(item.start),timetableTime(item.end),item.duration,item.type,item.order,item.teaching]);
    await client.query('COMMIT');
    res.json({ok:true,id,message:'Academic time configuration saved successfully.',periods});
  }catch(error){
    await client.query('ROLLBACK');
    console.error('Time configuration save error:',error.message);
    const inUse=error.code==='23503';
    const invalid=error.code==='23514'||error.code==='23505'||error.code==='P0001';
    res.status(inUse||invalid?409:500).json({ok:false,message:inUse?'This configuration is used by a timetable and cannot replace its periods.':invalid?error.message:'Unable to save academic time configuration.'});
  }finally{client.release();}
});

app.get('/api/student-mentor-allotment-options', authenticate, async (_req,res)=>{
  try{
    await pool.query(`INSERT INTO mentoring.mentors(employee_id,department_id)
      SELECT employee_id,department_id FROM employees WHERE UPPER(COALESCE(status,'ACTIVE'))='ACTIVE'
      ON CONFLICT(employee_id) DO UPDATE SET department_id=EXCLUDED.department_id`);
    const [years,programmes,batches,semesters,sections,mentors]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(NULLIF(academic_year_name,''),year_label) AS name,is_current
        FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT programme_id AS id,programme_code AS code,programme_name AS name
        FROM programmes WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY programme_name`),
      pool.query(`SELECT batch_id AS id,programme_id,batch_name AS name
        FROM admission_batches WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY admission_year DESC,batch_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name,semester_number
        FROM semesters WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY semester_number`),
      pool.query(`SELECT section_id AS id,batch_id,semester_id,section_name AS name
        FROM sections WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY section_name`),
      pool.query(`SELECT employee_id AS id,department_id,employee_code,
        TRIM(CONCAT_WS(' ',first_name,middle_name,last_name)) AS name
        FROM employees WHERE UPPER(COALESCE(status,'ACTIVE'))='ACTIVE' ORDER BY name`)
    ]);
    res.json({ok:true,academicYears:years.rows,programmes:programmes.rows,batches:batches.rows,
      semesters:semesters.rows,sections:sections.rows,mentors:mentors.rows});
  }catch(error){console.error('Student mentor options error:',error.message);res.status(500).json({ok:false,message:'Unable to load mentor allotment options.'});}
});

app.get('/api/student-mentor-allotment-students', authenticate, async (req,res)=>{
  try{
    const {academicYearId,programmeId,batchId,semesterId,sectionId,fromRegistration,toRegistration}=req.query;
    if(!academicYearId||!programmeId||!batchId||!semesterId||!sectionId)
      return res.status(400).json({ok:false,message:'Academic year, programme, batch, semester and section are required.'});
    const values=[Number(academicYearId),Number(programmeId),Number(batchId),Number(semesterId),Number(sectionId)],where=[
      'st.programme_id=$2','st.batch_id=$3','st.semester_id=$4','st.section_id=$5',
      "COALESCE(st.is_active,TRUE)=TRUE","COALESCE(st.is_deleted,FALSE)=FALSE"
    ];
    if(fromRegistration){values.push(String(fromRegistration).trim());where.push(`COALESCE(NULLIF(st.registration_number,''),st.registration_no)>=$${values.length}`);}
    if(toRegistration){values.push(String(toRegistration).trim());where.push(`COALESCE(NULLIF(st.registration_number,''),st.registration_no)<=$${values.length}`);}
    const result=await pool.query(`SELECT st.student_id AS id,
      COALESCE(NULLIF(st.registration_number,''),NULLIF(st.registration_no,''),st.student_code) AS registration_number,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS student_name,
      CASE WHEN COALESCE(st.is_active,TRUE) THEN 'Active' ELSE 'Inactive' END AS student_status,
      a.mentor_id AS current_mentor_id,
      TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS current_mentor
      FROM students st
      LEFT JOIN student_mentor_allotments a ON a.student_id=st.student_id AND a.academic_year_id=$1 AND a.status='Active'
      LEFT JOIN employees e ON e.employee_id=a.mentor_id
      WHERE ${where.join(' AND ')}
      ORDER BY COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code),st.student_id`,values);
    res.json({ok:true,students:result.rows});
  }catch(error){console.error('Student mentor load error:',error.message);res.status(500).json({ok:false,message:'Unable to load students for mentor allotment.'});}
});

app.post('/api/student-mentor-allotments', authenticate, async (req,res)=>{
  const client=await pool.connect();
  try{
    const data=req.body||{},studentIds=[...new Set((data.studentIds||[]).map(Number).filter(Boolean))];
    if(!data.academicYearId||!data.programmeId||!data.batchId||!data.semesterId||!data.sectionId||!data.mentorId||!studentIds.length)
      throw new Error('Select the academic details, mentor, and at least one student.');
    await client.query('BEGIN');
    const mentoringMentor=(await client.query(`INSERT INTO mentoring.mentors(employee_id,department_id)
      SELECT employee_id,department_id FROM employees WHERE employee_id=$1
      ON CONFLICT(employee_id) DO UPDATE SET department_id=EXCLUDED.department_id
      RETURNING mentor_id`,[Number(data.mentorId)])).rows[0];
    if(!mentoringMentor)throw new Error('Selected mentor employee was not found.');
    const students=await client.query(`SELECT student_id,institution_id FROM students
      WHERE student_id=ANY($1::bigint[]) AND programme_id=$2 AND batch_id=$3 AND semester_id=$4 AND section_id=$5
        AND COALESCE(is_active,TRUE)=TRUE AND COALESCE(is_deleted,FALSE)=FALSE FOR UPDATE`,
      [studentIds,Number(data.programmeId),Number(data.batchId),Number(data.semesterId),Number(data.sectionId)]);
    if(students.rowCount!==studentIds.length)throw new Error('One or more selected students no longer match the selected class.');
    for(const student of students.rows){
      await client.query(`UPDATE student_mentor_allotments SET status='Transferred',allotment_status='Transferred',
        is_active=FALSE,effective_to=CURRENT_DATE,updated_by=$1,updated_at=NOW()
        WHERE academic_year_id=$2 AND student_id=$3 AND status='Active'`,[req.auth.userId,Number(data.academicYearId),student.student_id]);
      await client.query(`INSERT INTO student_mentor_allotments
        (institute_id,academic_year_id,programme_id,programme_batch_id,semester_id,programme_section_id,
         student_id,mentor_id,allotted_date,effective_from,effective_to,status,remarks,
         is_primary,allotment_status,is_active,created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_DATE,CURRENT_DATE,NULL,'Active',$9,TRUE,'Active',TRUE,$10)`,
        [student.institution_id,Number(data.academicYearId),Number(data.programmeId),Number(data.batchId),Number(data.semesterId),
         Number(data.sectionId),student.student_id,Number(data.mentorId),data.remarks?.trim()||null,req.auth.userId]);
      await client.query(`UPDATE mentoring.student_mentor_allotments SET allotment_status='Changed',
        allotted_to=CURRENT_DATE,updated_by=$1,updated_at=NOW()
        WHERE academic_year_id=$2 AND student_id=$3 AND allotment_status='Active'`,
        [req.auth.userId,Number(data.academicYearId),student.student_id]);
      await client.query(`INSERT INTO mentoring.student_mentor_allotments
        (academic_year_id,student_id,mentor_id,programme_id,programme_batch_id,semester_id,
         programme_section_id,allotted_from,allotment_status,created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_DATE,'Active',$8)`,
        [Number(data.academicYearId),student.student_id,mentoringMentor.mentor_id,Number(data.programmeId),
         Number(data.batchId),Number(data.semesterId),Number(data.sectionId),req.auth.userId]);
    }
    await client.query('COMMIT');
    res.status(201).json({ok:true,count:students.rowCount,message:`Mentor assigned to ${students.rowCount} student${students.rowCount===1?'':'s'} successfully.`});
  }catch(error){await client.query('ROLLBACK');console.error('Student mentor assignment error:',error.message);
    res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'An active mentor allotment already exists for a selected student.':error.message});}
  finally{client.release();}
});

app.get('/api/mentoring-existing-student-options', authenticate, async (_req,res)=>{
  try{
    const [years,programmes,batches,semesters,sections]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(NULLIF(academic_year_name,''),year_label) AS name,is_current
        FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT programme_id AS id,programme_name AS name,programme_code AS code FROM programmes ORDER BY programme_name`),
      pool.query(`SELECT batch_id AS id,programme_id,batch_name AS name FROM admission_batches ORDER BY admission_year DESC,batch_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name FROM semesters ORDER BY semester_number`),
      pool.query(`SELECT section_id AS id,batch_id,semester_id,section_name AS name FROM sections ORDER BY section_name`)
    ]);
    res.json({ok:true,academicYears:years.rows,programmes:programmes.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows});
  }catch(error){console.error('Mentoring existing options error:',error.message);res.status(500).json({ok:false,message:'Unable to load mentoring filters.'});}
});

app.get('/api/mentoring-existing-students', authenticate, async (req,res)=>{
  try{
    const values=[],where=["sma.allotment_status='Active'"];
    const add=(value,column)=>{if(value){values.push(value);where.push(`${column}=$${values.length}`);}};
    add(req.query.academicYearId,'sma.academic_year_id');add(req.query.programmeId,'sma.programme_id');
    add(req.query.batchId,'sma.programme_batch_id');add(req.query.semesterId,'sma.semester_id');
    add(req.query.sectionId,'sma.programme_section_id');
    if(req.query.studentStatus){values.push(String(req.query.studentStatus).toLowerCase()==='active');where.push(`COALESCE(st.is_active,TRUE)=$${values.length}`);}
    if(req.query.search){values.push(`%${String(req.query.search).trim()}%`);where.push(`(
      COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) ILIKE $${values.length}
      OR TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) ILIKE $${values.length}
      OR COALESCE(NULLIF(st.mobile_number,''),st.mobile) ILIKE $${values.length})`);}
    const result=await pool.query(`SELECT sma.mentor_allotment_id,sma.academic_year_id,sma.mentor_id,
      st.student_id AS id,COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) AS registration_number,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS student_name,
      COALESCE(NULLIF(st.mobile_number,''),st.mobile) AS student_contact,
      COALESCE(st.student_profile_details->>'fatherName','') AS father_name,
      COALESCE(st.student_profile_details->>'fatherMobile',st.student_profile_details->>'guardianMobile','') AS guardian_contact,
      p.programme_name,se.semester_name,sec.section_name,
      TRIM(CONCAT_WS(' ',em.first_name,em.middle_name,em.last_name)) AS mentor_name,
      COUNT(DISTINCT sc.student_counselling_id)::int AS total_counselling,
      COUNT(DISTINCT sc.student_counselling_id) FILTER(WHERE sc.discussion_date>=CURRENT_DATE-15)::int AS counselling_last_15_days,
      MAX(sc.discussion_date) AS last_counselled,
      COUNT(DISTINCT pi.parent_interaction_id)::int AS total_guardian_discussions,
      COUNT(DISTINCT pi.parent_interaction_id) FILTER(WHERE pi.interaction_date>=CURRENT_DATE-30)::int AS guardian_last_30_days,
      MAX(pi.interaction_date) AS last_guardian_contact,
      CASE WHEN COALESCE(st.is_active,TRUE) THEN 'Active' ELSE 'Inactive' END AS student_status
      FROM mentoring.student_mentor_allotments sma JOIN students st ON st.student_id=sma.student_id
      JOIN mentoring.mentors m ON m.mentor_id=sma.mentor_id JOIN employees em ON em.employee_id=m.employee_id
      LEFT JOIN programmes p ON p.programme_id=sma.programme_id LEFT JOIN semesters se ON se.semester_id=sma.semester_id
      LEFT JOIN sections sec ON sec.section_id=sma.programme_section_id
      LEFT JOIN mentoring.student_counsellings sc ON sc.student_id=st.student_id AND sc.mentor_id=sma.mentor_id
      LEFT JOIN mentoring.parent_interactions pi ON pi.student_id=st.student_id AND pi.mentor_id=sma.mentor_id
      WHERE ${where.join(' AND ')}
      GROUP BY sma.mentor_allotment_id,st.student_id,p.programme_name,se.semester_name,sec.section_name,
        em.first_name,em.middle_name,em.last_name
      ORDER BY registration_number`,values);
    res.json({ok:true,students:result.rows});
  }catch(error){console.error('Mentoring existing students error:',error.message);res.status(500).json({ok:false,message:'Unable to load students under mentorship.'});}
});

app.post('/api/student-counsellings', authenticate, async (req,res)=>{
  try{
    const data=req.body||{};
    if(!data.academicYearId||!data.studentId||!data.mentorId||!data.discussionDate||!data.communicationMode||!data.purpose||!data.detailedDiscussion?.trim())
      return res.status(400).json({ok:false,message:'Complete all required counselling fields.'});
    if(data.followUpRequired&&!data.nextFollowUpDate)return res.status(400).json({ok:false,message:'Next follow-up date is required.'});
    const active=await pool.query(`SELECT 1 FROM mentoring.student_mentor_allotments
      WHERE academic_year_id=$1 AND student_id=$2 AND mentor_id=$3 AND allotment_status='Active'`,
      [Number(data.academicYearId),Number(data.studentId),Number(data.mentorId)]);
    if(!active.rowCount)return res.status(409).json({ok:false,message:'The student is not actively allotted to this mentor.'});
    await pool.query(`INSERT INTO mentoring.student_counsellings
      (academic_year_id,student_id,mentor_id,discussion_date,communication_mode,purpose,detailed_discussion,
       mentor_remarks,follow_up_required,next_follow_up_date,counselling_status,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [Number(data.academicYearId),Number(data.studentId),Number(data.mentorId),data.discussionDate,data.communicationMode,
       data.purpose,data.detailedDiscussion.trim(),data.mentorRemarks?.trim()||null,Boolean(data.followUpRequired),
       data.followUpRequired?data.nextFollowUpDate:null,data.status||'Open',req.auth.userId]);
    res.status(201).json({ok:true,message:'Student counselling discussion saved successfully.'});
  }catch(error){console.error('Student counselling save error:',error.message);res.status(400).json({ok:false,message:error.message});}
});

app.get('/api/counselling-reviews/options',authenticate,async(_req,res)=>{
  try{
    const [years,modes,purposes,students]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(NULLIF(academic_year_name,''),year_label) AS name,is_current
        FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT communication_mode_id AS id,mode_name AS name FROM mentoring.communication_modes WHERE is_active ORDER BY communication_mode_id`),
      pool.query(`SELECT counselling_purpose_id AS id,purpose_name AS name FROM mentoring.counselling_purposes WHERE is_active ORDER BY counselling_purpose_id`),
      pool.query(`SELECT sma.academic_year_id,st.student_id AS id,
        COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) AS registration_no,
        TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS name,
        sma.mentor_id,sma.programme_id,sma.programme_batch_id,sma.semester_id,sma.programme_section_id,
        p.programme_name,ab.batch_name,se.semester_name,sec.section_name,
        TRIM(CONCAT_WS(' ',me.first_name,me.middle_name,me.last_name)) AS mentor_name,
        reviewers.reviewer_1_name,reviewers.reviewer_2_name,reviewers.chief_reviewer_name
        FROM mentoring.student_mentor_allotments sma JOIN students st ON st.student_id=sma.student_id
        JOIN mentoring.mentors m ON m.mentor_id=sma.mentor_id JOIN employees me ON me.employee_id=m.employee_id
        LEFT JOIN LATERAL (
          SELECT MAX(TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name))) FILTER(WHERE d.reviewer_role='Reviewer 1') AS reviewer_1_name,
            MAX(TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name))) FILTER(WHERE d.reviewer_role='Reviewer 2') AS reviewer_2_name,
            MAX(TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name))) FILTER(WHERE d.reviewer_role='Chief Reviewer') AS chief_reviewer_name
          FROM mentoring.mentor_reviewer_allotments a
          JOIN mentoring.mentor_reviewer_allotment_details d ON d.mentor_reviewer_allotment_id=a.mentor_reviewer_allotment_id AND d.is_active=TRUE
          JOIN employees re ON re.employee_id=d.reviewer_id
          WHERE a.academic_year_id=sma.academic_year_id AND a.mentor_id=m.employee_id AND a.allotment_status='Active'
        ) reviewers ON TRUE
        LEFT JOIN programmes p ON p.programme_id=sma.programme_id
        LEFT JOIN admission_batches ab ON ab.batch_id=sma.programme_batch_id
        LEFT JOIN semesters se ON se.semester_id=sma.semester_id
        LEFT JOIN sections sec ON sec.section_id=sma.programme_section_id
        WHERE sma.allotment_status='Active' AND COALESCE(st.is_active,TRUE)=TRUE ORDER BY name`)
    ]);
    res.json({ok:true,academicYears:years.rows,modes:modes.rows,purposes:purposes.rows,students:students.rows});
  }catch(error){console.error('Counselling review options error:',error.message);res.status(500).json({ok:false,message:'Unable to load counselling options.'});}
});

app.get('/api/counselling-reviews',authenticate,async(req,res)=>{
  try{
    const values=[],where=['TRUE'];
    const add=(value,column)=>{if(value){values.push(value);where.push(`${column}=$${values.length}`);}};
    add(req.query.academicYearId,'sc.academic_year_id');add(req.query.modeId,'sc.communication_mode_id');
    add(req.query.purposeId,'sc.counselling_purpose_id');add(req.query.mentorId,'sc.mentor_id');
    if(req.query.date){values.push(req.query.date);where.push(`sc.discussion_date=$${values.length}`);}
    if(req.query.registration){values.push(`%${String(req.query.registration).trim()}%`);where.push(`COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) ILIKE $${values.length}`);}
    if(req.query.student){values.push(`%${String(req.query.student).trim()}%`);where.push(`TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) ILIKE $${values.length}`);}
    const result=await pool.query(`SELECT sc.student_counselling_id AS id,sc.*,v.communication_mode,v.purpose,
      v.reviewer_1_remarks,v.reviewer_2_remarks,v.chief_reviewer_remarks,
      COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) AS registration_no,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS student_name,
      TRIM(CONCAT_WS(' ',me.first_name,me.middle_name,me.last_name)) AS mentor_name,
      p.programme_name,ab.batch_name,se.semester_name,sec.section_name
      FROM mentoring.student_counsellings sc
      JOIN mentoring.vw_student_counsellings_reviews v ON v.student_counselling_id=sc.student_counselling_id
      JOIN students st ON st.student_id=sc.student_id
      JOIN mentoring.mentors m ON m.mentor_id=sc.mentor_id JOIN employees me ON me.employee_id=m.employee_id
      LEFT JOIN programmes p ON p.programme_id=sc.programme_id LEFT JOIN admission_batches ab ON ab.batch_id=sc.programme_batch_id
      LEFT JOIN semesters se ON se.semester_id=sc.semester_id LEFT JOIN sections sec ON sec.section_id=sc.programme_section_id
      WHERE ${where.join(' AND ')} ORDER BY sc.discussion_date DESC,sc.student_counselling_id DESC`,values);
    res.json({ok:true,counsellings:result.rows});
  }catch(error){console.error('Counselling review list error:',error.message);res.status(500).json({ok:false,message:'Unable to load student counsellings and reviews.'});}
});

app.get('/api/counselling-reviews/:id',authenticate,async(req,res)=>{
  try{
    const counselling=(await pool.query(`SELECT sc.*,v.communication_mode,v.purpose,
      v.reviewer_1_remarks,v.reviewer_2_remarks,v.chief_reviewer_remarks,
      COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) AS registration_no,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS student_name,
      TRIM(CONCAT_WS(' ',me.first_name,me.middle_name,me.last_name)) AS mentor_name,
      p.programme_name,ab.batch_name,se.semester_name,sec.section_name
      FROM mentoring.student_counsellings sc JOIN mentoring.vw_student_counsellings_reviews v USING(student_counselling_id)
      JOIN students st ON st.student_id=sc.student_id JOIN mentoring.mentors m ON m.mentor_id=sc.mentor_id
      JOIN employees me ON me.employee_id=m.employee_id LEFT JOIN programmes p ON p.programme_id=sc.programme_id
      LEFT JOIN admission_batches ab ON ab.batch_id=sc.programme_batch_id LEFT JOIN semesters se ON se.semester_id=sc.semester_id
      LEFT JOIN sections sec ON sec.section_id=sc.programme_section_id WHERE sc.student_counselling_id=$1`,[Number(req.params.id)])).rows[0];
    if(!counselling)return res.status(404).json({ok:false,message:'Student counselling not found.'});
    const reviews=(await pool.query(`SELECT crr.*,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS reviewer_name
      FROM mentoring.counselling_reviewer_remarks crr JOIN employees e ON e.employee_id=crr.reviewer_id
      WHERE student_counselling_id=$1 ORDER BY CASE reviewer_level WHEN 'Reviewer 1' THEN 1 WHEN 'Reviewer 2' THEN 2 ELSE 3 END`,[Number(req.params.id)])).rows;
    res.json({ok:true,counselling,reviews});
  }catch(error){console.error('Counselling detail error:',error.message);res.status(500).json({ok:false,message:'Unable to load counselling details.'});}
});

async function saveCounselling(req,res,id=null){
  const data=req.body||{};
  if(!data.academicYearId||!data.studentId||!data.discussionDate||!data.communicationModeId||!data.purposeId||!data.detailedDiscussion?.trim())
    return res.status(400).json({ok:false,message:'Complete all required counselling fields.'});
  try{
    const student=(await pool.query(`SELECT sma.* FROM mentoring.student_mentor_allotments sma
      WHERE sma.academic_year_id=$1 AND sma.student_id=$2 AND sma.allotment_status='Active' LIMIT 1`,
      [Number(data.academicYearId),Number(data.studentId)])).rows[0];
    if(!student)return res.status(409).json({ok:false,message:'The student has no active mentor allotment for this academic year.'});
    const mode=(await pool.query('SELECT mode_name FROM mentoring.communication_modes WHERE communication_mode_id=$1 AND is_active',[Number(data.communicationModeId)])).rows[0];
    const purpose=(await pool.query('SELECT purpose_name FROM mentoring.counselling_purposes WHERE counselling_purpose_id=$1 AND is_active',[Number(data.purposeId)])).rows[0];
    if(!mode||!purpose)return res.status(400).json({ok:false,message:'Select a valid communication mode and purpose.'});
    const params=[Number(data.academicYearId),Number(data.studentId),student.mentor_id,student.programme_id,student.programme_batch_id,
      student.semester_id,student.programme_section_id,data.discussionDate,Number(data.communicationModeId),mode.mode_name,
      Number(data.purposeId),purpose.purpose_name,data.detailedDiscussion.trim(),data.mentorRemarks?.trim()||null,
      Boolean(data.followUpRequired),data.followUpRequired&&data.nextFollowUpDate?data.nextFollowUpDate:null,
      data.counsellingStatus||'Open',req.auth.userId];
    let result;
    if(id)result=await pool.query(`UPDATE mentoring.student_counsellings SET academic_year_id=$1,student_id=$2,mentor_id=$3,
      programme_id=$4,programme_batch_id=$5,semester_id=$6,programme_section_id=$7,discussion_date=$8,
      communication_mode_id=$9,communication_mode=$10,counselling_purpose_id=$11,purpose=$12,detailed_discussion=$13,
      mentor_remarks=$14,follow_up_required=$15,next_follow_up_date=$16,counselling_status=$17,updated_by=$18,updated_at=NOW()
      WHERE student_counselling_id=$19 RETURNING student_counselling_id`,[...params,id]);
    else result=await pool.query(`INSERT INTO mentoring.student_counsellings
      (academic_year_id,student_id,mentor_id,programme_id,programme_batch_id,semester_id,programme_section_id,
       discussion_date,communication_mode_id,communication_mode,counselling_purpose_id,purpose,detailed_discussion,
       mentor_remarks,follow_up_required,next_follow_up_date,counselling_status,created_by)
      VALUES (${params.map((_,i)=>`$${i+1}`).join(',')}) RETURNING student_counselling_id`,params);
    if(id&&!result.rowCount)return res.status(404).json({ok:false,message:'Student counselling not found.'});
    res.status(id?200:201).json({ok:true,id:result.rows[0].student_counselling_id,message:`Student counselling ${id?'updated':'created'} successfully.`});
  }catch(error){console.error('Counselling save error:',error.message);res.status(error.code==='23514'?400:500).json({ok:false,message:error.code==='23514'?error.message:'Unable to save student counselling.'});}
}
app.post('/api/counselling-reviews',authenticate,(req,res)=>saveCounselling(req,res));
app.put('/api/counselling-reviews/:id',authenticate,(req,res)=>saveCounselling(req,res,Number(req.params.id)));

const reviewerAdminRoles=new Set(['ADMIN','SUPER_ADMIN','INSTITUTE_ADMIN']);
async function authenticatedEmployeeId(req,client=pool){
  if(reviewerAdminRoles.has(req.auth.role))return null;
  const row=(await client.query(`SELECT employee_id FROM employees WHERE user_id=$1 LIMIT 1`,[req.auth.userId])).rows[0];
  return row?.employee_id||0;
}

app.post('/api/counselling-reviews/:id/reviewer-remarks',authenticate,async(req,res)=>{
  const data=req.body||{},level=data.reviewerLevel;
  if(!['Reviewer 1','Reviewer 2','Chief Reviewer'].includes(level)||!data.reviewerRemarks?.trim())
    return res.status(400).json({ok:false,message:'Reviewer level and remarks are required.'});
  try{
    const context=(await pool.query(`SELECT sc.student_counselling_id,mrd.reviewer_id
      FROM mentoring.student_counsellings sc JOIN mentoring.mentors m ON m.mentor_id=sc.mentor_id
      JOIN mentoring.mentor_reviewer_allotments mra ON mra.academic_year_id=sc.academic_year_id
        AND mra.mentor_id=m.employee_id AND mra.allotment_status='Active'
      JOIN mentoring.mentor_reviewer_allotment_details mrd ON mrd.mentor_reviewer_allotment_id=mra.mentor_reviewer_allotment_id
        AND mrd.reviewer_role=$2 AND mrd.is_active=TRUE WHERE sc.student_counselling_id=$1 LIMIT 1`,
      [Number(req.params.id),level])).rows[0];
    if(!context)return res.status(409).json({ok:false,message:`No active ${level} allotment exists for this student's mentor.`});
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null&&Number(employeeId)!==Number(context.reviewer_id))
      return res.status(403).json({ok:false,message:`Only the employee assigned as ${level} can submit these remarks.`});
    await pool.query(`INSERT INTO mentoring.counselling_reviewer_remarks
      (student_counselling_id,reviewer_id,reviewer_level,review_date,reviewer_remarks,recommendation,
       follow_up_required,next_review_date,review_status,created_by)
      VALUES ($1,$2,$3,CURRENT_DATE,$4,$5,$6,$7,$8,$9)
      ON CONFLICT(student_counselling_id,reviewer_level) DO UPDATE SET reviewer_id=EXCLUDED.reviewer_id,
       review_date=CURRENT_DATE,reviewer_remarks=EXCLUDED.reviewer_remarks,recommendation=EXCLUDED.recommendation,
       follow_up_required=EXCLUDED.follow_up_required,next_review_date=EXCLUDED.next_review_date,
       review_status=EXCLUDED.review_status,updated_by=EXCLUDED.created_by,updated_at=NOW()`,
      [Number(req.params.id),context.reviewer_id,level,data.reviewerRemarks.trim(),data.recommendation?.trim()||null,
       Boolean(data.followUpRequired),data.followUpRequired&&data.nextReviewDate?data.nextReviewDate:null,
       data.reviewStatus||'Submitted',req.auth.userId]);
    res.status(201).json({ok:true,message:`${level} remarks saved successfully.`});
  }catch(error){console.error('Counselling reviewer save error:',error.message);res.status(error.code==='23514'?400:500).json({ok:false,message:error.message});}
});

app.post('/api/parent-interactions', authenticate, async (req,res)=>{
  try{
    const data=req.body||{};
    if(!data.studentId||!data.mentorId||!data.interactionDate||!data.communicationMode||!data.discussionDetails?.trim())
      return res.status(400).json({ok:false,message:'Complete all required parent discussion fields.'});
    await pool.query(`INSERT INTO mentoring.parent_interactions
      (student_id,mentor_id,interaction_date,parent_name,relationship,parent_contact_number,communication_mode,
       discussion_details,parent_commitment,action_required,next_contact_date,interaction_status,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [Number(data.studentId),Number(data.mentorId),data.interactionDate,data.parentName?.trim()||null,data.relationship||null,
       data.contactNumber?.trim()||null,data.communicationMode,data.discussionDetails.trim(),data.parentCommitment?.trim()||null,
       data.actionRequired?.trim()||null,data.nextContactDate||null,data.status||'Completed',req.auth.userId]);
    res.status(201).json({ok:true,message:'Parent or guardian discussion saved successfully.'});
  }catch(error){console.error('Parent interaction save error:',error.message);res.status(400).json({ok:false,message:error.message});}
});

app.get('/api/mentoring-discussion-history/:studentId', authenticate, async (req,res)=>{
  try{
    const studentId=Number(req.params.studentId),mentorId=Number(req.query.mentorId);
    const [student,counsellings,parents]=await Promise.all([
      pool.query(`SELECT student_id AS id,COALESCE(NULLIF(registration_number,''),registration_no,student_code) AS registration_number,
        TRIM(CONCAT_WS(' ',first_name,middle_name,last_name)) AS student_name FROM students WHERE student_id=$1`,[studentId]),
      pool.query(`SELECT student_counselling_id AS id,discussion_date AS date,'Student' AS discussion_with,
        communication_mode AS mode,purpose,detailed_discussion AS details,next_follow_up_date AS next_date,
        counselling_status AS status FROM mentoring.student_counsellings
        WHERE student_id=$1 AND mentor_id=$2 ORDER BY discussion_date DESC,student_counselling_id DESC`,[studentId,mentorId]),
      pool.query(`SELECT parent_interaction_id AS id,interaction_date AS date,
        COALESCE(NULLIF(parent_name,''),'Parent / Guardian') AS discussion_with,communication_mode AS mode,
        relationship AS purpose,discussion_details AS details,next_contact_date AS next_date,
        interaction_status AS status FROM mentoring.parent_interactions
        WHERE student_id=$1 AND mentor_id=$2 ORDER BY interaction_date DESC,parent_interaction_id DESC`,[studentId,mentorId])
    ]);
    if(!student.rowCount)return res.status(404).json({ok:false,message:'Student not found.'});
    res.json({ok:true,student:student.rows[0],counsellings:counsellings.rows,parentInteractions:parents.rows,reviewerRemarks:[],followUps:counsellings.rows.filter(item=>item.next_date)});
  }catch(error){console.error('Mentoring history error:',error.message);res.status(500).json({ok:false,message:'Unable to load discussion history.'});}
});

app.get('/api/first-reviewer-remarks/options', authenticate, async (_req,res)=>{
  try{
    const [years,programmes,semesters,sections,students]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(NULLIF(academic_year_name,''),year_label) AS name,is_current
        FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT programme_id AS id,programme_name AS name FROM programmes
        WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY programme_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name FROM semesters
        WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY semester_number`),
      pool.query(`SELECT section_id AS id,semester_id,section_name AS name FROM sections
        WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY section_name`),
      pool.query(`SELECT DISTINCT sma.academic_year_id,st.student_id AS id,
        COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) AS registration_no,
        TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS name,
        sma.programme_id,sma.semester_id,sma.programme_section_id AS section_id,
        p.programme_name,se.semester_name,sec.section_name,sma.mentor_id,
        TRIM(CONCAT_WS(' ',me.first_name,me.middle_name,me.last_name)) AS mentor_name,
        mra.mentor_reviewer_allotment_id,mrd.reviewer_id,
        TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name)) AS reviewer_name
        FROM mentoring.student_mentor_allotments sma
        JOIN students st ON st.student_id=sma.student_id
        JOIN mentoring.mentors m ON m.mentor_id=sma.mentor_id
        JOIN employees me ON me.employee_id=m.employee_id
        LEFT JOIN programmes p ON p.programme_id=sma.programme_id
        LEFT JOIN semesters se ON se.semester_id=sma.semester_id
        LEFT JOIN sections sec ON sec.section_id=sma.programme_section_id
        JOIN mentoring.mentor_reviewer_allotments mra ON mra.academic_year_id=sma.academic_year_id
          AND mra.mentor_id=m.employee_id AND mra.allotment_status='Active'
        JOIN mentoring.mentor_reviewer_allotment_details mrd
          ON mrd.mentor_reviewer_allotment_id=mra.mentor_reviewer_allotment_id
          AND mrd.reviewer_role='Reviewer 1' AND mrd.is_active=TRUE
        JOIN employees re ON re.employee_id=mrd.reviewer_id
        WHERE sma.allotment_status='Active' AND COALESCE(st.is_active,TRUE)=TRUE
        ORDER BY name`)
    ]);
    res.json({ok:true,academicYears:years.rows,programmes:programmes.rows,semesters:semesters.rows,
      sections:sections.rows,students:students.rows});
  }catch(error){console.error('First reviewer options error:',error.message);res.status(500).json({ok:false,message:'Unable to load first reviewer remark options.'});}
});

app.get('/api/first-reviewer-remarks', authenticate, async (req,res)=>{
  try{
    const values=[],where=['TRUE'];
    const add=(value,column)=>{if(value){values.push(value);where.push(`${column}=$${values.length}`);}};
    add(req.query.academicYearId,'f.academic_year_id');add(req.query.programmeId,'sma.programme_id');
    add(req.query.semesterId,'sma.semester_id');add(req.query.sectionId,'sma.programme_section_id');
    add(req.query.status,'f.review_status');
    for(const [value,column] of [[req.query.studentId,'f.student_id'],[req.query.reviewerId,'f.reviewer_id'],
      [req.query.grade,'f.grading_to_mentor']])add(value,column);
    if(req.query.information){values.push(`%${String(req.query.information).trim()}%`);where.push(`COALESCE(f.information_entered,'') ILIKE $${values.length}`);}
    if(req.query.remarks){values.push(`%${String(req.query.remarks).trim()}%`);where.push(`COALESCE(f.first_reviewer_remarks,'') ILIKE $${values.length}`);}
    if(req.query.suggestion){values.push(`%${String(req.query.suggestion).trim()}%`);where.push(`COALESCE(f.suggestion_to_mentor,'') ILIKE $${values.length}`);}
    const result=await pool.query(`SELECT f.first_reviewer_remark_id AS id,f.*,v.registration_no,v.student_name,
      v.mentor_name,v.first_reviewer_name,p.programme_name,se.semester_name,sec.section_name
      FROM mentoring.first_reviewer_remarks f
      JOIN mentoring.vw_first_reviewer_remarks v ON v.first_reviewer_remark_id=f.first_reviewer_remark_id
      LEFT JOIN mentoring.student_mentor_allotments sma ON sma.academic_year_id=f.academic_year_id
        AND sma.student_id=f.student_id AND sma.mentor_id=f.mentor_id AND sma.allotment_status='Active'
      LEFT JOIN programmes p ON p.programme_id=sma.programme_id
      LEFT JOIN semesters se ON se.semester_id=sma.semester_id
      LEFT JOIN sections sec ON sec.section_id=sma.programme_section_id
      WHERE ${where.join(' AND ')}
      ORDER BY f.review_date DESC,f.first_reviewer_remark_id DESC`,values);
    res.json({ok:true,remarks:result.rows});
  }catch(error){console.error('First reviewer list error:',error.message);res.status(500).json({ok:false,message:'Unable to load first reviewer remarks.'});}
});

async function saveFirstReviewerRemark(req,res,id=null){
  const data=req.body||{};
  if(!data.academicYearId||!data.studentId||!data.firstReviewerRemarks?.trim())
    return res.status(400).json({ok:false,message:'Academic year, student, and first reviewer remarks are required.'});
  try{
    const context=(await pool.query(`SELECT sma.mentor_id,mra.mentor_reviewer_allotment_id,mrd.reviewer_id
      FROM mentoring.student_mentor_allotments sma
      JOIN mentoring.mentors m ON m.mentor_id=sma.mentor_id
      JOIN mentoring.mentor_reviewer_allotments mra ON mra.academic_year_id=sma.academic_year_id
        AND mra.mentor_id=m.employee_id AND mra.allotment_status='Active'
      JOIN mentoring.mentor_reviewer_allotment_details mrd
        ON mrd.mentor_reviewer_allotment_id=mra.mentor_reviewer_allotment_id
        AND mrd.reviewer_role='Reviewer 1' AND mrd.is_active=TRUE
      WHERE sma.academic_year_id=$1 AND sma.student_id=$2 AND sma.allotment_status='Active' LIMIT 1`,
      [Number(data.academicYearId),Number(data.studentId)])).rows[0];
    if(!context)return res.status(409).json({ok:false,message:'No active mentor and first-reviewer allotment exists for this student.'});
    const employeeId=await authenticatedEmployeeId(req);
    if(employeeId!==null&&Number(employeeId)!==Number(context.reviewer_id))
      return res.status(403).json({ok:false,message:'Only the employee assigned as First Reviewer can save these remarks.'});
    const params=[Number(data.academicYearId),Number(data.studentId),context.mentor_id,context.reviewer_id,
      context.mentor_reviewer_allotment_id,data.reviewDate||new Date().toISOString().slice(0,10),
      data.informationEntered?.trim()||null,data.firstReviewerRemarks.trim(),data.gradingToMentor||null,
      data.suggestionToMentor?.trim()||null,Boolean(data.followUpRequired),
      data.followUpRequired&&data.nextReviewDate?data.nextReviewDate:null,data.reviewStatus||'Draft',req.auth.userId];
    let result;
    if(id)result=await pool.query(`UPDATE mentoring.first_reviewer_remarks SET academic_year_id=$1,student_id=$2,
      mentor_id=$3,reviewer_id=$4,mentor_reviewer_allotment_id=$5,review_date=$6,information_entered=$7,
      first_reviewer_remarks=$8,grading_to_mentor=$9,suggestion_to_mentor=$10,follow_up_required=$11,
      next_review_date=$12,review_status=$13,updated_by=$14,updated_at=NOW()
      WHERE first_reviewer_remark_id=$15 RETURNING first_reviewer_remark_id`,[...params,id]);
    else result=await pool.query(`INSERT INTO mentoring.first_reviewer_remarks
      (academic_year_id,student_id,mentor_id,reviewer_id,mentor_reviewer_allotment_id,review_date,
       information_entered,first_reviewer_remarks,grading_to_mentor,suggestion_to_mentor,
       follow_up_required,next_review_date,review_status,created_by)
      VALUES (${params.map((_,index)=>`$${index+1}`).join(',')}) RETURNING first_reviewer_remark_id`,params);
    if(id&&!result.rowCount)return res.status(404).json({ok:false,message:'First reviewer remark not found.'});
    res.status(id?200:201).json({ok:true,id:result.rows[0].first_reviewer_remark_id,
      message:`First reviewer remarks ${id?'updated':'saved'} successfully.`});
  }catch(error){console.error('First reviewer save error:',error.message);
    const conflict=error.code==='23505',invalid=error.code==='23514'||error.code==='23503';
    res.status(conflict?409:invalid?400:500).json({ok:false,message:conflict?'An active first-reviewer remark already exists for this student and reviewer.':invalid?error.message:'Unable to save first reviewer remarks.'});}
}
app.post('/api/first-reviewer-remarks',authenticate,(req,res)=>saveFirstReviewerRemark(req,res));
app.put('/api/first-reviewer-remarks/:id',authenticate,(req,res)=>saveFirstReviewerRemark(req,res,Number(req.params.id)));

app.get('/api/prospective-mentor-eligibility',authenticate,async(_req,res)=>{
  try{
    const [employees,departments,designations]=await Promise.all([
      pool.query(`SELECT e.employee_id AS id,COALESCE(NULLIF(e.employee_category,''),d.category,'Staff') AS category,
        e.department_id,e.designation_id,dp.department_name,d.designation_name,
        TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS employee_name,
        COALESCE(eme.is_mentor_for_new_students,FALSE) AS is_mentor,
        COALESCE(eme.maximum_students,30) AS maximum_students,eme.effective_from,eme.effective_to,
        COALESCE(eme.eligibility_status,'Active') AS eligibility_status,COALESCE(eme.remarks,'') AS remarks
        FROM employees e LEFT JOIN departments dp ON dp.department_id=e.department_id
        LEFT JOIN designations d ON d.designation_id=e.designation_id
        LEFT JOIN mentoring.employee_mentor_eligibility eme ON eme.employee_id=e.employee_id
        WHERE UPPER(COALESCE(e.status,'ACTIVE'))='ACTIVE' ORDER BY employee_name`),
      pool.query(`SELECT department_id AS id,department_name AS name FROM departments WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY name`),
      pool.query(`SELECT designation_id AS id,designation_name AS name FROM designations WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY name`)
    ]);
    res.json({ok:true,employees:employees.rows,departments:departments.rows,designations:designations.rows});
  }catch(error){console.error('Prospective mentor eligibility list error:',error.message);res.status(500).json({ok:false,message:'Unable to load employee mentor eligibility.'});}
});

app.put('/api/prospective-mentor-eligibility/:employeeId',authenticate,async(req,res)=>{
  const client=await pool.connect();
  try{
    const employeeId=Number(req.params.employeeId),data=req.body||{};
    if(!Number(data.maximumStudents)||Number(data.maximumStudents)<1)return res.status(400).json({ok:false,message:'Maximum students must be greater than zero.'});
    if(data.effectiveTo&&data.effectiveTo<data.effectiveFrom)return res.status(400).json({ok:false,message:'Effective To cannot be before Effective From.'});
    await client.query('BEGIN');
    const old=(await client.query('SELECT * FROM mentoring.employee_mentor_eligibility WHERE employee_id=$1 FOR UPDATE',[employeeId])).rows[0];
    const saved=(await client.query(`INSERT INTO mentoring.employee_mentor_eligibility
      (employee_id,is_mentor_for_new_students,maximum_students,effective_from,effective_to,eligibility_status,remarks,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT(employee_id) DO UPDATE SET is_mentor_for_new_students=EXCLUDED.is_mentor_for_new_students,
        maximum_students=EXCLUDED.maximum_students,effective_from=EXCLUDED.effective_from,effective_to=EXCLUDED.effective_to,
        eligibility_status=EXCLUDED.eligibility_status,remarks=EXCLUDED.remarks,updated_by=EXCLUDED.created_by,updated_at=NOW()
      RETURNING employee_mentor_eligibility_id`,[employeeId,Boolean(data.isMentor),Number(data.maximumStudents),
      data.effectiveFrom||new Date().toISOString().slice(0,10),data.effectiveTo||null,data.status||'Active',data.remarks?.trim()||null,req.auth.userId])).rows[0];
    await client.query(`INSERT INTO mentoring.employee_mentor_eligibility_history
      (employee_mentor_eligibility_id,old_is_mentor,new_is_mentor,old_maximum_students,new_maximum_students,change_reason,changed_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7)`,[saved.employee_mentor_eligibility_id,old?.is_mentor_for_new_students??null,
      Boolean(data.isMentor),old?.maximum_students??null,Number(data.maximumStudents),data.remarks?.trim()||'Eligibility updated',req.auth.userId]);
    await client.query(`INSERT INTO mentoring.mentors(employee_id,department_id,maximum_students,mentor_status,employee_mentor_eligibility_id)
      SELECT e.employee_id,e.department_id,$2,$3,$4 FROM employees e WHERE e.employee_id=$1
      ON CONFLICT(employee_id) DO UPDATE SET maximum_students=EXCLUDED.maximum_students,
        mentor_status=EXCLUDED.mentor_status,employee_mentor_eligibility_id=EXCLUDED.employee_mentor_eligibility_id`,
      [employeeId,Number(data.maximumStudents),data.isMentor&&data.status==='Active'?'Active':'Inactive',saved.employee_mentor_eligibility_id]);
    await client.query('COMMIT');res.json({ok:true,message:'Mentor eligibility updated successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Prospective mentor eligibility update error:',error.message);res.status(400).json({ok:false,message:error.message});}
  finally{client.release();}
});

app.get('/api/prospective-mentor-assignment-options',authenticate,async(_req,res)=>{
  try{
    const [years,programmes,mentors]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(NULLIF(academic_year_name,''),year_label) AS name,is_current
        FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT programme_id AS id,programme_name AS name,programme_code AS code FROM programmes
        WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY name`),
      pool.query(`SELECT e.employee_id AS id,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,
        eme.maximum_students,COUNT(psma.prospective_student_mentor_allotment_id) FILTER(WHERE psma.allotment_status='Active')::int AS assigned_count
        FROM mentoring.employee_mentor_eligibility eme JOIN employees e ON e.employee_id=eme.employee_id
        LEFT JOIN mentoring.prospective_student_mentor_allotments psma ON psma.employee_id=e.employee_id
        WHERE eme.is_mentor_for_new_students=TRUE AND eme.eligibility_status='Active'
          AND eme.effective_from<=CURRENT_DATE AND (eme.effective_to IS NULL OR eme.effective_to>=CURRENT_DATE)
        GROUP BY e.employee_id,eme.maximum_students ORDER BY name`)
    ]);
    res.json({ok:true,academicYears:years.rows,programmes:programmes.rows,mentors:mentors.rows});
  }catch(error){console.error('Prospective assignment options error:',error.message);res.status(500).json({ok:false,message:'Unable to load prospective mentor assignment options.'});}
});

app.get('/api/prospective-mentor-students',authenticate,async(req,res)=>{
  try{
    if(!req.query.academicYearId||!req.query.programmeId)return res.status(400).json({ok:false,message:'Admission session and programme are required.'});
    const values=[Number(req.query.academicYearId),Number(req.query.programmeId)],where=['ps.academic_year_id=$1','ps.programme_id=$2','ps.is_active=TRUE','ps.is_converted=FALSE'];
    if(req.query.fromEnquiry){values.push(String(req.query.fromEnquiry).trim());where.push(`ps.enquiry_number>=$${values.length}`);}
    if(req.query.toEnquiry){values.push(String(req.query.toEnquiry).trim());where.push(`ps.enquiry_number<=$${values.length}`);}
    const result=await pool.query(`SELECT ps.prospective_student_id AS id,ps.enquiry_number,ps.applicant_name,
      ps.mobile_number,p.programme_name,cmv.value_name AS admission_status,
      current.employee_id AS current_mentor_id,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS current_mentor
      FROM prospective_students ps LEFT JOIN programmes p ON p.programme_id=ps.programme_id
      LEFT JOIN common_master_values cmv ON cmv.master_value_id=ps.admission_status_value_id
      LEFT JOIN mentoring.prospective_student_mentor_allotments current
        ON current.prospective_student_id=ps.prospective_student_id AND current.allotment_status='Active'
      LEFT JOIN employees e ON e.employee_id=current.employee_id
      WHERE ${where.join(' AND ')} ORDER BY ps.enquiry_number`,values);
    res.json({ok:true,students:result.rows});
  }catch(error){console.error('Prospective students load error:',error.message);res.status(500).json({ok:false,message:'Unable to load prospective students.'});}
});

app.post('/api/prospective-mentor-allotments',authenticate,async(req,res)=>{
  const client=await pool.connect();
  try{
    const data=req.body||{},ids=[...new Set((data.studentIds||[]).map(Number).filter(Boolean))];
    if(!data.employeeId||!data.academicYearId||!data.programmeId||!ids.length)
      return res.status(400).json({ok:false,message:'Select the admission session, programme, eligible mentor, and at least one student.'});
    await client.query('BEGIN');
    const eligible=(await client.query(`SELECT maximum_students FROM mentoring.employee_mentor_eligibility
      WHERE employee_id=$1 AND is_mentor_for_new_students=TRUE AND eligibility_status='Active'
        AND effective_from<=CURRENT_DATE AND (effective_to IS NULL OR effective_to>=CURRENT_DATE) FOR UPDATE`,[Number(data.employeeId)])).rows[0];
    if(!eligible)throw new Error('The selected employee is not currently eligible to mentor new students.');
    const validStudents=await client.query(`SELECT prospective_student_id FROM prospective_students
      WHERE prospective_student_id=ANY($1::bigint[]) AND academic_year_id=$2 AND programme_id=$3
        AND is_active=TRUE AND is_converted=FALSE FOR UPDATE`,
      [ids,Number(data.academicYearId),Number(data.programmeId)]);
    if(validStudents.rowCount!==ids.length)throw new Error('One or more selected enquiries no longer match the admission session and programme.');
    const assigned=Number((await client.query(`SELECT COUNT(*) FROM mentoring.prospective_student_mentor_allotments
      WHERE employee_id=$1 AND allotment_status='Active'`,[Number(data.employeeId)])).rows[0].count);
    if(assigned+ids.length>eligible.maximum_students)throw new Error(`This assignment exceeds the mentor limit of ${eligible.maximum_students} students.`);
    await client.query(`UPDATE mentoring.prospective_student_mentor_allotments SET allotment_status='Changed',
      allotted_to=CURRENT_DATE,change_reason='Reassigned through prospective student allotment',updated_by=$1,updated_at=NOW()
      WHERE prospective_student_id=ANY($2::bigint[]) AND allotment_status='Active'`,[req.auth.userId,ids]);
    for(const id of ids)await client.query(`INSERT INTO mentoring.prospective_student_mentor_allotments
      (prospective_student_id,employee_id,allotted_from,allotment_status,created_by) VALUES ($1,$2,CURRENT_DATE,'Active',$3)`,
      [id,Number(data.employeeId),req.auth.userId]);
    await client.query('COMMIT');res.status(201).json({ok:true,message:`Mentor assigned to ${ids.length} prospective student${ids.length===1?'':'s'} successfully.`});
  }catch(error){await client.query('ROLLBACK');console.error('Prospective mentor assignment error:',error.message);res.status(400).json({ok:false,message:error.message});}
  finally{client.release();}
});

app.get('/api/mentor-allotment-report/options',authenticate,async(_req,res)=>{
  try{
    const [years,departments,designations,categories]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(NULLIF(academic_year_name,''),year_label) AS name,is_current
        FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT department_id AS id,department_name AS name FROM departments WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY name`),
      pool.query(`SELECT MIN(designation_id) AS id,MIN(TRIM(designation_name)) AS name FROM designations WHERE COALESCE(is_active,TRUE)=TRUE GROUP BY LOWER(TRIM(designation_name)) ORDER BY name`),
      pool.query(`SELECT DISTINCT COALESCE(NULLIF(e.employee_category,''),d.category,'Staff') AS name
        FROM employees e LEFT JOIN designations d ON d.designation_id=e.designation_id ORDER BY name`)
    ]);
    res.json({ok:true,academicYears:years.rows,departments:departments.rows,designations:designations.rows,categories:categories.rows});
  }catch(error){console.error('Mentor report options error:',error.message);res.status(500).json({ok:false,message:'Unable to load mentor report options.'});}
});

app.get('/api/mentor-allotment-report',authenticate,async(req,res)=>{
  try{
    const values=[],where=["UPPER(COALESCE(e.status,'ACTIVE'))='ACTIVE'"];
    const add=(value,column)=>{if(value){values.push(value);where.push(`${column}=$${values.length}`);}};
    const year=Number(req.query.academicYearId)||null;
    add(req.query.departmentId,'e.department_id');
    if(req.query.designationId){values.push(req.query.designationId);where.push(`LOWER(TRIM(des.designation_name))=(SELECT LOWER(TRIM(designation_name)) FROM designations WHERE designation_id=$${values.length})`);}
    if(req.query.category){values.push(req.query.category);where.push(`COALESCE(NULLIF(e.employee_category,''),des.category,'Staff')=$${values.length}`);}
    if(req.query.mentorStatus){values.push(req.query.mentorStatus);where.push(`COALESCE(m.mentor_status,'Inactive')=$${values.length}`);}
    if(req.query.search){values.push(`%${String(req.query.search).trim()}%`);where.push(`TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) ILIKE $${values.length}`);}
    values.push(year);const yearIndex=values.length;
    const result=await pool.query(`SELECT e.employee_id AS id,m.mentor_id,e.first_name,e.middle_name,e.last_name,
      dp.department_name,des.designation_name,COALESCE(NULLIF(e.employee_category,''),des.category,'Staff') AS category,
      COALESCE(m.mentor_status,'Inactive') AS mentor_status,COALESCE(counts.students_allotted,0)::int AS students_allotted
      FROM employees e LEFT JOIN departments dp ON dp.department_id=e.department_id
      LEFT JOIN designations des ON des.designation_id=e.designation_id
      LEFT JOIN mentoring.mentors m ON m.employee_id=e.employee_id
      LEFT JOIN LATERAL (SELECT COUNT(DISTINCT sma.student_id)::int AS students_allotted
        FROM mentoring.student_mentor_allotments sma WHERE sma.mentor_id=m.mentor_id
          AND sma.allotment_status='Active' AND ($${yearIndex}::bigint IS NULL OR sma.academic_year_id=$${yearIndex})) counts ON TRUE
      WHERE ${where.join(' AND ')} ORDER BY e.first_name,e.middle_name,e.last_name`,values);
    res.json({ok:true,employees:result.rows});
  }catch(error){console.error('Mentor report error:',error.message);res.status(500).json({ok:false,message:'Unable to load mentor allotment report.'});}
});

app.get('/api/mentor-allotment-report/:employeeId/students',authenticate,async(req,res)=>{
  try{
    const employeeId=Number(req.params.employeeId),yearId=Number(req.query.academicYearId);
    if(!yearId)return res.status(400).json({ok:false,message:'Academic year is required.'});
    const employee=(await pool.query(`SELECT e.employee_id,m.mentor_id,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS mentor_name,
      dp.department_name,des.designation_name,COALESCE(NULLIF(e.employee_category,''),des.category,'Staff') AS category,
      COALESCE(NULLIF(y.academic_year_name,''),y.year_label) AS academic_year
      FROM employees e LEFT JOIN mentoring.mentors m ON m.employee_id=e.employee_id
      LEFT JOIN departments dp ON dp.department_id=e.department_id LEFT JOIN designations des ON des.designation_id=e.designation_id
      CROSS JOIN academic_years y WHERE e.employee_id=$1 AND y.academic_year_id=$2`,[employeeId,yearId])).rows[0];
    if(!employee)return res.status(404).json({ok:false,message:'Employee or academic year not found.'});
    const students=employee.mentor_id?(await pool.query(`SELECT sma.mentor_allotment_id AS id,
      COALESCE(NULLIF(st.registration_number,''),st.registration_no,st.student_code) AS registration_no,
      TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS student_name,
      p.programme_name,ab.batch_name,se.semester_name,sec.section_name,sma.allotted_from,sma.allotment_status
      FROM mentoring.student_mentor_allotments sma JOIN students st ON st.student_id=sma.student_id
      LEFT JOIN programmes p ON p.programme_id=sma.programme_id LEFT JOIN admission_batches ab ON ab.batch_id=sma.programme_batch_id
      LEFT JOIN semesters se ON se.semester_id=sma.semester_id LEFT JOIN sections sec ON sec.section_id=sma.programme_section_id
      WHERE sma.mentor_id=$1 AND sma.academic_year_id=$2 AND sma.allotment_status='Active' ORDER BY registration_no`,
      [employee.mentor_id,yearId])).rows:[];
    res.json({ok:true,employee,students});
  }catch(error){console.error('Mentor report students error:',error.message);res.status(500).json({ok:false,message:'Unable to load students allotted to mentor.'});}
});

app.get('/api/mentor-reviewer-options', authenticate, async (_req,res)=>{
  try{
    const [years,departments,mentors,reviewers]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,COALESCE(NULLIF(academic_year_name,''),year_label) AS name,is_current
        FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT department_id AS id,department_name AS name FROM departments
        WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY department_name`),
      pool.query(`SELECT e.employee_id AS id,e.department_id,
        TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,e.employee_code
        FROM employees e
        WHERE UPPER(COALESCE(e.status,'ACTIVE'))='ACTIVE' ORDER BY name`),
      pool.query(`SELECT e.employee_id AS id,e.department_id,
        TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,e.employee_code
        FROM employees e
        WHERE UPPER(COALESCE(e.status,'ACTIVE'))='ACTIVE' ORDER BY name`)
    ]);
    res.json({ok:true,academicYears:years.rows,departments:departments.rows,mentors:mentors.rows,reviewers:reviewers.rows});
  }catch(error){console.error('Mentor reviewer options error:',error.message);res.status(500).json({ok:false,message:'Unable to load mentor reviewer options.'});}
});

app.get('/api/mentor-reviewer-allotments', authenticate, async (req,res)=>{
  try{
    const values=[],where=[];
    const add=(value,clause)=>{if(value){values.push(value);where.push(clause.replace('?',`$${values.length}`));}};
    add(req.query.academicYearId,'a.academic_year_id=?');
    add(req.query.departmentId,'a.department_id=?');
    add(req.query.mentorId,'a.mentor_id=?');
    add(req.query.reviewerId,`EXISTS (SELECT 1 FROM mentoring.mentor_reviewer_allotment_details fx
      WHERE fx.mentor_reviewer_allotment_id=a.mentor_reviewer_allotment_id AND fx.reviewer_id=? AND fx.is_active=TRUE)`);
    add(req.query.status,'a.allotment_status=?');
    if(req.query.search){values.push(`%${String(req.query.search).trim()}%`);where.push(`(
      TRIM(CONCAT_WS(' ',me.first_name,me.middle_name,me.last_name)) ILIKE $${values.length}
      OR EXISTS (SELECT 1 FROM mentoring.mentor_reviewer_allotment_details sx
        JOIN employees se ON se.employee_id=sx.reviewer_id
        WHERE sx.mentor_reviewer_allotment_id=a.mentor_reviewer_allotment_id
        AND TRIM(CONCAT_WS(' ',se.first_name,se.middle_name,se.last_name)) ILIKE $${values.length}))`);}
    const result=await pool.query(`SELECT a.mentor_reviewer_allotment_id AS id,a.academic_year_id,a.department_id,a.mentor_id,
      COALESCE(NULLIF(y.academic_year_name,''),y.year_label) AS academic_year,d.department_name,
      TRIM(CONCAT_WS(' ',me.first_name,me.middle_name,me.last_name)) AS mentor_name,
      a.effective_from,a.effective_to,a.allotment_status AS status,a.remarks,
      MAX(CASE WHEN x.reviewer_role='Reviewer 1' THEN x.reviewer_id END) AS reviewer1_id,
      MAX(CASE WHEN x.reviewer_role='Reviewer 1' THEN TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name)) END) AS reviewer1_name,
      MAX(CASE WHEN x.reviewer_role='Reviewer 2' THEN x.reviewer_id END) AS reviewer2_id,
      MAX(CASE WHEN x.reviewer_role='Reviewer 2' THEN TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name)) END) AS reviewer2_name,
      MAX(CASE WHEN x.reviewer_role='Chief Reviewer' THEN x.reviewer_id END) AS chief_reviewer_id,
      MAX(CASE WHEN x.reviewer_role='Chief Reviewer' THEN TRIM(CONCAT_WS(' ',re.first_name,re.middle_name,re.last_name)) END) AS chief_reviewer_name
      FROM mentoring.mentor_reviewer_allotments a
      JOIN academic_years y ON y.academic_year_id=a.academic_year_id
      LEFT JOIN departments d ON d.department_id=a.department_id
      JOIN employees me ON me.employee_id=a.mentor_id
      LEFT JOIN mentoring.mentor_reviewer_allotment_details x ON x.mentor_reviewer_allotment_id=a.mentor_reviewer_allotment_id AND x.is_active=TRUE
      LEFT JOIN employees re ON re.employee_id=x.reviewer_id
      ${where.length?`WHERE ${where.join(' AND ')}`:''}
      GROUP BY a.mentor_reviewer_allotment_id,y.academic_year_name,y.year_label,d.department_name,me.first_name,me.middle_name,me.last_name
      ORDER BY a.created_at DESC`,values);
    res.json({ok:true,items:result.rows});
  }catch(error){console.error('Mentor reviewer list error:',error.message);res.status(500).json({ok:false,message:'Unable to load mentor reviewer allotments.'});}
});

function mentorReviewerPayload(data){
  const reviewers=[
    ['Reviewer 1',data.reviewer1Id,1],['Reviewer 2',data.reviewer2Id,2],['Chief Reviewer',data.chiefReviewerId,3]
  ].filter(([,id])=>id);
  if(!data.academicYearId||!data.mentorId||!data.reviewer1Id||!data.chiefReviewerId)throw new Error('Academic year, mentor, Reviewer 1 and Chief Reviewer are required.');
  if(new Set(reviewers.map(([,id])=>String(id))).size!==reviewers.length)throw new Error('Each reviewer must be a different employee.');
  if(reviewers.some(([,id])=>String(id)===String(data.mentorId)))throw new Error('The mentor cannot also be selected as a reviewer.');
  if(data.effectiveTo&&data.effectiveTo<data.effectiveFrom)throw new Error('Effective To cannot be before Effective From.');
  return reviewers;
}

async function ensureSingleReviewerPermission(client,data,reviewers,excludeAllotmentId=null){
  for(const [role,reviewerId] of reviewers){
    const conflict=await client.query(`SELECT d.reviewer_role
      FROM mentoring.mentor_reviewer_allotment_details d
      JOIN mentoring.mentor_reviewer_allotments a
        ON a.mentor_reviewer_allotment_id=d.mentor_reviewer_allotment_id
      WHERE a.academic_year_id=$1 AND a.allotment_status='Active'
        AND d.reviewer_id=$2 AND d.is_active=TRUE AND d.reviewer_role<>$3
        AND ($4::bigint IS NULL OR a.mentor_reviewer_allotment_id<>$4)
      LIMIT 1`,[Number(data.academicYearId),Number(reviewerId),role,excludeAllotmentId]);
    if(conflict.rowCount)throw new Error(`This employee already has ${conflict.rows[0].reviewer_role} permission for the selected academic year and cannot also be assigned as ${role}.`);
  }
}

app.post('/api/mentor-reviewer-allotments', authenticate, async (req,res)=>{
  const client=await pool.connect();
  try{
    const data=req.body||{},reviewers=mentorReviewerPayload(data);
    await client.query('BEGIN');
    await ensureSingleReviewerPermission(client,data,reviewers);
    const saved=await client.query(`INSERT INTO mentoring.mentor_reviewer_allotments
      (academic_year_id,department_id,mentor_id,effective_from,effective_to,allotment_status,remarks,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING mentor_reviewer_allotment_id`,
      [Number(data.academicYearId),data.departmentId?Number(data.departmentId):null,Number(data.mentorId),data.effectiveFrom||new Date().toISOString().slice(0,10),
       data.effectiveTo||null,data.status||'Active',data.remarks?.trim()||null,req.auth.userId]);
    const id=saved.rows[0].mentor_reviewer_allotment_id;
    for(const [role,reviewerId,order] of reviewers)await client.query(`INSERT INTO mentoring.mentor_reviewer_allotment_details
      (mentor_reviewer_allotment_id,reviewer_id,reviewer_role,display_order,assigned_from,assigned_to,remarks,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[id,Number(reviewerId),role,order,data.effectiveFrom||new Date().toISOString().slice(0,10),data.effectiveTo||null,data.remarks?.trim()||null,req.auth.userId]);
    await client.query('COMMIT');res.status(201).json({ok:true,id,message:'Mentor reviewer allotment created successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Mentor reviewer create error:',error.message);
    res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'An active allotment already exists for this mentor and academic year.':error.message});}
  finally{client.release();}
});

app.put('/api/mentor-reviewer-allotments/:id', authenticate, async (req,res)=>{
  const client=await pool.connect();
  try{
    const id=Number(req.params.id),data=req.body||{},reviewers=mentorReviewerPayload(data);
    await client.query('BEGIN');
    await ensureSingleReviewerPermission(client,data,reviewers,id);
    const current=await client.query(`SELECT reviewer_role,reviewer_id FROM mentoring.mentor_reviewer_allotment_details
      WHERE mentor_reviewer_allotment_id=$1 AND is_active=TRUE`,[id]);
    if(!current.rowCount)throw new Error('Mentor reviewer allotment not found.');
    const old=new Map(current.rows.map(row=>[row.reviewer_role,String(row.reviewer_id)]));
    await client.query(`UPDATE mentoring.mentor_reviewer_allotments SET department_id=$1,effective_from=$2,effective_to=$3,
      allotment_status=$4,remarks=$5,updated_by=$6,updated_at=NOW() WHERE mentor_reviewer_allotment_id=$7`,
      [data.departmentId?Number(data.departmentId):null,data.effectiveFrom,data.effectiveTo||null,data.status||'Active',data.remarks?.trim()||null,req.auth.userId,id]);
    await client.query(`DELETE FROM mentoring.mentor_reviewer_allotment_details WHERE mentor_reviewer_allotment_id=$1`,[id]);
    for(const [role,reviewerId,order] of reviewers){
      await client.query(`INSERT INTO mentoring.mentor_reviewer_allotment_details
        (mentor_reviewer_allotment_id,reviewer_id,reviewer_role,display_order,assigned_from,assigned_to,remarks,created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[id,Number(reviewerId),role,order,data.effectiveFrom,data.effectiveTo||null,data.remarks?.trim()||null,req.auth.userId]);
      if(old.get(role)!==String(reviewerId))await client.query(`INSERT INTO mentoring.mentor_reviewer_change_history
        (mentor_reviewer_allotment_id,reviewer_role,old_reviewer_id,new_reviewer_id,effective_date,change_reason,changed_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,[id,role,old.get(role)?Number(old.get(role)):null,Number(reviewerId),data.effectiveFrom,data.changeReason?.trim()||'Reviewer allotment updated',req.auth.userId]);
    }
    await client.query('COMMIT');res.json({ok:true,message:'Mentor reviewer allotment updated successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Mentor reviewer update error:',error.message);
    res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'This reviewer is already assigned in the allotment.':error.message});}
  finally{client.release();}
});

app.delete('/api/mentor-reviewer-allotments/:id', authenticate, async (req,res)=>{
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const result=await client.query(`UPDATE mentoring.mentor_reviewer_allotments
      SET allotment_status='Inactive',effective_to=COALESCE(effective_to,CURRENT_DATE),updated_by=$1,updated_at=NOW()
      WHERE mentor_reviewer_allotment_id=$2 AND allotment_status='Active' RETURNING mentor_reviewer_allotment_id`,
      [req.auth.userId,Number(req.params.id)]);
    if(!result.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Active mentor reviewer allotment not found.'});}
    await client.query(`UPDATE mentoring.mentor_reviewer_allotment_details SET is_active=FALSE,
      assigned_to=COALESCE(assigned_to,CURRENT_DATE) WHERE mentor_reviewer_allotment_id=$1`,[Number(req.params.id)]);
    await client.query('COMMIT');res.json({ok:true,message:'Mentor reviewer allotment deactivated successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('Mentor reviewer deactivate error:',error.message);res.status(500).json({ok:false,message:'Unable to deactivate mentor reviewer allotment.'});}
  finally{client.release();}
});

app.get('/api/user-settings/options',authenticate,async(_req,res)=>{
  try{
    const [types,employees,students]=await Promise.all([
      pool.query('SELECT user_type_id AS id,user_type_code AS code,user_type_name AS name FROM user_types ORDER BY display_order'),
      pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,
        TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,u.user_id AS linked_user_id
        FROM employees e LEFT JOIN users u ON u.employee_id=e.employee_id
        WHERE UPPER(COALESCE(e.status,'ACTIVE'))='ACTIVE' ORDER BY name`),
      pool.query(`SELECT s.student_id AS id,COALESCE(NULLIF(s.registration_number,''),s.registration_no,s.student_code) AS code,
        TRIM(CONCAT_WS(' ',s.first_name,s.middle_name,s.last_name)) AS name,u.user_id AS linked_user_id
        FROM students s LEFT JOIN users u ON u.student_id=s.student_id
        WHERE COALESCE(s.is_active,TRUE)=TRUE AND COALESCE(s.is_deleted,FALSE)=FALSE ORDER BY name`)
    ]);
    res.json({ok:true,userTypes:types.rows,employees:employees.rows,students:students.rows});
  }catch(error){console.error('User settings options error:',error.message);res.status(500).json({ok:false,message:'Unable to load user settings options.'});}
});

app.get('/api/user-settings',authenticate,async(req,res)=>{
  try{
    const values=[],where=['TRUE'];
    const add=(value,column)=>{if(value){values.push(value);where.push(`${column}=$${values.length}`);}};
    add(req.query.userType,'ut.user_type_code');add(req.query.status,'u.user_status');
    if(req.query.search){values.push(`%${String(req.query.search).trim()}%`);where.push(`(u.username ILIKE $${values.length} OR COALESCE(u.full_name,u.display_name,'') ILIKE $${values.length})`);}
    const result=await pool.query(`SELECT u.user_id AS id,u.username,COALESCE(u.full_name,u.display_name,u.username) AS full_name,
      u.email,u.mobile,u.user_type_id,ut.user_type_code,ut.user_type_name,u.employee_id,u.student_id,
      COALESCE(NULLIF(u.photo_path,''),NULLIF(up.file_path,''),NULLIF(e.photo_url,''),
        NULLIF(s.profile_photo_url,''),NULLIF(s.photo_url,'')) AS photo_path,u.user_status,u.remarks,
      CASE WHEN u.employee_id IS NOT NULL THEN e.employee_code
        WHEN u.student_id IS NOT NULL THEN COALESCE(NULLIF(s.registration_number,''),s.registration_no,s.student_code) END AS linked_record
      FROM users u LEFT JOIN user_types ut ON ut.user_type_id=u.user_type_id
      LEFT JOIN employees e ON e.employee_id=u.employee_id OR (u.employee_id IS NULL AND e.user_id=u.user_id)
      LEFT JOIN students s ON s.student_id=u.student_id OR (u.student_id IS NULL AND s.user_id=u.user_id)
      LEFT JOIN LATERAL (SELECT file_path FROM user_photos WHERE user_id=u.user_id AND is_current=TRUE
        ORDER BY uploaded_at DESC,user_photo_id DESC LIMIT 1) up ON TRUE
      WHERE ${where.join(' AND ')} ORDER BY u.created_at DESC,u.user_id`,values);
    res.json({ok:true,users:result.rows});
  }catch(error){console.error('User settings list error:',error.message);res.status(500).json({ok:false,message:'Unable to load users.'});}
});

async function saveUserPhoto(client,userId,data,actorId){
  if(!data.photoData)return;
  await client.query('UPDATE user_photos SET is_current=FALSE WHERE user_id=$1',[userId]);
  await client.query(`INSERT INTO user_photos(user_id,original_file_name,stored_file_name,file_path,file_type,file_size_bytes,uploaded_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7)`,[userId,data.photoName||'user-photo',`${userId}-${Date.now()}`,data.photoData,data.photoType||null,
    Number(data.photoSize)||null,actorId]);
}
const legacyUserType=code=>code==='ADMIN'?'ADMIN':code==='STUDENT'?'STUDENT':'EMPLOYEE';

app.post('/api/user-settings',authenticate,async(req,res)=>{
  const client=await pool.connect();
  try{
    const data=req.body||{};
    if(!data.username?.trim()||!data.fullName?.trim()||!data.userTypeId||!data.password)
      return res.status(400).json({ok:false,message:'User ID, user name, user type, and password are required.'});
    if(data.password!==data.confirmPassword)return res.status(400).json({ok:false,message:'Password and confirm password do not match.'});
    const type=(await client.query('SELECT user_type_code FROM user_types WHERE user_type_id=$1',[Number(data.userTypeId)])).rows[0];
    if(!type)return res.status(400).json({ok:false,message:'Select a valid user type.'});
    await client.query('BEGIN');
    const saved=(await client.query(`INSERT INTO users
      (username,password_hash,email,mobile,display_name,full_name,user_type,user_type_id,employee_id,student_id,
       photo_path,user_status,is_active,must_change_password,remarks,created_by,password_changed_at)
      VALUES ($1,$2,$3,$4,$5::text,$5::text,$6,$7,$8,$9,$10::text,$11::text,$12::boolean,TRUE,$13,$14,NOW()) RETURNING user_id`,
      [data.username.trim(),await hashPassword(data.password),data.email?.trim()||null,data.mobile?.trim()||null,data.fullName.trim(),
       legacyUserType(type.user_type_code),Number(data.userTypeId),data.employeeId?Number(data.employeeId):null,
       data.studentId?Number(data.studentId):null,data.photoData||null,data.status||'Active',(data.status||'Active')==='Active',
       data.remarks?.trim()||null,req.auth.userId])).rows[0];
    if(data.employeeId)await client.query('UPDATE employees SET user_id=$1 WHERE employee_id=$2',[saved.user_id,Number(data.employeeId)]);
    if(data.studentId)await client.query('UPDATE students SET user_id=$1 WHERE student_id=$2',[saved.user_id,Number(data.studentId)]);
    await saveUserPhoto(client,saved.user_id,data,req.auth.userId);
    await client.query('COMMIT');res.status(201).json({ok:true,message:'User created successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('User settings create error:',error.message);
    res.status(error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'User ID, email, or linked record already exists.':error.message});}
  finally{client.release();}
});

app.put('/api/user-settings/:id',authenticate,async(req,res)=>{
  const client=await pool.connect();
  try{
    const id=Number(req.params.id),data=req.body||{};
    if(!data.username?.trim()||!data.fullName?.trim()||!data.userTypeId)return res.status(400).json({ok:false,message:'User ID, user name, and user type are required.'});
    const type=(await client.query('SELECT user_type_code FROM user_types WHERE user_type_id=$1',[Number(data.userTypeId)])).rows[0];
    if(!type)return res.status(400).json({ok:false,message:'Select a valid user type.'});
    await client.query('BEGIN');
    const old=(await client.query('SELECT employee_id,student_id,user_status FROM users WHERE user_id=$1 FOR UPDATE',[id])).rows[0];
    if(!old)throw Object.assign(new Error('User not found.'),{code:'USER_NOT_FOUND'});
    const result=await client.query(`UPDATE users SET username=$1,display_name=$2::text,full_name=$2::text,user_type=$3,user_type_id=$4,
      employee_id=$5,student_id=$6,email=$7,mobile=$8,user_status=$9::text,is_active=$10::boolean,remarks=$11,
      photo_path=COALESCE($12::text,photo_path),updated_by=$13,updated_at=NOW(),
      failed_login_count=CASE WHEN $9::text='Active' THEN 0 ELSE failed_login_count END,
      locked_until=CASE WHEN $9::text='Active' THEN NULL ELSE locked_until END
      WHERE user_id=$14 RETURNING user_id`,
      [data.username.trim(),data.fullName.trim(),legacyUserType(type.user_type_code),Number(data.userTypeId),
       data.employeeId?Number(data.employeeId):null,data.studentId?Number(data.studentId):null,data.email?.trim()||null,
       data.mobile?.trim()||null,data.status||'Active',(data.status||'Active')==='Active',data.remarks?.trim()||null,
       data.photoData||null,req.auth.userId,id]);
    if(old.employee_id&&String(old.employee_id)!==String(data.employeeId||''))await client.query('UPDATE employees SET user_id=NULL WHERE employee_id=$1 AND user_id=$2',[old.employee_id,id]);
    if(old.student_id&&String(old.student_id)!==String(data.studentId||''))await client.query('UPDATE students SET user_id=NULL WHERE student_id=$1 AND user_id=$2',[old.student_id,id]);
    if(data.employeeId)await client.query('UPDATE employees SET user_id=$1 WHERE employee_id=$2',[id,Number(data.employeeId)]);
    if(data.studentId)await client.query('UPDATE students SET user_id=$1 WHERE student_id=$2',[id,Number(data.studentId)]);
    if(old.user_status!==(data.status||'Active'))await client.query(`INSERT INTO user_status_history(user_id,old_status,new_status,change_reason,changed_by)
      VALUES ($1,$2,$3,$4,$5)`,[id,old.user_status,data.status||'Active',data.remarks?.trim()||'User status updated',req.auth.userId]);
    await saveUserPhoto(client,id,data,req.auth.userId);
    await client.query('COMMIT');res.json({ok:true,id:result.rows[0].user_id,message:'User updated successfully.'});
  }catch(error){await client.query('ROLLBACK');console.error('User settings update error:',error.message);
    res.status(error.code==='USER_NOT_FOUND'?404:error.code==='23505'?409:400).json({ok:false,message:error.code==='23505'?'User ID, email, or linked record already exists.':error.message});}
  finally{client.release();}
});

app.get('/api/sms/:audience', authenticate, async (req,res)=>{
  if(!['student','staff'].includes(req.params.audience))
    return res.status(404).json({ok:false,message:'SMS audience not found.'});
  const staff=req.params.audience==='staff';
  try{
    const [academicYears,programmes,batches,semesters,sections,departments,designations,templates,recipients,history]=await Promise.all([
      pool.query(`SELECT academic_year_id AS id,year_label AS name,is_current FROM academic_years WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY is_current DESC,start_date DESC`),
      pool.query(`SELECT programme_id AS id,programme_name AS name FROM programmes WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY programme_name`),
      pool.query(`SELECT batch_id AS id,programme_id,batch_name AS name FROM admission_batches WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY admission_year DESC,batch_name`),
      pool.query(`SELECT semester_id AS id,programme_id,semester_name AS name,semester_number FROM semesters WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY semester_number`),
      pool.query(`SELECT s.section_id AS id,s.batch_id,s.semester_id,COALESCE(sm.section_master_name,s.section_name) AS name FROM sections s LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id WHERE COALESCE(s.is_active,TRUE)=TRUE ORDER BY name`),
      pool.query(`SELECT department_id AS id,department_name AS name FROM departments WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY department_name`),
      pool.query(`SELECT designation_id AS id,designation_name AS name FROM designations WHERE COALESCE(is_active,TRUE)=TRUE ORDER BY designation_name`),
      pool.query(`SELECT sms_template_id AS id,template_name,template_code,recipient_type,template_message,language_code,is_active FROM communication.sms_templates WHERE recipient_type IN ($1,'General') ORDER BY template_name`,[staff?'Employee':'Student']),
      staff
        ? pool.query(`SELECT e.employee_id AS id,e.employee_code AS code,TRIM(CONCAT_WS(' ',e.first_name,e.middle_name,e.last_name)) AS name,e.employee_category AS category,e.department_id,e.designation_id,d.department_name AS department,dg.designation_name AS designation,e.mobile,UPPER(COALESCE(e.status,'')) AS status FROM employees e LEFT JOIN departments d ON d.department_id=e.department_id LEFT JOIN designations dg ON dg.designation_id=e.designation_id ORDER BY e.employee_code`)
        : pool.query(`SELECT st.student_id AS id,COALESCE(st.registration_number,st.registration_no,st.student_code) AS code,TRIM(CONCAT_WS(' ',st.first_name,st.middle_name,st.last_name)) AS name,st.academic_year_id,st.programme_id,st.batch_id,st.semester_id,st.section_id,p.programme_name AS programme,se.semester_name AS semester,COALESCE(sm.section_master_name,s.section_name) AS section,COALESCE(NULLIF(st.mobile_number,''),st.mobile) AS mobile,sp.guardian_mobile,st.status,st.is_active FROM students st JOIN programmes p ON p.programme_id=st.programme_id LEFT JOIN semesters se ON se.semester_id=st.semester_id LEFT JOIN sections s ON s.section_id=st.section_id LEFT JOIN section_masters sm ON sm.section_master_id=s.section_master_id LEFT JOIN student_parents sp ON sp.student_id=st.student_id WHERE COALESCE(st.is_deleted,FALSE)=FALSE ORDER BY code`),
      pool.query(`SELECT sr.sms_recipient_id AS id,b.created_at AS sent_at,sr.recipient_name,sr.mobile_number,sr.personalized_message,sr.sms_parts,sr.recipient_status,b.batch_reference,b.recipient_category,COALESCE(u.display_name,u.full_name,u.username,'System') AS sent_by,COALESCE(st.registration_number,st.registration_no,st.student_code) AS registration_number,e.employee_code,d.department_name FROM communication.sms_recipients sr JOIN communication.sms_batches b ON b.sms_batch_id=sr.sms_batch_id LEFT JOIN users u ON u.user_id=b.created_by LEFT JOIN students st ON st.student_id=sr.student_id LEFT JOIN employees e ON e.employee_id=sr.employee_id LEFT JOIN departments d ON d.department_id=e.department_id WHERE sr.recipient_type ${staff?"='Employee'":"IN ('Student','Guardian')"} ORDER BY b.created_at DESC LIMIT 500`)
    ]);
    res.json({ok:true,academicYears:academicYears.rows,programmes:programmes.rows,batches:batches.rows,semesters:semesters.rows,sections:sections.rows,departments:departments.rows,designations:designations.rows,templates:templates.rows,recipients:recipients.rows,history:history.rows});
  }catch(error){console.error('SMS page query error:',error.message);res.status(500).json({ok:false,message:'Unable to load SMS records.'});}
});

app.post('/api/sms/batches', authenticate, async (req,res)=>{
  const data=req.body,recipients=Array.isArray(data.recipients)?data.recipients:[],message=String(data.message||'').trim(),sendType=data.sendType==='Scheduled'?'Scheduled':'Immediate';
  if(!['Student','Guardian','Student and Guardian','Employee'].includes(data.recipientCategory)||!message||!recipients.length)return res.status(400).json({ok:false,message:'Select at least one valid recipient and enter a message.'});
  if(sendType==='Scheduled'&&!data.scheduledAt)return res.status(400).json({ok:false,message:'Select a schedule date and time.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const reference=`SMS-${Date.now()}-${Math.floor(Math.random()*1000).toString().padStart(3,'0')}`;
    const batch=(await client.query(`INSERT INTO communication.sms_batches (batch_reference,recipient_category,sms_template_id,message_text,language_code,sender_id,send_type,scheduled_at,batch_status,total_recipients,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'Queued',$9,$10) RETURNING sms_batch_id`,[reference,data.recipientCategory,data.templateId?Number(data.templateId):null,message,data.language||'en',data.senderId||'ABITCLG',sendType,sendType==='Scheduled'?new Date(data.scheduledAt):null,recipients.length,req.auth.userId])).rows[0];
    for(const recipient of recipients){
      const type=recipient.type==='Employee'?'Employee':recipient.type==='Guardian'?'Guardian':'Student',personalized=message.replaceAll('{{student_name}}',recipient.name||'Student').replaceAll('{{employee_name}}',recipient.name||'Employee'),parts=Math.max(1,Math.ceil(personalized.length/(data.language==='en'?160:70)));
      await client.query(`INSERT INTO communication.sms_recipients (sms_batch_id,recipient_type,student_id,employee_id,recipient_name,mobile_number,personalized_message,sms_parts,recipient_status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'Queued')`,[batch.sms_batch_id,type,recipient.studentId?Number(recipient.studentId):null,recipient.employeeId?Number(recipient.employeeId):null,recipient.name,String(recipient.mobile||'').trim(),personalized,parts]);
    }
    await client.query('COMMIT');res.status(201).json({ok:true,batchReference:reference,message:`${recipients.length} SMS recipient${recipients.length===1?'':'s'} queued successfully.`});
  }catch(error){await client.query('ROLLBACK');console.error('SMS batch save error:',error.message);res.status(500).json({ok:false,message:'Unable to queue the SMS batch.'});}
  finally{client.release();}
});

app.post('/api/sms/templates', authenticate, async (req,res)=>{
  const data=req.body,code=String(data.code||'').trim().toUpperCase().replaceAll(/[^A-Z0-9_]/g,'_');
  if(!data.name?.trim()||!code||!data.message?.trim()||!['Student','Guardian','Employee','General'].includes(data.recipientType))return res.status(400).json({ok:false,message:'Complete all required SMS template fields.'});
  try{await pool.query(`INSERT INTO communication.sms_templates (template_name,template_code,recipient_type,template_message,is_active,created_by) VALUES ($1,$2,$3,$4,$5,$6)`,[data.name.trim(),code,data.recipientType,data.message.trim(),data.isActive!==false,req.auth.userId]);res.status(201).json({ok:true,message:'SMS template created successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Template code already exists.':'Unable to create SMS template.'});}
});

app.put('/api/sms/templates/:id', authenticate, async (req,res)=>{
  const id=Number(req.params.id),data=req.body,code=String(data.code||'').trim().toUpperCase().replaceAll(/[^A-Z0-9_]/g,'_');
  if(!id||!data.name?.trim()||!code||!data.message?.trim())return res.status(400).json({ok:false,message:'Complete all required SMS template fields.'});
  try{const result=await pool.query(`UPDATE communication.sms_templates SET template_name=$1,template_code=$2,recipient_type=$3,template_message=$4,is_active=$5,updated_by=$6,updated_at=NOW() WHERE sms_template_id=$7 RETURNING sms_template_id`,[data.name.trim(),code,data.recipientType,data.message.trim(),data.isActive!==false,req.auth.userId,id]);if(!result.rowCount)return res.status(404).json({ok:false,message:'SMS template not found.'});res.json({ok:true,message:'SMS template updated successfully.'});}
  catch(error){res.status(error.code==='23505'?409:500).json({ok:false,message:error.code==='23505'?'Template code already exists.':'Unable to update SMS template.'});}
});

app.use((error, _req, res, next) => {
  if (error?.type === 'entity.too.large') return res.status(413).json({ ok:false, message:'The submitted information is too large. Please upload smaller files.' });
  if (error instanceof SyntaxError && error.status === 400) return res.status(400).json({ ok:false, message:'Invalid request data.' });
  next(error);
});

// Initialize the database before opening the API port.
initialiseAuthentication()
  .then(() => app.listen(port, () => console.log(`Server listening on http://localhost:${port}`)))
  .catch((error) => { console.error('Database initialisation failed:', error.message); process.exitCode = 1; });
