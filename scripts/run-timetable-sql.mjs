import 'dotenv/config';
import fs from 'node:fs';
import pg from 'pg';

const pool = new pg.Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

try {
  if (!process.argv.includes('--inspect')) {
    const sql = fs.readFileSync('abit_ims_timetable_module.sql', 'utf8');
    await pool.query(sql);
  }

  const tables = await pool.query(`
    SELECT table_schema, table_name
    FROM information_schema.tables
    WHERE table_schema IN ('public', 'academics')
      AND (
        table_name LIKE 'timetable%'
        OR table_name LIKE 'programme%'
        OR table_name LIKE 'semester%'
        OR table_name LIKE 'section%'
        OR table_name IN (
          'week_days',
          'academic_time_configurations',
          'academic_breaks',
          'academic_periods',
          'subjects',
          'employees',
          'campus_rooms',
          'academic_years',
          'users'
        )
      )
    ORDER BY table_schema, table_name
  `);

  const views = await pool.query(`
    SELECT table_schema, table_name
    FROM information_schema.views
    WHERE table_schema = 'academics'
      AND table_name LIKE 'vw_%timetable%'
    ORDER BY table_name
  `);

  const columns = process.argv.includes('--inspect') ? await pool.query(`
    SELECT table_schema, table_name, column_name
    FROM information_schema.columns
    WHERE table_schema IN ('public', 'academics')
      AND table_name IN (
        'academic_years', 'programmes', 'admission_batches', 'semesters',
        'sections', 'subject_masters', 'employees', 'rooms', 'users',
        'subject_teacher_allocations'
      )
    ORDER BY table_schema, table_name, ordinal_position
  `) : { rows: [] };

  console.log(JSON.stringify({
    tables: tables.rows,
    views: views.rows,
    ...(process.argv.includes('--inspect') ? { columns: columns.rows } : {}),
  }, null, 2));
} finally {
  await pool.end();
}
