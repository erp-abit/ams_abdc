import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import pg from 'pg';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres'
});

const required = [
  'institutions', 'users', 'employees', 'departments', 'programmes',
  'academic_years', 'semesters', 'sections', 'campuses', 'common_master_values'
];

try {
  if (process.argv.includes('--inspect')) {
    const [result, tables] = await Promise.all([pool.query(
      `SELECT table_name,column_name FROM information_schema.columns
       WHERE table_schema='public' AND table_name IN ('students','student_documents')
       ORDER BY table_name,ordinal_position`
    ), pool.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema='public' AND (table_name LIKE 'student_%' OR table_name IN ('students','admission_categories','mentoring_topics'))
       ORDER BY table_name`
    )]);
    console.log(`Module tables: ${tables.rowCount}`);
    console.log(`Biometrics table: ${tables.rows.some(row => row.table_name==='student_biometrics')?'present':'absent'}`);
    console.log(result.rows.map(row => `${row.table_name}.${row.column_name}`).join('\n'));
  } else {
    const result = await pool.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema='public' AND table_name=ANY($1::text[])`,
      [required]
    );
    const available = new Set(result.rows.map(row => row.table_name));
    const missing = required.filter(table => !available.has(table));
    if (missing.length) {
      throw new Error(`Missing prerequisite tables: ${missing.join(', ')}`);
    }
    const sql = await readFile(new URL('../abit_ims_student_and_mentoring_tables_no_biometrics.sql', import.meta.url), 'utf8');
    await pool.query(sql);
    console.log('Student and mentoring schema applied successfully.');
  }
} finally {
  await pool.end();
}
