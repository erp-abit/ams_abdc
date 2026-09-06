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

try {
  const sql = await readFile(new URL('../mentoring_mentor_reviewer_allotments.sql', import.meta.url), 'utf8');
  await pool.query(sql);
  const verification = await pool.query(`
    SELECT conname, confrelid::regclass::text AS references_table
    FROM pg_constraint
    WHERE conrelid IN (
      'mentoring.mentor_reviewer_allotments'::regclass,
      'mentoring.mentor_reviewer_allotment_details'::regclass,
      'mentoring.mentor_reviewer_change_history'::regclass
    )
    AND contype = 'f'
    AND conname IN (
      'mentor_reviewer_allotments_mentor_id_fkey',
      'mentor_reviewer_allotment_details_reviewer_id_fkey',
      'mentor_reviewer_change_history_old_reviewer_id_fkey',
      'mentor_reviewer_change_history_new_reviewer_id_fkey'
    )
    ORDER BY conname
  `);
  console.log('Mentor reviewer schema applied successfully.');
  console.table(verification.rows);
} finally {
  await pool.end();
}
