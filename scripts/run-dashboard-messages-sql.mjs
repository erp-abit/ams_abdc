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
  await pool.query(fs.readFileSync('abit_ims_dashboard_messages.sql','utf8'));
  const result=await pool.query(`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema='public' AND table_name='dashboard_messages'
  `);
  console.log(JSON.stringify({tables:result.rows.map(row=>row.table_name)},null,2));
} finally {
  await pool.end();
}
