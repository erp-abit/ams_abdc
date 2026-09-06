import fs from 'node:fs/promises';
import pg from 'pg';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres'
});

try {
  const sql = await fs.readFile(new URL('../programme_semester_definitions.sql', import.meta.url), 'utf8');
  await pool.query(sql);
  console.log('programme_semester_definitions schema applied successfully.');
} finally {
  await pool.end();
}
