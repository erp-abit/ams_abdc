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
  const sql = await readFile(
    new URL('../abdc_db_user_logins.sql', import.meta.url),
    'utf8'
  );
  await pool.query(sql);
  console.log('ABDC_DB.user_logins schema applied successfully.');
  const connection = await pool.query('SELECT current_database() AS database_name, current_user AS database_user');
  console.log(`Connected database: ${connection.rows[0].database_name} (user: ${connection.rows[0].database_user})`);
  const result = await pool.query(
    `SELECT login_id,account_status,failed_login_attempts
     FROM "ABDC_DB".user_logins WHERE user_type='SUPER_ADMIN' ORDER BY login_id`
  );
  console.log(`Configured SUPER_ADMIN accounts: ${result.rowCount}`);
  for (const account of result.rows) {
    console.log(`${account.login_id}: ${account.account_status}, failed attempts: ${account.failed_login_attempts}`);
  }
} finally {
  await pool.end();
}
