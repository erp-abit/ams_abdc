import 'dotenv/config';
import { scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import pg from 'pg';

const loginId = process.argv[2];
const password = process.argv[3];
if (!loginId || !password) throw new Error('Usage: node scripts/verify-super-admin.mjs <login-id> <password>');

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost', port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'postgres', user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres'
});

try {
  const result = await pool.query(
    `SELECT password_hash,account_status,user_type FROM "ABDC_DB".user_logins
     WHERE LOWER(login_id)=LOWER($1) LIMIT 1`, [loginId]
  );
  const account = result.rows[0];
  if (!account) throw new Error('Account not found.');
  const [algorithm, salt, key] = account.password_hash.split(':');
  const derived = Buffer.from(await promisify(scryptCallback)(password, salt, 64));
  const saved = Buffer.from(key, 'hex');
  const passwordValid = algorithm === 'scrypt' && saved.length === derived.length && timingSafeEqual(saved, derived);
  console.log(JSON.stringify({ found:true, userType:account.user_type, status:account.account_status, passwordValid }));
} finally {
  await pool.end();
}
