import 'dotenv/config';
import { randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
import pg from 'pg';

const scrypt = promisify(scryptCallback);
const loginId = process.argv[2] || 'superadmin';
const temporaryPassword = randomBytes(15).toString('base64url');
const salt = randomBytes(16).toString('hex');
const derived = await scrypt(temporaryPassword, salt, 64);
const passwordHash = `scrypt:${salt}:${Buffer.from(derived).toString('hex')}`;

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres'
});

try {
  await pool.query(
    `INSERT INTO "ABDC_DB".user_logins
      (login_id,password_hash,user_type,display_name,account_status,
       force_password_change,failed_login_attempts,updated_at)
     VALUES ($1,$2,'SUPER_ADMIN','Super Administrator','ACTIVE',TRUE,0,NOW())
     ON CONFLICT (login_id) DO UPDATE SET
       password_hash=EXCLUDED.password_hash,
       user_type='SUPER_ADMIN',
       display_name=EXCLUDED.display_name,
       account_status='ACTIVE',
       force_password_change=TRUE,
       failed_login_attempts=0,
       updated_at=NOW()`,
    [loginId, passwordHash]
  );
  console.log(`Login ID: ${loginId}`);
  console.log(`Temporary password: ${temporaryPassword}`);
  console.log('Password change required: yes');
} finally {
  await pool.end();
}
