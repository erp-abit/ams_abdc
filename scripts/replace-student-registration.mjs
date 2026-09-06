import pg from 'pg';

const [oldRegistration, newRegistration] = process.argv.slice(2);
if (!oldRegistration || !newRegistration) {
  throw new Error('Usage: node scripts/replace-student-registration.mjs <old-registration> <new-registration>');
}

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres'
});

const client = await pool.connect();
try {
  await client.query('BEGIN');
  const student = (await client.query(
    `SELECT student_id,user_id,registration_number,registration_no
     FROM students
     WHERE registration_number=$1 OR registration_no=$1
     FOR UPDATE`,
    [oldRegistration]
  )).rows[0];
  if (!student) throw new Error(`Student registration ${oldRegistration} was not found.`);

  await client.query(
    `UPDATE students
     SET registration_number=$1::varchar,registration_no=$1::varchar,
         student_profile_details=COALESCE(student_profile_details,'{}'::jsonb)
           || jsonb_build_object('registrationNumber',$1::text,'loginId',$1::text),
         updated_at=NOW()
     WHERE student_id=$2`,
    [newRegistration, student.student_id]
  );
  if (student.user_id) {
    await client.query('UPDATE users SET username=$1,updated_at=NOW() WHERE user_id=$2', [newRegistration, student.user_id]);
  }
  await client.query('COMMIT');
  console.log(JSON.stringify({ studentId: student.student_id, oldRegistration, newRegistration }));
} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  client.release();
  await pool.end();
}
