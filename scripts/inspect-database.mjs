import 'dotenv/config';
import pg from 'pg';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres'
});

try {
  const result = await pool.query(`
    SELECT table_schema, table_name
    FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
    ORDER BY table_schema, table_name
  `);
  console.log(`Database: ${process.env.DB_NAME || 'postgres'}`);
  console.log(`Application tables: ${result.rowCount}`);
  console.log(result.rows.map(row => `${row.table_schema}.${row.table_name}`).join('\n'));
  const counts = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM institutions) AS institutions,
      (SELECT COUNT(*)::int FROM users) AS users,
      (SELECT COUNT(*)::int FROM employees) AS employees,
      (SELECT COUNT(*)::int FROM students) AS students
  `);
  console.log('Core record counts:', counts.rows[0]);
} finally {
  await pool.end();
}
