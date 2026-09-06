import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import pg from 'pg';

const pool=new pg.Pool({
  host:process.env.DB_HOST||'localhost',port:Number(process.env.DB_PORT||5432),
  database:process.env.DB_NAME||'postgres',user:process.env.DB_USER||'postgres',
  password:process.env.DB_PASSWORD||'postgres'
});
try{
  await pool.query(await readFile(new URL('../mentoring_first_reviewer_remarks.sql',import.meta.url),'utf8'));
  console.log('First reviewer remarks schema applied successfully.');
}finally{await pool.end();}
