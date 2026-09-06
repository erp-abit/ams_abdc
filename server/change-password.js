export async function saveAccountPassword(client, auth, passwordHash) {
  const account = await client.query(
    'UPDATE users SET password_hash=$1,must_change_password=FALSE,password_changed_at=NOW(),updated_at=NOW() WHERE user_id=$2 RETURNING username,user_type',
    [passwordHash, auth.userId]
  );
  if (!account.rowCount) throw new Error('Account not found. Please sign in again.');
  const user = account.rows[0];
  if (user.user_type === 'SUPER_ADMIN' || auth.authSource === 'ABDC_DB') {
    const login = await client.query(
      `UPDATE "ABDC_DB".user_logins SET password_hash=$1,force_password_change=FALSE,updated_at=NOW()
       WHERE LOWER(login_id)=LOWER($2) AND user_type='SUPER_ADMIN' RETURNING user_id`,
      [passwordHash, user.username]
    );
    if (auth.authSource === 'ABDC_DB' && !login.rowCount) throw new Error('Super admin login not found.');
  }
}
