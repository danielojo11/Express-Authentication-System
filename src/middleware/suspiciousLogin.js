import pool from "../config/db.js";

export const detectSuspiciousLogin = async ({ userId, country, ip }) => {
  const result = await pool.query(
    "SELECT country, ip_address FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5",
    [userId],
  );

  const knownCountries = result.rows.map((r) => r.country);

  const suspicious = !knownCountries.includes(country);

  return suspicious;
};
