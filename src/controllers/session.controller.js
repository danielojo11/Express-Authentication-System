import pool from "../config/db.js";

export const getSessions = async (req, res) => {
  const result = await pool.query(
    "SELECT id, browser, os, country, city, ip_address, created_at, last_used_at, revoked FROM sessions WHERE user_id = $1 ORDER BY created_at DESC",
    [req.user.id],
  );
  res.json(result.rows);
};

export const revokeSession = async (req, res) => {
  const { sessionsId } = req.params;

  await pool.query(
    "UPDATE sessions SET revoked = true WHERE id = $1 AND user_id = $2",
    [sessionsId, req.user.id],
  );
  res.json({
    message: "Session Revoked",
  });
};
