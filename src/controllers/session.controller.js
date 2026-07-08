import pool from "../config/db.js";
import { verifyAccessToken } from "../utils/jwt.js";

export const getSessions = async (req, res) => {
  try {
    const authorization = req.headers.authorization;
    console.log(authorization);
    if (!authorization) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authorization.split(" ")[1];
    const user = verifyAccessToken(token);
    console.log(user);
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const result = await pool.query(
      "SELECT id, browser, os, country, city, ip_address, created_at, last_used_at, revoked FROM sessions WHERE user_id = $1 ORDER BY created_at DESC",
      [user.id],
    );
    console.log(result.rows);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

export const revokeSession = async (req, res) => {
  const { sessionsId } = req.params;

  await pool.query("UPDATE sessions SET revoked = true WHERE id = $1 AND user_id = $2", [
    sessionsId,
    req.user.id,
  ]);
  res.json({
    message: "Session Revoked",
  });
};

export const revokeAllSessions = async (req, res) => {
  await pool.query("UPDATE sessions SET revoked = true WHERE user_id = $1", [req.user.id]);
  res.status(200).json({
    message: "All Sessions Revoked",
  });
};
