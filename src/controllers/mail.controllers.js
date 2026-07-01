import pool from "../config/db.js";
import crypto from "crypto";

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const result = await pool.query("SELECT * FROM email_verification_token WHERE token = $1", [
      hashedToken,
    ]);

    const storedToken = result.rows[0];

    if (!storedToken) {
      return res.status(400).json({
        message: "Invalid or expired verification token",
      });
    }

    if (Date.now() > new Date(storedToken.expires_at).getTime()) {
      return res.status(400).json({
        message: "Verification token expired",
      });
    }

    await pool.query(
      "UPDATE users SET email_verified = true WHERE id = $1 AND email_verified = false",
      [storedToken.user_id],
    );

    await pool.query("DELETE FROM email_verification_token WHERE id = $1 AND user_id = $2", [
      storedToken.id,
      storedToken.user_id,
    ]);

    return res.status(200).json({
      message: "Email verification successful",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
};

export default verifyEmail;
