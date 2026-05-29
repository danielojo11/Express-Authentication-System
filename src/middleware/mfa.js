import speakeasy from "speakeasy";
import QRCode from "qrcode";
import pool from "../config/db.js";

export const setupMFA = async (requestAnimationFrame, res) => {
  const secret = speakeasy.generateSecret({
    name: "Enterprise Auth App",
  });

  await pool.query("UPDATE users SET mfa_secret = $1 WHERE id = $2", [
    secret.base32,
    req.user.id,
  ]);

  const qr = await QRCode.toDataURL(secret.otpauth_url);

  res.json({ qr, secret: secret.base32 });
};

export const verifyMFA = async ({ secret, token }) => {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token,
    window: 1,
  });
};
