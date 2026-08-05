import bcrypt from "bcrypt";
import crypto from "crypto";
import speakeasy from "speakeasy";

import pool from "../config/db.js";
import {
  generateAccessToken,
  geneateRefreshToken,
  verifyRefreshToken,
  verifyAccessToken,
} from "../utils/jwt.js";
import { parsedevice } from "../utils/fingerprint.js";
import { getGeoData } from "../utils/geo.js";
import { sendMail } from "../utils/mail.js";
import { generateQRCode } from "../utils/qrcode.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const setAuthCookies = (res, refreshToken, sessionId) => {
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax", 
    maxAge: 1000 * 60 * 60 * 24 * 7,
  };
  res.cookie("refreshToken", refreshToken, cookieOptions);
  res.cookie("sessionId", sessionId, cookieOptions);
};

export const register = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  const disposableDomains = [
    "mailinator.com", "10minutemail.com", "tempmail.com",
    "guerrillamail.com", "yopmail.com", "trashmail.com",
  ];

  const domain = email.split("@")[1].toLowerCase();
  if (disposableDomains.includes(domain)) {
    return res.status(400).json({ message: "Disposable emails are not allowed" });
  }

  const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
  if (existingUser.rows.length > 0) {
    return res.status(400).json({ message: "Email is already registered" });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const client = await pool.connect();
  
  try {
    await client.query("BEGIN");

    const result = await client.query(
      `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email`,
      [name, email, hashedPassword]
    );

    const user = result.rows[0];
    const rawToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(rawToken).digest("hex");

    await client.query(
      `INSERT INTO email_verification_token (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 minutes')`,
      [user.id, hashedToken]
    );

    const verificationURL = `${process.env.CLIENT_URL}/api/auth/verify-email?token=${rawToken}`;
    const messageSent = await sendMail(user.email, verificationURL);

    await client.query("COMMIT");

    if (messageSent === "success") {
      res.status(201).json({ message: "User created. Please verify your email.", user });
    } else {
      res.status(400).json({ message: "Error sending Message", user });
    }
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
});

export const login = asyncHandler(async (req, res) => {
  const { email, password, mfaToken } = req.body;

  const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  const user = userResult.rows[0];

  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(401).json({ message: "Invalid credentials" });

  if (user.mfa_enabled && !mfaToken) {
    const loginToken = generateAccessToken(user, { expiresIn: "5m" }, "login");
    return res.status(301).json({
      message: "MFA token required. Redirect to the MFA verification page.",
      loginToken: loginToken,
    });
  }

  const device = parsedevice(req);
  const ip = req.ip;
  const geo = getGeoData(ip);

  const sessionId = crypto.randomUUID();
  const refreshToken = geneateRefreshToken(sessionId);
  const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

  await pool.query(
    `INSERT INTO sessions (
      id, user_id, refresh_token_hash, user_agent, ip_address, device_name, browser, os, country, city, expires_at, is_current
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, NOW() + INTERVAL '7 days', true)`,
    [
      sessionId, user.id, refreshTokenHash, device.useragent, ip, device.device,
      device.browser, device.os, geo.country, geo.city,
    ]
  );

  const accessToken = generateAccessToken(user, {}, "access");
  setAuthCookies(res, refreshToken, sessionId);

  return res.json({
    accessToken,
    user: { id: user.id, email: user.email, name: user.name, mfa_enabled: user.mfa_enabled },
  });
});

export const verifyMfaLogin = asyncHandler(async (req, res) => {
  const { token, loginToken } = req.body;

  const payload = verifyAccessToken(loginToken) as any;
  if (payload.type !== "login") return res.status(401).json({ message: "Invalid login token" });

  const result = await pool.query("SELECT * FROM users WHERE email = $1", [payload.email]);
  const user = result.rows[0];

  if (!user || !user.mfa_enabled) return res.status(404).json({ message: "User not found or MFA not enabled" });

  const verified = speakeasy.totp.verify({ secret: user.mfa_secret, encoding: "base32", token, window: 1 });
  if (!verified) return res.status(401).json({ message: "Invalid MFA code" });

  const device = parsedevice(req);
  const ip = req.ip;
  const geo = getGeoData(ip);

  const sessionId = crypto.randomUUID();
  const refreshToken = geneateRefreshToken(sessionId);
  const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

  await pool.query(
    `INSERT INTO sessions (
      id, user_id, refresh_token_hash, user_agent, ip_address, device_name, browser, os, country, city, expires_at, is_current
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, NOW() + INTERVAL '7 days', true)`,
    [
      sessionId, user.id, refreshTokenHash, device.useragent, ip, device.device,
      device.browser, device.os, geo.country, geo.city,
    ]
  );

  const accessToken = generateAccessToken(user, {}, "access");
  setAuthCookies(res, refreshToken, sessionId);

  return res.json({
    accessToken,
    user: { id: user.id, email: user.email, name: user.name, mfa_enabled: user.mfa_enabled },
  });
});

export const refresh = asyncHandler(async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: "No refresh token" });

  const decoded = verifyRefreshToken(token) as any;
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  const sessionResult = await pool.query(
    `SELECT * FROM sessions WHERE id = $1 AND refresh_token_hash = $2 AND revoked = false`,
    [decoded.sessionId, hashedToken]
  );
  const session = sessionResult.rows[0];
  if (!session) return res.status(401).json({ message: "Invalid session" });

  const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [session.user_id]);
  const user = userResult.rows[0];

  const newSessionId = crypto.randomUUID();
  const newRefreshToken = geneateRefreshToken(newSessionId);
  const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");

  await pool.query(
    `INSERT INTO sessions (
      id, user_id, refresh_token_hash, user_agent, ip_address, device_name, browser, os, country, city, expires_at, is_current
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, NOW() + INTERVAL '7 days', true)`,
    [
      newSessionId, session.user_id, newRefreshTokenHash, session.user_agent, session.ip_address,
      session.device_name, session.browser, session.os, session.country, session.city,
    ]
  );

  await pool.query("UPDATE sessions SET revoked = true WHERE id = $1", [session.id]);

  const accessToken = generateAccessToken(user, {}, "access");
  setAuthCookies(res, newRefreshToken, newSessionId);

  return res.json({ accessToken });
});

export const logout = asyncHandler(async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(204);

  try {
    const decoded = verifyRefreshToken(token) as any;
    await pool.query("UPDATE sessions SET revoked = true WHERE id = $1", [decoded.sessionId]);
  } catch (err) {}

  res.clearCookie("refreshToken");
  res.clearCookie("sessionId");
  return res.json({ message: "Logged out" });
});

export const setupMFA = asyncHandler(async (req, res) => {
  const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
  const user = userResult.rows[0];

  if (!user) return res.status(404).json({ message: "User not found" });
  if (user.mfa_enabled) return res.status(400).json({ message: "MFA already enabled" });

  const secret = speakeasy.generateSecret({ length: 20 });
  await pool.query("UPDATE users SET mfa_secret = $1 WHERE id = $2", [secret.base32, user.id]);

  const qrCode = await generateQRCode("Auth System", user.email, secret.base32);
  return res.status(200).json({ qrCode });
});

export const enableMFA = asyncHandler(async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "MFA code required" });

  const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
  const user = result.rows[0];

  if (!user || !user.mfa_secret) return res.status(400).json({ message: "MFA has not been setup." });

  const verified = speakeasy.totp.verify({ secret: user.mfa_secret, encoding: "base32", token, window: 1 });
  if (!verified) return res.status(400).json({ message: "Invalid MFA code" });

  await pool.query(`UPDATE users SET mfa_enabled = true WHERE id = $1`, [user.id]);
  return res.status(200).json({ message: "MFA enabled successfully", mfaEnabled: true });
});

export const disableMFA = asyncHandler(async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "MFA code required" });

  const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
  const user = result.rows[0];

  if (!user.mfa_enabled) return res.status(400).json({ message: "MFA is not enabled." });

  const verified = speakeasy.totp.verify({ secret: user.mfa_secret, encoding: "base32", token, window: 1 });
  if (!verified) return res.status(400).json({ message: "Invalid MFA code" });

  await pool.query(`UPDATE users SET mfa_enabled = false, mfa_secret = null WHERE id = $1`, [user.id]);
  return res.status(200).json({ message: "MFA disabled successfully" });
});

export const updateUser = asyncHandler(async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ message: "Nothing to update" });

  await pool.query("UPDATE users SET name = $1 WHERE id = $2", [name, req.user.id]);
  return res.json({ message: "User updated successfully" });
});

export const updatePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const result = await pool.query("SELECT password FROM users WHERE id = $1", [req.user.id]);
  const user = result.rows[0];

  const validPassword = await bcrypt.compare(oldPassword, user.password);
  if (!validPassword) return res.status(401).json({ message: "Invalid old password" });

  const hashedPassword = await bcrypt.hash(newPassword, 12);
  await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, req.user.id]);

  return res.json({ message: "Password updated successfully" });
});

export const deleteUser = asyncHandler(async (req, res) => {
  await pool.query("DELETE FROM users WHERE id = $1", [req.user.id]);
  res.clearCookie("refreshToken");
  res.clearCookie("sessionId");
  return res.json({ message: "User deleted successfully" });
});

export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  const user = result.rows[0];

  if (!user) return res.status(404).json({ message: "User not found" });

  const rawToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(rawToken).digest("hex");

  await pool.query(
    `INSERT INTO password_reset_token (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')`,
    [user.id, hashedToken]
  );

  const resetURL = `${process.env.CLIENT_URL}/api/auth/reset-password?token=${rawToken}`;
  const messageSent = await sendMail(user.email, resetURL);

  if (messageSent === "success") {
    res.status(200).json({ message: "Password reset link sent to your email" });
  } else {
    res.status(400).json({ message: "Error sending Message" });
  }
});

export const resetPassword = asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  
  const tokenResult = await pool.query(
    "SELECT * FROM password_reset_token WHERE token = $1 AND expires_at > NOW()", 
    [hashedToken]
  );
  const resetToken = tokenResult.rows[0];

  if (!resetToken) return res.status(400).json({ message: "Invalid or expired token" });

  const hashedPassword = await bcrypt.hash(newPassword, 12);
  await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, resetToken.user_id]);
  await pool.query("DELETE FROM password_reset_token WHERE token = $1", [hashedToken]);

  res.status(200).json({ message: "Password reset successful" });
});
