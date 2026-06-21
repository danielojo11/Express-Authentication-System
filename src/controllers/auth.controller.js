import bcrypt from "bcrypt";
import crypto from "crypto";

import pool from "../config/db.js";

import {
  generateAccessToken,
  geneateRefreshToken,
  verifyRefreshToken,
} from "../utils/jwt.js";

import { parsedevice } from "../utils/fingerprint.js";

import { getGeoData } from "../utils/geo.js";
import { detectSuspiciousLogin } from "../middleware/suspiciousLogin.js";

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashedPassword],
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      message: `${error.message}+++`,
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password, mfaToken } = req.body;
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email],
    );
    const user = userResult.rows[0];

    if (!user) {
      return res.status(401).json({
        message: "Invalid Credentials",
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: "Invalid Credentials" });
    }

    if (user.mfa_enabled) {
      const speakeasy = await import("speakeasy");

      const verified = speakeasy.default.totp.verify({
        secret: user.mfa_secret,
        encoding: "base32",
        token: mfaToken,
      });

      if (!verified) {
        return res.status(401).json({
          message: "Invalid MFA Code",
        });
      }
    }

    const device = parsedevice(req);
    const ip = req.ip;
    const geo = getGeoData(ip);

    const suspicious = await detectSuspiciousLogin({
      userId: user.id,
      country: geo.country,
      ip,
    });

    if (suspicious) {
      console.log("Suspicious Login Detected");
    }

    const sessionId = crypto.randomUUID();

    const refreshToken = geneateRefreshToken(sessionId);

    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    await pool.query(
      "INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, device_name, browser, os, country, city, expires_at, is_current) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, NOW() + INTERVAL '7 days', true)",
      [
        sessionId,
        user.id,
        refreshTokenHash,
        device.useragent,
        ip,
        device.device,
        device.browser,
        device.os,
        geo.country,
        geo.city,
      ],
    );

    const accessToken = generateAccessToken(user);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    return res.json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: `${error.message}---`,
    });
  }
};

export const refresh = async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) {
      return res.status(401).json({
        message: "No Refresh Token",
      });
    }

    const decoded = verifyRefreshToken(token);

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const sessionResult = await pool.query(
      "SELECT * FROM sessions WHERE id = $1 AND refresh_token_hash = $2 AND revoked = false",
      [decoded.sessionId, hashedToken],
    );

    const session = sessionResult.rows[0];

    if (!session) {
      return res.status(401).json({
        message: "Invalid Session",
      });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
      session.user_id,
    ]);
    const newSessionId = crypto.randomUUID();
    const newRefreshToken = geneateRefreshToken(newSessionId);

    const newRefreshTokenHash = crypto
      .createHash("sha256")
      .update(newRefreshToken)
      .digest("hex");

    await pool.query(
      `
      INSERT INTO sessions (
        id,
        user_id,
        refresh_token_hash,
        user_agent,
        ip_address,
        device_name,
        browser,
        os,
        country,
        city,
        expires_at,
        is_current
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        NOW() + INTERVAL '7 days',
        true
      )
    `,
      [
        newSessionId,
        session.user_id,
        newRefreshTokenHash,
        session.user_agent,
        session.ip_address,
        session.device_name,
        session.browser,
        session.os,
        session.country,
        session.city,
      ],
    );

    const accessToken = generateAccessToken(user);

    res.cookie("refreshToken", newRefreshTOken, {
      httpOnly: true,
      secure: false,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    res.json({
      accessToken,
    });
  } catch (error) {
    res.status(401).json({
      message: "Refresh Failed",
    });
  }
};

export const logout = async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) {
    return res.sendStatus(204);
  }

  try {
    const decoded = verifyRefreshToken(token);

    await pool.query("UPDATE sessions SET revoked = true WHERE id = $1", [
      decoded.sessionId,
    ]);

    res.clearCookie("refreshToken");
    res.json({
      message: "Logged Out",
    });
  } catch (error) {
    res.sendStatus(204);
  }
};
