import bcrypt from "bcrypt";
import crypto from "crypto";

import pool from "../config/db.js";
import {
  generateAccessToken,
  geneateRefreshToken,
  verifyRefreshToken,
  verifyAccessToken,
} from "../utils/jwt.js";

import { parsedevice } from "../utils/fingerprint.js";
import { getGeoData } from "../utils/geo.js";
import { detectSuspiciousLogin } from "../middleware/suspiciousLogin.js";
import transporter from "../config/mail.js";
import { generateQRCode } from "../utils/qrcode.js";

import speakeasy from "speakeasy";
import fs from "fs/promises";

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const disposableDomains = [
      "mailinator.com",
      "10minutemail.com",
      "tempmail.com",
      "guerrillamail.com",
      "yopmail.com",
      "trashmail.com",
    ];

    if (!name || typeof name !== "string") {
      return res.status(400).json({ message: "Invalid name" });
    }

    if (!email || typeof email !== "string") {
      return res.status(400).json({ message: "Invalid email" });
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const domain = email.split("@")[1].toLowerCase();
    if (new Set(disposableDomains).has(domain)) {
      return res.status(400).json({
        message: "Disposable emails are not allowed",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, name, email`,
      [name, email, hashedPassword],
    );

    const user = result.rows[0];
    const rawToken = crypto.randomBytes(32).toString("hex");
    const user_email = result.rows[0].email;
    const hashedEmail = crypto.createHash("sha256").update(user_email).digest("hex");
    const hashedToken = crypto.createHash("sha256").update(rawToken).digest("hex");

    await pool.query(
      `INSERT INTO email_verification_token
      (user_id, token, expires_at)
      VALUES ($1, $2, NOW() + INTERVAL '30 minutes')`,
      [user.id, hashedToken],
    );

    const verificationURL = `${process.env.CLIENT_URL}/api/auth/verify-email?token=${rawToken}`;

    await transporter.sendMail({
      from: `"My App" <${process.env.SMTP_USER}>`,
      to: user_email,
      subject: "Verify your email address",
      html: `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify your email</title>
</head>

<body style="margin:0;padding:0;background:#f4f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;background:#f4f7fb;">
<tr>
<td align="center">

<table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.08);">

<tr>
<td style="background:#111827;padding:32px;text-align:center;">

<h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:700;">
My App
</h1>

<p style="margin-top:10px;color:#cbd5e1;font-size:15px;">
Secure Authentication Platform
</p>

</td>
</tr>

<tr>
<td style="padding:48px;">

<h2 style="margin-top:0;color:#111827;font-size:30px;">
Verify your email
</h2>

<p style="font-size:16px;line-height:1.7;color:#4b5563;">
Thanks for creating your account.
To complete your registration and activate your account,
please verify your email address.
</p>

<table cellpadding="0" cellspacing="0" style="margin:40px auto;">
<tr>
<td align="center">

<a href="${verificationURL}"
style="
display:inline-block;
padding:16px 34px;
background:#2563eb;
color:#ffffff;
text-decoration:none;
font-size:16px;
font-weight:600;
border-radius:10px;
">
Verify Email
</a>

</td>
</tr>
</table>

<p style="font-size:15px;color:#6b7280;line-height:1.7;">
This verification link expires in
<strong>30 minutes</strong>.
</p>

<p style="font-size:15px;color:#6b7280;line-height:1.7;">
If the button doesn't work, copy and paste this URL into your browser:
</p>

<p style="
word-break:break-all;
background:#f3f4f6;
padding:16px;
border-radius:8px;
font-size:14px;
color:#2563eb;
">
${verificationURL}
</p>

<hr style="margin:40px 0;border:none;border-top:1px solid #e5e7eb;">

<p style="font-size:14px;color:#6b7280;line-height:1.7;">
If you didn't create an account with My App,
you can safely ignore this email.
No account will be created unless this email is verified.
</p>

</td>
</tr>

<tr>
<td style="background:#f9fafb;padding:30px;text-align:center;">

<p style="margin:0;font-size:13px;color:#9ca3af;">
© ${new Date().getFullYear()} My App. All rights reserved.
</p>

<p style="margin-top:10px;font-size:13px;color:#9ca3af;">
Built with security and privacy in mind.
</p>

</td>
</tr>

</table>

</td>
</tr>
</table>

</body>
</html>
`,
    });

    return res.status(201).json({
      message: "User created. Please verify your email.",
      user,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: error.message,
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password, mfaToken } = req.body;

    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    const user = userResult.rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const device = parsedevice(req);
    const ip = req.ip;
    const geo = getGeoData(ip);

    await detectSuspiciousLogin({
      userId: user.id,
      country: geo.country,
      ip,
    });

    if (user.mfa_enabled && !mfaToken) {
      const loginToken = generateAccessToken(user, { expiresIn: "5m" }, "login");
      return res.status(301).json({
        message: "MFA token required. Redirect to the MFA verification page.",
        loginToken: loginToken,
        // url: `${process.env.CLIENT_URL}/mfa-verify`,
      });
    }

    const sessionId = crypto.randomUUID();

    const refreshToken = geneateRefreshToken(sessionId);

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    await pool.query(
      `INSERT INTO sessions (
        id, user_id, refresh_token_hash,
        user_agent, ip_address,
        device_name, browser, os,
        country, city,
        expires_at, is_current
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        NOW() + INTERVAL '7 days',
        true
      )`,
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
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    res.cookie("sessionId", sessionId, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    return res.json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        mfa_enabled: user.mfa_enabled,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: error.message,
    });
  }
};

export const refresh = async (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      return res.status(401).json({ message: "No refresh token" });
    }

    const decoded = verifyRefreshToken(token);

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const sessionResult = await pool.query(
      `SELECT * FROM sessions
       WHERE id = $1 AND refresh_token_hash = $2 AND revoked = false`,
      [decoded.sessionId, hashedToken],
    );

    const session = sessionResult.rows[0];

    if (!session) {
      return res.status(401).json({ message: "Invalid session" });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [session.user_id]);

    const user = userResult.rows[0];

    const newSessionId = crypto.randomUUID();

    const newRefreshToken = geneateRefreshToken(newSessionId);

    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");

    await pool.query(
      `INSERT INTO sessions (
        id, user_id, refresh_token_hash,
        user_agent, ip_address,
        device_name, browser, os,
        country, city,
        expires_at, is_current
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        NOW() + INTERVAL '7 days',
        true
      )`,
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

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    return res.json({ accessToken });
  } catch (error) {
    return res.status(401).json({
      message: "Refresh failed",
    });
  }
};

export const logout = async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) return res.sendStatus(204);

  try {
    const decoded = verifyRefreshToken(token);

    await pool.query("UPDATE sessions SET revoked = true WHERE id = $1", [decoded.sessionId]);

    res.clearCookie("refreshToken");
    res.clearCookie("sessionId");

    return res.json({ message: "Logged out" });
  } catch (error) {
    return res.sendStatus(204);
  }
};

export const setupMFA = async (req, res) => {
  try {
    const authorization = req.headers.authorization;

    if (!authorization) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    const accessToken = authorization.split(" ")[1];

    const payload = verifyAccessToken(accessToken);
    console.log("payload", payload);

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [payload.id]);

    const user = userResult.rows[0];
    console.log("user", user);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.mfa_enabled) {
      return res.status(400).json({
        message: "MFA already enabled",
      });
    }

    const secret = speakeasy.generateSecret({
      length: 20,
    });

    await pool.query("UPDATE users SET mfa_secret = $1 WHERE id = $2", [secret.base32, user.id]);

    const qrCode = await generateQRCode("Auth System", user.email, secret.base32);

    // await fs.writeFile("qrcode.png", qrCode.replace(/^data:image\/png;base64,/, ""), "base64");

    return res.status(200).json({
      qrCode,
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message: "Failed to setup MFA",
    });
  }
};

export const verifyMFA = async (req, res) => {
  try {
    const authorization = req.headers.authorization;
    const { token, loginToken } = req.body;

    // if (!authorization) {
    //   return res.status(401).json({ message: "Unauthorized" });
    // }

    if (!token) {
      return res.status(400).json({ message: "MFA code required" });
    }

    // const accessToken = authorization.split(" ")[1];
    const payload = verifyAccessToken(loginToken);

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [payload.email]);

    const user = result.rows[0];

    if (payload.type === "login") {
      const sessionId = crypto.randomUUID();

      const refreshToken = geneateRefreshToken(sessionId);

      const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

      const device = parsedevice(req);
      const ip = req.ip;
      const geo = getGeoData(ip);

      await pool.query(
        `INSERT INTO sessions (
        id, user_id, refresh_token_hash,
        user_agent, ip_address,
        device_name, browser, os,
        country, city,
        expires_at, is_current
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        NOW() + INTERVAL '7 days',
        true
      )`,
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
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24 * 7,
      });

      res.cookie("sessionId", sessionId, {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24 * 7,
      });

      return res.json({
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          mfa_enabled: user.mfa_enabled,
        },
      });
      return res.status(200).json({
        message: "MFA verified successfully. User Logged in",
      });
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.mfa_secret) {
      return res.status(400).json({
        message: "MFA has not been setup.",
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(400).json({
        message: "Invalid MFA code",
      });
    }

    await pool.query(
      `UPDATE users
       SET mfa_enabled = true,
           mfa_enabled_at = NOW(),
           mfa_verified_at = NOW()
       WHERE id = $1`,
      [user.id],
    );

    return res.status(200).json({
      message: "MFA enabled successfully",
      mfaEnabled: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};

export const disableMFA = async (req, res) => {
  try {
    const authorization = req.headers.authorization;
    const { token } = req.body;

    if (!authorization) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    const accessToken = authorization.split(" ")[1];

    const payload = verifyAccessToken(accessToken);
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [payload.email]);
    const user = result.rows[0];

    if (!user.mfa_enabled) {
      return res.status(400).json({
        message: "MFA has not been setup.",
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(400).json({
        message: "Invalid MFA code",
      });
    }

    await pool.query(
      `UPDATE users
       SET mfa_enabled = false,
           mfa_secret = null,
           mfa_enabled_at = null,
           mfa_verified_at = null
       WHERE id = $1`,
      [user.id],
    );
    return res.status(200).json({
      message: "MFA disabled successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: error.message,
    });
  }
};

export const updatePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const authorization = req.headers.authorization;
  const token = authorization.split(" ")[1];

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      message: "Current and new password are required",
    });
  }

  if (currentPassword === newPassword) {
    return res.status(400).json({
      message: "New password cannot be the same as the current password",
    });
  }

  const user = verifyAccessToken(token);
  const userEmail = user.email;
  const currentPasswordhash = await bcrypt.hash(currentPassword, 12);

  const result = await pool.query("SELECT * FROM users WHERE email = $1", [userEmail]);
  const dbUser = result.rows[0];

  const isPasswordSame = await bcrypt.compare(currentPassword, dbUser.password);

  if (!isPasswordSame) {
    return res.status(400).json({
      message: "Current password is incorrect",
    });
  }

  const newPasswordHash = await bcrypt.hash(newPassword, 12);

  const updatePassword = await pool.query("UPDATE users SET password = $1 WHERE email = $2", [
    newPasswordHash,
    userEmail,
  ]);

  return res.status(200).json({
    message: "Password Updated Successfully",
  });
};

export const updateUser = async (req, res) => {
  const { name, email, bio } = req.body;
  const authorization = req.headers.authorization;
  const token = authorization.split(" ")[1];

  const user = verifyAccessToken(token);
  const userEmail = user.email;

  if (name === user.name && email === user.email && bio === user.bio) {
    return res.status(400).json({
      message: "No changes to update",
    });
  }

  const update = {};
  if (email && email !== user.email) {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        message: "Invalid email format",
      });
    }
    update.email = email;
  }
  if (name && name !== user.name) {
    update.name = name;
  }
  if (bio && bio !== user.bio) {
    update.bio = bio;
  }

  const result = await pool.query(
    "UPDATE users SET name = $1, email = $2, bio = $3 WHERE email = $4 RETURNING *",
    [update.name || user.name, update.email || user.email, update.bio || user.bio, userEmail],
  );

  return res.status(200).json({
    message: "User updated successfully",
  });
};
