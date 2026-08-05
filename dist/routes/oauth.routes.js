import express from "express";
import passport from "passport";
import crypto from "crypto";
import pool from "../config/db.js";
import { generateAccessToken, geneateRefreshToken } from "../utils/jwt.js";
const router = express.Router();
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
router.get("/google", passport.authenticate("google", {
    scope: ["profile", "email"],
}));
router.get("/google/callback", passport.authenticate("google", {
    session: false,
    failureRedirect: "/login",
}), async (req, res) => {
    try {
        const user = req.user;
        const sessionId = crypto.randomUUID();
        const refreshToken = geneateRefreshToken(sessionId);
        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
        await pool.query(`INSERT INTO sessions (
          id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, is_current
        ) VALUES ($1,$2,$3,$4,$5, NOW() + INTERVAL '7 days', true)`, [
            sessionId, user.id, refreshTokenHash, req.headers["user-agent"], req.ip
        ]);
        const accessToken = generateAccessToken(user, {}, "access");
        setAuthCookies(res, refreshToken, sessionId);
        res.redirect(`${process.env.CLIENT_URL || "http://localhost:8080"}/dashboard?token=${accessToken}`);
    }
    catch (err) {
        console.error(err);
        res.redirect("/login?error=oauth_failed");
    }
});
export default router;
