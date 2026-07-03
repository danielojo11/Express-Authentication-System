import express from "express";

import { register, login, refresh, logout } from "../controllers/auth.controller.js";
import verifyEmail from "../controllers/mail.controllers.js";
import { authLimiter } from "../middleware/rateLimiter.js";
import { setupMFA, verifyMFA } from "../controllers/auth.controller.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", authLimiter, login);
router.post("/login/mfa", verifyMFA);
router.post("/refresh", refresh);
router.post("/logout", logout);
router.get("/verify-email", verifyEmail);
router.post("/mfa/setup", setupMFA);
router.post("/mfa/verify", verifyMFA);

export default router;
