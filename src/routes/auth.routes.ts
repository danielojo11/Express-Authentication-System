import express from "express";

import { 
  register, login, refresh, logout, 
  setupMFA, verifyMfaLogin, enableMFA, disableMFA,
  updateUser, updatePassword, deleteUser,
  forgotPassword, resetPassword
} from "../controllers/auth.controller.js";
import verifyEmail from "../controllers/mail.controllers.js";
import { authLimiter } from "../middleware/rateLimiter.js";
import { protect } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import { 
  registerSchema, loginSchema, mfaVerifySchema, 
  updatePasswordSchema, updateUserSchema,
  forgotPasswordSchema, resetPasswordSchema
} from "../utils/validators.js";

const router = express.Router();

router.post("/register", validate(registerSchema), register);
router.post("/login", authLimiter, validate(loginSchema), login);
router.post("/login/mfa", validate(mfaVerifySchema), verifyMfaLogin);
router.post("/refresh", protect, refresh);
router.post("/logout", protect, logout);
router.get("/verify-email", protect, verifyEmail);

router.post("/forgot-password", validate(forgotPasswordSchema), forgotPassword);
router.post("/reset-password", validate(resetPasswordSchema), resetPassword);

router.post("/mfa/setup", protect, setupMFA);
router.post("/mfa/enable", protect, validate(mfaVerifySchema), enableMFA);
router.post("/mfa/disable", protect, validate(mfaVerifySchema), disableMFA);

router.put("/user", protect, validate(updateUserSchema), updateUser);
router.put("/user/password", protect, validate(updatePasswordSchema), updatePassword);
router.delete("/user", protect, deleteUser);

export default router;
