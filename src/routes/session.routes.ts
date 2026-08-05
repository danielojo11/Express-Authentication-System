import express from "express";
import { getSessions, revokeSession } from "../controllers/session.controller.js";

import { protect } from "../middleware/auth.js";

const router = express.Router();

router.get("/getsessions", getSessions);
router.delete("/:sessionId", protect, revokeSession);

export default router;
