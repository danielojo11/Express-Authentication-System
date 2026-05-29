import rateLimit from "express-rate-limit";

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,

  message: {
    message: "Too many login attempts",
  },

  standardHeaders: true,
  legacyHeaders: true,
});
