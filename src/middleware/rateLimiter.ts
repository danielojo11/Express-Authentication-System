import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import Redis from "ioredis";
import dotenv from "dotenv";
dotenv.config();

const RedisClient: any = Redis;
const redisClient = new RedisClient(process.env.REDIS_URL || "redis://localhost:6379");

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    message: "Too many login attempts",
  },
  standardHeaders: true,
  legacyHeaders: true,
  store: new RedisStore({
    sendCommand: (...args: string[]) => redisClient.call(...args),
  }),
});
