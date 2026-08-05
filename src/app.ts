import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import session from "express-session";
import { RedisStore } from "connect-redis";
import Redis from "ioredis";
import dotenv from "dotenv";
import swaggerUi from "swagger-ui-express";
import YAML from "yamljs";
import path from "path";

import pool from "./config/db.js";

import authRoutes from "./routes/auth.routes.js";
import sesssionRoutes from "./routes/session.routes.js";
import oauthRoutes from "./routes/oauth.routes.js";

dotenv.config();

const app = express();

const RedisClient: any = Redis;
const redisClient = new RedisClient(process.env.REDIS_URL || "redis://localhost:6379");

app.use(helmet());
app.use(
  cors({
    origin: "*",
    credentials: false,
  }),
);

app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    store: new RedisStore({
      client: redisClient,
      prefix: "sess:",
    }),
    secret: process.env.SESSION_SECRET || "fallback_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  }),
);

import { errorHandler } from "./middleware/errorHandler.js";

app.use("/api/auth", authRoutes);
app.use("/api/sessions", sesssionRoutes);
app.use("/api/oauth", oauthRoutes);

const swaggerDocument = YAML.load(path.join(process.cwd(), "docs/swagger.yml"));
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use(errorHandler);

export default app;
