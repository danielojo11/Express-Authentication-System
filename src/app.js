import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import dotenv from "dotenv";

import pool from "./config/db.js";

import authRoutes from "./routes/auth.routes.js";
import sesssionRoutes from "./routes/session.routes.js";
import oauthRoutes from "./routes/oauth.routes.js";

dotenv.config();

const app = express();

const PgSession = connectPgSimple(session);
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
    store: new PgSession({
      pool,
      tableName: "user_sesssions",
    }),

    secret: process.env.SESSION_SECRET,

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24,
    },
  }),
);

app.use("/api/auth", authRoutes);
app.use("/api/sessions", sesssionRoutes);
app.use("/api/oauth", oauthRoutes);

export default app;
