import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import pool from "./db.js";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "api/oauth/google/callback",
    },

    async (verifyAccessToken, verifyRefreshToken, profile, done) => {
      try {
        const existing = await pool.query(
          "SELECT * FROM users WHERE oauth_id = $1",
          [profile.id],
        );
        if (existing.rows[0]) {
          return done(null, existing.rows[0]);
        }

        const newUser = await pool.query(
          "INSERT INTO users (name, email, oauth_provider, oauth_id) VALUES ($1,$2,$3,$4) RETURNING *",
          [profile.displayName, profile.emails[0].value, "google", profile.id],
        );

        done(null, newUser.rows[0]);
      } catch (error) {
        done(error, null);
      }
    },
  ),
);
