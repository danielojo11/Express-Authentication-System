import express from "express";
import register from "./handlers/register.js";
import login from "./handlers/login.js";
import logout from "./handlers/logout.js";
import getMe from "./handlers/get-me.js";
import isAuthenticated from "./middleware/protected.js";

const authRouter = express.Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/logout", logout);
authRouter.get("/get-me", isAuthenticated, getMe);

export default authRouter;
