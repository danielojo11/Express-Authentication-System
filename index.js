import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

import authRouter from "./auth/auth.js";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth", authRouter);

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`Server started @ ${PORT}`);
});
