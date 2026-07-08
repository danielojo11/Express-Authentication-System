import { verifyAccessToken } from "../utils/jwt.js";

export const protect = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = verifyAccessToken(token);
    if (decoded.type !== "access") {
      return res.status(401).json({ message: "Invalid Token Type. Access Denied" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid Token" });
    next(error);
  }
};
