import { verifyAccessToken } from "../utils/jwt.js";

export const protect = (req, res, next) => {
  try {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const token = authorization.split(" ")[1];
    const decoded = verifyAccessToken(token) as any;
    
    if (decoded.type !== "access") {
      return res.status(401).json({ message: "Unauthorized. Access Denied" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid Token" });
  }
};
