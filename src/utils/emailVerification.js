import crypto from "crypto";

const generateEmailVerificationToken = () => {
  const token = crypto.randomBytes(32).toString("hex");

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  return hashedToken;
};

export default generateEmailVerificationToken;
