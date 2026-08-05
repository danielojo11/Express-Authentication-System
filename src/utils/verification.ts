import crypto from "crypto";

const generateEmailVerificationToken = () => {
  const token = crypto.randomBytes(32).toString("hex");

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  return hashedToken;
};

const generateOtpToken = () => {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  return otp;
};

export { generateEmailVerificationToken, generateOtpToken };
