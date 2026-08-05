import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

try {
  await transporter.verify();
  console.log("SMTP Connection verified successfully.");
} catch (error) {
  console.warn("SMTP Verification failed (Email features may not work):", error.message);
}
export default transporter;
