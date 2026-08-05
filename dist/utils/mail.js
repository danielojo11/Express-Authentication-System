import transporter from "../config/mail.js";
export const sendMail = async (user_email, verificationURL) => {
    try {
        await transporter.sendMail({
            from: `"My App" <${process.env.SMTP_USER}>`,
            to: user_email,
            subject: "Verify your email address",
            html: `
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify your email</title>
            </head>

            <body style="
            margin:0;
            padding:40px 20px;
            background:#f5f7fb;
            font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
            color:#111827;
            ">

            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr>
            <td align="center">

            <table role="presentation"
            width="560"
            cellspacing="0"
            cellpadding="0"
            style="
            background:#ffffff;
            border-radius:18px;
            padding:56px 48px;
            box-shadow:0 12px 40px rgba(17,24,39,.06);
            ">

            <tr>
            <td>

            <div style="
            width:52px;
            height:52px;
            border-radius:14px;
            background:#2563eb;
            text-align:center;
            line-height:52px;
            font-size:24px;
            font-weight:700;
            color:white;
            margin-bottom:32px;
            ">
            ✓
            </div>

            <p style="
            margin:0;
            font-size:14px;
            font-weight:600;
            letter-spacing:.08em;
            text-transform:uppercase;
            color:#2563eb;
            ">
            Email Verification
            </p>

            <h1 style="
            margin:14px 0 20px;
            font-size:34px;
            font-weight:700;
            line-height:1.2;
            color:#111827;
            ">
            Welcome to My App
            </h1>

            <p style="
            margin:0;
            font-size:17px;
            line-height:1.8;
            color:#4b5563;
            ">
            Thanks for signing up.
            Before you can start using your account, we just need to confirm that this email address belongs to you.
            </p>

            <table
            role="presentation"
            cellspacing="0"
            cellpadding="0"
            style="margin:42px 0;">
            <tr>
            <td>

            <a
            href="${verificationURL}"
            style="
            background:#2563eb;
            color:#ffffff;
            padding:16px 34px;
            border-radius:12px;
            font-weight:600;
            font-size:16px;
            text-decoration:none;
            display:inline-block;
            ">
            Verify Email
            </a>

            </td>
            </tr>
            </table>

            <div style="
            background:#f8fafc;
            border:1px solid #e5e7eb;
            border-radius:12px;
            padding:20px;
            margin-bottom:34px;
            ">

            <p style="
            margin:0;
            font-size:15px;
            line-height:1.7;
            color:#4b5563;
            ">
            This verification link will expire in
            <strong style="color:#111827;">30 minutes</strong>.
            If it expires, simply request another verification email.
            </p>

            </div>

            <p style="
            margin:0 0 14px;
            font-size:15px;
            color:#6b7280;
            ">
            If the button above doesn't work, copy and paste this link into your browser:
            </p>

            <div style="
            background:#f9fafb;
            border:1px solid #e5e7eb;
            padding:16px;
            border-radius:10px;
            font-size:13px;
            word-break:break-all;
            line-height:1.7;
            color:#2563eb;
            ">
            ${verificationURL}
            </div>

            <hr style="
            margin:42px 0;
            border:none;
            border-top:1px solid #eceff3;
            ">

            <p style="
            margin:0;
            font-size:14px;
            line-height:1.8;
            color:#6b7280;
            ">
            Didn't create an account?
            You can safely ignore this email. No changes will be made unless the address is verified.
            </p>

            </td>
            </tr>

            <tr>
            <td style="padding-top:50px;">

            <p style="
            margin:0;
            font-size:13px;
            color:#9ca3af;
            text-align:center;
            ">
            © ${new Date().getFullYear()} My App
            </p>

            </td>
            </tr>

            </table>

            </td>
            </tr>
            </table>

            </body>
            </html>
            `,
        });
        return "success";
    }
    catch (error) {
        return "error";
    }
};
