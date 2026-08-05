import { z } from "zod";
export const registerSchema = z.object({
    body: z.object({
        name: z.string().min(2, "Name must be at least 2 characters"),
        email: z.string().email("Invalid email address"),
        password: z.string().min(8, "Password must be at least 8 characters"),
    }),
});
export const loginSchema = z.object({
    body: z.object({
        email: z.string().email("Invalid email address"),
        password: z.string().min(1, "Password is required"),
        mfaToken: z.string().optional(),
    }),
});
export const mfaVerifySchema = z.object({
    body: z.object({
        token: z.string().min(1, "Token is required"),
        loginToken: z.string().optional(),
    }),
});
export const updatePasswordSchema = z.object({
    body: z.object({
        oldPassword: z.string().min(1, "Old password is required"),
        newPassword: z.string().min(8, "New password must be at least 8 characters"),
    }),
});
export const updateUserSchema = z.object({
    body: z.object({
        name: z.string().min(2, "Name must be at least 2 characters").optional(),
    }),
});
export const forgotPasswordSchema = z.object({
    body: z.object({
        email: z.string().email("Invalid email address"),
    }),
});
export const resetPasswordSchema = z.object({
    body: z.object({
        token: z.string().min(1, "Token is required"),
        newPassword: z.string().min(8, "New password must be at least 8 characters"),
    }),
});
