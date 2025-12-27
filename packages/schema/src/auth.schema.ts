import * as z from 'zod';

export const RegisterSchema = z.object({
    email: z.email(),
    username: z.string().min(3),
    password: z.string().min(6),
});

export const LoginSchema = z.object({
    login: z.string().min(1, { error: 'Enter email or username' }),
    password: z.string().min(1),
});

export type RegisterInput = z.infer<typeof RegisterSchema>;
export type LoginInput = z.infer<typeof LoginSchema>;
