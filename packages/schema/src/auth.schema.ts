import * as z from 'zod';

export const RegisterSchema = z.object({
    email: z.email(),
    username: z.string().min(3),
    password: z.string().min(6),
    name: z.string().optional(),
});

export const RegisterFormSchema = RegisterSchema.extend({
    password2: z.string().min(1, 'Confirm password'),
}).refine((data) => data.password === data.password2, {
    error: 'Passwords do not match',
    path: ['password2'],
});

export const LoginSchema = z.object({
    login: z.string().min(1, { error: 'Enter email or username' }),
    password: z.string().min(1),
});

export type RegisterInput = z.infer<typeof RegisterSchema>;
export type RegisterFormInput = z.infer<typeof RegisterFormSchema>;
export type LoginInput = z.infer<typeof LoginSchema>;
