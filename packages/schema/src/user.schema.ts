import * as z from 'zod';

export const UserSchema = z.object({
    id: z.string(),
    email: z.email(),
    username: z.string().min(3),
    role: z.enum(['USER', 'ADMIN']),
    createdAt: z.string(),
    name: z.string().optional(),
    avatar: z.string().optional(),
});

export type User = z.infer<typeof UserSchema>;
