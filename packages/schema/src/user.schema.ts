import * as z from 'zod';

export const UserSchema = z.object({
    id: z.string(),
    email: z.email(),
    username: z.string().min(3),
    role: z.enum(['USER', 'ADMIN']),
    createdAt: z.string(),
    name: z.string().optional(),
    avatar: z.string().optional(),
    bio: z.string().optional(),
});

export const PublicUserSchema = UserSchema.pick({
    id: true,
    username: true,
    name: true,
    avatar: true,
    bio: true,
});

export const UpdateProfileSchema = UserSchema.pick({
    bio: true,
    name: true,
}).refine((data) => data.name !== undefined || data.bio !== undefined, {
    message: "At least one of 'name' or 'bio' must be filled.",
    path: ['root'],
});

export type User = z.infer<typeof UserSchema>;
export type PublicUser = z.infer<typeof PublicUserSchema>;
export type UpdateProfileInput = z.infer<typeof UpdateProfileSchema>;
