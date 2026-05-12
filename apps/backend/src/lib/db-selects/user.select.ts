export const publicUserSelect = {
    id: true,
    email: true,
    username: true,
    role: true,
    createdAt: true,
    name: true,
    avatar: true,
    bio: true,
} as const;

export const conversationUserSelect = {
    id: true,
    username: true,
    name: true,
    avatar: true,
} as const;
