import * as z from 'zod';
import { PublicUserSchema } from './user.schema';

export const SendMessageSchema = z.object({
    content: z.string(),
});

export const MessagePreviewSchema = z.object({
    id: z.string(),
    content: z.string(),
    senderId: z.string(),
    conversationId: z.string(),
    createdAt: z.string(),
});

export const MessageFullSchema = MessagePreviewSchema.extend({
    sender: PublicUserSchema,
});

export type MessagePreview = z.infer<typeof MessagePreviewSchema>;
export type MessageFull = z.infer<typeof MessageFullSchema>;
