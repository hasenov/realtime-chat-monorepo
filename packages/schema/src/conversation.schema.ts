import * as z from 'zod';

export const ConversationSchema = z.object({
    id: z.string(),
    name: z.string().optional(),
    isGroup: z.boolean(),
    createdAt: z.string(),
    updatedAt: z.string(),
});

export const ConversationRequestSchema = z.object({
    name: z.string().optional(),
    isGroup: z.boolean(),
    userIds: z.array(z.string()),
});

export type Conversation = z.infer<typeof ConversationSchema>;
export type ConversationRequest = z.infer<typeof ConversationRequestSchema>;
