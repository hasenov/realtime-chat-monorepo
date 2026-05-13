import { prisma } from '@realtime-chat/database';
import { ConversationRequest } from '@realtime-chat/schema';
import { StatusCodes } from 'http-status-codes';
import { conversationUserSelect } from '../lib/db-selects/user.select';
import { AppError } from '../lib/exceptions/AppError';

export class ConversationService {
    async getConversations(userId: string) {
        return await prisma.conversation.findMany({
            where: {
                participants: {
                    some: {
                        userId: userId,
                    },
                },
            },
            include: {
                participants: {
                    include: {
                        user: {
                            select: conversationUserSelect,
                        },
                    },
                },
                messages: {
                    take: 1,
                    orderBy: {
                        createdAt: 'desc',
                    },
                },
            },
            orderBy: {
                updatedAt: 'desc',
            },
        });
    }

    async getConversationById(conversationId: string, userId: string) {
        const conversation = await prisma.conversation.findFirst({
            where: {
                id: conversationId,
                participants: {
                    some: {
                        userId: userId,
                    },
                },
            },
            include: {
                participants: {
                    include: {
                        user: {
                            select: conversationUserSelect,
                        },
                    },
                },
                messages: {
                    take: 1,
                    orderBy: {
                        createdAt: 'desc',
                    },
                },
            },
        });

        if (!conversation) {
            throw new AppError('Conversation not found', StatusCodes.NOT_FOUND);
        }

        return conversation;
    }

    async startConversation(currentUserId: string, data: ConversationRequest) {
        const { isGroup, userIds, name } = data;

        const allParticipantIds = Array.from(
            new Set([...userIds, currentUserId])
        );

        if (!isGroup && allParticipantIds.length === 2) {
            const existingConversation = await prisma.conversation.findFirst({
                where: {
                    isGroup: false,
                    AND: [
                        {
                            participants: {
                                some: { userId: allParticipantIds[0] },
                            },
                        },
                        {
                            participants: {
                                some: { userId: allParticipantIds[1] },
                            },
                        },
                    ],
                },
                include: {
                    participants: {
                        include: {
                            user: {
                                select: {
                                    id: true,
                                    username: true,
                                    name: true,
                                    avatar: true,
                                },
                            },
                        },
                    },
                    messages: { take: 1, orderBy: { createdAt: 'desc' } },
                },
            });

            if (existingConversation) return existingConversation;
        }

        return await prisma.conversation.create({
            data: {
                name: isGroup ? name : null,
                participants: {
                    create: allParticipantIds.map((id) => ({
                        userId: id,
                    })),
                },
            },
            include: {
                participants: {
                    include: {
                        user: {
                            select: conversationUserSelect,
                        },
                    },
                },
            },
        });
    }
}

export const conversationService = new ConversationService();
