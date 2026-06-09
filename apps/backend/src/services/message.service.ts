import { prisma } from '@realtime-chat/database';
import { StatusCodes } from 'http-status-codes';
import { conversationUserSelect } from '../lib/db-selects/user.select';
import { AppError } from '../lib/exceptions/AppError';

class MessageService {
    async createMessage(
        senderId: string,
        conversationId: string,
        content: string
    ) {
        const accessibleConversation = await prisma.conversation.findFirst({
            where: {
                id: conversationId,
                participants: {
                    some: {
                        userId: senderId,
                    },
                },
            },
            select: {
                id: true,
            },
        });

        if (!accessibleConversation) {
            throw new AppError('Forbidden', StatusCodes.FORBIDDEN);
        }

        const message = await prisma.$transaction(async (tx) => {
            const createdMessage = await tx.message.create({
                data: {
                    conversationId,
                    senderId,
                    content,
                },
                include: {
                    sender: {
                        select: conversationUserSelect,
                    },
                },
            });

            await tx.conversation.update({
                where: {
                    id: conversationId,
                },
                data: {
                    updatedAt: new Date(),
                },
            });

            return createdMessage;
        });

        return message;
    }

    async getMessagesByConversation(userId: string, conversationId: string) {
        const accessibleConversation = await prisma.conversation.findFirst({
            where: {
                id: conversationId,
                participants: {
                    some: {
                        userId: userId,
                    },
                },
            },
            select: {
                id: true,
            },
        });

        if (!accessibleConversation) {
            throw new AppError('Forbidden', StatusCodes.FORBIDDEN);
        }

        return prisma.message.findMany({
            where: {
                conversationId: conversationId,
            },
            orderBy: {
                createdAt: 'asc',
            },
            include: {
                sender: {
                    select: conversationUserSelect,
                },
            },
        });
    }
}

export const messageService = new MessageService();
