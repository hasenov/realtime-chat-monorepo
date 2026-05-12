import { ConversationRequestSchema } from '@realtime-chat/schema';
import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { requireUser } from '../lib/helpers';
import { conversationService } from '../services/conversation.service';

type ConversationParams = {
    id: string;
};

class ConversationController {
    getConversations = async (req: Request, res: Response) => {
        const user = requireUser(req);

        const conversations = await conversationService.getConversations(
            user.id
        );

        res.status(StatusCodes.OK).json({
            status: 'success',
            data: {
                conversations,
            },
        });
    };

    getConversation = async (
        req: Request<ConversationParams>,
        res: Response
    ) => {
        const user = requireUser(req);
        const { id } = req.params;

        const conversation = await conversationService.getConversationById(
            id,
            user.id
        );

        res.status(StatusCodes.OK).json({
            status: 'success',
            data: {
                conversation,
            },
        });
    };

    startConversation = async (req: Request, res: Response) => {
        const user = requireUser(req);

        const validatedData = ConversationRequestSchema.parse(req.body);

        const conversation = await conversationService.startConversation(
            user.id,
            validatedData
        );

        res.status(StatusCodes.CREATED).json({
            status: 'success',
            data: {
                conversation,
            },
        });
    };
}

export const conversationController = new ConversationController();
