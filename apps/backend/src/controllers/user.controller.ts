import { SearchSchema } from '@realtime-chat/schema';
import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { AppError } from '../lib/exceptions/AppError';
import { requireUser } from '../lib/helpers';
import { userService } from '../services/user.service';

class UserController {
    uploadAvatar = async (req: Request, res: Response) => {
        const user = requireUser(req);

        if (!req.file) {
            throw new AppError('File not found', StatusCodes.BAD_REQUEST);
        }

        const avatarUrl = `/uploads/avatars/${req.file.filename}`;

        const updatedUser = await userService.uploadAvatar(user.id, avatarUrl);

        res.status(StatusCodes.OK).json({
            status: 'success',
            message: 'Avatar uploaded successfully',
            data: {
                user: updatedUser,
            },
        });
    };

    searchUsers = async (req: Request, res: Response) => {
        const user = requireUser(req);

        const validatedQuery = SearchSchema.parse(req.query);

        const currentUserId = user.id;

        const users = await userService.searchUsers(
            validatedQuery,
            currentUserId
        );

        res.status(StatusCodes.OK).json({
            status: 'success',
            data: {
                users,
            },
        });
    };

    getMe = async (req: Request, res: Response) => {
        const user = requireUser(req);

        const userFromDb = await userService.findById(user.id);

        res.status(StatusCodes.OK).json({
            status: 'success',
            data: {
                user: userFromDb,
            },
        });
    };
}

export const userController = new UserController();
