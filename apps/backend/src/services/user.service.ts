import { prisma } from '@realtime-chat/database';
import { SearchInput, User } from '@realtime-chat/schema';
import fs from 'fs';
import { StatusCodes } from 'http-status-codes';
import path from 'path';
import {
    conversationUserSelect,
    publicUserSelect,
} from '../lib/db-selects/user.select';
import { AppError } from '../lib/exceptions/AppError';

class UserService {
    async findById(userId: string) {
        const user = await prisma.user.findUnique({
            where: {
                id: userId,
            },
            select: publicUserSelect,
        });

        if (!user) {
            throw new AppError('User not found', StatusCodes.NOT_FOUND);
        }

        return user;
    }

    async uploadAvatar(userId: string, avatarUrl: string) {
        const currentUser = await prisma.user.findUnique({
            where: {
                id: userId,
            },
            select: {
                avatar: true,
            },
        });

        const oldAvatarUrl = currentUser?.avatar;

        const updatedUser = await prisma.user.update({
            where: {
                id: userId,
            },
            data: {
                avatar: avatarUrl,
            },
            select: publicUserSelect,
        });

        if (oldAvatarUrl) {
            try {
                const fileName = path.basename(oldAvatarUrl);

                const filePath = path.join(
                    process.cwd(),
                    'public',
                    'uploads',
                    'avatars',
                    fileName
                );

                fs.unlink(filePath, (err) => {
                    if (err) throw err;
                    console.log(`Old avatar deleted: ${fileName}`);
                });
            } catch (error: any) {
                if (error.code === 'ENOENT') {
                    console.warn(
                        'Old avatar was not found on disk. Skipping deletion'
                    );
                } else {
                    console.error('Error deleting old avatar:', error);
                }
            }
        }

        return updatedUser;
    }

    async searchUsers(query: SearchInput, currentUserId: string) {
        if (!query.q) {
            return [];
        }

        return await prisma.user.findMany({
            where: {
                id: { not: currentUserId },
                username: {
                    contains: query.q,
                    mode: 'insensitive',
                },
            },
            select: conversationUserSelect,
        });
    }

    async updateProfile(userId: string, data: Pick<User, 'name' | 'bio'>) {
        return await prisma.user.update({
            where: {
                id: userId,
            },
            data: {
                bio: data.bio,
                name: data.name,
            },
            select: publicUserSelect,
        });
    }
}

export const userService = new UserService();
