import { prisma } from '@realtime-chat/database';
import { RegisterInput } from '@realtime-chat/schema';
import bcrypt from 'bcryptjs';
import tokenService from './token.service';

export class AuthService {
    async register(data: RegisterInput, userAgent: string, ip: string) {
        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [{ email: data.email }, { username: data.username }],
            },
        });

        if (existingUser) {
            throw new Error('User already exists');
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(data.password, salt);

        const user = await prisma.user.create({
            data: {
                email: data.email,
                username: data.username,
                password: hashedPassword,
            },
            select: {
                id: true,
                email: true,
                username: true,
                role: true,
                createdAt: true,
            },
        });

        const tokens = tokenService.generateTokens({
            id: user.id,
            email: user.email,
            role: user.role,
        });

        await tokenService.saveToken(
            user.id,
            tokens.refreshToken,
            userAgent || '',
            ip || ''
        );

        return { tokens, user };
    }
}

export const authService = new AuthService();
