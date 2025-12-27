import jwt from 'jsonwebtoken';
import { prisma } from '@realtime-chat/database';
import { UserJwtPayload } from '../types/jwt.types';

class TokenService {
    // Generate access and refresh token pair
    generateTokens(payload: any) {
        const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
            expiresIn: '15m',
        });
        const refreshToken = jwt.sign(
            payload,
            process.env.JWT_REFRESH_SECRET!,
            { expiresIn: '30d' }
        );
        return { accessToken, refreshToken };
    }

    // Save refresh token to the database
    async saveToken(
        userId: string,
        refreshToken: string,
        userAgent: string,
        ip: string
    ) {
        const tokenData = await prisma.token.findFirst({
            where: { userId, userAgent },
        });

        // If a session already exists for this device/user-agent, update the token
        if (tokenData) {
            tokenData.refreshToken = refreshToken;
            return prisma.token.update({
                where: { id: tokenData.id },
                data: { refreshToken },
            });
        }

        // Otherwise, create a new session record
        return prisma.token.create({
            data: {
                userId,
                refreshToken,
                userAgent,
                ip,
                expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
            },
        });
    }

    validateAccessToken(token: string): UserJwtPayload | null {
        try {
            return jwt.verify(
                token,
                process.env.JWT_ACCESS_SECRET!
            ) as UserJwtPayload;
        } catch (e) {
            return null;
        }
    }

    validateRefreshToken(token: string): UserJwtPayload | null {
        try {
            return jwt.verify(
                token,
                process.env.JWT_REFRESH_SECRET!
            ) as UserJwtPayload;
        } catch (e) {
            return null;
        }
    }

    async findToken(refreshToken: string) {
        return prisma.token.findUnique({
            where: { refreshToken },
        });
    }

    async updateToken(
        id: string,
        refreshToken: string,
        userAgent: string,
        ip: string
    ) {
        return prisma.token.update({
            where: { id },
            data: {
                refreshToken,
                userAgent,
                ip,
            },
        });
    }

    async removeToken(refreshToken: string): Promise<{ count: number }> {
        return prisma.token.deleteMany({
            where: { refreshToken },
        });
    }

    async removeAllUserTokens(userId: string): Promise<{ count: number }> {
        return prisma.token.deleteMany({
            where: { userId },
        });
    }
}

export default new TokenService();
