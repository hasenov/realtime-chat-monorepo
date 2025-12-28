import jwt from 'jsonwebtoken';
import { Prisma, prisma } from '@realtime-chat/database';
import { DecodedToken, UserPayload } from '../types/auth.types';

class TokenService {
    // Generate access and refresh token pair
    generateTokens(payload: UserPayload) {
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
        ip: string,
        tx?: Prisma.TransactionClient
    ) {
        const db = tx || prisma;
        const tokenData = await db.token.findFirst({
            where: { userId, userAgent },
        });

        // If a session already exists for this device/user-agent, update the token
        if (tokenData) {
            return db.token.update({
                where: { id: tokenData.id },
                data: { refreshToken },
            });
        }

        // Otherwise, create a new session record
        return db.token.create({
            data: {
                userId,
                refreshToken,
                userAgent,
                ip,
                expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
            },
        });
    }

    async updateToken(
        id: string,
        refreshToken: string,
        userAgent: string,
        ip: string,
        tx?: Prisma.TransactionClient
    ) {
        const db = tx || prisma;
        return db.token.update({
            where: { id },
            data: {
                refreshToken,
                userAgent,
                ip,
            },
        });
    }

    async findToken(refreshToken: string) {
        return prisma.token.findUnique({
            where: { refreshToken },
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

    validateAccessToken(token: string): DecodedToken | null {
        try {
            return jwt.verify(
                token,
                process.env.JWT_ACCESS_SECRET!
            ) as DecodedToken;
        } catch (e) {
            return null;
        }
    }

    validateRefreshToken(token: string): DecodedToken | null {
        try {
            return jwt.verify(
                token,
                process.env.JWT_REFRESH_SECRET!
            ) as DecodedToken;
        } catch (e) {
            return null;
        }
    }
}

export default new TokenService();
