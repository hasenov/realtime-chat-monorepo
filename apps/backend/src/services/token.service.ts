import jwt from 'jsonwebtoken';
import { prisma } from '@realtime-chat/database';

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

    validateAccessToken(token: string) {
        try {
            return jwt.verify(token, process.env.JWT_ACCESS_SECRET!);
        } catch (e) {
            return null;
        }
    }

    // ... validateRefreshToken, removeToken, findToken
}

export default new TokenService();
