import { prisma } from '@realtime-chat/database';
import { LoginInput, RegisterInput } from '@realtime-chat/schema';
import bcrypt from 'bcryptjs';
import tokenService from './token.service';
import { AppError } from '../lib/exceptions/AppError';
import { StatusCodes } from 'http-status-codes';

export class AuthService {
    async register(data: RegisterInput, userAgent: string, ip: string) {
        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [{ email: data.email }, { username: data.username }],
            },
        });

        if (existingUser) {
            throw new AppError('User already exists', StatusCodes.CONFLICT);
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

    async login(data: LoginInput, userAgent: string, ip: string) {
        const user = await prisma.user.findFirst({
            where: {
                OR: [{ email: data.login }, { username: data.login }],
            },
        });

        if (!user) {
            throw new AppError(
                'Invalid login or password',
                StatusCodes.UNAUTHORIZED
            );
        }

        const isValid = await bcrypt.compare(data.password, user.password);
        if (!isValid) {
            throw new AppError(
                'Invalid login or password',
                StatusCodes.UNAUTHORIZED
            );
        }

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

        const { password, ...userWithoutSensitiveData } = user;

        return { tokens, user: userWithoutSensitiveData };
    }

    async refresh(refreshToken: string, userAgent: string, ip: string) {
        const userData = tokenService.validateRefreshToken(refreshToken);
        const tokenFromDb = await tokenService.findToken(refreshToken);

        if (!tokenFromDb && userData) {
            await tokenService.removeAllUserTokens(userData.id);
            throw new AppError(
                'Refresh token reused. Security alert! Please login again.',
                StatusCodes.FORBIDDEN
            );
        }

        if (!tokenFromDb || !userData) {
            throw new AppError('Unauthorized', StatusCodes.UNAUTHORIZED);
        }

        const newTokens = tokenService.generateTokens({
            id: userData.id,
            email: userData.email,
            role: userData.role,
        });

        await tokenService.updateToken(
            tokenFromDb.id,
            newTokens.refreshToken,
            userAgent || '',
            ip || ''
        );

        return newTokens;
    }

    async logout(refreshToken: string) {
        if (!refreshToken) return;
        return tokenService.removeToken(refreshToken);
    }

    async getMe(userId: string) {
        const user = await prisma.user.findUnique({
            where: {
                id: userId,
            },
            select: {
                id: true,
                email: true,
                username: true,
                role: true,
                createdAt: true,
            },
        });

        if (!user) {
            throw new AppError('User not found', StatusCodes.NOT_FOUND);
        }

        return user;
    }
}

export const authService = new AuthService();
