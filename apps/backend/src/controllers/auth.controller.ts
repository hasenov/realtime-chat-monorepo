import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { REFRESH_COOKIE_OPTIONS } from '../config/cookie.config';
import { LoginSchema, RegisterSchema } from '@realtime-chat/schema';
import { StatusCodes } from 'http-status-codes';
import { AppError } from '../lib/exceptions/AppError';

export class AuthController {
    register = async (req: Request, res: Response) => {
        const validatedData = RegisterSchema.parse(req.body);

        const userAgent = req.headers['user-agent'] || 'unknown';
        const ip = req.ip || 'unknown';

        const { tokens, user } = await authService.register(
            validatedData,
            userAgent,
            ip
        );

        res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE_OPTIONS);

        res.status(StatusCodes.CREATED).json({
            status: 'success',
            message: 'User registered successfully',
            data: {
                accessToken: tokens.accessToken,
                user,
            },
        });
    };

    login = async (req: Request, res: Response) => {
        const validatedData = LoginSchema.parse(req.body);

        const userAgent = req.headers['user-agent'] || 'unknown';
        const ip = req.ip || 'unknown';

        const { tokens, user } = await authService.login(
            validatedData,
            userAgent,
            ip
        );

        res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE_OPTIONS);

        res.status(StatusCodes.CREATED).json({
            status: 'success',
            message: 'Logged in successfully',
            data: {
                accessToken: tokens.accessToken,
                user,
            },
        });
    };

    refresh = async (req: Request, res: Response) => {
        const userAgent = req.headers['user-agent'] || 'unknown';
        const ip = req.ip || 'unknown';
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            throw new AppError('Unauthorized');
        }

        const newTokens = await authService.refresh(
            refreshToken,
            userAgent,
            ip
        );

        res.cookie(
            'refreshToken',
            newTokens.refreshToken,
            REFRESH_COOKIE_OPTIONS
        );

        res.status(StatusCodes.OK).json({
            status: 'success',
            data: {
                accessToken: newTokens.accessToken,
            },
        });
    };

    logout = async (req: Request, res: Response) => {
        const refreshToken = req.cookies.refreshToken;

        if (refreshToken) {
            await authService.logout(refreshToken);
        }

        const { maxAge, ...clearOptions } = REFRESH_COOKIE_OPTIONS;

        res.clearCookie('refreshToken', clearOptions);

        res.status(StatusCodes.OK).json({
            status: 'success',
            message: 'Logged out successfully',
        });
    };
}

export const authController = new AuthController();
