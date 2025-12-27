import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { REFRESH_COOKIE_OPTIONS } from '../config/cookie.config';
import { LoginSchema, RegisterSchema } from '@realtime-chat/schema';
import { StatusCodes } from 'http-status-codes';
import * as z from 'zod';

export class AuthController {
    register = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = RegisterSchema.parse(req.body);

            const userAgent = req.headers['user-agent'] || 'unknown';
            const ip = req.ip || 'unknown';

            const { tokens, user } = await authService.register(
                validatedData,
                userAgent,
                ip
            );

            res.cookie(
                'refreshToken',
                tokens.refreshToken,
                REFRESH_COOKIE_OPTIONS
            );

            res.status(StatusCodes.CREATED).json({
                status: 'success',
                message: 'User registered successfully',
                data: {
                    accessToken: tokens.accessToken,
                    user,
                },
            });
        } catch (error: any) {
            if (error.message === 'User already exists') {
                res.status(StatusCodes.CONFLICT).json({
                    message: error.message,
                });
                return;
            }

            if (error instanceof z.ZodError) {
                res.status(StatusCodes.BAD_REQUEST).json({
                    errors: error.issues,
                });
                return;
            }

            next(error);
        }
    };

    login = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = LoginSchema.parse(req.body);

            const userAgent = req.headers['user-agent'] || 'unknown';
            const ip = req.ip || 'unknown';

            const { tokens, user } = await authService.login(
                validatedData,
                userAgent,
                ip
            );

            res.cookie(
                'refreshToken',
                tokens.refreshToken,
                REFRESH_COOKIE_OPTIONS
            );

            res.status(StatusCodes.CREATED).json({
                status: 'success',
                message: 'Logged in successfully',
                data: {
                    accessToken: tokens.accessToken,
                    user,
                },
            });
        } catch (error: any) {
            if (error instanceof z.ZodError) {
                res.status(StatusCodes.BAD_REQUEST).json({
                    errors: error.issues,
                });
                return;
            }

            next(error);
        }
    };

    refresh = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const userAgent = req.headers['user-agent'] || 'unknown';
            const ip = req.ip || 'unknown';
            const refreshToken = req.cookies.refreshToken;

            if (!refreshToken) {
                throw new Error('Unauthorized');
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
        } catch (error: any) {
            next(error);
        }
    };

    logout = async (req: Request, res: Response, next: NextFunction) => {
        try {
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
        } catch (error: any) {
            next(error);
        }
    };
}

export const authController = new AuthController();
