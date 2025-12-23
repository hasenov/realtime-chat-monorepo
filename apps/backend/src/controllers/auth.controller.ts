import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { RegisterSchema } from '@realtime-chat/schema';
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

            res.cookie('refreshToken', tokens.refreshToken, {
                maxAge: 30 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict', // CSRF protection
            });

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
}

export const authController = new AuthController();
