import { NextFunction, Request, Response } from 'express';
import { AppError } from '../lib/exceptions/AppError';
import tokenService from '../services/token.service';
import { StatusCodes } from 'http-status-codes';

export const authMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        throw new AppError(
            'Authorization header missing',
            StatusCodes.UNAUTHORIZED
        );
    }

    const [bearer, token] = authHeader.split(' ');
    if (bearer !== 'Bearer' || !token) {
        throw new AppError(
            'Invalid authorization format. Use Bearer scheme',
            StatusCodes.UNAUTHORIZED
        );
    }

    const payload = tokenService.validateAccessToken(token);
    if (!payload) {
        throw new AppError(
            'Invalid or expired access token',
            StatusCodes.UNAUTHORIZED
        );
    }

    req.user = payload;

    next();
};
