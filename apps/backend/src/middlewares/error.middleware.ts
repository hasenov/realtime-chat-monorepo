import { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { ZodError } from 'zod';
import { AppError } from '../lib/exceptions/AppError';

export const errorHandler = (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    if (err instanceof ZodError) {
        res.status(StatusCodes.BAD_REQUEST).json({
            status: 'fail',
            message: 'Validation Error',
            errors: err.issues.map((issue) => ({
                path: issue.path.join('.'),
                message: issue.message,
            })),
        });
        return;
    }

    if (err instanceof AppError) {
        return res.status(err.statusCode).json({
            status: err.status,
            message: err.message,
        });
    }

    // Prisma (P2002 - Unique constraint)
    if ((err as any).code === 'P2002') {
        res.status(StatusCodes.CONFLICT).json({
            status: 'fail',
            message: 'Resource already exists (unique constraint)',
        });
        return;
    }

    console.error('ERROR', err);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        status: 'error',
        message: 'Something went wrong',
    });
};
