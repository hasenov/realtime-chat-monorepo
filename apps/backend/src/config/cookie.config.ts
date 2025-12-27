import { CookieOptions } from 'express';

export const REFRESH_COOKIE_OPTIONS: CookieOptions = {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict', // CSRF protection
    path: '/',
};
