import jwt from 'jsonwebtoken';

export interface UserJwtPayload extends jwt.JwtPayload {
    id: string;
    email: string;
    role: string;
}
