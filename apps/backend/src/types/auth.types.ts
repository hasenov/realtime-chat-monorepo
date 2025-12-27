import { JwtPayload } from 'jsonwebtoken';

export interface UserPayload {
    id: string;
    email: string;
    role: string;
}

export interface DecodedToken extends UserPayload, JwtPayload {}
