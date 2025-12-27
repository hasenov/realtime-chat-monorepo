import { DecodedToken } from './auth.types';

declare global {
    namespace Express {
        interface Request {
            user?: DecodedToken;
        }
    }
}
