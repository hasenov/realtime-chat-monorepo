import { User } from './user.schema';

export interface FieldError {
    path: string;
    message: string;
}

export interface ApiBaseSuccess {
    status: 'success';
    message?: string;
}

export interface ApiErrorResponse {
    status: 'fail' | 'error';
    message: string;
    errors?: FieldError[];
}

export interface ApiDataResponse<T> extends ApiBaseSuccess {
    data: T;
}

export interface ApiMessageResponse extends ApiBaseSuccess {}

export type ApiResponse<T = void> =
    | (T extends void ? ApiMessageResponse : ApiDataResponse<T>)
    | ApiErrorResponse;

// Response Payloads
export type AuthResponseData = {
    accessToken: string;
    user: User;
};

export type UserResponseData = {
    user: User;
};

export type UsersResponseData = {
    users: User[];
};

export type RefreshTokenData = {
    accessToken: string;
};
