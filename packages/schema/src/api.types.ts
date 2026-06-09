import {
    ConversationDetails,
    ConversationListItem,
} from './conversation.schema';
import { MessageFull } from './message.schema';
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

export type RefreshTokenResponseData = {
    accessToken: string;
};

export type ConversationResponseData = {
    conversation: ConversationDetails;
};

export type ConversationsResponseData = {
    conversations: ConversationListItem[];
};

export type MessagesResponseData = {
    messages: MessageFull[];
};

export type MessageResponseData = {
    message: MessageFull;
};
