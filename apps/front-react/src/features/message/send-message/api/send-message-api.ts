import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    MessageFull,
    MessageResponseData,
    SendMessageInput,
} from '@realtime-chat/schema';

export const messageApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
        sendMessage: build.mutation<MessageFull, SendMessageInput>({
            query: (body) => ({
                url: `/conversations/${body.id}/messages`,
                body: {
                    content: body.content,
                },
                method: 'post',
            }),
            transformResponse: (
                response: ApiDataResponse<MessageResponseData>
            ) => {
                return response.data.message;
            },
            invalidatesTags(_result, _error, arg) {
                return [
                    { type: 'Messages', id: arg.id },
                    { type: 'Conversations' },
                ];
            },
        }),
    }),
});

export const { useSendMessageMutation } = messageApi;
