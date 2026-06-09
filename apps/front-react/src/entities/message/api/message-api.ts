import { baseApi } from '@/shared/api/base-api';
import { socketService } from '@/shared/lib/socket/socket-service';
import type {
    ApiDataResponse,
    MessageFull,
    MessagesResponseData,
} from '@realtime-chat/schema';

export const messageApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
        getMessages: build.query<MessageFull[], string>({
            query: (conversationId) =>
                `/conversations/${conversationId}/messages`,
            transformResponse: (
                response: ApiDataResponse<MessagesResponseData>
            ) => {
                return response.data.messages;
            },
            async onCacheEntryAdded(
                conversationId,
                { updateCachedData, cacheDataLoaded, cacheEntryRemoved }
            ) {
                const handleNewMessage = (newMessage: MessageFull) => {
                    updateCachedData((draft) => {
                        const exists = draft.some(
                            (m) => m.id === newMessage.id
                        );
                        if (
                            !exists &&
                            conversationId === newMessage.conversationId
                        ) {
                            draft.push(newMessage);
                        }
                    });
                };

                try {
                    await cacheDataLoaded;

                    const joinRoom = () => {
                        socketService.socket?.emit('conversation:join', {
                            conversationId,
                        });
                    };

                    if (socketService.socket?.connected) {
                        joinRoom();
                    } else {
                        socketService.socket?.once('connect', joinRoom);
                    }

                    socketService.socket?.on('message:new', handleNewMessage);
                } catch (error) {}

                await cacheEntryRemoved;

                socketService.socket?.emit('conversation:leave', {
                    conversationId,
                });
                socketService.socket?.off('message:new', handleNewMessage);
            },
        }),
    }),
});

export const { useGetMessagesQuery } = messageApi;
