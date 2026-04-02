import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    User,
    UsersResponseData,
} from '@realtime-chat/schema';

export const searchApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
        search: build.query<User[], string>({
            query: (searchTerm) => ({
                url: '/users/search',
                params: {
                    q: searchTerm,
                },
            }),
            transformResponse: (
                response: ApiDataResponse<UsersResponseData>
            ) => {
                return response.data.users;
            },
        }),
    }),
});

export const { useSearchQuery } = searchApi;
