import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    ApiMessageResponse,
    User,
    UserResponseData,
} from '@realtime-chat/schema';

export const sessionApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
        getMe: build.query<User, void>({
            query: () => '/me',
            providesTags: ['Session'],
            transformResponse: (
                response: ApiDataResponse<UserResponseData>
            ) => {
                return response.data.user;
            },
        }),
        logout: build.mutation<ApiMessageResponse, void>({
            query: () => ({ url: '/auth/logout', method: 'post' }),
        }),
    }),
});

export const { useGetMeQuery, useLogoutMutation } = sessionApi;
