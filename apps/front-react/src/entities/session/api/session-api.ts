import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    ApiMessageResponse,
    GetMeResponseData,
    User,
} from '@realtime-chat/schema';

export const sessionApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
        getMe: build.query<User, void>({
            query: () => '/auth/me',
            providesTags: ['Session'],
            transformResponse: (
                response: ApiDataResponse<GetMeResponseData>
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
