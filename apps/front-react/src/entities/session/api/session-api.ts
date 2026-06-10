import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    ApiMessageResponse,
    UpdateProfileInput,
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

        uploadAvatar: build.mutation<User, FormData>({
            query: (formData) => ({
                url: '/me/avatar',
                body: formData,
                method: 'post',
            }),
            transformResponse: (
                response: ApiDataResponse<UserResponseData>
            ) => {
                return response.data.user;
            },
        }),

        updateProfile: build.mutation<User, UpdateProfileInput>({
            query: (body) => ({
                url: '/me',
                body,
                method: 'PATCH',
            }),
            transformResponse: (
                response: ApiDataResponse<UserResponseData>
            ) => {
                return response.data.user;
            },
        }),
    }),
});

export const {
    useGetMeQuery,
    useLogoutMutation,
    useUploadAvatarMutation,
    useUpdateProfileMutation,
} = sessionApi;
