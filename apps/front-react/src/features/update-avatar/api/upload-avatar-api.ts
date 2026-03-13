import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    User,
    UserResponseData,
} from '@realtime-chat/schema';

export const uploadAvatarApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
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
    }),
});

export const { useUploadAvatarMutation } = uploadAvatarApi;
