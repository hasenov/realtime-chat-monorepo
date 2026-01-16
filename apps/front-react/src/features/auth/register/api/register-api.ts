import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    AuthResponseData,
    RegisterInput,
} from '@realtime-chat/schema';

export const registerApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
        register: build.mutation<
            ApiDataResponse<AuthResponseData>,
            RegisterInput
        >({
            query: (body) => ({
                url: '/auth/register',
                body: body,
                method: 'post',
            }),
        }),
    }),
});

export const { useRegisterMutation } = registerApi;
