import { baseApi } from '@/shared/api/base-api';
import type {
    ApiDataResponse,
    AuthResponseData,
    LoginInput,
} from '@realtime-chat/schema';

export const loginApi = baseApi.injectEndpoints({
    endpoints: (build) => ({
        login: build.mutation<ApiDataResponse<AuthResponseData>, LoginInput>({
            query: (body) => ({
                url: '/auth/login',
                body: body,
                method: 'post',
            }),
        }),
    }),
});

export const { useLoginMutation } = loginApi;
