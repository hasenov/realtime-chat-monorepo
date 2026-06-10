import type { User } from '@realtime-chat/schema';
import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import { sessionApi } from '../api/session-api';

export interface SessionState {
    user: User | null;
    accessToken: string | null;
    isAuth: boolean;
}

const initialState: SessionState = {
    user: null,
    accessToken: null,
    isAuth: false,
};

export const sessionSlice = createSlice({
    name: 'session',
    initialState,
    reducers: {
        setCredentials(
            state,
            { payload }: PayloadAction<{ user: User; accessToken: string }>
        ) {
            state.user = payload.user;
            state.accessToken = payload.accessToken;
            state.isAuth = true;
        },
        logout(state) {
            state.user = null;
            state.accessToken = null;
            state.isAuth = false;
        },
        tokenReceived(state, { payload }: PayloadAction<string>) {
            state.accessToken = payload;
        },
    },
    extraReducers: (builder) => {
        builder.addMatcher(
            sessionApi.endpoints.getMe.matchFulfilled,
            (state, { payload }) => {
                state.user = payload;
                state.isAuth = true;
            }
        );

        builder.addMatcher(
            sessionApi.endpoints.uploadAvatar.matchFulfilled,
            (state, { payload }) => {
                if (state.user) {
                    state.user.avatar = payload.avatar;
                }
            }
        );

        builder.addMatcher(
            sessionApi.endpoints.updateProfile.matchFulfilled,
            (state, { payload }) => {
                if (state.user) {
                    if (payload.name) state.user.name = payload.name;
                    if (payload.bio) state.user.bio = payload.bio;
                }
            }
        );
    },
});

export const { setCredentials, logout, tokenReceived } = sessionSlice.actions;
