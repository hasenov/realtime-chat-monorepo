import { MessageFull } from '@realtime-chat/schema';
import type { CorsOptions } from 'cors';
import type { Server as HttpServer } from 'http';
import { Server, Socket } from 'socket.io';
import tokenService from './services/token.service';
import type { DecodedToken } from './types/auth.types';

interface ServerToClientEvents {
    'message:new': (message: MessageFull) => void;
}

interface ClientToServerEvents {
    'conversation:join': (data: { conversationId: string }) => void;
    'conversation:leave': (data: { conversationId: string }) => void;
}

interface SocketData {
    user: DecodedToken;
}

type CustomServer = Server<
    ClientToServerEvents,
    ServerToClientEvents,
    never,
    SocketData
>;
type CustomSocket = Socket<
    ClientToServerEvents,
    ServerToClientEvents,
    never,
    SocketData
>;

let io: CustomServer | null = null;

export const initSocket = (
    httpServer: HttpServer,
    corsOptions: CorsOptions
): CustomServer => {
    io = new Server(httpServer, {
        cors: corsOptions,
    });

    io.use((socket: CustomSocket, next) => {
        const token = socket.handshake.auth?.token;

        if (!token) {
            return next(new Error('Authentication error: Token missing'));
        }

        const userData = tokenService.validateAccessToken(token);

        if (!userData) {
            return next(
                new Error('Authentication error: Invalid or expired token')
            );
        }

        socket.data.user = userData;
        next();
    });

    io.on('connection', (socket: CustomSocket) => {
        const userId = socket.data.user?.id;
        console.log(`User connected: ${socket.id}, UserID: ${userId}`);

        socket.on('conversation:join', ({ conversationId }) => {
            const newRoomName = `conversation:${conversationId}`;

            for (const room of socket.rooms) {
                if (room.startsWith('conversation:') && room !== newRoomName) {
                    socket.leave(room);
                }
            }

            socket.join(newRoomName);
            console.log(`User ${userId} joined room: ${newRoomName}`);
        });

        socket.on('conversation:leave', ({ conversationId }) => {
            socket.leave(`conversation:${conversationId}`);
        });

        socket.on('disconnect', () => {
            console.log(`User disconnected: ${socket.id}`);
        });
    });

    return io;
};

export const getIO = (): CustomServer => {
    if (!io) {
        throw new Error('Socket.io not initialized!');
    }
    return io;
};
