import { Socket, io } from 'socket.io-client';

class SocketService {
    public socket: Socket | null = null;

    connect(accessToken: string) {
        if (this.socket) {
            this.socket.auth = { token: accessToken };

            if (!this.socket.connected) {
                this.socket.connect();
            }

            return;
        }

        this.socket = io(import.meta.env.VITE_BACKEND_URL, {
            auth: {
                token: accessToken,
            },
            autoConnect: true,
        });

        this.socket.on('connect', () => {
            console.log('Connected to socket server');
        });
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
            console.log('Disconnected from socket server');
        }
    }
}

export const socketService = new SocketService();
