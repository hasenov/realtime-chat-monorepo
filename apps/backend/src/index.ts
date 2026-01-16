import { prisma } from '@realtime-chat/database';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';

import { CORS_OPTIONS } from './config/cors.config';
import { errorMiddleware } from './middlewares/error.middleware';
import authRoutes from './routes/auth.routes';

const app = express();
app.use(cookieParser());

const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: CORS_OPTIONS,
});

app.use(cors(CORS_OPTIONS));
app.use(express.json());
app.use('/api/auth', authRoutes);

app.get('/', async (req, res) => {
    const users = await prisma.user.findMany();
    res.json({ message: 'Server is running', users });
});

app.use(errorMiddleware);

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

const PORT = process.env.PORT || 3001;

httpServer.listen(PORT, () => {
    console.log(`Server ready on port ${PORT}`);
});
