import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import { prisma } from '@realtime-chat/database';
import cookieParser from 'cookie-parser';

import authRoutes from './routes/auth.routes';
import { errorHandler } from './middlewares/error.middleware';

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: '*', // Configure for specific fronts later
    },
});

app.use(cookieParser());
app.use(cors());
app.use(express.json());
app.use('/api/auth', authRoutes);

app.get('/', async (req, res) => {
    const users = await prisma.user.findMany();
    res.json({ message: 'Server is running', users });
});

app.use(errorHandler);

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
