import { prisma } from '@realtime-chat/database';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import { createServer } from 'http';

import path from 'path';
import { CORS_OPTIONS } from './config/cors.config';
import { errorMiddleware } from './middlewares/error.middleware';
import authRoutes from './routes/auth.routes';
import conversationRoutes from './routes/conversation.routes';
import meRoutes from './routes/me.routes';
import userRoutes from './routes/user.routes';
import { initSocket } from './socket';

const app = express();
app.use(cookieParser());

const httpServer = createServer(app);

initSocket(httpServer, CORS_OPTIONS);
app.use(cors(CORS_OPTIONS));
app.use(express.json());
app.use('/uploads', express.static(path.join(process.cwd(), 'public/uploads')));
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/conversations', conversationRoutes);
app.use('/api/me', meRoutes);

app.get('/', async (req, res) => {
    const users = await prisma.user.findMany();
    res.json({ message: 'Server is running', users });
});

app.use(errorMiddleware);

const PORT = process.env.PORT || 3001;

httpServer.listen(PORT, () => {
    console.log(`Server ready on port ${PORT}`);
});
