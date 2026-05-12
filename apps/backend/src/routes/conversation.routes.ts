import { Router } from 'express';
import { conversationController } from '../controllers/conversation.controller';
import { authMiddleware } from '../middlewares/auth.middleware';

const router: Router = Router();

router.use(authMiddleware);

router.get('/', conversationController.getConversations);
router.get('/:id', conversationController.getConversation);
router.post('/', conversationController.startConversation);
// router.post('/:id/messages', conversationController.sendMessage);

export default router;
