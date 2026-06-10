import { Router } from 'express';
import { uploadAvatarMiddleware } from '../config/multer.config';
import { userController } from '../controllers/user.controller';
import { authMiddleware } from '../middlewares/auth.middleware';

const router: Router = Router();

router.use(authMiddleware);

router.get('/', userController.getMe);
router.post(
    '/avatar',
    uploadAvatarMiddleware.single('avatar'),
    userController.uploadAvatar
);
router.patch('/', userController.updateProfile);

export default router;
