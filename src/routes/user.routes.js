import Router from 'express';
import { registerUser, loginUser, getAllUserProfile } from '../controllers/user.controller.js';
import authenticate from '../middleware/authMiddleware.js';

const router = Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/profile', authenticate, getAllUserProfile); // Protected route

export default router;
