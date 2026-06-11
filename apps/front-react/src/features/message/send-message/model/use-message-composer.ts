import { showApiErrorToast } from '@/shared/lib/show-api-error-toast';
import { socketService } from '@/shared/lib/socket/socket-service';
import {
    useEffect,
    useRef,
    useState,
    type ChangeEvent,
    type FormEvent,
} from 'react';
import { useSendMessageMutation } from '../api/send-message-api';

export const useMessageComposer = (conversationId: string) => {
    const [content, setContent] = useState('');
    const [sendMessage, { isLoading }] = useSendMessageMutation();

    const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const isTypingRef = useRef(false);

    const trimmedContent = content.trim();
    const canSend = !isLoading && trimmedContent.length > 0;

    const handleTyping = (e: ChangeEvent<HTMLInputElement>) => {
        setContent(e.target.value);

        if (!isTypingRef.current) {
            isTypingRef.current = true;
            socketService.socket?.emit('typing:start', { conversationId });
        }

        if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);

        typingTimeoutRef.current = setTimeout(() => {
            socketService.socket?.emit('typing:stop', { conversationId });
            isTypingRef.current = false;
        }, 2000);
    };

    const handleSubmit = async (e?: FormEvent<HTMLFormElement>) => {
        e?.preventDefault();

        if (!canSend) return;

        try {
            if (typingTimeoutRef.current) {
                clearTimeout(typingTimeoutRef.current);
            }

            if (isTypingRef.current) {
                socketService.socket?.emit('typing:stop', { conversationId });
                isTypingRef.current = false;
            }

            await sendMessage({
                id: conversationId,
                content: trimmedContent,
            }).unwrap();

            setContent('');
        } catch (error) {
            showApiErrorToast(error);
        }
    };

    useEffect(() => {
        return () => {
            if (typingTimeoutRef.current) {
                clearTimeout(typingTimeoutRef.current);
            }
        };
    }, [conversationId]);

    return {
        handleSubmit,
        content,
        handleTyping,
        isLoading,
        canSend,
    };
};
