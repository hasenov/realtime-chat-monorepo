import { ScrollArea } from '@/shared/ui/scroll-area';
import type { MessageFull } from '@realtime-chat/schema';
import { useEffect, useRef } from 'react';
import { useGetTypingUsersQuery } from '../api/message-api';
import { MessageBubble } from './message-bubble';

interface MessageListProps {
    messages: MessageFull[];
    meId: string;
    conversationId: string;
}

export function MessageList({
    messages = [],
    meId,
    conversationId,
}: MessageListProps) {
    const chatInnerRef = useRef<HTMLDivElement>(null);

    const { data: typingUsers = [] } = useGetTypingUsersQuery(conversationId);

    const scrollToBottom = () => {
        chatInnerRef.current?.scrollIntoView(false);
    };

    useEffect(() => {
        scrollToBottom();
    }, []);

    useEffect(() => {
        scrollToBottom();
    }, [messages, typingUsers]);

    return (
        <ScrollArea className="flex-1 bg-muted/20 overflow-y-auto">
            <div
                className="flex flex-col gap-4 max-w-4xl mx-auto p-4"
                ref={chatInnerRef}
            >
                {messages.map((msg) => (
                    <MessageBubble key={msg.id} msg={msg} meId={meId} />
                ))}
                {typingUsers.length > 0 && (
                    <div className="text-xs text-muted-foreground italic animate-pulse">
                        {typingUsers.length === 1
                            ? 'Собеседник печатает...'
                            : 'Несколько человек печатают...'}
                    </div>
                )}
            </div>
        </ScrollArea>
    );
}
