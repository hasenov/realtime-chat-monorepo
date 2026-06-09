import { ScrollArea } from '@/shared/ui/scroll-area';
import type { MessageFull } from '@realtime-chat/schema';
import { useEffect, useRef } from 'react';
import { MessageBubble } from './message-bubble';

interface MessageListProps {
    messages?: MessageFull[];
    meId: string;
}

export function MessageList({ messages = [], meId }: MessageListProps) {
    const chatInnerRef = useRef<HTMLDivElement>(null);

    const scrollToBottom = () => {
        chatInnerRef.current?.scrollIntoView(false);
    };

    useEffect(() => {
        scrollToBottom();
    }, []);

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    return (
        <ScrollArea className="flex-1 bg-muted/20 overflow-y-auto">
            <div
                className="flex flex-col gap-4 max-w-4xl mx-auto p-4"
                ref={chatInnerRef}
            >
                {messages.map((msg) => (
                    <MessageBubble key={msg.id} msg={msg} meId={meId} />
                ))}
            </div>
        </ScrollArea>
    );
}
