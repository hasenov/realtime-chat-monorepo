import type { MessageFull } from '@realtime-chat/schema';

interface MessageBubbleProps {
    msg: MessageFull;
    meId: string;
}

export function MessageBubble({ msg, meId }: MessageBubbleProps) {
    return (
        <div
            className={`flex w-full ${
                msg.senderId === meId ? 'justify-end' : 'justify-start'
            }`}
        >
            <div
                className={`flex max-w-[70%] flex-col gap-1 rounded-xl px-4 py-2 text-sm shadow-sm ${
                    msg.senderId === meId
                        ? 'bg-primary text-primary-foreground rounded-tr-none'
                        : 'bg-white dark:bg-zinc-800 border rounded-tl-none'
                }`}
            >
                <div>{msg.content}</div>
                <div
                    className={`text-[10px] self-end ${
                        msg.senderId === meId
                            ? 'text-primary-foreground/70'
                            : 'text-muted-foreground'
                    }`}
                >
                    {msg.createdAt}
                </div>
            </div>
        </div>
    );
}
