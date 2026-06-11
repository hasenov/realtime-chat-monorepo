import { Button } from '@/shared/ui/button';
import { Input } from '@/shared/ui/input';
import { Paperclip, Send, Smile } from 'lucide-react';
import { useMessageComposer } from '../model/use-message-composer';

interface MessageComposerProps {
    conversationId: string;
}

export function MessageComposer({ conversationId }: MessageComposerProps) {
    const { content, handleTyping, handleSubmit, isLoading, canSend } =
        useMessageComposer(conversationId);

    return (
        <div className="p-4 border-t bg-background">
            <form
                className="flex items-end gap-2 max-w-4xl mx-auto"
                onSubmit={handleSubmit}
            >
                <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="shrink-0 text-muted-foreground"
                    disabled={isLoading}
                >
                    <Paperclip className="size-5" />
                </Button>
                <Input
                    placeholder="Напишите сообщение..."
                    className="min-h-5 bg-muted/50 border-0 focus-visible:ring-1 focus-visible:ring-primary shadow-none"
                    value={content}
                    onChange={handleTyping}
                    disabled={isLoading}
                />
                <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="shrink-0 text-muted-foreground"
                    disabled={isLoading}
                >
                    <Smile className="size-5" />
                </Button>
                <Button
                    type="submit"
                    size="icon"
                    className="shrink-0"
                    disabled={!canSend}
                >
                    <Send className="size-4" />
                </Button>
            </form>
        </div>
    );
}
