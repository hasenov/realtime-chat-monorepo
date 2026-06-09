import { getImageUrl } from '@/shared/lib/get-image-url';
import { Avatar, AvatarFallback, AvatarImage } from '@/shared/ui/avatar';
import type { ConversationListItem as ConversationListItemSchema } from '@realtime-chat/schema';
import { NavLink } from 'react-router';
import { getConversationPreviewInfo } from '../model/get-conversation-preview-info';

interface ConversationListItemProps {
    conversation: ConversationListItemSchema;
    currentUserId: string;
}

export function ConversationListItem({
    conversation,
    currentUserId,
}: ConversationListItemProps) {
    const preview = getConversationPreviewInfo(conversation, currentUserId);

    return (
        <NavLink
            to={`/conversations/${conversation.id}`}
            className={({ isActive }) =>
                `flex cursor-pointer items-center gap-3 border-b p-4 text-sm transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground ${isActive ? 'bg-sidebar-accent text-sidebar-accent-foreground' : ''}`
            }
        >
            <Avatar className="h-10 w-10 border">
                <AvatarImage src={getImageUrl(preview.avatar) ?? undefined} />
                <AvatarFallback className="font-semibold">
                    {preview.avatarFallback}
                </AvatarFallback>
            </Avatar>
            <div className="flex flex-1 flex-col overflow-hidden">
                <div className="flex justify-between font-medium">
                    <span className="truncate">{preview.title}</span>
                    <span className="text-xs text-muted-foreground ml-2 whitespace-nowrap">
                        {preview.updatedAtLabel}
                    </span>
                </div>
                <div className="flex justify-between items-center mt-1">
                    {preview.lastMessagePreview && (
                        <span className="truncate text-xs text-muted-foreground pr-2">
                            {preview.lastMessagePreview}
                        </span>
                    )}
                    {/* {preview.unread > 0 && (
                                                        <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1 text-[10px] text-primary-foreground">
                                                            {preview.unread}
                                                        </span>
                                                    )} */}
                </div>
            </div>
        </NavLink>
    );
}
