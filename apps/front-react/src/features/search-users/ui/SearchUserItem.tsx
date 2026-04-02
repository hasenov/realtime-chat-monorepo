import { Avatar, AvatarFallback, AvatarImage } from '@/shared/ui/avatar';
import type { User } from '@realtime-chat/schema';
import { UserPlus } from 'lucide-react';

interface SearchUserItemProps {
    user: User;
}

export function SearchUserItem({ user }: SearchUserItemProps) {
    return (
        <button
            className="w-full flex items-center justify-between p-3 rounded-lg hover:bg-muted/80 transition-colors group cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onClick={() => {
                /* Логика */
            }}
        >
            <div className="flex items-center gap-3 min-w-0">
                <Avatar className="h-10 w-10 border shrink-0">
                    <AvatarImage src={user.avatar} alt={user.name} />
                    <AvatarFallback>{user.name?.[0]}</AvatarFallback>
                </Avatar>
                <div className="flex flex-col items-start text-sm truncate">
                    <span className="font-medium truncate w-full text-left">
                        {user.name}
                    </span>
                    <span className="text-muted-foreground text-xs italic truncate w-full text-left">
                        @{user.username}
                    </span>
                </div>
            </div>

            <UserPlus className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 group-focus:opacity-100 transition-opacity shrink-0 ml-2" />
        </button>
    );
}
