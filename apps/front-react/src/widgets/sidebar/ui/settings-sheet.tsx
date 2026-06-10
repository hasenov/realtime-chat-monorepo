import { useLogout } from '@/features/auth/logout';
import { getImageUrl } from '@/shared/lib/get-image-url';
import { Avatar, AvatarFallback, AvatarImage } from '@/shared/ui/avatar';
import { SheetContent, SheetHeader, SheetTitle } from '@/shared/ui/sheet';
import type { User } from '@realtime-chat/schema';
import {
    Bell,
    CircleHelp,
    Laptop,
    Lock,
    LogOut,
    Shield,
    User as UserIcon,
} from 'lucide-react';

interface SettingsSheetProps {
    user: User;
}

export function SettingsSheet({ user }: SettingsSheetProps) {
    const { handleLogout } = useLogout();

    const menuItems = [
        {
            icon: UserIcon,
            label: 'Аккаунт',
            sub: 'Смена номера, удаление аккаунта',
        },
        {
            icon: Lock,
            label: 'Конфиденциальность',
            sub: 'Блокировка, статус, фото профиля',
        },
        {
            icon: Shield,
            label: 'Безопасность',
            sub: 'Пароль, двухфакторная аутентификация',
        },
        { icon: Laptop, label: 'Тема и обои', sub: 'Светлая/темная тема' },
        { icon: Bell, label: 'Уведомления', sub: 'Звуки сообщений' },
        { icon: CircleHelp, label: 'Помощь', sub: 'Связаться с нами' },
    ];

    return (
        <SheetContent
            side="left"
            className="w-[350px] p-0 gap-0 border-r sm:max-w-[350px]"
        >
            <SheetHeader className="bg-primary px-4 py-10 text-primary-foreground">
                <SheetTitle className="text-primary-foreground text-xl font-medium">
                    Настройки
                </SheetTitle>
            </SheetHeader>

            <div className="flex flex-col h-full bg-muted/10">
                <div className="flex items-center gap-4 p-4 bg-background shadow-sm mb-2 cursor-pointer hover:bg-muted/50 transition-colors">
                    <Avatar className="h-16 w-16">
                        <AvatarImage src={getImageUrl(user.avatar)} />
                        <AvatarFallback>{user.username?.[0]}</AvatarFallback>
                    </Avatar>
                    <div className="flex flex-col">
                        <span className="font-medium text-lg">
                            {user.name || user.username}
                        </span>
                        {user.bio && (
                            <span className="text-sm text-muted-foreground truncate max-w-[200px]">
                                {user.bio}
                            </span>
                        )}
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto bg-background">
                    {menuItems.map((item, index) => (
                        <button
                            key={index}
                            className="w-full flex items-center gap-4 p-4 hover:bg-muted/50 transition-colors border-b last:border-0 text-left"
                        >
                            <item.icon className="size-5 text-muted-foreground" />
                            <div className="flex flex-col">
                                <span className="text-sm font-medium">
                                    {item.label}
                                </span>
                                {item.sub && (
                                    <span className="text-xs text-muted-foreground">
                                        {item.sub}
                                    </span>
                                )}
                            </div>
                        </button>
                    ))}

                    <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-4 p-4 hover:bg-red-50 hover:text-red-600 text-red-500 transition-colors mt-4 border-t"
                    >
                        <LogOut className="size-5" />
                        <span className="text-sm font-medium">Выйти</span>
                    </button>
                </div>
            </div>
        </SheetContent>
    );
}
