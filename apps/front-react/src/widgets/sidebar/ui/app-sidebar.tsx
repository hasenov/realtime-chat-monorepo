import {
    Command,
    LucideSettings,
    MessageSquare,
    Phone,
    Plus,
    Search,
    Users2,
} from 'lucide-react';
import * as React from 'react';

import { SearchUsersDialogContent } from '@/features/search-users';
import { useAppSelector } from '@/shared/lib/hooks';
import { Avatar, AvatarFallback, AvatarImage } from '@/shared/ui/avatar';
import { Dialog } from '@/shared/ui/dialog';
import { Sheet, SheetTrigger } from '@/shared/ui/sheet';
import {
    Sidebar,
    SidebarContent,
    SidebarFooter,
    SidebarGroup,
    SidebarGroupContent,
    SidebarHeader,
    SidebarInput,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
} from '@/shared/ui/sidebar';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip';
import { DialogTrigger } from '@radix-ui/react-dialog';
import { ProfileSheet } from './profile-sheet';
import { SettingsSheet } from './settings-sheet';

// mock data
const data = {
    chats: [
        {
            id: '1',
            name: 'Alice Smith',
            avatar: 'https://i.pravatar.cc/300',
            lastMessage: 'Привет! Как насчет встречи завтра?',
            date: '09:42',
            unread: 2,
        },
        {
            id: '2',
            name: 'Frontend Team',
            avatar: '',
            lastMessage: 'Кто запушил в мастер без ревью?!',
            date: 'Вчера',
            unread: 0,
        },
        {
            id: '3',
            name: 'Роберт Де Ниро',
            avatar: 'https://i.pravatar.cc/300',
            lastMessage: 'Ты мне это говоришь?',
            date: 'Пн',
            unread: 0,
        },
    ],
};

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
    const [activeTab, setActiveTab] = React.useState('chats');
    const [activeChatId, setActiveChatId] = React.useState('1');

    const user = useAppSelector((state) => state.session.user);

    return (
        <Sidebar
            collapsible="icon"
            className="overflow-hidden *:data-[sidebar=sidebar]:flex-row"
            {...props}
        >
            <Sidebar
                collapsible="none"
                className="w-[calc(var(--sidebar-width-icon)+1px)]! border-r bg-background"
            >
                <SidebarHeader>
                    <SidebarMenu>
                        <SidebarMenuItem>
                            <SidebarMenuButton
                                size="lg"
                                asChild
                                className="md:h-8 md:p-0"
                            >
                                <a href="#">
                                    <div className="bg-sidebar-primary text-sidebar-primary-foreground flex aspect-square size-8 items-center justify-center rounded-lg">
                                        <Command className="size-4" />
                                    </div>
                                    <div className="grid flex-1 text-left text-sm leading-tight">
                                        <span className="truncate font-medium">
                                            Acme Inc
                                        </span>
                                        <span className="truncate text-xs">
                                            Enterprise
                                        </span>
                                    </div>
                                </a>
                            </SidebarMenuButton>
                        </SidebarMenuItem>
                    </SidebarMenu>
                </SidebarHeader>
                <SidebarContent>
                    <SidebarGroup>
                        <SidebarGroupContent className="px-1.5 md:px-0">
                            <SidebarMenu>
                                {[
                                    {
                                        id: 'chats',
                                        icon: MessageSquare,
                                        label: 'Чаты',
                                    },
                                    {
                                        id: 'calls',
                                        icon: Phone,
                                        label: 'Звонки',
                                    },
                                    {
                                        id: 'contacts',
                                        icon: Users2,
                                        label: 'Контакты',
                                    },
                                ].map((item) => (
                                    <SidebarMenuItem key={item.id}>
                                        <SidebarMenuButton
                                            tooltip={{
                                                children: item.label,
                                                hidden: false,
                                            }}
                                            isActive={activeTab === item.id}
                                            onClick={() =>
                                                setActiveTab(item.id)
                                            }
                                            className="px-2.5 md:px-2"
                                        >
                                            <item.icon />
                                            <span>{item.label}</span>
                                        </SidebarMenuButton>
                                    </SidebarMenuItem>
                                ))}
                            </SidebarMenu>
                        </SidebarGroupContent>
                    </SidebarGroup>
                </SidebarContent>
                {user && (
                    <SidebarFooter>
                        <Sheet>
                            <SheetTrigger>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <span className="size-8 flex items-center justify-center hover:bg-sidebar-accent rounded-md transition-colors cursor-pointer text-muted-foreground">
                                            <LucideSettings className="size-5" />
                                        </span>
                                    </TooltipTrigger>
                                    <TooltipContent side="right">
                                        Настройки
                                    </TooltipContent>
                                </Tooltip>
                            </SheetTrigger>
                            <SettingsSheet user={user} />
                        </Sheet>

                        <Sheet>
                            <SheetTrigger>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Avatar className="size-8 rounded-lg cursor-pointer hover:opacity-80 transition-opacity">
                                            <AvatarImage
                                                src={user.avatar}
                                                alt={user.name || ''}
                                            />
                                            <AvatarFallback className="rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
                                                {user.username
                                                    .slice(0, 2)
                                                    .toUpperCase()}
                                            </AvatarFallback>
                                        </Avatar>
                                    </TooltipTrigger>
                                    <TooltipContent side="right">
                                        Профиль
                                    </TooltipContent>
                                </Tooltip>
                            </SheetTrigger>
                            <ProfileSheet user={user} />
                        </Sheet>
                    </SidebarFooter>
                )}
            </Sidebar>

            <Sidebar
                collapsible="none"
                className="hidden flex-1 md:flex bg-muted/10 min-w-0"
            >
                <SidebarHeader className="gap-3.5 border-b p-4">
                    <div className="flex w-full items-center justify-between">
                        <div className="text-base font-medium text-foreground">
                            {activeTab === 'chats' ? 'Сообщения' : 'Контакты'}
                        </div>
                        <div className="flex items-center gap-2">
                            <Dialog>
                                <DialogTrigger className="text-muted-foreground hover:text-primary">
                                    <Plus className="size-5" />
                                </DialogTrigger>
                                <SearchUsersDialogContent />
                            </Dialog>
                        </div>
                    </div>
                    <div className="relative">
                        <Search className="absolute left-2 top-2.5 size-4 text-muted-foreground" />
                        <SidebarInput placeholder="Поиск..." className="pl-8" />
                    </div>
                </SidebarHeader>

                <SidebarContent>
                    <SidebarGroup className="px-0">
                        <SidebarGroupContent>
                            {data.chats.map((chat) => (
                                <div
                                    key={chat.id}
                                    onClick={() => setActiveChatId(chat.id)}
                                    className={`flex cursor-pointer items-center gap-3 border-b p-4 text-sm transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground ${
                                        activeChatId === chat.id
                                            ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                                            : ''
                                    }`}
                                >
                                    <Avatar className="h-10 w-10 border">
                                        <AvatarImage src={chat.avatar} />
                                        <AvatarFallback className="font-semibold">
                                            {chat.name
                                                .substring(0, 2)
                                                .toUpperCase()}
                                        </AvatarFallback>
                                    </Avatar>
                                    <div className="flex flex-1 flex-col overflow-hidden">
                                        <div className="flex justify-between font-medium">
                                            <span className="truncate">
                                                {chat.name}
                                            </span>
                                            <span className="text-xs text-muted-foreground ml-2 whitespace-nowrap">
                                                {chat.date}
                                            </span>
                                        </div>
                                        <div className="flex justify-between items-center mt-1">
                                            <span className="truncate text-xs text-muted-foreground pr-2">
                                                {chat.lastMessage}
                                            </span>
                                            {chat.unread > 0 && (
                                                <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1 text-[10px] text-primary-foreground">
                                                    {chat.unread}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </SidebarGroupContent>
                    </SidebarGroup>
                </SidebarContent>
            </Sidebar>
        </Sidebar>
    );
}
