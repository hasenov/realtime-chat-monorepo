import { Avatar, AvatarFallback, AvatarImage } from '@/shared/ui/avatar';
import { Button } from '@/shared/ui/button';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu';
import { Input } from '@/shared/ui/input';
import { ScrollArea } from '@/shared/ui/scroll-area';
import { Separator } from '@/shared/ui/separator';
import {
    Sheet,
    SheetContent,
    SheetHeader,
    SheetTitle,
    SheetTrigger,
} from '@/shared/ui/sheet';
import {
    Info,
    MoreVertical,
    Paperclip,
    Phone,
    Send,
    Smile,
    Video,
} from 'lucide-react';
import * as React from 'react';

// mock data
const messages = [
    {
        id: 1,
        text: 'Привет! Давно не виделись.',
        sender: 'them',
        time: '10:00',
    },
    {
        id: 2,
        text: 'Привет! Да, сто лет прошло. Как дела?',
        sender: 'me',
        time: '10:05',
    },
    {
        id: 3,
        text: 'Работаю над новым проектом.',
        sender: 'them',
        time: '10:07',
    },
    {
        id: 4,
        text: 'А что за проект?',
        sender: 'me',
        time: '10:10',
    },
    {
        id: 5,
        text: 'Чат приложение.',
        sender: 'them',
        time: '10:11',
    },
];

export function ChatWindow() {
    return (
        <div className="flex h-full flex-col bg-background">
            <header className="flex h-16 shrink-0 items-center justify-between border-b px-4 bg-background/95 backdrop-blur supports-backdrop-filter:bg-background/60">
                <div className="flex items-center gap-3">
                    <Avatar>
                        <AvatarImage src="https://i.pravatar.cc/300" />
                        <AvatarFallback>JD</AvatarFallback>
                    </Avatar>
                    <div>
                        <div className="font-semibold text-sm">Alice Smith</div>
                        <div className="text-xs text-primary font-medium">
                            Online
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-1">
                    <Button
                        variant="ghost"
                        size="icon"
                        className="text-muted-foreground"
                    >
                        <Phone className="size-5" />
                    </Button>
                    <Button
                        variant="ghost"
                        size="icon"
                        className="text-muted-foreground"
                    >
                        <Video className="size-5" />
                    </Button>

                    <Sheet>
                        <SheetTrigger asChild>
                            <Button
                                variant="ghost"
                                size="icon"
                                className="text-muted-foreground"
                            >
                                <Info className="size-5" />
                            </Button>
                        </SheetTrigger>
                        <SheetContent className="w-75 sm:w-100">
                            <SheetHeader className="pb-4 border-b">
                                <SheetTitle>Информация о контакте</SheetTitle>
                            </SheetHeader>
                            <div className="flex flex-col items-center gap-4 py-6 px-4">
                                <Avatar className="h-24 w-24">
                                    <AvatarImage src="https://ferf1mheo22r9ira.public.blob.vercel-storage.com/avatar-01-nBC72Sn2rggx0HQziYHsphZop1zllM.png" />
                                    <AvatarFallback className="text-2xl">
                                        AS
                                    </AvatarFallback>
                                </Avatar>
                                <div className="text-center">
                                    <h2 className="text-xl font-bold">
                                        Alice Smith
                                    </h2>
                                    <p className="text-sm text-muted-foreground">
                                        +7 (999) 123-45-67
                                    </p>
                                </div>
                            </div>

                            <div className="space-y-4 px-4">
                                <div className="space-y-1">
                                    <Label className="text-xs text-muted-foreground">
                                        О себе
                                    </Label>
                                    <p className="text-sm">
                                        Frontend Developer. Люблю котиков и
                                        React.
                                    </p>
                                </div>
                                <Separator />
                                <div className="space-y-2">
                                    <Label className="text-xs text-muted-foreground">
                                        Медиа
                                    </Label>
                                    <div className="grid grid-cols-4 gap-2">
                                        {[1, 2, 3, 4].map((i) => (
                                            <div
                                                key={i}
                                                className="aspect-square rounded-md bg-muted/50 border"
                                            />
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </SheetContent>
                    </Sheet>

                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button
                                variant="ghost"
                                size="icon"
                                className="text-muted-foreground"
                            >
                                <MoreVertical className="size-5" />
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuItem>Очистить чат</DropdownMenuItem>
                            <DropdownMenuItem className="text-destructive">
                                Заблокировать
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
            </header>

            <ScrollArea className="flex-1 p-4 bg-muted/20">
                <div className="flex flex-col gap-4 max-w-4xl mx-auto">
                    {messages.map((msg) => (
                        <div
                            key={msg.id}
                            className={`flex w-full ${
                                msg.sender === 'me'
                                    ? 'justify-end'
                                    : 'justify-start'
                            }`}
                        >
                            <div
                                className={`flex max-w-[70%] flex-col gap-1 rounded-xl px-4 py-2 text-sm shadow-sm ${
                                    msg.sender === 'me'
                                        ? 'bg-primary text-primary-foreground rounded-tr-none' // Мои сообщения
                                        : 'bg-white dark:bg-zinc-800 border rounded-tl-none' // Чужие сообщения
                                }`}
                            >
                                <div>{msg.text}</div>
                                <div
                                    className={`text-[10px] self-end ${
                                        msg.sender === 'me'
                                            ? 'text-primary-foreground/70'
                                            : 'text-muted-foreground'
                                    }`}
                                >
                                    {msg.time}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </ScrollArea>

            <div className="p-4 border-t bg-background">
                <form
                    className="flex items-end gap-2 max-w-4xl mx-auto"
                    onSubmit={(e) => {
                        e.preventDefault();
                    }}
                >
                    <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="shrink-0 text-muted-foreground"
                    >
                        <Paperclip className="size-5" />
                    </Button>
                    <Input
                        placeholder="Напишите сообщение..."
                        className="min-h-5 bg-muted/50 border-0 focus-visible:ring-1 focus-visible:ring-primary shadow-none"
                    />
                    <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="shrink-0 text-muted-foreground"
                    >
                        <Smile className="size-5" />
                    </Button>
                    <Button type="submit" size="icon" className="shrink-0">
                        <Send className="size-4" />
                    </Button>
                </form>
            </div>
        </div>
    );
}

function Label({
    className,
    children,
}: {
    className?: string;
    children: React.ReactNode;
}) {
    return <div className={`font-medium ${className}`}>{children}</div>;
}
