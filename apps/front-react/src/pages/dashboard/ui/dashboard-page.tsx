import { SidebarInset, SidebarProvider } from '@/shared/ui/sidebar';
import { ChatWindow } from '@/widgets/chat-window';
import { AppSidebar } from '@/widgets/sidebar';
import { MessageSquareDashed } from 'lucide-react';

export function DashboardPage() {
    // В реальном приложении здесь проверяем наличие chatId в URL
    const isChatSelected = true;

    return (
        <SidebarProvider
            style={
                {
                    '--sidebar-width': '350px',
                } as React.CSSProperties
            }
        >
            <AppSidebar />

            <SidebarInset className="h-svh overflow-hidden">
                {isChatSelected ? (
                    <ChatWindow />
                ) : (
                    <div className="flex flex-1 flex-col items-center justify-center gap-4 bg-muted/10">
                        <div className="flex h-20 w-20 items-center justify-center rounded-full bg-muted">
                            <MessageSquareDashed className="size-10 text-muted-foreground" />
                        </div>
                        <div className="text-center">
                            <h2 className="text-2xl font-bold">
                                Realtime chat
                            </h2>
                            <p className="text-muted-foreground mt-2">
                                Выберите чат, чтобы начать общение, <br /> или
                                создайте новый контакт.
                            </p>
                        </div>
                    </div>
                )}
            </SidebarInset>
        </SidebarProvider>
    );
}
