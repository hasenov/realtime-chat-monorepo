import {
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from '@/shared/ui/dialog';
import { Field, FieldLabel } from '@/shared/ui/field';
import { Input } from '@/shared/ui/input';
import { ScrollArea } from '@/shared/ui/scroll-area';
import { Search } from 'lucide-react';
import { useSearch } from '../model/use-search';
import { SearchUserItem } from './SearchUserItem';
import { SearchUsersSkeletons } from './SearchUsersSkeletons';

export function SearchUsersDialogContent() {
    const { data, isLoading, searchTerm, setSearchTerm } = useSearch();
    const users = data || [];

    const isIdle = !searchTerm && !isLoading;
    const isNotFound = searchTerm && !isLoading && users.length === 0;
    const hasResults = users.length > 0;

    return (
        <DialogContent className="sm:max-w-[425px] p-0 gap-0">
            <DialogHeader className="p-6 pb-2">
                <DialogTitle>Новый чат</DialogTitle>
                <DialogDescription>
                    Введите имя или @username пользователя, чтобы начать
                    общение.
                </DialogDescription>
            </DialogHeader>

            <div className="px-6 pb-4">
                <form className="relative">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Field>
                        <FieldLabel htmlFor="search" className="sr-only">
                            Поиск пользователей
                        </FieldLabel>
                        <Input
                            type="text"
                            placeholder="Поиск пользователей..."
                            className="pl-9 bg-muted/50 border-none focus-visible:ring-1"
                            autoFocus
                            id="search"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </Field>
                </form>
            </div>

            <Separator />

            <ScrollArea className="h-[300px]">
                <div className="p-2">
                    {isLoading && <SearchUsersSkeletons />}

                    {!isLoading &&
                        hasResults &&
                        users.map((user) => (
                            <SearchUserItem key={user.id} user={user} />
                        ))}

                    {isNotFound && (
                        <div className="py-10 text-center">
                            <p className="text-sm font-medium">
                                Пользователи не найдены
                            </p>
                            <p className="text-xs text-muted-foreground">
                                По запросу "{searchTerm}" совпадений нет
                            </p>
                        </div>
                    )}
                </div>
            </ScrollArea>
        </DialogContent>
    );
}

function Separator() {
    return <div className="h-[1px] bg-border w-full" />;
}
