import { AvatarUploader } from '@/features/update-avatar';
import { Button } from '@/shared/ui/button';
import { Input } from '@/shared/ui/input';
import { Label } from '@/shared/ui/label';
import { SheetContent, SheetHeader, SheetTitle } from '@/shared/ui/sheet';
import { Textarea } from '@/shared/ui/textarea';
import type { User } from '@realtime-chat/schema';
import { Check, Edit2 } from 'lucide-react';
import { useState } from 'react';

interface ProfileSheetProps {
    user: User;
}

export function ProfileSheet({ user }: ProfileSheetProps) {
    const [isEditingName, setIsEditingName] = useState(false);
    const [isEditingAbout, setIsEditingAbout] = useState(false);
    const [name, setName] = useState(user.name || '');
    const [about, setAbout] = useState('Frontend Developer. Люблю котиков.');

    return (
        <SheetContent
            side="left"
            className="w-[350px] p-0 gap-0 border-r sm:max-w-[350px]"
        >
            <SheetHeader className="bg-primary px-4 py-10 text-primary-foreground">
                <SheetTitle className="text-primary-foreground text-xl font-medium">
                    Профиль
                </SheetTitle>
            </SheetHeader>

            <div className="flex flex-col gap-6 overflow-y-auto bg-muted/10 h-full pb-6">
                <div className="flex justify-center py-6">
                    <AvatarUploader user={user} />
                </div>

                <div className="bg-background px-6 py-4 shadow-sm space-y-3">
                    <Label className="text-xs text-primary font-bold uppercase tracking-wider">
                        Ваше имя
                    </Label>
                    <div className="flex items-center justify-between gap-2">
                        {isEditingName ? (
                            <div className="flex w-full items-center gap-2 animate-in fade-in zoom-in-95 duration-200">
                                <Input
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                    className="h-8 border-b-2 border-primary border-t-0 border-x-0 rounded-none px-0 shadow-none focus-visible:ring-0"
                                    autoFocus
                                />
                                <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-8 w-8 text-muted-foreground hover:text-primary"
                                    onClick={() => setIsEditingName(false)}
                                >
                                    <Check className="size-4" />
                                </Button>
                            </div>
                        ) : (
                            <>
                                <span className="text-base truncate flex-1">
                                    {name}
                                </span>
                                <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-8 w-8 text-muted-foreground"
                                    onClick={() => setIsEditingName(true)}
                                >
                                    <Edit2 className="size-4" />
                                </Button>
                            </>
                        )}
                    </div>
                </div>

                <div className="bg-background px-6 py-4 shadow-sm space-y-3">
                    <Label className="text-xs text-primary font-bold uppercase tracking-wider">
                        Сведения
                    </Label>
                    <div className="flex items-start justify-between gap-2">
                        {isEditingAbout ? (
                            <div className="flex w-full items-end gap-2 animate-in fade-in zoom-in-95 duration-200">
                                <Textarea
                                    value={about}
                                    onChange={(e) => setAbout(e.target.value)}
                                    className="min-h-[60px] resize-none border-b-2 border-primary border-t-0 border-x-0 rounded-none px-0 shadow-none focus-visible:ring-0 bg-transparent"
                                    autoFocus
                                />
                                <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-8 w-8 text-muted-foreground hover:text-primary mb-1"
                                    onClick={() => setIsEditingAbout(false)}
                                >
                                    <Check className="size-4" />
                                </Button>
                            </div>
                        ) : (
                            <>
                                <span className="text-sm text-foreground/90 leading-relaxed flex-1 break-words">
                                    {about}
                                </span>
                                <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-8 w-8 text-muted-foreground mt-[-2px]"
                                    onClick={() => setIsEditingAbout(true)}
                                >
                                    <Edit2 className="size-4" />
                                </Button>
                            </>
                        )}
                    </div>
                </div>
            </div>
        </SheetContent>
    );
}
