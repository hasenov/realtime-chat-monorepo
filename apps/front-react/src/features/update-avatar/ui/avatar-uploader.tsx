import { getImageUrl } from '@/shared/lib/get-image-url';
import { Avatar, AvatarFallback, AvatarImage } from '@/shared/ui/avatar';
import type { User } from '@realtime-chat/schema';
import { Camera } from 'lucide-react';
import { useAvatarUpload } from '../model/use-avatar-upload';

interface AvatarUploaderProps {
    user: User;
}

export function AvatarUploader({ user }: AvatarUploaderProps) {
    const { handleFileChange, isLoading } = useAvatarUpload();

    return (
        <label className="relative group cursor-pointer">
            <input
                type="file"
                className="sr-only"
                accept="image/jpeg, image/png, image/webp"
                onChange={handleFileChange}
                disabled={isLoading}
            />
            <Avatar className="h-40 w-40 border-4 border-background shadow-sm">
                <AvatarImage
                    src={getImageUrl(user.avatar)}
                    className="object-cover"
                />
                <AvatarFallback className="text-4xl bg-muted text-muted-foreground">
                    {user.username?.[0]?.toUpperCase()}
                </AvatarFallback>
            </Avatar>
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 rounded-full bg-black/60 opacity-0 transition-opacity group-hover:opacity-100 text-white font-medium">
                <Camera className="size-8" />
                <span className="text-xs text-center px-2">
                    Изменить <br /> фото
                </span>
            </div>
        </label>
    );
}
