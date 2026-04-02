import { Skeleton } from '@/shared/ui/skeleton';

export function SearchUsersSkeletons() {
    return Array.from({ length: 3 }).map((_, i) => (
        <div key={`skeleton-${i}`} className="flex items-center gap-3 p-3">
            <Skeleton className="h-10 w-10 rounded-full" />

            <div className="space-y-2">
                <Skeleton className="h-4 w-[120px]" />

                <Skeleton className="h-3 w-[80px]" />
            </div>
        </div>
    ));
}
