import { useGetMeQuery } from '@/entities/session';
import { useAppSelector } from '@/shared/lib/hooks';
import { Spinner } from '@/shared/ui/spinner';

export function AuthProvider({ children }: { children: React.ReactNode }) {
    const isAuth = useAppSelector((state) => state.session.isAuth);
    const { data, isLoading, isError, isSuccess } = useGetMeQuery(undefined, {
        skip: isAuth,
    });

    if (isLoading) {
        return (
            <div className="h-svh flex items-center justify-center">
                <Spinner className="size-12 text-primary" />
            </div>
        );
    }

    return <>{children}</>;
}
