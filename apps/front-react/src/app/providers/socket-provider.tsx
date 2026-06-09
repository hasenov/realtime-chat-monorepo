import { useAppSelector } from '@/shared/lib/hooks';
import { socketService } from '@/shared/lib/socket/socket-service';
import { useEffect } from 'react';

export function SocketProvider({ children }: { children: React.ReactNode }) {
    const token = useAppSelector((state) => state.session.accessToken);

    useEffect(() => {
        if (!token) {
            socketService.disconnect();
            return;
        }

        socketService.connect(token);
    }, [token]);

    return <>{children}</>;
}
