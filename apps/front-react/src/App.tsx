import { Toaster } from '@/shared/ui/sonner';
import { BrowserRouter } from 'react-router';
import { AuthProvider } from './app/providers/auth-provider';
import { AppRouter } from './app/providers/router-provider';
import { SocketProvider } from './app/providers/socket-provider';

export function App() {
    return (
        <AuthProvider>
            <SocketProvider>
                <BrowserRouter>
                    <AppRouter />
                    <Toaster />
                </BrowserRouter>
            </SocketProvider>
        </AuthProvider>
    );
}

export default App;
