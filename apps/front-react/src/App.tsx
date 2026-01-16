import { Toaster } from '@/shared/ui/sonner';
import { BrowserRouter } from 'react-router';
import { AuthProvider } from './app/providers/auth-provider';
import { AppRouter } from './app/providers/router-provider';

export function App() {
    return (
        <AuthProvider>
            <BrowserRouter>
                <AppRouter />
                <Toaster />
            </BrowserRouter>
        </AuthProvider>
    );
}

export default App;
