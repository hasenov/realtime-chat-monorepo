import { LoginPage, RegisterPage } from '@/pages/auth';
import { DashboardPage } from '@/pages/dashboard';
import { useAppSelector } from '@/shared/lib/hooks';
import { Navigate, Outlet, Route, Routes } from 'react-router';

const PublicRoute = () => {
    const isAuth = useAppSelector((state) => state.session.isAuth);
    return !isAuth ? <Outlet /> : <Navigate to="/" replace />;
};

const PrivateRoute = () => {
    const isAuth = useAppSelector((state) => state.session.isAuth);
    return isAuth ? <Outlet /> : <Navigate to="/login" replace />;
};

export function AppRouter() {
    return (
        <Routes>
            <Route element={<PublicRoute />}>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />
            </Route>
            <Route element={<PrivateRoute />}>
                <Route path="/" element={<DashboardPage />} />
            </Route>
        </Routes>
    );
}
