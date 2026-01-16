import { logout, useLogoutMutation } from '@/entities/session';
import { useAppDispatch } from '@/shared/lib/hooks';

export const useLogout = () => {
    const [triggerLogout, { isLoading }] = useLogoutMutation();
    const dispatch = useAppDispatch();

    const handleLogout = async () => {
        try {
            await triggerLogout().unwrap();
            dispatch(logout());
        } catch (err) {
            console.error(err);
        }
    };

    return { handleLogout, isLoading };
};
