import { setCredentials } from '@/entities/session';
import { handleApiError } from '@/shared/lib/handle-api-error';
import { useAppDispatch } from '@/shared/lib/hooks';
import { zodResolver } from '@hookform/resolvers/zod';
import { LoginSchema, type LoginInput } from '@realtime-chat/schema';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router';
import { useLoginMutation } from '../api/login-api';

export const useLoginForm = () => {
    const dispatch = useAppDispatch();
    const navigate = useNavigate();
    const [login, { isLoading }] = useLoginMutation();

    const form = useForm<LoginInput>({
        resolver: zodResolver(LoginSchema),
        defaultValues: {
            login: '',
            password: '',
        },
    });

    useEffect(() => {
        const subscription = form.watch(() => {
            if (form.formState.errors.root) {
                form.clearErrors('root');
            }
        });
        return () => subscription.unsubscribe();
    }, [form.watch, form.formState.errors.root, form.clearErrors]);

    const onSubmit = async (data: LoginInput) => {
        try {
            const res = await login(data).unwrap();
            dispatch(
                setCredentials({
                    user: res.data.user,
                    accessToken: res.data.accessToken,
                })
            );

            navigate('/');
        } catch (error) {
            handleApiError(error, form.setError);
        }
    };

    return {
        form,
        isLoading,
        onSubmit: form.handleSubmit(onSubmit),
        rootError: form.formState.errors.root?.message,
    };
};
