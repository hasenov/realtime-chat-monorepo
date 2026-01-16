import { setCredentials } from '@/entities/session';
import { handleApiError } from '@/shared/lib/handle-api-error';
import { useAppDispatch } from '@/shared/lib/hooks';
import { zodResolver } from '@hookform/resolvers/zod';
import {
    RegisterFormSchema,
    type RegisterFormInput,
} from '@realtime-chat/schema';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router';
import { useRegisterMutation } from '../api/register-api';

export const useRegisterForm = () => {
    const dispatch = useAppDispatch();
    const navigate = useNavigate();
    const [register, { isLoading }] = useRegisterMutation();

    const form = useForm<RegisterFormInput>({
        resolver: zodResolver(RegisterFormSchema),
        defaultValues: {
            email: '',
            username: '',
            name: '',
            password: '',
            password2: '',
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

    const onSubmit = async (values: RegisterFormInput) => {
        const { password2, ...data } = values;
        try {
            const res = await register(data).unwrap();
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
