import type { ApiErrorResponse } from '@realtime-chat/schema';
import type { FetchBaseQueryError } from '@reduxjs/toolkit/query';
import type { FieldValues, Path, UseFormSetError } from 'react-hook-form';
import { toast } from 'sonner';

/**
 * Type predicate: проверяет, является ли ошибка ответом от RTK Query (HTTP error)
 */
export function isFetchBaseQueryError(
    error: unknown
): error is FetchBaseQueryError {
    return typeof error === 'object' && error != null && 'status' in error;
}

/**
 * Type predicate: проверяет, соответствует ли data нашему формату ApiErrorResponse
 */
function isApiErrorData(data: unknown): data is ApiErrorResponse {
    return (
        typeof data === 'object' &&
        data !== null &&
        'message' in data &&
        // Проверяем, что message - строка
        typeof (data as any).message === 'string'
    );
}

export const handleApiError = <T extends FieldValues>(
    error: unknown,
    setError: UseFormSetError<T>
) => {
    // 1. Проверяем, что это ошибка запроса (HTTP)
    if (isFetchBaseQueryError(error)) {
        const errorData = error.data;

        // 2. Проверяем, что сервер вернул ошибку в нашем ожидаемом формате
        if (isApiErrorData(errorData)) {
            // А. Если есть детальные ошибки полей (обычно статус 400 / ZodError)
            if (errorData.errors && Array.isArray(errorData.errors)) {
                errorData.errors.forEach((err) => {
                    setError(err.path as Path<T>, {
                        type: 'server',
                        message: err.message,
                    });
                });
            }
            // Б. Если это общая ошибка (401 Unauthorized, 409 Conflict, etc.)
            else {
                setError('root', {
                    type: 'server',
                    message: errorData.message, // "Invalid login or password"
                });
            }
        } else {
            // В. Сервер вернул что-то странное (не JSON, или HTML страницу ошибки nginx)
            console.error('Unknown API Error Format:', error);
            toast.error('Something went wrong on the server');
            return;
        }
    }
    // 3. Ошибки сети, парсинга или JS (SerializedError)
    else {
        console.error('Non-HTTP Error:', error);
        toast.error('Network error or internal issue. Please try again.');
    }
};
