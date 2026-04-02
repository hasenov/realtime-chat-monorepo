import { useDebounce } from '@/shared/lib/use-debounce';
import { useState } from 'react';
import { useSearchQuery } from '../api/search-api';

export const useSearch = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const debouncedSearchTerm = useDebounce(searchTerm);

    const { data, isLoading, isFetching } = useSearchQuery(
        debouncedSearchTerm,
        {
            skip: debouncedSearchTerm.length < 2,
        }
    );

    return {
        data,
        isLoading,
        isFetching,
        searchTerm,
        setSearchTerm,
    };
};
