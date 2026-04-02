import * as z from 'zod';

export const SearchSchema = z.object({
    q: z.string().min(2).max(50).trim(),
});

export type SearchInput = z.infer<typeof SearchSchema>;
