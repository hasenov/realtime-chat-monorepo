import { useUpdateProfileMutation } from '@/entities/session/api/session-api';
import { showApiErrorToast } from '@/shared/lib/show-api-error-toast';
import type { User } from '@realtime-chat/schema';
import { useState } from 'react';

export function useProfileSheetForm(user: User) {
    const [updateProfile] = useUpdateProfileMutation();

    const [isEditingName, setIsEditingName] = useState(false);
    const [isEditingBio, setIsEditingBio] = useState(false);

    const [name, setName] = useState(user.name || '');
    const [bio, setBio] = useState(user.bio || '');

    const handleSaveName = async () => {
        if (name.trim() === user.name) {
            setIsEditingName(false);
            return;
        }

        try {
            await updateProfile({ name: name.trim() }).unwrap();
            setIsEditingName(false);
        } catch (error) {
            showApiErrorToast(error);
            setName(user.name || '');
        }
    };

    const handleSaveBio = async () => {
        if (bio.trim() === user.bio) {
            setIsEditingBio(false);
            return;
        }

        try {
            await updateProfile({ bio: bio.trim() }).unwrap();
            setIsEditingBio(false);
        } catch (error) {
            showApiErrorToast(error);
            setBio(user.bio || '');
        }
    };

    return {
        name,
        setName,
        isEditingName,
        setIsEditingName,
        handleSaveName,
        bio,
        setBio,
        isEditingBio,
        setIsEditingBio,
        handleSaveBio,
    };
}
