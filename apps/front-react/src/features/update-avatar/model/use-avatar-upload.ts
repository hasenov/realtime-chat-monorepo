import { toast } from 'sonner';
import { useUploadAvatarMutation } from '../api/upload-avatar-api';

export const useAvatarUpload = () => {
    const [uploadAvatar, { isLoading }] = useUploadAvatarMutation();

    const handleFileChange = async (
        event: React.ChangeEvent<HTMLInputElement>
    ) => {
        const file = event.target.files?.[0];
        if (!file) return;

        if (!file.type.startsWith('image/')) {
            toast.error('Please select an image');
            return;
        }

        if (file.size > 5 * 1024 * 1024) {
            toast.error('File is too large (5mb max)');
            return;
        }

        const formData = new FormData();
        formData.append('avatar', file);

        try {
            await uploadAvatar(formData).unwrap();
            event.target.value = '';
        } catch (error) {
            console.error(error);
        }
    };

    return {
        handleFileChange,
        isLoading,
    };
};
