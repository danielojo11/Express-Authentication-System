import supabase from "../config/storage.js";

export const uploadProfilePic = async (userId, buffer, mimetype, filename) => {
  const extension = mimetype.split("/")[1];
  const path = `${userId}/${filename}.${extension}`;

  const { error } = await supabase.storage
    .from(process.env.SUPABASE_STORAGE_BUCKET)
    .upload(path, buffer, {
      contentType: mimetype,
      upsert: true,
    });

  if (error) {
    throw error;
  }

  return path;
};

export const deleteAvatar = async (path) => {
  if (!path) return;

  const { error } = await supabase.storage.from(process.env.SUPABASE_STORAGE_BUCKET).remove([path]);

  if (error) {
    throw error;
  }
};

export const getAvatarUrl = async (path) => {
  if (!path) return;

  const { data } = await supabase.storage
    .from(process.env.SUPABASE_STORAGE_BUCKET)
    .getPublicUrl(path);

  return data.publicUrl;
};
