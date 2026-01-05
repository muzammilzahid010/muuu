// Cloudinary upload utility for videos and images
// Fetches video from VEO URL and uploads to Cloudinary
// Converts base64 images and uploads to Cloudinary

import { readFile } from 'fs/promises';

interface CloudinaryUploadResponse {
  secure_url: string;
  public_id: string;
  format: string;
  duration: number;
  width: number;
  height: number;
  url: string;
}

// Get Cloudinary settings from database
async function getCloudinaryConfig() {
  const { storage } = await import('./storage');
  const settings = await storage.getAppSettings();
  
  const cloudName = settings?.cloudinaryCloudName || 'dfk0nvgff';
  const uploadPreset = settings?.cloudinaryUploadPreset || 'demo123';
  
  return {
    cloudName,
    uploadPreset,
    videoUploadUrl: `https://api.cloudinary.com/v1_1/${cloudName}/video/upload`,
    imageUploadUrl: `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
  };
}

export async function uploadVideoToCloudinary(videoUrlOrPath: string): Promise<string> {
  try {
    // Get Cloudinary config from database
    const config = await getCloudinaryConfig();
    
    let videoBlob: Blob;
    
    // Check if it's a local file path or URL
    if (videoUrlOrPath.startsWith('http://') || videoUrlOrPath.startsWith('https://')) {
      // It's a URL - fetch from remote
      console.log('[Cloudinary] Starting upload from URL:', videoUrlOrPath.substring(0, 100));
      console.log('[Cloudinary] Fetching video from URL...');
      const videoResponse = await fetch(videoUrlOrPath);
      
      if (!videoResponse.ok) {
        throw new Error(`Failed to fetch video: ${videoResponse.statusText}`);
      }

      videoBlob = await videoResponse.blob();
      console.log('[Cloudinary] Video fetched, size:', videoBlob.size, 'bytes');
    } else {
      // It's a local file path - read from disk and convert to Blob
      console.log('[Cloudinary] Starting upload from local file:', videoUrlOrPath);
      const fileBuffer = await readFile(videoUrlOrPath);
      videoBlob = new Blob([fileBuffer], { type: 'video/mp4' });
      console.log('[Cloudinary] File read, size:', videoBlob.size, 'bytes');
    }

    // Create FormData for Cloudinary upload
    const formData = new FormData();
    formData.append('file', videoBlob, 'video.mp4');
    formData.append('upload_preset', config.uploadPreset);

    // Upload to Cloudinary
    console.log('[Cloudinary] Uploading to Cloudinary...');
    const uploadResponse = await fetch(config.videoUploadUrl, {
      method: 'POST',
      body: formData,
    });

    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      throw new Error(`Cloudinary upload failed: ${uploadResponse.statusText} - ${errorText}`);
    }

    const result: CloudinaryUploadResponse = await uploadResponse.json();
    console.log('[Cloudinary] Upload successful! URL:', result.secure_url);
    
    return result.secure_url;
  } catch (error) {
    console.error('[Cloudinary] Upload error:', error);
    throw new Error(`Failed to upload video to Cloudinary: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

export async function uploadImageToCloudinary(base64Data: string, extension: string = 'png'): Promise<string> {
  try {
    // Get Cloudinary config from database
    const config = await getCloudinaryConfig();
    
    console.log(`[Cloudinary] Converting base64 to ${extension} image...`);
    
    // Convert base64 to buffer
    const imageBuffer = Buffer.from(base64Data, 'base64');
    console.log(`[Cloudinary] Image size: ${imageBuffer.length} bytes`);
    
    // Create blob from buffer
    const imageBlob = new Blob([imageBuffer], { 
      type: extension === 'jpg' ? 'image/jpeg' : `image/${extension}` 
    });

    // Create FormData for Cloudinary upload
    const formData = new FormData();
    formData.append('file', imageBlob, `image.${extension}`);
    formData.append('upload_preset', config.uploadPreset);
    formData.append('folder', 'ai-images');

    // Upload to Cloudinary
    console.log('[Cloudinary] Uploading image to Cloudinary...');
    const uploadResponse = await fetch(config.imageUploadUrl, {
      method: 'POST',
      body: formData,
    });

    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      throw new Error(`Cloudinary upload failed: ${uploadResponse.statusText} - ${errorText}`);
    }

    const result: CloudinaryUploadResponse = await uploadResponse.json();
    console.log('[Cloudinary] Image upload successful! URL:', result.secure_url);
    
    return result.secure_url;
  } catch (error) {
    console.error('[Cloudinary] Image upload error:', error);
    throw new Error(`Failed to upload image to Cloudinary: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Upload base64 video directly to Cloudinary (used by bulk/background generation)
export async function uploadBase64VideoToCloudinary(base64Data: string): Promise<string> {
  try {
    const config = await getCloudinaryConfig();
    
    console.log('[Cloudinary] Converting base64 video for upload...');
    
    // Convert base64 to buffer
    const videoBuffer = Buffer.from(base64Data, 'base64');
    console.log(`[Cloudinary] Video size: ${Math.round(videoBuffer.length / (1024 * 1024))}MB`);
    
    // Create blob from buffer
    const videoBlob = new Blob([videoBuffer], { type: 'video/mp4' });

    // Create FormData for Cloudinary upload
    const formData = new FormData();
    formData.append('file', videoBlob, 'video.mp4');
    formData.append('upload_preset', config.uploadPreset);
    formData.append('folder', 'ai-videos');

    // Upload to Cloudinary
    console.log('[Cloudinary] Uploading video to Cloudinary...');
    const uploadResponse = await fetch(config.videoUploadUrl, {
      method: 'POST',
      body: formData,
    });

    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      throw new Error(`Cloudinary upload failed: ${uploadResponse.statusText} - ${errorText}`);
    }

    const result: CloudinaryUploadResponse = await uploadResponse.json();
    console.log('[Cloudinary] Video upload successful! URL:', result.secure_url);
    
    return result.secure_url;
  } catch (error) {
    console.error('[Cloudinary] Video upload error:', error);
    throw new Error(`Failed to upload video to Cloudinary: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Get storage method from database settings
async function getStorageMethod(): Promise<"cloudinary" | "google_drive" | "cloudinary_with_fallback" | "direct_to_user" | "local_disk"> {
  const { storage } = await import('./storage');
  const settings = await storage.getAppSettings();
  return (settings?.storageMethod as "cloudinary" | "google_drive" | "cloudinary_with_fallback" | "direct_to_user" | "local_disk") || 'cloudinary_with_fallback';
}

// Upload base64 video using configured storage method with memory fallback
export async function uploadBase64VideoWithFallback(
  base64Data: string, 
  videoId?: string, 
  prompt?: string, 
  aspectRatio?: string
): Promise<{ url: string; storedInMemory: boolean }> {
  const storageMethod = await getStorageMethod();
  const sizeMB = Math.round(Buffer.from(base64Data, 'base64').length / 1024 / 1024 * 10) / 10;
  console.log(`[Upload] Method: ${storageMethod}, Size: ${sizeMB}MB`);

  // Handle direct_to_user - return data URL without uploading
  if (storageMethod === 'direct_to_user') {
    console.log(`[Upload] Direct to user mode - returning data URL (${sizeMB}MB)`);
    const dataUrl = `data:video/mp4;base64,${base64Data}`;
    return { url: dataUrl, storedInMemory: false };
  }

  // Handle local_disk storage - saves to VPS disk with 3-hour expiry
  if (storageMethod === 'local_disk') {
    try {
      const { saveVideoToLocalDisk } = await import('./localDiskStorage');
      const result = await saveVideoToLocalDisk(base64Data, {
        prompt,
        externalVideoId: videoId  // Preserve video ID from generation pipeline
      });
      console.log(`[Upload] Local disk success: ${result.videoUrl}`);
      return { url: result.videoUrl, storedInMemory: false };
    } catch (localError) {
      console.log('[Upload] Local disk failed, trying Cloudinary fallback...');
      try {
        const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
        return { url: cloudinaryUrl, storedInMemory: false };
      } catch (cloudinaryError) {
        console.error('[Upload] All storage methods failed:', { localError, cloudinaryError });
        throw new Error(`Local disk and Cloudinary failed: ${localError}`);
      }
    }
  }

  const tryMemoryFallback = async (cloudinaryError: any, driveError: any): Promise<{ url: string; storedInMemory: boolean }> => {
    if (!videoId) {
      throw new Error(`Both uploads failed. Cloudinary: ${cloudinaryError}, Drive: ${driveError}`);
    }
    
    console.log('[Upload] Both cloud uploads failed, storing in memory cache...');
    const { storeVideoInMemory } = await import('./memoryVideoCache');
    const buffer = Buffer.from(base64Data, 'base64');
    const stored = storeVideoInMemory(videoId, buffer, prompt || '', aspectRatio || '16:9');
    
    if (stored) {
      console.log(`[Upload] Video ${videoId} stored in memory cache (${sizeMB}MB)`);
      return { url: `memory://${videoId}`, storedInMemory: true };
    }
    
    throw new Error(`All storage methods failed. Cloudinary: ${cloudinaryError}, Drive: ${driveError}, Memory: cache full`);
  };

  if (storageMethod === 'google_drive') {
    try {
      const { uploadBase64VideoToGoogleDrive, getDirectDownloadLink } = await import('./googleDrive');
      const driveResult = await uploadBase64VideoToGoogleDrive(base64Data);
      const driveUrl = getDirectDownloadLink(driveResult.id);
      console.log('[Upload] Drive success:', driveUrl.slice(0, 60));
      return { url: driveUrl, storedInMemory: false };
    } catch (driveError) {
      console.log('[Upload] Drive failed, trying Cloudinary...');
      try {
        const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
        return { url: cloudinaryUrl, storedInMemory: false };
      } catch (cloudinaryError) {
        return tryMemoryFallback(cloudinaryError, driveError);
      }
    }
  }

  if (storageMethod === 'cloudinary') {
    try {
      const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
      return { url: cloudinaryUrl, storedInMemory: false };
    } catch (cloudinaryError) {
      try {
        const { uploadBase64VideoToGoogleDrive, getDirectDownloadLink } = await import('./googleDrive');
        const driveResult = await uploadBase64VideoToGoogleDrive(base64Data);
        const driveUrl = getDirectDownloadLink(driveResult.id);
        return { url: driveUrl, storedInMemory: false };
      } catch (driveError) {
        return tryMemoryFallback(cloudinaryError, driveError);
      }
    }
  }

  // Default: Cloudinary with Drive fallback, then memory
  try {
    const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
    return { url: cloudinaryUrl, storedInMemory: false };
  } catch (cloudinaryError) {
    console.log('[Upload] Cloudinary failed, trying Drive...');
    try {
      const { uploadBase64VideoToGoogleDrive, getDirectDownloadLink } = await import('./googleDrive');
      const driveResult = await uploadBase64VideoToGoogleDrive(base64Data);
      const driveUrl = getDirectDownloadLink(driveResult.id);
      return { url: driveUrl, storedInMemory: false };
    } catch (driveError) {
      return tryMemoryFallback(cloudinaryError, driveError);
    }
  }
}
