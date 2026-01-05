// Google Drive video upload utility
// Uploads large merged videos to Google Drive

import { google } from 'googleapis';
import { createReadStream } from 'fs';
import { readFile } from 'fs/promises';

interface UploadResult {
  id: string;
  webViewLink: string;
  webContentLink: string;
}

// Default Shared Drive ID (fallback)
const DEFAULT_SHARED_DRIVE_ID = '0AA_GJi95SjbdUk9PVA';

// Get Google Drive credentials from database or environment
async function getGoogleDriveCredentials(): Promise<object> {
  // First try database
  try {
    const { storage } = await import('./storage');
    const settings = await storage.getAppSettings();
    
    if (settings?.googleDriveCredentials) {
      const parsed = JSON.parse(settings.googleDriveCredentials);
      console.log('[Google Drive] Using credentials from database');
      return parsed;
    }
  } catch (dbError) {
    console.log('[Google Drive] Could not get credentials from database:', dbError);
  }
  
  // Fallback to environment variable
  const envCredentials = process.env.GOOGLE_DRIVE_CREDENTIALS;
  if (envCredentials) {
    console.log('[Google Drive] Using credentials from environment variable');
    return JSON.parse(envCredentials);
  }
  
  throw new Error('Google Drive credentials not configured. Please add them in Admin Settings.');
}

// Get Google Drive folder/shared drive ID from database or use default
async function getGoogleDriveFolderId(): Promise<string> {
  try {
    const { storage } = await import('./storage');
    const settings = await storage.getAppSettings();
    
    if (settings?.googleDriveFolderId) {
      console.log('[Google Drive] Using folder ID from database:', settings.googleDriveFolderId);
      return settings.googleDriveFolderId;
    }
  } catch (dbError) {
    console.log('[Google Drive] Could not get folder ID from database:', dbError);
  }
  
  // Fallback to environment variable
  const envFolderId = process.env.GOOGLE_DRIVE_FOLDER_ID;
  if (envFolderId) {
    console.log('[Google Drive] Using folder ID from environment variable');
    return envFolderId;
  }
  
  console.log('[Google Drive] Using default folder ID:', DEFAULT_SHARED_DRIVE_ID);
  return DEFAULT_SHARED_DRIVE_ID;
}

/**
 * Upload a video file to Google Drive
 * @param filePath Local path to the video file
 * @param fileName Name for the file in Google Drive
 * @returns Object containing file ID and shareable link
 */
export async function uploadVideoToGoogleDrive(
  filePath: string,
  fileName: string = 'merged-video.mp4'
): Promise<UploadResult> {
  try {
    console.log('[Google Drive] Starting upload from local file:', filePath);
    
    // Get Google Drive credentials from database or environment
    const credentialsJson = await getGoogleDriveCredentials();

    // Create auth client
    const auth = new google.auth.GoogleAuth({
      credentials: credentialsJson,
      scopes: ['https://www.googleapis.com/auth/drive.file'],
    });

    const drive = google.drive({ version: 'v3', auth });

    // Get file stats
    const fileBuffer = await readFile(filePath);
    console.log('[Google Drive] File size:', fileBuffer.byteLength, 'bytes');

    // Create file metadata
    const fileMetadata = {
      name: fileName,
      mimeType: 'video/mp4',
    };

    // Upload the file
    console.log('[Google Drive] Uploading to Google Drive...');
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: {
        mimeType: 'video/mp4',
        body: createReadStream(filePath),
      },
      fields: 'id, webViewLink, webContentLink',
    });

    const fileId = response.data.id;
    if (!fileId) {
      throw new Error('Failed to get file ID from Google Drive');
    }

    console.log('[Google Drive] Upload successful! File ID:', fileId);

    // Make the file publicly accessible
    await drive.permissions.create({
      fileId,
      requestBody: {
        role: 'reader',
        type: 'anyone',
      },
    });

    console.log('[Google Drive] File set to public access');

    // Get the direct download link
    const file = await drive.files.get({
      fileId,
      fields: 'webViewLink, webContentLink',
    });

    return {
      id: fileId,
      webViewLink: file.data.webViewLink || '',
      webContentLink: file.data.webContentLink || '',
    };
  } catch (error) {
    console.error('[Google Drive] Upload error:', error);
    throw new Error(
      `Failed to upload video to Google Drive: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Upload a base64 encoded video to Google Drive
 * @param base64Data Base64 encoded video data
 * @param fileName Name for the file in Google Drive
 * @returns Object containing file ID and shareable link
 */
export async function uploadBase64VideoToGoogleDrive(
  base64Data: string,
  fileName: string = `video-${Date.now()}.mp4`
): Promise<UploadResult> {
  try {
    console.log('[Google Drive] Starting base64 video upload to Shared Drive...');
    
    // Get Google Drive credentials and folder ID from database or environment
    const credentialsJson = await getGoogleDriveCredentials();
    const folderId = await getGoogleDriveFolderId();

    // Create auth client
    const auth = new google.auth.GoogleAuth({
      credentials: credentialsJson,
      scopes: ['https://www.googleapis.com/auth/drive.file'],
    });

    const drive = google.drive({ version: 'v3', auth });

    // Convert base64 to buffer
    const videoBuffer = Buffer.from(base64Data, 'base64');
    console.log('[Google Drive] Video size:', Math.round(videoBuffer.length / (1024 * 1024)), 'MB');

    // Create a readable stream from buffer
    const { Readable } = await import('stream');
    const bufferStream = new Readable();
    bufferStream.push(videoBuffer);
    bufferStream.push(null);

    // Create file metadata with Shared Drive as parent
    const fileMetadata = {
      name: fileName,
      mimeType: 'video/mp4',
      parents: [folderId],
    };

    // Upload the file to Shared Drive
    console.log('[Google Drive] Uploading to Shared Drive:', folderId);
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: {
        mimeType: 'video/mp4',
        body: bufferStream,
      },
      fields: 'id, webViewLink, webContentLink',
      supportsAllDrives: true,
    });

    const fileId = response.data.id;
    if (!fileId) {
      throw new Error('Failed to get file ID from Google Drive');
    }

    console.log('[Google Drive] Upload successful! File ID:', fileId);

    // Make the file publicly accessible
    await drive.permissions.create({
      fileId,
      requestBody: {
        role: 'reader',
        type: 'anyone',
      },
      supportsAllDrives: true,
    });

    console.log('[Google Drive] File set to public access');

    // Get the direct download link
    const file = await drive.files.get({
      fileId,
      fields: 'webViewLink, webContentLink',
      supportsAllDrives: true,
    });

    return {
      id: fileId,
      webViewLink: file.data.webViewLink || '',
      webContentLink: file.data.webContentLink || '',
    };
  } catch (error) {
    console.error('[Google Drive] Base64 upload error:', error);
    throw new Error(
      `Failed to upload video to Google Drive: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Get a direct download/stream link for a Google Drive file
 * @param fileId Google Drive file ID
 * @returns URL that allows direct download/streaming
 */
export function getDirectDownloadLink(fileId: string): string {
  // Use direct streaming URL - works immediately without Google processing delay
  return `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t`;
}
