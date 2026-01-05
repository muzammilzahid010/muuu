import { google } from 'googleapis';
import fs from 'fs';

interface GoogleDriveConfig {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}

function getOAuth2Client(config: GoogleDriveConfig, redirectUri?: string) {
  const oauth2Client = new google.auth.OAuth2(
    config.clientId,
    config.clientSecret,
    redirectUri || 'http://localhost:8080'
  );

  oauth2Client.setCredentials({
    refresh_token: config.refreshToken,
  });

  return oauth2Client;
}

export async function uploadVideoToGoogleDriveOAuth(
  filePath: string,
  fileName: string
): Promise<{ id: string; webViewLink: string; webContentLink: string }> {
  try {
    const clientId = process.env.GOOGLE_DRIVE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_DRIVE_CLIENT_SECRET;
    const refreshToken = process.env.GOOGLE_DRIVE_REFRESH_TOKEN;

    if (!clientId || !clientSecret || !refreshToken) {
      throw new Error(
        'Missing Google Drive OAuth credentials. Please set GOOGLE_DRIVE_CLIENT_ID, GOOGLE_DRIVE_CLIENT_SECRET, and GOOGLE_DRIVE_REFRESH_TOKEN environment variables.'
      );
    }

    const auth = getOAuth2Client({ clientId, clientSecret, refreshToken });
    const drive = google.drive({ version: 'v3', auth });

    console.log(`[Google Drive OAuth] Uploading file: ${fileName}`);

    const fileMetadata = {
      name: fileName,
    };

    const media = {
      mimeType: 'video/mp4',
      body: fs.createReadStream(filePath),
    };

    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: media,
      fields: 'id, webViewLink, webContentLink',
    });

    if (!response.data.id) {
      throw new Error('Upload succeeded but no file ID returned');
    }

    console.log(`[Google Drive OAuth] File uploaded successfully. ID: ${response.data.id}`);

    // Make the file publicly accessible
    await drive.permissions.create({
      fileId: response.data.id,
      requestBody: {
        role: 'reader',
        type: 'anyone',
      },
    });

    console.log(`[Google Drive OAuth] File permissions set to public`);

    return {
      id: response.data.id,
      webViewLink: response.data.webViewLink || '',
      webContentLink: response.data.webContentLink || '',
    };
  } catch (error) {
    console.error('[Google Drive OAuth] Upload error:', error);
    throw error;
  }
}

export function getDirectDownloadLinkOAuth(fileId: string): string {
  // Use direct view link for HTML5 video players
  // This works for public files and allows streaming playback
  return `https://drive.google.com/uc?export=view&id=${fileId}`;
}

export function getEmbedLink(fileId: string): string {
  // For iframe embedding if needed
  return `https://drive.google.com/file/d/${fileId}/preview`;
}

export async function generateAuthUrl(): Promise<string> {
  const clientId = process.env.GOOGLE_DRIVE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_DRIVE_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('Missing GOOGLE_DRIVE_CLIENT_ID or GOOGLE_DRIVE_CLIENT_SECRET');
  }

  const oauth2Client = new google.auth.OAuth2(
    clientId,
    clientSecret,
    'http://localhost:8080'
  );

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.file'],
    prompt: 'consent',
  });

  return authUrl;
}

export async function exchangeCodeForToken(code: string): Promise<string> {
  const clientId = process.env.GOOGLE_DRIVE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_DRIVE_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('Missing GOOGLE_DRIVE_CLIENT_ID or GOOGLE_DRIVE_CLIENT_SECRET');
  }

  const oauth2Client = new google.auth.OAuth2(
    clientId,
    clientSecret,
    'http://localhost:8080'
  );

  const { tokens } = await oauth2Client.getToken(code);

  if (!tokens.refresh_token) {
    throw new Error('No refresh token received. Make sure to use prompt=consent in the auth URL.');
  }

  return tokens.refresh_token;
}
