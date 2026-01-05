// Video merger utility using local FFmpeg
// Downloads videos from URLs, merges them sequentially, and uploads to Cloudinary

import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFile, mkdir, rm } from 'fs/promises';
import { existsSync, statSync } from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { ObjectStorageService } from './objectStorage';
import { uploadVideoToCloudinary } from './cloudinary.js';

const execAsync = promisify(exec);
const objectStorageService = new ObjectStorageService();

export async function mergeVideosWithFFmpeg(videoUrls: string[]): Promise<string> {
  if (videoUrls.length === 0) {
    throw new Error('No video URLs provided for merging');
  }

  if (videoUrls.length > 14) {
    throw new Error('Cannot merge more than 14 videos at once');
  }

  // Create unique temp directory for this merge operation
  const uniqueId = randomUUID();
  const tempDir = path.join('/tmp', `video-merge-${uniqueId}`);
  const listFile = path.join(tempDir, 'filelist.txt');
  const outputFile = path.join(tempDir, 'merged-output.mp4');

  try {
    // Create temp directory if it doesn't exist
    if (!existsSync(tempDir)) {
      await mkdir(tempDir, { recursive: true });
    }

    console.log(`[FFmpeg Merger] Starting merge of ${videoUrls.length} videos in ${tempDir}`);

    // Step 1: Download all videos to temp directory
    const downloadedFiles: string[] = [];
    for (let i = 0; i < videoUrls.length; i++) {
      const filename = path.join(tempDir, `video-${i + 1}.mp4`);
      console.log(`[FFmpeg Merger] Downloading video ${i + 1}/${videoUrls.length}...`);
      
      const response = await fetch(videoUrls[i]);
      if (!response.ok) {
        throw new Error(`Failed to download video ${i + 1}: ${response.statusText}`);
      }
      
      const buffer = await response.arrayBuffer();
      await writeFile(filename, Buffer.from(buffer));
      downloadedFiles.push(filename);
      console.log(`[FFmpeg Merger] Downloaded video ${i + 1} (${buffer.byteLength} bytes)`);
    }

    // Step 2: Create file list for FFmpeg concat
    const fileListContent = downloadedFiles
      .map(file => `file '${file}'`)
      .join('\n');
    await writeFile(listFile, fileListContent);
    console.log(`[FFmpeg Merger] Created file list with ${downloadedFiles.length} videos`);

    // Step 3: Merge videos using FFmpeg concat demuxer
    console.log(`[FFmpeg Merger] Running FFmpeg to merge videos...`);
    const ffmpegCommand = `ffmpeg -f concat -safe 0 -i "${listFile}" -c copy "${outputFile}"`;
    
    try {
      const { stdout, stderr } = await execAsync(ffmpegCommand, { maxBuffer: 1024 * 1024 * 10 });
      console.log(`[FFmpeg Merger] FFmpeg completed successfully`);
      if (stderr) {
        console.log(`[FFmpeg Merger] FFmpeg stderr:`, stderr.substring(0, 500));
      }
    } catch (ffmpegError: any) {
      console.error(`[FFmpeg Merger] FFmpeg error:`, ffmpegError.stderr || ffmpegError.message);
      throw new Error(`FFmpeg failed: ${ffmpegError.message}`);
    }

    // Step 4: Upload merged video to Cloudinary
    console.log(`[FFmpeg Merger] Uploading merged video to Cloudinary...`);
    
    // Check file size
    const fileStats = statSync(outputFile);
    const fileSizeMB = (fileStats.size / (1024 * 1024)).toFixed(2);
    console.log(`[FFmpeg Merger] Merged video size: ${fileSizeMB} MB`);
    
    // Upload video file directly from disk to Cloudinary
    const uploadUrl = await uploadVideoToCloudinary(outputFile);
    console.log(`[FFmpeg Merger] Cloudinary upload complete! URL: ${uploadUrl}`);

    // Step 5: Clean up temp directory
    try {
      await rm(tempDir, { recursive: true, force: true });
      console.log(`[FFmpeg Merger] Cleanup successful`);
    } catch (cleanupError) {
      console.error(`[FFmpeg Merger] Cleanup failed:`, cleanupError);
    }

    return uploadUrl;
  } catch (error) {
    console.error(`[FFmpeg Merger] Error during merge process:`, error);
    
    // Clean up on error - remove entire temp directory
    try {
      if (existsSync(tempDir)) {
        await rm(tempDir, { recursive: true, force: true });
        console.log(`[FFmpeg Merger] Error cleanup successful`);
      }
    } catch (cleanupError) {
      console.error(`[FFmpeg Merger] Error cleanup failed:`, cleanupError);
    }
    
    throw new Error(`Failed to merge videos with FFmpeg: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

export async function mergeVideosWithFFmpegTemporary(
  videoUrls: string[], 
  expiryHours: number = 24
): Promise<{ videoPath: string; expiresAt: string }> {
  if (videoUrls.length === 0) {
    throw new Error('No video URLs provided for merging');
  }

  if (videoUrls.length > 14) {
    throw new Error('Cannot merge more than 14 videos at once');
  }

  const uniqueId = randomUUID();
  const tempDir = path.join('/tmp', `video-merge-${uniqueId}`);
  const listFile = path.join(tempDir, 'filelist.txt');
  const outputFile = path.join(tempDir, 'merged-output.mp4');

  try {
    if (!existsSync(tempDir)) {
      await mkdir(tempDir, { recursive: true });
    }

    console.log(`[FFmpeg Temporary] Starting merge of ${videoUrls.length} videos in ${tempDir}`);

    const downloadedFiles: string[] = [];
    for (let i = 0; i < videoUrls.length; i++) {
      const filename = path.join(tempDir, `video-${i + 1}.mp4`);
      console.log(`[FFmpeg Temporary] Downloading video ${i + 1}/${videoUrls.length}...`);
      
      const response = await fetch(videoUrls[i]);
      if (!response.ok) {
        throw new Error(`Failed to download video ${i + 1}: ${response.statusText}`);
      }
      
      const buffer = await response.arrayBuffer();
      await writeFile(filename, Buffer.from(buffer));
      downloadedFiles.push(filename);
      console.log(`[FFmpeg Temporary] Downloaded video ${i + 1} (${buffer.byteLength} bytes)`);
    }

    const fileListContent = downloadedFiles
      .map(file => `file '${file}'`)
      .join('\n');
    await writeFile(listFile, fileListContent);
    console.log(`[FFmpeg Temporary] Created file list with ${downloadedFiles.length} videos`);

    console.log(`[FFmpeg Temporary] Running FFmpeg to merge videos...`);
    const ffmpegCommand = `ffmpeg -f concat -safe 0 -i "${listFile}" -c copy "${outputFile}"`;
    
    try {
      const { stdout, stderr } = await execAsync(ffmpegCommand, { maxBuffer: 1024 * 1024 * 10 });
      console.log(`[FFmpeg Temporary] FFmpeg completed successfully`);
      if (stderr) {
        console.log(`[FFmpeg Temporary] FFmpeg stderr:`, stderr.substring(0, 500));
      }
    } catch (ffmpegError: any) {
      console.error(`[FFmpeg Temporary] FFmpeg error:`, ffmpegError.stderr || ffmpegError.message);
      throw new Error(`FFmpeg failed: ${ffmpegError.message}`);
    }

    console.log(`[FFmpeg Temporary] Uploading to temporary storage (expires in ${expiryHours} hours)...`);
    const videoPath = await objectStorageService.uploadTemporaryVideo(outputFile, expiryHours);

    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + expiryHours);

    console.log(`[FFmpeg Temporary] Upload complete! Path: ${videoPath}`);
    console.log(`[FFmpeg Temporary] Expires at: ${expiryDate.toISOString()}`);

    try {
      await rm(tempDir, { recursive: true, force: true });
      console.log(`[FFmpeg Temporary] Cleanup successful`);
    } catch (cleanupError) {
      console.error(`[FFmpeg Temporary] Cleanup failed:`, cleanupError);
    }

    return {
      videoPath,
      expiresAt: expiryDate.toISOString()
    };
  } catch (error) {
    console.error(`[FFmpeg Temporary] Error during merge process:`, error);
    
    try {
      if (existsSync(tempDir)) {
        await rm(tempDir, { recursive: true, force: true });
        console.log(`[FFmpeg Temporary] Error cleanup successful`);
      }
    } catch (cleanupError) {
      console.error(`[FFmpeg Temporary] Error cleanup failed:`, cleanupError);
    }
    
    throw new Error(`Failed to merge videos with FFmpeg: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}
