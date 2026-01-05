/**
 * Local Disk Storage Service for Videos
 * Stores videos on local disk with automatic 3-hour expiry cleanup
 * Optimized for VPS hosting with 6 cores CPU and 180GB disk
 */

import { promises as fs } from 'fs';
import { existsSync, mkdirSync, createReadStream } from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';

// Configuration
const VIDEO_STORAGE_DIR = path.join(process.cwd(), 'temp_video');
const VIDEO_EXPIRY_HOURS = 3; // Videos expire after 3 hours
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // Check every 5 minutes

interface VideoMetadata {
  id: string;
  filename: string;
  createdAt: number;
  expiresAt: number;
  sizeBytes: number;
  prompt?: string;
  userId?: string;
}

// In-memory index for fast lookups
const videoIndex = new Map<string, VideoMetadata>();

// Ensure storage directory exists
function ensureStorageDir(): void {
  if (!existsSync(VIDEO_STORAGE_DIR)) {
    mkdirSync(VIDEO_STORAGE_DIR, { recursive: true });
    console.log(`[LocalDisk] Created storage directory: ${VIDEO_STORAGE_DIR}`);
  }
}

// Load existing videos on startup
async function loadExistingVideos(): Promise<void> {
  ensureStorageDir();
  
  try {
    const files = await fs.readdir(VIDEO_STORAGE_DIR);
    const metadataFiles = files.filter(f => f.endsWith('.meta.json'));
    
    for (const metaFile of metadataFiles) {
      try {
        const metaPath = path.join(VIDEO_STORAGE_DIR, metaFile);
        const metaContent = await fs.readFile(metaPath, 'utf-8');
        const metadata: VideoMetadata = JSON.parse(metaContent);
        
        // Check if video file still exists
        const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
        if (existsSync(videoPath)) {
          videoIndex.set(metadata.id, metadata);
        } else {
          // Clean up orphaned metadata
          await fs.unlink(metaPath).catch(() => {});
        }
      } catch (e) {
        console.error(`[LocalDisk] Error loading metadata ${metaFile}:`, e);
      }
    }
    
    console.log(`[LocalDisk] Loaded ${videoIndex.size} existing videos from disk`);
  } catch (e) {
    console.error('[LocalDisk] Error loading existing videos:', e);
  }
}

/**
 * Save a video to local disk storage
 * @param base64Data - Base64 encoded video data
 * @param options - Optional parameters: prompt, userId, externalVideoId
 * @returns The video ID and local URL
 */
export async function saveVideoToLocalDisk(
  base64Data: string,
  options?: {
    prompt?: string;
    userId?: string;
    externalVideoId?: string;  // Video ID from generation pipeline
  }
): Promise<{ videoId: string; videoUrl: string }> {
  ensureStorageDir();
  
  // Use external video ID if provided, otherwise generate new one
  const videoId = options?.externalVideoId || randomUUID();
  const filename = `${videoId}.mp4`;
  const metaFilename = `${videoId}.meta.json`;
  const videoPath = path.join(VIDEO_STORAGE_DIR, filename);
  const metaPath = path.join(VIDEO_STORAGE_DIR, metaFilename);
  
  // Convert base64 to buffer and save
  const videoBuffer = Buffer.from(base64Data, 'base64');
  const sizeBytes = videoBuffer.length;
  const sizeMB = (sizeBytes / (1024 * 1024)).toFixed(2);
  
  console.log(`[LocalDisk] Saving video ${videoId} (${sizeMB}MB)...`);
  
  await fs.writeFile(videoPath, videoBuffer);
  
  // Create metadata
  const now = Date.now();
  const metadata: VideoMetadata = {
    id: videoId,
    filename,
    createdAt: now,
    expiresAt: now + (VIDEO_EXPIRY_HOURS * 60 * 60 * 1000),
    sizeBytes,
    prompt: options?.prompt,
    userId: options?.userId
  };
  
  // Save metadata
  await fs.writeFile(metaPath, JSON.stringify(metadata, null, 2));
  
  // Add to index
  videoIndex.set(videoId, metadata);
  
  console.log(`[LocalDisk] Video ${videoId} saved. Expires at: ${new Date(metadata.expiresAt).toISOString()}`);
  
  // Return local URL that will be served by our API
  const videoUrl = `/api/local-video/${videoId}`;
  
  return { videoId, videoUrl };
}

/**
 * Get video file path by ID
 * Falls back to disk check if not in memory (for PM2 cluster mode)
 */
export function getVideoPath(videoId: string): string | null {
  // First check in-memory index
  const metadata = videoIndex.get(videoId);
  if (metadata) {
    const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
    if (existsSync(videoPath)) {
      return videoPath;
    }
    // File doesn't exist, remove from index
    videoIndex.delete(videoId);
    return null;
  }
  
  // Fallback: Check disk directly (important for PM2 cluster mode)
  // Each cluster instance has its own memory, so video might exist on disk
  // but not in this instance's memory
  const expectedPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.mp4`);
  if (existsSync(expectedPath)) {
    // Try to load metadata if available
    const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
    if (existsSync(metaPath)) {
      try {
        const metaContent = require('fs').readFileSync(metaPath, 'utf-8');
        const diskMetadata: VideoMetadata = JSON.parse(metaContent);
        // Add to this instance's index for future requests
        videoIndex.set(videoId, diskMetadata);
      } catch (e) {
        // Metadata read failed, but video exists - create basic entry
        const stats = require('fs').statSync(expectedPath);
        const now = Date.now();
        videoIndex.set(videoId, {
          id: videoId,
          filename: `${videoId}.mp4`,
          createdAt: stats.mtimeMs,
          expiresAt: stats.mtimeMs + (VIDEO_EXPIRY_HOURS * 60 * 60 * 1000),
          sizeBytes: stats.size
        });
      }
    }
    return expectedPath;
  }
  
  return null;
}

/**
 * Get video read stream for serving
 */
export function getVideoStream(videoId: string): NodeJS.ReadableStream | null {
  const videoPath = getVideoPath(videoId);
  if (!videoPath) return null;
  
  return createReadStream(videoPath);
}

/**
 * Get video metadata
 */
export function getVideoMetadata(videoId: string): VideoMetadata | null {
  return videoIndex.get(videoId) || null;
}

/**
 * Check if a video exists
 */
export function videoExists(videoId: string): boolean {
  return getVideoPath(videoId) !== null;
}

/**
 * Delete a video manually
 */
export async function deleteVideo(videoId: string): Promise<boolean> {
  const metadata = videoIndex.get(videoId);
  if (!metadata) return false;
  
  const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
  const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
  
  try {
    await fs.unlink(videoPath).catch(() => {});
    await fs.unlink(metaPath).catch(() => {});
    videoIndex.delete(videoId);
    console.log(`[LocalDisk] Deleted video ${videoId}`);
    return true;
  } catch (e) {
    console.error(`[LocalDisk] Error deleting video ${videoId}:`, e);
    return false;
  }
}

/**
 * Cleanup expired videos (runs periodically)
 */
export async function cleanupExpiredVideos(): Promise<number> {
  const now = Date.now();
  let deletedCount = 0;
  
  console.log(`[LocalDisk Cleanup] Starting cleanup check. ${videoIndex.size} videos in index.`);
  
  const entries = Array.from(videoIndex.entries());
  for (const [videoId, metadata] of entries) {
    if (metadata.expiresAt < now) {
      const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
      const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
      
      try {
        await fs.unlink(videoPath).catch(() => {});
        await fs.unlink(metaPath).catch(() => {});
        videoIndex.delete(videoId);
        deletedCount++;
        
        const ageHours = ((now - metadata.createdAt) / (1000 * 60 * 60)).toFixed(1);
        console.log(`[LocalDisk Cleanup] Deleted expired video ${videoId} (age: ${ageHours}h)`);
      } catch (e) {
        console.error(`[LocalDisk Cleanup] Error deleting ${videoId}:`, e);
      }
    }
  }
  
  // Also scan disk for orphaned files
  try {
    const files = await fs.readdir(VIDEO_STORAGE_DIR);
    for (const file of files) {
      if (file.endsWith('.mp4')) {
        const videoId = file.replace('.mp4', '');
        if (!videoIndex.has(videoId)) {
          // Orphaned video file - check creation time
          const filePath = path.join(VIDEO_STORAGE_DIR, file);
          const stats = await fs.stat(filePath);
          const fileAge = now - stats.mtimeMs;
          
          // Delete if older than expiry time
          if (fileAge > VIDEO_EXPIRY_HOURS * 60 * 60 * 1000) {
            await fs.unlink(filePath).catch(() => {});
            const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
            await fs.unlink(metaPath).catch(() => {});
            deletedCount++;
            console.log(`[LocalDisk Cleanup] Deleted orphaned video file: ${file}`);
          }
        }
      }
    }
  } catch (e) {
    console.error('[LocalDisk Cleanup] Error scanning for orphaned files:', e);
  }
  
  if (deletedCount > 0) {
    console.log(`[LocalDisk Cleanup] Cleanup complete. Deleted ${deletedCount} expired videos.`);
  }
  
  return deletedCount;
}

/**
 * Get storage statistics
 */
export async function getStorageStats(): Promise<{
  totalVideos: number;
  totalSizeBytes: number;
  totalSizeMB: number;
  totalSizeGB: number;
  oldestVideo: Date | null;
  newestVideo: Date | null;
  expiryHours: number;
}> {
  let totalSizeBytes = 0;
  let oldestCreated: number | null = null;
  let newestCreated: number | null = null;
  
  const values = Array.from(videoIndex.values());
  for (const metadata of values) {
    totalSizeBytes += metadata.sizeBytes;
    
    if (oldestCreated === null || metadata.createdAt < oldestCreated) {
      oldestCreated = metadata.createdAt;
    }
    if (newestCreated === null || metadata.createdAt > newestCreated) {
      newestCreated = metadata.createdAt;
    }
  }
  
  return {
    totalVideos: videoIndex.size,
    totalSizeBytes,
    totalSizeMB: Math.round(totalSizeBytes / (1024 * 1024)),
    totalSizeGB: Math.round(totalSizeBytes / (1024 * 1024 * 1024) * 100) / 100,
    oldestVideo: oldestCreated ? new Date(oldestCreated) : null,
    newestVideo: newestCreated ? new Date(newestCreated) : null,
    expiryHours: VIDEO_EXPIRY_HOURS
  };
}

/**
 * List all videos with their metadata
 */
export function listAllVideos(): VideoMetadata[] {
  return Array.from(videoIndex.values()).sort((a, b) => b.createdAt - a.createdAt);
}

// Cleanup job handle
let cleanupInterval: NodeJS.Timeout | null = null;

/**
 * Start the automatic cleanup job
 */
export function startCleanupJob(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
  
  console.log(`[LocalDisk] Starting cleanup job (every ${CLEANUP_INTERVAL_MS / 1000 / 60} minutes)`);
  
  // Run cleanup periodically
  cleanupInterval = setInterval(async () => {
    try {
      await cleanupExpiredVideos();
    } catch (e) {
      console.error('[LocalDisk Cleanup] Job error:', e);
    }
  }, CLEANUP_INTERVAL_MS);
  
  // Also run once on startup after a short delay
  setTimeout(async () => {
    try {
      await cleanupExpiredVideos();
    } catch (e) {
      console.error('[LocalDisk Cleanup] Initial cleanup error:', e);
    }
  }, 10000);
}

/**
 * Stop the cleanup job
 */
export function stopCleanupJob(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log('[LocalDisk] Cleanup job stopped');
  }
}

/**
 * Initialize the local disk storage service
 */
export async function initLocalDiskStorage(): Promise<void> {
  console.log('[LocalDisk] Initializing local disk storage...');
  console.log(`[LocalDisk] Storage directory: ${VIDEO_STORAGE_DIR}`);
  console.log(`[LocalDisk] Video expiry: ${VIDEO_EXPIRY_HOURS} hours`);
  
  await loadExistingVideos();
  startCleanupJob();
  
  const stats = await getStorageStats();
  console.log(`[LocalDisk] Ready. ${stats.totalVideos} videos, ${stats.totalSizeMB}MB total`);
}
