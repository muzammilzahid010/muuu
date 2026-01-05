import { storage } from "./storage";
import { withRetry } from "./db";
import type { FlowCookie, ApiToken, VideoHistory } from "@shared/schema";
import crypto from 'crypto';
import { uploadBase64VideoWithFallback } from './cloudinary';
import * as fs from 'fs/promises';
import * as path from 'path';

// ==================== TEMP FILE STORAGE FOR VIDEOS ====================
// Store videos as temp files instead of in-memory to prevent memory overflow on VPS
const TEMP_VIDEO_DIR = '/tmp/video_cache';
const TEMP_UPLOAD_DIR = '/tmp/video_uploads';

// Ensure temp directories exist and clean up orphaned files from previous crashes
async function ensureTempDirs() {
  try {
    await fs.mkdir(TEMP_VIDEO_DIR, { recursive: true });
    await fs.mkdir(TEMP_UPLOAD_DIR, { recursive: true });
  } catch (e) {
    // Ignore if already exists
  }
}

// Startup sweep: Clean up orphaned temp files from previous crashes/restarts
async function cleanupOrphanedTempFiles() {
  let cleanedVideos = 0;
  let cleanedUploads = 0;
  
  try {
    // Clean video cache directory
    const videoFiles = await fs.readdir(TEMP_VIDEO_DIR);
    for (const file of videoFiles) {
      if (file.endsWith('.b64')) {
        await deleteTempFile(path.join(TEMP_VIDEO_DIR, file));
        cleanedVideos++;
      }
    }
    
    // Clean upload directory
    const uploadFiles = await fs.readdir(TEMP_UPLOAD_DIR);
    for (const file of uploadFiles) {
      if (file.endsWith('.b64')) {
        await deleteTempFile(path.join(TEMP_UPLOAD_DIR, file));
        cleanedUploads++;
      }
    }
    
    if (cleanedVideos > 0 || cleanedUploads > 0) {
      console.log(`[Startup] Cleaned ${cleanedVideos} orphaned video files and ${cleanedUploads} orphaned upload files from previous session`);
    }
  } catch (e) {
    console.error('[Startup] Error cleaning orphaned temp files:', e);
  }
}

// Initialize on startup
ensureTempDirs().then(() => cleanupOrphanedTempFiles());

// Helper to get temp file path for a video
function getTempVideoPath(videoId: string): string {
  return path.join(TEMP_VIDEO_DIR, `${videoId}.b64`);
}

function getTempUploadPath(videoId: string): string {
  return path.join(TEMP_UPLOAD_DIR, `${videoId}.b64`);
}

// Helper to safely delete a temp file
async function deleteTempFile(filePath: string): Promise<boolean> {
  try {
    await fs.unlink(filePath);
    return true;
  } catch (e) {
    return false; // File doesn't exist or already deleted
  }
}

// ==================== MEMORY MONITORING ====================
// Log heap usage periodically and alert on high memory
const MEMORY_LOG_INTERVAL = 60000; // Every 60 seconds
const MEMORY_HIGH_WATER_MARK = 0.85; // Alert at 85% of max heap

function formatBytes(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)}MB`;
}

function logMemoryUsage() {
  const usage = process.memoryUsage();
  const heapUsedPercent = (usage.heapUsed / usage.heapTotal) * 100;
  
  // Only log if significant usage or in verbose mode
  if (heapUsedPercent > 50 || LOG_LEVEL >= 3) {
    console.log(`[Memory] Heap: ${formatBytes(usage.heapUsed)}/${formatBytes(usage.heapTotal)} (${heapUsedPercent.toFixed(1)}%) | RSS: ${formatBytes(usage.rss)} | External: ${formatBytes(usage.external)}`);
  }
  
  // High water mark alert
  if (usage.heapUsed / usage.heapTotal > MEMORY_HIGH_WATER_MARK) {
    console.warn(`[Memory] WARNING: Heap usage at ${heapUsedPercent.toFixed(1)}% - approaching limit!`);
    console.warn(`[Memory] Cache stats: Videos=${directVideoCacheMeta.size}, Uploads=${uploadQueue.length}`);
  }
}

// Start memory monitoring
setInterval(logMemoryUsage, MEMORY_LOG_INTERVAL);

// Export memory stats for admin dashboard
export function getMemoryStats() {
  const usage = process.memoryUsage();
  return {
    heapUsed: usage.heapUsed,
    heapTotal: usage.heapTotal,
    heapUsedPercent: Math.round((usage.heapUsed / usage.heapTotal) * 100),
    rss: usage.rss,
    external: usage.external,
    videoCacheSize: directVideoCacheMeta.size,
    uploadQueueSize: uploadQueue.length,
    formatted: {
      heapUsed: formatBytes(usage.heapUsed),
      heapTotal: formatBytes(usage.heapTotal),
      rss: formatBytes(usage.rss)
    }
  };
}

// ==================== GLOBAL LIMITS ====================
// MEMORY OPTIMIZATION: Reduced limits to prevent RAM growth in cluster mode
// Each worker has its own cache, so lower limits = lower total memory
const MAX_TOTAL_CACHED_VIDEOS = 150; // Max videos across all users (temp files) - reduced from 500
const MAX_TOTAL_UPLOAD_QUEUE = 100; // Max uploads in queue - reduced from 200
const STALE_UPLOAD_TIMEOUT = 30 * 60 * 1000; // 30 minutes - cleanup stuck uploads

// Evict oldest entries when cache is full
async function enforceGlobalLimits() {
  const now = Date.now();
  
  // Enforce video cache limit
  if (directVideoCacheMeta.size > MAX_TOTAL_CACHED_VIDEOS) {
    const entries = Array.from(directVideoCacheMeta.entries());
    entries.sort((a, b) => a[1].addedAt - b[1].addedAt); // Sort by oldest first
    
    const toEvict = entries.slice(0, entries.length - MAX_TOTAL_CACHED_VIDEOS);
    for (const [videoId, meta] of toEvict) {
      await deleteTempFile(meta.filePath);
      directVideoCacheMeta.delete(videoId);
    }
    if (toEvict.length > 0) {
      console.log(`[GlobalLimits] Evicted ${toEvict.length} oldest videos from cache`);
    }
  }
  
  // Enforce upload queue limit - delete oldest temp files
  if (uploadQueue.length > MAX_TOTAL_UPLOAD_QUEUE) {
    const toRemove = uploadQueue.length - MAX_TOTAL_UPLOAD_QUEUE;
    const removed = uploadQueue.splice(0, toRemove); // Remove oldest first
    for (const upload of removed) {
      await deleteTempFile(upload.filePath);
      decrementUserUploadCount(upload.userId);
    }
    console.log(`[GlobalLimits] Evicted ${toRemove} oldest uploads from queue`);
  }
  
  // MEMORY OPTIMIZATION: Cleanup stuck/stale uploads older than 30 minutes
  // These can leak memory if upload fails and retry never completes
  let staleCount = 0;
  for (let i = uploadQueue.length - 1; i >= 0; i--) {
    const upload = uploadQueue[i];
    if (now - upload.addedAt > STALE_UPLOAD_TIMEOUT) {
      await deleteTempFile(upload.filePath);
      decrementUserUploadCount(upload.userId);
      uploadQueue.splice(i, 1);
      staleCount++;
    }
  }
  if (staleCount > 0) {
    console.log(`[GlobalLimits] Cleaned ${staleCount} stale uploads (>30min old)`);
  }
}

// Run global limits check every 30 seconds
setInterval(enforceGlobalLimits, 30000);

// ==================== LOGGING OPTIMIZATION ====================
// Log levels: 0=none, 1=errors only, 2=important, 3=verbose
const LOG_LEVEL = process.env.NODE_ENV === 'production' ? 1 : 2;
const LOG_SAMPLING_RATE = 0.1; // Only log 10% of routine messages in production

function shouldLog(level: number, sample = false): boolean {
  if (level > LOG_LEVEL) return false;
  if (sample && LOG_LEVEL < 3) return Math.random() < LOG_SAMPLING_RATE;
  return true;
}

// ==================== TOKEN CACHE ====================
// Cache active tokens to reduce DB calls
let cachedTokens: ApiToken[] = [];
let tokensCacheTime = 0;
const TOKENS_CACHE_TTL = 5000; // 5 seconds

async function getCachedActiveTokens(): Promise<ApiToken[]> {
  const now = Date.now();
  if (now - tokensCacheTime > TOKENS_CACHE_TTL || cachedTokens.length === 0) {
    cachedTokens = await storage.getActiveApiTokens();
    tokensCacheTime = now;
  }
  return cachedTokens;
}

// Force refresh token cache (called when token errors occur)
function invalidateTokenCache() {
  tokensCacheTime = 0;
}

// ==================== STORAGE METHOD CACHE ====================
// Cache storage method to reduce DB calls
let cachedStorageMethod: string = 'cloudinary_with_fallback';
let storageMethodCacheTime = 0;
const STORAGE_METHOD_CACHE_TTL = 10000; // 10 seconds

async function getCachedStorageMethod(): Promise<string> {
  const now = Date.now();
  if (now - storageMethodCacheTime > STORAGE_METHOD_CACHE_TTL) {
    try {
      const settings = await storage.getAppSettings();
      cachedStorageMethod = settings?.storageMethod || 'cloudinary_with_fallback';
      storageMethodCacheTime = now;
    } catch (e) {
      // Use default on error
    }
  }
  return cachedStorageMethod;
}

// ==================== DIRECT VIDEO CACHE (for direct_to_user mode) ====================
// NOW USES TEMP FILES instead of memory to prevent VPS memory overflow
// Only metadata is stored in memory, actual video data is in /tmp/video_cache/

interface CachedVideoMeta {
  addedAt: number;
  userId: string;
  filePath: string;
}

// Only stores metadata - actual video data is in temp files
const directVideoCacheMeta = new Map<string, CachedVideoMeta>();
const DIRECT_VIDEO_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_CACHED_VIDEOS_PER_USER = 50; // Can be higher now since we use files

// Cleanup expired videos periodically - delete temp files
setInterval(async () => {
  const now = Date.now();
  let cleaned = 0;
  const entries = Array.from(directVideoCacheMeta.entries());
  for (const [videoId, meta] of entries) {
    if (now - meta.addedAt > DIRECT_VIDEO_TTL) {
      await deleteTempFile(meta.filePath);
      directVideoCacheMeta.delete(videoId);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`[DirectCache] Cleaned ${cleaned} expired video files. Active: ${directVideoCacheMeta.size}`);
  }
}, 60000); // Every minute

// Save video to temp file cache with proper cleanup on any failure
async function saveDirectVideo(videoId: string, base64: string, userId: string): Promise<boolean> {
  const filePath = getTempVideoPath(videoId);
  
  try {
    // Write file first
    await fs.writeFile(filePath, base64, 'utf8');
    
    // Then update metadata - if this fails, clean up the file
    try {
      directVideoCacheMeta.set(videoId, {
        addedAt: Date.now(),
        userId,
        filePath
      });
    } catch (metaError) {
      // Metadata update failed - delete the orphaned file
      await deleteTempFile(filePath);
      console.error(`[DirectCache] Failed to set metadata for ${videoId}, cleaned up file:`, metaError);
      return false;
    }
    
    return true;
  } catch (e) {
    // File write failed - ensure no orphaned file exists
    await deleteTempFile(filePath);
    console.error(`[DirectCache] Failed to save video ${videoId}:`, e);
    return false;
  }
}

// Get video from temp file cache (for download endpoint)
export async function getDirectVideo(videoId: string): Promise<string | null> {
  const meta = directVideoCacheMeta.get(videoId);
  if (!meta) return null;
  
  try {
    const base64 = await fs.readFile(meta.filePath, 'utf8');
    return base64;
  } catch (e) {
    // File doesn't exist or was deleted
    directVideoCacheMeta.delete(videoId);
    return null;
  }
}

// Explicitly delete a video from cache (called after confirmed successful fetch)
export async function deleteDirectVideo(videoId: string): Promise<boolean> {
  const meta = directVideoCacheMeta.get(videoId);
  if (!meta) return false;
  
  const deleted = await deleteTempFile(meta.filePath);
  directVideoCacheMeta.delete(videoId);
  
  if (deleted) {
    console.log(`[DirectCache] Video ${videoId} deleted after confirmed download`);
  }
  return deleted;
}

// Get cache stats
export function getDirectCacheStats(): { total: number; perUser: Record<string, number> } {
  const perUser: Record<string, number> = {};
  const entries = Array.from(directVideoCacheMeta.entries());
  for (const [_, meta] of entries) {
    perUser[meta.userId] = (perUser[meta.userId] || 0) + 1;
  }
  return { total: directVideoCacheMeta.size, perUser };
}

// ==================== BACKGROUND UPLOAD QUEUE ====================
// Upload queue to process Cloudinary uploads in parallel without blocking workers
// NOW USES TEMP FILES instead of storing base64 in memory to prevent VPS memory overflow

interface PendingUpload {
  videoId: string;
  filePath: string;  // Path to temp file with base64 data (NOT in-memory base64)
  userId: string;
  sceneNumber: number;
  retries: number;
  addedAt: number;
}

const uploadQueue: PendingUpload[] = [];
const MAX_CONCURRENT_UPLOADS = 10; // Parallel uploads
const MAX_UPLOAD_RETRIES = 3;
let activeUploads = 0;
let uploadProcessorRunning = false;

// Fast user upload counter (O(1) instead of O(n))
const userUploadCounts = new Map<string, number>();

function logUpload(message: string, level = 2) {
  if (!shouldLog(level)) return;
  const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
  console.log(`[${timestamp}] [Upload] ${message}`);
}

// Count uploads per user (O(1) lookup)
function countUserUploads(userId: string): number {
  return userUploadCounts.get(userId) || 0;
}

function incrementUserUploadCount(userId: string) {
  userUploadCounts.set(userId, (userUploadCounts.get(userId) || 0) + 1);
}

function decrementUserUploadCount(userId: string) {
  const current = userUploadCounts.get(userId) || 0;
  if (current <= 1) {
    userUploadCounts.delete(userId);
  } else {
    userUploadCounts.set(userId, current - 1);
  }
}

// Add to upload queue (non-blocking) with per-user limit
// Returns true if queued, false if rejected due to limit
// NOW SAVES BASE64 TO TEMP FILE to prevent memory overflow
async function queueUpload(videoId: string, base64Video: string, userId: string, sceneNumber: number): Promise<boolean> {
  const userUploadCount = countUserUploads(userId);
  
  // ENFORCE per-user upload limit - wait for slots to free up
  if (userUploadCount >= MAX_UPLOADS_PER_USER) {
    logUpload(`User ${userId.slice(0,8)}: Upload queue full (${userUploadCount}/${MAX_UPLOADS_PER_USER}), waiting...`);
    
    // Wait up to 60 seconds for a slot to free up
    const maxWait = 60000;
    const checkInterval = 1000;
    let waited = 0;
    
    while (countUserUploads(userId) >= MAX_UPLOADS_PER_USER && waited < maxWait) {
      await new Promise(r => setTimeout(r, checkInterval));
      waited += checkInterval;
    }
    
    // If still full after waiting, reject
    if (countUserUploads(userId) >= MAX_UPLOADS_PER_USER) {
      logUpload(`User ${userId.slice(0,8)}: Upload rejected after ${maxWait/1000}s wait - queue still full`);
      return false;
    }
  }
  
  // Save base64 to temp file instead of keeping in memory
  const filePath = getTempUploadPath(videoId);
  try {
    await fs.writeFile(filePath, base64Video, 'utf8');
  } catch (e) {
    logUpload(`Failed to save upload temp file for video ${videoId}: ${e}`);
    return false;
  }
  
  uploadQueue.push({
    videoId,
    filePath,  // Store file path, NOT base64 data
    userId,
    sceneNumber,
    retries: 0,
    addedAt: Date.now()
  });
  incrementUserUploadCount(userId);
  logUpload(`Queued video ${sceneNumber} for user ${userId.slice(0,8)} (user: ${countUserUploads(userId)}, total: ${uploadQueue.length})`);
  startUploadProcessor();
  return true;
}

// Background upload processor with DB retry logic
// NOW READS FROM TEMP FILE and deletes after upload
async function processUpload(upload: PendingUpload) {
  activeUploads++;
  const startTime = Date.now();
  
  try {
    // Read base64 from temp file (NOT stored in memory)
    const base64Video = await fs.readFile(upload.filePath, 'utf8');
    
    const uploadResult = await uploadBase64VideoWithFallback(base64Video, upload.videoId);
    const duration = Math.round((Date.now() - startTime) / 1000);
    
    if (uploadResult.url) {
      // Update video history with URL (with retry for DB timeouts)
      await withRetry(() => storage.updateVideoHistoryFields(upload.videoId, { 
        status: 'completed', 
        videoUrl: uploadResult.url 
      }), 3, 2000);
      logUpload(`Video ${upload.sceneNumber} uploaded in ${duration}s: ${uploadResult.url.slice(0, 50)}...`);
    }
    // Success - decrement user counter and DELETE temp file
    decrementUserUploadCount(upload.userId);
    await deleteTempFile(upload.filePath);
  } catch (error) {
    const duration = Math.round((Date.now() - startTime) / 1000);
    logUpload(`Video ${upload.sceneNumber} upload FAILED after ${duration}s: ${error}`);
    
    // Retry if under limit (don't decrement - still in queue, keep temp file)
    if (upload.retries < MAX_UPLOAD_RETRIES) {
      upload.retries++;
      uploadQueue.push(upload); // Re-add to queue, counter stays same
      logUpload(`Requeueing video ${upload.sceneNumber} (retry ${upload.retries}/${MAX_UPLOAD_RETRIES})`);
    } else {
      // Permanent failure - decrement counter and DELETE temp file
      decrementUserUploadCount(upload.userId);
      await deleteTempFile(upload.filePath);
      try {
        await withRetry(() => storage.updateVideoHistoryFields(upload.videoId, { 
          status: 'failed',
          errorMessage: 'Upload failed after max retries'
        }), 3, 2000);
      } catch (dbError) {
        logUpload(`DB error updating failed status: ${dbError}`);
      }
      logUpload(`Video ${upload.sceneNumber} PERMANENTLY FAILED after ${MAX_UPLOAD_RETRIES} retries`);
    }
  } finally {
    activeUploads--;
  }
}

// Start upload processor (runs until queue empty)
function startUploadProcessor() {
  if (uploadProcessorRunning) return;
  uploadProcessorRunning = true;
  
  (async () => {
    while (uploadQueue.length > 0 || activeUploads > 0) {
      // Start new uploads up to concurrency limit
      while (uploadQueue.length > 0 && activeUploads < MAX_CONCURRENT_UPLOADS) {
        const upload = uploadQueue.shift()!;
        processUpload(upload); // Don't await - run in parallel
      }
      
      // Wait a bit before checking again
      await new Promise(r => setTimeout(r, 500));
    }
    
    uploadProcessorRunning = false;
    logUpload('Upload processor finished - queue empty');
  })();
}

// Get upload queue stats
export function getUploadQueueStats() {
  return {
    pending: uploadQueue.length,
    active: activeUploads,
    total: uploadQueue.length + activeUploads
  };
}

// NO IN-MEMORY CACHE - All videos go directly to Cloudinary
// These stub functions exist only for backward compatibility with routes.ts

export function getVideoBufferFromBulk(videoId: string): Buffer | null {
  // No memory storage - always return null
  return null;
}

export function deleteVideoBufferFromBulk(videoId: string): boolean {
  // No memory storage - nothing to delete
  return false;
}

export function getBulkCacheStats() {
  // No cache - always empty
  return { count: 0, sizeBytes: 0, sizeMB: 0, sizeGB: 0 };
}

interface QueuedVideo {
  videoId: string;
  prompt: string;
  aspectRatio: string;
  sceneNumber: number;
  userId: string;
  assignedCookie?: FlowCookie;
  assignedToken?: ApiToken;
}

interface UserQueueState {
  queue: QueuedVideo[];
  isProcessing: boolean;
  shouldStop: boolean;
  processingStartedAt: number | null;
  lastProgressAt: number | null; // Track last completed video for stuck detection
  activeWorkers: number;
  completedCount: number;
  failedCount: number;
  batchVideoIds: Set<string>; // Track all video IDs in current batch for fast status queries
}

// Stuck queue detection: reset isProcessing if no progress for 2 minutes (reduced from 3)
const STUCK_QUEUE_TIMEOUT_MS = 2 * 60 * 1000; // 2 minutes
const HEALTH_CHECK_INTERVAL_MS = 30 * 1000; // Run health check every 30 seconds

// ==================== WORKER LIMITS CONFIG ====================
// Global: unlimited (very high), Per-user: 20 concurrent max
const GLOBAL_MAX_CONCURRENT_WORKERS = parseInt(process.env.GLOBAL_MAX_WORKERS || '10000', 10);
const MAX_CONCURRENT_PER_USER = parseInt(process.env.PER_USER_MAX_WORKERS || '20', 10);
const MAX_UPLOADS_PER_USER = parseInt(process.env.PER_USER_MAX_UPLOADS || '100', 10);
const MAX_PROCESSING_TIME_MS = 2 * 60 * 60 * 1000;

// Global worker tracking for fair scheduling
let globalActiveWorkers = 0;

// Memory logging helper
function logMemory(context: string) {
  const used = process.memoryUsage();
  console.log(`[Memory] ${context}: Heap ${Math.round(used.heapUsed / 1024 / 1024)}MB / ${Math.round(used.heapTotal / 1024 / 1024)}MB`);
}

// Get global stats for monitoring
export function getGlobalStats() {
  let totalQueuedVideos = 0;
  let totalActiveWorkers = 0;
  const activeUsers: string[] = [];
  
  userQueues.forEach((queue, userId) => {
    if (queue.isProcessing || queue.queue.length > 0 || queue.activeWorkers > 0) {
      activeUsers.push(userId);
      totalQueuedVideos += queue.queue.length;
      totalActiveWorkers += queue.activeWorkers;
    }
  });
  
  return {
    globalActiveWorkers,
    totalQueuedVideos,
    totalActiveWorkers,
    activeUserCount: activeUsers.length,
    globalLimit: GLOBAL_MAX_CONCURRENT_WORKERS,
    perUserLimit: MAX_CONCURRENT_PER_USER,
    perUserUploadLimit: MAX_UPLOADS_PER_USER
  };
}

let tokenRotationIndex = 0;

function randomDelay(minMs: number, maxMs: number): number {
  return Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
}

function getAndIncrementTokenRotationIndex(count: number, totalTokens: number): number {
  const startIndex = tokenRotationIndex;
  tokenRotationIndex = (tokenRotationIndex + count) % totalTokens;
  return startIndex;
}

const userQueues = new Map<string, UserQueueState>();

// ==================== MEMORY CLEANUP ====================
// Periodically clean up inactive user queues to prevent memory buildup
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes
const INACTIVE_QUEUE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

function cleanupInactiveQueues() {
  const now = Date.now();
  let cleaned = 0;
  
  userQueues.forEach((queue, userId) => {
    // Skip if actively processing or has pending work
    if (queue.isProcessing || queue.queue.length > 0 || queue.activeWorkers > 0) {
      return;
    }
    
    // Check if queue has been inactive for too long
    const lastActivity = queue.lastProgressAt || queue.processingStartedAt || 0;
    if (lastActivity > 0 && (now - lastActivity) > INACTIVE_QUEUE_TIMEOUT_MS) {
      userQueues.delete(userId);
      userUploadCounts.delete(userId);
      cleaned++;
    }
  });
  
  if (cleaned > 0) {
    console.log(`[BulkFlow] Cleaned up ${cleaned} inactive user queues. Active: ${userQueues.size}`);
  }
}

// Start cleanup interval
setInterval(cleanupInactiveQueues, CLEANUP_INTERVAL_MS);

// ==================== STUCK QUEUE HEALTH CHECK ====================
// Mark videos that are stuck in "processing" status as failed
async function markStuckProcessingVideosAsFailed(userId: string, batchVideoIds: Set<string>) {
  if (batchVideoIds.size === 0) return;
  
  try {
    // Get all videos in this batch that are stuck in "processing" status
    const videoIds = Array.from(batchVideoIds);
    let markedCount = 0;
    
    for (const videoId of videoIds) {
      try {
        // Only mark as failed if currently in "processing" status
        const video = await storage.getVideoById(videoId);
        if (video && video.status === 'processing') {
          await storage.updateVideoHistoryFields(videoId, {
            status: 'failed',
            errorMessage: 'Stuck in processing - auto-recovered'
          });
          markedCount++;
        }
      } catch (e) {
        // Ignore individual video errors
      }
    }
    
    if (markedCount > 0) {
      console.log(`[BulkFlow] Marked ${markedCount} stuck "processing" videos as failed for user ${userId.slice(0, 8)}`);
    }
  } catch (error) {
    console.log(`[BulkFlow] Error marking stuck videos: ${error}`);
  }
}

// Proactively detect and recover stuck queues every 30 seconds
function checkAndRecoverStuckQueues() {
  const now = Date.now();
  let recoveredCount = 0;
  
  userQueues.forEach((queue, userId) => {
    // Only check queues that claim to be processing
    if (!queue.isProcessing) return;
    
    const lastActivity = queue.lastProgressAt || queue.processingStartedAt || now;
    const stuckDuration = now - lastActivity;
    
    if (stuckDuration > STUCK_QUEUE_TIMEOUT_MS) {
      const stuckWorkers = queue.activeWorkers;
      console.log(`[BulkFlow] STUCK DETECTED: User ${userId.slice(0, 8)} stuck for ${Math.round(stuckDuration / 1000)}s`);
      console.log(`[BulkFlow] - Resetting: isProcessing=false, activeWorkers=0 (was ${stuckWorkers})`);
      console.log(`[BulkFlow] - Queue has ${queue.queue.length} pending videos`);
      
      // Reset the stuck state (save worker count before resetting)
      queue.isProcessing = false;
      queue.activeWorkers = 0;
      globalActiveWorkers = Math.max(0, globalActiveWorkers - stuckWorkers);
      recoveredCount++;
      
      // If there are pending videos in queue, restart processing
      // NOTE: Only videos in queue.queue (pending) will be processed
      // Videos already in "processing" status in DB are NOT retried - they stay as-is
      if (queue.queue.length > 0) {
        console.log(`[BulkFlow] - Restarting queue for ${queue.queue.length} PENDING videos only`);
        console.log(`[BulkFlow] - Videos already in "processing" status will NOT be retried`);
        // Schedule restart to avoid blocking
        setTimeout(() => processFlowQueue(userId), 100);
      } else {
        console.log(`[BulkFlow] - No pending videos in queue, marking stuck "processing" videos as failed`);
        // Mark any stuck "processing" videos as failed in DB
        markStuckProcessingVideosAsFailed(userId, queue.batchVideoIds);
      }
    }
  });
  
  if (recoveredCount > 0) {
    console.log(`[BulkFlow] Health check: Recovered ${recoveredCount} stuck queue(s)`);
  }
}

// Start health check interval
setInterval(checkAndRecoverStuckQueues, HEALTH_CHECK_INTERVAL_MS);

// ==================== PENDING VIDEO RECOVERY ====================
// Recover pending videos from database that are not in memory queue
// This handles cases where server restarted or queue was lost
// CRITICAL: Query DB directly for ALL users with pending videos, not just userQueues map
async function recoverPendingVideosFromDB() {
  try {
    // FIXED: Query database directly for all pending videos across ALL users
    // This works even after server restart when userQueues is empty
    const allPendingVideos = await storage.getAllPendingVideos();
    
    if (allPendingVideos.length === 0) return;
    
    // Group pending videos by userId
    const pendingByUser = new Map<string, typeof allPendingVideos>();
    for (const video of allPendingVideos) {
      if (!pendingByUser.has(video.userId)) {
        pendingByUser.set(video.userId, []);
      }
      pendingByUser.get(video.userId)!.push(video);
    }
    
    console.log(`[BulkFlow] Recovery check: Found ${allPendingVideos.length} pending videos for ${pendingByUser.size} users`);
    
    // For each user with pending videos
    for (const [userId, pendingVideos] of Array.from(pendingByUser.entries())) {
      const userQueue = getUserQueue(userId); // Creates queue if doesn't exist
      
      // Skip if already processing
      if (userQueue.isProcessing) continue;
      
      // Find videos that are pending in DB but not in memory queue
      const queuedVideoIds = new Set(userQueue.queue.map((v: QueuedVideo) => v.videoId));
      const missingPendingVideos = pendingVideos.filter((v: VideoHistory) => 
        !queuedVideoIds.has(v.id)
      );
      
      if (missingPendingVideos.length === 0) continue;
      
      console.log(`[BulkFlow] Recovering ${missingPendingVideos.length} pending videos for user ${userId.slice(0, 8)}`);
      
      // FIXED: Sort by createdAt to preserve original order, use timestamp-based scene numbers
      missingPendingVideos.sort((a: VideoHistory, b: VideoHistory) => 
        new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
      );
      
      // Find the highest scene number already in queue to avoid duplicates
      const existingMaxScene = userQueue.queue.reduce((max, v) => Math.max(max, v.sceneNumber), 0);
      
      // Add missing videos to queue with unique scene numbers
      for (let i = 0; i < missingPendingVideos.length; i++) {
        const video = missingPendingVideos[i];
        userQueue.queue.push({
          videoId: video.id,
          prompt: video.prompt,
          aspectRatio: video.aspectRatio || '16:9',
          sceneNumber: existingMaxScene + i + 1, // Unique scene number based on existing max
          userId: video.userId
        });
        userQueue.batchVideoIds.add(video.id);
      }
      
      console.log(`[BulkFlow] Re-queued ${missingPendingVideos.length} videos (scenes ${existingMaxScene + 1}-${existingMaxScene + missingPendingVideos.length})`);
      
      // Start processing
      setTimeout(() => processFlowQueue(userId), 100);
    }
  } catch (error) {
    console.log(`[BulkFlow] Error recovering pending videos: ${error}`);
  }
}

// Run pending video recovery every 60 seconds
setInterval(recoverPendingVideosFromDB, 60 * 1000);

// Also run once on startup after a short delay
setTimeout(recoverPendingVideosFromDB, 5000);

function log(message: string, level = 2) {
  if (!shouldLog(level)) return;
  const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
  console.log(`[${timestamp}] [BulkFlow] ${message}`);
}

// Sanitize API responses to remove large base64 data from logs
function sanitizeForLog(obj: any): any {
  if (!obj || typeof obj !== 'object') return obj;
  
  const sanitized: any = Array.isArray(obj) ? [] : {};
  
  for (const key in obj) {
    const value = obj[key];
    
    // Redact binary/base64 fields
    if (['rawBytes', 'encodedVideo', 'encodedImage', 'imageBytes', 'videoBytes'].includes(key)) {
      if (typeof value === 'string' && value.length > 100) {
        sanitized[key] = `[REDACTED: ${Math.round(value.length / 1024)}KB]`;
      } else {
        sanitized[key] = value;
      }
    } else if (typeof value === 'object') {
      sanitized[key] = sanitizeForLog(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

function getUserQueue(userId: string): UserQueueState {
  if (!userQueues.has(userId)) {
    userQueues.set(userId, {
      queue: [],
      isProcessing: false,
      shouldStop: false,
      processingStartedAt: null,
      lastProgressAt: null,
      activeWorkers: 0,
      completedCount: 0,
      failedCount: 0,
      batchVideoIds: new Set()
    });
  }
  return userQueues.get(userId)!;
}

// Cancel existing batch and clean up all queues for user
async function cancelExistingBatch(userId: string): Promise<number> {
  const userQueue = getUserQueue(userId);
  let cancelledCount = 0;
  
  // 1. Get all video IDs that need to be cancelled from the queue
  const queuedVideoIds = userQueue.queue.map(v => v.videoId);
  cancelledCount += queuedVideoIds.length;
  
  // 2. Clear the user's video queue
  userQueue.queue = [];
  
  // 3. Remove user's entries from upload queue and reset counter
  const beforeUploadCount = uploadQueue.length;
  for (let i = uploadQueue.length - 1; i >= 0; i--) {
    if (uploadQueue[i].userId === userId) {
      cancelledCount++;
      uploadQueue.splice(i, 1);
    }
  }
  const removedFromUpload = beforeUploadCount - uploadQueue.length;
  
  // Reset user's upload counter completely
  userUploadCounts.delete(userId);
  
  // 4. Mark all pending/processing/uploading videos as failed in DB
  if (userQueue.batchVideoIds.size > 0) {
    const videoIdsToCancel = Array.from(userQueue.batchVideoIds);
    try {
      await storage.batchCancelVideos(userId, videoIdsToCancel, 'Cancelled - new batch started');
      log(`Cancelled ${videoIdsToCancel.length} videos in DB for user ${userId}`);
    } catch (error) {
      log(`Error cancelling videos in DB: ${error}`);
    }
  }
  
  // 5. Reset counts
  userQueue.completedCount = 0;
  userQueue.failedCount = 0;
  userQueue.batchVideoIds.clear();
  
  if (cancelledCount > 0 || removedFromUpload > 0) {
    log(`User ${userId}: Cancelled ${cancelledCount} queued + ${removedFromUpload} uploads from previous batch`);
  }
  
  return cancelledCount;
}

export async function addToFlowQueue(videos: QueuedVideo[], isNewBatch: boolean = true) {
  if (videos.length === 0) return;
  
  const userId = videos[0].userId;
  const userQueue = getUserQueue(userId);
  
  userQueue.shouldStop = false;
  
  // Cancel previous batch before adding new one
  if (isNewBatch) {
    await cancelExistingBatch(userId);
  }
  
  // Add all video IDs to batch tracking set
  for (const video of videos) {
    userQueue.batchVideoIds.add(video.videoId);
  }
  
  userQueue.queue.push(...videos);
  
  log(`User ${userId}: Added ${videos.length} videos. Queue: ${userQueue.queue.length}`);
  
  if (!userQueue.isProcessing) {
    processFlowQueue(userId);
  }
}

export function stopFlowQueue(userId: string): { stopped: boolean; remaining: number } {
  const userQueue = getUserQueue(userId);
  const remaining = userQueue.queue.length;
  
  // CRITICAL: Fully reset queue state so new batch can start immediately
  userQueue.shouldStop = true;
  userQueue.queue.length = 0;
  userQueue.isProcessing = false;
  userQueue.activeWorkers = 0;
  userQueue.completedCount = 0;
  userQueue.failedCount = 0;
  userQueue.batchVideoIds.clear();
  
  log(`User ${userId}: Stop requested. Cleared ${remaining} pending videos. Queue state fully reset.`);
  return { stopped: true, remaining };
}

export function getFlowQueueStatus(userId: string) {
  const userQueue = getUserQueue(userId);
  return {
    isProcessing: userQueue.isProcessing,
    queueLength: userQueue.queue.length,
    activeWorkers: userQueue.activeWorkers,
    completedCount: userQueue.completedCount,
    failedCount: userQueue.failedCount,
    batchVideoIds: Array.from(userQueue.batchVideoIds) // Return as array for JSON serialization
  };
}

const MAX_RETRIES = 3; // Silent auto-retry 3 times for any error
const WHISK_BASE_URL = "https://aisandbox-pa.googleapis.com/v1";

// All errors are now retryable - silent auto-retry for any failure
function isRetryableError(_errorMsg: string): boolean {
  // Always return true - retry any error up to MAX_RETRIES times
  return true;
}

interface WhiskImageResponse {
  imagePanels?: Array<{
    prompt: string;
    generatedImages: Array<{
      encodedImage: string;
      mediaGenerationId: string;
    }>;
  }>;
  workflowId?: string;
}

interface WhiskVideoResponse {
  operation?: {
    operation: {
      name: string;
    };
  };
}

interface VideoStatusResponse {
  operations?: Array<{
    status?: string;
    rawBytes?: string;
    operation: {
      done?: boolean;
      error?: {
        code?: number;
        message?: string;
      };
      response?: {
        videoResult?: {
          video?: {
            encodedVideo?: string;
            uri?: string;
            rawBytes?: string;
          };
        };
        generatedVideo?: {
          encodedVideo?: string;
          videoUrl?: string;
          rawBytes?: string;
        };
        rawBytes?: string;
      };
    };
  }>;
  rawBytes?: string;
}

async function generateWhiskImage(
  apiKey: string,
  prompt: string,
  aspectRatio: string
): Promise<{ encodedImage: string; mediaGenerationId: string; workflowId: string }> {
  const workflowId = crypto.randomUUID();
  const sessionId = `;${Date.now()}`;
  const seed = Math.floor(Math.random() * 1000000);
  
  const imageAspectRatio = aspectRatio === 'portrait' || aspectRatio === '9:16'
    ? 'IMAGE_ASPECT_RATIO_PORTRAIT' 
    : 'IMAGE_ASPECT_RATIO_LANDSCAPE';

  const requestBody = {
    clientContext: {
      workflowId: workflowId,
      tool: "BACKBONE",
      sessionId: sessionId
    },
    imageModelSettings: {
      imageModel: "IMAGEN_3_5",
      aspectRatio: imageAspectRatio
    },
    seed: seed,
    prompt: prompt,
    mediaCategory: "MEDIA_CATEGORY_BOARD"
  };

  const response = await fetch(`${WHISK_BASE_URL}/whisk:generateImage`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Image generation failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }

  const data: WhiskImageResponse = await response.json();
  
  if (!data.imagePanels || data.imagePanels.length === 0 || 
      !data.imagePanels[0].generatedImages || data.imagePanels[0].generatedImages.length === 0) {
    throw new Error('No image generated from Whisk API');
  }

  const generatedImage = data.imagePanels[0].generatedImages[0];
  return {
    encodedImage: generatedImage.encodedImage,
    mediaGenerationId: generatedImage.mediaGenerationId,
    workflowId: data.workflowId || workflowId
  };
}

async function startWhiskVideoGeneration(
  apiKey: string,
  prompt: string,
  encodedImage: string,
  mediaGenerationId: string,
  workflowId: string
): Promise<string> {
  const sessionId = `;${Date.now()}`;

  const requestBody = {
    clientContext: {
      sessionId: sessionId,
      tool: "BACKBONE",
      workflowId: workflowId
    },
    promptImageInput: {
      prompt: prompt,
      rawBytes: encodedImage,
      mediaGenerationId: mediaGenerationId
    },
    modelNameType: "VEO_3_1_I2V_12STEP",
    modelKey: "",
    userInstructions: prompt,
    loopVideo: false
  };

  const response = await fetch(`${WHISK_BASE_URL}/whisk:generateVideo`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Video generation start failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }

  const data: WhiskVideoResponse = await response.json();
  
  if (!data.operation?.operation?.name) {
    throw new Error('No operation name returned from video generation');
  }

  return data.operation.operation.name;
}

async function checkWhiskVideoStatus(
  apiKey: string,
  operationName: string,
  videoId?: string,
  userId?: string,
  sceneNumber?: number
): Promise<{ done: boolean; videoUrl?: string; error?: string; uploading?: boolean }> {
  const requestBody = {
    operations: [{
      operation: {
        name: operationName
      }
    }]
  };

  const response = await fetch(`${WHISK_BASE_URL}:runVideoFxSingleClipsStatusCheck`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(`Status check failed: ${response.status}`);
  }

  const data: VideoStatusResponse = await response.json();
  
  // Sanitize response to remove large base64 data before logging
  const sanitizedData = sanitizeForLog(data);
  log(`Poll: status=${sanitizedData.operations?.[0]?.status || 'unknown'}, done=${sanitizedData.operations?.[0]?.done || false}`);
  
  if (!data.operations || data.operations.length === 0) {
    return { done: false };
  }

  const operationData = data.operations[0];
  const operation = operationData.operation;
  const status = operationData.status;
  
  if (operation?.error) {
    return { 
      done: true, 
      error: operation.error.message || 'Video generation failed' 
    };
  }

  // Check for success using status field (MEDIA_GENERATION_STATUS_SUCCESSFUL)
  const isSuccessful = status === 'MEDIA_GENERATION_STATUS_SUCCESSFUL' || operation?.done;

  if (isSuccessful) {
    let videoUrl: string | undefined;
    let base64Video: string | undefined;
    
    // Check for URL first
    if (operation?.response?.videoResult?.video?.uri) {
      videoUrl = operation.response.videoResult.video.uri;
    } else if (operation?.response?.generatedVideo?.videoUrl) {
      videoUrl = operation.response.generatedVideo.videoUrl;
    }
    
    // Check for rawBytes - prioritize direct field on operations[0]
    if (!videoUrl) {
      base64Video = 
        operationData.rawBytes ||
        data.rawBytes ||
        operation?.response?.rawBytes ||
        operation?.response?.videoResult?.video?.rawBytes ||
        operation?.response?.generatedVideo?.rawBytes ||
        operation?.response?.videoResult?.video?.encodedVideo ||
        operation?.response?.generatedVideo?.encodedVideo;
    }
    
    if (base64Video && videoId && userId && sceneNumber !== undefined) {
      // Check storage method - if direct_to_user, skip upload entirely
      const storageMethod = await getCachedStorageMethod();
      
      if (storageMethod === 'direct_to_user') {
        // Store in temp file cache with TTL (NOT in memory to prevent VPS memory overflow)
        await saveDirectVideo(videoId, base64Video, userId);
        
        // Only store marker in database, NOT the full base64 (saves memory + DB space)
        await storage.updateVideoHistoryFields(videoId, { 
          status: 'completed', 
          videoUrl: `direct:${videoId}` // Marker for frontend to use download endpoint
        });
        log(`Video ${sceneNumber} complete - direct to user (cached in temp file)`);
        return { done: true, videoUrl: `direct:${videoId}` };
      }
      
      // Queue upload in background - don't block the worker!
      queueUpload(videoId, base64Video, userId, sceneNumber);
      log(`Video ${sceneNumber} generation complete, queued for upload`);
      // Return special status indicating upload is queued
      return { done: true, uploading: true };
    } else if (base64Video && videoId) {
      // Fallback: blocking upload if no userId/sceneNumber (shouldn't happen)
      const storageMethod = await getCachedStorageMethod();
      
      if (storageMethod === 'direct_to_user') {
        // Store in temp file cache with unknown user (fallback case)
        await saveDirectVideo(videoId, base64Video, 'unknown');
        return { done: true, videoUrl: `direct:${videoId}` };
      }
      
      try {
        const uploadResult = await uploadBase64VideoWithFallback(base64Video, videoId);
        videoUrl = uploadResult.url;
        log(`Video uploaded (sync): ${videoUrl?.slice(0, 60)}...`);
      } catch (uploadError) {
        log(`All upload methods FAILED: ${uploadError}`);
        throw new Error(`Upload failed: ${uploadError}`);
      }
    }

    if (videoUrl) {
      return { done: true, videoUrl };
    }
    
    // If we queued the upload, return uploading status (handled above)
    return { done: true, error: 'Video completed but no URL found' };
  }

  return { done: false };
}

async function generateVideoWithWhiskAPI(
  prompt: string,
  aspectRatio: string,
  token: ApiToken,
  videoId?: string,
  userId?: string,
  sceneNumber?: number
): Promise<{ success: boolean; videoUrl?: string; error?: string; uploading?: boolean }> {
  const apiKey = token.token;
  
  try {
    log(`Generating image for prompt: "${prompt.substring(0, 40)}..."`);
    const imageResult = await generateWhiskImage(apiKey, prompt, aspectRatio);
    
    log(`Starting video generation...`);
    const operationName = await startWhiskVideoGeneration(
      apiKey,
      prompt,
      imageResult.encodedImage,
      imageResult.mediaGenerationId,
      imageResult.workflowId
    );
    
    log(`Polling for video status: ${operationName}`);
    const maxPolls = 40; // Reduced from 60 - faster timeout detection
    const pollInterval = 6000; // Reduced from 10000 - faster status checks
    
    for (let i = 0; i < maxPolls; i++) {
      const status = await checkWhiskVideoStatus(apiKey, operationName, videoId, userId, sceneNumber);
      
      if (status.done) {
        if (status.uploading) {
          // Video complete, upload queued in background
          return { success: true, uploading: true };
        } else if (status.videoUrl) {
          return { success: true, videoUrl: status.videoUrl };
        } else {
          return { success: false, error: status.error || 'Video generation failed' };
        }
      }
      
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
    
    return { success: false, error: 'Video generation timed out' };
    
  } catch (error) {
    return { 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    };
  }
}

async function processSingleVideoWithFlow(video: QueuedVideo, _cookie: FlowCookie, activeTokens: ApiToken[]): Promise<boolean> {
  log(`Processing video ${video.sceneNumber} with Whisk API`);
  
  let usedTokenIds = new Set<string>();
  
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      if (attempt === 1) {
        // Use retry for initial status update (DB may timeout under load)
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, 'processing'), 2, 1000);
      }
      
      // Get cached tokens (5s TTL) to reduce DB calls while still handling admin token changes
      // Cache is invalidated on token errors
      const freshActiveTokens = await getCachedActiveTokens();
      
      // Use pre-assigned token for first attempt ONLY IF it's still active
      let token: ApiToken | null = null;
      
      if (attempt === 1 && video.assignedToken) {
        // Check if pre-assigned token is still active
        const stillActive = freshActiveTokens.some(t => t.id === video.assignedToken!.id);
        if (stillActive) {
          token = video.assignedToken;
          log(`Using pre-assigned token: ${token.label}`);
        } else {
          log(`Pre-assigned token ${video.assignedToken.label} no longer active, getting fresh token`);
          video.assignedToken = undefined; // Clear invalid assignment
        }
      }
      
      if (!token) {
        // Get a fresh token (excluding already used ones)
        const availableTokens = freshActiveTokens.filter(t => !usedTokenIds.has(t.id));
        if (availableTokens.length > 0) {
          const randomIdx = Math.floor(Math.random() * availableTokens.length);
          token = availableTokens[randomIdx] ?? null;
        } else {
          // All tokens used, try to get any available
          token = (await storage.getNextRotationToken()) ?? null;
        }
      }
      
      if (!token) {
        throw new Error('No active API tokens available');
      }
      
      usedTokenIds.add(token.id);
      await storage.updateTokenUsage(token.id);
      log(`Using token: ${token.label} (attempt ${attempt})`);
      
      const result = await generateVideoWithWhiskAPI(
        video.prompt,
        video.aspectRatio,
        token,
        video.videoId,
        video.userId,
        video.sceneNumber
      );
      
      if (result.success && result.uploading) {
        // Video generation successful, upload queued in background
        log(`Video ${video.sceneNumber} SUCCESS with token ${token.label} (attempt ${attempt}) - upload queued`);
        // Mark as "uploading" status so frontend knows it's processing (with retry)
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, 'uploading'), 2, 1000);
        return true;
      } else if (result.success && result.videoUrl) {
        log(`Video ${video.sceneNumber} SUCCESS with token ${token.label} (attempt ${attempt})`);
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, 'completed', result.videoUrl), 2, 1000);
        return true;
        
      } else {
        const errorMsg = result.error || 'Unknown error';
        
        storage.recordTokenError(token.id);
        invalidateTokenCache(); // Force fresh tokens on next attempt
        
        // Silent auto-retry for any error (up to 3 times)
        if (attempt < MAX_RETRIES) {
          // Silent retry - only log at verbose level (level 3)
          log(`Video ${video.sceneNumber} retry ${attempt}/${MAX_RETRIES}`, 3);
          await new Promise(resolve => setTimeout(resolve, randomDelay(500, 1500)));
          continue;
        }
        
        // Final failure after all retries - log as error
        log(`Video ${video.sceneNumber} FAILED after ${MAX_RETRIES} retries: ${errorMsg}`, 1);
        
        // Use try-catch for final status update (don't let DB error crash the worker)
        try {
          await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, errorMsg), 2, 1000);
        } catch (dbErr) {
          log(`DB error updating failed status for video ${video.sceneNumber}: ${dbErr}`);
        }
        return false;
      }
      
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      
      // Silent auto-retry for any error (up to 3 times)
      if (attempt < MAX_RETRIES) {
        // Silent retry - only log at verbose level (level 3)
        log(`Video ${video.sceneNumber} retry ${attempt}/${MAX_RETRIES} (error)`, 3);
        await new Promise(resolve => setTimeout(resolve, randomDelay(500, 1500)));
        continue;
      }
      
      // Final failure after all retries - log as error
      log(`Video ${video.sceneNumber} FAILED after ${MAX_RETRIES} retries: ${errorMsg}`, 1);
      
      // Use try-catch for final status update (don't let DB error crash the worker)
      try {
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, errorMsg), 2, 1000);
      } catch (dbErr) {
        log(`DB error updating failed status for video ${video.sceneNumber}: ${dbErr}`);
      }
      return false;
    }
  }
  
  return false;
}

async function processFlowQueue(userId: string) {
  const userQueue = getUserQueue(userId);
  
  // STUCK QUEUE DETECTION: If processing is stuck for too long, reset it
  if (userQueue.isProcessing) {
    const now = Date.now();
    const lastActivity = userQueue.lastProgressAt || userQueue.processingStartedAt || now;
    const stuckDuration = now - lastActivity;
    
    if (stuckDuration > STUCK_QUEUE_TIMEOUT_MS) {
      log(`User ${userId}: Queue stuck for ${Math.round(stuckDuration/1000)}s, resetting isProcessing flag`, 1);
      userQueue.isProcessing = false;
      userQueue.activeWorkers = 0; // Reset worker count to prevent leaks
    } else {
      log(`User ${userId}: Already processing (last activity ${Math.round(stuckDuration/1000)}s ago), skipping`);
      return;
    }
  }
  
  userQueue.isProcessing = true;
  userQueue.processingStartedAt = Date.now();
  userQueue.lastProgressAt = Date.now(); // Initialize progress timestamp
  
  log(`User ${userId}: Starting queue with ${userQueue.queue.length} videos`);
  
  try {
    // Use cached tokens to reduce DB calls
    const activeTokens = await getCachedActiveTokens();
    
    if (activeTokens.length === 0) {
      log(`No active API tokens available, aborting`, 1);
      userQueue.isProcessing = false;
      return;
    }
    
    // Sliding window approach - continuously start new videos as soon as slots free up
    const activePromises = new Set<Promise<void>>();
    let tokenIndex = 0;
    
    const startNextVideo = async () => {
      if (userQueue.queue.length === 0 || userQueue.shouldStop) return;
      if (Date.now() - userQueue.processingStartedAt! > MAX_PROCESSING_TIME_MS) return;
      
      // MULTI-USER OPTIMIZATION: Check both user limit AND global limit
      if (userQueue.activeWorkers >= MAX_CONCURRENT_PER_USER) {
        log(`User ${userId.slice(0,8)}: At per-user limit (${userQueue.activeWorkers}/${MAX_CONCURRENT_PER_USER})`);
        return;
      }
      if (globalActiveWorkers >= GLOBAL_MAX_CONCURRENT_WORKERS) {
        log(`Global limit reached (${globalActiveWorkers}/${GLOBAL_MAX_CONCURRENT_WORKERS}), waiting...`);
        // Retry after a short delay
        setTimeout(() => startNextVideo(), 500);
        return;
      }
      
      const video = userQueue.queue.shift()!;
      
      // CRITICAL: Increment BEFORE any async work, decrement in finally block
      userQueue.activeWorkers++;
      globalActiveWorkers++;
      
      let promiseRef: Promise<void>;
      
      const videoProcessor = async () => {
        try {
          // Assign token using round-robin
          video.assignedToken = activeTokens[tokenIndex % activeTokens.length];
          tokenIndex++;
          
          log(`Video ${video.sceneNumber} started (user: ${userQueue.activeWorkers}/${MAX_CONCURRENT_PER_USER}, global: ${globalActiveWorkers}/${GLOBAL_MAX_CONCURRENT_WORKERS})`);
          
          const success = await processSingleVideoWithFlow(video, {} as FlowCookie, activeTokens);
          if (success) {
            userQueue.completedCount++;
          } else {
            userQueue.failedCount++;
          }
          // Update progress timestamp after each video completes
          userQueue.lastProgressAt = Date.now();
        } catch (err) {
          userQueue.failedCount++;
          userQueue.lastProgressAt = Date.now(); // Update even on error
          log(`Error processing video ${video.sceneNumber}: ${err}`);
        } finally {
          // ALWAYS decrement in finally to prevent leaks
          userQueue.activeWorkers--;
          globalActiveWorkers--;
          
          // Remove this promise from active set
          activePromises.delete(promiseRef);
          
          // Immediately start next video if slot is available (check both limits)
          if (userQueue.activeWorkers < MAX_CONCURRENT_PER_USER && 
              globalActiveWorkers < GLOBAL_MAX_CONCURRENT_WORKERS &&
              userQueue.queue.length > 0 && !userQueue.shouldStop) {
            // TAIL-END OPTIMIZATION: Minimal delay when queue is small
            const delay = userQueue.queue.length < 5 ? 10 : 50;
            await new Promise(resolve => setTimeout(resolve, delay));
            startNextVideo();
          }
        }
      };
      
      promiseRef = videoProcessor();
      activePromises.add(promiseRef);
    };
    
    // Initial burst - fill up to per-user max, respecting global limit
    const availableGlobalSlots = GLOBAL_MAX_CONCURRENT_WORKERS - globalActiveWorkers;
    const initialBurst = Math.min(MAX_CONCURRENT_PER_USER, userQueue.queue.length, availableGlobalSlots);
    log(`User ${userId.slice(0,8)}: Starting ${initialBurst} videos (global available: ${availableGlobalSlots})`);
    
    for (let i = 0; i < initialBurst; i++) {
      startNextVideo();
      await new Promise(resolve => setTimeout(resolve, 100)); // Small stagger to prevent API spike
    }
    
    logMemory(`Initial burst complete, ${activePromises.size} active workers`);
    
    // Wait for all videos to complete
    // CRITICAL: Use activeWorkers as source of truth (not activePromises.size) to avoid race condition
    // The race: finally block deletes promise, 50ms delay, then starts next - during that window activePromises is empty
    while (userQueue.activeWorkers > 0 || userQueue.queue.length > 0 || activePromises.size > 0) {
      if (userQueue.shouldStop) {
        log(`Stop requested, waiting for ${userQueue.activeWorkers} active videos to complete`);
        break;
      }
      
      if (Date.now() - userQueue.processingStartedAt! > MAX_PROCESSING_TIME_MS) {
        log(`Max processing time exceeded, stopping`);
        break;
      }
      
      // TAIL-END OPTIMIZATION: Faster checks when near completion
      const remainingTotal = userQueue.activeWorkers + userQueue.queue.length;
      const checkInterval = remainingTotal <= 5 ? 100 : 500; // 100ms for last 5 videos
      await new Promise(resolve => setTimeout(resolve, checkInterval));
      
      // Log progress for debugging slow batches
      if (userQueue.activeWorkers > 0) {
        log(`Progress: ${userQueue.completedCount + userQueue.failedCount}/${userQueue.completedCount + userQueue.failedCount + userQueue.activeWorkers + userQueue.queue.length} (${userQueue.activeWorkers} active, ${userQueue.queue.length} queued)`);
      }
      
      // If we have slots available and queue has items, start more
      while (userQueue.activeWorkers < MAX_CONCURRENT_PER_USER && userQueue.queue.length > 0 && !userQueue.shouldStop) {
        startNextVideo();
        // TAIL-END OPTIMIZATION: Minimal delay when queue is small  
        const startDelay = userQueue.queue.length < 5 ? 10 : 50;
        await new Promise(resolve => setTimeout(resolve, startDelay));
      }
    }
    
    // Wait for remaining active promises (safety net)
    if (activePromises.size > 0) {
      log(`Waiting for ${activePromises.size} remaining videos to complete...`);
      await Promise.all(activePromises);
    }
    
  } finally {
    userQueue.isProcessing = false;
    userQueue.processingStartedAt = null;
    log(`User ${userId}: Queue COMPLETE. Completed: ${userQueue.completedCount}, Failed: ${userQueue.failedCount}`);
  }
}

export { processFlowQueue };
