/**
 * Memory Video Cache - Fallback storage when Cloudinary and Google Drive both fail
 * Features:
 * - LRU eviction when cache is full
 * - TTL-based auto cleanup (30 min default)
 * - Size limits per item and total cache
 * - Memory-efficient with Buffer zeroing
 */

interface CachedVideo {
  buffer: Buffer;
  videoId: string;
  prompt: string;
  aspectRatio: string;
  createdAt: number;
  sizeBytes: number;
}

// Configuration - can be overridden via env
const MAX_CACHE_BYTES = parseInt(process.env.BULK_MAX_CACHE_MB || '512', 10) * 1024 * 1024; // 512MB default
const MAX_ITEM_BYTES = 75 * 1024 * 1024; // 75MB max per video
const TTL_MS = 30 * 60 * 1000; // 30 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // Cleanup every 5 minutes

// LRU Cache implementation
const cache = new Map<string, CachedVideo>();
let currentCacheBytes = 0;

function log(message: string) {
  const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
  console.log(`[${timestamp}] [MemCache] ${message}`);
}

/**
 * Store video buffer in memory cache
 * Returns true if stored successfully, false if rejected (too large, etc)
 */
export function storeVideoInMemory(
  videoId: string,
  buffer: Buffer,
  prompt: string,
  aspectRatio: string
): boolean {
  const sizeBytes = buffer.length;
  
  // Reject if single item too large
  if (sizeBytes > MAX_ITEM_BYTES) {
    log(`Rejected ${videoId}: ${(sizeBytes / 1024 / 1024).toFixed(1)}MB exceeds max ${MAX_ITEM_BYTES / 1024 / 1024}MB`);
    return false;
  }
  
  // Evict old items until we have space (LRU)
  while (currentCacheBytes + sizeBytes > MAX_CACHE_BYTES && cache.size > 0) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey) {
      evictItem(oldestKey);
    }
  }
  
  // Still not enough space after eviction
  if (currentCacheBytes + sizeBytes > MAX_CACHE_BYTES) {
    log(`Rejected ${videoId}: No space available (${(currentCacheBytes / 1024 / 1024).toFixed(1)}MB used)`);
    return false;
  }
  
  // Store the video
  cache.set(videoId, {
    buffer,
    videoId,
    prompt: prompt.slice(0, 200), // Truncate prompt for memory
    aspectRatio,
    createdAt: Date.now(),
    sizeBytes
  });
  
  currentCacheBytes += sizeBytes;
  log(`Stored ${videoId}: ${(sizeBytes / 1024 / 1024).toFixed(1)}MB (total: ${(currentCacheBytes / 1024 / 1024).toFixed(1)}MB, items: ${cache.size})`);
  
  return true;
}

/**
 * Get video buffer from memory cache
 */
export function getVideoFromMemory(videoId: string): Buffer | null {
  const cached = cache.get(videoId);
  if (!cached) return null;
  
  // Move to end (LRU update)
  cache.delete(videoId);
  cache.set(videoId, cached);
  
  return cached.buffer;
}

/**
 * Delete video from memory cache and zero out buffer
 */
export function deleteVideoFromMemory(videoId: string): boolean {
  const cached = cache.get(videoId);
  if (!cached) return false;
  
  // Zero out buffer for security
  cached.buffer.fill(0);
  currentCacheBytes -= cached.sizeBytes;
  cache.delete(videoId);
  
  log(`Deleted ${videoId}: freed ${(cached.sizeBytes / 1024 / 1024).toFixed(1)}MB`);
  return true;
}

/**
 * Evict item from cache (internal use)
 */
function evictItem(videoId: string) {
  const cached = cache.get(videoId);
  if (!cached) return;
  
  cached.buffer.fill(0);
  currentCacheBytes -= cached.sizeBytes;
  cache.delete(videoId);
  log(`Evicted ${videoId} (LRU): freed ${(cached.sizeBytes / 1024 / 1024).toFixed(1)}MB`);
}

/**
 * Cleanup expired items (TTL-based)
 */
function cleanupExpired() {
  const now = Date.now();
  let cleanedCount = 0;
  let cleanedBytes = 0;
  
  const entries = Array.from(cache.entries());
  for (const [videoId, cached] of entries) {
    if (now - cached.createdAt > TTL_MS) {
      cleanedBytes += cached.sizeBytes;
      cached.buffer.fill(0);
      currentCacheBytes -= cached.sizeBytes;
      cache.delete(videoId);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    log(`TTL cleanup: removed ${cleanedCount} items, freed ${(cleanedBytes / 1024 / 1024).toFixed(1)}MB`);
  }
}

/**
 * Get cache statistics
 */
export function getMemoryCacheStats() {
  return {
    count: cache.size,
    sizeBytes: currentCacheBytes,
    sizeMB: Math.round(currentCacheBytes / 1024 / 1024 * 10) / 10,
    maxMB: MAX_CACHE_BYTES / 1024 / 1024,
    usagePercent: Math.round((currentCacheBytes / MAX_CACHE_BYTES) * 100),
    oldestItemAge: cache.size > 0 
      ? Math.round((Date.now() - Array.from(cache.values())[0].createdAt) / 1000 / 60) 
      : 0
  };
}

/**
 * List all cached video IDs with metadata
 */
export function listCachedVideos() {
  return Array.from(cache.values()).map(v => ({
    videoId: v.videoId,
    prompt: v.prompt,
    aspectRatio: v.aspectRatio,
    sizeMB: Math.round(v.sizeBytes / 1024 / 1024 * 10) / 10,
    ageMinutes: Math.round((Date.now() - v.createdAt) / 1000 / 60)
  }));
}

/**
 * Clear entire cache
 */
export function clearMemoryCache() {
  const values = Array.from(cache.values());
  for (const cached of values) {
    cached.buffer.fill(0);
  }
  cache.clear();
  currentCacheBytes = 0;
  log('Cache cleared');
}

// Start periodic cleanup
setInterval(cleanupExpired, CLEANUP_INTERVAL_MS);
log(`Initialized: max ${MAX_CACHE_BYTES / 1024 / 1024}MB, TTL ${TTL_MS / 60000}min`);
