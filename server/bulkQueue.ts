import { storage } from "./storage";
import type { ApiToken } from "@shared/schema";

// Queue to store videos pending generation
interface QueuedVideo {
  videoId: string;
  prompt: string;
  aspectRatio: string;
  sceneNumber: number;
  userId: string;
  assignedToken?: ApiToken; // Pre-assigned token for this video
}

// Per-user queue state
interface UserQueueState {
  queue: QueuedVideo[];
  isProcessing: boolean;
  shouldStop: boolean;
  processingStartedAt: number | null; // Timestamp when processing started
}

// Maximum time a queue can be in processing state before auto-reset (2 hours)
const MAX_PROCESSING_TIME_MS = 2 * 60 * 60 * 1000;

// Map of userId -> queue state (user-specific queues)
const userQueues = new Map<string, UserQueueState>();

const DELAY_BETWEEN_REQUESTS_MS = 3000; // 3 seconds - faster throughput
const MAX_INSTANT_RETRIES = 10; // Max instant retries when initial generation fails
const MAX_POLLING_RETRIES = 10; // Max polling retries when VEO returns failure during status check
const INSTANT_RETRY_DELAY_MS = 500; // 500ms between instant retries (< 1 second)

/**
 * Get or create user queue state
 */
function getUserQueue(userId: string): UserQueueState {
  if (!userQueues.has(userId)) {
    userQueues.set(userId, {
      queue: [],
      isProcessing: false,
      shouldStop: false,
      processingStartedAt: null
    });
  }
  return userQueues.get(userId)!;
}

/**
 * Check if a user's queue is stuck (processing for too long) and auto-reset if needed
 */
function checkAndResetStuckQueue(userId: string): boolean {
  const userQueue = getUserQueue(userId);
  
  if (userQueue.isProcessing && userQueue.processingStartedAt) {
    const processingDuration = Date.now() - userQueue.processingStartedAt;
    
    if (processingDuration > MAX_PROCESSING_TIME_MS) {
      console.log(`[Bulk Queue] User ${userId}: ⚠️ Queue stuck for ${Math.round(processingDuration / 60000)} minutes. Auto-resetting...`);
      
      // Force reset the queue state
      userQueue.isProcessing = false;
      userQueue.shouldStop = true;
      userQueue.processingStartedAt = null;
      userQueue.queue.length = 0;
      
      console.log(`[Bulk Queue] User ${userId}: ✅ Queue auto-reset complete`);
      return true; // Was stuck and reset
    }
  }
  
  return false; // Not stuck
}

/**
 * Add videos to the bulk generation queue (user-specific)
 */
export function addToQueue(videos: QueuedVideo[], delaySeconds?: number) {
  if (videos.length === 0) return;
  
  const userId = videos[0].userId; // All videos in batch belong to same user
  const userQueue = getUserQueue(userId);
  
  // CRITICAL: Reset stop flag when starting new generation
  userQueue.shouldStop = false;
  
  userQueue.queue.push(...videos);
  console.log(`[Bulk Queue] User ${userId}: Added ${videos.length} videos to queue. Total in queue: ${userQueue.queue.length}`);
  
  // Start processing if not already running for this user
  if (!userQueue.isProcessing) {
    processQueue(userId, delaySeconds);
  }
}

/**
 * Process a single video from the batch with instant retry on failure
 */
async function processSingleVideo(video: QueuedVideo): Promise<void> {
  let attemptNumber = 0;
  let lastError: string | undefined;
  let succeeded = false;
  const disabledTokenIds = new Set<string>(); // Track disabled tokens in this video's retry session
  
  // Try up to MAX_INSTANT_RETRIES times with different tokens
  while (attemptNumber < MAX_INSTANT_RETRIES && !succeeded) {
    attemptNumber++;
    let rotationToken: ApiToken | undefined;
    
    try {
      console.log(`[Bulk Queue] 🔄 Processing video ${video.sceneNumber} (ID: ${video.videoId}) - Attempt ${attemptNumber}/${MAX_INSTANT_RETRIES}`);
      
      // Get API token using round-robin rotation (different token on each attempt)
      let apiKey: string | undefined;
      
      // Use pre-assigned token for first attempt (if not disabled), or get next token for retries
      if (attemptNumber === 1 && video.assignedToken && !disabledTokenIds.has(video.assignedToken.id)) {
        rotationToken = video.assignedToken;
        console.log(`[Bulk Queue] 🎯 Using PRE-ASSIGNED token ${rotationToken.label} (ID: ${rotationToken.id}) for video ${video.sceneNumber}`);
      } else {
        // Get next token excluding disabled ones
        const allTokens = await storage.getActiveApiTokens();
        const availableTokens = allTokens
          .filter(t => !disabledTokenIds.has(t.id) && !storage.isTokenInCooldown(t.id))
          .sort((a, b) => {
            const aTime = a.lastUsedAt ? new Date(a.lastUsedAt).getTime() : 0;
            const bTime = b.lastUsedAt ? new Date(b.lastUsedAt).getTime() : 0;
            return aTime - bTime;
          });
        rotationToken = availableTokens[0];
        
        if (!rotationToken) {
          // No tokens available after exclusion - abort immediately
          lastError = `No active API tokens available after excluding ${disabledTokenIds.size} disabled tokens. All tokens exhausted.`;
          console.error(`[Bulk Queue] ❌ ${lastError}`);
          await storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, lastError);
          return;
        }
        
        console.log(`[Bulk Queue] 🔄 Using NEXT ROTATION token ${rotationToken.label} (ID: ${rotationToken.id}) for retry attempt ${attemptNumber}${disabledTokenIds.size > 0 ? ` (excluding ${disabledTokenIds.size} disabled)` : ''}`);
        // Update usage for retry tokens
        await storage.updateTokenUsage(rotationToken.id);
      }
      
      apiKey = rotationToken.token;
      console.log(`[Bulk Queue] 🎯 Token: ${rotationToken.label} (ID: ${rotationToken.id}) for video ${video.sceneNumber} (attempt ${attemptNumber})`);

      // Send VEO generation request
      const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
      const sceneId = `bulk-${video.videoId}-${Date.now()}-attempt${attemptNumber}`;
      const seed = Math.floor(Math.random() * 100000);

      const payload = {
        clientContext: {
          projectId: veoProjectId,
          tool: "PINHOLE",
          userPaygateTier: "PAYGATE_TIER_TWO"
        },
        requests: [{
          aspectRatio: video.aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
          seed: seed,
          textInput: {
            prompt: video.prompt
          },
          videoModelKey: video.aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
          metadata: {
            sceneId: sceneId
          }
        }]
      };

      // Add timeout to fetch request (90 seconds - VEO API can be slow to accept requests)
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 90000);
      
      let response;
      let data;
      
      try {
        response = await fetch('https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        
        clearTimeout(timeout);
        data = await response.json();
      } catch (fetchError: any) {
        clearTimeout(timeout);
        
        // Check if this is an authentication error
        const isAuthError = fetchError.message && (
          fetchError.message.toLowerCase().includes('invalid authentication') ||
          fetchError.message.toLowerCase().includes('oauth 2 access token') ||
          fetchError.message.toLowerCase().includes('unauthorized') ||
          fetchError.message.toLowerCase().includes('401')
        );
        
        if (rotationToken) {
          if (isAuthError) {
            console.log(`[Bulk Queue] 🔴 Authentication error detected - auto-disabling token ${rotationToken.id}`);
            await storage.toggleApiTokenStatus(rotationToken.id, false);
            // Add to exclusion list for this video's retries
            disabledTokenIds.add(rotationToken.id);
            console.log(`[Bulk Queue] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
            // Clear assignedToken so retries get a different token
            if (video.assignedToken && video.assignedToken.id === rotationToken.id) {
              video.assignedToken = undefined;
              console.log(`[Bulk Queue] Cleared disabled token from video ${video.sceneNumber} assignedToken`);
            }
          } else {
            storage.recordTokenError(rotationToken.id);
          }
        }
        
        if (fetchError.name === 'AbortError') {
          lastError = `Request timeout after 90 seconds - VEO API not responding`;
          console.error(`[Bulk Queue] ❌ Attempt ${attemptNumber} - Request timeout:`, fetchError);
        } else {
          lastError = `Network error: ${fetchError.message}`;
          console.error(`[Bulk Queue] ❌ Attempt ${attemptNumber} - Network error:`, fetchError);
        }
        
        // Retry with different token after short delay
        if (attemptNumber < MAX_INSTANT_RETRIES) {
          console.log(`[Bulk Queue] ⏳ Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
          await new Promise(resolve => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
          continue;
        }
        
        // All attempts failed
        await storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
        return;
      }

      if (!response.ok) {
        lastError = `VEO API error (${response.status}): ${JSON.stringify(data).substring(0, 200)}`;
        console.error(`[Bulk Queue] ❌ Attempt ${attemptNumber} - VEO API error:`, data);
        
        // Check for authentication error
        const isAuthError = response.status === 401 || 
          (data.error && (
            data.error.message?.toLowerCase().includes('invalid authentication') ||
            data.error.message?.toLowerCase().includes('oauth 2 access token') ||
            data.error.message?.toLowerCase().includes('unauthorized')
          ));
        
        if (rotationToken) {
          if (isAuthError) {
            console.log(`[Bulk Queue] 🔴 Authentication error detected - auto-disabling token ${rotationToken.id}`);
            await storage.toggleApiTokenStatus(rotationToken.id, false);
            // Add to exclusion list for this video's retries
            disabledTokenIds.add(rotationToken.id);
            console.log(`[Bulk Queue] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
            // Clear assignedToken so retries get a different token
            if (video.assignedToken && video.assignedToken.id === rotationToken.id) {
              video.assignedToken = undefined;
              console.log(`[Bulk Queue] Cleared disabled token from video ${video.sceneNumber} assignedToken`);
            }
          } else {
            storage.recordTokenError(rotationToken.id);
          }
        }
        
        // Retry with different token after short delay
        if (attemptNumber < MAX_INSTANT_RETRIES) {
          console.log(`[Bulk Queue] ⏳ Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
          await new Promise(resolve => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
          continue;
        }
        
        // All attempts failed
        await storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
        return;
      }

      if (!data.operations || data.operations.length === 0) {
        lastError = 'No operations returned from VEO API - possible API issue';
        console.error(`[Bulk Queue] ❌ Attempt ${attemptNumber} - No operations returned from VEO API`);
        
        if (rotationToken) {
          storage.recordTokenError(rotationToken.id);
        }
        
        // Retry with different token after short delay
        if (attemptNumber < MAX_INSTANT_RETRIES) {
          console.log(`[Bulk Queue] ⏳ Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
          await new Promise(resolve => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
          continue;
        }
        
        // All attempts failed
        await storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
        return;
      }

      // SUCCESS! Video generation started
      const operation = data.operations[0];
      const operationName = operation.operation.name;

      console.log(`[Bulk Queue] ✅ Started generation for video ${video.sceneNumber} - Operation: ${operationName} (attempt ${attemptNumber})`);
      succeeded = true;

      // Update history with token ID if available
      if (rotationToken) {
        try {
          await storage.updateVideoHistoryFields(video.videoId, { tokenUsed: rotationToken.id });
        } catch (err) {
          console.error('[Bulk Queue] Failed to update video history with token ID:', err);
        }
      }

      // Start background polling for this video
      startBackgroundPolling(video.videoId, video.userId, operationName, sceneId, apiKey, rotationToken);
      
      // Exit retry loop immediately on success
      break;

    } catch (error) {
      lastError = `Error processing video: ${error instanceof Error ? error.message : String(error)}`;
      console.error(`[Bulk Queue] ❌ Attempt ${attemptNumber} - Error processing video ${video.sceneNumber}:`, error);
      
      // Check for authentication error
      const errorMessage = error instanceof Error ? error.message : String(error);
      const isAuthError = errorMessage.toLowerCase().includes('invalid authentication') ||
        errorMessage.toLowerCase().includes('oauth 2 access token') ||
        errorMessage.toLowerCase().includes('unauthorized') ||
        errorMessage.toLowerCase().includes('401');
      
      if (rotationToken) {
        if (isAuthError) {
          console.log(`[Bulk Queue] 🔴 Authentication error detected - auto-disabling token ${rotationToken.id}`);
          await storage.toggleApiTokenStatus(rotationToken.id, false);
          // Add to exclusion list for this video's retries
          disabledTokenIds.add(rotationToken.id);
          console.log(`[Bulk Queue] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
          // Clear assignedToken so retries get a different token
          if (video.assignedToken && video.assignedToken.id === rotationToken.id) {
            video.assignedToken = undefined;
            console.log(`[Bulk Queue] Cleared disabled token from video ${video.sceneNumber} assignedToken`);
          }
        } else {
          storage.recordTokenError(rotationToken.id);
        }
      }
      
      // Retry with different token after short delay
      if (attemptNumber < MAX_INSTANT_RETRIES) {
        console.log(`[Bulk Queue] ⏳ Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
        await new Promise(resolve => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
        continue;
      }
      
      // All attempts failed
      await storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
    }
  }
}

/**
 * Process the queue in the background with batch processing (user-specific)
 */
async function processQueue(userId: string, overrideDelaySeconds?: number) {
  const userQueue = getUserQueue(userId);
  
  if (userQueue.isProcessing) {
    console.log(`[Bulk Queue] User ${userId}: Already processing queue`);
    return;
  }

  userQueue.isProcessing = true;
  userQueue.processingStartedAt = Date.now();
  console.log(`[Bulk Queue] User ${userId}: Started processing queue at ${new Date().toISOString()}`);

  // Fetch batch settings from database
  let videosPerBatch = 10;
  let batchDelaySeconds = overrideDelaySeconds || 20;
  
  try {
    try {
      const settings = await storage.getTokenSettings();
      if (settings) {
        videosPerBatch = parseInt(settings.videosPerBatch, 10) || 5;
        if (!overrideDelaySeconds) {
          batchDelaySeconds = parseInt(settings.batchDelaySeconds, 10) || 20;
        }
        console.log(`[Bulk Queue] Using batch settings: ${videosPerBatch} videos per batch, ${batchDelaySeconds}s delay${overrideDelaySeconds ? ' (plan-specific)' : ''}`);
      }
    } catch (error) {
      console.error('[Bulk Queue] Error fetching batch settings, using defaults:', error);
    }

    while (userQueue.queue.length > 0) {
      // Check if stop was requested for this user
      if (userQueue.shouldStop) {
        console.log(`[Bulk Queue] User ${userId}: 🛑 Stop flag detected. Stopping queue processing.`);
        userQueue.shouldStop = false; // Reset flag
        break;
      }
      
      // Get N videos from queue for this batch
      const batchSize = Math.min(videosPerBatch, userQueue.queue.length);
      const batch: QueuedVideo[] = [];
      
      for (let i = 0; i < batchSize; i++) {
        const video = userQueue.queue.shift();
        if (video) {
          batch.push(video);
        }
      }

      if (batch.length === 0) {
        continue;
      }

      // Fetch ALL active tokens for round-robin rotation
      const activeTokens = await storage.getActiveApiTokens();
      console.log(`[Bulk Queue] 📊 Found ${activeTokens.length} active tokens available for rotation`);
      
      if (activeTokens.length === 0) {
        console.log(`[Bulk Queue] ⚠️ No active tokens available - batch will fail`);
        // Mark all videos in batch as failed
        for (const video of batch) {
          await storage.updateVideoHistoryStatus(video.videoId, video.userId, 'failed', undefined, 'No active API tokens available');
        }
        continue;
      }
      
      console.log(`[Bulk Queue] User ${userId}: 📦 Processing batch of ${batch.length} videos. Remaining in queue: ${userQueue.queue.length}`);

      // PRE-ASSIGN tokens using TRUE ROUND-ROBIN rotation (cycles through ALL tokens)
      // Atomically get current rotation index and reserve spots for this batch
      const startRotationIndex = await storage.getAndIncrementRotationIndex(batch.length, activeTokens.length);
      
      console.log(`[Bulk Queue] 🎲 Starting token assignment from rotation index ${startRotationIndex} (cycling through all ${activeTokens.length} tokens)...`);
      
      // Assign tokens using round-robin rotation
      for (let i = 0; i < batch.length; i++) {
        const video = batch[i];
        
        // Use modulo to cycle through all available tokens (1→34→1→34...)
        const tokenIndex = (startRotationIndex + i) % activeTokens.length;
        const token = activeTokens[tokenIndex];
        
        video.assignedToken = token;
        console.log(`[Bulk Queue] ✅ Video ${video.sceneNumber} → Token ${tokenIndex + 1}/${activeTokens.length}: ${token.label} (ID: ${token.id})`);
      }
      
      console.log(`[Bulk Queue] 🎯 All ${batch.length} videos assigned tokens via round-robin rotation (next batch starts at index ${(startRotationIndex + batch.length) % activeTokens.length})!`);

      // Process all videos in batch in parallel (each with its pre-assigned unique token)
      await Promise.all(batch.map(video => processSingleVideo(video)));

      console.log(`[Bulk Queue] User ${userId}: ✅ Batch of ${batch.length} videos submitted successfully`);

      // Wait for batchDelaySeconds before processing next batch
      if (userQueue.queue.length > 0) {
        console.log(`[Bulk Queue] User ${userId}: ⏸️ Waiting ${batchDelaySeconds} seconds before next batch...`);
        await new Promise(resolve => setTimeout(resolve, batchDelaySeconds * 1000));
      }
    }
  } finally {
    // ALWAYS reset processing state, even if an error occurs
    userQueue.isProcessing = false;
    userQueue.processingStartedAt = null;
    console.log(`[Bulk Queue] User ${userId}: Finished processing queue at ${new Date().toISOString()}`);
  }
}

/**
 * Start background polling for a video
 */
export async function startBackgroundPolling(
  videoId: string, 
  userId: string, 
  operationName: string, 
  sceneId: string, 
  apiKey: string,
  rotationToken: ApiToken | undefined
) {
  (async () => {
    try {
      let completed = false;
      let attempts = 0;
      const maxAttempts = 120; // 30 minutes max (120 attempts * 15 seconds = 1800 seconds)
      const retryAttempt = 16; // 4 minutes (16 * 15 seconds = 240 seconds)
      let currentOperationName = operationName;
      let currentSceneId = sceneId;
      let currentApiKey = apiKey;
      let currentRotationToken = rotationToken;
      let hasRetriedWithNewToken = false;
      let pollingRetryCount = 0; // Track polling retries separately (max 2)

      while (!completed && attempts < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, 15000));
        attempts++;

        // After 4 minutes, try with next API token if not completed
        if (attempts === retryAttempt && !completed && !hasRetriedWithNewToken) {
          console.log(`[Bulk Queue Polling] Video ${videoId} not completed after 4 minutes, trying with next API token...`);
          
          if (currentRotationToken) {
            storage.recordTokenError(currentRotationToken.id);
          }

          try {
            const nextToken = await storage.getNextRotationToken();
            
            if (nextToken && nextToken.id !== currentRotationToken?.id) {
              console.log(`[Bulk Queue Polling] Starting NEW generation with next token: ${nextToken.label}`);
              // NOTE: We keep polling the OLD operation with the OLD token (don't change currentApiKey)
              // The new generation will have its own operation that we'll poll separately
              await storage.updateTokenUsage(nextToken.id);
              
              // Start new generation with the new token
              const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
              const newSceneId = `retry-${videoId}-${Date.now()}`;
              const seed = Math.floor(Math.random() * 100000);

              const video = await storage.updateVideoHistoryStatus(videoId, userId, 'pending');
              if (!video) continue;

              const payload = {
                clientContext: {
                  projectId: veoProjectId,
                  tool: "PINHOLE",
                  userPaygateTier: "PAYGATE_TIER_TWO"
                },
                requests: [{
                  aspectRatio: video.aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                  seed: seed,
                  textInput: {
                    prompt: video.prompt
                  },
                  videoModelKey: video.aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                  metadata: {
                    sceneId: newSceneId
                  }
                }]
              };

              // Add timeout for retry request too
              const retryController = new AbortController();
              const retryTimeout = setTimeout(() => retryController.abort(), 90000);
              
              const response = await fetch('https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText', {
                method: 'POST',
                headers: {
                  'Authorization': `Bearer ${nextToken.token}`,
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
                signal: retryController.signal,
              });
              
              clearTimeout(retryTimeout);

              const data = await response.json();
              
              if (response.ok && data.operations && data.operations.length > 0) {
                const newOperation = data.operations[0].operation.name;
                console.log(`[Bulk Queue Polling] ✅ Retry successful! New operation: ${newOperation}`);
                
                // Switch to polling the NEW operation with the NEW token
                currentOperationName = newOperation;
                currentSceneId = newSceneId;
                currentApiKey = nextToken.token;
                currentRotationToken = nextToken;
                hasRetriedWithNewToken = true;
                console.log(`[Bulk Queue Polling] Now polling NEW operation ${newOperation} with token ${nextToken.label}`);
                
                await storage.updateVideoHistoryFields(videoId, { 
                  status: 'retrying',
                  tokenUsed: nextToken.id 
                });
              }
            }
          } catch (retryError) {
            console.error('[Bulk Queue Polling] Error retrying with new token:', retryError);
          }
        }

        // Check video status using proper API endpoint
        try {
          const requestBody = {
            operations: [{
              operation: {
                name: currentOperationName
              },
              sceneId: currentSceneId,
              status: "MEDIA_GENERATION_STATUS_PENDING"
            }]
          };

          // Add timeout to status check (30 seconds)
          const statusController = new AbortController();
          const statusTimeout = setTimeout(() => statusController.abort(), 30000);

          const statusResponse = await fetch('https://aisandbox-pa.googleapis.com/v1/video:batchCheckAsyncVideoGenerationStatus', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${currentApiKey}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody),
            signal: statusController.signal,
          });

          clearTimeout(statusTimeout);

          if (!statusResponse.ok) {
            console.error(`[Bulk Queue Polling] Status check failed (${statusResponse.status}) - will retry on next poll`);
            continue; // Try again on next poll
          }

          const statusData = await statusResponse.json();
          console.log(`[Bulk Queue Polling] Status for ${videoId}:`, JSON.stringify(statusData, null, 2).substring(0, 500));

          // Check operations array for status
          if (statusData.operations && statusData.operations.length > 0) {
            const operationData = statusData.operations[0];
            const operation = operationData.operation;
            const opStatus = operationData.status;
            
            console.log(`[Bulk Queue Polling] Video ${videoId} status: ${opStatus}`);
            
            // Extract video URL from nested metadata structure (matching veo3.ts)
            let veoVideoUrl: string | undefined;
            
            if (operation?.metadata?.video?.fifeUrl) {
              veoVideoUrl = operation.metadata.video.fifeUrl;
            } else if (operation?.videoUrl) {
              veoVideoUrl = operation.videoUrl;
            } else if (operation?.fileUrl) {
              veoVideoUrl = operation.fileUrl;
            } else if (operation?.downloadUrl) {
              veoVideoUrl = operation.downloadUrl;
            }
            
            // Decode HTML entities (VEO returns &amp; instead of &)
            if (veoVideoUrl) {
              veoVideoUrl = veoVideoUrl
                .replace(/&amp;/g, '&')
                .replace(/&lt;/g, '<')
                .replace(/&gt;/g, '>')
                .replace(/&quot;/g, '"')
                .replace(/&#39;/g, "'");
            }
            
            // Check if video is completed
            if (opStatus === 'MEDIA_GENERATION_STATUS_COMPLETE' || opStatus === 'MEDIA_GENERATION_STATUS_SUCCESSFUL' || opStatus === 'COMPLETED') {
              if (veoVideoUrl) {
                console.log(`[Bulk Queue Polling] Video ${videoId} completed (saving directly, no Cloudinary)`);
                
                await storage.updateVideoHistoryStatus(videoId, userId, 'completed', veoVideoUrl);
                console.log(`[Bulk Queue Polling] Video ${videoId} completed successfully`);
                completed = true;
              } else {
                console.log(`[Bulk Queue Polling] Video ${videoId} shows complete but no URL found`);
              }
            } else if (operation?.error) {
              const errorMessage = `VEO generation failed: ${operation.error.message || JSON.stringify(operation.error).substring(0, 200)}`;
              const errorCode = operation.error.code;
              const errorMsgLower = (operation.error.message || '').toLowerCase();
              
              console.error(`[Bulk Queue Polling] Video ${videoId} failed:`, operation.error);
              
              // Detect specific errors that should trigger retry
              const isHighTrafficError = errorCode === 13 || errorMsgLower.includes('high_traffic') || errorMsgLower.includes('high traffic');
              const isTimeoutError = errorCode === 4 || errorMsgLower.includes('timed_out') || errorMsgLower.includes('timeout');
              const isExpiredDeadlineError = errorMsgLower.includes('expired') || errorMsgLower.includes('deadline');
              const isUnsafeGenerationError = errorMsgLower.includes('unsafe_generation') || errorMsgLower.includes('unsafe generation');
              const isMinorError = errorMsgLower.includes('error_minor') || errorMsgLower.includes('minor error');
              const shouldRetry = isHighTrafficError || isTimeoutError || isExpiredDeadlineError || isUnsafeGenerationError || isMinorError;
              
              if (shouldRetry) {
                console.log(`[Bulk Queue Polling] 🔍 Detected retryable error for ${videoId}:`, {
                  errorCode,
                  isHighTrafficError,
                  isTimeoutError,
                  isExpiredDeadlineError,
                  isUnsafeGenerationError,
                  isMinorError,
                  retryCount: pollingRetryCount
                });
              }
              
              // Only record token error for non-retryable errors
              if (!shouldRetry && currentRotationToken) {
                storage.recordTokenError(currentRotationToken.id);
              }
              
              // RETRY with different token for specific errors (max 10 times)
              if (shouldRetry && pollingRetryCount < MAX_POLLING_RETRIES) {
                pollingRetryCount++;
                console.log(`[Bulk Queue Polling] 🔄 VEO returned failure. Retrying with different token (polling retry ${pollingRetryCount}/${MAX_POLLING_RETRIES})...`);
                
                try {
                  const newToken = await storage.getNextRotationToken();
                  if (newToken) {
                    await storage.updateTokenUsage(newToken.id);
                    const newApiKey = newToken.token;
                    currentRotationToken = newToken;
                    
                    console.log(`[Bulk Queue Polling] 🔄 Retry attempt with new token: ${newToken.label}`);
                    
                    const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
                    const newSceneId = `retry-${videoId}-${Date.now()}`;
                    const seed = Math.floor(Math.random() * 100000);
                    
                    // Fetch video history to get original prompt and aspect ratio
                    const videoHistory = await storage.getUserVideoHistory(userId);
                    const video = videoHistory.find(v => v.id === videoId);
                    
                    if (video && video.prompt) {
                      const payload = {
                        clientContext: {
                          projectId: veoProjectId,
                          tool: "PINHOLE",
                          userPaygateTier: "PAYGATE_TIER_TWO"
                        },
                        requests: [{
                          aspectRatio: video.aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                          seed: seed,
                          textInput: { prompt: video.prompt },
                          videoModelKey: video.aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                          metadata: { sceneId: newSceneId }
                        }]
                      };
                      
                      const retryController = new AbortController();
                      const retryTimeout = setTimeout(() => retryController.abort(), 90000);
                      
                      const retryResponse = await fetch('https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText', {
                        method: 'POST',
                        headers: {
                          'Authorization': `Bearer ${newApiKey}`,
                          'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(payload),
                        signal: retryController.signal,
                      });
                      
                      clearTimeout(retryTimeout);
                      const retryData = await retryResponse.json();
                      
                      if (retryResponse.ok && retryData.operations && retryData.operations.length > 0) {
                        const newOperation = retryData.operations[0].operation.name;
                        console.log(`[Bulk Queue Polling] ✅ Retry successful! New operation: ${newOperation}`);
                        
                        await storage.updateVideoHistoryFields(videoId, {
                          status: 'retrying',
                          tokenUsed: newToken.id
                        });
                        
                        // Continue polling with new operation (don't reset attempts to avoid infinite retries)
                        currentSceneId = newSceneId;
                        currentOperationName = newOperation;
                        currentApiKey = newApiKey;
                        currentRotationToken = newToken;
                        // DON'T reset attempts or pollingRetryCount - let them continue
                        continue;
                      }
                    }
                  }
                } catch (retryError) {
                  console.error('[Bulk Queue Polling] Error retrying with new token:', retryError);
                }
              }
              
              // All retries exhausted - mark as failed
              await storage.updateVideoHistoryStatus(videoId, userId, 'failed', undefined, `${errorMessage} (Failed after ${pollingRetryCount} polling retries)`);
              completed = true;
            }
          }
        } catch (pollError: any) {
          // Log network errors with more detail
          if (pollError.name === 'AbortError') {
            console.error(`[Bulk Queue Polling] Status check timeout for video ${videoId} - will retry on next poll`);
          } else if (pollError.code === 'ECONNRESET' || pollError.cause?.code === 'ECONNRESET') {
            console.error(`[Bulk Queue Polling] Network connection reset for video ${videoId} - will retry on next poll`);
          } else {
            console.error(`[Bulk Queue Polling] Error polling video ${videoId}:`, pollError);
          }
          // Continue polling - will retry on next attempt
        }
      }

      // If not completed after max attempts, mark as failed
      if (!completed) {
        const errorMessage = `Video generation timed out after ${maxAttempts * 2} seconds (${maxAttempts} attempts)`;
        console.log(`[Bulk Queue Polling] Video ${videoId} timed out after ${maxAttempts} attempts`);
        await storage.updateVideoHistoryStatus(videoId, userId, 'failed', undefined, errorMessage);
      }
    } catch (error) {
      const errorMessage = `Fatal error during video generation: ${error instanceof Error ? error.message : String(error)}`;
      console.error(`[Bulk Queue Polling] Fatal error polling video ${videoId}:`, error);
      await storage.updateVideoHistoryStatus(videoId, userId, 'failed', undefined, errorMessage);
    }
  })();
}

/**
 * Get current queue status for a specific user
 * Also checks for stuck queues and auto-resets if needed
 */
export function getQueueStatus(userId: string) {
  // Check for stuck queue and auto-reset if needed
  const wasReset = checkAndResetStuckQueue(userId);
  
  const userQueue = getUserQueue(userId);
  return {
    queueLength: userQueue.queue.length,
    isProcessing: userQueue.isProcessing,
    wasAutoReset: wasReset,
    processingStartedAt: userQueue.processingStartedAt
  };
}

/**
 * Stop bulk video processing for a specific user
 * Clears the user's queue and sets stop flag
 */
export function stopAllProcessing(userId: string) {
  const userQueue = getUserQueue(userId);
  const clearedCount = userQueue.queue.length;
  const wasProcessing = userQueue.isProcessing;
  console.log(`[Bulk Queue] User ${userId}: 🛑 STOP requested. Clearing ${clearedCount} videos from queue.`);
  
  // Clear the user's queue
  userQueue.queue.length = 0;
  
  // Set stop flag (will stop current batch after current videos finish)
  userQueue.shouldStop = true;
  
  // Force reset isProcessing flag and timestamp so user can start new batch immediately
  userQueue.isProcessing = false;
  userQueue.processingStartedAt = null;
  
  return {
    message: 'Bulk processing stopped. Queue cleared.',
    clearedVideos: clearedCount,
    wasProcessing: wasProcessing
  };
}

/**
 * Force reset a user's queue state (for admin use when queue is stuck)
 */
export function forceResetQueue(userId: string) {
  const userQueue = getUserQueue(userId);
  const previousState = {
    queueLength: userQueue.queue.length,
    isProcessing: userQueue.isProcessing,
    processingStartedAt: userQueue.processingStartedAt
  };
  
  console.log(`[Bulk Queue] User ${userId}: ⚠️ FORCE RESET requested. Previous state:`, previousState);
  
  // Force reset everything
  userQueue.queue.length = 0;
  userQueue.isProcessing = false;
  userQueue.shouldStop = true;
  userQueue.processingStartedAt = null;
  
  console.log(`[Bulk Queue] User ${userId}: ✅ Queue force reset complete`);
  
  return {
    message: 'Queue force reset complete.',
    previousState
  };
}
