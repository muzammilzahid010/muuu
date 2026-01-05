/**
 * Background Video Generation System using Whisk API
 * Flow: Generate Image -> Generate Video from Image -> Poll Status
 */

import { storage } from './storage';
import crypto from 'crypto';
import { uploadBase64VideoWithFallback } from './cloudinary';

// NO IN-MEMORY CACHE - All videos go directly to Cloudinary
// These stub functions exist only for backward compatibility with routes.ts

export function getVideoBuffer(videoId: string): Buffer | null {
  // No memory storage - always return null
  return null;
}

export function deleteVideoBuffer(videoId: string): void {
  // No memory storage - nothing to delete
}

export function getVideoCacheStats() {
  // No cache - always empty
  return { count: 0, sizeBytes: 0, sizeMB: 0, sizeGB: 0 };
}

interface BackgroundJob {
  videoId: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  videoUrl?: string;
  videoData?: string; // Direct base64 data (no cloud upload)
  error?: string;
  startedAt: number;
  stage?: 'image_generation' | 'video_generation' | 'status_polling';
}

const activeJobs = new Map<string, BackgroundJob>();

const WHISK_BASE_URL = "https://aisandbox-pa.googleapis.com/v1";

interface WhiskImageResponse {
  imagePanels?: Array<{
    prompt: string;
    generatedImages: Array<{
      encodedImage: string;
      mediaGenerationId: string;
      seed: number;
      prompt: string;
      imageModel: string;
      workflowId: string;
      aspectRatio: string;
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

interface EncodedVideoObject {
  rawBytes?: string;
  uri?: string;
  mimeType?: string;
}

interface VideoStatusResponse {
  operations?: Array<{
    // Direct fields (actual Whisk API structure)
    status?: string;
    [key: string]: any; // base64 data can be in various keys directly
    // Nested structure (fallback)
    operation?: {
      done?: boolean;
      error?: {
        code?: number;
        message?: string;
      };
      response?: {
        videoResult?: {
          video?: {
            encodedVideo?: string | EncodedVideoObject;
            uri?: string;
            rawBytes?: string;
          };
        };
        generatedVideo?: Array<{
          encodedVideo?: string | EncodedVideoObject;
          videoUrl?: string;
          rawBytes?: string;
        }> | {
          encodedVideo?: string | EncodedVideoObject;
          videoUrl?: string;
          rawBytes?: string;
        };
        rawBytes?: string;
      };
      metadata?: any;
    };
    rawBytes?: string;
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
  
  const imageAspectRatio = aspectRatio === 'portrait' 
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

  console.log(`[Whisk Image] Generating image for prompt: "${prompt.substring(0, 50)}..."`);
  
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
    console.error(`[Whisk Image] API error ${response.status}:`, errorText);
    throw new Error(`Image generation failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }

  const data: WhiskImageResponse = await response.json();
  
  if (!data.imagePanels || data.imagePanels.length === 0 || 
      !data.imagePanels[0].generatedImages || data.imagePanels[0].generatedImages.length === 0) {
    throw new Error('No image generated from Whisk API');
  }

  const generatedImage = data.imagePanels[0].generatedImages[0];
  console.log(`[Whisk Image] Image generated successfully. MediaGenerationId: ${generatedImage.mediaGenerationId}`);

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

  console.log(`[Whisk Video] Starting video generation...`);
  
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
    console.error(`[Whisk Video] API error ${response.status}:`, errorText);
    throw new Error(`Video generation start failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }

  const data: WhiskVideoResponse = await response.json();
  
  if (!data.operation?.operation?.name) {
    console.error(`[Whisk Video] Unexpected response:`, JSON.stringify(data));
    throw new Error('No operation name returned from video generation');
  }

  const operationName = data.operation.operation.name;
  console.log(`[Whisk Video] Video generation started. Operation: ${operationName}`);

  return operationName;
}

async function checkWhiskVideoStatus(
  apiKey: string,
  operationName: string,
  videoId?: string,
  directToUser: boolean = false
): Promise<{ done: boolean; videoUrl?: string; videoData?: string; error?: string }> {
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
    const errorText = await response.text();
    console.error(`[Whisk Status] API error ${response.status}:`, errorText);
    throw new Error(`Status check failed: ${response.status}`);
  }

  const data: VideoStatusResponse = await response.json();
  
  // Log response structure (truncate base64 for readability)
  const logData = JSON.stringify(data, (key, value) => {
    if (typeof value === 'string' && value.length > 100) {
      return value.substring(0, 50) + `...[${value.length} chars]...` + value.substring(value.length - 50);
    }
    return value;
  }, 2);
  console.log(`[Whisk Status] Poll response:`, logData);
  
  if (!data.operations || data.operations.length === 0) {
    return { done: false };
  }

  const operationData = data.operations[0];
  const nestedOperation = operationData.operation;
  
  // Check for error in nested structure
  if (nestedOperation?.error) {
    return { 
      done: true, 
      error: nestedOperation.error.message || 'Video generation failed' 
    };
  }

  // Helper to extract rawBytes from encodedVideo (can be string or object)
  const extractRawBytes = (encodedVideo: string | EncodedVideoObject | undefined): string | undefined => {
    if (!encodedVideo) return undefined;
    if (typeof encodedVideo === 'string') return encodedVideo;
    if (typeof encodedVideo === 'object' && encodedVideo.rawBytes) return encodedVideo.rawBytes;
    return undefined;
  };

  // Check if video generation is done using EITHER:
  // 1. Direct status field: status === "MEDIA_GENERATION_STATUS_SUCCESSFUL"
  // 2. Nested operation.done === true
  const isSuccessful = 
    operationData.status === 'MEDIA_GENERATION_STATUS_SUCCESSFUL' ||
    nestedOperation?.done === true;

  if (isSuccessful) {
    let videoUrl: string | undefined;
    let base64Video: string | undefined;
    
    // FIRST: Check for base64 data directly in operationData (actual Whisk API structure)
    // Look for any long base64-looking string in the direct fields
    for (const [key, value] of Object.entries(operationData)) {
      if (key !== 'status' && key !== 'operation' && typeof value === 'string' && value.length > 1000) {
        // This is likely the base64 video data
        console.log(`[Whisk Status] Found base64 data in direct field "${key}" (${value.length} chars)`);
        base64Video = value;
        break;
      }
    }
    
    // SECOND: Check nested structure (fallback for different API versions)
    if (!base64Video && nestedOperation) {
      // Check for URL first
      if (nestedOperation.response?.videoResult?.video?.uri) {
        videoUrl = nestedOperation.response.videoResult.video.uri;
      }
      
      // Check for rawBytes in nested locations
      if (!videoUrl) {
        // 1. Check generatedVideo array format
        const generatedVideo = nestedOperation.response?.generatedVideo;
        if (Array.isArray(generatedVideo) && generatedVideo.length > 0) {
          const firstVideo = generatedVideo[0];
          base64Video = extractRawBytes(firstVideo.encodedVideo) || firstVideo.rawBytes;
          if (!videoUrl && firstVideo.videoUrl) {
            videoUrl = firstVideo.videoUrl;
          }
          console.log(`[Whisk Status] Found rawBytes in generatedVideo array: ${base64Video ? 'yes' : 'no'}`);
        }
        // 2. Check generatedVideo object format
        else if (generatedVideo && typeof generatedVideo === 'object' && !Array.isArray(generatedVideo)) {
          base64Video = extractRawBytes(generatedVideo.encodedVideo) || generatedVideo.rawBytes;
          if (!videoUrl && generatedVideo.videoUrl) {
            videoUrl = generatedVideo.videoUrl;
          }
          console.log(`[Whisk Status] Found rawBytes in generatedVideo object: ${base64Video ? 'yes' : 'no'}`);
        }
        
        // 3. Check videoResult.video
        if (!base64Video) {
          const video = nestedOperation.response?.videoResult?.video;
          if (video) {
            base64Video = extractRawBytes(video.encodedVideo) || video.rawBytes;
            console.log(`[Whisk Status] Found rawBytes in videoResult: ${base64Video ? 'yes' : 'no'}`);
          }
        }
        
        // 4. Check top-level rawBytes
        if (!base64Video) {
          base64Video = 
            nestedOperation.response?.rawBytes ||
            operationData.rawBytes ||
            data.rawBytes;
          if (base64Video) {
            console.log(`[Whisk Status] Found rawBytes at top level`);
          }
        }
      }
    }
    
    if (base64Video) {
      // Direct to user mode - return base64 directly, no upload
      if (directToUser) {
        console.log(`[Whisk Status] Direct to user mode - returning raw base64 (${(base64Video.length / 1024 / 1024).toFixed(2)}MB)`);
        return { done: true, videoData: base64Video };
      }
      
      // Upload to Cloudinary with Google Drive fallback, then memory
      try {
        const uploadResult = await uploadBase64VideoWithFallback(base64Video, videoId);
        videoUrl = uploadResult.url;
        if (uploadResult.storedInMemory) {
          console.log(`[Whisk Status] Video stored in MEMORY cache (cloud uploads failed)`);
        } else {
          console.log(`[Whisk Status] Video uploaded: ${videoUrl?.slice(0, 60)}...`);
        }
      } catch (uploadError) {
        console.log(`[Whisk Status] All upload methods FAILED: ${uploadError}`);
        throw new Error(`Upload failed: ${uploadError}`);
      }
    }

    if (videoUrl) {
      return { done: true, videoUrl };
    }
    
    // Log all keys in operationData to help debug
    console.log(`[Whisk Status] Operation successful but no video found. Keys in operationData:`, Object.keys(operationData));
    return { done: true, error: 'Video completed but no URL found' };
  }

  return { done: false };
}

export async function startBackgroundVideoGeneration(
  videoId: string,
  prompt: string,
  aspectRatio: string,
  _sessionCookie?: string,
  _cookieId?: string,
  userId?: string
): Promise<void> {
  activeJobs.set(videoId, {
    videoId,
    status: 'processing',
    startedAt: Date.now(),
    stage: 'image_generation'
  });

  (async () => {
    let tokenId: string | undefined;
    
    try {
      console.log(`[BackgroundGen] Starting video ${videoId} - "${prompt.substring(0, 50)}..."`);
      
      // Check if direct_to_user mode
      const appSettings = await storage.getAppSettings();
      const directToUser = appSettings?.storageMethod === 'direct_to_user';
      if (directToUser) {
        console.log(`[BackgroundGen] Direct to user mode - video will not be stored in database`);
      }
      
      if (userId && !directToUser) {
        await storage.updateVideoHistoryStatus(videoId, userId, 'processing');
      }

      const token = await storage.getNextRotationToken();
      if (!token) {
        throw new Error('No active API tokens available');
      }
      
      tokenId = token.id;
      const apiKey = token.token;
      console.log(`[BackgroundGen] Using token: ${token.label}`);
      await storage.updateTokenUsage(token.id);

      activeJobs.set(videoId, {
        videoId,
        status: 'processing',
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now(),
        stage: 'image_generation'
      });

      const imageResult = await generateWhiskImage(apiKey, prompt, aspectRatio);
      console.log(`[BackgroundGen] Image generated for video ${videoId}`);

      activeJobs.set(videoId, {
        videoId,
        status: 'processing',
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now(),
        stage: 'video_generation'
      });

      const operationName = await startWhiskVideoGeneration(
        apiKey,
        prompt,
        imageResult.encodedImage,
        imageResult.mediaGenerationId,
        imageResult.workflowId
      );

      activeJobs.set(videoId, {
        videoId,
        status: 'processing',
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now(),
        stage: 'status_polling'
      });

      const maxPolls = 60;
      const pollInterval = 10000;
      let pollCount = 0;

      while (pollCount < maxPolls) {
        pollCount++;
        console.log(`[BackgroundGen] Video ${videoId} - Poll ${pollCount}/${maxPolls}`);
        
        const status = await checkWhiskVideoStatus(apiKey, operationName, videoId, directToUser);
        
        if (status.done) {
          // Direct to user mode - store base64 in memory, don't save to database
          if (directToUser && status.videoData) {
            console.log(`[BackgroundGen] Video ${videoId} completed! (direct to user - no database storage)`);
            
            activeJobs.set(videoId, {
              videoId,
              status: 'completed',
              videoData: status.videoData, // Raw base64 for direct delivery
              startedAt: activeJobs.get(videoId)?.startedAt || Date.now()
            });

            // Only increment counters, don't store URL in database
            if (userId) {
              await storage.incrementDailyVideoCount(userId);
              await storage.incrementTotalVideosGenerated();
            }
            return;
          }
          
          // Cloud storage mode - store URL in database
          if (status.videoUrl) {
            console.log(`[BackgroundGen] Video ${videoId} completed!`);
            
            activeJobs.set(videoId, {
              videoId,
              status: 'completed',
              videoUrl: status.videoUrl,
              startedAt: activeJobs.get(videoId)?.startedAt || Date.now()
            });

            if (userId) {
              await storage.updateVideoHistoryStatus(videoId, userId, 'completed', status.videoUrl);
              await storage.incrementDailyVideoCount(userId);
              await storage.incrementTotalVideosGenerated();
            }
            return;
          } else {
            throw new Error(status.error || 'Video generation failed');
          }
        }

        await new Promise(resolve => setTimeout(resolve, pollInterval));
      }

      throw new Error('Video generation timed out after 10 minutes');

    } catch (error: any) {
      const errorMsg = error?.message || 'Unknown error';
      console.error(`[BackgroundGen] Video ${videoId} error: ${errorMsg}`);
      
      activeJobs.set(videoId, {
        videoId,
        status: 'failed',
        error: errorMsg,
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now()
      });

      if (userId) {
        await storage.updateVideoHistoryStatus(videoId, userId, 'failed', undefined, errorMsg);
      }
      
      if (tokenId) {
        storage.recordTokenError(tokenId);
      }
    }

    setTimeout(() => {
      activeJobs.delete(videoId);
    }, 10 * 60 * 1000);
  })();
}

export function getJobStatus(videoId: string): BackgroundJob | null {
  return activeJobs.get(videoId) || null;
}

export function getActiveJobsCount(): number {
  return activeJobs.size;
}
