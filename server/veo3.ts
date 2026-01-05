
const VEO3_BASE_URL = "https://aisandbox-pa.googleapis.com/v1/video";

interface VideoGenerationRequest {
  clientContext: {
    projectId: string;
    tool: string;
    userPaygateTier: string;
  };
  requests: Array<{
    aspectRatio: string;
    seed: number;
    textInput: {
      prompt: string;
    };
    videoModelKey: string;
    metadata: {
      sceneId: string;
    };
  }>;
}

interface VideoGenerationResponse {
  operations?: Array<{
    operation: {
      name: string;
    };
    sceneId: string;
    status: string;
  }>;
  remainingCredits?: number;
}

interface VideoStatusRequest {
  operations: Array<{
    operation: {
      name: string;
    };
    sceneId: string;
    status: string;
  }>;
}

interface VideoStatusResponse {
  operations?: Array<{
    operation: {
      error?: {
        code?: number;
        message: string;
      };
      videoUrl?: string;
      fileUrl?: string;
      downloadUrl?: string;
      metadata?: {
        video?: {
          fifeUrl?: string;
        };
      };
      [key: string]: any; // Allow for other fields
    };
    sceneId: string;
    status: string;
  }>;
  remainingCredits?: number;
}

export interface GeneratedVideo {
  sceneId: string;
  sceneNumber: number;
  operationName: string;
  status: string;
  videoUrl?: string;
  error?: string;
}

// Clean prompt by removing special characters that can cause errors
function cleanPrompt(prompt: string): string {
  // Remove special characters: " * , : ; _ -
  return prompt
    .replace(/["*,:;_-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Parse scene description to get the full prompt text
export async function checkVideoStatus(
  operationName: string,
  sceneId: string,
  apiKey: string,
  retryCount: number = 0
): Promise<{ status: string; videoUrl?: string; error?: string; errorCode?: number; remainingCredits?: number; needsTokenRetry?: boolean }> {
  const MAX_RETRIES = 3;
  
  // Trim the API key and remove "Bearer " prefix if present
  let trimmedApiKey = apiKey.trim();
  if (trimmedApiKey.startsWith('Bearer ')) {
    trimmedApiKey = trimmedApiKey.substring(7); // Remove "Bearer " prefix
  }

  const requestBody: VideoStatusRequest = {
    operations: [{
      operation: {
        name: operationName
      },
      sceneId: sceneId,
      status: "MEDIA_GENERATION_STATUS_PENDING"
    }]
  };

  // Create an AbortController for timeout handling (30 seconds)
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch(`${VEO3_BASE_URL}:batchCheckAsyncVideoGenerationStatus`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${trimmedApiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`VEO 3 status check error: ${response.status} - ${errorText}`);
    }

    // Parse JSON response (handle HTML error pages)
    const responseText = await response.text();
    let data: VideoStatusResponse;
    try {
      data = JSON.parse(responseText);
    } catch (jsonError) {
      // Check if response is HTML (rate limit or error page)
      const isHtmlError = responseText.trim().startsWith('<') || responseText.includes('<html');
      if (isHtmlError) {
        console.error(`[VEO3] API returned HTML error page instead of JSON. Token may be rate limited.`);
        console.error(`[VEO3] Raw response:`, responseText.substring(0, 500));
        throw new Error('API returned HTML error page. Token may be rate limited. Retrying with different token...');
      }
      throw new Error(`Invalid JSON response from VEO API: ${responseText.substring(0, 200)}`);
    }
    console.log(`[VEO3] Status check response:`, JSON.stringify(data, null, 2));

    if (!data.operations || data.operations.length === 0) {
      console.log(`[VEO3] No operations in status response, returning PENDING`);
      return { status: "PENDING" };
    }

  const operationData = data.operations[0];
  console.log(`[VEO3] Operation status: ${operationData.status}`);
  console.log(`[VEO3] Operation data:`, JSON.stringify(operationData.operation, null, 2));
  
  // Handle PUBLIC_ERROR_HIGH_TRAFFIC - signal for auto-retry with new token
  if (operationData.operation?.error?.message === "PUBLIC_ERROR_HIGH_TRAFFIC") {
    console.log(`[VEO3] ⚠️ PUBLIC_ERROR_HIGH_TRAFFIC detected - signaling for auto-retry with new token`);
    return { 
      status: "PENDING",
      error: operationData.operation.error.message,
      errorCode: operationData.operation.error.code,
      remainingCredits: data.remainingCredits,
      needsTokenRetry: true // Signal to trigger auto-retry with different token
    };
  }
  
  // Handle code 13 LMRoot/Gemini model errors - signal for auto-retry with new token
  const errorMessage = operationData.operation?.error?.message || '';
  const errorCode = operationData.operation?.error?.code;
  if (errorCode === 13 || errorMessage.includes('LMRoot') || errorMessage.includes('Gemini model')) {
    console.log(`[VEO3] ⚠️ LMRoot/Gemini error detected (code: ${errorCode}) - signaling for auto-retry with new token`);
    return { 
      status: "PENDING",
      error: errorMessage,
      errorCode: errorCode,
      remainingCredits: data.remainingCredits,
      needsTokenRetry: true // Signal to trigger auto-retry with different token
    };
  }
  
  // Handle PUBLIC_ERROR_UNSAFE_GENERATION - treat as PENDING to allow retry (max 5 attempts)
  if (operationData.operation?.error?.message === "PUBLIC_ERROR_UNSAFE_GENERATION") {
    // Check if we've exceeded max retry attempts
    if (retryCount >= 5) {
      console.log(`[VEO3] ❌ PUBLIC_ERROR_UNSAFE_GENERATION - Max retry attempts (5) reached, marking as FAILED`);
      return {
        status: "MEDIA_GENERATION_STATUS_FAILED",
        error: "Content Policy Violation: Your image or prompt contains content that violates our safety guidelines. This may include adult/suggestive content, violence, or other prohibited material. Please use a different image or modify your prompt and try again.",
        errorCode: operationData.operation.error.code,
        remainingCredits: data.remainingCredits
      };
    }
    
    console.log(`[VEO3] ⚠️ PUBLIC_ERROR_UNSAFE_GENERATION detected (attempt ${retryCount + 1}/5) - returning PENDING status to allow retry`);
    return { 
      status: "PENDING",
      error: operationData.operation.error.message,
      errorCode: operationData.operation.error.code,
      remainingCredits: data.remainingCredits
    };
  }
  
  // Handle PUBLIC_ERROR_MINOR - treat as PENDING to allow retry (max 20 attempts)
  if (operationData.operation?.error?.message === "PUBLIC_ERROR_MINOR") {
    // Check if we've exceeded max retry attempts
    if (retryCount >= 20) {
      console.log(`[VEO3] ❌ PUBLIC_ERROR_MINOR - Max retry attempts (20) reached, marking as FAILED`);
      return {
        status: "MEDIA_GENERATION_STATUS_FAILED",
        error: "Child Safety Policy: Your image appears to contain a minor (person under 18). For child safety protection, video generation with images of minors is not permitted. Please use an image of an adult instead.",
        errorCode: operationData.operation.error.code,
        remainingCredits: data.remainingCredits
      };
    }
    
    console.log(`[VEO3] ⚠️ PUBLIC_ERROR_MINOR detected (attempt ${retryCount + 1}/20) - returning PENDING status to allow retry`);
    return { 
      status: "PENDING",
      error: operationData.operation.error.message,
      errorCode: operationData.operation.error.code,
      remainingCredits: data.remainingCredits
    };
  }
  
  // Extract video URL from the nested metadata structure
  let videoUrl: string | undefined;
  
  // Try to get from metadata.video.fifeUrl (the actual location)
  if (operationData.operation?.metadata?.video?.fifeUrl) {
    videoUrl = operationData.operation.metadata.video.fifeUrl;
  }
  // Fallback to other possible locations
  else if ((operationData.operation as any).videoUrl) {
    videoUrl = (operationData.operation as any).videoUrl;
  }
  else if ((operationData.operation as any).fileUrl) {
    videoUrl = (operationData.operation as any).fileUrl;
  }
  else if ((operationData.operation as any).downloadUrl) {
    videoUrl = (operationData.operation as any).downloadUrl;
  }
  
  // Decode HTML entities in the URL (VEO 3 returns &amp; instead of &)
  if (videoUrl) {
    const originalUrl = videoUrl;
    // Use a comprehensive HTML entity decoder
    videoUrl = videoUrl
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    
    console.log(`[VEO3] Found video URL`);
    console.log(`[VEO3] Original length: ${originalUrl.length}, Decoded length: ${videoUrl.length}`);
    console.log(`[VEO3] URL starts with: ${videoUrl.substring(0, 100)}`);
    console.log(`[VEO3] Has &: ${videoUrl.includes('&')}, Has &amp;: ${videoUrl.includes('&amp;')}`);
  } else {
    console.log(`[VEO3] No video URL found in response`);
  }
  
    return {
      status: operationData.status,
      videoUrl: videoUrl,
      error: operationData.operation.error?.message,
      errorCode: operationData.operation.error?.code,
      remainingCredits: data.remainingCredits
    };
  } catch (error: any) {
    clearTimeout(timeoutId);
    
    // Handle timeout specifically with retry logic
    if (error.name === 'AbortError') {
      if (retryCount < MAX_RETRIES) {
        const waitTime = Math.pow(2, retryCount) * 1000; // Exponential backoff: 1s, 2s, 4s
        console.log(`[VEO3] Status check timeout for ${sceneId}, retrying in ${waitTime}ms (attempt ${retryCount + 1}/${MAX_RETRIES})`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
        return checkVideoStatus(operationName, sceneId, apiKey, retryCount + 1);
      } else {
        console.error(`[VEO3] Status check timeout after ${MAX_RETRIES} retries for ${sceneId}`);
        // Return PENDING status instead of throwing to allow polling to continue
        return { status: "PENDING" };
      }
    }
    
    throw error;
  }
}

// Poll for video completion with timeout
export async function waitForVideoCompletion(
  operationName: string,
  sceneId: string,
  apiKey: string,
  maxWaitTime: number = 300000 // 5 minutes default
): Promise<{ videoUrl: string }> {
  const startTime = Date.now();
  const pollInterval = 15000; // Check every 15 seconds
  const initialDelay = 15000; // Wait 15 seconds before first check

  // Wait initially to give the API time to process
  console.log(`[VEO3] Waiting ${initialDelay/1000}s before first status check for ${sceneId}`);
  await new Promise(resolve => setTimeout(resolve, initialDelay));

  while (Date.now() - startTime < maxWaitTime) {
    const status = await checkVideoStatus(operationName, sceneId, apiKey);

    console.log(`[VEO3] Polling status for ${sceneId}: ${status.status}`);

    if (status.status === "COMPLETED" || status.status === "MEDIA_GENERATION_STATUS_COMPLETE" || status.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
      if (status.videoUrl) {
        console.log(`[VEO3] Video completed successfully with URL: ${status.videoUrl}`);
        return { videoUrl: status.videoUrl };
      }
      throw new Error("Video completed but no URL provided");
    }

    if (status.status === "FAILED" || status.status === "MEDIA_GENERATION_STATUS_FAILED") {
      throw new Error(`Video generation failed: ${status.error || "Unknown error"}`);
    }

    // Wait before next poll
    await new Promise(resolve => setTimeout(resolve, pollInterval));
  }

  throw new Error("Video generation timed out");
}

// Poll for video completion with timeout and status updates callback
export async function waitForVideoCompletionWithUpdates(
  operationName: string,
  sceneId: string,
  apiKey: string,
  onStatusUpdate?: (message: string) => void,
  maxWaitTime: number = 300000 // 5 minutes default
): Promise<{ videoUrl: string }> {
  const startTime = Date.now();
  const pollInterval = 15000; // Check every 15 seconds
  const initialDelay = 15000; // Wait 15 seconds before first check

  // Wait initially to give the API time to process
  console.log(`[VEO3] Waiting ${initialDelay/1000}s before first status check for ${sceneId}`);
  if (onStatusUpdate) {
    onStatusUpdate('Waiting for VEO to start processing...');
  }
  await new Promise(resolve => setTimeout(resolve, initialDelay));

  let pollCount = 0;
  while (Date.now() - startTime < maxWaitTime) {
    pollCount++;
    const elapsedSeconds = Math.floor((Date.now() - startTime) / 1000);
    
    const status = await checkVideoStatus(operationName, sceneId, apiKey);

    console.log(`[VEO3] Polling status for ${sceneId}: ${status.status}`);

    // Send status update every poll to show activity
    if (onStatusUpdate) {
      onStatusUpdate(`Still generating... (${elapsedSeconds}s elapsed)`);
    }

    if (status.status === "COMPLETED" || status.status === "MEDIA_GENERATION_STATUS_COMPLETE" || status.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
      if (status.videoUrl) {
        console.log(`[VEO3] Video completed successfully with URL: ${status.videoUrl}`);
        if (onStatusUpdate) {
          onStatusUpdate('Video generation complete!');
        }
        return { videoUrl: status.videoUrl };
      }
      throw new Error("Video completed but no URL provided");
    }

    if (status.status === "FAILED" || status.status === "MEDIA_GENERATION_STATUS_FAILED") {
      throw new Error(`Video generation failed: ${status.error || "Unknown error"}`);
    }

    // Wait before next poll
    await new Promise(resolve => setTimeout(resolve, pollInterval));
  }

  throw new Error("Video generation timed out");
}
