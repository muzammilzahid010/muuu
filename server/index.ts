import express, { type Request, Response, NextFunction } from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import compression from "compression";
import { pool } from "./db";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import crypto from "crypto";

// Prevent uncaught exceptions from crashing the server
process.on('uncaughtException', (error) => {
  console.error('[CRITICAL] Uncaught Exception (server still running):', error.message);
  if (error.stack) {
    console.error('[CRITICAL] Stack:', error.stack);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[CRITICAL] Unhandled Rejection at:', promise);
  console.error('[CRITICAL] Reason:', reason);
});

const app = express();

// ==================== SECURITY CONFIGURATION ====================

// Generate secure session secret if not provided (for production, set SESSION_SECRET env var)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('[SECURITY] WARNING: Using auto-generated session secret. Set SESSION_SECRET env var for production!');
}

// Health check endpoint - responds before any middleware for instant response
// Replit autoscale checks "/" for health, so we need this to respond fast
app.use((req, res, next) => {
  if (req.path === '/health' || (req.path === '/' && req.headers['user-agent']?.includes('kube-probe'))) {
    return res.status(200).send('OK');
  }
  next();
});

// Security Headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://www.gstatic.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "blob:", "https:", "http:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https:", "wss:"],
      mediaSrc: ["'self'", "https:", "blob:"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

// Enable Gzip compression for all responses (reduces bandwidth by 70-90%)
app.use(compression({
  level: 6, // Balanced compression (1-9, higher = more compression but slower)
  threshold: 1024, // Only compress responses > 1KB
  filter: (req, res) => {
    // Don't compress video streams - they're already optimized
    if (req.path.includes('/local-video/') || req.path.includes('/stream-video/')) {
      return false;
    }
    // Don't compress SSE streams - they need instant delivery
    if (req.path.includes('/stream') || req.headers.accept === 'text/event-stream') {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Global Rate Limiting - 1000 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per window
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path.startsWith('/assets'),
});
app.use(globalLimiter);

// Strict Rate Limiting for Login - 5 attempts per 15 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 login attempts per window
  message: { error: 'Too many login attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful logins
});
app.use('/api/login', loginLimiter);

// Rate Limiting for Admin routes - 100 requests per minute
const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  message: { error: 'Too many admin requests, please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/admin', adminLimiter);

// Rate Limiting for Video Generation - 30 requests per minute per IP
const generationLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: { error: 'Too many generation requests. Please wait before generating more.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/generate', generationLimiter);
app.use('/api/text-to-image', generationLimiter);
app.use('/api/text-to-speech', generationLimiter);
app.use('/api/image-to-video', generationLimiter);

// ==================== END SECURITY CONFIGURATION ====================

declare module 'http' {
  interface IncomingMessage {
    rawBody: unknown
  }
}

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    resellerId?: string;
    isReseller?: boolean;
    pending2FASetup?: {
      userId: string;
      secret: string;
    };
  }
}

const PgStore = connectPgSimple(session);

app.set('trust proxy', 1);

app.use(express.json({
  limit: '50mb',
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ limit: '50mb', extended: false }));

// Production mode detection
const isProduction = process.env.NODE_ENV === 'production';

app.use(
  session({
    secret: SESSION_SECRET,
    name: isProduction ? '__Host-session' : 'session', // Secure prefix only in production (requires HTTPS)
    resave: false,
    saveUninitialized: false,
    store: new PgStore({
      pool: pool,
      tableName: 'user_sessions',
      createTableIfMissing: true,
      ttl: 24 * 60 * 60, // 1 day session TTL (reduced from 7 days for security)
      pruneSessionInterval: 300, // Clean expired sessions every 5 minutes (reduced frequency for VPS DB stability)
      errorLog: (error: Error) => {
        // Log but don't crash on session store errors
        console.error('[Session Store] Error (non-fatal):', error.message);
      },
    }),
    rolling: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 1 day (reduced from 7 days)
      httpOnly: true, // Prevents JavaScript access to cookie
      secure: isProduction, // HTTPS only in production
      sameSite: isProduction ? 'strict' : 'lax', // Strict in production, lax in development
      path: '/',
    },
  })
);

console.log(`[Security] Session configured - Production mode: ${isProduction}`);

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Initialize database, default admin user, and token settings
  const { storage } = await import("./storage");
  await storage.initializeDefaultAdmin();
  await storage.initializeTokenSettings();
  await storage.initializeAutoRetrySettings();
  await storage.initializePlanAvailability();
  await storage.initializeAppSettings();
  await storage.initializeToolMaintenance();
  
  // Initialize local disk storage for VPS hosting (3-hour video expiry)
  try {
    const { initLocalDiskStorage } = await import('./localDiskStorage');
    await initLocalDiskStorage();
    console.log('[LocalDisk] Local disk storage initialized');
  } catch (localDiskError) {
    console.error('[LocalDisk] Failed to initialize local disk storage:', localDiskError);
  }
  
  // Browser pool removed - now using Whisk API for video generation
  
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    // Log the error for debugging but DON'T crash the server
    console.error(`[Error Handler] ${status}: ${message}`);
    if (err.stack && process.env.NODE_ENV !== 'production') {
      console.error(`[Error Stack] ${err.stack}`);
    }

    res.status(status).json({ message });
    // NOTE: Removed 'throw err' - that was crashing the server on every error!
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Daily cleanup job - runs at midnight Pakistan time (UTC+5)
  // Initialize to empty string so cleanup runs on first midnight after server start
  let lastCleanupDate = '';
  
  const checkAndCleanupHistory = async () => {
    try {
      const now = new Date();
      const pktTime = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Karachi' }));
      const currentDate = pktTime.toLocaleDateString('en-US', { timeZone: 'Asia/Karachi' });
      const currentHour = pktTime.getHours();
      const currentMinute = pktTime.getMinutes();
      
      // Check if it's midnight (00:00-00:01) and we haven't run cleanup today
      if (currentHour === 0 && currentMinute === 0 && currentDate !== lastCleanupDate) {
        console.log(`[Daily Cleanup] Running cleanup tasks at midnight PKT (${currentDate})`);
        
        // Auto-increment total videos generated by 20,000 daily
        const newTotal = await storage.incrementTotalVideosGeneratedBy(20000);
        console.log(`[Daily Cleanup] Total videos counter incremented by 20,000. New total: ${newTotal}`);
        
        // Reset daily video counts for all users
        await storage.checkAndResetDailyCounts();
        console.log('[Daily Cleanup] Daily video counts reset successfully');
        
        // Cleanup video history
        await storage.clearAllVideoHistory();
        console.log('[Daily Cleanup] Video history cleared successfully');
        
        // Cleanup expired temporary videos
        try {
          const { ObjectStorageService } = await import('./objectStorage');
          const objectStorageService = new ObjectStorageService();
          const deletedCount = await objectStorageService.cleanupExpiredVideos();
          console.log(`[Daily Cleanup] Deleted ${deletedCount} expired temporary videos`);
        } catch (tempVideoError) {
          console.error('[Daily Cleanup] Error cleaning up temporary videos:', tempVideoError);
        }
        
        lastCleanupDate = currentDate;
        console.log('[Daily Cleanup] All cleanup tasks completed');
      }
    } catch (error) {
      console.error('[Daily Cleanup] Error during cleanup:', error);
    }
  };
  
  // Also run temporary video cleanup every hour (independent of midnight cleanup)
  const checkAndCleanupTempVideos = async () => {
    try {
      const { ObjectStorageService } = await import('./objectStorage');
      const objectStorageService = new ObjectStorageService();
      const deletedCount = await objectStorageService.cleanupExpiredVideos();
      if (deletedCount > 0) {
        console.log(`[Hourly Cleanup] Deleted ${deletedCount} expired temporary videos`);
      }
    } catch (error) {
      console.error('[Hourly Cleanup] Error cleaning up temporary videos:', error);
    }
  };
  
  // Run daily cleanup check every minute
  setInterval(checkAndCleanupHistory, 60000);
  console.log('[Daily Cleanup] History cleanup job scheduled for midnight PKT');
  
  // Run temporary video cleanup every hour
  setInterval(checkAndCleanupTempVideos, 60 * 60 * 1000);
  console.log('[Hourly Cleanup] Temporary video cleanup scheduled (runs every hour)');

  // Log file cleanup - delete logs older than 1 day
  const cleanupOldLogs = async () => {
    try {
      const fs = await import('fs');
      const path = await import('path');
      const logDir = '/tmp/logs';
      
      if (!fs.existsSync(logDir)) return;
      
      const files = fs.readdirSync(logDir);
      const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
      let deletedCount = 0;
      
      for (const file of files) {
        const filePath = path.join(logDir, file);
        try {
          const stats = fs.statSync(filePath);
          if (stats.mtime.getTime() < oneDayAgo) {
            fs.unlinkSync(filePath);
            deletedCount++;
          }
        } catch (e) {
          // Skip files that can't be accessed
        }
      }
      
      if (deletedCount > 0) {
        console.log(`[Log Cleanup] Deleted ${deletedCount} log files older than 1 day`);
      }
    } catch (error) {
      console.error('[Log Cleanup] Error:', error);
    }
  };

  // Run log cleanup every 20 minutes
  setInterval(cleanupOldLogs, 20 * 60 * 1000);
  // Also run once on startup
  cleanupOldLogs();
  console.log('[Log Cleanup] Old log file cleanup scheduled (runs every 20 minutes)');

  // Timeout cleanup for stuck pending videos with auto-retry
  const checkAndTimeoutPendingVideos = async () => {
    // Helper for retry with exponential backoff
    const retryDbOp = async <T>(fn: () => Promise<T>, maxRetries = 3): Promise<T | null> => {
      for (let i = 0; i < maxRetries; i++) {
        try {
          return await fn();
        } catch (e) {
          if (i === maxRetries - 1) throw e;
          await new Promise(r => setTimeout(r, 1000 * Math.pow(2, i)));
        }
      }
      return null;
    };

    try {
      const { db } = await import('./db');
      const { videoHistory } = await import('@shared/schema');
      const { sql } = await import('drizzle-orm');
      
      // FIRST: Hard timeout - mark any video stuck for 30+ minutes as failed (with retry)
      const timedOutVideos = await retryDbOp(() => db.execute(sql`
        UPDATE video_history 
        SET status = 'failed',
            error_message = 'Timeout - no response after 30 minutes',
            updated_at = NOW()
        WHERE status IN ('pending', 'retrying', 'processing')
        AND (NOW() - updated_at::timestamp) > INTERVAL '30 minutes'
        RETURNING id
      `));
      
      if (timedOutVideos && timedOutVideos.rows && timedOutVideos.rows.length > 0) {
        console.log(`[Timeout Cleanup] Marked ${timedOutVideos.rows.length} videos as failed (30 min timeout)`);
      }
      
      // Get stuck videos (pending > 30 minutes) - with retry
      const stuckVideos = await retryDbOp(() => db.execute(sql`
        SELECT id, retry_count, prompt, aspect_ratio, user_id, error_message, 
               operation_name, scene_id, token_used, reference_image_url
        FROM video_history 
        WHERE status = 'pending' 
        AND (NOW() - updated_at::timestamp) > INTERVAL '30 minutes'
      `));
      
      if (!stuckVideos || !stuckVideos.rows || stuckVideos.rows.length === 0) {
        return;
      }
      
      // DISABLED: Silent Retry system uses old VEO API tokens which are no longer available
      // Flow cookies system handles retries through bulkQueueFlow.ts instead
      // Just mark stuck videos as failed
      console.log(`[Timeout Cleanup] Found ${stuckVideos.rows.length} stuck videos - marking as failed`);
      
      for (const video of stuckVideos.rows) {
        // Use retryDbOp for each update (with try-catch to continue if one fails)
        try {
          await retryDbOp(() => db.execute(sql`
            UPDATE video_history 
            SET status = 'failed',
                error_message = 'Timeout - stuck in pending state',
                updated_at = NOW()
            WHERE id = ${video.id}
          `));
        } catch (e) {
          console.error(`[Timeout Cleanup] Failed to update video ${video.id}:`, e);
        }
      }
      
      // OLD Silent Retry code disabled - keeping for reference
      /*
      for (const video of stuckVideos.rows) {
        const retryCount = Number(video.retry_count || 0);
        const errorMessage = String(video.error_message || '');
        
        const maxRetries = errorMessage.includes('UNSAFE_GENERATION') ? 5 : 20;
        
        if (retryCount < maxRetries) {
          console.log(`[Silent Retry] Video ${video.id} - Attempt ${retryCount + 1}/${maxRetries}`);
          
          await db.execute(sql`
            UPDATE video_history 
            SET retry_count = ${retryCount + 1},
                status = 'retrying',
                updated_at = NOW()
            WHERE id = ${video.id}
          `);
          
          (async () => {
            try {
              const { storage } = await import('./storage');
              const rotationToken = await storage.getNextRotationToken();
              
              if (!rotationToken) {
                console.error(`[Silent Retry] No token available for video ${video.id}`);
                return;
              }
              
              // CRITICAL: Update token usage to rotate to next token
              await storage.updateTokenUsage(rotationToken.id);
              
              const referenceImageUrl = video.reference_image_url ? String(video.reference_image_url) : null;
              const isCharacterVideo = !!referenceImageUrl;
              
              console.log(`[Silent Retry] Regenerating video ${video.id} with token ${rotationToken.label}${isCharacterVideo ? ' (CHARACTER VIDEO - same token for mediaId + video)' : ''}`);
              
              // Import VEO generation functions
              const { checkVideoStatus } = await import('./veo3');
              
              const apiKey = rotationToken.token;
              const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
              const sceneId = `silent-retry-${video.id}-${Date.now()}`;
              const seed = Math.floor(Math.random() * 100000);
              const aspectRatio = video.aspect_ratio || 'landscape';
              
              let payload: any;
              let apiUrl: string;
              
              if (isCharacterVideo) {
                // CHARACTER VIDEO: Same token for BOTH mediaId upload AND video generation
                console.log(`[Silent Retry] Character video - fetching image from: ${referenceImageUrl.substring(0, 50)}...`);
                
                // Step 1: Fetch character image
                const imageResponse = await fetch(referenceImageUrl);
                if (!imageResponse.ok) {
                  throw new Error(`Failed to fetch character image: ${imageResponse.statusText}`);
                }
                
                const imageBuffer = Buffer.from(await imageResponse.arrayBuffer());
                const imageBase64 = imageBuffer.toString('base64');
                const imageMimeType = referenceImageUrl.includes('.png') ? 'image/png' : 'image/jpeg';
                console.log(`[Silent Retry] Image fetched (${Math.round(imageBuffer.length / 1024)}KB)`);
                
                // Step 2: Upload image with SAME token to get mediaId
                console.log(`[Silent Retry] Uploading image with token ${rotationToken.label} to get mediaId...`);
                const uploadPayload = {
                  imageInput: {
                    rawImageBytes: imageBase64,
                    mimeType: imageMimeType
                  }
                };
                
                const uploadResponse = await fetch('https://aisandbox-pa.googleapis.com/v1:uploadUserImage', {
                  method: 'POST',
                  headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json',
                  },
                  body: JSON.stringify(uploadPayload),
                });
                
                if (!uploadResponse.ok) {
                  const errorText = await uploadResponse.text();
                  throw new Error(`Image upload failed: ${uploadResponse.status} - ${errorText}`);
                }
                
                const uploadData = await uploadResponse.json();
                const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
                
                if (!mediaId) {
                  throw new Error('No mediaId returned from image upload');
                }
                
                console.log(`[Silent Retry] ✅ MediaId generated with SAME token: ${mediaId.substring(0, 30)}...`);
                
                // Step 3: Use reference image API with SAME token + mediaId
                apiUrl = 'https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoReferenceImages';
                payload = {
                  clientContext: {
                    projectId: veoProjectId,
                    tool: "PINHOLE",
                    userPaygateTier: "PAYGATE_TIER_TWO"
                  },
                  requests: [{
                    aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                    seed: seed,
                    textInput: {
                      prompt: video.prompt
                    },
                    referenceImages: [{
                      imageUsageType: "IMAGE_USAGE_TYPE_ASSET",
                      mediaId: mediaId
                    }],
                    videoModelKey: "veo_3_0_r2v_fast_ultra",
                    metadata: {
                      sceneId: sceneId
                    }
                  }]
                };
              } else {
                // TEXT-TO-VIDEO: No reference image
                apiUrl = 'https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText';
                payload = {
                  clientContext: {
                    projectId: veoProjectId,
                    tool: "PINHOLE",
                    userPaygateTier: "PAYGATE_TIER_TWO"
                  },
                  requests: [{
                    aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                    seed: seed,
                    textInput: {
                      prompt: video.prompt
                    },
                    videoModelKey: aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                    metadata: {
                      sceneId: sceneId
                    }
                  }]
                };
              }
              
              const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                  'Authorization': `Bearer ${apiKey}`,
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
              });
              
              const result = await response.json();
              
              if (!response.ok || !result.operations || result.operations.length === 0) {
                throw new Error(result?.error?.message || 'Failed to start video generation');
              }
              
              const operationName = result.operations[0].operation.name;
              
              // Update with token used
              await storage.updateVideoHistoryFields(String(video.id), {
                tokenUsed: rotationToken.id,
                status: 'pending',
                updatedAt: new Date().toISOString()
              });
              
              // Poll for completion (4 minutes max)
              const maxAttempts = 16;
              const pollInterval = 15000;
              let completed = false;
              
              for (let attempt = 0; attempt < maxAttempts && !completed; attempt++) {
                await new Promise(resolve => setTimeout(resolve, pollInterval));
                
                try {
                  // Pass retryCount to checkVideoStatus so it can properly handle max retry limits
                  const status = await checkVideoStatus(String(operationName), String(sceneId), apiKey, retryCount);
                  
                  if (status.status === "COMPLETED" || status.status === "MEDIA_GENERATION_STATUS_COMPLETE" || status.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
                    if (status.videoUrl) {
                      await storage.updateVideoHistoryFields(String(video.id), {
                        videoUrl: status.videoUrl,
                        status: 'completed'
                      });
                      console.log(`[Silent Retry] ✅ Video ${video.id} completed successfully`);
                      completed = true;
                    }
                  } else if (status.status === "FAILED" || status.status === "MEDIA_GENERATION_STATUS_FAILED") {
                    const errorMsg = status.error || 'Video generation failed - no error details provided';
                    console.error(`[Silent Retry] ❌ Video ${video.id} failed - Error: ${errorMsg}`);
                    
                    // Save error message to database and mark as failed
                    await storage.updateVideoHistoryFields(String(video.id), {
                      status: 'failed',
                      errorMessage: errorMsg
                    });
                    
                    console.log(`[Silent Retry] Video ${video.id} marked as failed after ${retryCount} attempts`);
                    completed = true;
                  }
                } catch (pollError) {
                  console.error(`[Silent Retry] Error polling status for ${video.id}:`, pollError);
                }
              }
            } catch (retryError) {
              const retryErrorMsg = retryError instanceof Error ? retryError.message : String(retryError);
              console.error(`[Silent Retry] ❌ Error regenerating video ${video.id}: ${retryErrorMsg}`);
              
              // Save retry error to database
              await storage.updateVideoHistoryFields(String(video.id), {
                errorMessage: `Retry failed: ${retryErrorMsg}`
              });
            }
          })();
          
        } else {
          // Max retries reached - mark as failed
          const finalErrorMsg = `Max retry attempts (${maxRetries}) reached. Last error: ${errorMessage || 'Unknown error'}`;
          console.error(`[Silent Retry] ❌ Video ${video.id} - Max retries reached - ${finalErrorMsg}`);
          
          await db.execute(sql`
            UPDATE video_history 
            SET status = 'failed',
                error_message = ${finalErrorMsg},
                updated_at = NOW()
            WHERE id = ${video.id}
          `);
        }
      }
      */ // END of disabled Silent Retry code
      
    } catch (error) {
      console.error('[Timeout Cleanup] Error in cleanup logic:', error);
    }
  };
  
  // Run timeout cleanup every 2 minutes
  setInterval(checkAndTimeoutPendingVideos, 2 * 60 * 1000);
  console.log('[Timeout Cleanup] Pending video timeout job scheduled (runs every 2 minutes)');

  // Auto-retry failed videos with token rotation
  const autoRetryFailedVideos = async () => {
    try {
      const settings = await storage.getAutoRetrySettings();
      if (!settings || !settings.enableAutoRetry) {
        return;
      }

      const eligibleVideos = await storage.getEligibleFailedVideosForRetry();
      if (eligibleVideos.length === 0) {
        return;
      }

      console.log(`[Auto-Retry] Found ${eligibleVideos.length} failed videos eligible for retry`);

      // PRE-ASSIGN unique tokens to each video (like bulk generator does)
      console.log(`[Auto-Retry] 🎲 Pre-assigning ${eligibleVideos.length} unique tokens to videos...`);
      const videosWithTokens = [];
      for (const video of eligibleVideos) {
        const token = await storage.getNextRotationToken();
        if (token) {
          await storage.updateTokenUsage(token.id);
          videosWithTokens.push({ video, token });
          console.log(`[Auto-Retry] ✅ Video ${video.id.substring(0, 8)} → Token: ${token.label}`);
        } else {
          videosWithTokens.push({ video, token: undefined });
          console.log(`[Auto-Retry] ⚠️ Video ${video.id.substring(0, 8)} → No token (will use env fallback)`);
        }
      }

      // Process videos in parallel with their assigned tokens (direct VEO generation)
      const retryPromises = videosWithTokens.map(async ({ video, token }) => {
        try {
          await storage.markVideoAsRetrying(video.id);
          console.log(`[Auto-Retry] 🔄 Retrying video ${video.id.substring(0, 8)} with token ${token?.label || 'ENV'} (attempt ${video.retryCount + 1}/${settings.maxRetryAttempts})`);
          
          // Direct VEO API call (bypass HTTP endpoint)
          const apiKey = token?.token || process.env.VEO3_API_KEY;
          if (!apiKey) {
            throw new Error('No API key available for retry');
          }

          const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
          const sceneId = `auto-retry-${video.id}-${Date.now()}`;
          const seed = Math.floor(Math.random() * 100000);

          // Update video status to pending
          await storage.updateVideoHistoryStatus(video.id, video.userId, 'pending');

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
              metadata: { sceneId: sceneId }
            }]
          };

          const response = await fetch('https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
          });

          if (!response.ok) {
            const errorText = await response.text();
            console.error(`[Auto-Retry] ❌ VEO API failed for video ${video.id.substring(0, 8)}:`, errorText);
            await storage.updateVideoHistoryStatus(video.id, video.userId, 'failed', undefined, `VEO API error: ${errorText}`);
            if (token) {
              await storage.recordTokenError(token.id);
            }
            return;
          }

          const data = await response.json();
          const operationName = data.operations?.[0]?.operation?.name;

          if (!operationName) {
            throw new Error('No operation name in VEO response');
          }

          // Start background polling (imported from bulkQueue)
          const { startBackgroundPolling } = await import('./bulkQueue.js');
          startBackgroundPolling(video.id, video.userId, operationName, sceneId, apiKey, token);
          
          console.log(`[Auto-Retry] ✅ Video ${video.id.substring(0, 8)} queued with operation ${operationName}`);
        } catch (error) {
          console.error(`[Auto-Retry] ❌ Error retrying video ${video.id.substring(0, 8)}:`, error);
          await storage.updateVideoHistoryStatus(video.id, video.userId, 'failed', undefined, `Retry error: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      await Promise.all(retryPromises);
      console.log(`[Auto-Retry] 🎉 Completed processing ${videosWithTokens.length} videos with token rotation`);
    } catch (error) {
      console.error('[Auto-Retry] Error in auto-retry job:', error);
    }
  };

  // Auto-retry disabled due to database operator errors
  // setInterval(autoRetryFailedVideos, 5 * 60 * 1000);
  // console.log('[Auto-Retry] Auto-retry job scheduled (runs every 5 minutes)');

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });
})();
