/**
 * Zyphra API Integration for Voice Cloning and Text-to-Speech
 * Supports multiple API keys with automatic rotation
 */

import { db } from "./db";
import { zyphraTokens } from "@shared/schema";
import { eq, and, lt } from "drizzle-orm";
import * as mm from "music-metadata";

const ZYPHRA_API_URL = "http://api.zyphra.com/v1/audio/text-to-speech";

export interface ZyphraTextToSpeechRequest {
  text: string;
  speakingRate?: number; // 5-35, default 15
  model?: "zonos-v0.1-transformer" | "zonos-v0.1-hybrid";
  languageIsoCode?: string; // en-us, fr-fr, de, ja, ko, cmn
  mimeType?: "audio/webm" | "audio/mp3" | "audio/wav" | "audio/ogg";
  speakerAudio?: string; // Base64 encoded audio for voice cloning
  emotion?: {
    happiness?: number;
    sadness?: number;
    disgust?: number;
    fear?: number;
    surprise?: number;
    anger?: number;
    other?: number;
    neutral?: number;
  };
  pitchStd?: number; // 0-100, default 45
  speakerNoised?: boolean; // For hybrid model only
  defaultVoiceName?: string; // Use predefined voice
}

export interface ZyphraResponse {
  success: boolean;
  audioData?: Buffer;
  mimeType?: string;
  error?: string;
  tokenId?: string;
  minutesUsed?: number;
}

const MIN_REMAINING_MINUTES = 15; // Auto-disable tokens with less than 15 minutes remaining

/**
 * Check and auto-disable tokens with less than 15 minutes remaining
 */
async function checkAndAutoDisableLowTimeTokens(): Promise<void> {
  try {
    const allActiveTokens = await db
      .select()
      .from(zyphraTokens)
      .where(eq(zyphraTokens.isActive, true));
    
    for (const token of allActiveTokens) {
      const remainingMinutes = token.minutesLimit - token.minutesUsed;
      if (remainingMinutes < MIN_REMAINING_MINUTES) {
        console.log(`[Zyphra Auto-Disable] Token ${token.id.slice(0, 8)} has only ${remainingMinutes.toFixed(2)} minutes remaining (< ${MIN_REMAINING_MINUTES}). Disabling...`);
        await db
          .update(zyphraTokens)
          .set({ isActive: false })
          .where(eq(zyphraTokens.id, token.id));
        console.log(`[Zyphra Auto-Disable] Token ${token.id.slice(0, 8)} has been disabled.`);
      }
    }
  } catch (error) {
    console.error("[Zyphra Auto-Disable] Error checking tokens:", error);
  }
}

/**
 * Get an available Zyphra API token with at least 15 minutes remaining
 * @param excludeTokenIds - Optional array of token IDs to exclude (for retry logic)
 */
export async function getAvailableZyphraToken(excludeTokenIds: string[] = []): Promise<{ id: string; apiKey: string } | null> {
  try {
    // First, check and auto-disable low-time tokens
    await checkAndAutoDisableLowTimeTokens();
    
    const allTokens = await db
      .select()
      .from(zyphraTokens)
      .where(
        and(
          eq(zyphraTokens.isActive, true),
          lt(zyphraTokens.minutesUsed, zyphraTokens.minutesLimit)
        )
      );
    
    // Filter out excluded tokens
    const availableTokens = allTokens.filter(t => !excludeTokenIds.includes(t.id));

    if (availableTokens.length === 0) {
      // If all tokens are excluded but there are active tokens, allow retry with excluded tokens
      if (allTokens.length > 0 && excludeTokenIds.length > 0) {
        console.log(`[Zyphra] All available tokens were excluded, falling back to excluded tokens`);
        return { id: allTokens[0].id, apiKey: allTokens[0].apiKey };
      }
      return null;
    }
    
    const token = availableTokens[0];
    
    // Double-check remaining minutes (Note: uses integer storage, so may have ~1 min precision)
    const remainingMinutes = token.minutesLimit - token.minutesUsed;
    if (remainingMinutes < MIN_REMAINING_MINUTES) {
      // This shouldn't happen after the check above, but just in case
      console.log(`[Zyphra] Token ${token.id.slice(0, 8)} has insufficient remaining time (${remainingMinutes} min). Skipping.`);
      return null;
    }

    return { id: token.id, apiKey: token.apiKey };
  } catch (error) {
    console.error("Error getting Zyphra token:", error);
    return null;
  }
}

/**
 * Update token usage after API call
 */
async function updateTokenUsage(tokenId: string, minutesUsed: number): Promise<void> {
  try {
    const token = await db.select().from(zyphraTokens).where(eq(zyphraTokens.id, tokenId)).limit(1);
    if (token.length > 0) {
      await db
        .update(zyphraTokens)
        .set({
          minutesUsed: token[0].minutesUsed + minutesUsed,
          lastUsedAt: new Date().toISOString(),
        })
        .where(eq(zyphraTokens.id, tokenId));
    }
  } catch (error) {
    console.error("Error updating token usage:", error);
  }
}

/**
 * Calculate actual audio duration in minutes from audio buffer
 */
async function calculateAudioDuration(audioBuffer: Buffer, mimeType: string, textLength?: number): Promise<number> {
  try {
    // music-metadata requires fileInfo object with mimeType property
    const metadata = await mm.parseBuffer(audioBuffer, { mimeType, size: audioBuffer.length });
    if (metadata.format.duration) {
      // Convert seconds to minutes, round to 2 decimal places
      const minutes = metadata.format.duration / 60;
      console.log(`[Zyphra] Audio duration: ${metadata.format.duration}s = ${minutes.toFixed(2)} min`);
      return Math.round(minutes * 100) / 100;
    }
    console.log("[Zyphra] No duration in audio metadata, using text estimate");
  } catch (error) {
    console.error("[Zyphra] Error calculating audio duration:", error);
  }
  // Fallback: estimate based on text length (150 words/min, ~5 chars/word)
  if (textLength && textLength > 0) {
    const words = textLength / 5;
    const minutes = words / 150;
    const estimated = Math.max(0.01, Math.round(minutes * 100) / 100);
    console.log(`[Zyphra] Estimated duration from ${textLength} chars: ${estimated} min`);
    return estimated;
  }
  return 0.01;
}

/**
 * Estimate audio duration in minutes based on text length (fallback only)
 * Approximate: 150 words per minute, average 5 chars per word
 */
function estimateMinutes(text: string): number {
  const words = text.length / 5;
  const minutes = words / 150;
  return Math.round(minutes * 100) / 100; // No minimum - calculate actual
}

/**
 * Generate speech from text using Zyphra API
 * @param request - TTS request parameters
 * @param excludeTokenIds - Optional array of token IDs to exclude (for retry logic)
 */
export async function generateSpeech(request: ZyphraTextToSpeechRequest, excludeTokenIds: string[] = []): Promise<ZyphraResponse> {
  const token = await getAvailableZyphraToken(excludeTokenIds);
  
  if (!token) {
    return {
      success: false,
      error: "Voice generation service unavailable. Please try again later.",
    };
  }

  try {
    const requestBody: Record<string, any> = {
      text: request.text,
      speaking_rate: request.speakingRate || 15,
      model: request.model || "zonos-v0.1-transformer",
    };

    if (request.languageIsoCode) {
      requestBody.language_iso_code = request.languageIsoCode;
    }

    if (request.mimeType) {
      requestBody.mime_type = request.mimeType;
    }

    if (request.speakerAudio) {
      requestBody.speaker_audio = request.speakerAudio;
    }

    if (request.emotion && request.model !== "zonos-v0.1-hybrid") {
      requestBody.emotion = request.emotion;
    }

    if (request.pitchStd !== undefined && request.model !== "zonos-v0.1-hybrid") {
      requestBody.pitchStd = request.pitchStd;
    }

    if (request.speakerNoised !== undefined && request.model === "zonos-v0.1-hybrid") {
      requestBody.speaker_noised = request.speakerNoised;
    }

    if (request.defaultVoiceName) {
      requestBody.default_voice_name = request.defaultVoiceName;
    }

    console.log(`[Zyphra] Generating speech with token ${token.id.slice(0, 8)}...`);

    const response = await fetch(ZYPHRA_API_URL, {
      method: "POST",
      headers: {
        "X-API-Key": token.apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[Zyphra] API Error: ${response.status} - ${errorText}`);
      return {
        success: false,
        error: `Voice generation failed. Please try again.`,
        tokenId: token.id,
      };
    }

    const audioBuffer = await response.arrayBuffer();
    const audioData = Buffer.from(audioBuffer);
    const mimeType = request.mimeType || "audio/webm";
    
    // Calculate actual audio duration from the generated audio (pass text length for fallback estimation)
    const actualMinutes = await calculateAudioDuration(audioData, mimeType, request.text.length);
    
    // Update token usage with actual duration
    await updateTokenUsage(token.id, actualMinutes);

    console.log(`[Zyphra] Speech generated successfully (${actualMinutes} min actual duration)`);

    return {
      success: true,
      audioData,
      mimeType,
      tokenId: token.id,
      minutesUsed: actualMinutes,
    };
  } catch (error: any) {
    console.error("[Zyphra] Error generating speech:", error);
    return {
      success: false,
      error: error.message || "Failed to generate speech",
      tokenId: token.id,
    };
  }
}

const MAX_SILENT_RETRIES = 3; // Silent retries before showing error to user

/**
 * Generate speech with silent retry mechanism
 * Retries up to 3 times silently before showing error to user
 * Each retry excludes previously failing tokens to try different API keys
 */
export async function generateSpeechWithRetry(request: ZyphraTextToSpeechRequest): Promise<ZyphraResponse> {
  let lastError: string | undefined;
  const failedTokenIds: string[] = [];
  
  for (let attempt = 1; attempt <= MAX_SILENT_RETRIES; attempt++) {
    console.log(`[Zyphra] TTS attempt ${attempt}/${MAX_SILENT_RETRIES}${failedTokenIds.length > 0 ? ` (excluding ${failedTokenIds.length} previously failed tokens)` : ''}...`);
    
    const result = await generateSpeech(request, failedTokenIds);
    
    if (result.success) {
      if (attempt > 1) {
        console.log(`[Zyphra] TTS succeeded on attempt ${attempt}`);
      }
      return result;
    }
    
    // Track the failed token to try a different one on next attempt
    if (result.tokenId && !failedTokenIds.includes(result.tokenId)) {
      failedTokenIds.push(result.tokenId);
      console.log(`[Zyphra] Token ${result.tokenId.slice(0, 8)} failed, will try different token on next attempt`);
    }
    
    // Store the error for potential display on final failure
    lastError = result.error;
    
    if (attempt < MAX_SILENT_RETRIES) {
      // Silent retry - don't expose error to user yet
      console.log(`[Zyphra] TTS attempt ${attempt} failed silently, retrying... Error: ${result.error}`);
      // Small delay between retries (500ms)
      await new Promise(resolve => setTimeout(resolve, 500));
    } else {
      // Final attempt failed - now show error to user
      console.error(`[Zyphra] TTS failed after ${MAX_SILENT_RETRIES} attempts. Final error: ${result.error}`);
    }
  }
  
  // All retries exhausted - return the error
  return {
    success: false,
    error: lastError || "Voice generation failed after multiple attempts. Please try again.",
  };
}

/**
 * Voice cloning with silent retry mechanism
 * Retries up to 3 times silently before showing error to user
 */
export async function cloneVoiceWithRetry(
  text: string,
  referenceAudioBase64: string,
  options?: {
    speakingRate?: number;
    languageIsoCode?: string;
    mimeType?: "audio/webm" | "audio/mp3" | "audio/wav" | "audio/ogg";
    model?: "zonos-v0.1-transformer" | "zonos-v0.1-hybrid";
  }
): Promise<ZyphraResponse> {
  return generateSpeechWithRetry({
    text,
    speakerAudio: referenceAudioBase64,
    speakingRate: options?.speakingRate || 15,
    languageIsoCode: options?.languageIsoCode,
    mimeType: options?.mimeType || "audio/mp3",
    model: options?.model || "zonos-v0.1-transformer",
  });
}

/**
 * Voice cloning - generate speech with a cloned voice
 */
export async function cloneVoice(
  text: string,
  referenceAudioBase64: string,
  options?: {
    speakingRate?: number;
    languageIsoCode?: string;
    mimeType?: "audio/webm" | "audio/mp3" | "audio/wav" | "audio/ogg";
    model?: "zonos-v0.1-transformer" | "zonos-v0.1-hybrid";
  }
): Promise<ZyphraResponse> {
  return generateSpeech({
    text,
    speakerAudio: referenceAudioBase64,
    speakingRate: options?.speakingRate || 15,
    languageIsoCode: options?.languageIsoCode,
    mimeType: options?.mimeType || "audio/mp3",
    model: options?.model || "zonos-v0.1-transformer",
  });
}

/**
 * Get all Zyphra tokens with usage stats
 */
export async function getAllZyphraTokens() {
  return db.select().from(zyphraTokens);
}

/**
 * Add a new Zyphra API key
 */
export async function addZyphraToken(apiKey: string, label: string, minutesLimit: number = 100) {
  return db.insert(zyphraTokens).values({
    apiKey,
    label,
    minutesLimit,
  }).returning();
}

/**
 * Delete a Zyphra token
 */
export async function deleteZyphraToken(id: string) {
  return db.delete(zyphraTokens).where(eq(zyphraTokens.id, id));
}

/**
 * Update Zyphra token
 */
export async function updateZyphraToken(id: string, updates: {
  label?: string;
  isActive?: boolean;
  minutesUsed?: number;
  minutesLimit?: number;
}) {
  return db.update(zyphraTokens).set(updates).where(eq(zyphraTokens.id, id)).returning();
}

/**
 * Reset all token usage (for monthly reset)
 */
export async function resetAllTokenUsage() {
  return db.update(zyphraTokens).set({ minutesUsed: 0 });
}

/**
 * Reset individual token usage
 */
export async function resetTokenUsage(id: string) {
  return db.update(zyphraTokens).set({ minutesUsed: 0 }).where(eq(zyphraTokens.id, id));
}

/**
 * Available default voices
 */
export const DEFAULT_VOICES = [
  { name: "american_female", description: "Standard American English female voice" },
  { name: "american_male", description: "Standard American English male voice" },
  { name: "anime_girl", description: "Stylized anime girl character voice" },
  { name: "british_female", description: "British English female voice" },
  { name: "british_male", description: "British English male voice" },
  { name: "energetic_boy", description: "Energetic young male voice" },
  { name: "energetic_girl", description: "Energetic young female voice" },
  { name: "japanese_female", description: "Japanese female voice" },
  { name: "japanese_male", description: "Japanese male voice" },
];

/**
 * Supported languages
 */
export const SUPPORTED_LANGUAGES = [
  { code: "en-us", name: "English (US)" },
  { code: "fr-fr", name: "French" },
  { code: "de", name: "German" },
  { code: "ja", name: "Japanese" },
  { code: "ko", name: "Korean" },
  { code: "cmn", name: "Mandarin Chinese" },
];
