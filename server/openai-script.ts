import { storage } from "./storage";

// Models to try - with fallback options
const MEGALLM_MODELS = [
  "gpt-4o-mini",
  "gemini-2.0-flash-001",
  "claude-3.5-sonnet"
];

/**
 * Generate script/storyboard using megallm.io API with auto model fallback
 * If one model fails, automatically tries the next model in the list
 */
export async function generateScript(
  storyAbout: string,
  numberOfPrompts: number,
  finalStep: string
): Promise<string> {
  const MAX_RETRIES_PER_MODEL = 2;
  const TIMEOUT_MS = 120000; // 120 seconds
  
  // Get API key from database first, fall back to environment variable
  const appSettings = await storage.getAppSettings();
  const apiKey = appSettings?.scriptApiKey || process.env.OPENAI_API_KEY;
  
  if (!apiKey) {
    throw new Error("Script API key not configured. Please set it in Admin Panel > App Settings or add OPENAI_API_KEY environment variable.");
  }
  
  // Log API key prefix for debugging (first 10 chars only)
  console.log(`[Script Generator] Using API key: ${apiKey.substring(0, 10)}...`);

  const prompt = `Write a storyboard for an animated film about a ${storyAbout}, consisting of ${numberOfPrompts} steps. Each step should include an English prompt. The final step should ${finalStep}. Describe the animated character fully in English at the beginning, and repeat that full character description in each prompt (do not use pronouns or shorthand such as "the same character"). The purpose is to reinforce the character's identity in every scene.

CRITICAL FORMATTING REQUIREMENTS:
1. Output ONLY the scene descriptions (no labels, no numbering, no step numbers, no titles)
2. Separate EACH scene with a blank line (press enter twice between scenes)
3. Each scene should be a single detailed paragraph
4. Example format:

The brave knight, standing tall in polished armor, wakes at dawn in the castle courtyard...

The brave knight, standing tall in polished armor, mounts his black horse and rides through the misty forest...

The brave knight, standing tall in polished armor, confronts the dragon at the mountain peak...`;

  let lastError = "";
  
  // Try each model in sequence until one succeeds
  for (let modelIndex = 0; modelIndex < MEGALLM_MODELS.length; modelIndex++) {
    const currentModel = MEGALLM_MODELS[modelIndex];
    
    // Try each model with retries
    for (let attempt = 1; attempt <= MAX_RETRIES_PER_MODEL; attempt++) {
      try {
        console.log(`[Script Generator] Model ${modelIndex + 1}/${MEGALLM_MODELS.length} (${currentModel}), Attempt ${attempt}/${MAX_RETRIES_PER_MODEL}`);

        // Create abort controller for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

        try {
          const response = await fetch('https://ai.megallm.io/v1/chat/completions', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              model: currentModel,
              messages: [
                { 
                  role: "system", 
                  content: "You are a creative screenwriter and storyboard artist. Generate detailed, vivid storyboards for animated films." 
                },
                { 
                  role: "user", 
                  content: prompt 
                }
              ],
              max_tokens: 16000,
            }),
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API request failed: ${response.status} ${response.statusText} - ${errorText}`);
          }

          const data = await response.json();
          
          // Validate response structure
          if (!data || typeof data !== 'object') {
            throw new Error("Invalid API response format");
          }

          if (!data.choices || !Array.isArray(data.choices) || data.choices.length === 0) {
            throw new Error("API response missing choices array");
          }

          const messageContent = data.choices[0]?.message?.content;
          
          if (!messageContent || typeof messageContent !== 'string') {
            throw new Error("API response missing message content");
          }

          const storyboard = messageContent.trim();

          if (storyboard.length < 50) {
            throw new Error("Generated script is too short, likely incomplete");
          }

          console.log(`[Script Generator] Success with model ${currentModel} on attempt ${attempt}`);
          return storyboard;

        } catch (fetchError) {
          clearTimeout(timeoutId);
          
          // If it's an abort error (timeout), throw to retry
          if (fetchError instanceof Error && fetchError.name === 'AbortError') {
            throw new Error(`Request timeout after ${TIMEOUT_MS}ms`);
          }
          
          throw fetchError;
        }

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        lastError = errorMessage;
        console.error(`[Script Generator] Model ${currentModel}, Attempt ${attempt} failed:`, errorMessage);
        
        // If this was the last attempt for this model, try next model
        if (attempt === MAX_RETRIES_PER_MODEL) {
          console.log(`[Script Generator] Model ${currentModel} exhausted, switching to next model...`);
          break; // Move to next model
        }
        
        // Wait before retrying same model (short delay)
        const waitMs = 1000;
        console.log(`[Script Generator] Waiting ${waitMs}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, waitMs));
      }
    }
  }
  
  // All models failed
  throw new Error(`Failed to generate script after trying all ${MEGALLM_MODELS.length} models. Last error: ${lastError}`);
}
