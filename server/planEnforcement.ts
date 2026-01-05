import type { User } from "@shared/schema";

// Voice character limits per plan (resets every X days)
export const VOICE_CHARACTER_LIMITS = {
  free: {
    limit: 10000, // 10K characters
    resetDays: 10,
  },
  scale: {
    limit: 50000, // 50K characters
    resetDays: 10,
  },
  empire: {
    limit: 1000000, // 1 million characters
    resetDays: 10,
  },
  enterprise: {
    limit: 5000000, // 5 million characters (can be customized)
    resetDays: 10,
  },
} as const;

// Per-request character limits for TTS (based on plan type)
export const PER_REQUEST_CHAR_LIMITS = {
  free: 5000,      // 5K per request for free
  scale: 10000,    // 10K per request for Scale
  empire: 10000,   // 10K per request for Empire
  enterprise: 100000, // 100K per request for Enterprise
  admin: 200000,   // 200K per request for admins
} as const;

/**
 * Get per-request character limit based on user's plan
 */
export function getPerRequestCharLimit(user: User): number {
  if (user.isAdmin) {
    return PER_REQUEST_CHAR_LIMITS.admin;
  }
  const planType = (user.planType || 'free') as keyof typeof PER_REQUEST_CHAR_LIMITS;
  return PER_REQUEST_CHAR_LIMITS[planType] || PER_REQUEST_CHAR_LIMITS.free;
}

// Plan configuration constants
export const PLAN_CONFIGS = {
  free: {
    name: "Free",
    dailyVideoLimit: 0, // Free users have limited access
    allowedTools: ["veo", "voiceTools"] as const, // VEO 3 + Voice Tools
    bulkGeneration: {
      maxBatch: 0,
      delaySeconds: 0,
      maxPrompts: 0,
    },
  },
  scale: {
    name: "Scale",
    price: "900 PKR",
    duration: "10 days",
    dailyVideoLimit: 1000,
    allowedTools: ["veo", "bulk", "voiceTools"] as const, // VEO 3 + Bulk generation + Voice Tools
    bulkGeneration: {
      maxBatch: 7,
      delaySeconds: 30,
      maxPrompts: 50,
    },
  },
  empire: {
    name: "Empire",
    price: "1500 PKR",
    duration: "10 days",
    dailyVideoLimit: 2000,
    allowedTools: ["veo", "bulk", "script", "textToImage", "imageToVideo", "voiceTools"] as const, // All tools
    bulkGeneration: {
      maxBatch: 100,
      delaySeconds: 15,
      maxPrompts: 100,
    },
  },
  enterprise: {
    name: "Enterprise",
    price: "Custom",
    duration: "Custom",
    dailyVideoLimit: 20000, // Default, will be overridden by user's custom limit
    allowedTools: ["veo", "bulk", "script", "textToImage", "imageToVideo", "voiceTools"] as const, // All tools
    bulkGeneration: {
      maxBatch: 100,
      delaySeconds: 10,
      maxPrompts: 500,
    },
  },
} as const;

export type PlanType = keyof typeof PLAN_CONFIGS;
export type AllowedTool = "veo" | "bulk" | "script" | "textToImage" | "imageToVideo" | "voiceTools";

export interface PlanCheckResult {
  allowed: boolean;
  reason?: string;
  remainingVideos?: number;
}

/**
 * Check if a user's plan has expired
 */
export function isPlanExpired(user: User): boolean {
  // Admin never expires
  if (user.isAdmin) {
    return false;
  }

  // Free plan never expires
  if (user.planType === "free") {
    return false;
  }

  // Check if plan has expiry date and if it's past
  if (user.planExpiry) {
    const expiryDate = new Date(user.planExpiry);
    const now = new Date();
    return now > expiryDate;
  }

  return false;
}

/**
 * Check if user has reached their daily video limit
 */
export function hasReachedDailyLimit(user: User): boolean {
  // Admin has no limits
  if (user.isAdmin) {
    return false;
  }

  const config = PLAN_CONFIGS[user.planType as PlanType];
  if (!config) {
    return true; // Unknown plan type, restrict access
  }

  // For enterprise users, use their custom dailyVideoLimit from database
  const limit = user.planType === "enterprise" && user.dailyVideoLimit 
    ? user.dailyVideoLimit 
    : config.dailyVideoLimit;

  return user.dailyVideoCount >= limit;
}

/**
 * Get remaining videos for the day
 */
export function getRemainingVideos(user: User): number {
  // Admin has unlimited
  if (user.isAdmin) {
    return Infinity;
  }

  const config = PLAN_CONFIGS[user.planType as PlanType];
  if (!config) {
    return 0;
  }

  // For enterprise users, use their custom dailyVideoLimit from database
  const limit = user.planType === "enterprise" && user.dailyVideoLimit 
    ? user.dailyVideoLimit 
    : config.dailyVideoLimit;

  const remaining = limit - user.dailyVideoCount;
  return Math.max(0, remaining);
}

/**
 * Check if user can access a specific tool
 */
export function canAccessTool(user: User, tool: AllowedTool): PlanCheckResult {
  // Admin can access everything
  if (user.isAdmin) {
    return { allowed: true };
  }

  // Check if plan is expired
  if (isPlanExpired(user)) {
    return {
      allowed: false,
      reason: "Your plan has expired. Please contact admin to renew.",
    };
  }

  const config = PLAN_CONFIGS[user.planType as PlanType];
  if (!config) {
    return {
      allowed: false,
      reason: "Invalid plan type. Please contact admin.",
    };
  }

  // Check if tool is allowed for this plan
  if (!config.allowedTools.includes(tool as any)) {
    return {
      allowed: false,
      reason: `This tool is not available on your ${config.name} plan. Please upgrade to access this feature.`,
    };
  }

  return { allowed: true };
}

/**
 * Check if user can generate videos (considering daily limit)
 */
export function canGenerateVideo(user: User): PlanCheckResult {
  // Admin can always generate
  if (user.isAdmin) {
    return { allowed: true };
  }

  // Check if plan is expired
  if (isPlanExpired(user)) {
    return {
      allowed: false,
      reason: "Your plan has expired. Please contact admin to renew.",
    };
  }

  // Check daily limit
  if (hasReachedDailyLimit(user)) {
    const config = PLAN_CONFIGS[user.planType as PlanType];
    // For enterprise users, use their custom dailyVideoLimit from database
    const limit = user.planType === "enterprise" && user.dailyVideoLimit 
      ? user.dailyVideoLimit 
      : config.dailyVideoLimit;
    return {
      allowed: false,
      reason: `You have reached your daily limit of ${limit} videos. Limit resets at midnight.`,
    };
  }

  const remaining = getRemainingVideos(user);
  return {
    allowed: true,
    remainingVideos: remaining,
  };
}

/**
 * Check if user can perform bulk generation with specified count
 */
export function canBulkGenerate(user: User, videoCount: number): PlanCheckResult {
  // Admin can always generate
  if (user.isAdmin) {
    return { allowed: true };
  }

  // Check tool access first
  const toolCheck = canAccessTool(user, "bulk");
  if (!toolCheck.allowed) {
    return toolCheck;
  }

  const config = PLAN_CONFIGS[user.planType as PlanType];
  
  // For enterprise users, use their custom maxPrompts if available
  const maxPrompts = user.planType === "enterprise" && user.bulkMaxPrompts 
    ? user.bulkMaxPrompts 
    : config.bulkGeneration.maxPrompts;
  
  // Check if total prompts exceeds plan limit
  if (videoCount > maxPrompts) {
    return {
      allowed: false,
      reason: `Your ${config.name} plan allows a maximum of ${maxPrompts} prompts in total. Please reduce the number of prompts.`,
    };
  }
  
  // Check if batch size exceeds plan limit (not enforced here, enforced by backend delay/batch processing)
  // This is informational only
  if (config.bulkGeneration.maxBatch > 0 && videoCount > config.bulkGeneration.maxBatch) {
    // Note: This won't block submission but videos will be processed in batches
  }

  // Check daily limit
  const remaining = getRemainingVideos(user);
  if (videoCount > remaining) {
    return {
      allowed: false,
      reason: `You have ${remaining} videos remaining today. Cannot generate ${videoCount} videos.`,
    };
  }

  return {
    allowed: true,
    remainingVideos: remaining,
  };
}

/**
 * Get batch configuration for user's plan
 */
export function getBatchConfig(user: User): { maxBatch: number; delaySeconds: number } {
  // Admin gets empire config
  if (user.isAdmin) {
    return PLAN_CONFIGS.empire.bulkGeneration;
  }

  const config = PLAN_CONFIGS[user.planType as PlanType];
  if (!config) {
    return { maxBatch: 0, delaySeconds: 0 };
  }

  // For enterprise users, use their custom bulk settings if available
  if (user.planType === "enterprise") {
    return {
      maxBatch: user.bulkMaxBatch ?? config.bulkGeneration.maxBatch,
      delaySeconds: user.bulkDelaySeconds ?? config.bulkGeneration.delaySeconds,
    };
  }

  return config.bulkGeneration;
}

/**
 * Get user's plan configuration
 */
export function getPlanConfig(user: User) {
  if (user.isAdmin) {
    return {
      ...PLAN_CONFIGS.empire,
      name: "Admin (Unlimited)",
      dailyVideoLimit: Infinity,
    };
  }

  return PLAN_CONFIGS[user.planType as PlanType] || PLAN_CONFIGS.free;
}

/**
 * Format plan expiry date for display
 */
export function formatPlanExpiry(expiryDate: string | null): string {
  if (!expiryDate) {
    return "Never";
  }

  const date = new Date(expiryDate);
  const now = new Date();
  
  // If expired
  if (date < now) {
    return "Expired";
  }

  // Calculate days remaining
  const diffTime = date.getTime() - now.getTime();
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  if (diffDays === 0) {
    return "Expires today";
  } else if (diffDays === 1) {
    return "Expires tomorrow";
  } else {
    return `${diffDays} days remaining`;
  }
}

/**
 * Check if voice character reset is needed (every 10 days)
 */
export function shouldResetVoiceCharacters(user: User): boolean {
  if (!user.voiceCharactersResetDate) {
    return true; // No reset date set, need to initialize
  }
  
  const resetDate = new Date(user.voiceCharactersResetDate);
  const now = new Date();
  return now >= resetDate;
}

/**
 * Get voice character limit for user's plan
 */
export function getVoiceCharacterLimit(user: User): number {
  // Admin has unlimited
  if (user.isAdmin) {
    return Infinity;
  }
  
  const planType = user.planType as PlanType;
  const config = VOICE_CHARACTER_LIMITS[planType];
  return config?.limit ?? VOICE_CHARACTER_LIMITS.free.limit;
}

/**
 * Get voice character usage info for a user
 */
export function getVoiceCharacterUsage(user: User): {
  used: number;
  limit: number;
  remaining: number;
  resetDate: string | null;
  resetDays: number;
} {
  const limit = getVoiceCharacterLimit(user);
  const used = user.voiceCharactersUsed ?? 0;
  const remaining = Math.max(0, limit - used);
  const planType = user.planType as PlanType;
  const resetDays = VOICE_CHARACTER_LIMITS[planType]?.resetDays ?? 10;
  
  return {
    used,
    limit: limit === Infinity ? -1 : limit, // -1 means unlimited
    remaining: limit === Infinity ? -1 : remaining,
    resetDate: user.voiceCharactersResetDate ?? null,
    resetDays,
  };
}

/**
 * Check if user can use voice characters (before generation)
 */
export function canUseVoiceCharacters(user: User, characterCount: number): PlanCheckResult {
  // Admin can always use (unlimited)
  if (user.isAdmin) {
    return { allowed: true };
  }
  
  // Check if plan is expired
  if (isPlanExpired(user)) {
    return {
      allowed: false,
      reason: "Your plan has expired. Please contact admin to renew.",
    };
  }
  
  // Check tool access
  const toolCheck = canAccessTool(user, "voiceTools");
  if (!toolCheck.allowed) {
    return toolCheck;
  }
  
  const limit = getVoiceCharacterLimit(user);
  
  // If unlimited (Infinity), always allow
  if (limit === Infinity || limit <= 0) {
    return { allowed: true };
  }
  
  const used = user.voiceCharactersUsed ?? 0;
  const remaining = limit - used;
  
  if (characterCount > remaining) {
    const planType = user.planType as PlanType;
    const config = VOICE_CHARACTER_LIMITS[planType];
    return {
      allowed: false,
      reason: `Character limit exceeded. You have ${remaining.toLocaleString()} characters remaining out of ${limit.toLocaleString()}. Limit resets every ${config?.resetDays ?? 10} days.`,
    };
  }
  
  return { allowed: true };
}

/**
 * Calculate next reset date (10 days from now)
 */
export function calculateNextResetDate(resetDays: number = 10): string {
  const now = new Date();
  now.setDate(now.getDate() + resetDays);
  return now.toISOString();
}
