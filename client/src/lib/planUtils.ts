type User = {
  id: string;
  username: string;
  isAdmin: boolean;
  planType: string;
  planStatus: string;
  planExpiry: string | null;
  dailyVideoCount: number;
};

type PlanConfig = {
  name: string;
  dailyLimit: number;
  allowedTools: string[];
  bulkGeneration: {
    maxBatch: number;
    delaySeconds: number;
    maxPrompts: number;
  };
};

export const PLAN_CONFIGS: Record<string, PlanConfig> = {
  free: {
    name: "Free",
    dailyLimit: 0,
    allowedTools: ["veo"],
    bulkGeneration: {
      maxBatch: 0,
      delaySeconds: 0,
      maxPrompts: 0,
    },
  },
  scale: {
    name: "Scale",
    dailyLimit: 1000,
    allowedTools: ["veo", "bulk"],
    bulkGeneration: {
      maxBatch: 7,
      delaySeconds: 30,
      maxPrompts: 50,
    },
  },
  empire: {
    name: "Empire",
    dailyLimit: 2000,
    allowedTools: ["veo", "bulk", "script", "textToImage", "imageToVideo"],
    bulkGeneration: {
      maxBatch: 20,
      delaySeconds: 15,
      maxPrompts: 100,
    },
  },
  enterprise: {
    name: "Enterprise",
    dailyLimit: 20000,
    allowedTools: ["veo", "bulk", "script", "textToImage", "imageToVideo"],
    bulkGeneration: {
      maxBatch: 50,
      delaySeconds: 10,
      maxPrompts: 200,
    },
  },
};

export function isPlanExpired(user: User): boolean {
  if (user.isAdmin || user.planType === "free") {
    return false;
  }

  if (user.planExpiry) {
    const expiryDate = new Date(user.planExpiry);
    const now = new Date();
    return now > expiryDate;
  }

  return false;
}

export function hasReachedDailyLimit(user: User): boolean {
  if (user.isAdmin) {
    return false;
  }

  const config = PLAN_CONFIGS[user.planType];
  if (!config) {
    return true;
  }

  return user.dailyVideoCount >= config.dailyLimit;
}

export function getRemainingVideos(user: User): number {
  if (user.isAdmin) {
    return Infinity;
  }

  const config = PLAN_CONFIGS[user.planType];
  if (!config) {
    return 0;
  }

  // Empire plan shows Unlimited in UI (backend still enforces 2000 limit)
  if (user.planType === 'empire') {
    return Infinity;
  }

  const remaining = config.dailyLimit - user.dailyVideoCount;
  return Math.max(0, remaining);
}

export function canAccessTool(user: User, tool: string): { allowed: boolean; reason?: string } {
  if (user.isAdmin) {
    return { allowed: true };
  }

  if (isPlanExpired(user)) {
    return {
      allowed: false,
      reason: "Your plan has expired. Please contact admin to renew.",
    };
  }

  const config = PLAN_CONFIGS[user.planType];
  if (!config) {
    return {
      allowed: false,
      reason: "Invalid plan type. Please contact admin.",
    };
  }

  if (!config.allowedTools.includes(tool)) {
    return {
      allowed: false,
      reason: `This tool is not available on your ${config.name} plan. Please upgrade to access this feature.`,
    };
  }

  return { allowed: true };
}

export function getPlanConfig(user: User): PlanConfig {
  if (user.isAdmin) {
    return {
      ...PLAN_CONFIGS.empire,
      name: "Admin (Unlimited)",
      dailyLimit: Infinity,
    };
  }

  return PLAN_CONFIGS[user.planType] || PLAN_CONFIGS.free;
}
