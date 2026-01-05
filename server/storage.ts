import {
  type User,
  type InsertUser,
  type UpdateUserPlan,
  type UpdateUserApiToken,
  type ApiToken,
  type InsertApiToken,
  type TokenSettings,
  type UpdateTokenSettings,
  type VideoHistory,
  type InsertVideoHistory,
  type AutoRetrySettings,
  type UpdateAutoRetrySettings,
  type PlanAvailability,
  type UpdatePlanAvailability,
  type AppSettings,
  type UpdateAppSettings,
  type ToolMaintenance,
  type UpdateToolMaintenance,
  type CreditsSnapshot,
  type ImageHistory,
  imageHistory,
  type Character,
  type InsertCharacter,
  type AdminMessage,
  type Reseller,
  type InsertReseller,
  type UpdateReseller,
  type ResellerCreditLedger,
  type ResellerUser,
  type ResellerCreateUser,
  type FlowCookie,
  type UpdateFlowCookie,
  type CommunityVoice,
  type InsertCommunityVoice,
  type CommunityVoiceLike,
  type PricingPlan,
  type InsertPricingPlan,
  type UpdatePricingPlan,
  users,
  apiTokens,
  tokenSettings,
  videoHistory,
  autoRetrySettings,
  planAvailability,
  appSettings,
  toolMaintenance,
  creditsSnapshots,
  characters,
  adminMessages,
  userReadMessages,
  resellers,
  resellerCreditLedger,
  resellerUsers,
  flowCookies,
  communityVoices,
  communityVoiceLikes,
  pricingPlans,
} from "@shared/schema";
import { db } from "./db";
import { eq, and, desc, sql, notInArray, inArray, isNotNull, ne, gt } from "drizzle-orm";
import bcrypt from "bcrypt";

const SALT_ROUNDS = 10;

// Token error tracking: tokenId -> array of error timestamps (for logging only, no cooldown)
const tokenErrorTracking = new Map<string, number[]>();

const ERROR_THRESHOLD = 10; // For logging purposes only
const ERROR_WINDOW_MS = 20 * 60 * 1000; // 20 minutes in milliseconds

// Storage interface for user operations
export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;
  createUser(user: InsertUser): Promise<User>;
  deleteUser(userId: string): Promise<void>;
  updateUserPlan(userId: string, plan: UpdateUserPlan): Promise<User | undefined>;
  removePlan(userId: string): Promise<User | undefined>;
  updateUserApiToken(userId: string, token: UpdateUserApiToken): Promise<User | undefined>;
  incrementDailyVideoCount(userId: string): Promise<void>;
  resetDailyVideoCount(userId: string): Promise<void>;
  checkAndResetDailyCounts(): Promise<void>;
  // Voice character tracking
  incrementVoiceCharacters(userId: string, charCount: number): Promise<void>;
  resetVoiceCharacters(userId: string, resetDate: string): Promise<void>;
  checkAndResetVoiceCharacters(userId: string): Promise<User | undefined>;
  verifyPassword(user: User, password: string): Promise<boolean>;
  initializeDefaultAdmin(): Promise<void>;
  updateUserIp(userId: string, ip1: string | null, ip2: string | null): Promise<User | undefined>;
  deactivateUserAccount(userId: string): Promise<User | undefined>;
  reactivateUserAccount(userId: string): Promise<User | undefined>;
  extendAllUsersExpiry(days: number): Promise<number>;
  
  // Token pool management
  getAllApiTokens(): Promise<ApiToken[]>;
  getActiveApiTokens(): Promise<ApiToken[]>;
  addApiToken(token: InsertApiToken): Promise<ApiToken>;
  deleteApiToken(tokenId: string): Promise<void>;
  toggleApiTokenStatus(tokenId: string, isActive: boolean): Promise<ApiToken | undefined>;
  getNextRotationToken(excludeTokenId?: string): Promise<ApiToken | undefined>;
  getTokenById(tokenId: string): Promise<ApiToken | undefined>;
  getTokenByIndex(index: number): Promise<ApiToken | undefined>;
  updateTokenUsage(tokenId: string): Promise<void>;
  replaceAllTokens(tokens: string[]): Promise<ApiToken[]>;
  recordTokenError(tokenId: string): void;
  isTokenInCooldown(tokenId: string): boolean;
  
  // Token settings
  getTokenSettings(): Promise<TokenSettings | undefined>;
  updateTokenSettings(settings: UpdateTokenSettings): Promise<TokenSettings>;
  initializeTokenSettings(): Promise<void>;
  
  // Video history
  getUserVideoHistory(userId: string, limit?: number): Promise<VideoHistory[]>;
  getAllUsersVideoStats(): Promise<Map<string, { completed: number; failed: number; pending: number; total: number }>>;
  getVideoById(videoId: string): Promise<VideoHistory | undefined>;
  addVideoHistory(video: InsertVideoHistory): Promise<VideoHistory>;
  updateVideoHistoryStatus(videoId: string, userId: string, status: string, videoUrl?: string, errorMessage?: string): Promise<VideoHistory | undefined>;
  updateVideoHistoryFields(videoId: string, fields: Partial<VideoHistory>): Promise<VideoHistory | undefined>;
  batchUpdateVideoStatus(updates: Array<{videoId: string, status: string, videoUrl?: string, errorMessage?: string}>): Promise<void>;
  batchCancelVideos(userId: string, videoIds: string[], reason: string): Promise<number>;
  getPendingVideosForUser(userId: string): Promise<VideoHistory[]>;
  getAllPendingVideos(): Promise<VideoHistory[]>; // Get all pending videos across all users
  
  // Auto-retry settings
  getAutoRetrySettings(): Promise<AutoRetrySettings | undefined>;
  updateAutoRetrySettings(settings: UpdateAutoRetrySettings): Promise<AutoRetrySettings>;
  initializeAutoRetrySettings(): Promise<void>;
  getEligibleFailedVideosForRetry(): Promise<VideoHistory[]>;
  markVideoAsRetrying(videoId: string): Promise<VideoHistory | undefined>;
  
  // Plan availability
  getPlanAvailability(): Promise<PlanAvailability | undefined>;
  updatePlanAvailability(availability: UpdatePlanAvailability): Promise<PlanAvailability>;
  initializePlanAvailability(): Promise<void>;
  
  // App settings
  getAppSettings(): Promise<AppSettings | undefined>;
  updateAppSettings(settings: UpdateAppSettings): Promise<AppSettings>;
  initializeAppSettings(): Promise<void>;
  incrementTotalVideosGenerated(): Promise<number>; // Increment and return new count
  incrementTotalVideosGeneratedBy(amount: number): Promise<number>; // Increment by specific amount (for daily auto-increment)
  getTotalVideosGenerated(): Promise<number>; // Get current count
  
  // Tool maintenance
  getToolMaintenance(): Promise<ToolMaintenance | undefined>;
  updateToolMaintenance(maintenance: UpdateToolMaintenance): Promise<ToolMaintenance>;
  initializeToolMaintenance(): Promise<void>;
  
  // Credits snapshots (admin-only)
  getLatestCreditsSnapshot(): Promise<CreditsSnapshot | undefined>;
  getRecentCreditsSnapshots(limit: number): Promise<CreditsSnapshot[]>;
  addCreditsSnapshot(remainingCredits: number, source: string): Promise<CreditsSnapshot>;
  
  // Character management
  getUserCharacters(userId: string): Promise<Character[]>;
  getCharacterById(characterId: string): Promise<Character | undefined>;
  addCharacter(character: InsertCharacter): Promise<Character>;
  deleteCharacter(characterId: string, userId: string): Promise<void>;
  
  // Admin messages
  getAllAdminMessages(): Promise<AdminMessage[]>;
  getActiveAdminMessages(): Promise<AdminMessage[]>;
  getAdminMessageById(messageId: string): Promise<AdminMessage | undefined>;
  createAdminMessage(title: string, message: string): Promise<AdminMessage>;
  updateAdminMessage(messageId: string, title: string, message: string, isActive: boolean): Promise<AdminMessage | undefined>;
  deleteAdminMessage(messageId: string): Promise<void>;
  toggleAdminMessageStatus(messageId: string, isActive: boolean): Promise<AdminMessage | undefined>;
  getUnreadMessagesCount(userId: string): Promise<number>;
  markMessageAsRead(userId: string, messageId: string): Promise<void>;
  markAllMessagesAsRead(userId: string): Promise<void>;
  getUserReadMessageIds(userId: string): Promise<string[]>;
  
  // Reseller management
  getAllResellers(): Promise<Reseller[]>;
  getResellerById(resellerId: string): Promise<Reseller | undefined>;
  getResellerByUsername(username: string): Promise<Reseller | undefined>;
  createReseller(reseller: InsertReseller): Promise<Reseller>;
  updateResellerCredits(resellerId: string, creditChange: number, reason: string): Promise<Reseller | undefined>;
  toggleResellerStatus(resellerId: string, isActive: boolean): Promise<Reseller | undefined>;
  deleteReseller(resellerId: string): Promise<void>;
  verifyResellerPassword(reseller: Reseller, password: string): Promise<boolean>;
  getResellerCreditLedger(resellerId: string): Promise<ResellerCreditLedger[]>;
  getResellerUsers(resellerId: string): Promise<(ResellerUser & { user: { username: string; isAccountActive: boolean } })[]>;
  createUserByReseller(resellerId: string, userData: ResellerCreateUser): Promise<{ user: User; resellerUser: ResellerUser }>;
  
  // Flow Cookies management
  getAllFlowCookies(): Promise<FlowCookie[]>;
  getActiveFlowCookies(): Promise<FlowCookie[]>;
  getFlowCookieById(cookieId: string): Promise<FlowCookie | undefined>;
  addFlowCookie(label: string, cookieData: string): Promise<FlowCookie>;
  updateFlowCookie(cookieId: string, updates: UpdateFlowCookie): Promise<FlowCookie | undefined>;
  deleteFlowCookie(cookieId: string): Promise<void>;
  toggleFlowCookieStatus(cookieId: string, isActive: boolean): Promise<FlowCookie | undefined>;
  bulkAddFlowCookies(cookiesText: string): Promise<FlowCookie[]>;
  getNextFlowCookie(): Promise<FlowCookie | undefined>;
  recordFlowCookieSuccess(cookieId: string): Promise<void>;
  recordFlowCookieFailure(cookieId: string): Promise<void>;
  recordFlowCookieExpired(cookieId: string): Promise<void>;
  deleteAllFlowCookies(): Promise<number>;
  
  // Community Voices
  getAllCommunityVoices(): Promise<CommunityVoice[]>;
  getCommunityVoiceById(voiceId: string): Promise<CommunityVoice | undefined>;
  createCommunityVoice(voice: InsertCommunityVoice, userId: string, creatorName: string): Promise<CommunityVoice>;
  deleteCommunityVoice(voiceId: string): Promise<void>;
  getTopCommunityVoices(limit: number): Promise<CommunityVoice[]>;
  toggleCommunityVoiceLike(voiceId: string, userId: string): Promise<{ liked: boolean; likesCount: number }>;
  hasUserLikedVoice(voiceId: string, userId: string): Promise<boolean>;
  getUserLikedVoiceIds(userId: string): Promise<string[]>;
  
  // Pricing Plans
  getAllPricingPlans(): Promise<PricingPlan[]>;
  getActivePricingPlans(): Promise<PricingPlan[]>;
  getPricingPlanById(planId: string): Promise<PricingPlan | undefined>;
  createPricingPlan(plan: InsertPricingPlan): Promise<PricingPlan>;
  updatePricingPlan(planId: string, updates: UpdatePricingPlan): Promise<PricingPlan | undefined>;
  deletePricingPlan(planId: string): Promise<void>;
  reorderPricingPlans(planIds: string[]): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async getAllUsers(): Promise<User[]> {
    return await db.select().from(users);
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const hashedPassword = await bcrypt.hash(insertUser.password, SALT_ROUNDS);
    
    // Calculate plan expiry if plan is assigned
    let planExpiry = null;
    let planStartDate = null;
    let dailyVideoLimit = null;
    let bulkMaxBatch = null;
    let bulkDelaySeconds = null;
    let bulkMaxPrompts = null;
    
    if (insertUser.planType && insertUser.planType !== "free") {
      planStartDate = new Date().toISOString();
      const expiryDate = new Date();
      
      // For enterprise, use custom expiry days if provided, otherwise default to 30 days
      // For scale/empire, default to 10 days
      if (insertUser.planType === "enterprise") {
        const expiryDays = insertUser.expiryDays || 30;
        expiryDate.setDate(expiryDate.getDate() + expiryDays);
        // Set custom daily video limit for enterprise users
        dailyVideoLimit = insertUser.dailyVideoLimit ?? null;
        // Set custom bulk settings for enterprise users
        bulkMaxBatch = insertUser.bulkMaxBatch ?? null;
        bulkDelaySeconds = insertUser.bulkDelaySeconds ?? null;
        bulkMaxPrompts = insertUser.bulkMaxPrompts ?? null;
      } else {
        expiryDate.setDate(expiryDate.getDate() + 10);
      }
      
      planExpiry = expiryDate.toISOString();
    }
    
    const [user] = await db
      .insert(users)
      .values({
        username: insertUser.username,
        password: hashedPassword,
        isAdmin: insertUser.isAdmin ?? false,
        planType: insertUser.planType || "free",
        planStartDate: planStartDate,
        planExpiry: planExpiry,
        dailyVideoLimit: dailyVideoLimit,
        bulkMaxBatch: bulkMaxBatch,
        bulkDelaySeconds: bulkDelaySeconds,
        bulkMaxPrompts: bulkMaxPrompts,
        dailyResetDate: new Date().toISOString(),
      })
      .returning();
    return user;
  }

  async deleteUser(userId: string): Promise<void> {
    // Use transaction to nullify/delete all dependent records before deleting user
    await db.transaction(async (tx) => {
      // Nullify user_id in tables with nullable foreign keys (preserves history)
      // Using raw SQL to handle tables that may or may not exist
      
      try {
        await tx.execute(sql`UPDATE video_history SET user_id = NULL WHERE user_id = ${userId}::uuid`);
        console.log(`[Delete User] Nullified video_history for user ${userId}`);
      } catch (e) {
        console.log(`[Delete User] video_history update skipped: ${e}`);
      }
      
      try {
        await tx.execute(sql`UPDATE image_history SET user_id = NULL WHERE user_id = ${userId}::uuid`);
        console.log(`[Delete User] Nullified image_history for user ${userId}`);
      } catch (e) {
        console.log(`[Delete User] image_history update skipped: ${e}`);
      }
      
      try {
        await tx.execute(sql`DELETE FROM characters WHERE user_id = ${userId}::uuid`);
        console.log(`[Delete User] Deleted characters for user ${userId}`);
      } catch (e) {
        console.log(`[Delete User] characters delete skipped: ${e}`);
      }
      
      try {
        await tx.execute(sql`DELETE FROM user_read_messages WHERE user_id = ${userId}::uuid`);
        console.log(`[Delete User] Deleted user_read_messages for user ${userId}`);
      } catch (e) {
        console.log(`[Delete User] user_read_messages delete skipped: ${e}`);
      }
      
      try {
        await tx.execute(sql`UPDATE reseller_users SET user_id = NULL WHERE user_id = ${userId}::uuid`);
        console.log(`[Delete User] Nullified reseller_users for user ${userId}`);
      } catch (e) {
        console.log(`[Delete User] reseller_users update skipped: ${e}`);
      }
      
      // Finally delete the user
      await tx.execute(sql`DELETE FROM users WHERE id = ${userId}::uuid`);
      console.log(`[Delete User] Deleted user ${userId}`);
    });
  }

  async updateUserPlan(userId: string, plan: UpdateUserPlan): Promise<User | undefined> {
    try {
      // Get the current user to preserve existing values if not provided
      const currentUser = await this.getUser(userId);
      if (!currentUser) {
        return undefined;
      }

      // Use provided values or keep existing, only auto-generate for new non-free plans
      let planStartDate = plan.planStartDate && plan.planStartDate.trim() !== "" 
        ? plan.planStartDate 
        : currentUser.planStartDate;
      
      let planExpiry = plan.planExpiry && plan.planExpiry.trim() !== "" 
        ? plan.planExpiry 
        : currentUser.planExpiry;
      
      // Handle expiryDays for enterprise users - recalculate planExpiry from today
      if (plan.planType === "enterprise" && plan.expiryDays) {
        planStartDate = new Date().toISOString();
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + plan.expiryDays);
        planExpiry = expiryDate.toISOString();
      }
      // Only auto-set dates when switching to a paid plan from free AND no dates exist
      else if (plan.planType !== "free" && currentUser.planType === "free" && !planStartDate && !planExpiry) {
        planStartDate = new Date().toISOString();
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 10);
        planExpiry = expiryDate.toISOString();
      }
      
      // Handle dailyVideoLimit for enterprise users
      const dailyVideoLimit = plan.planType === "enterprise" 
        ? (plan.dailyVideoLimit ?? currentUser.dailyVideoLimit) 
        : null;
      
      // Handle bulk settings for enterprise users
      const bulkMaxBatch = plan.planType === "enterprise" 
        ? (plan.bulkMaxBatch ?? currentUser.bulkMaxBatch) 
        : null;
      const bulkDelaySeconds = plan.planType === "enterprise" 
        ? (plan.bulkDelaySeconds ?? currentUser.bulkDelaySeconds) 
        : null;
      const bulkMaxPrompts = plan.planType === "enterprise" 
        ? (plan.bulkMaxPrompts ?? currentUser.bulkMaxPrompts) 
        : null;
      
      const [updatedUser] = await db
        .update(users)
        .set({
          planType: plan.planType,
          planStatus: plan.planStatus,
          planStartDate: planStartDate,
          planExpiry: planExpiry,
          dailyVideoLimit: dailyVideoLimit,
          bulkMaxBatch: bulkMaxBatch,
          bulkDelaySeconds: bulkDelaySeconds,
          bulkMaxPrompts: bulkMaxPrompts,
        })
        .where(eq(users.id, userId))
        .returning();
      
      return updatedUser || undefined;
    } catch (error) {
      console.error("Error updating user plan:", error);
      throw error;
    }
  }

  async removePlan(userId: string): Promise<User | undefined> {
    try {
      const [updatedUser] = await db
        .update(users)
        .set({
          planType: "free",
          planStatus: "active", // Free users remain active
          planStartDate: null,
          planExpiry: null,
          dailyVideoCount: 0,
          dailyResetDate: new Date().toISOString(),
        })
        .where(eq(users.id, userId))
        .returning();
      
      return updatedUser || undefined;
    } catch (error) {
      console.error("Error removing user plan:", error);
      throw error;
    }
  }

  async updateUserApiToken(userId: string, token: UpdateUserApiToken): Promise<User | undefined> {
    try {
      const [updatedUser] = await db
        .update(users)
        .set({
          apiToken: token.apiToken,
        })
        .where(eq(users.id, userId))
        .returning();
      
      return updatedUser || undefined;
    } catch (error) {
      console.error("Error updating user API token:", error);
      throw error;
    }
  }

  async updateUserIp(userId: string, ip1: string | null, ip2: string | null): Promise<User | undefined> {
    try {
      const [updatedUser] = await db
        .update(users)
        .set({
          allowedIp1: ip1,
          allowedIp2: ip2,
        })
        .where(eq(users.id, userId))
        .returning();
      
      return updatedUser || undefined;
    } catch (error) {
      console.error("Error updating user IP:", error);
      throw error;
    }
  }

  async deactivateUserAccount(userId: string): Promise<User | undefined> {
    try {
      const [updatedUser] = await db
        .update(users)
        .set({
          isAccountActive: false,
        })
        .where(eq(users.id, userId))
        .returning();
      
      return updatedUser || undefined;
    } catch (error) {
      console.error("Error deactivating user account:", error);
      throw error;
    }
  }

  async reactivateUserAccount(userId: string): Promise<User | undefined> {
    try {
      const [updatedUser] = await db
        .update(users)
        .set({
          isAccountActive: true,
          allowedIp1: null,
          allowedIp2: null,
        })
        .where(eq(users.id, userId))
        .returning();
      
      return updatedUser || undefined;
    } catch (error) {
      console.error("Error reactivating user account:", error);
      throw error;
    }
  }

  async extendAllUsersExpiry(days: number): Promise<number> {
    try {
      // Get all users with a plan expiry date
      const allUsers = await db.select().from(users);
      let updatedCount = 0;
      
      for (const user of allUsers) {
        if (user.planExpiry) {
          const currentExpiry = new Date(user.planExpiry);
          currentExpiry.setDate(currentExpiry.getDate() + days);
          
          await db
            .update(users)
            .set({ planExpiry: currentExpiry.toISOString() })
            .where(eq(users.id, user.id));
          
          updatedCount++;
        }
      }
      
      return updatedCount;
    } catch (error) {
      console.error("Error extending all users expiry:", error);
      throw error;
    }
  }

  async incrementDailyVideoCount(userId: string): Promise<void> {
    // Use atomic SQL increment to avoid race conditions
    await db
      .update(users)
      .set({ dailyVideoCount: sql`${users.dailyVideoCount} + 1` })
      .where(eq(users.id, userId));
  }

  async resetDailyVideoCount(userId: string): Promise<void> {
    await db
      .update(users)
      .set({
        dailyVideoCount: 0,
        dailyResetDate: new Date().toISOString(),
      })
      .where(eq(users.id, userId));
  }

  async checkAndResetDailyCounts(): Promise<void> {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    
    // Reset all users whose dailyResetDate is before today
    // This query is more efficient than fetching all users
    await db
      .update(users)
      .set({
        dailyVideoCount: 0,
        dailyResetDate: today,
      })
      .where(sql`daily_reset_date < ${today} OR daily_reset_date IS NULL`);
  }

  // Voice character tracking methods
  async incrementVoiceCharacters(userId: string, charCount: number): Promise<void> {
    await db
      .update(users)
      .set({ voiceCharactersUsed: sql`${users.voiceCharactersUsed} + ${charCount}` })
      .where(eq(users.id, userId));
  }

  async resetVoiceCharacters(userId: string, resetDate: string): Promise<void> {
    await db
      .update(users)
      .set({
        voiceCharactersUsed: 0,
        voiceCharactersResetDate: resetDate,
      })
      .where(eq(users.id, userId));
  }

  async checkAndResetVoiceCharacters(userId: string): Promise<User | undefined> {
    const user = await this.getUser(userId);
    if (!user) return undefined;
    
    // Check if reset is needed
    if (!user.voiceCharactersResetDate) {
      // Initialize reset date (10 days from now)
      const resetDate = new Date();
      resetDate.setDate(resetDate.getDate() + 10);
      await this.resetVoiceCharacters(userId, resetDate.toISOString());
      return await this.getUser(userId);
    }
    
    const resetDate = new Date(user.voiceCharactersResetDate);
    const now = new Date();
    
    if (now >= resetDate) {
      // Reset voice characters and set new reset date (10 days from now)
      const newResetDate = new Date();
      newResetDate.setDate(newResetDate.getDate() + 10);
      await this.resetVoiceCharacters(userId, newResetDate.toISOString());
      return await this.getUser(userId);
    }
    
    return user;
  }

  async verifyPassword(user: User, password: string): Promise<boolean> {
    return await bcrypt.compare(password, user.password);
  }

  async initializeDefaultAdmin(): Promise<void> {
    try {
      // Check if default admin already exists
      const existingAdmin = await this.getUserByUsername("muzi");
      
      if (!existingAdmin) {
        // Create default admin user
        const hashedPassword = await bcrypt.hash("muzi123", SALT_ROUNDS);
        await db.insert(users).values({
          username: "muzi",
          password: hashedPassword,
          isAdmin: true,
          planType: "free",
          planStatus: "active",
        });
        console.log("✓ Default admin user created (username: muzi, password: muzi123)");
      }
    } catch (error) {
      // If unique constraint error, admin already exists (race condition)
      if (error && typeof error === 'object' && 'code' in error && error.code === '23505') {
        console.log("✓ Default admin user already exists");
      } else {
        console.error("Error initializing default admin:", error);
        throw error;
      }
    }
  }

  // Token pool management methods
  async getAllApiTokens(): Promise<ApiToken[]> {
    return await db.select().from(apiTokens).orderBy(desc(apiTokens.createdAt));
  }

  async getActiveApiTokens(): Promise<ApiToken[]> {
    // Order by lastUsedAt (ascending) so least recently used tokens come first
    return await db
      .select()
      .from(apiTokens)
      .where(eq(apiTokens.isActive, true))
      .orderBy(apiTokens.lastUsedAt);
  }

  async addApiToken(token: InsertApiToken): Promise<ApiToken> {
    const [newToken] = await db.insert(apiTokens).values(token).returning();
    return newToken;
  }

  async deleteApiToken(tokenId: string): Promise<void> {
    await db.delete(apiTokens).where(eq(apiTokens.id, tokenId));
  }

  async toggleApiTokenStatus(tokenId: string, isActive: boolean): Promise<ApiToken | undefined> {
    const [updatedToken] = await db
      .update(apiTokens)
      .set({ isActive })
      .where(eq(apiTokens.id, tokenId))
      .returning();
    return updatedToken || undefined;
  }

  async getNextRotationToken(excludeTokenId?: string): Promise<ApiToken | undefined> {
    // Get active tokens ordered by least recently used
    const tokens = await db
      .select()
      .from(apiTokens)
      .where(eq(apiTokens.isActive, true))
      .orderBy(apiTokens.lastUsedAt);
    
    for (const token of tokens) {
      // Skip the excluded token (used for auto-retry with different token)
      if (excludeTokenId && token.id === excludeTokenId) {
        console.log(`[Token Rotation] Skipping token ${token.id} - excluded for retry`);
        continue;
      }
      
      return token;
    }
    
    console.log('[Token Rotation] No active tokens available');
    return undefined;
  }

  async getTokenById(tokenId: string): Promise<ApiToken | undefined> {
    const [token] = await db
      .select()
      .from(apiTokens)
      .where(eq(apiTokens.id, tokenId));
    return token || undefined;
  }

  async getTokenByIndex(index: number): Promise<ApiToken | undefined> {
    // Get all active tokens in consistent order (by creation time)
    const tokens = await db
      .select()
      .from(apiTokens)
      .where(eq(apiTokens.isActive, true))
      .orderBy(apiTokens.createdAt);
    
    if (tokens.length === 0) {
      console.log('[Token Rotation] No active tokens available');
      return undefined;
    }
    
    // Round-robin: select token by index modulo number of tokens
    const selectedToken = tokens[index % tokens.length];
    console.log(`[Token Rotation] Selected token ${selectedToken.label} (index ${index} % ${tokens.length} tokens = ${index % tokens.length})`);
    
    return selectedToken;
  }

  async updateTokenUsage(tokenId: string): Promise<void> {
    const token = await db.select().from(apiTokens).where(eq(apiTokens.id, tokenId));
    if (token[0]) {
      const currentCount = parseInt(token[0].requestCount || "0");
      await db
        .update(apiTokens)
        .set({
          lastUsedAt: new Date().toISOString(),
          requestCount: (currentCount + 1).toString(),
        })
        .where(eq(apiTokens.id, tokenId));
    }
  }

  async replaceAllTokens(tokens: string[]): Promise<ApiToken[]> {
    // Validate input
    if (tokens.length === 0) {
      throw new Error("Cannot replace tokens with empty array - at least one token required");
    }
    
    // Check for duplicates in input
    const uniqueTokens = new Set(tokens);
    if (uniqueTokens.size !== tokens.length) {
      throw new Error("Duplicate tokens found in input");
    }
    
    // Execute deletion and insertion in a single transaction
    return await db.transaction(async (tx) => {
      // STEP 1: Nullify ALL foreign key references to api_tokens FIRST
      // This is CRITICAL to avoid foreign key constraint violations
      // Using raw SQL to ensure ALL rows are updated (Drizzle ORM sometimes misses)
      
      // 1a. Nullify tokenUsed in video_history using RAW SQL
      await tx.execute(sql`UPDATE video_history SET token_used = NULL WHERE token_used IS NOT NULL`);
      console.log('[Bulk Replace] Nullified tokenUsed in video_history (raw SQL)');
      
      // 1b. Nullify tokenUsed in image_history using RAW SQL
      await tx.execute(sql`UPDATE image_history SET token_used = NULL WHERE token_used IS NOT NULL`);
      console.log('[Bulk Replace] Nullified tokenUsed in image_history (raw SQL)');
      
      // 1c. Nullify uploadTokenId in characters using RAW SQL
      await tx.execute(sql`UPDATE characters SET upload_token_id = NULL WHERE upload_token_id IS NOT NULL`);
      console.log('[Bulk Replace] Nullified uploadTokenId in characters (raw SQL)');
      
      // STEP 2: Check for existing characters and delete them
      const existingCharacters = await tx
        .select()
        .from(characters);
      
      console.log(`[Bulk Replace] Found ${existingCharacters.length} total characters`);
      
      // CRITICAL: VEO API requires same token for upload AND generation
      // Cannot remap characters to new tokens - they must be re-uploaded
      // So we delete all existing characters during bulk replace
      if (existingCharacters.length > 0) {
        await tx.delete(characters);
        console.log(`[Bulk Replace] ⚠️  DELETED ${existingCharacters.length} characters - VEO API requires same token for upload and generation`);
        console.log('[Bulk Replace] Users must re-upload characters with new tokens');
      }
      
      // STEP 3: Now safely delete all existing tokens (no more FK references)
      await tx.delete(apiTokens);
      
      console.log('[Bulk Replace] Deleted all old tokens');
      
      // Add all new tokens with auto-generated labels
      const newTokens: ApiToken[] = [];
      for (let i = 0; i < tokens.length; i++) {
        const [token] = await tx
          .insert(apiTokens)
          .values({
            token: tokens[i],
            label: `Token ${i + 1}`,
            isActive: true,
          })
          .returning();
        newTokens.push(token);
      }
      
      console.log(`[Bulk Replace] Added ${newTokens.length} new tokens`);
      
      return newTokens;
    });
  }

  recordTokenError(tokenId: string): void {
    const now = Date.now();
    
    // Get or initialize error array for this token
    const errors = tokenErrorTracking.get(tokenId) || [];
    
    // Add new error timestamp
    errors.push(now);
    
    // Remove errors older than ERROR_WINDOW_MS (20 minutes)
    const recentErrors = errors.filter(timestamp => now - timestamp < ERROR_WINDOW_MS);
    
    tokenErrorTracking.set(tokenId, recentErrors);
    
    // Log error count (no cooldown - tokens remain active)
    console.log(`[Token Error Tracking] Recorded error for token ${tokenId}. ${recentErrors.length} errors in last 20 minutes`);
  }

  isTokenInCooldown(tokenId: string): boolean {
    // Cooldown disabled - tokens are always available
    return false;
  }

  getRecentErrorCount(tokenId: string): number {
    const errors = tokenErrorTracking.get(tokenId) || [];
    const now = Date.now();
    
    // Count errors within the last 20 minutes
    const recentErrors = errors.filter(timestamp => now - timestamp < ERROR_WINDOW_MS);
    return recentErrors.length;
  }

  // Token settings methods
  async getTokenSettings(): Promise<TokenSettings | undefined> {
    const [settings] = await db.select().from(tokenSettings).limit(1);
    return settings || undefined;
  }

  async updateTokenSettings(settings: UpdateTokenSettings): Promise<TokenSettings> {
    const existing = await this.getTokenSettings();
    
    if (existing) {
      const [updated] = await db
        .update(tokenSettings)
        .set(settings)
        .where(eq(tokenSettings.id, existing.id))
        .returning();
      return updated;
    } else {
      const [newSettings] = await db.insert(tokenSettings).values(settings).returning();
      return newSettings;
    }
  }

  async initializeTokenSettings(): Promise<void> {
    // Use fixed singleton ID to ensure only one token_settings row exists
    const SINGLETON_ID = '00000000-0000-0000-0000-000000000001';
    
    try {
      // Clean up any legacy rows with random IDs first
      await db.execute(sql`
        DELETE FROM token_settings WHERE id != ${SINGLETON_ID}
      `);
      
      // Insert singleton row (safe if already exists)
      await db.execute(sql`
        INSERT INTO token_settings (id, rotation_enabled, rotation_interval_minutes, max_requests_per_token, videos_per_batch, batch_delay_seconds, next_rotation_index)
        VALUES (${SINGLETON_ID}, false, '60', '1000', '10', '20', 0)
        ON CONFLICT (id) DO NOTHING
      `);
    } catch (error) {
      // Safe to ignore - settings already initialized or permission error
      console.log('Token settings initialization completed or already exists');
    }
  }

  /**
   * Atomically get and increment the rotation index for round-robin token assignment
   * Uses atomic SQL to prevent race conditions with concurrent batches
   * Returns the STARTING index for this batch (before increment)
   */
  async getAndIncrementRotationIndex(incrementBy: number, totalTokens: number): Promise<number> {
    // Input validation: prevent division by zero and invalid parameters
    if (totalTokens <= 0) {
      throw new Error(`totalTokens must be positive, got: ${totalTokens}`);
    }
    if (incrementBy <= 0) {
      throw new Error(`incrementBy must be positive, got: ${incrementBy}`);
    }
    
    // Ensure settings exist first (uses INSERT ... ON CONFLICT for safety)
    await this.initializeTokenSettings();
    
    // Use fixed singleton ID for deterministic row selection
    const SINGLETON_ID = '00000000-0000-0000-0000-000000000001';
    
    // Atomic SQL: UPDATE with modulo arithmetic and RETURNING
    // Double-modulo pattern: ((x - y) % n + n) % n ensures non-negative result
    // This handles all edge cases including incrementBy >= totalTokens
    const result = await db.execute(sql`
      UPDATE token_settings
      SET next_rotation_index = (next_rotation_index + ${incrementBy}) % ${totalTokens}
      WHERE id = ${SINGLETON_ID}
      RETURNING ((next_rotation_index - ${incrementBy}) % ${totalTokens} + ${totalTokens}) % ${totalTokens} AS start_index
    `);
    
    if (!result.rows || result.rows.length === 0) {
      throw new Error('Failed to atomically update rotation index - no settings row found');
    }
    
    // Robust type coercion: handle string/bigint/Buffer from different Postgres drivers
    const rawStartIndex = (result.rows[0] as any).start_index;
    const startIndex = Number.parseInt(String(rawStartIndex), 10);
    
    if (Number.isNaN(startIndex) || startIndex < 0) {
      throw new Error(`Invalid rotation index returned: ${rawStartIndex} (parsed as ${startIndex})`);
    }
    
    return startIndex;
  }

  // Video history methods
  async getUserVideoHistory(userId: string, limit: number = 100): Promise<VideoHistory[]> {
    // Optimized: filter deleted videos in query, use index on user_id + created_at
    return await db
      .select()
      .from(videoHistory)
      .where(and(
        eq(videoHistory.userId, userId),
        eq(videoHistory.deletedByUser, false)
      ))
      .orderBy(desc(videoHistory.createdAt))
      .limit(limit);
  }
  
  // Batch update multiple video statuses in single query
  async batchUpdateVideoStatus(updates: Array<{videoId: string, status: string, videoUrl?: string, errorMessage?: string}>): Promise<void> {
    if (updates.length === 0) return;
    
    const now = new Date().toISOString();
    
    // Use Promise.all for parallel updates but with batched approach
    const batchSize = 20;
    for (let i = 0; i < updates.length; i += batchSize) {
      const batch = updates.slice(i, i + batchSize);
      await Promise.all(batch.map(async (update) => {
        const setFields: any = {
          status: update.status,
          updatedAt: now
        };
        if (update.videoUrl) setFields.videoUrl = update.videoUrl;
        if (update.errorMessage) setFields.errorMessage = update.errorMessage;
        
        await db
          .update(videoHistory)
          .set(setFields)
          .where(eq(videoHistory.id, update.videoId));
      }));
    }
  }
  
  // Cancel all pending/processing/uploading videos for a user (batch cancellation)
  async batchCancelVideos(userId: string, videoIds: string[], reason: string): Promise<number> {
    if (videoIds.length === 0) return 0;
    
    const now = new Date().toISOString();
    
    // Update all videos that are not already completed/failed
    const result = await db
      .update(videoHistory)
      .set({ 
        status: 'failed',
        errorMessage: reason,
        updatedAt: now
      })
      .where(and(
        eq(videoHistory.userId, userId),
        inArray(videoHistory.id, videoIds),
        ne(videoHistory.status, 'completed'),
        ne(videoHistory.status, 'failed')
      ));
    
    return videoIds.length;
  }

  // Get only pending videos for status check (optimized)
  async getPendingVideosForUser(userId: string): Promise<VideoHistory[]> {
    return await db
      .select()
      .from(videoHistory)
      .where(and(
        eq(videoHistory.userId, userId),
        eq(videoHistory.status, 'pending'),
        eq(videoHistory.deletedByUser, false)
      ))
      .orderBy(desc(videoHistory.updatedAt))
      .limit(100);
  }

  // Get all pending videos across ALL users (for recovery after server restart)
  // Only get videos created in the last 15 minutes to avoid recovering old stuck videos
  async getAllPendingVideos(): Promise<VideoHistory[]> {
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    
    return await db
      .select()
      .from(videoHistory)
      .where(and(
        eq(videoHistory.status, 'pending'),
        eq(videoHistory.deletedByUser, false),
        gt(videoHistory.createdAt, fifteenMinutesAgo) // Only recent videos (last 15 min)
      ))
      .orderBy(videoHistory.createdAt)
      .limit(500); // Limit to prevent memory issues
  }

  async getAllUsersVideoStats(): Promise<Map<string, { completed: number; failed: number; pending: number; total: number }>> {
    // Single efficient SQL query to get all users' video statistics
    const result = await db.execute(sql`
      SELECT 
        user_id,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
        SUM(CASE WHEN status IN ('pending', 'queued', 'retrying') THEN 1 ELSE 0 END) as pending
      FROM video_history
      GROUP BY user_id
    `);
    
    const statsMap = new Map<string, { completed: number; failed: number; pending: number; total: number }>();
    
    for (const row of result.rows) {
      const r = row as any;
      statsMap.set(r.user_id, {
        total: Number(r.total) || 0,
        completed: Number(r.completed) || 0,
        failed: Number(r.failed) || 0,
        pending: Number(r.pending) || 0,
      });
    }
    
    return statsMap;
  }

  async getVideoById(videoId: string): Promise<VideoHistory | undefined> {
    const [video] = await db
      .select()
      .from(videoHistory)
      .where(eq(videoHistory.id, videoId))
      .limit(1);
    return video || undefined;
  }

  async addVideoHistory(video: InsertVideoHistory): Promise<VideoHistory> {
    const [newVideo] = await db
      .insert(videoHistory)
      .values(video)
      .returning();
    return newVideo;
  }

  async updateVideoHistoryStatus(
    videoId: string,
    userId: string,
    status: string,
    videoUrl?: string,
    errorMessage?: string
  ): Promise<VideoHistory | undefined> {
    // Get current status before update to check if this is a new completion
    const currentVideo = await this.getVideoById(videoId);
    const wasNotCompleted = currentVideo && currentVideo.status !== 'completed';
    
    const updateData: Partial<VideoHistory> = { 
      status,
      updatedAt: sql`now()::text` as any
    };
    if (videoUrl) {
      updateData.videoUrl = videoUrl;
    }
    if (errorMessage) {
      updateData.errorMessage = errorMessage;
    }

    const [updated] = await db
      .update(videoHistory)
      .set(updateData)
      .where(and(eq(videoHistory.id, videoId), eq(videoHistory.userId, userId)))
      .returning();
    
    // Increment daily video count ONLY when video completes successfully
    // This ensures failed videos don't count toward daily limit
    if (updated && status === 'completed') {
      await this.incrementDailyVideoCount(userId);
      console.log(`[Storage] ✅ Video ${videoId} completed - Daily count incremented for user ${userId}`);
      
      // Also increment total videos counter (permanent, never resets)
      if (wasNotCompleted) {
        await this.incrementTotalVideosGenerated();
        console.log(`[Storage] Total videos counter incremented for video ${videoId}`);
      }
    }
    
    return updated || undefined;
  }

  async updateVideoHistoryFields(
    videoId: string,
    fields: Partial<VideoHistory>
  ): Promise<VideoHistory | undefined> {
    // Get current status before update to check if this is a new completion
    const currentVideo = await this.getVideoById(videoId);
    const wasNotCompleted = currentVideo && currentVideo.status !== 'completed';
    const isNowCompleted = fields.status === 'completed';
    
    const [updated] = await db
      .update(videoHistory)
      .set({ ...fields, updatedAt: sql`now()::text` as any })
      .where(eq(videoHistory.id, videoId))
      .returning();
    
    // Increment total videos counter when a video is newly completed
    if (updated && wasNotCompleted && isNowCompleted) {
      await this.incrementTotalVideosGenerated();
      console.log(`[Storage] Total videos counter incremented for video ${videoId}`);
    }
    
    return updated || undefined;
  }

  async clearAllVideoHistory(): Promise<void> {
    await db.delete(videoHistory);
  }

  async deleteVideoHistoryById(videoId: string): Promise<boolean> {
    const result = await db.delete(videoHistory).where(eq(videoHistory.id, videoId)).returning();
    return result.length > 0;
  }

  // Auto-retry settings methods
  async getAutoRetrySettings(): Promise<AutoRetrySettings | undefined> {
    const [settings] = await db.select().from(autoRetrySettings).limit(1);
    return settings || undefined;
  }

  async updateAutoRetrySettings(settings: UpdateAutoRetrySettings): Promise<AutoRetrySettings> {
    const existing = await this.getAutoRetrySettings();
    
    if (existing) {
      const [updated] = await db
        .update(autoRetrySettings)
        .set({ ...settings, updatedAt: sql`now()::text` as any })
        .where(eq(autoRetrySettings.id, existing.id))
        .returning();
      return updated;
    } else {
      const [newSettings] = await db.insert(autoRetrySettings).values(settings).returning();
      return newSettings;
    }
  }

  async initializeAutoRetrySettings(): Promise<void> {
    const existing = await this.getAutoRetrySettings();
    if (!existing) {
      await db.insert(autoRetrySettings).values({});
      console.log("✓ Auto-retry settings initialized");
    }
  }

  async getEligibleFailedVideosForRetry(): Promise<VideoHistory[]> {
    const settings = await this.getAutoRetrySettings();
    
    if (!settings || !settings.enableAutoRetry) {
      return [];
    }

    const delayMinutes = settings.retryDelayMinutes;
    const maxRetryAttempts = settings.maxRetryAttempts;
    
    const eligibleVideos = await db
      .select()
      .from(videoHistory)
      .where(
        and(
          eq(videoHistory.status, 'failed'),
          sql`${videoHistory.retryCount} < ${maxRetryAttempts}`,
          sql`(
            ${videoHistory.lastRetryAt} IS NULL 
            OR CAST(${videoHistory.lastRetryAt} AS timestamp) <= (now() - interval '${sql.raw(delayMinutes.toString())} minutes')
          )`,
          // Exclude merged videos (they have mergedVideoIds in metadata)
          sql`(${videoHistory.metadata} IS NULL OR ${videoHistory.metadata}->>'mergedVideoIds' IS NULL)`
        )
      )
      .orderBy(desc(videoHistory.createdAt))
      .limit(10);

    return eligibleVideos;
  }

  async markVideoAsRetrying(videoId: string): Promise<VideoHistory | undefined> {
    const [updated] = await db
      .update(videoHistory)
      .set({ 
        status: 'retrying',
        retryCount: sql`${videoHistory.retryCount} + 1`,
        lastRetryAt: sql`now()::text`,
        updatedAt: sql`now()::text`
      } as any)
      .where(eq(videoHistory.id, videoId))
      .returning();
    return updated || undefined;
  }

  // Plan availability methods
  async getPlanAvailability(): Promise<PlanAvailability | undefined> {
    const [availability] = await db.select().from(planAvailability).limit(1);
    return availability || undefined;
  }

  async updatePlanAvailability(availability: UpdatePlanAvailability): Promise<PlanAvailability> {
    const existing = await this.getPlanAvailability();
    
    if (existing) {
      const [updated] = await db
        .update(planAvailability)
        .set({ ...availability, updatedAt: sql`now()::text` as any })
        .where(eq(planAvailability.id, existing.id))
        .returning();
      return updated;
    } else {
      const [newAvailability] = await db.insert(planAvailability).values(availability).returning();
      return newAvailability;
    }
  }

  async initializePlanAvailability(): Promise<void> {
    const existing = await this.getPlanAvailability();
    if (!existing) {
      await db.insert(planAvailability).values({});
      console.log("✓ Plan availability settings initialized");
    }
  }

  // App settings methods
  async getAppSettings(): Promise<AppSettings | undefined> {
    const [settings] = await db.select().from(appSettings).limit(1);
    return settings || undefined;
  }

  async updateAppSettings(settings: UpdateAppSettings): Promise<AppSettings> {
    const existing = await this.getAppSettings();
    
    if (existing) {
      const [updated] = await db
        .update(appSettings)
        .set({ ...settings, updatedAt: sql`now()::text` as any })
        .where(eq(appSettings.id, existing.id))
        .returning();
      return updated;
    } else {
      const [newSettings] = await db.insert(appSettings).values(settings).returning();
      return newSettings;
    }
  }

  async initializeAppSettings(): Promise<void> {
    const existing = await this.getAppSettings();
    if (!existing) {
      await db.insert(appSettings).values({});
      console.log("✓ App settings initialized");
    }
  }

  async incrementTotalVideosGenerated(): Promise<number> {
    const existing = await this.getAppSettings();
    if (existing) {
      const newCount = (existing.totalVideosGenerated || 0) + 1;
      await db
        .update(appSettings)
        .set({ totalVideosGenerated: newCount })
        .where(eq(appSettings.id, existing.id));
      return newCount;
    }
    return 0;
  }

  async incrementTotalVideosGeneratedBy(amount: number): Promise<number> {
    const existing = await this.getAppSettings();
    if (existing) {
      const newCount = (existing.totalVideosGenerated || 0) + amount;
      await db
        .update(appSettings)
        .set({ totalVideosGenerated: newCount })
        .where(eq(appSettings.id, existing.id));
      return newCount;
    }
    return 0;
  }

  async getTotalVideosGenerated(): Promise<number> {
    const settings = await this.getAppSettings();
    return settings?.totalVideosGenerated || 0;
  }

  // Tool maintenance methods
  async getToolMaintenance(): Promise<ToolMaintenance | undefined> {
    const [maintenance] = await db.select().from(toolMaintenance).limit(1);
    return maintenance || undefined;
  }

  async updateToolMaintenance(maintenance: UpdateToolMaintenance): Promise<ToolMaintenance> {
    const existing = await this.getToolMaintenance();
    
    if (existing) {
      const [updated] = await db
        .update(toolMaintenance)
        .set({ ...maintenance, updatedAt: sql`now()::text` as any })
        .where(eq(toolMaintenance.id, existing.id))
        .returning();
      return updated;
    } else {
      const [newMaintenance] = await db.insert(toolMaintenance).values(maintenance).returning();
      return newMaintenance;
    }
  }

  async initializeToolMaintenance(): Promise<void> {
    const existing = await this.getToolMaintenance();
    if (!existing) {
      await db.insert(toolMaintenance).values({});
      console.log("✓ Tool maintenance settings initialized");
    }
  }

  // Credits snapshot methods (admin-only)
  async getLatestCreditsSnapshot(): Promise<CreditsSnapshot | undefined> {
    const [snapshot] = await db
      .select()
      .from(creditsSnapshots)
      .orderBy(desc(creditsSnapshots.recordedAt))
      .limit(1);
    return snapshot || undefined;
  }

  async getRecentCreditsSnapshots(limit: number): Promise<CreditsSnapshot[]> {
    return await db
      .select()
      .from(creditsSnapshots)
      .orderBy(desc(creditsSnapshots.recordedAt))
      .limit(limit);
  }

  async addCreditsSnapshot(remainingCredits: number, source: string, tokenId?: string): Promise<CreditsSnapshot> {
    const [snapshot] = await db
      .insert(creditsSnapshots)
      .values({ remainingCredits, source, tokenId: tokenId || null })
      .returning();
    return snapshot;
  }
  
  async getLatestCreditsSnapshotByToken(tokenId: string): Promise<CreditsSnapshot | undefined> {
    const snapshots = await db
      .select()
      .from(creditsSnapshots)
      .where(eq(creditsSnapshots.tokenId, tokenId))
      .orderBy(desc(creditsSnapshots.recordedAt))
      .limit(1);
    return snapshots[0];
  }
  
  async getLatestCreditsSnapshotsPerToken(): Promise<CreditsSnapshot[]> {
    // Get the most recent snapshot for each unique tokenId
    const result = await db.execute(sql`
      SELECT DISTINCT ON (token_id) *
      FROM credits_snapshots
      WHERE token_id IS NOT NULL
      ORDER BY token_id, recorded_at DESC
    `);
    return result.rows as CreditsSnapshot[];
  }

  // Character management methods
  async getUserCharacters(userId: string): Promise<Character[]> {
    return await db
      .select()
      .from(characters)
      .where(eq(characters.userId, userId))
      .orderBy(desc(characters.createdAt));
  }

  async getCharacterById(characterId: string): Promise<Character | undefined> {
    const [character] = await db
      .select()
      .from(characters)
      .where(eq(characters.id, characterId));
    return character || undefined;
  }

  async addCharacter(insertCharacter: InsertCharacter): Promise<Character> {
    const [character] = await db
      .insert(characters)
      .values(insertCharacter)
      .returning();
    return character;
  }

  async deleteCharacter(characterId: string, userId: string): Promise<void> {
    await db
      .delete(characters)
      .where(and(
        eq(characters.id, characterId),
        eq(characters.userId, userId)
      ));
  }

  // Admin messages methods
  async getAllAdminMessages(): Promise<AdminMessage[]> {
    return await db
      .select()
      .from(adminMessages)
      .orderBy(desc(adminMessages.createdAt));
  }

  async getActiveAdminMessages(): Promise<AdminMessage[]> {
    return await db
      .select()
      .from(adminMessages)
      .where(eq(adminMessages.isActive, true))
      .orderBy(desc(adminMessages.createdAt));
  }

  async getAdminMessageById(messageId: string): Promise<AdminMessage | undefined> {
    const [message] = await db
      .select()
      .from(adminMessages)
      .where(eq(adminMessages.id, messageId));
    return message || undefined;
  }

  async createAdminMessage(title: string, message: string): Promise<AdminMessage> {
    const [newMessage] = await db
      .insert(adminMessages)
      .values({ title, message, isActive: true })
      .returning();
    return newMessage;
  }

  async updateAdminMessage(messageId: string, title: string, message: string, isActive: boolean): Promise<AdminMessage | undefined> {
    const [updatedMessage] = await db
      .update(adminMessages)
      .set({ title, message, isActive })
      .where(eq(adminMessages.id, messageId))
      .returning();
    return updatedMessage || undefined;
  }

  async deleteAdminMessage(messageId: string): Promise<void> {
    // First delete all read records for this message
    await db.delete(userReadMessages).where(eq(userReadMessages.messageId, messageId));
    // Then delete the message
    await db.delete(adminMessages).where(eq(adminMessages.id, messageId));
  }

  async toggleAdminMessageStatus(messageId: string, isActive: boolean): Promise<AdminMessage | undefined> {
    const [updatedMessage] = await db
      .update(adminMessages)
      .set({ isActive })
      .where(eq(adminMessages.id, messageId))
      .returning();
    return updatedMessage || undefined;
  }

  async getUnreadMessagesCount(userId: string): Promise<number> {
    // Get all active messages
    const activeMessages = await this.getActiveAdminMessages();
    // Get all read message IDs for this user
    const readMessageIds = await this.getUserReadMessageIds(userId);
    // Count unread
    const unreadCount = activeMessages.filter(msg => !readMessageIds.includes(msg.id)).length;
    return unreadCount;
  }

  async markMessageAsRead(userId: string, messageId: string): Promise<void> {
    // Check if already marked as read
    const [existing] = await db
      .select()
      .from(userReadMessages)
      .where(and(
        eq(userReadMessages.userId, userId),
        eq(userReadMessages.messageId, messageId)
      ));
    
    if (!existing) {
      await db.insert(userReadMessages).values({ userId, messageId });
    }
  }

  async markAllMessagesAsRead(userId: string): Promise<void> {
    const activeMessages = await this.getActiveAdminMessages();
    const readMessageIds = await this.getUserReadMessageIds(userId);
    
    // Insert read records for all unread messages
    const unreadMessages = activeMessages.filter(msg => !readMessageIds.includes(msg.id));
    for (const msg of unreadMessages) {
      await db.insert(userReadMessages).values({ userId, messageId: msg.id });
    }
  }

  async getUserReadMessageIds(userId: string): Promise<string[]> {
    const readRecords = await db
      .select({ messageId: userReadMessages.messageId })
      .from(userReadMessages)
      .where(eq(userReadMessages.userId, userId));
    return readRecords.map(r => r.messageId);
  }

  // Reseller management methods
  async getAllResellers(): Promise<Reseller[]> {
    return await db
      .select()
      .from(resellers)
      .orderBy(desc(resellers.createdAt));
  }

  async getResellerById(resellerId: string): Promise<Reseller | undefined> {
    const [reseller] = await db
      .select()
      .from(resellers)
      .where(eq(resellers.id, resellerId));
    return reseller || undefined;
  }

  async getResellerByUsername(username: string): Promise<Reseller | undefined> {
    const [reseller] = await db
      .select()
      .from(resellers)
      .where(eq(resellers.username, username));
    return reseller || undefined;
  }

  async createReseller(insertReseller: InsertReseller): Promise<Reseller> {
    const hashedPassword = await bcrypt.hash(insertReseller.password, SALT_ROUNDS);
    const initialCredits = insertReseller.creditBalance ?? 0;
    
    const [reseller] = await db
      .insert(resellers)
      .values({
        username: insertReseller.username,
        password: hashedPassword,
        creditBalance: initialCredits,
        isActive: true,
      })
      .returning();
    
    // Add initial credit ledger entry if credits were assigned
    if (initialCredits > 0) {
      await db.insert(resellerCreditLedger).values({
        resellerId: reseller.id,
        creditChange: initialCredits,
        balanceAfter: initialCredits,
        reason: "Initial credits assigned by admin",
      });
    }
    
    return reseller;
  }

  async updateResellerCredits(resellerId: string, creditChange: number, reason: string): Promise<Reseller | undefined> {
    const reseller = await this.getResellerById(resellerId);
    if (!reseller) return undefined;
    
    const newBalance = reseller.creditBalance + creditChange;
    if (newBalance < 0) {
      throw new Error("Insufficient credits");
    }
    
    const [updatedReseller] = await db
      .update(resellers)
      .set({ creditBalance: newBalance })
      .where(eq(resellers.id, resellerId))
      .returning();
    
    // Add ledger entry
    await db.insert(resellerCreditLedger).values({
      resellerId,
      creditChange,
      balanceAfter: newBalance,
      reason,
    });
    
    return updatedReseller || undefined;
  }

  async toggleResellerStatus(resellerId: string, isActive: boolean): Promise<Reseller | undefined> {
    const [updatedReseller] = await db
      .update(resellers)
      .set({ isActive })
      .where(eq(resellers.id, resellerId))
      .returning();
    return updatedReseller || undefined;
  }

  async deleteReseller(resellerId: string): Promise<void> {
    // Delete ledger entries first
    await db.delete(resellerCreditLedger).where(eq(resellerCreditLedger.resellerId, resellerId));
    // Delete reseller user links (not the actual users)
    await db.delete(resellerUsers).where(eq(resellerUsers.resellerId, resellerId));
    // Delete the reseller
    await db.delete(resellers).where(eq(resellers.id, resellerId));
  }

  async verifyResellerPassword(reseller: Reseller, password: string): Promise<boolean> {
    return await bcrypt.compare(password, reseller.password);
  }

  async getResellerCreditLedger(resellerId: string): Promise<ResellerCreditLedger[]> {
    return await db
      .select()
      .from(resellerCreditLedger)
      .where(eq(resellerCreditLedger.resellerId, resellerId))
      .orderBy(desc(resellerCreditLedger.createdAt));
  }

  async getResellerUsers(resellerId: string): Promise<(ResellerUser & { user: { username: string; isAccountActive: boolean } })[]> {
    const result = await db
      .select({
        id: resellerUsers.id,
        resellerId: resellerUsers.resellerId,
        userId: resellerUsers.userId,
        planType: resellerUsers.planType,
        creditCost: resellerUsers.creditCost,
        createdAt: resellerUsers.createdAt,
        username: users.username,
        isAccountActive: users.isAccountActive,
      })
      .from(resellerUsers)
      .innerJoin(users, eq(resellerUsers.userId, users.id))
      .where(eq(resellerUsers.resellerId, resellerId))
      .orderBy(desc(resellerUsers.createdAt));
    
    return result.map(row => ({
      id: row.id,
      resellerId: row.resellerId,
      userId: row.userId,
      planType: row.planType,
      creditCost: row.creditCost,
      createdAt: row.createdAt,
      user: {
        username: row.username,
        isAccountActive: row.isAccountActive,
      }
    }));
  }

  async createUserByReseller(resellerId: string, userData: ResellerCreateUser): Promise<{ user: User; resellerUser: ResellerUser }> {
    const reseller = await this.getResellerById(resellerId);
    if (!reseller) {
      throw new Error("Reseller not found");
    }
    if (!reseller.isActive) {
      throw new Error("Reseller account is inactive");
    }

    // Calculate credit cost
    const creditCost = userData.planType === "empire" ? 1500 : 900;
    
    // Check if reseller has enough credits
    if (reseller.creditBalance < creditCost) {
      throw new Error(`Insufficient credits. Need ${creditCost}, have ${reseller.creditBalance}`);
    }

    // Check if username already exists
    const existingUser = await this.getUserByUsername(userData.username);
    if (existingUser) {
      throw new Error("Username already exists");
    }

    // Create the user
    const hashedPassword = await bcrypt.hash(userData.password, SALT_ROUNDS);
    const planStartDate = new Date().toISOString();
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 10);
    const planExpiry = expiryDate.toISOString();

    const [user] = await db
      .insert(users)
      .values({
        username: userData.username,
        password: hashedPassword,
        isAdmin: false,
        planType: userData.planType,
        planStatus: "active",
        planStartDate,
        planExpiry,
        dailyResetDate: new Date().toISOString(),
      })
      .returning();

    // Create reseller user link
    const [resellerUser] = await db
      .insert(resellerUsers)
      .values({
        resellerId,
        userId: user.id,
        planType: userData.planType,
        creditCost,
      })
      .returning();

    // Deduct credits from reseller
    const newBalance = reseller.creditBalance - creditCost;
    await db
      .update(resellers)
      .set({ creditBalance: newBalance })
      .where(eq(resellers.id, resellerId));

    // Add ledger entry
    await db.insert(resellerCreditLedger).values({
      resellerId,
      creditChange: -creditCost,
      balanceAfter: newBalance,
      reason: `Created ${userData.planType} user: ${userData.username}`,
    });

    return { user, resellerUser };
  }

  // Flow Cookies management
  async getAllFlowCookies(): Promise<FlowCookie[]> {
    return await db.select().from(flowCookies).orderBy(desc(flowCookies.createdAt));
  }

  async getActiveFlowCookies(): Promise<FlowCookie[]> {
    return await db.select().from(flowCookies).where(eq(flowCookies.isActive, true)).orderBy(desc(flowCookies.createdAt));
  }

  async getFlowCookieById(cookieId: string): Promise<FlowCookie | undefined> {
    const [cookie] = await db.select().from(flowCookies).where(eq(flowCookies.id, cookieId));
    return cookie || undefined;
  }

  async addFlowCookie(label: string, cookieData: string): Promise<FlowCookie> {
    const [cookie] = await db
      .insert(flowCookies)
      .values({ label, cookieData })
      .returning();
    return cookie;
  }

  async updateFlowCookie(cookieId: string, updates: UpdateFlowCookie): Promise<FlowCookie | undefined> {
    const [cookie] = await db
      .update(flowCookies)
      .set(updates)
      .where(eq(flowCookies.id, cookieId))
      .returning();
    return cookie || undefined;
  }

  async deleteFlowCookie(cookieId: string): Promise<void> {
    await db.delete(flowCookies).where(eq(flowCookies.id, cookieId));
  }

  async toggleFlowCookieStatus(cookieId: string, isActive: boolean): Promise<FlowCookie | undefined> {
    const [cookie] = await db
      .update(flowCookies)
      .set({ isActive })
      .where(eq(flowCookies.id, cookieId))
      .returning();
    return cookie || undefined;
  }

  async bulkAddFlowCookies(cookiesText: string): Promise<FlowCookie[]> {
    const lines = cookiesText.split('\n').filter(line => line.trim());
    const addedCookies: FlowCookie[] = [];
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      
      let label: string;
      let cookieData: string;
      
      // Check if format is: email|[JSON cookies]
      if (line.includes('|[')) {
        const pipeIndex = line.indexOf('|');
        label = line.substring(0, pipeIndex).trim();
        cookieData = line.substring(pipeIndex + 1).trim();
      } else {
        // Fallback to old format (just cookie data, auto-generate label)
        label = `Account ${i + 1}`;
        cookieData = line;
      }
      
      if (cookieData) {
        const cookie = await this.addFlowCookie(label, cookieData);
        addedCookies.push(cookie);
      }
    }
    
    return addedCookies;
  }

  async getNextFlowCookie(): Promise<FlowCookie | undefined> {
    // Get the active cookie with the oldest lastUsedAt (or null = never used)
    const cookies = await db
      .select()
      .from(flowCookies)
      .where(eq(flowCookies.isActive, true))
      .orderBy(flowCookies.lastUsedAt)
      .limit(1);
    
    if (cookies.length === 0) return undefined;
    
    // Update lastUsedAt
    const [updated] = await db
      .update(flowCookies)
      .set({ lastUsedAt: new Date().toISOString() })
      .where(eq(flowCookies.id, cookies[0].id))
      .returning();
    
    return updated;
  }

  async recordFlowCookieSuccess(cookieId: string): Promise<void> {
    await db
      .update(flowCookies)
      .set({ 
        successCount: sql`${flowCookies.successCount} + 1`,
        lastUsedAt: new Date().toISOString()
      })
      .where(eq(flowCookies.id, cookieId));
  }

  async recordFlowCookieFailure(cookieId: string): Promise<void> {
    await db
      .update(flowCookies)
      .set({ 
        failCount: sql`${flowCookies.failCount} + 1`,
        lastUsedAt: new Date().toISOString()
      })
      .where(eq(flowCookies.id, cookieId));
  }

  async recordFlowCookieExpired(cookieId: string): Promise<void> {
    await db
      .update(flowCookies)
      .set({ 
        expiredCount: sql`${flowCookies.expiredCount} + 1`,
        lastUsedAt: new Date().toISOString()
      })
      .where(eq(flowCookies.id, cookieId));
  }

  async deleteAllFlowCookies(): Promise<number> {
    const all = await db.select().from(flowCookies);
    await db.delete(flowCookies);
    return all.length;
  }

  // Community Voices implementation
  async getAllCommunityVoices(): Promise<CommunityVoice[]> {
    return await db.select().from(communityVoices).where(eq(communityVoices.isActive, true)).orderBy(desc(communityVoices.createdAt));
  }

  async getCommunityVoiceById(voiceId: string): Promise<CommunityVoice | undefined> {
    const [voice] = await db.select().from(communityVoices).where(eq(communityVoices.id, voiceId));
    return voice || undefined;
  }

  async createCommunityVoice(voice: InsertCommunityVoice, userId: string, creatorName: string): Promise<CommunityVoice> {
    const [newVoice] = await db.insert(communityVoices).values({
      name: voice.name,
      description: voice.description || null,
      language: voice.language,
      gender: voice.gender,
      creatorId: userId,
      creatorName: creatorName,
      demoAudioBase64: voice.demoAudioBase64,
      durationSeconds: voice.durationSeconds,
      fileSizeBytes: voice.fileSizeBytes,
    }).returning();
    return newVoice;
  }

  async deleteCommunityVoice(voiceId: string): Promise<void> {
    // Delete likes first
    await db.delete(communityVoiceLikes).where(eq(communityVoiceLikes.voiceId, voiceId));
    // Then delete voice
    await db.delete(communityVoices).where(eq(communityVoices.id, voiceId));
  }

  async getTopCommunityVoices(limit: number): Promise<CommunityVoice[]> {
    return await db.select().from(communityVoices).where(eq(communityVoices.isActive, true)).orderBy(desc(communityVoices.likesCount)).limit(limit);
  }

  async toggleCommunityVoiceLike(voiceId: string, userId: string): Promise<{ liked: boolean; likesCount: number }> {
    // Check if already liked
    const [existing] = await db.select().from(communityVoiceLikes).where(and(eq(communityVoiceLikes.voiceId, voiceId), eq(communityVoiceLikes.userId, userId)));
    
    if (existing) {
      // Unlike
      await db.delete(communityVoiceLikes).where(eq(communityVoiceLikes.id, existing.id));
      const [updated] = await db.update(communityVoices).set({ likesCount: sql`${communityVoices.likesCount} - 1` }).where(eq(communityVoices.id, voiceId)).returning();
      return { liked: false, likesCount: updated.likesCount };
    } else {
      // Like
      await db.insert(communityVoiceLikes).values({ voiceId, userId });
      const [updated] = await db.update(communityVoices).set({ likesCount: sql`${communityVoices.likesCount} + 1` }).where(eq(communityVoices.id, voiceId)).returning();
      return { liked: true, likesCount: updated.likesCount };
    }
  }

  async hasUserLikedVoice(voiceId: string, userId: string): Promise<boolean> {
    const [existing] = await db.select().from(communityVoiceLikes).where(and(eq(communityVoiceLikes.voiceId, voiceId), eq(communityVoiceLikes.userId, userId)));
    return !!existing;
  }

  async getUserLikedVoiceIds(userId: string): Promise<string[]> {
    const likes = await db.select().from(communityVoiceLikes).where(eq(communityVoiceLikes.userId, userId));
    return likes.map(l => l.voiceId);
  }

  // Pricing Plans implementation
  async getAllPricingPlans(): Promise<PricingPlan[]> {
    return await db.select().from(pricingPlans).orderBy(pricingPlans.position);
  }

  async getActivePricingPlans(): Promise<PricingPlan[]> {
    return await db.select().from(pricingPlans).where(eq(pricingPlans.isActive, true)).orderBy(pricingPlans.position);
  }

  async getPricingPlanById(planId: string): Promise<PricingPlan | undefined> {
    const [plan] = await db.select().from(pricingPlans).where(eq(pricingPlans.id, planId));
    return plan || undefined;
  }

  async createPricingPlan(plan: InsertPricingPlan): Promise<PricingPlan> {
    // Get the max position to add this plan at the end
    const allPlans = await db.select().from(pricingPlans);
    const maxPosition = allPlans.length > 0 ? Math.max(...allPlans.map(p => p.position)) + 1 : 0;
    
    const [newPlan] = await db.insert(pricingPlans).values({
      name: plan.name,
      subtitle: plan.subtitle || null,
      displayPrice: plan.displayPrice,
      currency: plan.currency || "PKR",
      period: plan.period || null,
      alternatePrice: plan.alternatePrice || null,
      badge: plan.badge || null,
      badgeColor: plan.badgeColor || "default",
      iconType: plan.iconType || "zap",
      highlightBorder: plan.highlightBorder || false,
      featuresIntro: plan.featuresIntro || null,
      features: plan.features || "[]",
      buttonText: plan.buttonText || "Get Started",
      buttonAction: plan.buttonAction || "payment_dialog",
      position: plan.position ?? maxPosition,
    }).returning();
    return newPlan;
  }

  async updatePricingPlan(planId: string, updates: UpdatePricingPlan): Promise<PricingPlan | undefined> {
    const updateData: any = { updatedAt: new Date().toISOString() };
    
    if (updates.name !== undefined) updateData.name = updates.name;
    if (updates.subtitle !== undefined) updateData.subtitle = updates.subtitle;
    if (updates.displayPrice !== undefined) updateData.displayPrice = updates.displayPrice;
    if (updates.currency !== undefined) updateData.currency = updates.currency;
    if (updates.period !== undefined) updateData.period = updates.period;
    if (updates.alternatePrice !== undefined) updateData.alternatePrice = updates.alternatePrice;
    if (updates.badge !== undefined) updateData.badge = updates.badge;
    if (updates.badgeColor !== undefined) updateData.badgeColor = updates.badgeColor;
    if (updates.iconType !== undefined) updateData.iconType = updates.iconType;
    if (updates.highlightBorder !== undefined) updateData.highlightBorder = updates.highlightBorder;
    if (updates.featuresIntro !== undefined) updateData.featuresIntro = updates.featuresIntro;
    if (updates.features !== undefined) updateData.features = updates.features;
    if (updates.buttonText !== undefined) updateData.buttonText = updates.buttonText;
    if (updates.buttonAction !== undefined) updateData.buttonAction = updates.buttonAction;
    if (updates.position !== undefined) updateData.position = updates.position;
    if (updates.isActive !== undefined) updateData.isActive = updates.isActive;
    
    const [updated] = await db.update(pricingPlans).set(updateData).where(eq(pricingPlans.id, planId)).returning();
    return updated || undefined;
  }

  async deletePricingPlan(planId: string): Promise<void> {
    await db.delete(pricingPlans).where(eq(pricingPlans.id, planId));
  }

  async reorderPricingPlans(planIds: string[]): Promise<void> {
    // Update positions based on array order
    for (let i = 0; i < planIds.length; i++) {
      await db.update(pricingPlans).set({ position: i, updatedAt: new Date().toISOString() }).where(eq(pricingPlans.id, planIds[i]));
    }
  }
}

export const storage = new DatabaseStorage();
