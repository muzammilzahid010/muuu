var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  adminMessages: () => adminMessages,
  apiTokens: () => apiTokens,
  appSettings: () => appSettings,
  autoRetrySettings: () => autoRetrySettings,
  bulkAddFlowCookiesSchema: () => bulkAddFlowCookiesSchema,
  bulkAddZyphraTokensSchema: () => bulkAddZyphraTokensSchema,
  bulkReplaceTokensSchema: () => bulkReplaceTokensSchema,
  characters: () => characters,
  communityVoiceLikes: () => communityVoiceLikes,
  communityVoices: () => communityVoices,
  creditsSnapshots: () => creditsSnapshots,
  flowCookies: () => flowCookies,
  imageHistory: () => imageHistory,
  insertAdminMessageSchema: () => insertAdminMessageSchema,
  insertApiTokenSchema: () => insertApiTokenSchema,
  insertCharacterSchema: () => insertCharacterSchema,
  insertCommunityVoiceSchema: () => insertCommunityVoiceSchema,
  insertFlowCookieSchema: () => insertFlowCookieSchema,
  insertPricingPlanSchema: () => insertPricingPlanSchema,
  insertResellerSchema: () => insertResellerSchema,
  insertTopVoiceSchema: () => insertTopVoiceSchema,
  insertUserSchema: () => insertUserSchema,
  insertVideoHistorySchema: () => insertVideoHistorySchema,
  insertZyphraTokenSchema: () => insertZyphraTokenSchema,
  loginSchema: () => loginSchema,
  planAvailability: () => planAvailability,
  pricingPlans: () => pricingPlans,
  resellerCreateUserSchema: () => resellerCreateUserSchema,
  resellerCreditLedger: () => resellerCreditLedger,
  resellerLoginSchema: () => resellerLoginSchema,
  resellerUsers: () => resellerUsers,
  resellers: () => resellers,
  tokenSettings: () => tokenSettings,
  toolMaintenance: () => toolMaintenance,
  topVoices: () => topVoices,
  updateAppSettingsSchema: () => updateAppSettingsSchema,
  updateAutoRetrySettingsSchema: () => updateAutoRetrySettingsSchema,
  updateFlowCookieSchema: () => updateFlowCookieSchema,
  updatePlanAvailabilitySchema: () => updatePlanAvailabilitySchema,
  updatePricingPlanSchema: () => updatePricingPlanSchema,
  updateResellerSchema: () => updateResellerSchema,
  updateTokenSettingsSchema: () => updateTokenSettingsSchema,
  updateToolMaintenanceSchema: () => updateToolMaintenanceSchema,
  updateTopVoiceSchema: () => updateTopVoiceSchema,
  updateUserApiTokenSchema: () => updateUserApiTokenSchema,
  updateUserPlanSchema: () => updateUserPlanSchema,
  updateZyphraTokenSchema: () => updateZyphraTokenSchema,
  userReadMessages: () => userReadMessages,
  users: () => users,
  videoHistory: () => videoHistory,
  zyphraTokens: () => zyphraTokens
});
import { sql } from "drizzle-orm";
import { pgTable, text, varchar, boolean, integer, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var users, insertUserSchema, updateUserPlanSchema, updateUserApiTokenSchema, loginSchema, apiTokens, tokenSettings, insertApiTokenSchema, bulkReplaceTokensSchema, updateTokenSettingsSchema, videoHistory, insertVideoHistorySchema, autoRetrySettings, updateAutoRetrySettingsSchema, planAvailability, updatePlanAvailabilitySchema, appSettings, updateAppSettingsSchema, toolMaintenance, updateToolMaintenanceSchema, creditsSnapshots, imageHistory, characters, insertCharacterSchema, adminMessages, insertAdminMessageSchema, userReadMessages, resellers, insertResellerSchema, updateResellerSchema, resellerCreditLedger, resellerUsers, resellerCreateUserSchema, resellerLoginSchema, flowCookies, insertFlowCookieSchema, updateFlowCookieSchema, bulkAddFlowCookiesSchema, zyphraTokens, insertZyphraTokenSchema, updateZyphraTokenSchema, bulkAddZyphraTokensSchema, topVoices, insertTopVoiceSchema, updateTopVoiceSchema, communityVoices, communityVoiceLikes, insertCommunityVoiceSchema, pricingPlans, insertPricingPlanSchema, updatePricingPlanSchema;
var init_schema = __esm({
  "shared/schema.ts"() {
    "use strict";
    users = pgTable("users", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      username: text("username").notNull().unique(),
      password: text("password").notNull(),
      isAdmin: boolean("is_admin").notNull().default(false),
      planType: text("plan_type").notNull().default("free"),
      planStatus: text("plan_status").notNull().default("active"),
      planStartDate: text("plan_start_date").default(sql`null`),
      planExpiry: text("plan_expiry").default(sql`null`),
      dailyVideoCount: integer("daily_video_count").notNull().default(0),
      dailyVideoLimit: integer("daily_video_limit"),
      // Custom limit for enterprise users (null = use default plan limits)
      bulkMaxBatch: integer("bulk_max_batch"),
      // Custom bulk batch size for enterprise users
      bulkDelaySeconds: integer("bulk_delay_seconds"),
      // Custom delay between batches for enterprise users
      bulkMaxPrompts: integer("bulk_max_prompts"),
      // Custom max prompts for enterprise users
      dailyResetDate: text("daily_reset_date").default(sql`null`),
      apiToken: text("api_token").default(sql`null`),
      allowedIp1: text("allowed_ip_1").default(sql`null`),
      allowedIp2: text("allowed_ip_2").default(sql`null`),
      isAccountActive: boolean("is_account_active").notNull().default(true),
      // 2FA fields for admin security
      twoFactorSecret: text("two_factor_secret").default(sql`null`),
      twoFactorEnabled: boolean("two_factor_enabled").notNull().default(false),
      // Voice character usage tracking (for Empire plan: 1M chars per 10 days)
      voiceCharactersUsed: integer("voice_characters_used").notNull().default(0),
      voiceCharactersResetDate: text("voice_characters_reset_date").default(sql`null`)
    });
    insertUserSchema = createInsertSchema(users).pick({
      username: true,
      password: true,
      isAdmin: true
    }).extend({
      planType: z.enum(["free", "scale", "empire", "enterprise"]).optional(),
      planStartDate: z.string().optional(),
      planExpiry: z.string().optional(),
      dailyVideoLimit: z.number().int().min(0).optional(),
      // Custom limit for enterprise users (0 = unlimited)
      expiryDays: z.number().int().min(1).optional(),
      // Custom expiry duration for enterprise users
      bulkMaxBatch: z.number().int().min(1).optional(),
      // Custom bulk batch size for enterprise users
      bulkDelaySeconds: z.number().int().min(0).optional(),
      // Custom delay between batches for enterprise users
      bulkMaxPrompts: z.number().int().min(1).optional()
      // Custom max prompts for enterprise users
    });
    updateUserPlanSchema = z.object({
      planType: z.enum(["free", "scale", "empire", "enterprise"]),
      planStatus: z.enum(["active", "expired", "cancelled"]),
      planStartDate: z.string().optional(),
      planExpiry: z.string().optional(),
      dailyVideoLimit: z.number().int().min(0).optional(),
      // Custom limit for enterprise users (0 = unlimited)
      expiryDays: z.number().int().min(1).optional(),
      // Custom expiry duration for enterprise users (recalculates planExpiry)
      bulkMaxBatch: z.number().int().min(1).optional(),
      // Custom bulk batch size for enterprise users
      bulkDelaySeconds: z.number().int().min(0).optional(),
      // Custom delay between batches for enterprise users
      bulkMaxPrompts: z.number().int().min(1).optional()
      // Custom max prompts for enterprise users
    });
    updateUserApiTokenSchema = z.object({
      apiToken: z.string()
    });
    loginSchema = z.object({
      username: z.string().min(1, "Username is required"),
      password: z.string().min(1, "Password is required")
    });
    apiTokens = pgTable("api_tokens", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      token: text("token").notNull().unique(),
      label: text("label").notNull(),
      isActive: boolean("is_active").notNull().default(true),
      lastUsedAt: text("last_used_at"),
      requestCount: text("request_count").notNull().default("0"),
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    tokenSettings = pgTable("token_settings", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      rotationEnabled: boolean("rotation_enabled").notNull().default(false),
      rotationIntervalMinutes: text("rotation_interval_minutes").notNull().default("60"),
      maxRequestsPerToken: text("max_requests_per_token").notNull().default("1000"),
      videosPerBatch: text("videos_per_batch").notNull().default("10"),
      batchDelaySeconds: text("batch_delay_seconds").notNull().default("20"),
      nextRotationIndex: integer("next_rotation_index").notNull().default(0)
      // Track which token to use next
    });
    insertApiTokenSchema = createInsertSchema(apiTokens).pick({
      token: true,
      label: true
    });
    bulkReplaceTokensSchema = z.object({
      tokens: z.string().min(1, "Please enter at least one token")
    });
    updateTokenSettingsSchema = z.object({
      rotationEnabled: z.boolean().optional(),
      rotationIntervalMinutes: z.string().optional(),
      maxRequestsPerToken: z.string().optional(),
      videosPerBatch: z.string().optional(),
      batchDelaySeconds: z.string().optional()
      // nextRotationIndex is INTERNAL ONLY - not exposed to admin panel
      // Only the rotation algorithm should update this field
    });
    videoHistory = pgTable("video_history", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      userId: varchar("user_id").notNull().references(() => users.id),
      prompt: text("prompt").notNull(),
      aspectRatio: text("aspect_ratio").notNull(),
      videoUrl: text("video_url"),
      status: text("status").notNull().default("pending"),
      createdAt: text("created_at").notNull().default(sql`now()::text`),
      updatedAt: text("updated_at").notNull().default(sql`now()::text`),
      title: text("title"),
      tokenUsed: varchar("token_used").references(() => apiTokens.id),
      metadata: text("metadata"),
      // JSON string for merge info: { mergedVideoIds: string[] }
      errorMessage: text("error_message"),
      // Store error details for failed videos
      referenceImageUrl: text("reference_image_url"),
      // Reference image for image-to-video generation
      retryCount: integer("retry_count").notNull().default(0),
      // Track auto-retry attempts
      lastRetryAt: text("last_retry_at"),
      // Last auto-retry timestamp
      deletedByUser: boolean("deleted_by_user").notNull().default(false),
      // Soft delete flag - hidden from user but visible to admin
      deletedAt: text("deleted_at"),
      // Timestamp when user deleted this video
      operationName: text("operation_name"),
      // VEO API operation name for status polling
      sceneId: text("scene_id")
      // VEO API scene ID for status polling
    }, (table) => [
      index("video_history_user_id_idx").on(table.userId),
      index("video_history_status_idx").on(table.status),
      index("video_history_created_at_idx").on(table.createdAt),
      index("video_history_user_status_idx").on(table.userId, table.status)
    ]);
    insertVideoHistorySchema = createInsertSchema(videoHistory).omit({
      id: true,
      createdAt: true,
      updatedAt: true
    });
    autoRetrySettings = pgTable("auto_retry_settings", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      enableAutoRetry: boolean("enable_auto_retry").notNull().default(false),
      maxRetryAttempts: integer("max_retry_attempts").notNull().default(3),
      retryDelayMinutes: integer("retry_delay_minutes").notNull().default(5),
      updatedAt: text("updated_at").notNull().default(sql`now()::text`)
    });
    updateAutoRetrySettingsSchema = z.object({
      enableAutoRetry: z.boolean(),
      maxRetryAttempts: z.number().int().min(1).max(10),
      retryDelayMinutes: z.number().int().min(1).max(60)
    });
    planAvailability = pgTable("plan_availability", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      scalePlanAvailable: boolean("scale_plan_available").notNull().default(true),
      empirePlanAvailable: boolean("empire_plan_available").notNull().default(true),
      updatedAt: text("updated_at").notNull().default(sql`now()::text`)
    });
    updatePlanAvailabilitySchema = z.object({
      scalePlanAvailable: z.boolean(),
      empirePlanAvailable: z.boolean()
    });
    appSettings = pgTable("app_settings", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      whatsappUrl: text("whatsapp_url").notNull().default("https://api.whatsapp.com/send?phone=&text=Contact Support"),
      scriptApiKey: text("script_api_key"),
      geminiApiKey: text("gemini_api_key"),
      // Gemini API key for script to image prompts
      cloudinaryCloudName: text("cloudinary_cloud_name").notNull().default("dfk0nvgff"),
      cloudinaryUploadPreset: text("cloudinary_upload_preset").notNull().default("demo123"),
      // Feature toggles
      enableVideoMerge: boolean("enable_video_merge").notNull().default(true),
      // Show/hide merge videos feature
      // Branding
      logoUrl: text("logo_url"),
      // Custom logo URL for the application
      // Stats tracking (never resets)
      totalVideosGenerated: integer("total_videos_generated").notNull().default(0),
      // Permanent counter for total videos
      // Browser Pool Settings
      browserPoolMaxContexts: integer("browser_pool_max_contexts").notNull().default(50),
      // Global max contexts
      browserPoolMaxPerUser: integer("browser_pool_max_per_user").notNull().default(5),
      // Per-user limit
      // Google Drive Settings (for video upload fallback)
      googleDriveCredentials: text("google_drive_credentials"),
      // Service account JSON
      googleDriveFolderId: text("google_drive_folder_id"),
      // Shared Drive or Folder ID for uploads
      // Storage method preference: "cloudinary", "google_drive", "cloudinary_with_fallback", or "direct_to_user"
      storageMethod: text("storage_method").notNull().default("cloudinary_with_fallback"),
      updatedAt: text("updated_at").notNull().default(sql`now()::text`)
    });
    updateAppSettingsSchema = z.object({
      whatsappUrl: z.string().url("Please enter a valid URL"),
      scriptApiKey: z.string().optional(),
      geminiApiKey: z.string().optional(),
      cloudinaryCloudName: z.string().min(1, "Cloudinary cloud name is required"),
      cloudinaryUploadPreset: z.string().min(1, "Cloudinary upload preset is required"),
      enableVideoMerge: z.boolean().optional(),
      logoUrl: z.string().optional(),
      browserPoolMaxContexts: z.number().int().min(1).max(200).optional(),
      browserPoolMaxPerUser: z.number().int().min(1).max(50).optional(),
      googleDriveCredentials: z.string().optional(),
      googleDriveFolderId: z.string().optional(),
      storageMethod: z.enum(["cloudinary", "google_drive", "cloudinary_with_fallback", "direct_to_user", "local_disk"]).optional()
    });
    toolMaintenance = pgTable("tool_maintenance", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      veoGeneratorActive: boolean("veo_generator_active").notNull().default(true),
      bulkGeneratorActive: boolean("bulk_generator_active").notNull().default(true),
      textToImageActive: boolean("text_to_image_active").notNull().default(true),
      imageToVideoActive: boolean("image_to_video_active").notNull().default(true),
      scriptCreatorActive: boolean("script_creator_active").notNull().default(true),
      characterConsistencyActive: boolean("character_consistency_active").notNull().default(true),
      updatedAt: text("updated_at").notNull().default(sql`now()::text`)
    });
    updateToolMaintenanceSchema = z.object({
      veoGeneratorActive: z.boolean(),
      bulkGeneratorActive: z.boolean(),
      textToImageActive: z.boolean(),
      imageToVideoActive: z.boolean(),
      scriptCreatorActive: z.boolean(),
      characterConsistencyActive: z.boolean()
    });
    creditsSnapshots = pgTable("credits_snapshots", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      remainingCredits: integer("remaining_credits").notNull(),
      tokenId: varchar("token_id"),
      // Which API token these credits belong to
      source: text("source").notNull(),
      // e.g., "manual_check", "veo_generation", "image_to_video"
      recordedAt: text("recorded_at").notNull().default(sql`now()::text`)
    });
    imageHistory = pgTable("image_history", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      userId: varchar("user_id").notNull().references(() => users.id),
      prompt: text("prompt").notNull(),
      aspectRatio: text("aspect_ratio").notNull(),
      model: text("model").notNull().default("whisk"),
      imageUrl: text("image_url"),
      status: text("status").notNull().default("pending"),
      createdAt: text("created_at").notNull().default(sql`now()::text`),
      errorMessage: text("error_message"),
      tokenUsed: varchar("token_used").references(() => apiTokens.id)
    });
    characters = pgTable("characters", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      userId: varchar("user_id").notNull().references(() => users.id),
      name: text("name").notNull(),
      characterType: text("character_type").notNull().default("image"),
      // 'image' or 'text'
      imageUrl: text("image_url"),
      // URL to stored character image (nullable for text-based characters)
      mediaId: text("media_id"),
      // Google AI media generation ID for reference (nullable for text-based characters)
      uploadTokenId: varchar("upload_token_id").references(() => apiTokens.id),
      // Token used to upload this image (nullable for text-based characters)
      description: text("description"),
      // Text description for text-based characters (nullable for image-based characters)
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    insertCharacterSchema = createInsertSchema(characters).omit({
      id: true,
      createdAt: true
    }).extend({
      characterType: z.enum(["image", "text"])
    }).refine(
      (data) => {
        if (data.characterType === "image") {
          return !!data.imageUrl && !!data.mediaId;
        }
        if (data.characterType === "text") {
          return !!data.description && data.description.trim().length > 0;
        }
        return false;
      },
      {
        message: "Image characters must have imageUrl and mediaId. Text characters must have description."
      }
    );
    adminMessages = pgTable("admin_messages", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      title: text("title").notNull(),
      message: text("message").notNull(),
      isActive: boolean("is_active").notNull().default(true),
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    insertAdminMessageSchema = createInsertSchema(adminMessages).omit({
      id: true,
      createdAt: true
    });
    userReadMessages = pgTable("user_read_messages", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      userId: varchar("user_id").notNull().references(() => users.id),
      messageId: varchar("message_id").notNull().references(() => adminMessages.id),
      readAt: text("read_at").notNull().default(sql`now()::text`)
    });
    resellers = pgTable("resellers", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      username: text("username").notNull().unique(),
      password: text("password").notNull(),
      creditBalance: integer("credit_balance").notNull().default(0),
      isActive: boolean("is_active").notNull().default(true),
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    insertResellerSchema = createInsertSchema(resellers).pick({
      username: true,
      password: true
    }).extend({
      creditBalance: z.number().int().min(0).optional()
    });
    updateResellerSchema = z.object({
      creditBalance: z.number().int().min(0).optional(),
      isActive: z.boolean().optional()
    });
    resellerCreditLedger = pgTable("reseller_credit_ledger", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      resellerId: varchar("reseller_id").notNull().references(() => resellers.id),
      creditChange: integer("credit_change").notNull(),
      // positive for additions, negative for deductions
      balanceAfter: integer("balance_after").notNull(),
      reason: text("reason").notNull(),
      // e.g., "Admin added credits", "Created Scale user: john123"
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    resellerUsers = pgTable("reseller_users", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      resellerId: varchar("reseller_id").notNull().references(() => resellers.id),
      userId: varchar("user_id").notNull().references(() => users.id),
      planType: text("plan_type").notNull(),
      // scale or empire
      creditCost: integer("credit_cost").notNull(),
      // 900 for scale, 1500 for empire
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    resellerCreateUserSchema = z.object({
      username: z.string().min(3, "Username must be at least 3 characters"),
      password: z.string().min(6, "Password must be at least 6 characters"),
      planType: z.enum(["scale", "empire"])
    });
    resellerLoginSchema = z.object({
      username: z.string().min(1, "Username is required"),
      password: z.string().min(1, "Password is required")
    });
    flowCookies = pgTable("flow_cookies", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      label: text("label").notNull(),
      cookieData: text("cookie_data").notNull(),
      // JSON string or semicolon-separated cookies
      isActive: boolean("is_active").notNull().default(true),
      lastUsedAt: text("last_used_at"),
      successCount: integer("success_count").notNull().default(0),
      failCount: integer("fail_count").notNull().default(0),
      expiredCount: integer("expired_count").notNull().default(0),
      // Track cookie expired errors
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    insertFlowCookieSchema = createInsertSchema(flowCookies).pick({
      label: true,
      cookieData: true
    });
    updateFlowCookieSchema = z.object({
      label: z.string().optional(),
      cookieData: z.string().optional(),
      isActive: z.boolean().optional()
    });
    bulkAddFlowCookiesSchema = z.object({
      cookies: z.string().min(1, "Please enter at least one cookie")
    });
    zyphraTokens = pgTable("zyphra_tokens", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      apiKey: text("api_key").notNull().unique(),
      label: text("label").notNull(),
      isActive: boolean("is_active").notNull().default(true),
      minutesUsed: integer("minutes_used").notNull().default(0),
      minutesLimit: integer("minutes_limit").notNull().default(100),
      lastUsedAt: text("last_used_at"),
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    insertZyphraTokenSchema = createInsertSchema(zyphraTokens).pick({
      apiKey: true,
      label: true,
      minutesLimit: true
    });
    updateZyphraTokenSchema = z.object({
      label: z.string().optional(),
      isActive: z.boolean().optional(),
      minutesUsed: z.number().int().min(0).optional(),
      minutesLimit: z.number().int().min(1).optional()
    });
    bulkAddZyphraTokensSchema = z.object({
      tokens: z.string().min(1, "Please enter at least one API key")
    });
    topVoices = pgTable("top_voices", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      name: text("name").notNull(),
      description: text("description"),
      demoAudioUrl: text("demo_audio_url").notNull(),
      demoAudioBase64: text("demo_audio_base64"),
      // For caching the demo audio
      isActive: boolean("is_active").notNull().default(true),
      sortOrder: integer("sort_order").notNull().default(0),
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    insertTopVoiceSchema = createInsertSchema(topVoices).pick({
      name: true,
      description: true,
      demoAudioUrl: true,
      demoAudioBase64: true,
      sortOrder: true
    });
    updateTopVoiceSchema = z.object({
      name: z.string().optional(),
      description: z.string().optional(),
      demoAudioUrl: z.string().optional(),
      demoAudioBase64: z.string().optional(),
      isActive: z.boolean().optional(),
      sortOrder: z.number().int().optional()
    });
    communityVoices = pgTable("community_voices", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      name: text("name").notNull(),
      description: text("description"),
      language: text("language").notNull().default("English"),
      gender: text("gender").notNull().default("Male"),
      creatorId: varchar("creator_id").notNull().references(() => users.id),
      creatorName: text("creator_name").notNull(),
      demoAudioBase64: text("demo_audio_base64").notNull(),
      durationSeconds: integer("duration_seconds").notNull(),
      fileSizeBytes: integer("file_size_bytes").notNull(),
      likesCount: integer("likes_count").notNull().default(0),
      isActive: boolean("is_active").notNull().default(true),
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    communityVoiceLikes = pgTable("community_voice_likes", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      voiceId: varchar("voice_id").notNull().references(() => communityVoices.id),
      userId: varchar("user_id").notNull().references(() => users.id),
      createdAt: text("created_at").notNull().default(sql`now()::text`)
    });
    insertCommunityVoiceSchema = createInsertSchema(communityVoices).pick({
      name: true,
      description: true,
      language: true,
      gender: true,
      demoAudioBase64: true,
      durationSeconds: true,
      fileSizeBytes: true
    }).extend({
      name: z.string().min(2, "Name must be at least 2 characters"),
      language: z.string().min(1, "Language is required"),
      gender: z.enum(["Male", "Female"]),
      demoAudioBase64: z.string().min(1, "Demo audio is required"),
      durationSeconds: z.number().min(10, "Audio must be at least 10 seconds"),
      fileSizeBytes: z.number().max(5 * 1024 * 1024, "File must be less than 5MB")
    });
    pricingPlans = pgTable("pricing_plans", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      name: text("name").notNull(),
      // e.g., "Scale", "Empire", "Enterprise"
      subtitle: text("subtitle"),
      // e.g., "For starters", "For professionals"
      displayPrice: text("display_price").notNull(),
      // e.g., "900", "1500", "Custom"
      currency: text("currency").notNull().default("PKR"),
      // e.g., "PKR", "USD"
      period: text("period"),
      // e.g., "per 10 days"
      alternatePrice: text("alternate_price"),
      // e.g., "$10 USD for International"
      badge: text("badge"),
      // e.g., "Popular", "Best Value"
      badgeColor: text("badge_color").default("default"),
      // e.g., "default", "orange", "purple"
      iconType: text("icon_type").notNull().default("zap"),
      // lucide icon name
      highlightBorder: boolean("highlight_border").notNull().default(false),
      featuresIntro: text("features_intro"),
      // e.g., "WHAT'S INCLUDED", "EVERYTHING IN SCALE, PLUS"
      features: text("features").notNull().default("[]"),
      // JSON array of feature objects
      buttonText: text("button_text").notNull().default("Get Started"),
      buttonAction: text("button_action").notNull().default("payment_dialog"),
      // payment_dialog, contact_sales, disabled
      position: integer("position").notNull().default(0),
      isActive: boolean("is_active").notNull().default(true),
      dailyCharactersLimit: integer("daily_characters_limit"),
      // Optional daily character limit for voice features
      createdAt: text("created_at").notNull().default(sql`now()::text`),
      updatedAt: text("updated_at").notNull().default(sql`now()::text`)
    });
    insertPricingPlanSchema = createInsertSchema(pricingPlans).pick({
      name: true,
      subtitle: true,
      displayPrice: true,
      currency: true,
      period: true,
      alternatePrice: true,
      badge: true,
      badgeColor: true,
      iconType: true,
      highlightBorder: true,
      featuresIntro: true,
      features: true,
      buttonText: true,
      buttonAction: true,
      position: true,
      dailyCharactersLimit: true
    }).extend({
      name: z.string().min(1, "Name is required"),
      displayPrice: z.string().min(1, "Price is required"),
      features: z.string().optional().default("[]"),
      dailyCharactersLimit: z.number().int().min(0).optional().nullable()
    });
    updatePricingPlanSchema = z.object({
      name: z.string().min(1).optional(),
      subtitle: z.string().optional(),
      displayPrice: z.string().optional(),
      currency: z.string().optional(),
      period: z.string().optional(),
      alternatePrice: z.string().optional(),
      badge: z.string().optional(),
      badgeColor: z.string().optional(),
      iconType: z.string().optional(),
      highlightBorder: z.boolean().optional(),
      featuresIntro: z.string().optional(),
      features: z.string().optional(),
      buttonText: z.string().optional(),
      buttonAction: z.string().optional(),
      position: z.number().int().optional(),
      isActive: z.boolean().optional(),
      dailyCharactersLimit: z.number().int().min(0).optional().nullable()
    });
  }
});

// server/db.ts
var db_exports = {};
__export(db_exports, {
  db: () => db,
  pool: () => pool,
  withRetry: () => withRetry
});
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
function getDatabaseUrl() {
  const { PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE, DATABASE_URL } = process.env;
  if (PGHOST && PGPORT && PGUSER && PGPASSWORD && PGDATABASE) {
    return `postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}?sslmode=require`;
  }
  if (DATABASE_URL) {
    return DATABASE_URL;
  }
  throw new Error(
    "Database configuration missing. Set DATABASE_URL or individual PG* variables."
  );
}
async function withRetry(operation, maxRetries = 3, delayMs = 1e3) {
  let lastError = null;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      const isTimeoutError = error.message?.includes("timeout") || error.message?.includes("connect");
      if (isTimeoutError && attempt < maxRetries) {
        console.log(`[DB Retry] Attempt ${attempt} failed, retrying in ${delayMs}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delayMs * attempt));
        continue;
      }
      throw error;
    }
  }
  throw lastError;
}
var databaseUrl, pool, db;
var init_db = __esm({
  "server/db.ts"() {
    "use strict";
    init_schema();
    neonConfig.webSocketConstructor = ws;
    neonConfig.pipelineConnect = false;
    neonConfig.useSecureWebSocket = true;
    neonConfig.wsProxy = (host) => host;
    databaseUrl = getDatabaseUrl();
    pool = new Pool({
      connectionString: databaseUrl,
      max: 50,
      // Increased from 20 to 50 connections
      idleTimeoutMillis: 6e4,
      // Keep idle connections longer (60s)
      connectionTimeoutMillis: 3e4
      // Wait longer for connection (30s for Asia latency)
    });
    db = drizzle({ client: pool, schema: schema_exports });
  }
});

// server/storage.ts
var storage_exports = {};
__export(storage_exports, {
  DatabaseStorage: () => DatabaseStorage,
  storage: () => storage
});
import { eq, and, desc, sql as sql2, inArray, ne, gt } from "drizzle-orm";
import bcrypt from "bcrypt";
var SALT_ROUNDS, tokenErrorTracking, ERROR_WINDOW_MS, DatabaseStorage, storage;
var init_storage = __esm({
  "server/storage.ts"() {
    "use strict";
    init_schema();
    init_db();
    SALT_ROUNDS = 10;
    tokenErrorTracking = /* @__PURE__ */ new Map();
    ERROR_WINDOW_MS = 20 * 60 * 1e3;
    DatabaseStorage = class {
      async getUser(id) {
        const [user] = await db.select().from(users).where(eq(users.id, id));
        return user || void 0;
      }
      async getUserByUsername(username) {
        const [user] = await db.select().from(users).where(eq(users.username, username));
        return user || void 0;
      }
      async getAllUsers() {
        return await db.select().from(users);
      }
      async createUser(insertUser) {
        const hashedPassword = await bcrypt.hash(insertUser.password, SALT_ROUNDS);
        let planExpiry = null;
        let planStartDate = null;
        let dailyVideoLimit = null;
        let bulkMaxBatch = null;
        let bulkDelaySeconds = null;
        let bulkMaxPrompts = null;
        if (insertUser.planType && insertUser.planType !== "free") {
          planStartDate = (/* @__PURE__ */ new Date()).toISOString();
          const expiryDate = /* @__PURE__ */ new Date();
          if (insertUser.planType === "enterprise") {
            const expiryDays = insertUser.expiryDays || 30;
            expiryDate.setDate(expiryDate.getDate() + expiryDays);
            dailyVideoLimit = insertUser.dailyVideoLimit ?? null;
            bulkMaxBatch = insertUser.bulkMaxBatch ?? null;
            bulkDelaySeconds = insertUser.bulkDelaySeconds ?? null;
            bulkMaxPrompts = insertUser.bulkMaxPrompts ?? null;
          } else {
            expiryDate.setDate(expiryDate.getDate() + 10);
          }
          planExpiry = expiryDate.toISOString();
        }
        const [user] = await db.insert(users).values({
          username: insertUser.username,
          password: hashedPassword,
          isAdmin: insertUser.isAdmin ?? false,
          planType: insertUser.planType || "free",
          planStartDate,
          planExpiry,
          dailyVideoLimit,
          bulkMaxBatch,
          bulkDelaySeconds,
          bulkMaxPrompts,
          dailyResetDate: (/* @__PURE__ */ new Date()).toISOString()
        }).returning();
        return user;
      }
      async deleteUser(userId) {
        await db.transaction(async (tx) => {
          try {
            await tx.execute(sql2`UPDATE video_history SET user_id = NULL WHERE user_id = ${userId}::uuid`);
            console.log(`[Delete User] Nullified video_history for user ${userId}`);
          } catch (e) {
            console.log(`[Delete User] video_history update skipped: ${e}`);
          }
          try {
            await tx.execute(sql2`UPDATE image_history SET user_id = NULL WHERE user_id = ${userId}::uuid`);
            console.log(`[Delete User] Nullified image_history for user ${userId}`);
          } catch (e) {
            console.log(`[Delete User] image_history update skipped: ${e}`);
          }
          try {
            await tx.execute(sql2`DELETE FROM characters WHERE user_id = ${userId}::uuid`);
            console.log(`[Delete User] Deleted characters for user ${userId}`);
          } catch (e) {
            console.log(`[Delete User] characters delete skipped: ${e}`);
          }
          try {
            await tx.execute(sql2`DELETE FROM user_read_messages WHERE user_id = ${userId}::uuid`);
            console.log(`[Delete User] Deleted user_read_messages for user ${userId}`);
          } catch (e) {
            console.log(`[Delete User] user_read_messages delete skipped: ${e}`);
          }
          try {
            await tx.execute(sql2`UPDATE reseller_users SET user_id = NULL WHERE user_id = ${userId}::uuid`);
            console.log(`[Delete User] Nullified reseller_users for user ${userId}`);
          } catch (e) {
            console.log(`[Delete User] reseller_users update skipped: ${e}`);
          }
          await tx.execute(sql2`DELETE FROM users WHERE id = ${userId}::uuid`);
          console.log(`[Delete User] Deleted user ${userId}`);
        });
      }
      async updateUserPlan(userId, plan) {
        try {
          const currentUser = await this.getUser(userId);
          if (!currentUser) {
            return void 0;
          }
          let planStartDate = plan.planStartDate && plan.planStartDate.trim() !== "" ? plan.planStartDate : currentUser.planStartDate;
          let planExpiry = plan.planExpiry && plan.planExpiry.trim() !== "" ? plan.planExpiry : currentUser.planExpiry;
          if (plan.planType === "enterprise" && plan.expiryDays) {
            planStartDate = (/* @__PURE__ */ new Date()).toISOString();
            const expiryDate = /* @__PURE__ */ new Date();
            expiryDate.setDate(expiryDate.getDate() + plan.expiryDays);
            planExpiry = expiryDate.toISOString();
          } else if (plan.planType !== "free" && currentUser.planType === "free" && !planStartDate && !planExpiry) {
            planStartDate = (/* @__PURE__ */ new Date()).toISOString();
            const expiryDate = /* @__PURE__ */ new Date();
            expiryDate.setDate(expiryDate.getDate() + 10);
            planExpiry = expiryDate.toISOString();
          }
          const dailyVideoLimit = plan.planType === "enterprise" ? plan.dailyVideoLimit ?? currentUser.dailyVideoLimit : null;
          const bulkMaxBatch = plan.planType === "enterprise" ? plan.bulkMaxBatch ?? currentUser.bulkMaxBatch : null;
          const bulkDelaySeconds = plan.planType === "enterprise" ? plan.bulkDelaySeconds ?? currentUser.bulkDelaySeconds : null;
          const bulkMaxPrompts = plan.planType === "enterprise" ? plan.bulkMaxPrompts ?? currentUser.bulkMaxPrompts : null;
          const [updatedUser] = await db.update(users).set({
            planType: plan.planType,
            planStatus: plan.planStatus,
            planStartDate,
            planExpiry,
            dailyVideoLimit,
            bulkMaxBatch,
            bulkDelaySeconds,
            bulkMaxPrompts
          }).where(eq(users.id, userId)).returning();
          return updatedUser || void 0;
        } catch (error) {
          console.error("Error updating user plan:", error);
          throw error;
        }
      }
      async removePlan(userId) {
        try {
          const [updatedUser] = await db.update(users).set({
            planType: "free",
            planStatus: "active",
            // Free users remain active
            planStartDate: null,
            planExpiry: null,
            dailyVideoCount: 0,
            dailyResetDate: (/* @__PURE__ */ new Date()).toISOString()
          }).where(eq(users.id, userId)).returning();
          return updatedUser || void 0;
        } catch (error) {
          console.error("Error removing user plan:", error);
          throw error;
        }
      }
      async updateUserApiToken(userId, token) {
        try {
          const [updatedUser] = await db.update(users).set({
            apiToken: token.apiToken
          }).where(eq(users.id, userId)).returning();
          return updatedUser || void 0;
        } catch (error) {
          console.error("Error updating user API token:", error);
          throw error;
        }
      }
      async updateUserIp(userId, ip1, ip2) {
        try {
          const [updatedUser] = await db.update(users).set({
            allowedIp1: ip1,
            allowedIp2: ip2
          }).where(eq(users.id, userId)).returning();
          return updatedUser || void 0;
        } catch (error) {
          console.error("Error updating user IP:", error);
          throw error;
        }
      }
      async deactivateUserAccount(userId) {
        try {
          const [updatedUser] = await db.update(users).set({
            isAccountActive: false
          }).where(eq(users.id, userId)).returning();
          return updatedUser || void 0;
        } catch (error) {
          console.error("Error deactivating user account:", error);
          throw error;
        }
      }
      async reactivateUserAccount(userId) {
        try {
          const [updatedUser] = await db.update(users).set({
            isAccountActive: true,
            allowedIp1: null,
            allowedIp2: null
          }).where(eq(users.id, userId)).returning();
          return updatedUser || void 0;
        } catch (error) {
          console.error("Error reactivating user account:", error);
          throw error;
        }
      }
      async extendAllUsersExpiry(days) {
        try {
          const allUsers = await db.select().from(users);
          let updatedCount = 0;
          for (const user of allUsers) {
            if (user.planExpiry) {
              const currentExpiry = new Date(user.planExpiry);
              currentExpiry.setDate(currentExpiry.getDate() + days);
              await db.update(users).set({ planExpiry: currentExpiry.toISOString() }).where(eq(users.id, user.id));
              updatedCount++;
            }
          }
          return updatedCount;
        } catch (error) {
          console.error("Error extending all users expiry:", error);
          throw error;
        }
      }
      async incrementDailyVideoCount(userId) {
        await db.update(users).set({ dailyVideoCount: sql2`${users.dailyVideoCount} + 1` }).where(eq(users.id, userId));
      }
      async resetDailyVideoCount(userId) {
        await db.update(users).set({
          dailyVideoCount: 0,
          dailyResetDate: (/* @__PURE__ */ new Date()).toISOString()
        }).where(eq(users.id, userId));
      }
      async checkAndResetDailyCounts() {
        const now = /* @__PURE__ */ new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
        await db.update(users).set({
          dailyVideoCount: 0,
          dailyResetDate: today
        }).where(sql2`daily_reset_date < ${today} OR daily_reset_date IS NULL`);
      }
      // Voice character tracking methods
      async incrementVoiceCharacters(userId, charCount) {
        await db.update(users).set({ voiceCharactersUsed: sql2`${users.voiceCharactersUsed} + ${charCount}` }).where(eq(users.id, userId));
      }
      async resetVoiceCharacters(userId, resetDate) {
        await db.update(users).set({
          voiceCharactersUsed: 0,
          voiceCharactersResetDate: resetDate
        }).where(eq(users.id, userId));
      }
      async checkAndResetVoiceCharacters(userId) {
        const user = await this.getUser(userId);
        if (!user) return void 0;
        if (!user.voiceCharactersResetDate) {
          const resetDate2 = /* @__PURE__ */ new Date();
          resetDate2.setDate(resetDate2.getDate() + 10);
          await this.resetVoiceCharacters(userId, resetDate2.toISOString());
          return await this.getUser(userId);
        }
        const resetDate = new Date(user.voiceCharactersResetDate);
        const now = /* @__PURE__ */ new Date();
        if (now >= resetDate) {
          const newResetDate = /* @__PURE__ */ new Date();
          newResetDate.setDate(newResetDate.getDate() + 10);
          await this.resetVoiceCharacters(userId, newResetDate.toISOString());
          return await this.getUser(userId);
        }
        return user;
      }
      async verifyPassword(user, password) {
        return await bcrypt.compare(password, user.password);
      }
      async initializeDefaultAdmin() {
        try {
          const existingAdmin = await this.getUserByUsername("muzi");
          if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash("muzi123", SALT_ROUNDS);
            await db.insert(users).values({
              username: "muzi",
              password: hashedPassword,
              isAdmin: true,
              planType: "free",
              planStatus: "active"
            });
            console.log("\u2713 Default admin user created (username: muzi, password: muzi123)");
          }
        } catch (error) {
          if (error && typeof error === "object" && "code" in error && error.code === "23505") {
            console.log("\u2713 Default admin user already exists");
          } else {
            console.error("Error initializing default admin:", error);
            throw error;
          }
        }
      }
      // Token pool management methods
      async getAllApiTokens() {
        return await db.select().from(apiTokens).orderBy(desc(apiTokens.createdAt));
      }
      async getActiveApiTokens() {
        return await db.select().from(apiTokens).where(eq(apiTokens.isActive, true)).orderBy(apiTokens.lastUsedAt);
      }
      async addApiToken(token) {
        const [newToken] = await db.insert(apiTokens).values(token).returning();
        return newToken;
      }
      async deleteApiToken(tokenId) {
        await db.delete(apiTokens).where(eq(apiTokens.id, tokenId));
      }
      async toggleApiTokenStatus(tokenId, isActive) {
        const [updatedToken] = await db.update(apiTokens).set({ isActive }).where(eq(apiTokens.id, tokenId)).returning();
        return updatedToken || void 0;
      }
      async getNextRotationToken(excludeTokenId) {
        const tokens = await db.select().from(apiTokens).where(eq(apiTokens.isActive, true)).orderBy(apiTokens.lastUsedAt);
        for (const token of tokens) {
          if (excludeTokenId && token.id === excludeTokenId) {
            console.log(`[Token Rotation] Skipping token ${token.id} - excluded for retry`);
            continue;
          }
          return token;
        }
        console.log("[Token Rotation] No active tokens available");
        return void 0;
      }
      async getTokenById(tokenId) {
        const [token] = await db.select().from(apiTokens).where(eq(apiTokens.id, tokenId));
        return token || void 0;
      }
      async getTokenByIndex(index2) {
        const tokens = await db.select().from(apiTokens).where(eq(apiTokens.isActive, true)).orderBy(apiTokens.createdAt);
        if (tokens.length === 0) {
          console.log("[Token Rotation] No active tokens available");
          return void 0;
        }
        const selectedToken = tokens[index2 % tokens.length];
        console.log(`[Token Rotation] Selected token ${selectedToken.label} (index ${index2} % ${tokens.length} tokens = ${index2 % tokens.length})`);
        return selectedToken;
      }
      async updateTokenUsage(tokenId) {
        const token = await db.select().from(apiTokens).where(eq(apiTokens.id, tokenId));
        if (token[0]) {
          const currentCount = parseInt(token[0].requestCount || "0");
          await db.update(apiTokens).set({
            lastUsedAt: (/* @__PURE__ */ new Date()).toISOString(),
            requestCount: (currentCount + 1).toString()
          }).where(eq(apiTokens.id, tokenId));
        }
      }
      async replaceAllTokens(tokens) {
        if (tokens.length === 0) {
          throw new Error("Cannot replace tokens with empty array - at least one token required");
        }
        const uniqueTokens = new Set(tokens);
        if (uniqueTokens.size !== tokens.length) {
          throw new Error("Duplicate tokens found in input");
        }
        return await db.transaction(async (tx) => {
          await tx.execute(sql2`UPDATE video_history SET token_used = NULL WHERE token_used IS NOT NULL`);
          console.log("[Bulk Replace] Nullified tokenUsed in video_history (raw SQL)");
          await tx.execute(sql2`UPDATE image_history SET token_used = NULL WHERE token_used IS NOT NULL`);
          console.log("[Bulk Replace] Nullified tokenUsed in image_history (raw SQL)");
          await tx.execute(sql2`UPDATE characters SET upload_token_id = NULL WHERE upload_token_id IS NOT NULL`);
          console.log("[Bulk Replace] Nullified uploadTokenId in characters (raw SQL)");
          const existingCharacters = await tx.select().from(characters);
          console.log(`[Bulk Replace] Found ${existingCharacters.length} total characters`);
          if (existingCharacters.length > 0) {
            await tx.delete(characters);
            console.log(`[Bulk Replace] \u26A0\uFE0F  DELETED ${existingCharacters.length} characters - VEO API requires same token for upload and generation`);
            console.log("[Bulk Replace] Users must re-upload characters with new tokens");
          }
          await tx.delete(apiTokens);
          console.log("[Bulk Replace] Deleted all old tokens");
          const newTokens = [];
          for (let i = 0; i < tokens.length; i++) {
            const [token] = await tx.insert(apiTokens).values({
              token: tokens[i],
              label: `Token ${i + 1}`,
              isActive: true
            }).returning();
            newTokens.push(token);
          }
          console.log(`[Bulk Replace] Added ${newTokens.length} new tokens`);
          return newTokens;
        });
      }
      recordTokenError(tokenId) {
        const now = Date.now();
        const errors = tokenErrorTracking.get(tokenId) || [];
        errors.push(now);
        const recentErrors = errors.filter((timestamp) => now - timestamp < ERROR_WINDOW_MS);
        tokenErrorTracking.set(tokenId, recentErrors);
        console.log(`[Token Error Tracking] Recorded error for token ${tokenId}. ${recentErrors.length} errors in last 20 minutes`);
      }
      isTokenInCooldown(tokenId) {
        return false;
      }
      getRecentErrorCount(tokenId) {
        const errors = tokenErrorTracking.get(tokenId) || [];
        const now = Date.now();
        const recentErrors = errors.filter((timestamp) => now - timestamp < ERROR_WINDOW_MS);
        return recentErrors.length;
      }
      // Token settings methods
      async getTokenSettings() {
        const [settings] = await db.select().from(tokenSettings).limit(1);
        return settings || void 0;
      }
      async updateTokenSettings(settings) {
        const existing = await this.getTokenSettings();
        if (existing) {
          const [updated] = await db.update(tokenSettings).set(settings).where(eq(tokenSettings.id, existing.id)).returning();
          return updated;
        } else {
          const [newSettings] = await db.insert(tokenSettings).values(settings).returning();
          return newSettings;
        }
      }
      async initializeTokenSettings() {
        const SINGLETON_ID = "00000000-0000-0000-0000-000000000001";
        try {
          await db.execute(sql2`
        DELETE FROM token_settings WHERE id != ${SINGLETON_ID}
      `);
          await db.execute(sql2`
        INSERT INTO token_settings (id, rotation_enabled, rotation_interval_minutes, max_requests_per_token, videos_per_batch, batch_delay_seconds, next_rotation_index)
        VALUES (${SINGLETON_ID}, false, '60', '1000', '10', '20', 0)
        ON CONFLICT (id) DO NOTHING
      `);
        } catch (error) {
          console.log("Token settings initialization completed or already exists");
        }
      }
      /**
       * Atomically get and increment the rotation index for round-robin token assignment
       * Uses atomic SQL to prevent race conditions with concurrent batches
       * Returns the STARTING index for this batch (before increment)
       */
      async getAndIncrementRotationIndex(incrementBy, totalTokens) {
        if (totalTokens <= 0) {
          throw new Error(`totalTokens must be positive, got: ${totalTokens}`);
        }
        if (incrementBy <= 0) {
          throw new Error(`incrementBy must be positive, got: ${incrementBy}`);
        }
        await this.initializeTokenSettings();
        const SINGLETON_ID = "00000000-0000-0000-0000-000000000001";
        const result = await db.execute(sql2`
      UPDATE token_settings
      SET next_rotation_index = (next_rotation_index + ${incrementBy}) % ${totalTokens}
      WHERE id = ${SINGLETON_ID}
      RETURNING ((next_rotation_index - ${incrementBy}) % ${totalTokens} + ${totalTokens}) % ${totalTokens} AS start_index
    `);
        if (!result.rows || result.rows.length === 0) {
          throw new Error("Failed to atomically update rotation index - no settings row found");
        }
        const rawStartIndex = result.rows[0].start_index;
        const startIndex = Number.parseInt(String(rawStartIndex), 10);
        if (Number.isNaN(startIndex) || startIndex < 0) {
          throw new Error(`Invalid rotation index returned: ${rawStartIndex} (parsed as ${startIndex})`);
        }
        return startIndex;
      }
      // Video history methods
      async getUserVideoHistory(userId, limit = 100) {
        return await db.select().from(videoHistory).where(and(
          eq(videoHistory.userId, userId),
          eq(videoHistory.deletedByUser, false)
        )).orderBy(desc(videoHistory.createdAt)).limit(limit);
      }
      // Batch update multiple video statuses in single query
      async batchUpdateVideoStatus(updates) {
        if (updates.length === 0) return;
        const now = (/* @__PURE__ */ new Date()).toISOString();
        const batchSize = 20;
        for (let i = 0; i < updates.length; i += batchSize) {
          const batch = updates.slice(i, i + batchSize);
          await Promise.all(batch.map(async (update) => {
            const setFields = {
              status: update.status,
              updatedAt: now
            };
            if (update.videoUrl) setFields.videoUrl = update.videoUrl;
            if (update.errorMessage) setFields.errorMessage = update.errorMessage;
            await db.update(videoHistory).set(setFields).where(eq(videoHistory.id, update.videoId));
          }));
        }
      }
      // Cancel all pending/processing/uploading videos for a user (batch cancellation)
      async batchCancelVideos(userId, videoIds, reason) {
        if (videoIds.length === 0) return 0;
        const now = (/* @__PURE__ */ new Date()).toISOString();
        const result = await db.update(videoHistory).set({
          status: "failed",
          errorMessage: reason,
          updatedAt: now
        }).where(and(
          eq(videoHistory.userId, userId),
          inArray(videoHistory.id, videoIds),
          ne(videoHistory.status, "completed"),
          ne(videoHistory.status, "failed")
        ));
        return videoIds.length;
      }
      // Get only pending videos for status check (optimized)
      async getPendingVideosForUser(userId) {
        return await db.select().from(videoHistory).where(and(
          eq(videoHistory.userId, userId),
          eq(videoHistory.status, "pending"),
          eq(videoHistory.deletedByUser, false)
        )).orderBy(desc(videoHistory.updatedAt)).limit(100);
      }
      // Get all pending videos across ALL users (for recovery after server restart)
      // Only get videos created in the last 15 minutes to avoid recovering old stuck videos
      async getAllPendingVideos() {
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1e3).toISOString();
        return await db.select().from(videoHistory).where(and(
          eq(videoHistory.status, "pending"),
          eq(videoHistory.deletedByUser, false),
          gt(videoHistory.createdAt, fifteenMinutesAgo)
          // Only recent videos (last 15 min)
        )).orderBy(videoHistory.createdAt).limit(500);
      }
      async getAllUsersVideoStats() {
        const result = await db.execute(sql2`
      SELECT 
        user_id,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
        SUM(CASE WHEN status IN ('pending', 'queued', 'retrying') THEN 1 ELSE 0 END) as pending
      FROM video_history
      GROUP BY user_id
    `);
        const statsMap = /* @__PURE__ */ new Map();
        for (const row of result.rows) {
          const r = row;
          statsMap.set(r.user_id, {
            total: Number(r.total) || 0,
            completed: Number(r.completed) || 0,
            failed: Number(r.failed) || 0,
            pending: Number(r.pending) || 0
          });
        }
        return statsMap;
      }
      async getVideoById(videoId) {
        const [video] = await db.select().from(videoHistory).where(eq(videoHistory.id, videoId)).limit(1);
        return video || void 0;
      }
      async addVideoHistory(video) {
        const [newVideo] = await db.insert(videoHistory).values(video).returning();
        return newVideo;
      }
      async updateVideoHistoryStatus(videoId, userId, status, videoUrl, errorMessage) {
        const currentVideo = await this.getVideoById(videoId);
        const wasNotCompleted = currentVideo && currentVideo.status !== "completed";
        const updateData = {
          status,
          updatedAt: sql2`now()::text`
        };
        if (videoUrl) {
          updateData.videoUrl = videoUrl;
        }
        if (errorMessage) {
          updateData.errorMessage = errorMessage;
        }
        const [updated] = await db.update(videoHistory).set(updateData).where(and(eq(videoHistory.id, videoId), eq(videoHistory.userId, userId))).returning();
        if (updated && status === "completed") {
          await this.incrementDailyVideoCount(userId);
          console.log(`[Storage] \u2705 Video ${videoId} completed - Daily count incremented for user ${userId}`);
          if (wasNotCompleted) {
            await this.incrementTotalVideosGenerated();
            console.log(`[Storage] Total videos counter incremented for video ${videoId}`);
          }
        }
        return updated || void 0;
      }
      async updateVideoHistoryFields(videoId, fields) {
        const currentVideo = await this.getVideoById(videoId);
        const wasNotCompleted = currentVideo && currentVideo.status !== "completed";
        const isNowCompleted = fields.status === "completed";
        const [updated] = await db.update(videoHistory).set({ ...fields, updatedAt: sql2`now()::text` }).where(eq(videoHistory.id, videoId)).returning();
        if (updated && wasNotCompleted && isNowCompleted) {
          await this.incrementTotalVideosGenerated();
          console.log(`[Storage] Total videos counter incremented for video ${videoId}`);
        }
        return updated || void 0;
      }
      async clearAllVideoHistory() {
        await db.delete(videoHistory);
      }
      async deleteVideoHistoryById(videoId) {
        const result = await db.delete(videoHistory).where(eq(videoHistory.id, videoId)).returning();
        return result.length > 0;
      }
      // Auto-retry settings methods
      async getAutoRetrySettings() {
        const [settings] = await db.select().from(autoRetrySettings).limit(1);
        return settings || void 0;
      }
      async updateAutoRetrySettings(settings) {
        const existing = await this.getAutoRetrySettings();
        if (existing) {
          const [updated] = await db.update(autoRetrySettings).set({ ...settings, updatedAt: sql2`now()::text` }).where(eq(autoRetrySettings.id, existing.id)).returning();
          return updated;
        } else {
          const [newSettings] = await db.insert(autoRetrySettings).values(settings).returning();
          return newSettings;
        }
      }
      async initializeAutoRetrySettings() {
        const existing = await this.getAutoRetrySettings();
        if (!existing) {
          await db.insert(autoRetrySettings).values({});
          console.log("\u2713 Auto-retry settings initialized");
        }
      }
      async getEligibleFailedVideosForRetry() {
        const settings = await this.getAutoRetrySettings();
        if (!settings || !settings.enableAutoRetry) {
          return [];
        }
        const delayMinutes = settings.retryDelayMinutes;
        const maxRetryAttempts = settings.maxRetryAttempts;
        const eligibleVideos = await db.select().from(videoHistory).where(
          and(
            eq(videoHistory.status, "failed"),
            sql2`${videoHistory.retryCount} < ${maxRetryAttempts}`,
            sql2`(
            ${videoHistory.lastRetryAt} IS NULL 
            OR CAST(${videoHistory.lastRetryAt} AS timestamp) <= (now() - interval '${sql2.raw(delayMinutes.toString())} minutes')
          )`,
            // Exclude merged videos (they have mergedVideoIds in metadata)
            sql2`(${videoHistory.metadata} IS NULL OR ${videoHistory.metadata}->>'mergedVideoIds' IS NULL)`
          )
        ).orderBy(desc(videoHistory.createdAt)).limit(10);
        return eligibleVideos;
      }
      async markVideoAsRetrying(videoId) {
        const [updated] = await db.update(videoHistory).set({
          status: "retrying",
          retryCount: sql2`${videoHistory.retryCount} + 1`,
          lastRetryAt: sql2`now()::text`,
          updatedAt: sql2`now()::text`
        }).where(eq(videoHistory.id, videoId)).returning();
        return updated || void 0;
      }
      // Plan availability methods
      async getPlanAvailability() {
        const [availability] = await db.select().from(planAvailability).limit(1);
        return availability || void 0;
      }
      async updatePlanAvailability(availability) {
        const existing = await this.getPlanAvailability();
        if (existing) {
          const [updated] = await db.update(planAvailability).set({ ...availability, updatedAt: sql2`now()::text` }).where(eq(planAvailability.id, existing.id)).returning();
          return updated;
        } else {
          const [newAvailability] = await db.insert(planAvailability).values(availability).returning();
          return newAvailability;
        }
      }
      async initializePlanAvailability() {
        const existing = await this.getPlanAvailability();
        if (!existing) {
          await db.insert(planAvailability).values({});
          console.log("\u2713 Plan availability settings initialized");
        }
      }
      // App settings methods
      async getAppSettings() {
        const [settings] = await db.select().from(appSettings).limit(1);
        return settings || void 0;
      }
      async updateAppSettings(settings) {
        const existing = await this.getAppSettings();
        if (existing) {
          const [updated] = await db.update(appSettings).set({ ...settings, updatedAt: sql2`now()::text` }).where(eq(appSettings.id, existing.id)).returning();
          return updated;
        } else {
          const [newSettings] = await db.insert(appSettings).values(settings).returning();
          return newSettings;
        }
      }
      async initializeAppSettings() {
        const existing = await this.getAppSettings();
        if (!existing) {
          await db.insert(appSettings).values({});
          console.log("\u2713 App settings initialized");
        }
      }
      async incrementTotalVideosGenerated() {
        const existing = await this.getAppSettings();
        if (existing) {
          const newCount = (existing.totalVideosGenerated || 0) + 1;
          await db.update(appSettings).set({ totalVideosGenerated: newCount }).where(eq(appSettings.id, existing.id));
          return newCount;
        }
        return 0;
      }
      async incrementTotalVideosGeneratedBy(amount) {
        const existing = await this.getAppSettings();
        if (existing) {
          const newCount = (existing.totalVideosGenerated || 0) + amount;
          await db.update(appSettings).set({ totalVideosGenerated: newCount }).where(eq(appSettings.id, existing.id));
          return newCount;
        }
        return 0;
      }
      async getTotalVideosGenerated() {
        const settings = await this.getAppSettings();
        return settings?.totalVideosGenerated || 0;
      }
      // Tool maintenance methods
      async getToolMaintenance() {
        const [maintenance] = await db.select().from(toolMaintenance).limit(1);
        return maintenance || void 0;
      }
      async updateToolMaintenance(maintenance) {
        const existing = await this.getToolMaintenance();
        if (existing) {
          const [updated] = await db.update(toolMaintenance).set({ ...maintenance, updatedAt: sql2`now()::text` }).where(eq(toolMaintenance.id, existing.id)).returning();
          return updated;
        } else {
          const [newMaintenance] = await db.insert(toolMaintenance).values(maintenance).returning();
          return newMaintenance;
        }
      }
      async initializeToolMaintenance() {
        const existing = await this.getToolMaintenance();
        if (!existing) {
          await db.insert(toolMaintenance).values({});
          console.log("\u2713 Tool maintenance settings initialized");
        }
      }
      // Credits snapshot methods (admin-only)
      async getLatestCreditsSnapshot() {
        const [snapshot] = await db.select().from(creditsSnapshots).orderBy(desc(creditsSnapshots.recordedAt)).limit(1);
        return snapshot || void 0;
      }
      async getRecentCreditsSnapshots(limit) {
        return await db.select().from(creditsSnapshots).orderBy(desc(creditsSnapshots.recordedAt)).limit(limit);
      }
      async addCreditsSnapshot(remainingCredits, source, tokenId) {
        const [snapshot] = await db.insert(creditsSnapshots).values({ remainingCredits, source, tokenId: tokenId || null }).returning();
        return snapshot;
      }
      async getLatestCreditsSnapshotByToken(tokenId) {
        const snapshots = await db.select().from(creditsSnapshots).where(eq(creditsSnapshots.tokenId, tokenId)).orderBy(desc(creditsSnapshots.recordedAt)).limit(1);
        return snapshots[0];
      }
      async getLatestCreditsSnapshotsPerToken() {
        const result = await db.execute(sql2`
      SELECT DISTINCT ON (token_id) *
      FROM credits_snapshots
      WHERE token_id IS NOT NULL
      ORDER BY token_id, recorded_at DESC
    `);
        return result.rows;
      }
      // Character management methods
      async getUserCharacters(userId) {
        return await db.select().from(characters).where(eq(characters.userId, userId)).orderBy(desc(characters.createdAt));
      }
      async getCharacterById(characterId) {
        const [character] = await db.select().from(characters).where(eq(characters.id, characterId));
        return character || void 0;
      }
      async addCharacter(insertCharacter) {
        const [character] = await db.insert(characters).values(insertCharacter).returning();
        return character;
      }
      async deleteCharacter(characterId, userId) {
        await db.delete(characters).where(and(
          eq(characters.id, characterId),
          eq(characters.userId, userId)
        ));
      }
      // Admin messages methods
      async getAllAdminMessages() {
        return await db.select().from(adminMessages).orderBy(desc(adminMessages.createdAt));
      }
      async getActiveAdminMessages() {
        return await db.select().from(adminMessages).where(eq(adminMessages.isActive, true)).orderBy(desc(adminMessages.createdAt));
      }
      async getAdminMessageById(messageId) {
        const [message] = await db.select().from(adminMessages).where(eq(adminMessages.id, messageId));
        return message || void 0;
      }
      async createAdminMessage(title, message) {
        const [newMessage] = await db.insert(adminMessages).values({ title, message, isActive: true }).returning();
        return newMessage;
      }
      async updateAdminMessage(messageId, title, message, isActive) {
        const [updatedMessage] = await db.update(adminMessages).set({ title, message, isActive }).where(eq(adminMessages.id, messageId)).returning();
        return updatedMessage || void 0;
      }
      async deleteAdminMessage(messageId) {
        await db.delete(userReadMessages).where(eq(userReadMessages.messageId, messageId));
        await db.delete(adminMessages).where(eq(adminMessages.id, messageId));
      }
      async toggleAdminMessageStatus(messageId, isActive) {
        const [updatedMessage] = await db.update(adminMessages).set({ isActive }).where(eq(adminMessages.id, messageId)).returning();
        return updatedMessage || void 0;
      }
      async getUnreadMessagesCount(userId) {
        const activeMessages = await this.getActiveAdminMessages();
        const readMessageIds = await this.getUserReadMessageIds(userId);
        const unreadCount = activeMessages.filter((msg) => !readMessageIds.includes(msg.id)).length;
        return unreadCount;
      }
      async markMessageAsRead(userId, messageId) {
        const [existing] = await db.select().from(userReadMessages).where(and(
          eq(userReadMessages.userId, userId),
          eq(userReadMessages.messageId, messageId)
        ));
        if (!existing) {
          await db.insert(userReadMessages).values({ userId, messageId });
        }
      }
      async markAllMessagesAsRead(userId) {
        const activeMessages = await this.getActiveAdminMessages();
        const readMessageIds = await this.getUserReadMessageIds(userId);
        const unreadMessages = activeMessages.filter((msg) => !readMessageIds.includes(msg.id));
        for (const msg of unreadMessages) {
          await db.insert(userReadMessages).values({ userId, messageId: msg.id });
        }
      }
      async getUserReadMessageIds(userId) {
        const readRecords = await db.select({ messageId: userReadMessages.messageId }).from(userReadMessages).where(eq(userReadMessages.userId, userId));
        return readRecords.map((r) => r.messageId);
      }
      // Reseller management methods
      async getAllResellers() {
        return await db.select().from(resellers).orderBy(desc(resellers.createdAt));
      }
      async getResellerById(resellerId) {
        const [reseller] = await db.select().from(resellers).where(eq(resellers.id, resellerId));
        return reseller || void 0;
      }
      async getResellerByUsername(username) {
        const [reseller] = await db.select().from(resellers).where(eq(resellers.username, username));
        return reseller || void 0;
      }
      async createReseller(insertReseller) {
        const hashedPassword = await bcrypt.hash(insertReseller.password, SALT_ROUNDS);
        const initialCredits = insertReseller.creditBalance ?? 0;
        const [reseller] = await db.insert(resellers).values({
          username: insertReseller.username,
          password: hashedPassword,
          creditBalance: initialCredits,
          isActive: true
        }).returning();
        if (initialCredits > 0) {
          await db.insert(resellerCreditLedger).values({
            resellerId: reseller.id,
            creditChange: initialCredits,
            balanceAfter: initialCredits,
            reason: "Initial credits assigned by admin"
          });
        }
        return reseller;
      }
      async updateResellerCredits(resellerId, creditChange, reason) {
        const reseller = await this.getResellerById(resellerId);
        if (!reseller) return void 0;
        const newBalance = reseller.creditBalance + creditChange;
        if (newBalance < 0) {
          throw new Error("Insufficient credits");
        }
        const [updatedReseller] = await db.update(resellers).set({ creditBalance: newBalance }).where(eq(resellers.id, resellerId)).returning();
        await db.insert(resellerCreditLedger).values({
          resellerId,
          creditChange,
          balanceAfter: newBalance,
          reason
        });
        return updatedReseller || void 0;
      }
      async toggleResellerStatus(resellerId, isActive) {
        const [updatedReseller] = await db.update(resellers).set({ isActive }).where(eq(resellers.id, resellerId)).returning();
        return updatedReseller || void 0;
      }
      async deleteReseller(resellerId) {
        await db.delete(resellerCreditLedger).where(eq(resellerCreditLedger.resellerId, resellerId));
        await db.delete(resellerUsers).where(eq(resellerUsers.resellerId, resellerId));
        await db.delete(resellers).where(eq(resellers.id, resellerId));
      }
      async verifyResellerPassword(reseller, password) {
        return await bcrypt.compare(password, reseller.password);
      }
      async getResellerCreditLedger(resellerId) {
        return await db.select().from(resellerCreditLedger).where(eq(resellerCreditLedger.resellerId, resellerId)).orderBy(desc(resellerCreditLedger.createdAt));
      }
      async getResellerUsers(resellerId) {
        const result = await db.select({
          id: resellerUsers.id,
          resellerId: resellerUsers.resellerId,
          userId: resellerUsers.userId,
          planType: resellerUsers.planType,
          creditCost: resellerUsers.creditCost,
          createdAt: resellerUsers.createdAt,
          username: users.username,
          isAccountActive: users.isAccountActive
        }).from(resellerUsers).innerJoin(users, eq(resellerUsers.userId, users.id)).where(eq(resellerUsers.resellerId, resellerId)).orderBy(desc(resellerUsers.createdAt));
        return result.map((row) => ({
          id: row.id,
          resellerId: row.resellerId,
          userId: row.userId,
          planType: row.planType,
          creditCost: row.creditCost,
          createdAt: row.createdAt,
          user: {
            username: row.username,
            isAccountActive: row.isAccountActive
          }
        }));
      }
      async createUserByReseller(resellerId, userData) {
        const reseller = await this.getResellerById(resellerId);
        if (!reseller) {
          throw new Error("Reseller not found");
        }
        if (!reseller.isActive) {
          throw new Error("Reseller account is inactive");
        }
        const creditCost = userData.planType === "empire" ? 1500 : 900;
        if (reseller.creditBalance < creditCost) {
          throw new Error(`Insufficient credits. Need ${creditCost}, have ${reseller.creditBalance}`);
        }
        const existingUser = await this.getUserByUsername(userData.username);
        if (existingUser) {
          throw new Error("Username already exists");
        }
        const hashedPassword = await bcrypt.hash(userData.password, SALT_ROUNDS);
        const planStartDate = (/* @__PURE__ */ new Date()).toISOString();
        const expiryDate = /* @__PURE__ */ new Date();
        expiryDate.setDate(expiryDate.getDate() + 10);
        const planExpiry = expiryDate.toISOString();
        const [user] = await db.insert(users).values({
          username: userData.username,
          password: hashedPassword,
          isAdmin: false,
          planType: userData.planType,
          planStatus: "active",
          planStartDate,
          planExpiry,
          dailyResetDate: (/* @__PURE__ */ new Date()).toISOString()
        }).returning();
        const [resellerUser] = await db.insert(resellerUsers).values({
          resellerId,
          userId: user.id,
          planType: userData.planType,
          creditCost
        }).returning();
        const newBalance = reseller.creditBalance - creditCost;
        await db.update(resellers).set({ creditBalance: newBalance }).where(eq(resellers.id, resellerId));
        await db.insert(resellerCreditLedger).values({
          resellerId,
          creditChange: -creditCost,
          balanceAfter: newBalance,
          reason: `Created ${userData.planType} user: ${userData.username}`
        });
        return { user, resellerUser };
      }
      // Flow Cookies management
      async getAllFlowCookies() {
        return await db.select().from(flowCookies).orderBy(desc(flowCookies.createdAt));
      }
      async getActiveFlowCookies() {
        return await db.select().from(flowCookies).where(eq(flowCookies.isActive, true)).orderBy(desc(flowCookies.createdAt));
      }
      async getFlowCookieById(cookieId) {
        const [cookie] = await db.select().from(flowCookies).where(eq(flowCookies.id, cookieId));
        return cookie || void 0;
      }
      async addFlowCookie(label, cookieData) {
        const [cookie] = await db.insert(flowCookies).values({ label, cookieData }).returning();
        return cookie;
      }
      async updateFlowCookie(cookieId, updates) {
        const [cookie] = await db.update(flowCookies).set(updates).where(eq(flowCookies.id, cookieId)).returning();
        return cookie || void 0;
      }
      async deleteFlowCookie(cookieId) {
        await db.delete(flowCookies).where(eq(flowCookies.id, cookieId));
      }
      async toggleFlowCookieStatus(cookieId, isActive) {
        const [cookie] = await db.update(flowCookies).set({ isActive }).where(eq(flowCookies.id, cookieId)).returning();
        return cookie || void 0;
      }
      async bulkAddFlowCookies(cookiesText) {
        const lines = cookiesText.split("\n").filter((line) => line.trim());
        const addedCookies = [];
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          let label;
          let cookieData;
          if (line.includes("|[")) {
            const pipeIndex = line.indexOf("|");
            label = line.substring(0, pipeIndex).trim();
            cookieData = line.substring(pipeIndex + 1).trim();
          } else {
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
      async getNextFlowCookie() {
        const cookies = await db.select().from(flowCookies).where(eq(flowCookies.isActive, true)).orderBy(flowCookies.lastUsedAt).limit(1);
        if (cookies.length === 0) return void 0;
        const [updated] = await db.update(flowCookies).set({ lastUsedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(flowCookies.id, cookies[0].id)).returning();
        return updated;
      }
      async recordFlowCookieSuccess(cookieId) {
        await db.update(flowCookies).set({
          successCount: sql2`${flowCookies.successCount} + 1`,
          lastUsedAt: (/* @__PURE__ */ new Date()).toISOString()
        }).where(eq(flowCookies.id, cookieId));
      }
      async recordFlowCookieFailure(cookieId) {
        await db.update(flowCookies).set({
          failCount: sql2`${flowCookies.failCount} + 1`,
          lastUsedAt: (/* @__PURE__ */ new Date()).toISOString()
        }).where(eq(flowCookies.id, cookieId));
      }
      async recordFlowCookieExpired(cookieId) {
        await db.update(flowCookies).set({
          expiredCount: sql2`${flowCookies.expiredCount} + 1`,
          lastUsedAt: (/* @__PURE__ */ new Date()).toISOString()
        }).where(eq(flowCookies.id, cookieId));
      }
      async deleteAllFlowCookies() {
        const all = await db.select().from(flowCookies);
        await db.delete(flowCookies);
        return all.length;
      }
      // Community Voices implementation
      async getAllCommunityVoices() {
        return await db.select().from(communityVoices).where(eq(communityVoices.isActive, true)).orderBy(desc(communityVoices.createdAt));
      }
      async getCommunityVoiceById(voiceId) {
        const [voice] = await db.select().from(communityVoices).where(eq(communityVoices.id, voiceId));
        return voice || void 0;
      }
      async createCommunityVoice(voice, userId, creatorName) {
        const [newVoice] = await db.insert(communityVoices).values({
          name: voice.name,
          description: voice.description || null,
          language: voice.language,
          gender: voice.gender,
          creatorId: userId,
          creatorName,
          demoAudioBase64: voice.demoAudioBase64,
          durationSeconds: voice.durationSeconds,
          fileSizeBytes: voice.fileSizeBytes
        }).returning();
        return newVoice;
      }
      async deleteCommunityVoice(voiceId) {
        await db.delete(communityVoiceLikes).where(eq(communityVoiceLikes.voiceId, voiceId));
        await db.delete(communityVoices).where(eq(communityVoices.id, voiceId));
      }
      async getTopCommunityVoices(limit) {
        return await db.select().from(communityVoices).where(eq(communityVoices.isActive, true)).orderBy(desc(communityVoices.likesCount)).limit(limit);
      }
      async toggleCommunityVoiceLike(voiceId, userId) {
        const [existing] = await db.select().from(communityVoiceLikes).where(and(eq(communityVoiceLikes.voiceId, voiceId), eq(communityVoiceLikes.userId, userId)));
        if (existing) {
          await db.delete(communityVoiceLikes).where(eq(communityVoiceLikes.id, existing.id));
          const [updated] = await db.update(communityVoices).set({ likesCount: sql2`${communityVoices.likesCount} - 1` }).where(eq(communityVoices.id, voiceId)).returning();
          return { liked: false, likesCount: updated.likesCount };
        } else {
          await db.insert(communityVoiceLikes).values({ voiceId, userId });
          const [updated] = await db.update(communityVoices).set({ likesCount: sql2`${communityVoices.likesCount} + 1` }).where(eq(communityVoices.id, voiceId)).returning();
          return { liked: true, likesCount: updated.likesCount };
        }
      }
      async hasUserLikedVoice(voiceId, userId) {
        const [existing] = await db.select().from(communityVoiceLikes).where(and(eq(communityVoiceLikes.voiceId, voiceId), eq(communityVoiceLikes.userId, userId)));
        return !!existing;
      }
      async getUserLikedVoiceIds(userId) {
        const likes = await db.select().from(communityVoiceLikes).where(eq(communityVoiceLikes.userId, userId));
        return likes.map((l) => l.voiceId);
      }
      // Pricing Plans implementation
      async getAllPricingPlans() {
        return await db.select().from(pricingPlans).orderBy(pricingPlans.position);
      }
      async getActivePricingPlans() {
        return await db.select().from(pricingPlans).where(eq(pricingPlans.isActive, true)).orderBy(pricingPlans.position);
      }
      async getPricingPlanById(planId) {
        const [plan] = await db.select().from(pricingPlans).where(eq(pricingPlans.id, planId));
        return plan || void 0;
      }
      async createPricingPlan(plan) {
        const allPlans = await db.select().from(pricingPlans);
        const maxPosition = allPlans.length > 0 ? Math.max(...allPlans.map((p) => p.position)) + 1 : 0;
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
          position: plan.position ?? maxPosition
        }).returning();
        return newPlan;
      }
      async updatePricingPlan(planId, updates) {
        const updateData = { updatedAt: (/* @__PURE__ */ new Date()).toISOString() };
        if (updates.name !== void 0) updateData.name = updates.name;
        if (updates.subtitle !== void 0) updateData.subtitle = updates.subtitle;
        if (updates.displayPrice !== void 0) updateData.displayPrice = updates.displayPrice;
        if (updates.currency !== void 0) updateData.currency = updates.currency;
        if (updates.period !== void 0) updateData.period = updates.period;
        if (updates.alternatePrice !== void 0) updateData.alternatePrice = updates.alternatePrice;
        if (updates.badge !== void 0) updateData.badge = updates.badge;
        if (updates.badgeColor !== void 0) updateData.badgeColor = updates.badgeColor;
        if (updates.iconType !== void 0) updateData.iconType = updates.iconType;
        if (updates.highlightBorder !== void 0) updateData.highlightBorder = updates.highlightBorder;
        if (updates.featuresIntro !== void 0) updateData.featuresIntro = updates.featuresIntro;
        if (updates.features !== void 0) updateData.features = updates.features;
        if (updates.buttonText !== void 0) updateData.buttonText = updates.buttonText;
        if (updates.buttonAction !== void 0) updateData.buttonAction = updates.buttonAction;
        if (updates.position !== void 0) updateData.position = updates.position;
        if (updates.isActive !== void 0) updateData.isActive = updates.isActive;
        const [updated] = await db.update(pricingPlans).set(updateData).where(eq(pricingPlans.id, planId)).returning();
        return updated || void 0;
      }
      async deletePricingPlan(planId) {
        await db.delete(pricingPlans).where(eq(pricingPlans.id, planId));
      }
      async reorderPricingPlans(planIds) {
        for (let i = 0; i < planIds.length; i++) {
          await db.update(pricingPlans).set({ position: i, updatedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(pricingPlans.id, planIds[i]));
        }
      }
    };
    storage = new DatabaseStorage();
  }
});

// server/localDiskStorage.ts
var localDiskStorage_exports = {};
__export(localDiskStorage_exports, {
  cleanupExpiredVideos: () => cleanupExpiredVideos,
  deleteVideo: () => deleteVideo,
  getStorageStats: () => getStorageStats,
  getVideoMetadata: () => getVideoMetadata,
  getVideoPath: () => getVideoPath,
  getVideoStream: () => getVideoStream,
  initLocalDiskStorage: () => initLocalDiskStorage,
  listAllVideos: () => listAllVideos,
  saveVideoToLocalDisk: () => saveVideoToLocalDisk,
  startCleanupJob: () => startCleanupJob,
  stopCleanupJob: () => stopCleanupJob,
  videoExists: () => videoExists
});
import { promises as fs } from "fs";
import { existsSync, mkdirSync, createReadStream } from "fs";
import path from "path";
import { randomUUID } from "crypto";
function ensureStorageDir() {
  if (!existsSync(VIDEO_STORAGE_DIR)) {
    mkdirSync(VIDEO_STORAGE_DIR, { recursive: true });
    console.log(`[LocalDisk] Created storage directory: ${VIDEO_STORAGE_DIR}`);
  }
}
async function loadExistingVideos() {
  ensureStorageDir();
  try {
    const files = await fs.readdir(VIDEO_STORAGE_DIR);
    const metadataFiles = files.filter((f) => f.endsWith(".meta.json"));
    for (const metaFile of metadataFiles) {
      try {
        const metaPath = path.join(VIDEO_STORAGE_DIR, metaFile);
        const metaContent = await fs.readFile(metaPath, "utf-8");
        const metadata = JSON.parse(metaContent);
        const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
        if (existsSync(videoPath)) {
          videoIndex.set(metadata.id, metadata);
        } else {
          await fs.unlink(metaPath).catch(() => {
          });
        }
      } catch (e) {
        console.error(`[LocalDisk] Error loading metadata ${metaFile}:`, e);
      }
    }
    console.log(`[LocalDisk] Loaded ${videoIndex.size} existing videos from disk`);
  } catch (e) {
    console.error("[LocalDisk] Error loading existing videos:", e);
  }
}
async function saveVideoToLocalDisk(base64Data, options) {
  ensureStorageDir();
  const videoId = options?.externalVideoId || randomUUID();
  const filename = `${videoId}.mp4`;
  const metaFilename = `${videoId}.meta.json`;
  const videoPath = path.join(VIDEO_STORAGE_DIR, filename);
  const metaPath = path.join(VIDEO_STORAGE_DIR, metaFilename);
  const videoBuffer = Buffer.from(base64Data, "base64");
  const sizeBytes = videoBuffer.length;
  const sizeMB = (sizeBytes / (1024 * 1024)).toFixed(2);
  console.log(`[LocalDisk] Saving video ${videoId} (${sizeMB}MB)...`);
  await fs.writeFile(videoPath, videoBuffer);
  const now = Date.now();
  const metadata = {
    id: videoId,
    filename,
    createdAt: now,
    expiresAt: now + VIDEO_EXPIRY_HOURS * 60 * 60 * 1e3,
    sizeBytes,
    prompt: options?.prompt,
    userId: options?.userId
  };
  await fs.writeFile(metaPath, JSON.stringify(metadata, null, 2));
  videoIndex.set(videoId, metadata);
  console.log(`[LocalDisk] Video ${videoId} saved. Expires at: ${new Date(metadata.expiresAt).toISOString()}`);
  const videoUrl = `/api/local-video/${videoId}`;
  return { videoId, videoUrl };
}
function getVideoPath(videoId) {
  const metadata = videoIndex.get(videoId);
  if (metadata) {
    const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
    if (existsSync(videoPath)) {
      return videoPath;
    }
    videoIndex.delete(videoId);
    return null;
  }
  const expectedPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.mp4`);
  if (existsSync(expectedPath)) {
    const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
    if (existsSync(metaPath)) {
      try {
        const metaContent = __require("fs").readFileSync(metaPath, "utf-8");
        const diskMetadata = JSON.parse(metaContent);
        videoIndex.set(videoId, diskMetadata);
      } catch (e) {
        const stats = __require("fs").statSync(expectedPath);
        const now = Date.now();
        videoIndex.set(videoId, {
          id: videoId,
          filename: `${videoId}.mp4`,
          createdAt: stats.mtimeMs,
          expiresAt: stats.mtimeMs + VIDEO_EXPIRY_HOURS * 60 * 60 * 1e3,
          sizeBytes: stats.size
        });
      }
    }
    return expectedPath;
  }
  return null;
}
function getVideoStream(videoId) {
  const videoPath = getVideoPath(videoId);
  if (!videoPath) return null;
  return createReadStream(videoPath);
}
function getVideoMetadata(videoId) {
  return videoIndex.get(videoId) || null;
}
function videoExists(videoId) {
  return getVideoPath(videoId) !== null;
}
async function deleteVideo(videoId) {
  const metadata = videoIndex.get(videoId);
  if (!metadata) return false;
  const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
  const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
  try {
    await fs.unlink(videoPath).catch(() => {
    });
    await fs.unlink(metaPath).catch(() => {
    });
    videoIndex.delete(videoId);
    console.log(`[LocalDisk] Deleted video ${videoId}`);
    return true;
  } catch (e) {
    console.error(`[LocalDisk] Error deleting video ${videoId}:`, e);
    return false;
  }
}
async function cleanupExpiredVideos() {
  const now = Date.now();
  let deletedCount = 0;
  console.log(`[LocalDisk Cleanup] Starting cleanup check. ${videoIndex.size} videos in index.`);
  const entries = Array.from(videoIndex.entries());
  for (const [videoId, metadata] of entries) {
    if (metadata.expiresAt < now) {
      const videoPath = path.join(VIDEO_STORAGE_DIR, metadata.filename);
      const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
      try {
        await fs.unlink(videoPath).catch(() => {
        });
        await fs.unlink(metaPath).catch(() => {
        });
        videoIndex.delete(videoId);
        deletedCount++;
        const ageHours = ((now - metadata.createdAt) / (1e3 * 60 * 60)).toFixed(1);
        console.log(`[LocalDisk Cleanup] Deleted expired video ${videoId} (age: ${ageHours}h)`);
      } catch (e) {
        console.error(`[LocalDisk Cleanup] Error deleting ${videoId}:`, e);
      }
    }
  }
  try {
    const files = await fs.readdir(VIDEO_STORAGE_DIR);
    for (const file of files) {
      if (file.endsWith(".mp4")) {
        const videoId = file.replace(".mp4", "");
        if (!videoIndex.has(videoId)) {
          const filePath = path.join(VIDEO_STORAGE_DIR, file);
          const stats = await fs.stat(filePath);
          const fileAge = now - stats.mtimeMs;
          if (fileAge > VIDEO_EXPIRY_HOURS * 60 * 60 * 1e3) {
            await fs.unlink(filePath).catch(() => {
            });
            const metaPath = path.join(VIDEO_STORAGE_DIR, `${videoId}.meta.json`);
            await fs.unlink(metaPath).catch(() => {
            });
            deletedCount++;
            console.log(`[LocalDisk Cleanup] Deleted orphaned video file: ${file}`);
          }
        }
      }
    }
  } catch (e) {
    console.error("[LocalDisk Cleanup] Error scanning for orphaned files:", e);
  }
  if (deletedCount > 0) {
    console.log(`[LocalDisk Cleanup] Cleanup complete. Deleted ${deletedCount} expired videos.`);
  }
  return deletedCount;
}
async function getStorageStats() {
  let totalSizeBytes = 0;
  let oldestCreated = null;
  let newestCreated = null;
  const values = Array.from(videoIndex.values());
  for (const metadata of values) {
    totalSizeBytes += metadata.sizeBytes;
    if (oldestCreated === null || metadata.createdAt < oldestCreated) {
      oldestCreated = metadata.createdAt;
    }
    if (newestCreated === null || metadata.createdAt > newestCreated) {
      newestCreated = metadata.createdAt;
    }
  }
  return {
    totalVideos: videoIndex.size,
    totalSizeBytes,
    totalSizeMB: Math.round(totalSizeBytes / (1024 * 1024)),
    totalSizeGB: Math.round(totalSizeBytes / (1024 * 1024 * 1024) * 100) / 100,
    oldestVideo: oldestCreated ? new Date(oldestCreated) : null,
    newestVideo: newestCreated ? new Date(newestCreated) : null,
    expiryHours: VIDEO_EXPIRY_HOURS
  };
}
function listAllVideos() {
  return Array.from(videoIndex.values()).sort((a, b) => b.createdAt - a.createdAt);
}
function startCleanupJob() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
  console.log(`[LocalDisk] Starting cleanup job (every ${CLEANUP_INTERVAL_MS / 1e3 / 60} minutes)`);
  cleanupInterval = setInterval(async () => {
    try {
      await cleanupExpiredVideos();
    } catch (e) {
      console.error("[LocalDisk Cleanup] Job error:", e);
    }
  }, CLEANUP_INTERVAL_MS);
  setTimeout(async () => {
    try {
      await cleanupExpiredVideos();
    } catch (e) {
      console.error("[LocalDisk Cleanup] Initial cleanup error:", e);
    }
  }, 1e4);
}
function stopCleanupJob() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log("[LocalDisk] Cleanup job stopped");
  }
}
async function initLocalDiskStorage() {
  console.log("[LocalDisk] Initializing local disk storage...");
  console.log(`[LocalDisk] Storage directory: ${VIDEO_STORAGE_DIR}`);
  console.log(`[LocalDisk] Video expiry: ${VIDEO_EXPIRY_HOURS} hours`);
  await loadExistingVideos();
  startCleanupJob();
  const stats = await getStorageStats();
  console.log(`[LocalDisk] Ready. ${stats.totalVideos} videos, ${stats.totalSizeMB}MB total`);
}
var VIDEO_STORAGE_DIR, VIDEO_EXPIRY_HOURS, CLEANUP_INTERVAL_MS, videoIndex, cleanupInterval;
var init_localDiskStorage = __esm({
  "server/localDiskStorage.ts"() {
    "use strict";
    VIDEO_STORAGE_DIR = path.join(process.cwd(), "temp_video");
    VIDEO_EXPIRY_HOURS = 3;
    CLEANUP_INTERVAL_MS = 5 * 60 * 1e3;
    videoIndex = /* @__PURE__ */ new Map();
    cleanupInterval = null;
  }
});

// server/memoryVideoCache.ts
var memoryVideoCache_exports = {};
__export(memoryVideoCache_exports, {
  clearMemoryCache: () => clearMemoryCache,
  deleteVideoFromMemory: () => deleteVideoFromMemory,
  getMemoryCacheStats: () => getMemoryCacheStats,
  getVideoFromMemory: () => getVideoFromMemory,
  listCachedVideos: () => listCachedVideos,
  storeVideoInMemory: () => storeVideoInMemory
});
function log(message) {
  const timestamp = (/* @__PURE__ */ new Date()).toISOString().split("T")[1].slice(0, 8);
  console.log(`[${timestamp}] [MemCache] ${message}`);
}
function storeVideoInMemory(videoId, buffer, prompt, aspectRatio) {
  const sizeBytes = buffer.length;
  if (sizeBytes > MAX_ITEM_BYTES) {
    log(`Rejected ${videoId}: ${(sizeBytes / 1024 / 1024).toFixed(1)}MB exceeds max ${MAX_ITEM_BYTES / 1024 / 1024}MB`);
    return false;
  }
  while (currentCacheBytes + sizeBytes > MAX_CACHE_BYTES && cache.size > 0) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey) {
      evictItem(oldestKey);
    }
  }
  if (currentCacheBytes + sizeBytes > MAX_CACHE_BYTES) {
    log(`Rejected ${videoId}: No space available (${(currentCacheBytes / 1024 / 1024).toFixed(1)}MB used)`);
    return false;
  }
  cache.set(videoId, {
    buffer,
    videoId,
    prompt: prompt.slice(0, 200),
    // Truncate prompt for memory
    aspectRatio,
    createdAt: Date.now(),
    sizeBytes
  });
  currentCacheBytes += sizeBytes;
  log(`Stored ${videoId}: ${(sizeBytes / 1024 / 1024).toFixed(1)}MB (total: ${(currentCacheBytes / 1024 / 1024).toFixed(1)}MB, items: ${cache.size})`);
  return true;
}
function getVideoFromMemory(videoId) {
  const cached = cache.get(videoId);
  if (!cached) return null;
  cache.delete(videoId);
  cache.set(videoId, cached);
  return cached.buffer;
}
function deleteVideoFromMemory(videoId) {
  const cached = cache.get(videoId);
  if (!cached) return false;
  cached.buffer.fill(0);
  currentCacheBytes -= cached.sizeBytes;
  cache.delete(videoId);
  log(`Deleted ${videoId}: freed ${(cached.sizeBytes / 1024 / 1024).toFixed(1)}MB`);
  return true;
}
function evictItem(videoId) {
  const cached = cache.get(videoId);
  if (!cached) return;
  cached.buffer.fill(0);
  currentCacheBytes -= cached.sizeBytes;
  cache.delete(videoId);
  log(`Evicted ${videoId} (LRU): freed ${(cached.sizeBytes / 1024 / 1024).toFixed(1)}MB`);
}
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
function getMemoryCacheStats() {
  return {
    count: cache.size,
    sizeBytes: currentCacheBytes,
    sizeMB: Math.round(currentCacheBytes / 1024 / 1024 * 10) / 10,
    maxMB: MAX_CACHE_BYTES / 1024 / 1024,
    usagePercent: Math.round(currentCacheBytes / MAX_CACHE_BYTES * 100),
    oldestItemAge: cache.size > 0 ? Math.round((Date.now() - Array.from(cache.values())[0].createdAt) / 1e3 / 60) : 0
  };
}
function listCachedVideos() {
  return Array.from(cache.values()).map((v) => ({
    videoId: v.videoId,
    prompt: v.prompt,
    aspectRatio: v.aspectRatio,
    sizeMB: Math.round(v.sizeBytes / 1024 / 1024 * 10) / 10,
    ageMinutes: Math.round((Date.now() - v.createdAt) / 1e3 / 60)
  }));
}
function clearMemoryCache() {
  const values = Array.from(cache.values());
  for (const cached of values) {
    cached.buffer.fill(0);
  }
  cache.clear();
  currentCacheBytes = 0;
  log("Cache cleared");
}
var MAX_CACHE_BYTES, MAX_ITEM_BYTES, TTL_MS, CLEANUP_INTERVAL_MS2, cache, currentCacheBytes;
var init_memoryVideoCache = __esm({
  "server/memoryVideoCache.ts"() {
    "use strict";
    MAX_CACHE_BYTES = parseInt(process.env.BULK_MAX_CACHE_MB || "512", 10) * 1024 * 1024;
    MAX_ITEM_BYTES = 75 * 1024 * 1024;
    TTL_MS = 30 * 60 * 1e3;
    CLEANUP_INTERVAL_MS2 = 5 * 60 * 1e3;
    cache = /* @__PURE__ */ new Map();
    currentCacheBytes = 0;
    setInterval(cleanupExpired, CLEANUP_INTERVAL_MS2);
    log(`Initialized: max ${MAX_CACHE_BYTES / 1024 / 1024}MB, TTL ${TTL_MS / 6e4}min`);
  }
});

// server/googleDrive.ts
var googleDrive_exports = {};
__export(googleDrive_exports, {
  getDirectDownloadLink: () => getDirectDownloadLink,
  uploadBase64VideoToGoogleDrive: () => uploadBase64VideoToGoogleDrive,
  uploadVideoToGoogleDrive: () => uploadVideoToGoogleDrive
});
import { google } from "googleapis";
import { createReadStream as createReadStream2 } from "fs";
import { readFile } from "fs/promises";
async function getGoogleDriveCredentials() {
  try {
    const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
    const settings = await storage2.getAppSettings();
    if (settings?.googleDriveCredentials) {
      const parsed = JSON.parse(settings.googleDriveCredentials);
      console.log("[Google Drive] Using credentials from database");
      return parsed;
    }
  } catch (dbError) {
    console.log("[Google Drive] Could not get credentials from database:", dbError);
  }
  const envCredentials = process.env.GOOGLE_DRIVE_CREDENTIALS;
  if (envCredentials) {
    console.log("[Google Drive] Using credentials from environment variable");
    return JSON.parse(envCredentials);
  }
  throw new Error("Google Drive credentials not configured. Please add them in Admin Settings.");
}
async function getGoogleDriveFolderId() {
  try {
    const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
    const settings = await storage2.getAppSettings();
    if (settings?.googleDriveFolderId) {
      console.log("[Google Drive] Using folder ID from database:", settings.googleDriveFolderId);
      return settings.googleDriveFolderId;
    }
  } catch (dbError) {
    console.log("[Google Drive] Could not get folder ID from database:", dbError);
  }
  const envFolderId = process.env.GOOGLE_DRIVE_FOLDER_ID;
  if (envFolderId) {
    console.log("[Google Drive] Using folder ID from environment variable");
    return envFolderId;
  }
  console.log("[Google Drive] Using default folder ID:", DEFAULT_SHARED_DRIVE_ID);
  return DEFAULT_SHARED_DRIVE_ID;
}
async function uploadVideoToGoogleDrive(filePath, fileName = "merged-video.mp4") {
  try {
    console.log("[Google Drive] Starting upload from local file:", filePath);
    const credentialsJson = await getGoogleDriveCredentials();
    const auth = new google.auth.GoogleAuth({
      credentials: credentialsJson,
      scopes: ["https://www.googleapis.com/auth/drive.file"]
    });
    const drive = google.drive({ version: "v3", auth });
    const fileBuffer = await readFile(filePath);
    console.log("[Google Drive] File size:", fileBuffer.byteLength, "bytes");
    const fileMetadata = {
      name: fileName,
      mimeType: "video/mp4"
    };
    console.log("[Google Drive] Uploading to Google Drive...");
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: {
        mimeType: "video/mp4",
        body: createReadStream2(filePath)
      },
      fields: "id, webViewLink, webContentLink"
    });
    const fileId = response.data.id;
    if (!fileId) {
      throw new Error("Failed to get file ID from Google Drive");
    }
    console.log("[Google Drive] Upload successful! File ID:", fileId);
    await drive.permissions.create({
      fileId,
      requestBody: {
        role: "reader",
        type: "anyone"
      }
    });
    console.log("[Google Drive] File set to public access");
    const file = await drive.files.get({
      fileId,
      fields: "webViewLink, webContentLink"
    });
    return {
      id: fileId,
      webViewLink: file.data.webViewLink || "",
      webContentLink: file.data.webContentLink || ""
    };
  } catch (error) {
    console.error("[Google Drive] Upload error:", error);
    throw new Error(
      `Failed to upload video to Google Drive: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}
async function uploadBase64VideoToGoogleDrive(base64Data, fileName = `video-${Date.now()}.mp4`) {
  try {
    console.log("[Google Drive] Starting base64 video upload to Shared Drive...");
    const credentialsJson = await getGoogleDriveCredentials();
    const folderId = await getGoogleDriveFolderId();
    const auth = new google.auth.GoogleAuth({
      credentials: credentialsJson,
      scopes: ["https://www.googleapis.com/auth/drive.file"]
    });
    const drive = google.drive({ version: "v3", auth });
    const videoBuffer = Buffer.from(base64Data, "base64");
    console.log("[Google Drive] Video size:", Math.round(videoBuffer.length / (1024 * 1024)), "MB");
    const { Readable } = await import("stream");
    const bufferStream = new Readable();
    bufferStream.push(videoBuffer);
    bufferStream.push(null);
    const fileMetadata = {
      name: fileName,
      mimeType: "video/mp4",
      parents: [folderId]
    };
    console.log("[Google Drive] Uploading to Shared Drive:", folderId);
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: {
        mimeType: "video/mp4",
        body: bufferStream
      },
      fields: "id, webViewLink, webContentLink",
      supportsAllDrives: true
    });
    const fileId = response.data.id;
    if (!fileId) {
      throw new Error("Failed to get file ID from Google Drive");
    }
    console.log("[Google Drive] Upload successful! File ID:", fileId);
    await drive.permissions.create({
      fileId,
      requestBody: {
        role: "reader",
        type: "anyone"
      },
      supportsAllDrives: true
    });
    console.log("[Google Drive] File set to public access");
    const file = await drive.files.get({
      fileId,
      fields: "webViewLink, webContentLink",
      supportsAllDrives: true
    });
    return {
      id: fileId,
      webViewLink: file.data.webViewLink || "",
      webContentLink: file.data.webContentLink || ""
    };
  } catch (error) {
    console.error("[Google Drive] Base64 upload error:", error);
    throw new Error(
      `Failed to upload video to Google Drive: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}
function getDirectDownloadLink(fileId) {
  return `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t`;
}
var DEFAULT_SHARED_DRIVE_ID;
var init_googleDrive = __esm({
  "server/googleDrive.ts"() {
    "use strict";
    DEFAULT_SHARED_DRIVE_ID = "0AA_GJi95SjbdUk9PVA";
  }
});

// server/cloudinary.ts
import { readFile as readFile2 } from "fs/promises";
async function getCloudinaryConfig() {
  const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
  const settings = await storage2.getAppSettings();
  const cloudName = settings?.cloudinaryCloudName || "dfk0nvgff";
  const uploadPreset = settings?.cloudinaryUploadPreset || "demo123";
  return {
    cloudName,
    uploadPreset,
    videoUploadUrl: `https://api.cloudinary.com/v1_1/${cloudName}/video/upload`,
    imageUploadUrl: `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`
  };
}
async function uploadVideoToCloudinary(videoUrlOrPath) {
  try {
    const config = await getCloudinaryConfig();
    let videoBlob;
    if (videoUrlOrPath.startsWith("http://") || videoUrlOrPath.startsWith("https://")) {
      console.log("[Cloudinary] Starting upload from URL:", videoUrlOrPath.substring(0, 100));
      console.log("[Cloudinary] Fetching video from URL...");
      const videoResponse = await fetch(videoUrlOrPath);
      if (!videoResponse.ok) {
        throw new Error(`Failed to fetch video: ${videoResponse.statusText}`);
      }
      videoBlob = await videoResponse.blob();
      console.log("[Cloudinary] Video fetched, size:", videoBlob.size, "bytes");
    } else {
      console.log("[Cloudinary] Starting upload from local file:", videoUrlOrPath);
      const fileBuffer = await readFile2(videoUrlOrPath);
      videoBlob = new Blob([fileBuffer], { type: "video/mp4" });
      console.log("[Cloudinary] File read, size:", videoBlob.size, "bytes");
    }
    const formData = new FormData();
    formData.append("file", videoBlob, "video.mp4");
    formData.append("upload_preset", config.uploadPreset);
    console.log("[Cloudinary] Uploading to Cloudinary...");
    const uploadResponse = await fetch(config.videoUploadUrl, {
      method: "POST",
      body: formData
    });
    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      throw new Error(`Cloudinary upload failed: ${uploadResponse.statusText} - ${errorText}`);
    }
    const result = await uploadResponse.json();
    console.log("[Cloudinary] Upload successful! URL:", result.secure_url);
    return result.secure_url;
  } catch (error) {
    console.error("[Cloudinary] Upload error:", error);
    throw new Error(`Failed to upload video to Cloudinary: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
}
async function uploadBase64VideoToCloudinary(base64Data) {
  try {
    const config = await getCloudinaryConfig();
    console.log("[Cloudinary] Converting base64 video for upload...");
    const videoBuffer = Buffer.from(base64Data, "base64");
    console.log(`[Cloudinary] Video size: ${Math.round(videoBuffer.length / (1024 * 1024))}MB`);
    const videoBlob = new Blob([videoBuffer], { type: "video/mp4" });
    const formData = new FormData();
    formData.append("file", videoBlob, "video.mp4");
    formData.append("upload_preset", config.uploadPreset);
    formData.append("folder", "ai-videos");
    console.log("[Cloudinary] Uploading video to Cloudinary...");
    const uploadResponse = await fetch(config.videoUploadUrl, {
      method: "POST",
      body: formData
    });
    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      throw new Error(`Cloudinary upload failed: ${uploadResponse.statusText} - ${errorText}`);
    }
    const result = await uploadResponse.json();
    console.log("[Cloudinary] Video upload successful! URL:", result.secure_url);
    return result.secure_url;
  } catch (error) {
    console.error("[Cloudinary] Video upload error:", error);
    throw new Error(`Failed to upload video to Cloudinary: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
}
async function getStorageMethod() {
  const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
  const settings = await storage2.getAppSettings();
  return settings?.storageMethod || "cloudinary_with_fallback";
}
async function uploadBase64VideoWithFallback(base64Data, videoId, prompt, aspectRatio) {
  const storageMethod = await getStorageMethod();
  const sizeMB = Math.round(Buffer.from(base64Data, "base64").length / 1024 / 1024 * 10) / 10;
  console.log(`[Upload] Method: ${storageMethod}, Size: ${sizeMB}MB`);
  if (storageMethod === "direct_to_user") {
    console.log(`[Upload] Direct to user mode - returning data URL (${sizeMB}MB)`);
    const dataUrl = `data:video/mp4;base64,${base64Data}`;
    return { url: dataUrl, storedInMemory: false };
  }
  if (storageMethod === "local_disk") {
    try {
      const { saveVideoToLocalDisk: saveVideoToLocalDisk2 } = await Promise.resolve().then(() => (init_localDiskStorage(), localDiskStorage_exports));
      const result = await saveVideoToLocalDisk2(base64Data, {
        prompt,
        externalVideoId: videoId
        // Preserve video ID from generation pipeline
      });
      console.log(`[Upload] Local disk success: ${result.videoUrl}`);
      return { url: result.videoUrl, storedInMemory: false };
    } catch (localError) {
      console.log("[Upload] Local disk failed, trying Cloudinary fallback...");
      try {
        const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
        return { url: cloudinaryUrl, storedInMemory: false };
      } catch (cloudinaryError) {
        console.error("[Upload] All storage methods failed:", { localError, cloudinaryError });
        throw new Error(`Local disk and Cloudinary failed: ${localError}`);
      }
    }
  }
  const tryMemoryFallback = async (cloudinaryError, driveError) => {
    if (!videoId) {
      throw new Error(`Both uploads failed. Cloudinary: ${cloudinaryError}, Drive: ${driveError}`);
    }
    console.log("[Upload] Both cloud uploads failed, storing in memory cache...");
    const { storeVideoInMemory: storeVideoInMemory2 } = await Promise.resolve().then(() => (init_memoryVideoCache(), memoryVideoCache_exports));
    const buffer = Buffer.from(base64Data, "base64");
    const stored = storeVideoInMemory2(videoId, buffer, prompt || "", aspectRatio || "16:9");
    if (stored) {
      console.log(`[Upload] Video ${videoId} stored in memory cache (${sizeMB}MB)`);
      return { url: `memory://${videoId}`, storedInMemory: true };
    }
    throw new Error(`All storage methods failed. Cloudinary: ${cloudinaryError}, Drive: ${driveError}, Memory: cache full`);
  };
  if (storageMethod === "google_drive") {
    try {
      const { uploadBase64VideoToGoogleDrive: uploadBase64VideoToGoogleDrive2, getDirectDownloadLink: getDirectDownloadLink2 } = await Promise.resolve().then(() => (init_googleDrive(), googleDrive_exports));
      const driveResult = await uploadBase64VideoToGoogleDrive2(base64Data);
      const driveUrl = getDirectDownloadLink2(driveResult.id);
      console.log("[Upload] Drive success:", driveUrl.slice(0, 60));
      return { url: driveUrl, storedInMemory: false };
    } catch (driveError) {
      console.log("[Upload] Drive failed, trying Cloudinary...");
      try {
        const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
        return { url: cloudinaryUrl, storedInMemory: false };
      } catch (cloudinaryError) {
        return tryMemoryFallback(cloudinaryError, driveError);
      }
    }
  }
  if (storageMethod === "cloudinary") {
    try {
      const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
      return { url: cloudinaryUrl, storedInMemory: false };
    } catch (cloudinaryError) {
      try {
        const { uploadBase64VideoToGoogleDrive: uploadBase64VideoToGoogleDrive2, getDirectDownloadLink: getDirectDownloadLink2 } = await Promise.resolve().then(() => (init_googleDrive(), googleDrive_exports));
        const driveResult = await uploadBase64VideoToGoogleDrive2(base64Data);
        const driveUrl = getDirectDownloadLink2(driveResult.id);
        return { url: driveUrl, storedInMemory: false };
      } catch (driveError) {
        return tryMemoryFallback(cloudinaryError, driveError);
      }
    }
  }
  try {
    const cloudinaryUrl = await uploadBase64VideoToCloudinary(base64Data);
    return { url: cloudinaryUrl, storedInMemory: false };
  } catch (cloudinaryError) {
    console.log("[Upload] Cloudinary failed, trying Drive...");
    try {
      const { uploadBase64VideoToGoogleDrive: uploadBase64VideoToGoogleDrive2, getDirectDownloadLink: getDirectDownloadLink2 } = await Promise.resolve().then(() => (init_googleDrive(), googleDrive_exports));
      const driveResult = await uploadBase64VideoToGoogleDrive2(base64Data);
      const driveUrl = getDirectDownloadLink2(driveResult.id);
      return { url: driveUrl, storedInMemory: false };
    } catch (driveError) {
      return tryMemoryFallback(cloudinaryError, driveError);
    }
  }
}
var init_cloudinary = __esm({
  "server/cloudinary.ts"() {
    "use strict";
  }
});

// server/bulkQueueFlow.ts
var bulkQueueFlow_exports = {};
__export(bulkQueueFlow_exports, {
  addToFlowQueue: () => addToFlowQueue,
  deleteDirectVideo: () => deleteDirectVideo,
  deleteVideoBufferFromBulk: () => deleteVideoBufferFromBulk,
  getBulkCacheStats: () => getBulkCacheStats,
  getDirectCacheStats: () => getDirectCacheStats,
  getDirectVideo: () => getDirectVideo,
  getFlowQueueStatus: () => getFlowQueueStatus,
  getGlobalStats: () => getGlobalStats,
  getMemoryStats: () => getMemoryStats,
  getUploadQueueStats: () => getUploadQueueStats,
  getVideoBufferFromBulk: () => getVideoBufferFromBulk,
  processFlowQueue: () => processFlowQueue,
  stopFlowQueue: () => stopFlowQueue
});
import crypto2 from "crypto";
import * as fs2 from "fs/promises";
import * as path2 from "path";
async function ensureTempDirs() {
  try {
    await fs2.mkdir(TEMP_VIDEO_DIR, { recursive: true });
    await fs2.mkdir(TEMP_UPLOAD_DIR, { recursive: true });
  } catch (e) {
  }
}
async function cleanupOrphanedTempFiles() {
  let cleanedVideos = 0;
  let cleanedUploads = 0;
  try {
    const videoFiles = await fs2.readdir(TEMP_VIDEO_DIR);
    for (const file of videoFiles) {
      if (file.endsWith(".b64")) {
        await deleteTempFile(path2.join(TEMP_VIDEO_DIR, file));
        cleanedVideos++;
      }
    }
    const uploadFiles = await fs2.readdir(TEMP_UPLOAD_DIR);
    for (const file of uploadFiles) {
      if (file.endsWith(".b64")) {
        await deleteTempFile(path2.join(TEMP_UPLOAD_DIR, file));
        cleanedUploads++;
      }
    }
    if (cleanedVideos > 0 || cleanedUploads > 0) {
      console.log(`[Startup] Cleaned ${cleanedVideos} orphaned video files and ${cleanedUploads} orphaned upload files from previous session`);
    }
  } catch (e) {
    console.error("[Startup] Error cleaning orphaned temp files:", e);
  }
}
function getTempVideoPath(videoId) {
  return path2.join(TEMP_VIDEO_DIR, `${videoId}.b64`);
}
function getTempUploadPath(videoId) {
  return path2.join(TEMP_UPLOAD_DIR, `${videoId}.b64`);
}
async function deleteTempFile(filePath) {
  try {
    await fs2.unlink(filePath);
    return true;
  } catch (e) {
    return false;
  }
}
function formatBytes(bytes) {
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)}MB`;
}
function logMemoryUsage() {
  const usage = process.memoryUsage();
  const heapUsedPercent = usage.heapUsed / usage.heapTotal * 100;
  if (heapUsedPercent > 50 || LOG_LEVEL >= 3) {
    console.log(`[Memory] Heap: ${formatBytes(usage.heapUsed)}/${formatBytes(usage.heapTotal)} (${heapUsedPercent.toFixed(1)}%) | RSS: ${formatBytes(usage.rss)} | External: ${formatBytes(usage.external)}`);
  }
  if (usage.heapUsed / usage.heapTotal > MEMORY_HIGH_WATER_MARK) {
    console.warn(`[Memory] WARNING: Heap usage at ${heapUsedPercent.toFixed(1)}% - approaching limit!`);
    console.warn(`[Memory] Cache stats: Videos=${directVideoCacheMeta.size}, Uploads=${uploadQueue.length}`);
  }
}
function getMemoryStats() {
  const usage = process.memoryUsage();
  return {
    heapUsed: usage.heapUsed,
    heapTotal: usage.heapTotal,
    heapUsedPercent: Math.round(usage.heapUsed / usage.heapTotal * 100),
    rss: usage.rss,
    external: usage.external,
    videoCacheSize: directVideoCacheMeta.size,
    uploadQueueSize: uploadQueue.length,
    formatted: {
      heapUsed: formatBytes(usage.heapUsed),
      heapTotal: formatBytes(usage.heapTotal),
      rss: formatBytes(usage.rss)
    }
  };
}
async function enforceGlobalLimits() {
  const now = Date.now();
  if (directVideoCacheMeta.size > MAX_TOTAL_CACHED_VIDEOS) {
    const entries = Array.from(directVideoCacheMeta.entries());
    entries.sort((a, b) => a[1].addedAt - b[1].addedAt);
    const toEvict = entries.slice(0, entries.length - MAX_TOTAL_CACHED_VIDEOS);
    for (const [videoId, meta] of toEvict) {
      await deleteTempFile(meta.filePath);
      directVideoCacheMeta.delete(videoId);
    }
    if (toEvict.length > 0) {
      console.log(`[GlobalLimits] Evicted ${toEvict.length} oldest videos from cache`);
    }
  }
  if (uploadQueue.length > MAX_TOTAL_UPLOAD_QUEUE) {
    const toRemove = uploadQueue.length - MAX_TOTAL_UPLOAD_QUEUE;
    const removed = uploadQueue.splice(0, toRemove);
    for (const upload of removed) {
      await deleteTempFile(upload.filePath);
      decrementUserUploadCount(upload.userId);
    }
    console.log(`[GlobalLimits] Evicted ${toRemove} oldest uploads from queue`);
  }
  let staleCount = 0;
  for (let i = uploadQueue.length - 1; i >= 0; i--) {
    const upload = uploadQueue[i];
    if (now - upload.addedAt > STALE_UPLOAD_TIMEOUT) {
      await deleteTempFile(upload.filePath);
      decrementUserUploadCount(upload.userId);
      uploadQueue.splice(i, 1);
      staleCount++;
    }
  }
  if (staleCount > 0) {
    console.log(`[GlobalLimits] Cleaned ${staleCount} stale uploads (>30min old)`);
  }
}
function shouldLog(level, sample = false) {
  if (level > LOG_LEVEL) return false;
  if (sample && LOG_LEVEL < 3) return Math.random() < LOG_SAMPLING_RATE;
  return true;
}
async function getCachedActiveTokens() {
  const now = Date.now();
  if (now - tokensCacheTime > TOKENS_CACHE_TTL || cachedTokens.length === 0) {
    cachedTokens = await storage.getActiveApiTokens();
    tokensCacheTime = now;
  }
  return cachedTokens;
}
function invalidateTokenCache() {
  tokensCacheTime = 0;
}
async function getCachedStorageMethod() {
  const now = Date.now();
  if (now - storageMethodCacheTime > STORAGE_METHOD_CACHE_TTL) {
    try {
      const settings = await storage.getAppSettings();
      cachedStorageMethod = settings?.storageMethod || "cloudinary_with_fallback";
      storageMethodCacheTime = now;
    } catch (e) {
    }
  }
  return cachedStorageMethod;
}
async function saveDirectVideo(videoId, base64, userId) {
  const filePath = getTempVideoPath(videoId);
  try {
    await fs2.writeFile(filePath, base64, "utf8");
    try {
      directVideoCacheMeta.set(videoId, {
        addedAt: Date.now(),
        userId,
        filePath
      });
    } catch (metaError) {
      await deleteTempFile(filePath);
      console.error(`[DirectCache] Failed to set metadata for ${videoId}, cleaned up file:`, metaError);
      return false;
    }
    return true;
  } catch (e) {
    await deleteTempFile(filePath);
    console.error(`[DirectCache] Failed to save video ${videoId}:`, e);
    return false;
  }
}
async function getDirectVideo(videoId) {
  const meta = directVideoCacheMeta.get(videoId);
  if (!meta) return null;
  try {
    const base64 = await fs2.readFile(meta.filePath, "utf8");
    return base64;
  } catch (e) {
    directVideoCacheMeta.delete(videoId);
    return null;
  }
}
async function deleteDirectVideo(videoId) {
  const meta = directVideoCacheMeta.get(videoId);
  if (!meta) return false;
  const deleted = await deleteTempFile(meta.filePath);
  directVideoCacheMeta.delete(videoId);
  if (deleted) {
    console.log(`[DirectCache] Video ${videoId} deleted after confirmed download`);
  }
  return deleted;
}
function getDirectCacheStats() {
  const perUser = {};
  const entries = Array.from(directVideoCacheMeta.entries());
  for (const [_, meta] of entries) {
    perUser[meta.userId] = (perUser[meta.userId] || 0) + 1;
  }
  return { total: directVideoCacheMeta.size, perUser };
}
function logUpload(message, level = 2) {
  if (!shouldLog(level)) return;
  const timestamp = (/* @__PURE__ */ new Date()).toISOString().split("T")[1].slice(0, 8);
  console.log(`[${timestamp}] [Upload] ${message}`);
}
function countUserUploads(userId) {
  return userUploadCounts.get(userId) || 0;
}
function incrementUserUploadCount(userId) {
  userUploadCounts.set(userId, (userUploadCounts.get(userId) || 0) + 1);
}
function decrementUserUploadCount(userId) {
  const current = userUploadCounts.get(userId) || 0;
  if (current <= 1) {
    userUploadCounts.delete(userId);
  } else {
    userUploadCounts.set(userId, current - 1);
  }
}
async function queueUpload(videoId, base64Video, userId, sceneNumber) {
  const userUploadCount = countUserUploads(userId);
  if (userUploadCount >= MAX_UPLOADS_PER_USER) {
    logUpload(`User ${userId.slice(0, 8)}: Upload queue full (${userUploadCount}/${MAX_UPLOADS_PER_USER}), waiting...`);
    const maxWait = 6e4;
    const checkInterval = 1e3;
    let waited = 0;
    while (countUserUploads(userId) >= MAX_UPLOADS_PER_USER && waited < maxWait) {
      await new Promise((r) => setTimeout(r, checkInterval));
      waited += checkInterval;
    }
    if (countUserUploads(userId) >= MAX_UPLOADS_PER_USER) {
      logUpload(`User ${userId.slice(0, 8)}: Upload rejected after ${maxWait / 1e3}s wait - queue still full`);
      return false;
    }
  }
  const filePath = getTempUploadPath(videoId);
  try {
    await fs2.writeFile(filePath, base64Video, "utf8");
  } catch (e) {
    logUpload(`Failed to save upload temp file for video ${videoId}: ${e}`);
    return false;
  }
  uploadQueue.push({
    videoId,
    filePath,
    // Store file path, NOT base64 data
    userId,
    sceneNumber,
    retries: 0,
    addedAt: Date.now()
  });
  incrementUserUploadCount(userId);
  logUpload(`Queued video ${sceneNumber} for user ${userId.slice(0, 8)} (user: ${countUserUploads(userId)}, total: ${uploadQueue.length})`);
  startUploadProcessor();
  return true;
}
async function processUpload(upload) {
  activeUploads++;
  const startTime = Date.now();
  try {
    const base64Video = await fs2.readFile(upload.filePath, "utf8");
    const uploadResult = await uploadBase64VideoWithFallback(base64Video, upload.videoId);
    const duration = Math.round((Date.now() - startTime) / 1e3);
    if (uploadResult.url) {
      await withRetry(() => storage.updateVideoHistoryFields(upload.videoId, {
        status: "completed",
        videoUrl: uploadResult.url
      }), 3, 2e3);
      logUpload(`Video ${upload.sceneNumber} uploaded in ${duration}s: ${uploadResult.url.slice(0, 50)}...`);
    }
    decrementUserUploadCount(upload.userId);
    await deleteTempFile(upload.filePath);
  } catch (error) {
    const duration = Math.round((Date.now() - startTime) / 1e3);
    logUpload(`Video ${upload.sceneNumber} upload FAILED after ${duration}s: ${error}`);
    if (upload.retries < MAX_UPLOAD_RETRIES) {
      upload.retries++;
      uploadQueue.push(upload);
      logUpload(`Requeueing video ${upload.sceneNumber} (retry ${upload.retries}/${MAX_UPLOAD_RETRIES})`);
    } else {
      decrementUserUploadCount(upload.userId);
      await deleteTempFile(upload.filePath);
      try {
        await withRetry(() => storage.updateVideoHistoryFields(upload.videoId, {
          status: "failed",
          errorMessage: "Upload failed after max retries"
        }), 3, 2e3);
      } catch (dbError) {
        logUpload(`DB error updating failed status: ${dbError}`);
      }
      logUpload(`Video ${upload.sceneNumber} PERMANENTLY FAILED after ${MAX_UPLOAD_RETRIES} retries`);
    }
  } finally {
    activeUploads--;
  }
}
function startUploadProcessor() {
  if (uploadProcessorRunning) return;
  uploadProcessorRunning = true;
  (async () => {
    while (uploadQueue.length > 0 || activeUploads > 0) {
      while (uploadQueue.length > 0 && activeUploads < MAX_CONCURRENT_UPLOADS) {
        const upload = uploadQueue.shift();
        processUpload(upload);
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    uploadProcessorRunning = false;
    logUpload("Upload processor finished - queue empty");
  })();
}
function getUploadQueueStats() {
  return {
    pending: uploadQueue.length,
    active: activeUploads,
    total: uploadQueue.length + activeUploads
  };
}
function getVideoBufferFromBulk(videoId) {
  return null;
}
function deleteVideoBufferFromBulk(videoId) {
  return false;
}
function getBulkCacheStats() {
  return { count: 0, sizeBytes: 0, sizeMB: 0, sizeGB: 0 };
}
function logMemory(context) {
  const used = process.memoryUsage();
  console.log(`[Memory] ${context}: Heap ${Math.round(used.heapUsed / 1024 / 1024)}MB / ${Math.round(used.heapTotal / 1024 / 1024)}MB`);
}
function getGlobalStats() {
  let totalQueuedVideos = 0;
  let totalActiveWorkers = 0;
  const activeUsers = [];
  userQueues.forEach((queue, userId) => {
    if (queue.isProcessing || queue.queue.length > 0 || queue.activeWorkers > 0) {
      activeUsers.push(userId);
      totalQueuedVideos += queue.queue.length;
      totalActiveWorkers += queue.activeWorkers;
    }
  });
  return {
    globalActiveWorkers,
    totalQueuedVideos,
    totalActiveWorkers,
    activeUserCount: activeUsers.length,
    globalLimit: GLOBAL_MAX_CONCURRENT_WORKERS,
    perUserLimit: MAX_CONCURRENT_PER_USER,
    perUserUploadLimit: MAX_UPLOADS_PER_USER
  };
}
function randomDelay(minMs, maxMs) {
  return Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
}
function cleanupInactiveQueues() {
  const now = Date.now();
  let cleaned = 0;
  userQueues.forEach((queue, userId) => {
    if (queue.isProcessing || queue.queue.length > 0 || queue.activeWorkers > 0) {
      return;
    }
    const lastActivity = queue.lastProgressAt || queue.processingStartedAt || 0;
    if (lastActivity > 0 && now - lastActivity > INACTIVE_QUEUE_TIMEOUT_MS) {
      userQueues.delete(userId);
      userUploadCounts.delete(userId);
      cleaned++;
    }
  });
  if (cleaned > 0) {
    console.log(`[BulkFlow] Cleaned up ${cleaned} inactive user queues. Active: ${userQueues.size}`);
  }
}
async function markStuckProcessingVideosAsFailed(userId, batchVideoIds) {
  if (batchVideoIds.size === 0) return;
  try {
    const videoIds = Array.from(batchVideoIds);
    let markedCount = 0;
    for (const videoId of videoIds) {
      try {
        const video = await storage.getVideoById(videoId);
        if (video && video.status === "processing") {
          await storage.updateVideoHistoryFields(videoId, {
            status: "failed",
            errorMessage: "Stuck in processing - auto-recovered"
          });
          markedCount++;
        }
      } catch (e) {
      }
    }
    if (markedCount > 0) {
      console.log(`[BulkFlow] Marked ${markedCount} stuck "processing" videos as failed for user ${userId.slice(0, 8)}`);
    }
  } catch (error) {
    console.log(`[BulkFlow] Error marking stuck videos: ${error}`);
  }
}
function checkAndRecoverStuckQueues() {
  const now = Date.now();
  let recoveredCount = 0;
  userQueues.forEach((queue, userId) => {
    if (!queue.isProcessing) return;
    const lastActivity = queue.lastProgressAt || queue.processingStartedAt || now;
    const stuckDuration = now - lastActivity;
    if (stuckDuration > STUCK_QUEUE_TIMEOUT_MS) {
      const stuckWorkers = queue.activeWorkers;
      console.log(`[BulkFlow] STUCK DETECTED: User ${userId.slice(0, 8)} stuck for ${Math.round(stuckDuration / 1e3)}s`);
      console.log(`[BulkFlow] - Resetting: isProcessing=false, activeWorkers=0 (was ${stuckWorkers})`);
      console.log(`[BulkFlow] - Queue has ${queue.queue.length} pending videos`);
      queue.isProcessing = false;
      queue.activeWorkers = 0;
      globalActiveWorkers = Math.max(0, globalActiveWorkers - stuckWorkers);
      recoveredCount++;
      if (queue.queue.length > 0) {
        console.log(`[BulkFlow] - Restarting queue for ${queue.queue.length} PENDING videos only`);
        console.log(`[BulkFlow] - Videos already in "processing" status will NOT be retried`);
        setTimeout(() => processFlowQueue(userId), 100);
      } else {
        console.log(`[BulkFlow] - No pending videos in queue, marking stuck "processing" videos as failed`);
        markStuckProcessingVideosAsFailed(userId, queue.batchVideoIds);
      }
    }
  });
  if (recoveredCount > 0) {
    console.log(`[BulkFlow] Health check: Recovered ${recoveredCount} stuck queue(s)`);
  }
}
async function recoverPendingVideosFromDB() {
  try {
    const allPendingVideos = await storage.getAllPendingVideos();
    if (allPendingVideos.length === 0) return;
    const pendingByUser = /* @__PURE__ */ new Map();
    for (const video of allPendingVideos) {
      if (!pendingByUser.has(video.userId)) {
        pendingByUser.set(video.userId, []);
      }
      pendingByUser.get(video.userId).push(video);
    }
    console.log(`[BulkFlow] Recovery check: Found ${allPendingVideos.length} pending videos for ${pendingByUser.size} users`);
    for (const [userId, pendingVideos] of Array.from(pendingByUser.entries())) {
      const userQueue = getUserQueue(userId);
      if (userQueue.isProcessing) continue;
      const queuedVideoIds = new Set(userQueue.queue.map((v) => v.videoId));
      const missingPendingVideos = pendingVideos.filter(
        (v) => !queuedVideoIds.has(v.id)
      );
      if (missingPendingVideos.length === 0) continue;
      console.log(`[BulkFlow] Recovering ${missingPendingVideos.length} pending videos for user ${userId.slice(0, 8)}`);
      missingPendingVideos.sort(
        (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
      );
      const existingMaxScene = userQueue.queue.reduce((max, v) => Math.max(max, v.sceneNumber), 0);
      for (let i = 0; i < missingPendingVideos.length; i++) {
        const video = missingPendingVideos[i];
        userQueue.queue.push({
          videoId: video.id,
          prompt: video.prompt,
          aspectRatio: video.aspectRatio || "16:9",
          sceneNumber: existingMaxScene + i + 1,
          // Unique scene number based on existing max
          userId: video.userId
        });
        userQueue.batchVideoIds.add(video.id);
      }
      console.log(`[BulkFlow] Re-queued ${missingPendingVideos.length} videos (scenes ${existingMaxScene + 1}-${existingMaxScene + missingPendingVideos.length})`);
      setTimeout(() => processFlowQueue(userId), 100);
    }
  } catch (error) {
    console.log(`[BulkFlow] Error recovering pending videos: ${error}`);
  }
}
function log2(message, level = 2) {
  if (!shouldLog(level)) return;
  const timestamp = (/* @__PURE__ */ new Date()).toISOString().split("T")[1].slice(0, 8);
  console.log(`[${timestamp}] [BulkFlow] ${message}`);
}
function sanitizeForLog(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const sanitized = Array.isArray(obj) ? [] : {};
  for (const key in obj) {
    const value = obj[key];
    if (["rawBytes", "encodedVideo", "encodedImage", "imageBytes", "videoBytes"].includes(key)) {
      if (typeof value === "string" && value.length > 100) {
        sanitized[key] = `[REDACTED: ${Math.round(value.length / 1024)}KB]`;
      } else {
        sanitized[key] = value;
      }
    } else if (typeof value === "object") {
      sanitized[key] = sanitizeForLog(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}
function getUserQueue(userId) {
  if (!userQueues.has(userId)) {
    userQueues.set(userId, {
      queue: [],
      isProcessing: false,
      shouldStop: false,
      processingStartedAt: null,
      lastProgressAt: null,
      activeWorkers: 0,
      completedCount: 0,
      failedCount: 0,
      batchVideoIds: /* @__PURE__ */ new Set()
    });
  }
  return userQueues.get(userId);
}
async function cancelExistingBatch(userId) {
  const userQueue = getUserQueue(userId);
  let cancelledCount = 0;
  const queuedVideoIds = userQueue.queue.map((v) => v.videoId);
  cancelledCount += queuedVideoIds.length;
  userQueue.queue = [];
  const beforeUploadCount = uploadQueue.length;
  for (let i = uploadQueue.length - 1; i >= 0; i--) {
    if (uploadQueue[i].userId === userId) {
      cancelledCount++;
      uploadQueue.splice(i, 1);
    }
  }
  const removedFromUpload = beforeUploadCount - uploadQueue.length;
  userUploadCounts.delete(userId);
  if (userQueue.batchVideoIds.size > 0) {
    const videoIdsToCancel = Array.from(userQueue.batchVideoIds);
    try {
      await storage.batchCancelVideos(userId, videoIdsToCancel, "Cancelled - new batch started");
      log2(`Cancelled ${videoIdsToCancel.length} videos in DB for user ${userId}`);
    } catch (error) {
      log2(`Error cancelling videos in DB: ${error}`);
    }
  }
  userQueue.completedCount = 0;
  userQueue.failedCount = 0;
  userQueue.batchVideoIds.clear();
  if (cancelledCount > 0 || removedFromUpload > 0) {
    log2(`User ${userId}: Cancelled ${cancelledCount} queued + ${removedFromUpload} uploads from previous batch`);
  }
  return cancelledCount;
}
async function addToFlowQueue(videos, isNewBatch = true) {
  if (videos.length === 0) return;
  const userId = videos[0].userId;
  const userQueue = getUserQueue(userId);
  userQueue.shouldStop = false;
  if (isNewBatch) {
    await cancelExistingBatch(userId);
  }
  for (const video of videos) {
    userQueue.batchVideoIds.add(video.videoId);
  }
  userQueue.queue.push(...videos);
  log2(`User ${userId}: Added ${videos.length} videos. Queue: ${userQueue.queue.length}`);
  if (!userQueue.isProcessing) {
    processFlowQueue(userId);
  }
}
function stopFlowQueue(userId) {
  const userQueue = getUserQueue(userId);
  const remaining = userQueue.queue.length;
  userQueue.shouldStop = true;
  userQueue.queue.length = 0;
  userQueue.isProcessing = false;
  userQueue.activeWorkers = 0;
  userQueue.completedCount = 0;
  userQueue.failedCount = 0;
  userQueue.batchVideoIds.clear();
  log2(`User ${userId}: Stop requested. Cleared ${remaining} pending videos. Queue state fully reset.`);
  return { stopped: true, remaining };
}
function getFlowQueueStatus(userId) {
  const userQueue = getUserQueue(userId);
  return {
    isProcessing: userQueue.isProcessing,
    queueLength: userQueue.queue.length,
    activeWorkers: userQueue.activeWorkers,
    completedCount: userQueue.completedCount,
    failedCount: userQueue.failedCount,
    batchVideoIds: Array.from(userQueue.batchVideoIds)
    // Return as array for JSON serialization
  };
}
async function generateWhiskImage2(apiKey, prompt, aspectRatio) {
  const workflowId = crypto2.randomUUID();
  const sessionId = `;${Date.now()}`;
  const seed = Math.floor(Math.random() * 1e6);
  const imageAspectRatio = aspectRatio === "portrait" || aspectRatio === "9:16" ? "IMAGE_ASPECT_RATIO_PORTRAIT" : "IMAGE_ASPECT_RATIO_LANDSCAPE";
  const requestBody = {
    clientContext: {
      workflowId,
      tool: "BACKBONE",
      sessionId
    },
    imageModelSettings: {
      imageModel: "IMAGEN_3_5",
      aspectRatio: imageAspectRatio
    },
    seed,
    prompt,
    mediaCategory: "MEDIA_CATEGORY_BOARD"
  };
  const response = await fetch(`${WHISK_BASE_URL2}/whisk:generateImage`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Image generation failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }
  const data = await response.json();
  if (!data.imagePanels || data.imagePanels.length === 0 || !data.imagePanels[0].generatedImages || data.imagePanels[0].generatedImages.length === 0) {
    throw new Error("No image generated from Whisk API");
  }
  const generatedImage = data.imagePanels[0].generatedImages[0];
  return {
    encodedImage: generatedImage.encodedImage,
    mediaGenerationId: generatedImage.mediaGenerationId,
    workflowId: data.workflowId || workflowId
  };
}
async function startWhiskVideoGeneration2(apiKey, prompt, encodedImage, mediaGenerationId, workflowId) {
  const sessionId = `;${Date.now()}`;
  const requestBody = {
    clientContext: {
      sessionId,
      tool: "BACKBONE",
      workflowId
    },
    promptImageInput: {
      prompt,
      rawBytes: encodedImage,
      mediaGenerationId
    },
    modelNameType: "VEO_3_1_I2V_12STEP",
    modelKey: "",
    userInstructions: prompt,
    loopVideo: false
  };
  const response = await fetch(`${WHISK_BASE_URL2}/whisk:generateVideo`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Video generation start failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }
  const data = await response.json();
  if (!data.operation?.operation?.name) {
    throw new Error("No operation name returned from video generation");
  }
  return data.operation.operation.name;
}
async function checkWhiskVideoStatus2(apiKey, operationName, videoId, userId, sceneNumber) {
  const requestBody = {
    operations: [{
      operation: {
        name: operationName
      }
    }]
  };
  const response = await fetch(`${WHISK_BASE_URL2}:runVideoFxSingleClipsStatusCheck`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    throw new Error(`Status check failed: ${response.status}`);
  }
  const data = await response.json();
  const sanitizedData = sanitizeForLog(data);
  log2(`Poll: status=${sanitizedData.operations?.[0]?.status || "unknown"}, done=${sanitizedData.operations?.[0]?.done || false}`);
  if (!data.operations || data.operations.length === 0) {
    return { done: false };
  }
  const operationData = data.operations[0];
  const operation = operationData.operation;
  const status = operationData.status;
  if (operation?.error) {
    return {
      done: true,
      error: operation.error.message || "Video generation failed"
    };
  }
  const isSuccessful = status === "MEDIA_GENERATION_STATUS_SUCCESSFUL" || operation?.done;
  if (isSuccessful) {
    let videoUrl;
    let base64Video;
    if (operation?.response?.videoResult?.video?.uri) {
      videoUrl = operation.response.videoResult.video.uri;
    } else if (operation?.response?.generatedVideo?.videoUrl) {
      videoUrl = operation.response.generatedVideo.videoUrl;
    }
    if (!videoUrl) {
      base64Video = operationData.rawBytes || data.rawBytes || operation?.response?.rawBytes || operation?.response?.videoResult?.video?.rawBytes || operation?.response?.generatedVideo?.rawBytes || operation?.response?.videoResult?.video?.encodedVideo || operation?.response?.generatedVideo?.encodedVideo;
    }
    if (base64Video && videoId && userId && sceneNumber !== void 0) {
      const storageMethod = await getCachedStorageMethod();
      if (storageMethod === "direct_to_user") {
        await saveDirectVideo(videoId, base64Video, userId);
        await storage.updateVideoHistoryFields(videoId, {
          status: "completed",
          videoUrl: `direct:${videoId}`
          // Marker for frontend to use download endpoint
        });
        log2(`Video ${sceneNumber} complete - direct to user (cached in temp file)`);
        return { done: true, videoUrl: `direct:${videoId}` };
      }
      queueUpload(videoId, base64Video, userId, sceneNumber);
      log2(`Video ${sceneNumber} generation complete, queued for upload`);
      return { done: true, uploading: true };
    } else if (base64Video && videoId) {
      const storageMethod = await getCachedStorageMethod();
      if (storageMethod === "direct_to_user") {
        await saveDirectVideo(videoId, base64Video, "unknown");
        return { done: true, videoUrl: `direct:${videoId}` };
      }
      try {
        const uploadResult = await uploadBase64VideoWithFallback(base64Video, videoId);
        videoUrl = uploadResult.url;
        log2(`Video uploaded (sync): ${videoUrl?.slice(0, 60)}...`);
      } catch (uploadError) {
        log2(`All upload methods FAILED: ${uploadError}`);
        throw new Error(`Upload failed: ${uploadError}`);
      }
    }
    if (videoUrl) {
      return { done: true, videoUrl };
    }
    return { done: true, error: "Video completed but no URL found" };
  }
  return { done: false };
}
async function generateVideoWithWhiskAPI(prompt, aspectRatio, token, videoId, userId, sceneNumber) {
  const apiKey = token.token;
  try {
    log2(`Generating image for prompt: "${prompt.substring(0, 40)}..."`);
    const imageResult = await generateWhiskImage2(apiKey, prompt, aspectRatio);
    log2(`Starting video generation...`);
    const operationName = await startWhiskVideoGeneration2(
      apiKey,
      prompt,
      imageResult.encodedImage,
      imageResult.mediaGenerationId,
      imageResult.workflowId
    );
    log2(`Polling for video status: ${operationName}`);
    const maxPolls = 40;
    const pollInterval = 6e3;
    for (let i = 0; i < maxPolls; i++) {
      const status = await checkWhiskVideoStatus2(apiKey, operationName, videoId, userId, sceneNumber);
      if (status.done) {
        if (status.uploading) {
          return { success: true, uploading: true };
        } else if (status.videoUrl) {
          return { success: true, videoUrl: status.videoUrl };
        } else {
          return { success: false, error: status.error || "Video generation failed" };
        }
      }
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }
    return { success: false, error: "Video generation timed out" };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error"
    };
  }
}
async function processSingleVideoWithFlow(video, _cookie, activeTokens) {
  log2(`Processing video ${video.sceneNumber} with Whisk API`);
  let usedTokenIds = /* @__PURE__ */ new Set();
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      if (attempt === 1) {
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, "processing"), 2, 1e3);
      }
      const freshActiveTokens = await getCachedActiveTokens();
      let token = null;
      if (attempt === 1 && video.assignedToken) {
        const stillActive = freshActiveTokens.some((t) => t.id === video.assignedToken.id);
        if (stillActive) {
          token = video.assignedToken;
          log2(`Using pre-assigned token: ${token.label}`);
        } else {
          log2(`Pre-assigned token ${video.assignedToken.label} no longer active, getting fresh token`);
          video.assignedToken = void 0;
        }
      }
      if (!token) {
        const availableTokens = freshActiveTokens.filter((t) => !usedTokenIds.has(t.id));
        if (availableTokens.length > 0) {
          const randomIdx = Math.floor(Math.random() * availableTokens.length);
          token = availableTokens[randomIdx] ?? null;
        } else {
          token = await storage.getNextRotationToken() ?? null;
        }
      }
      if (!token) {
        throw new Error("No active API tokens available");
      }
      usedTokenIds.add(token.id);
      await storage.updateTokenUsage(token.id);
      log2(`Using token: ${token.label} (attempt ${attempt})`);
      const result = await generateVideoWithWhiskAPI(
        video.prompt,
        video.aspectRatio,
        token,
        video.videoId,
        video.userId,
        video.sceneNumber
      );
      if (result.success && result.uploading) {
        log2(`Video ${video.sceneNumber} SUCCESS with token ${token.label} (attempt ${attempt}) - upload queued`);
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, "uploading"), 2, 1e3);
        return true;
      } else if (result.success && result.videoUrl) {
        log2(`Video ${video.sceneNumber} SUCCESS with token ${token.label} (attempt ${attempt})`);
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, "completed", result.videoUrl), 2, 1e3);
        return true;
      } else {
        const errorMsg = result.error || "Unknown error";
        storage.recordTokenError(token.id);
        invalidateTokenCache();
        if (attempt < MAX_RETRIES) {
          log2(`Video ${video.sceneNumber} retry ${attempt}/${MAX_RETRIES}`, 3);
          await new Promise((resolve) => setTimeout(resolve, randomDelay(500, 1500)));
          continue;
        }
        log2(`Video ${video.sceneNumber} FAILED after ${MAX_RETRIES} retries: ${errorMsg}`, 1);
        try {
          await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, errorMsg), 2, 1e3);
        } catch (dbErr) {
          log2(`DB error updating failed status for video ${video.sceneNumber}: ${dbErr}`);
        }
        return false;
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      if (attempt < MAX_RETRIES) {
        log2(`Video ${video.sceneNumber} retry ${attempt}/${MAX_RETRIES} (error)`, 3);
        await new Promise((resolve) => setTimeout(resolve, randomDelay(500, 1500)));
        continue;
      }
      log2(`Video ${video.sceneNumber} FAILED after ${MAX_RETRIES} retries: ${errorMsg}`, 1);
      try {
        await withRetry(() => storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, errorMsg), 2, 1e3);
      } catch (dbErr) {
        log2(`DB error updating failed status for video ${video.sceneNumber}: ${dbErr}`);
      }
      return false;
    }
  }
  return false;
}
async function processFlowQueue(userId) {
  const userQueue = getUserQueue(userId);
  if (userQueue.isProcessing) {
    const now = Date.now();
    const lastActivity = userQueue.lastProgressAt || userQueue.processingStartedAt || now;
    const stuckDuration = now - lastActivity;
    if (stuckDuration > STUCK_QUEUE_TIMEOUT_MS) {
      log2(`User ${userId}: Queue stuck for ${Math.round(stuckDuration / 1e3)}s, resetting isProcessing flag`, 1);
      userQueue.isProcessing = false;
      userQueue.activeWorkers = 0;
    } else {
      log2(`User ${userId}: Already processing (last activity ${Math.round(stuckDuration / 1e3)}s ago), skipping`);
      return;
    }
  }
  userQueue.isProcessing = true;
  userQueue.processingStartedAt = Date.now();
  userQueue.lastProgressAt = Date.now();
  log2(`User ${userId}: Starting queue with ${userQueue.queue.length} videos`);
  try {
    const activeTokens = await getCachedActiveTokens();
    if (activeTokens.length === 0) {
      log2(`No active API tokens available, aborting`, 1);
      userQueue.isProcessing = false;
      return;
    }
    const activePromises = /* @__PURE__ */ new Set();
    let tokenIndex = 0;
    const startNextVideo = async () => {
      if (userQueue.queue.length === 0 || userQueue.shouldStop) return;
      if (Date.now() - userQueue.processingStartedAt > MAX_PROCESSING_TIME_MS) return;
      if (userQueue.activeWorkers >= MAX_CONCURRENT_PER_USER) {
        log2(`User ${userId.slice(0, 8)}: At per-user limit (${userQueue.activeWorkers}/${MAX_CONCURRENT_PER_USER})`);
        return;
      }
      if (globalActiveWorkers >= GLOBAL_MAX_CONCURRENT_WORKERS) {
        log2(`Global limit reached (${globalActiveWorkers}/${GLOBAL_MAX_CONCURRENT_WORKERS}), waiting...`);
        setTimeout(() => startNextVideo(), 500);
        return;
      }
      const video = userQueue.queue.shift();
      userQueue.activeWorkers++;
      globalActiveWorkers++;
      let promiseRef;
      const videoProcessor = async () => {
        try {
          video.assignedToken = activeTokens[tokenIndex % activeTokens.length];
          tokenIndex++;
          log2(`Video ${video.sceneNumber} started (user: ${userQueue.activeWorkers}/${MAX_CONCURRENT_PER_USER}, global: ${globalActiveWorkers}/${GLOBAL_MAX_CONCURRENT_WORKERS})`);
          const success = await processSingleVideoWithFlow(video, {}, activeTokens);
          if (success) {
            userQueue.completedCount++;
          } else {
            userQueue.failedCount++;
          }
          userQueue.lastProgressAt = Date.now();
        } catch (err) {
          userQueue.failedCount++;
          userQueue.lastProgressAt = Date.now();
          log2(`Error processing video ${video.sceneNumber}: ${err}`);
        } finally {
          userQueue.activeWorkers--;
          globalActiveWorkers--;
          activePromises.delete(promiseRef);
          if (userQueue.activeWorkers < MAX_CONCURRENT_PER_USER && globalActiveWorkers < GLOBAL_MAX_CONCURRENT_WORKERS && userQueue.queue.length > 0 && !userQueue.shouldStop) {
            const delay = userQueue.queue.length < 5 ? 10 : 50;
            await new Promise((resolve) => setTimeout(resolve, delay));
            startNextVideo();
          }
        }
      };
      promiseRef = videoProcessor();
      activePromises.add(promiseRef);
    };
    const availableGlobalSlots = GLOBAL_MAX_CONCURRENT_WORKERS - globalActiveWorkers;
    const initialBurst = Math.min(MAX_CONCURRENT_PER_USER, userQueue.queue.length, availableGlobalSlots);
    log2(`User ${userId.slice(0, 8)}: Starting ${initialBurst} videos (global available: ${availableGlobalSlots})`);
    for (let i = 0; i < initialBurst; i++) {
      startNextVideo();
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    logMemory(`Initial burst complete, ${activePromises.size} active workers`);
    while (userQueue.activeWorkers > 0 || userQueue.queue.length > 0 || activePromises.size > 0) {
      if (userQueue.shouldStop) {
        log2(`Stop requested, waiting for ${userQueue.activeWorkers} active videos to complete`);
        break;
      }
      if (Date.now() - userQueue.processingStartedAt > MAX_PROCESSING_TIME_MS) {
        log2(`Max processing time exceeded, stopping`);
        break;
      }
      const remainingTotal = userQueue.activeWorkers + userQueue.queue.length;
      const checkInterval = remainingTotal <= 5 ? 100 : 500;
      await new Promise((resolve) => setTimeout(resolve, checkInterval));
      if (userQueue.activeWorkers > 0) {
        log2(`Progress: ${userQueue.completedCount + userQueue.failedCount}/${userQueue.completedCount + userQueue.failedCount + userQueue.activeWorkers + userQueue.queue.length} (${userQueue.activeWorkers} active, ${userQueue.queue.length} queued)`);
      }
      while (userQueue.activeWorkers < MAX_CONCURRENT_PER_USER && userQueue.queue.length > 0 && !userQueue.shouldStop) {
        startNextVideo();
        const startDelay = userQueue.queue.length < 5 ? 10 : 50;
        await new Promise((resolve) => setTimeout(resolve, startDelay));
      }
    }
    if (activePromises.size > 0) {
      log2(`Waiting for ${activePromises.size} remaining videos to complete...`);
      await Promise.all(activePromises);
    }
  } finally {
    userQueue.isProcessing = false;
    userQueue.processingStartedAt = null;
    log2(`User ${userId}: Queue COMPLETE. Completed: ${userQueue.completedCount}, Failed: ${userQueue.failedCount}`);
  }
}
var TEMP_VIDEO_DIR, TEMP_UPLOAD_DIR, MEMORY_LOG_INTERVAL, MEMORY_HIGH_WATER_MARK, MAX_TOTAL_CACHED_VIDEOS, MAX_TOTAL_UPLOAD_QUEUE, STALE_UPLOAD_TIMEOUT, LOG_LEVEL, LOG_SAMPLING_RATE, cachedTokens, tokensCacheTime, TOKENS_CACHE_TTL, cachedStorageMethod, storageMethodCacheTime, STORAGE_METHOD_CACHE_TTL, directVideoCacheMeta, DIRECT_VIDEO_TTL, uploadQueue, MAX_CONCURRENT_UPLOADS, MAX_UPLOAD_RETRIES, activeUploads, uploadProcessorRunning, userUploadCounts, STUCK_QUEUE_TIMEOUT_MS, HEALTH_CHECK_INTERVAL_MS, GLOBAL_MAX_CONCURRENT_WORKERS, MAX_CONCURRENT_PER_USER, MAX_UPLOADS_PER_USER, MAX_PROCESSING_TIME_MS, globalActiveWorkers, userQueues, CLEANUP_INTERVAL_MS3, INACTIVE_QUEUE_TIMEOUT_MS, MAX_RETRIES, WHISK_BASE_URL2;
var init_bulkQueueFlow = __esm({
  "server/bulkQueueFlow.ts"() {
    "use strict";
    init_storage();
    init_db();
    init_cloudinary();
    TEMP_VIDEO_DIR = "/tmp/video_cache";
    TEMP_UPLOAD_DIR = "/tmp/video_uploads";
    ensureTempDirs().then(() => cleanupOrphanedTempFiles());
    MEMORY_LOG_INTERVAL = 6e4;
    MEMORY_HIGH_WATER_MARK = 0.85;
    setInterval(logMemoryUsage, MEMORY_LOG_INTERVAL);
    MAX_TOTAL_CACHED_VIDEOS = 150;
    MAX_TOTAL_UPLOAD_QUEUE = 100;
    STALE_UPLOAD_TIMEOUT = 30 * 60 * 1e3;
    setInterval(enforceGlobalLimits, 3e4);
    LOG_LEVEL = process.env.NODE_ENV === "production" ? 1 : 2;
    LOG_SAMPLING_RATE = 0.1;
    cachedTokens = [];
    tokensCacheTime = 0;
    TOKENS_CACHE_TTL = 5e3;
    cachedStorageMethod = "cloudinary_with_fallback";
    storageMethodCacheTime = 0;
    STORAGE_METHOD_CACHE_TTL = 1e4;
    directVideoCacheMeta = /* @__PURE__ */ new Map();
    DIRECT_VIDEO_TTL = 5 * 60 * 1e3;
    setInterval(async () => {
      const now = Date.now();
      let cleaned = 0;
      const entries = Array.from(directVideoCacheMeta.entries());
      for (const [videoId, meta] of entries) {
        if (now - meta.addedAt > DIRECT_VIDEO_TTL) {
          await deleteTempFile(meta.filePath);
          directVideoCacheMeta.delete(videoId);
          cleaned++;
        }
      }
      if (cleaned > 0) {
        console.log(`[DirectCache] Cleaned ${cleaned} expired video files. Active: ${directVideoCacheMeta.size}`);
      }
    }, 6e4);
    uploadQueue = [];
    MAX_CONCURRENT_UPLOADS = 10;
    MAX_UPLOAD_RETRIES = 3;
    activeUploads = 0;
    uploadProcessorRunning = false;
    userUploadCounts = /* @__PURE__ */ new Map();
    STUCK_QUEUE_TIMEOUT_MS = 2 * 60 * 1e3;
    HEALTH_CHECK_INTERVAL_MS = 30 * 1e3;
    GLOBAL_MAX_CONCURRENT_WORKERS = parseInt(process.env.GLOBAL_MAX_WORKERS || "10000", 10);
    MAX_CONCURRENT_PER_USER = parseInt(process.env.PER_USER_MAX_WORKERS || "20", 10);
    MAX_UPLOADS_PER_USER = parseInt(process.env.PER_USER_MAX_UPLOADS || "100", 10);
    MAX_PROCESSING_TIME_MS = 2 * 60 * 60 * 1e3;
    globalActiveWorkers = 0;
    userQueues = /* @__PURE__ */ new Map();
    CLEANUP_INTERVAL_MS3 = 10 * 60 * 1e3;
    INACTIVE_QUEUE_TIMEOUT_MS = 30 * 60 * 1e3;
    setInterval(cleanupInactiveQueues, CLEANUP_INTERVAL_MS3);
    setInterval(checkAndRecoverStuckQueues, HEALTH_CHECK_INTERVAL_MS);
    setInterval(recoverPendingVideosFromDB, 60 * 1e3);
    setTimeout(recoverPendingVideosFromDB, 5e3);
    MAX_RETRIES = 3;
    WHISK_BASE_URL2 = "https://aisandbox-pa.googleapis.com/v1";
  }
});

// server/bulkQueue.ts
var bulkQueue_exports = {};
__export(bulkQueue_exports, {
  addToQueue: () => addToQueue,
  forceResetQueue: () => forceResetQueue,
  getQueueStatus: () => getQueueStatus,
  startBackgroundPolling: () => startBackgroundPolling,
  stopAllProcessing: () => stopAllProcessing
});
function getUserQueue2(userId) {
  if (!userQueues2.has(userId)) {
    userQueues2.set(userId, {
      queue: [],
      isProcessing: false,
      shouldStop: false,
      processingStartedAt: null
    });
  }
  return userQueues2.get(userId);
}
function checkAndResetStuckQueue(userId) {
  const userQueue = getUserQueue2(userId);
  if (userQueue.isProcessing && userQueue.processingStartedAt) {
    const processingDuration = Date.now() - userQueue.processingStartedAt;
    if (processingDuration > MAX_PROCESSING_TIME_MS2) {
      console.log(`[Bulk Queue] User ${userId}: \u26A0\uFE0F Queue stuck for ${Math.round(processingDuration / 6e4)} minutes. Auto-resetting...`);
      userQueue.isProcessing = false;
      userQueue.shouldStop = true;
      userQueue.processingStartedAt = null;
      userQueue.queue.length = 0;
      console.log(`[Bulk Queue] User ${userId}: \u2705 Queue auto-reset complete`);
      return true;
    }
  }
  return false;
}
function addToQueue(videos, delaySeconds) {
  if (videos.length === 0) return;
  const userId = videos[0].userId;
  const userQueue = getUserQueue2(userId);
  userQueue.shouldStop = false;
  userQueue.queue.push(...videos);
  console.log(`[Bulk Queue] User ${userId}: Added ${videos.length} videos to queue. Total in queue: ${userQueue.queue.length}`);
  if (!userQueue.isProcessing) {
    processQueue(userId, delaySeconds);
  }
}
async function processSingleVideo(video) {
  let attemptNumber = 0;
  let lastError;
  let succeeded = false;
  const disabledTokenIds = /* @__PURE__ */ new Set();
  while (attemptNumber < MAX_INSTANT_RETRIES && !succeeded) {
    attemptNumber++;
    let rotationToken;
    try {
      console.log(`[Bulk Queue] \u{1F504} Processing video ${video.sceneNumber} (ID: ${video.videoId}) - Attempt ${attemptNumber}/${MAX_INSTANT_RETRIES}`);
      let apiKey;
      if (attemptNumber === 1 && video.assignedToken && !disabledTokenIds.has(video.assignedToken.id)) {
        rotationToken = video.assignedToken;
        console.log(`[Bulk Queue] \u{1F3AF} Using PRE-ASSIGNED token ${rotationToken.label} (ID: ${rotationToken.id}) for video ${video.sceneNumber}`);
      } else {
        const allTokens = await storage.getActiveApiTokens();
        const availableTokens = allTokens.filter((t) => !disabledTokenIds.has(t.id) && !storage.isTokenInCooldown(t.id)).sort((a, b) => {
          const aTime = a.lastUsedAt ? new Date(a.lastUsedAt).getTime() : 0;
          const bTime = b.lastUsedAt ? new Date(b.lastUsedAt).getTime() : 0;
          return aTime - bTime;
        });
        rotationToken = availableTokens[0];
        if (!rotationToken) {
          lastError = `No active API tokens available after excluding ${disabledTokenIds.size} disabled tokens. All tokens exhausted.`;
          console.error(`[Bulk Queue] \u274C ${lastError}`);
          await storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, lastError);
          return;
        }
        console.log(`[Bulk Queue] \u{1F504} Using NEXT ROTATION token ${rotationToken.label} (ID: ${rotationToken.id}) for retry attempt ${attemptNumber}${disabledTokenIds.size > 0 ? ` (excluding ${disabledTokenIds.size} disabled)` : ""}`);
        await storage.updateTokenUsage(rotationToken.id);
      }
      apiKey = rotationToken.token;
      console.log(`[Bulk Queue] \u{1F3AF} Token: ${rotationToken.label} (ID: ${rotationToken.id}) for video ${video.sceneNumber} (attempt ${attemptNumber})`);
      const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
      const sceneId = `bulk-${video.videoId}-${Date.now()}-attempt${attemptNumber}`;
      const seed = Math.floor(Math.random() * 1e5);
      const payload = {
        clientContext: {
          projectId: veoProjectId,
          tool: "PINHOLE",
          userPaygateTier: "PAYGATE_TIER_TWO"
        },
        requests: [{
          aspectRatio: video.aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
          seed,
          textInput: {
            prompt: video.prompt
          },
          videoModelKey: video.aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
          metadata: {
            sceneId
          }
        }]
      };
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 9e4);
      let response;
      let data;
      try {
        response = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload),
          signal: controller.signal
        });
        clearTimeout(timeout);
        data = await response.json();
      } catch (fetchError) {
        clearTimeout(timeout);
        const isAuthError = fetchError.message && (fetchError.message.toLowerCase().includes("invalid authentication") || fetchError.message.toLowerCase().includes("oauth 2 access token") || fetchError.message.toLowerCase().includes("unauthorized") || fetchError.message.toLowerCase().includes("401"));
        if (rotationToken) {
          if (isAuthError) {
            console.log(`[Bulk Queue] \u{1F534} Authentication error detected - auto-disabling token ${rotationToken.id}`);
            await storage.toggleApiTokenStatus(rotationToken.id, false);
            disabledTokenIds.add(rotationToken.id);
            console.log(`[Bulk Queue] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
            if (video.assignedToken && video.assignedToken.id === rotationToken.id) {
              video.assignedToken = void 0;
              console.log(`[Bulk Queue] Cleared disabled token from video ${video.sceneNumber} assignedToken`);
            }
          } else {
            storage.recordTokenError(rotationToken.id);
          }
        }
        if (fetchError.name === "AbortError") {
          lastError = `Request timeout after 90 seconds - VEO API not responding`;
          console.error(`[Bulk Queue] \u274C Attempt ${attemptNumber} - Request timeout:`, fetchError);
        } else {
          lastError = `Network error: ${fetchError.message}`;
          console.error(`[Bulk Queue] \u274C Attempt ${attemptNumber} - Network error:`, fetchError);
        }
        if (attemptNumber < MAX_INSTANT_RETRIES) {
          console.log(`[Bulk Queue] \u23F3 Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
          continue;
        }
        await storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
        return;
      }
      if (!response.ok) {
        lastError = `VEO API error (${response.status}): ${JSON.stringify(data).substring(0, 200)}`;
        console.error(`[Bulk Queue] \u274C Attempt ${attemptNumber} - VEO API error:`, data);
        const isAuthError = response.status === 401 || data.error && (data.error.message?.toLowerCase().includes("invalid authentication") || data.error.message?.toLowerCase().includes("oauth 2 access token") || data.error.message?.toLowerCase().includes("unauthorized"));
        if (rotationToken) {
          if (isAuthError) {
            console.log(`[Bulk Queue] \u{1F534} Authentication error detected - auto-disabling token ${rotationToken.id}`);
            await storage.toggleApiTokenStatus(rotationToken.id, false);
            disabledTokenIds.add(rotationToken.id);
            console.log(`[Bulk Queue] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
            if (video.assignedToken && video.assignedToken.id === rotationToken.id) {
              video.assignedToken = void 0;
              console.log(`[Bulk Queue] Cleared disabled token from video ${video.sceneNumber} assignedToken`);
            }
          } else {
            storage.recordTokenError(rotationToken.id);
          }
        }
        if (attemptNumber < MAX_INSTANT_RETRIES) {
          console.log(`[Bulk Queue] \u23F3 Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
          continue;
        }
        await storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
        return;
      }
      if (!data.operations || data.operations.length === 0) {
        lastError = "No operations returned from VEO API - possible API issue";
        console.error(`[Bulk Queue] \u274C Attempt ${attemptNumber} - No operations returned from VEO API`);
        if (rotationToken) {
          storage.recordTokenError(rotationToken.id);
        }
        if (attemptNumber < MAX_INSTANT_RETRIES) {
          console.log(`[Bulk Queue] \u23F3 Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
          continue;
        }
        await storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
        return;
      }
      const operation = data.operations[0];
      const operationName = operation.operation.name;
      console.log(`[Bulk Queue] \u2705 Started generation for video ${video.sceneNumber} - Operation: ${operationName} (attempt ${attemptNumber})`);
      succeeded = true;
      if (rotationToken) {
        try {
          await storage.updateVideoHistoryFields(video.videoId, { tokenUsed: rotationToken.id });
        } catch (err) {
          console.error("[Bulk Queue] Failed to update video history with token ID:", err);
        }
      }
      startBackgroundPolling(video.videoId, video.userId, operationName, sceneId, apiKey, rotationToken);
      break;
    } catch (error) {
      lastError = `Error processing video: ${error instanceof Error ? error.message : String(error)}`;
      console.error(`[Bulk Queue] \u274C Attempt ${attemptNumber} - Error processing video ${video.sceneNumber}:`, error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      const isAuthError = errorMessage.toLowerCase().includes("invalid authentication") || errorMessage.toLowerCase().includes("oauth 2 access token") || errorMessage.toLowerCase().includes("unauthorized") || errorMessage.toLowerCase().includes("401");
      if (rotationToken) {
        if (isAuthError) {
          console.log(`[Bulk Queue] \u{1F534} Authentication error detected - auto-disabling token ${rotationToken.id}`);
          await storage.toggleApiTokenStatus(rotationToken.id, false);
          disabledTokenIds.add(rotationToken.id);
          console.log(`[Bulk Queue] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
          if (video.assignedToken && video.assignedToken.id === rotationToken.id) {
            video.assignedToken = void 0;
            console.log(`[Bulk Queue] Cleared disabled token from video ${video.sceneNumber} assignedToken`);
          }
        } else {
          storage.recordTokenError(rotationToken.id);
        }
      }
      if (attemptNumber < MAX_INSTANT_RETRIES) {
        console.log(`[Bulk Queue] \u23F3 Retrying in ${INSTANT_RETRY_DELAY_MS}ms with different token...`);
        await new Promise((resolve) => setTimeout(resolve, INSTANT_RETRY_DELAY_MS));
        continue;
      }
      await storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, `${lastError} (Failed after ${MAX_INSTANT_RETRIES} attempts)`);
    }
  }
}
async function processQueue(userId, overrideDelaySeconds) {
  const userQueue = getUserQueue2(userId);
  if (userQueue.isProcessing) {
    console.log(`[Bulk Queue] User ${userId}: Already processing queue`);
    return;
  }
  userQueue.isProcessing = true;
  userQueue.processingStartedAt = Date.now();
  console.log(`[Bulk Queue] User ${userId}: Started processing queue at ${(/* @__PURE__ */ new Date()).toISOString()}`);
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
        console.log(`[Bulk Queue] Using batch settings: ${videosPerBatch} videos per batch, ${batchDelaySeconds}s delay${overrideDelaySeconds ? " (plan-specific)" : ""}`);
      }
    } catch (error) {
      console.error("[Bulk Queue] Error fetching batch settings, using defaults:", error);
    }
    while (userQueue.queue.length > 0) {
      if (userQueue.shouldStop) {
        console.log(`[Bulk Queue] User ${userId}: \u{1F6D1} Stop flag detected. Stopping queue processing.`);
        userQueue.shouldStop = false;
        break;
      }
      const batchSize = Math.min(videosPerBatch, userQueue.queue.length);
      const batch = [];
      for (let i = 0; i < batchSize; i++) {
        const video = userQueue.queue.shift();
        if (video) {
          batch.push(video);
        }
      }
      if (batch.length === 0) {
        continue;
      }
      const activeTokens = await storage.getActiveApiTokens();
      console.log(`[Bulk Queue] \u{1F4CA} Found ${activeTokens.length} active tokens available for rotation`);
      if (activeTokens.length === 0) {
        console.log(`[Bulk Queue] \u26A0\uFE0F No active tokens available - batch will fail`);
        for (const video of batch) {
          await storage.updateVideoHistoryStatus(video.videoId, video.userId, "failed", void 0, "No active API tokens available");
        }
        continue;
      }
      console.log(`[Bulk Queue] User ${userId}: \u{1F4E6} Processing batch of ${batch.length} videos. Remaining in queue: ${userQueue.queue.length}`);
      const startRotationIndex = await storage.getAndIncrementRotationIndex(batch.length, activeTokens.length);
      console.log(`[Bulk Queue] \u{1F3B2} Starting token assignment from rotation index ${startRotationIndex} (cycling through all ${activeTokens.length} tokens)...`);
      for (let i = 0; i < batch.length; i++) {
        const video = batch[i];
        const tokenIndex = (startRotationIndex + i) % activeTokens.length;
        const token = activeTokens[tokenIndex];
        video.assignedToken = token;
        console.log(`[Bulk Queue] \u2705 Video ${video.sceneNumber} \u2192 Token ${tokenIndex + 1}/${activeTokens.length}: ${token.label} (ID: ${token.id})`);
      }
      console.log(`[Bulk Queue] \u{1F3AF} All ${batch.length} videos assigned tokens via round-robin rotation (next batch starts at index ${(startRotationIndex + batch.length) % activeTokens.length})!`);
      await Promise.all(batch.map((video) => processSingleVideo(video)));
      console.log(`[Bulk Queue] User ${userId}: \u2705 Batch of ${batch.length} videos submitted successfully`);
      if (userQueue.queue.length > 0) {
        console.log(`[Bulk Queue] User ${userId}: \u23F8\uFE0F Waiting ${batchDelaySeconds} seconds before next batch...`);
        await new Promise((resolve) => setTimeout(resolve, batchDelaySeconds * 1e3));
      }
    }
  } finally {
    userQueue.isProcessing = false;
    userQueue.processingStartedAt = null;
    console.log(`[Bulk Queue] User ${userId}: Finished processing queue at ${(/* @__PURE__ */ new Date()).toISOString()}`);
  }
}
async function startBackgroundPolling(videoId, userId, operationName, sceneId, apiKey, rotationToken) {
  (async () => {
    try {
      let completed = false;
      let attempts = 0;
      const maxAttempts = 120;
      const retryAttempt = 16;
      let currentOperationName = operationName;
      let currentSceneId = sceneId;
      let currentApiKey = apiKey;
      let currentRotationToken = rotationToken;
      let hasRetriedWithNewToken = false;
      let pollingRetryCount = 0;
      while (!completed && attempts < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, 15e3));
        attempts++;
        if (attempts === retryAttempt && !completed && !hasRetriedWithNewToken) {
          console.log(`[Bulk Queue Polling] Video ${videoId} not completed after 4 minutes, trying with next API token...`);
          if (currentRotationToken) {
            storage.recordTokenError(currentRotationToken.id);
          }
          try {
            const nextToken = await storage.getNextRotationToken();
            if (nextToken && nextToken.id !== currentRotationToken?.id) {
              console.log(`[Bulk Queue Polling] Starting NEW generation with next token: ${nextToken.label}`);
              await storage.updateTokenUsage(nextToken.id);
              const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
              const newSceneId = `retry-${videoId}-${Date.now()}`;
              const seed = Math.floor(Math.random() * 1e5);
              const video = await storage.updateVideoHistoryStatus(videoId, userId, "pending");
              if (!video) continue;
              const payload = {
                clientContext: {
                  projectId: veoProjectId,
                  tool: "PINHOLE",
                  userPaygateTier: "PAYGATE_TIER_TWO"
                },
                requests: [{
                  aspectRatio: video.aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                  seed,
                  textInput: {
                    prompt: video.prompt
                  },
                  videoModelKey: video.aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                  metadata: {
                    sceneId: newSceneId
                  }
                }]
              };
              const retryController = new AbortController();
              const retryTimeout = setTimeout(() => retryController.abort(), 9e4);
              const response = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
                method: "POST",
                headers: {
                  "Authorization": `Bearer ${nextToken.token}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify(payload),
                signal: retryController.signal
              });
              clearTimeout(retryTimeout);
              const data = await response.json();
              if (response.ok && data.operations && data.operations.length > 0) {
                const newOperation = data.operations[0].operation.name;
                console.log(`[Bulk Queue Polling] \u2705 Retry successful! New operation: ${newOperation}`);
                currentOperationName = newOperation;
                currentSceneId = newSceneId;
                currentApiKey = nextToken.token;
                currentRotationToken = nextToken;
                hasRetriedWithNewToken = true;
                console.log(`[Bulk Queue Polling] Now polling NEW operation ${newOperation} with token ${nextToken.label}`);
                await storage.updateVideoHistoryFields(videoId, {
                  status: "retrying",
                  tokenUsed: nextToken.id
                });
              }
            }
          } catch (retryError) {
            console.error("[Bulk Queue Polling] Error retrying with new token:", retryError);
          }
        }
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
          const statusController = new AbortController();
          const statusTimeout = setTimeout(() => statusController.abort(), 3e4);
          const statusResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchCheckAsyncVideoGenerationStatus", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${currentApiKey}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify(requestBody),
            signal: statusController.signal
          });
          clearTimeout(statusTimeout);
          if (!statusResponse.ok) {
            console.error(`[Bulk Queue Polling] Status check failed (${statusResponse.status}) - will retry on next poll`);
            continue;
          }
          const statusData = await statusResponse.json();
          console.log(`[Bulk Queue Polling] Status for ${videoId}:`, JSON.stringify(statusData, null, 2).substring(0, 500));
          if (statusData.operations && statusData.operations.length > 0) {
            const operationData = statusData.operations[0];
            const operation = operationData.operation;
            const opStatus = operationData.status;
            console.log(`[Bulk Queue Polling] Video ${videoId} status: ${opStatus}`);
            let veoVideoUrl;
            if (operation?.metadata?.video?.fifeUrl) {
              veoVideoUrl = operation.metadata.video.fifeUrl;
            } else if (operation?.videoUrl) {
              veoVideoUrl = operation.videoUrl;
            } else if (operation?.fileUrl) {
              veoVideoUrl = operation.fileUrl;
            } else if (operation?.downloadUrl) {
              veoVideoUrl = operation.downloadUrl;
            }
            if (veoVideoUrl) {
              veoVideoUrl = veoVideoUrl.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
            }
            if (opStatus === "MEDIA_GENERATION_STATUS_COMPLETE" || opStatus === "MEDIA_GENERATION_STATUS_SUCCESSFUL" || opStatus === "COMPLETED") {
              if (veoVideoUrl) {
                console.log(`[Bulk Queue Polling] Video ${videoId} completed (saving directly, no Cloudinary)`);
                await storage.updateVideoHistoryStatus(videoId, userId, "completed", veoVideoUrl);
                console.log(`[Bulk Queue Polling] Video ${videoId} completed successfully`);
                completed = true;
              } else {
                console.log(`[Bulk Queue Polling] Video ${videoId} shows complete but no URL found`);
              }
            } else if (operation?.error) {
              const errorMessage = `VEO generation failed: ${operation.error.message || JSON.stringify(operation.error).substring(0, 200)}`;
              const errorCode = operation.error.code;
              const errorMsgLower = (operation.error.message || "").toLowerCase();
              console.error(`[Bulk Queue Polling] Video ${videoId} failed:`, operation.error);
              const isHighTrafficError = errorCode === 13 || errorMsgLower.includes("high_traffic") || errorMsgLower.includes("high traffic");
              const isTimeoutError = errorCode === 4 || errorMsgLower.includes("timed_out") || errorMsgLower.includes("timeout");
              const isExpiredDeadlineError = errorMsgLower.includes("expired") || errorMsgLower.includes("deadline");
              const isUnsafeGenerationError = errorMsgLower.includes("unsafe_generation") || errorMsgLower.includes("unsafe generation");
              const isMinorError = errorMsgLower.includes("error_minor") || errorMsgLower.includes("minor error");
              const shouldRetry = isHighTrafficError || isTimeoutError || isExpiredDeadlineError || isUnsafeGenerationError || isMinorError;
              if (shouldRetry) {
                console.log(`[Bulk Queue Polling] \u{1F50D} Detected retryable error for ${videoId}:`, {
                  errorCode,
                  isHighTrafficError,
                  isTimeoutError,
                  isExpiredDeadlineError,
                  isUnsafeGenerationError,
                  isMinorError,
                  retryCount: pollingRetryCount
                });
              }
              if (!shouldRetry && currentRotationToken) {
                storage.recordTokenError(currentRotationToken.id);
              }
              if (shouldRetry && pollingRetryCount < MAX_POLLING_RETRIES) {
                pollingRetryCount++;
                console.log(`[Bulk Queue Polling] \u{1F504} VEO returned failure. Retrying with different token (polling retry ${pollingRetryCount}/${MAX_POLLING_RETRIES})...`);
                try {
                  const newToken = await storage.getNextRotationToken();
                  if (newToken) {
                    await storage.updateTokenUsage(newToken.id);
                    const newApiKey = newToken.token;
                    currentRotationToken = newToken;
                    console.log(`[Bulk Queue Polling] \u{1F504} Retry attempt with new token: ${newToken.label}`);
                    const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
                    const newSceneId = `retry-${videoId}-${Date.now()}`;
                    const seed = Math.floor(Math.random() * 1e5);
                    const videoHistory2 = await storage.getUserVideoHistory(userId);
                    const video = videoHistory2.find((v) => v.id === videoId);
                    if (video && video.prompt) {
                      const payload = {
                        clientContext: {
                          projectId: veoProjectId,
                          tool: "PINHOLE",
                          userPaygateTier: "PAYGATE_TIER_TWO"
                        },
                        requests: [{
                          aspectRatio: video.aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                          seed,
                          textInput: { prompt: video.prompt },
                          videoModelKey: video.aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                          metadata: { sceneId: newSceneId }
                        }]
                      };
                      const retryController = new AbortController();
                      const retryTimeout = setTimeout(() => retryController.abort(), 9e4);
                      const retryResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
                        method: "POST",
                        headers: {
                          "Authorization": `Bearer ${newApiKey}`,
                          "Content-Type": "application/json"
                        },
                        body: JSON.stringify(payload),
                        signal: retryController.signal
                      });
                      clearTimeout(retryTimeout);
                      const retryData = await retryResponse.json();
                      if (retryResponse.ok && retryData.operations && retryData.operations.length > 0) {
                        const newOperation = retryData.operations[0].operation.name;
                        console.log(`[Bulk Queue Polling] \u2705 Retry successful! New operation: ${newOperation}`);
                        await storage.updateVideoHistoryFields(videoId, {
                          status: "retrying",
                          tokenUsed: newToken.id
                        });
                        currentSceneId = newSceneId;
                        currentOperationName = newOperation;
                        currentApiKey = newApiKey;
                        currentRotationToken = newToken;
                        continue;
                      }
                    }
                  }
                } catch (retryError) {
                  console.error("[Bulk Queue Polling] Error retrying with new token:", retryError);
                }
              }
              await storage.updateVideoHistoryStatus(videoId, userId, "failed", void 0, `${errorMessage} (Failed after ${pollingRetryCount} polling retries)`);
              completed = true;
            }
          }
        } catch (pollError) {
          if (pollError.name === "AbortError") {
            console.error(`[Bulk Queue Polling] Status check timeout for video ${videoId} - will retry on next poll`);
          } else if (pollError.code === "ECONNRESET" || pollError.cause?.code === "ECONNRESET") {
            console.error(`[Bulk Queue Polling] Network connection reset for video ${videoId} - will retry on next poll`);
          } else {
            console.error(`[Bulk Queue Polling] Error polling video ${videoId}:`, pollError);
          }
        }
      }
      if (!completed) {
        const errorMessage = `Video generation timed out after ${maxAttempts * 2} seconds (${maxAttempts} attempts)`;
        console.log(`[Bulk Queue Polling] Video ${videoId} timed out after ${maxAttempts} attempts`);
        await storage.updateVideoHistoryStatus(videoId, userId, "failed", void 0, errorMessage);
      }
    } catch (error) {
      const errorMessage = `Fatal error during video generation: ${error instanceof Error ? error.message : String(error)}`;
      console.error(`[Bulk Queue Polling] Fatal error polling video ${videoId}:`, error);
      await storage.updateVideoHistoryStatus(videoId, userId, "failed", void 0, errorMessage);
    }
  })();
}
function getQueueStatus(userId) {
  const wasReset = checkAndResetStuckQueue(userId);
  const userQueue = getUserQueue2(userId);
  return {
    queueLength: userQueue.queue.length,
    isProcessing: userQueue.isProcessing,
    wasAutoReset: wasReset,
    processingStartedAt: userQueue.processingStartedAt
  };
}
function stopAllProcessing(userId) {
  const userQueue = getUserQueue2(userId);
  const clearedCount = userQueue.queue.length;
  const wasProcessing = userQueue.isProcessing;
  console.log(`[Bulk Queue] User ${userId}: \u{1F6D1} STOP requested. Clearing ${clearedCount} videos from queue.`);
  userQueue.queue.length = 0;
  userQueue.shouldStop = true;
  userQueue.isProcessing = false;
  userQueue.processingStartedAt = null;
  return {
    message: "Bulk processing stopped. Queue cleared.",
    clearedVideos: clearedCount,
    wasProcessing
  };
}
function forceResetQueue(userId) {
  const userQueue = getUserQueue2(userId);
  const previousState = {
    queueLength: userQueue.queue.length,
    isProcessing: userQueue.isProcessing,
    processingStartedAt: userQueue.processingStartedAt
  };
  console.log(`[Bulk Queue] User ${userId}: \u26A0\uFE0F FORCE RESET requested. Previous state:`, previousState);
  userQueue.queue.length = 0;
  userQueue.isProcessing = false;
  userQueue.shouldStop = true;
  userQueue.processingStartedAt = null;
  console.log(`[Bulk Queue] User ${userId}: \u2705 Queue force reset complete`);
  return {
    message: "Queue force reset complete.",
    previousState
  };
}
var MAX_PROCESSING_TIME_MS2, userQueues2, MAX_INSTANT_RETRIES, MAX_POLLING_RETRIES, INSTANT_RETRY_DELAY_MS;
var init_bulkQueue = __esm({
  "server/bulkQueue.ts"() {
    "use strict";
    init_storage();
    MAX_PROCESSING_TIME_MS2 = 2 * 60 * 60 * 1e3;
    userQueues2 = /* @__PURE__ */ new Map();
    MAX_INSTANT_RETRIES = 10;
    MAX_POLLING_RETRIES = 10;
    INSTANT_RETRY_DELAY_MS = 500;
  }
});

// server/systemMetrics.ts
var systemMetrics_exports = {};
__export(systemMetrics_exports, {
  checkGPUAvailability: () => checkGPUAvailability,
  getSystemMetrics: () => getSystemMetrics
});
import { exec } from "child_process";
import { promisify } from "util";
import si from "systeminformation";
async function getGPUInfo() {
  try {
    const { stdout } = await execAsync(
      "nvidia-smi --query-gpu=index,name,utilization.gpu,memory.total,memory.used,memory.free,temperature.gpu,power.draw --format=csv,noheader,nounits"
    );
    const lines = stdout.trim().split("\n");
    const gpus = [];
    for (const line of lines) {
      const [index2, name, util, memTotal, memUsed, memFree, temp, power] = line.split(", ");
      let processes = [];
      try {
        const { stdout: procStdout } = await execAsync(
          `nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv,noheader,nounits --id=${index2}`
        );
        if (procStdout.trim()) {
          const procLines = procStdout.trim().split("\n");
          processes = procLines.map((procLine) => {
            const [pid, procName, mem] = procLine.split(", ");
            return { pid, name: procName, memory: mem + " MB" };
          });
        }
      } catch (procError) {
        console.log(`No GPU processes for GPU ${index2}`);
      }
      gpus.push({
        index: parseInt(index2),
        name,
        utilization: parseFloat(util),
        memoryTotal: parseFloat(memTotal),
        memoryUsed: parseFloat(memUsed),
        memoryFree: parseFloat(memFree),
        memoryPercent: parseFloat(memUsed) / parseFloat(memTotal) * 100,
        temperature: parseFloat(temp),
        powerDraw: parseFloat(power),
        processes
      });
    }
    return gpus;
  } catch (error) {
    return null;
  }
}
async function getLocalVideoStorageStats() {
  try {
    const { getStorageStats: getStorageStats2 } = await Promise.resolve().then(() => (init_localDiskStorage(), localDiskStorage_exports));
    const stats = await getStorageStats2();
    let oldestVideoAge = null;
    if (stats.oldestVideo) {
      const ageMs = Date.now() - stats.oldestVideo.getTime();
      const ageMinutes = Math.floor(ageMs / 6e4);
      if (ageMinutes < 60) {
        oldestVideoAge = `${ageMinutes}m`;
      } else {
        const hours = Math.floor(ageMinutes / 60);
        const mins = ageMinutes % 60;
        oldestVideoAge = `${hours}h ${mins}m`;
      }
    }
    return {
      totalVideos: stats.totalVideos,
      totalSizeMB: stats.totalSizeMB,
      oldestVideoAge
    };
  } catch (error) {
    return null;
  }
}
async function getSystemMetrics() {
  try {
    const [cpuLoad, mem, diskLayout, networkStats, processes, cpuTemp, cpuSpeed, gpuInfo, localVideoStorage] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize(),
      si.networkStats(),
      si.processes(),
      si.cpuTemperature(),
      si.cpu(),
      getGPUInfo(),
      getLocalVideoStorageStats()
    ]);
    const cpuUsage = cpuLoad.currentLoad;
    const cores = cpuLoad.cpus.map((core, index2) => ({
      core: index2,
      usage: parseFloat(core.load.toFixed(2))
    }));
    const memory = {
      total: Math.round(mem.total / 1024 ** 3 * 100) / 100,
      // GB
      used: Math.round(mem.used / 1024 ** 3 * 100) / 100,
      free: Math.round(mem.free / 1024 ** 3 * 100) / 100,
      usagePercent: parseFloat((mem.used / mem.total * 100).toFixed(2))
    };
    const primaryDisk = diskLayout[0];
    const disk = primaryDisk ? {
      total: Math.round(primaryDisk.size / 1024 ** 3 * 100) / 100,
      // GB
      used: Math.round(primaryDisk.used / 1024 ** 3 * 100) / 100,
      free: Math.round((primaryDisk.size - primaryDisk.used) / 1024 ** 3 * 100) / 100,
      usagePercent: parseFloat(primaryDisk.use.toFixed(2))
    } : {
      total: 0,
      used: 0,
      free: 0,
      usagePercent: 0
    };
    const activeNetwork = networkStats[0];
    const network = activeNetwork ? {
      rx_sec: Math.round(activeNetwork.rx_sec / 1024 * 100) / 100,
      // KB/s
      tx_sec: Math.round(activeNetwork.tx_sec / 1024 * 100) / 100
    } : {
      rx_sec: 0,
      tx_sec: 0
    };
    const topProcesses = processes.list.sort((a, b) => b.cpu - a.cpu).slice(0, 10).map((proc) => ({
      pid: proc.pid,
      name: proc.name,
      cpu: parseFloat(proc.cpu.toFixed(2)),
      mem: parseFloat(proc.mem.toFixed(2))
    }));
    return {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      cpu: {
        usage: parseFloat(cpuUsage.toFixed(2)),
        cores,
        temperature: cpuTemp.main || null,
        speed: cpuSpeed.speed
      },
      memory,
      disk,
      network,
      processes: topProcesses,
      gpu: gpuInfo,
      hasGPU: gpuInfo !== null && gpuInfo.length > 0,
      localVideoStorage
    };
  } catch (error) {
    console.error("Error collecting system metrics:", error);
    throw error;
  }
}
async function checkGPUAvailability() {
  try {
    await execAsync("nvidia-smi --version");
    return true;
  } catch (error) {
    return false;
  }
}
var execAsync;
var init_systemMetrics = __esm({
  "server/systemMetrics.ts"() {
    "use strict";
    execAsync = promisify(exec);
  }
});

// server/zyphra.ts
var zyphra_exports = {};
__export(zyphra_exports, {
  DEFAULT_VOICES: () => DEFAULT_VOICES,
  SUPPORTED_LANGUAGES: () => SUPPORTED_LANGUAGES,
  addZyphraToken: () => addZyphraToken,
  cloneVoice: () => cloneVoice,
  cloneVoiceWithRetry: () => cloneVoiceWithRetry,
  deleteZyphraToken: () => deleteZyphraToken,
  generateSpeech: () => generateSpeech,
  generateSpeechWithRetry: () => generateSpeechWithRetry,
  getAllZyphraTokens: () => getAllZyphraTokens,
  getAvailableZyphraToken: () => getAvailableZyphraToken,
  resetAllTokenUsage: () => resetAllTokenUsage,
  resetTokenUsage: () => resetTokenUsage,
  updateZyphraToken: () => updateZyphraToken
});
import { eq as eq2, and as and2, lt } from "drizzle-orm";
import * as mm from "music-metadata";
async function checkAndAutoDisableLowTimeTokens() {
  try {
    const allActiveTokens = await db.select().from(zyphraTokens).where(eq2(zyphraTokens.isActive, true));
    for (const token of allActiveTokens) {
      const remainingMinutes = token.minutesLimit - token.minutesUsed;
      if (remainingMinutes < MIN_REMAINING_MINUTES) {
        console.log(`[Zyphra Auto-Disable] Token ${token.id.slice(0, 8)} has only ${remainingMinutes.toFixed(2)} minutes remaining (< ${MIN_REMAINING_MINUTES}). Disabling...`);
        await db.update(zyphraTokens).set({ isActive: false }).where(eq2(zyphraTokens.id, token.id));
        console.log(`[Zyphra Auto-Disable] Token ${token.id.slice(0, 8)} has been disabled.`);
      }
    }
  } catch (error) {
    console.error("[Zyphra Auto-Disable] Error checking tokens:", error);
  }
}
async function getAvailableZyphraToken(excludeTokenIds = []) {
  try {
    await checkAndAutoDisableLowTimeTokens();
    const allTokens = await db.select().from(zyphraTokens).where(
      and2(
        eq2(zyphraTokens.isActive, true),
        lt(zyphraTokens.minutesUsed, zyphraTokens.minutesLimit)
      )
    );
    const availableTokens = allTokens.filter((t) => !excludeTokenIds.includes(t.id));
    if (availableTokens.length === 0) {
      if (allTokens.length > 0 && excludeTokenIds.length > 0) {
        console.log(`[Zyphra] All available tokens were excluded, falling back to excluded tokens`);
        return { id: allTokens[0].id, apiKey: allTokens[0].apiKey };
      }
      return null;
    }
    const token = availableTokens[0];
    const remainingMinutes = token.minutesLimit - token.minutesUsed;
    if (remainingMinutes < MIN_REMAINING_MINUTES) {
      console.log(`[Zyphra] Token ${token.id.slice(0, 8)} has insufficient remaining time (${remainingMinutes} min). Skipping.`);
      return null;
    }
    return { id: token.id, apiKey: token.apiKey };
  } catch (error) {
    console.error("Error getting Zyphra token:", error);
    return null;
  }
}
async function updateTokenUsage(tokenId, minutesUsed) {
  try {
    const token = await db.select().from(zyphraTokens).where(eq2(zyphraTokens.id, tokenId)).limit(1);
    if (token.length > 0) {
      await db.update(zyphraTokens).set({
        minutesUsed: token[0].minutesUsed + minutesUsed,
        lastUsedAt: (/* @__PURE__ */ new Date()).toISOString()
      }).where(eq2(zyphraTokens.id, tokenId));
    }
  } catch (error) {
    console.error("Error updating token usage:", error);
  }
}
async function calculateAudioDuration(audioBuffer, mimeType) {
  try {
    const metadata = await mm.parseBuffer(audioBuffer, { mimeType, size: audioBuffer.length });
    if (metadata.format.duration) {
      const minutes = metadata.format.duration / 60;
      console.log(`[Zyphra] Audio duration: ${metadata.format.duration}s = ${minutes.toFixed(2)} min`);
      return Math.round(minutes * 100) / 100;
    }
    console.log("[Zyphra] No duration in audio metadata, using text estimate");
  } catch (error) {
    console.error("[Zyphra] Error calculating audio duration:", error);
  }
  return 0.01;
}
async function generateSpeech(request, excludeTokenIds = []) {
  const token = await getAvailableZyphraToken(excludeTokenIds);
  if (!token) {
    return {
      success: false,
      error: "Voice generation service unavailable. Please try again later."
    };
  }
  try {
    const requestBody = {
      text: request.text,
      speaking_rate: request.speakingRate || 15,
      model: request.model || "zonos-v0.1-transformer"
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
    if (request.pitchStd !== void 0 && request.model !== "zonos-v0.1-hybrid") {
      requestBody.pitchStd = request.pitchStd;
    }
    if (request.speakerNoised !== void 0 && request.model === "zonos-v0.1-hybrid") {
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
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[Zyphra] API Error: ${response.status} - ${errorText}`);
      return {
        success: false,
        error: `Voice generation failed. Please try again.`,
        tokenId: token.id
      };
    }
    const audioBuffer = await response.arrayBuffer();
    const audioData = Buffer.from(audioBuffer);
    const mimeType = request.mimeType || "audio/webm";
    const actualMinutes = await calculateAudioDuration(audioData, mimeType);
    await updateTokenUsage(token.id, actualMinutes);
    console.log(`[Zyphra] Speech generated successfully (${actualMinutes} min actual duration)`);
    return {
      success: true,
      audioData,
      mimeType,
      tokenId: token.id,
      minutesUsed: actualMinutes
    };
  } catch (error) {
    console.error("[Zyphra] Error generating speech:", error);
    return {
      success: false,
      error: error.message || "Failed to generate speech",
      tokenId: token.id
    };
  }
}
async function generateSpeechWithRetry(request) {
  let lastError;
  const failedTokenIds = [];
  for (let attempt = 1; attempt <= MAX_SILENT_RETRIES; attempt++) {
    console.log(`[Zyphra] TTS attempt ${attempt}/${MAX_SILENT_RETRIES}${failedTokenIds.length > 0 ? ` (excluding ${failedTokenIds.length} previously failed tokens)` : ""}...`);
    const result = await generateSpeech(request, failedTokenIds);
    if (result.success) {
      if (attempt > 1) {
        console.log(`[Zyphra] TTS succeeded on attempt ${attempt}`);
      }
      return result;
    }
    if (result.tokenId && !failedTokenIds.includes(result.tokenId)) {
      failedTokenIds.push(result.tokenId);
      console.log(`[Zyphra] Token ${result.tokenId.slice(0, 8)} failed, will try different token on next attempt`);
    }
    lastError = result.error;
    if (attempt < MAX_SILENT_RETRIES) {
      console.log(`[Zyphra] TTS attempt ${attempt} failed silently, retrying... Error: ${result.error}`);
      await new Promise((resolve) => setTimeout(resolve, 500));
    } else {
      console.error(`[Zyphra] TTS failed after ${MAX_SILENT_RETRIES} attempts. Final error: ${result.error}`);
    }
  }
  return {
    success: false,
    error: lastError || "Voice generation failed after multiple attempts. Please try again."
  };
}
async function cloneVoiceWithRetry(text2, referenceAudioBase64, options) {
  return generateSpeechWithRetry({
    text: text2,
    speakerAudio: referenceAudioBase64,
    speakingRate: options?.speakingRate || 15,
    languageIsoCode: options?.languageIsoCode,
    mimeType: options?.mimeType || "audio/mp3",
    model: options?.model || "zonos-v0.1-transformer"
  });
}
async function cloneVoice(text2, referenceAudioBase64, options) {
  return generateSpeech({
    text: text2,
    speakerAudio: referenceAudioBase64,
    speakingRate: options?.speakingRate || 15,
    languageIsoCode: options?.languageIsoCode,
    mimeType: options?.mimeType || "audio/mp3",
    model: options?.model || "zonos-v0.1-transformer"
  });
}
async function getAllZyphraTokens() {
  return db.select().from(zyphraTokens);
}
async function addZyphraToken(apiKey, label, minutesLimit = 100) {
  return db.insert(zyphraTokens).values({
    apiKey,
    label,
    minutesLimit
  }).returning();
}
async function deleteZyphraToken(id) {
  return db.delete(zyphraTokens).where(eq2(zyphraTokens.id, id));
}
async function updateZyphraToken(id, updates) {
  return db.update(zyphraTokens).set(updates).where(eq2(zyphraTokens.id, id)).returning();
}
async function resetAllTokenUsage() {
  return db.update(zyphraTokens).set({ minutesUsed: 0 });
}
async function resetTokenUsage(id) {
  return db.update(zyphraTokens).set({ minutesUsed: 0 }).where(eq2(zyphraTokens.id, id));
}
var ZYPHRA_API_URL, MIN_REMAINING_MINUTES, MAX_SILENT_RETRIES, DEFAULT_VOICES, SUPPORTED_LANGUAGES;
var init_zyphra = __esm({
  "server/zyphra.ts"() {
    "use strict";
    init_db();
    init_schema();
    ZYPHRA_API_URL = "http://api.zyphra.com/v1/audio/text-to-speech";
    MIN_REMAINING_MINUTES = 15;
    MAX_SILENT_RETRIES = 3;
    DEFAULT_VOICES = [
      { name: "american_female", description: "Standard American English female voice" },
      { name: "american_male", description: "Standard American English male voice" },
      { name: "anime_girl", description: "Stylized anime girl character voice" },
      { name: "british_female", description: "British English female voice" },
      { name: "british_male", description: "British English male voice" },
      { name: "energetic_boy", description: "Energetic young male voice" },
      { name: "energetic_girl", description: "Energetic young female voice" },
      { name: "japanese_female", description: "Japanese female voice" },
      { name: "japanese_male", description: "Japanese male voice" }
    ];
    SUPPORTED_LANGUAGES = [
      { code: "en-us", name: "English (US)" },
      { code: "fr-fr", name: "French" },
      { code: "de", name: "German" },
      { code: "ja", name: "Japanese" },
      { code: "ko", name: "Korean" },
      { code: "cmn", name: "Mandarin Chinese" }
    ];
  }
});

// server/objectStorage.ts
var objectStorage_exports = {};
__export(objectStorage_exports, {
  ObjectNotFoundError: () => ObjectNotFoundError,
  ObjectStorageService: () => ObjectStorageService,
  objectStorageClient: () => objectStorageClient
});
import { Storage } from "@google-cloud/storage";
import { randomUUID as randomUUID2 } from "crypto";
import { createReadStream as createReadStream3 } from "fs";
function parseObjectPath(path6) {
  if (!path6.startsWith("/")) {
    path6 = `/${path6}`;
  }
  const pathParts = path6.split("/");
  if (pathParts.length < 3) {
    throw new Error("Invalid path: must contain at least a bucket name");
  }
  const bucketName = pathParts[1];
  const objectName = pathParts.slice(2).join("/");
  return {
    bucketName,
    objectName
  };
}
var REPLIT_SIDECAR_ENDPOINT, objectStorageClient, ObjectNotFoundError, ObjectStorageService;
var init_objectStorage = __esm({
  "server/objectStorage.ts"() {
    "use strict";
    REPLIT_SIDECAR_ENDPOINT = "http://127.0.0.1:1106";
    objectStorageClient = new Storage({
      credentials: {
        audience: "replit",
        subject_token_type: "access_token",
        token_url: `${REPLIT_SIDECAR_ENDPOINT}/token`,
        type: "external_account",
        credential_source: {
          url: `${REPLIT_SIDECAR_ENDPOINT}/credential`,
          format: {
            type: "json",
            subject_token_field_name: "access_token"
          }
        },
        universe_domain: "googleapis.com"
      },
      projectId: ""
    });
    ObjectNotFoundError = class _ObjectNotFoundError extends Error {
      constructor() {
        super("Object not found");
        this.name = "ObjectNotFoundError";
        Object.setPrototypeOf(this, _ObjectNotFoundError.prototype);
      }
    };
    ObjectStorageService = class {
      getPrivateObjectDir() {
        const dir = process.env.PRIVATE_OBJECT_DIR || "";
        if (!dir) {
          throw new Error(
            "PRIVATE_OBJECT_DIR not set. Create a bucket in 'Object Storage' pane and set PRIVATE_OBJECT_DIR env var."
          );
        }
        return dir;
      }
      async downloadObject(file, res, cacheTtlSec = 3600) {
        try {
          const [metadata] = await file.getMetadata();
          res.set({
            "Content-Type": metadata.contentType || "application/octet-stream",
            "Content-Length": metadata.size,
            "Cache-Control": `public, max-age=${cacheTtlSec}`,
            "Accept-Ranges": "bytes"
          });
          const stream = file.createReadStream();
          stream.on("error", (err) => {
            console.error("Stream error:", err);
            if (!res.headersSent) {
              res.status(500).json({ error: "Error streaming file" });
            }
          });
          stream.pipe(res);
        } catch (error) {
          console.error("Error downloading file:", error);
          if (!res.headersSent) {
            res.status(500).json({ error: "Error downloading file" });
          }
        }
      }
      async getObjectEntityFile(objectPath) {
        if (!objectPath.startsWith("/videos/")) {
          throw new ObjectNotFoundError();
        }
        const parts = objectPath.slice(1).split("/");
        if (parts.length < 2) {
          throw new ObjectNotFoundError();
        }
        const entityId = parts.slice(1).join("/");
        let entityDir = this.getPrivateObjectDir();
        if (!entityDir.endsWith("/")) {
          entityDir = `${entityDir}/`;
        }
        const objectEntityPath = `${entityDir}${entityId}`;
        const { bucketName, objectName } = parseObjectPath(objectEntityPath);
        const bucket = objectStorageClient.bucket(bucketName);
        const objectFile = bucket.file(objectName);
        const [exists] = await objectFile.exists();
        if (!exists) {
          throw new ObjectNotFoundError();
        }
        return objectFile;
      }
      async uploadMergedVideo(localFilePath) {
        const privateObjectDir = this.getPrivateObjectDir();
        const videoId = randomUUID2();
        const fullPath = `${privateObjectDir}/merged/${videoId}.mp4`;
        console.log(`[Object Storage] Uploading to: ${fullPath}`);
        const { bucketName, objectName } = parseObjectPath(fullPath);
        const bucket = objectStorageClient.bucket(bucketName);
        const file = bucket.file(objectName);
        await new Promise((resolve, reject) => {
          const readStream = createReadStream3(localFilePath);
          const writeStream = file.createWriteStream({
            metadata: {
              contentType: "video/mp4"
            },
            public: true
          });
          readStream.pipe(writeStream).on("error", reject).on("finish", resolve);
        });
        console.log(`[Object Storage] Upload complete`);
        return `/videos/merged/${videoId}.mp4`;
      }
      async uploadTemporaryVideo(localFilePath, expiryHours = 24) {
        const privateObjectDir = this.getPrivateObjectDir();
        const videoId = randomUUID2();
        const fullPath = `${privateObjectDir}/temp/${videoId}.mp4`;
        const expiryDate = /* @__PURE__ */ new Date();
        expiryDate.setHours(expiryDate.getHours() + expiryHours);
        console.log(`[Object Storage] Uploading temporary video to: ${fullPath}`);
        console.log(`[Object Storage] Video will expire at: ${expiryDate.toISOString()}`);
        const { bucketName, objectName } = parseObjectPath(fullPath);
        const bucket = objectStorageClient.bucket(bucketName);
        const file = bucket.file(objectName);
        await new Promise((resolve, reject) => {
          const readStream = createReadStream3(localFilePath);
          const writeStream = file.createWriteStream({
            metadata: {
              contentType: "video/mp4",
              metadata: {
                expiresAt: expiryDate.toISOString(),
                isTemporary: "true"
              }
            },
            public: true
          });
          readStream.pipe(writeStream).on("error", reject).on("finish", resolve);
        });
        console.log(`[Object Storage] Temporary video upload complete`);
        return `/videos/temp/${videoId}.mp4`;
      }
      async cleanupExpiredVideos() {
        const privateObjectDir = this.getPrivateObjectDir();
        const tempPath = `${privateObjectDir}/temp/`;
        console.log(`[Object Storage] Starting cleanup of expired videos in: ${tempPath}`);
        const { bucketName, objectName } = parseObjectPath(tempPath);
        const bucket = objectStorageClient.bucket(bucketName);
        try {
          const [files] = await bucket.getFiles({ prefix: objectName });
          let deletedCount = 0;
          const now = /* @__PURE__ */ new Date();
          for (const file of files) {
            try {
              const [metadata] = await file.getMetadata();
              const expiresAt = metadata.metadata?.expiresAt;
              if (expiresAt && typeof expiresAt === "string" && new Date(expiresAt) < now) {
                await file.delete();
                deletedCount++;
                console.log(`[Object Storage] Deleted expired video: ${file.name}`);
              }
            } catch (error) {
              console.error(`[Object Storage] Error processing file ${file.name}:`, error);
            }
          }
          console.log(`[Object Storage] Cleanup complete. Deleted ${deletedCount} expired videos`);
          return deletedCount;
        } catch (error) {
          console.error(`[Object Storage] Error during cleanup:`, error);
          return 0;
        }
      }
      async getVideoExpiryInfo(videoPath) {
        try {
          const file = await this.getObjectEntityFile(videoPath);
          const [metadata] = await file.getMetadata();
          const expiresAtRaw = metadata.metadata?.expiresAt;
          const expiresAt = typeof expiresAtRaw === "string" ? expiresAtRaw : null;
          const isExpired = expiresAt ? new Date(expiresAt) < /* @__PURE__ */ new Date() : false;
          return { expiresAt, isExpired };
        } catch (error) {
          return { expiresAt: null, isExpired: false };
        }
      }
    };
  }
});

// server/videoMergerFFmpeg.ts
var videoMergerFFmpeg_exports = {};
__export(videoMergerFFmpeg_exports, {
  mergeVideosWithFFmpeg: () => mergeVideosWithFFmpeg,
  mergeVideosWithFFmpegTemporary: () => mergeVideosWithFFmpegTemporary
});
import { exec as exec2 } from "child_process";
import { promisify as promisify2 } from "util";
import { writeFile as writeFile2, mkdir as mkdir2, rm } from "fs/promises";
import { existsSync as existsSync2, statSync } from "fs";
import path3 from "path";
import { randomUUID as randomUUID3 } from "crypto";
async function mergeVideosWithFFmpeg(videoUrls) {
  if (videoUrls.length === 0) {
    throw new Error("No video URLs provided for merging");
  }
  if (videoUrls.length > 14) {
    throw new Error("Cannot merge more than 14 videos at once");
  }
  const uniqueId = randomUUID3();
  const tempDir = path3.join("/tmp", `video-merge-${uniqueId}`);
  const listFile = path3.join(tempDir, "filelist.txt");
  const outputFile = path3.join(tempDir, "merged-output.mp4");
  try {
    if (!existsSync2(tempDir)) {
      await mkdir2(tempDir, { recursive: true });
    }
    console.log(`[FFmpeg Merger] Starting merge of ${videoUrls.length} videos in ${tempDir}`);
    const downloadedFiles = [];
    for (let i = 0; i < videoUrls.length; i++) {
      const filename = path3.join(tempDir, `video-${i + 1}.mp4`);
      console.log(`[FFmpeg Merger] Downloading video ${i + 1}/${videoUrls.length}...`);
      const response = await fetch(videoUrls[i]);
      if (!response.ok) {
        throw new Error(`Failed to download video ${i + 1}: ${response.statusText}`);
      }
      const buffer = await response.arrayBuffer();
      await writeFile2(filename, Buffer.from(buffer));
      downloadedFiles.push(filename);
      console.log(`[FFmpeg Merger] Downloaded video ${i + 1} (${buffer.byteLength} bytes)`);
    }
    const fileListContent = downloadedFiles.map((file) => `file '${file}'`).join("\n");
    await writeFile2(listFile, fileListContent);
    console.log(`[FFmpeg Merger] Created file list with ${downloadedFiles.length} videos`);
    console.log(`[FFmpeg Merger] Running FFmpeg to merge videos...`);
    const ffmpegCommand = `ffmpeg -f concat -safe 0 -i "${listFile}" -c copy "${outputFile}"`;
    try {
      const { stdout, stderr } = await execAsync2(ffmpegCommand, { maxBuffer: 1024 * 1024 * 10 });
      console.log(`[FFmpeg Merger] FFmpeg completed successfully`);
      if (stderr) {
        console.log(`[FFmpeg Merger] FFmpeg stderr:`, stderr.substring(0, 500));
      }
    } catch (ffmpegError) {
      console.error(`[FFmpeg Merger] FFmpeg error:`, ffmpegError.stderr || ffmpegError.message);
      throw new Error(`FFmpeg failed: ${ffmpegError.message}`);
    }
    console.log(`[FFmpeg Merger] Uploading merged video to Cloudinary...`);
    const fileStats = statSync(outputFile);
    const fileSizeMB = (fileStats.size / (1024 * 1024)).toFixed(2);
    console.log(`[FFmpeg Merger] Merged video size: ${fileSizeMB} MB`);
    const uploadUrl = await uploadVideoToCloudinary(outputFile);
    console.log(`[FFmpeg Merger] Cloudinary upload complete! URL: ${uploadUrl}`);
    try {
      await rm(tempDir, { recursive: true, force: true });
      console.log(`[FFmpeg Merger] Cleanup successful`);
    } catch (cleanupError) {
      console.error(`[FFmpeg Merger] Cleanup failed:`, cleanupError);
    }
    return uploadUrl;
  } catch (error) {
    console.error(`[FFmpeg Merger] Error during merge process:`, error);
    try {
      if (existsSync2(tempDir)) {
        await rm(tempDir, { recursive: true, force: true });
        console.log(`[FFmpeg Merger] Error cleanup successful`);
      }
    } catch (cleanupError) {
      console.error(`[FFmpeg Merger] Error cleanup failed:`, cleanupError);
    }
    throw new Error(`Failed to merge videos with FFmpeg: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
}
async function mergeVideosWithFFmpegTemporary(videoUrls, expiryHours = 24) {
  if (videoUrls.length === 0) {
    throw new Error("No video URLs provided for merging");
  }
  if (videoUrls.length > 14) {
    throw new Error("Cannot merge more than 14 videos at once");
  }
  const uniqueId = randomUUID3();
  const tempDir = path3.join("/tmp", `video-merge-${uniqueId}`);
  const listFile = path3.join(tempDir, "filelist.txt");
  const outputFile = path3.join(tempDir, "merged-output.mp4");
  try {
    if (!existsSync2(tempDir)) {
      await mkdir2(tempDir, { recursive: true });
    }
    console.log(`[FFmpeg Temporary] Starting merge of ${videoUrls.length} videos in ${tempDir}`);
    const downloadedFiles = [];
    for (let i = 0; i < videoUrls.length; i++) {
      const filename = path3.join(tempDir, `video-${i + 1}.mp4`);
      console.log(`[FFmpeg Temporary] Downloading video ${i + 1}/${videoUrls.length}...`);
      const response = await fetch(videoUrls[i]);
      if (!response.ok) {
        throw new Error(`Failed to download video ${i + 1}: ${response.statusText}`);
      }
      const buffer = await response.arrayBuffer();
      await writeFile2(filename, Buffer.from(buffer));
      downloadedFiles.push(filename);
      console.log(`[FFmpeg Temporary] Downloaded video ${i + 1} (${buffer.byteLength} bytes)`);
    }
    const fileListContent = downloadedFiles.map((file) => `file '${file}'`).join("\n");
    await writeFile2(listFile, fileListContent);
    console.log(`[FFmpeg Temporary] Created file list with ${downloadedFiles.length} videos`);
    console.log(`[FFmpeg Temporary] Running FFmpeg to merge videos...`);
    const ffmpegCommand = `ffmpeg -f concat -safe 0 -i "${listFile}" -c copy "${outputFile}"`;
    try {
      const { stdout, stderr } = await execAsync2(ffmpegCommand, { maxBuffer: 1024 * 1024 * 10 });
      console.log(`[FFmpeg Temporary] FFmpeg completed successfully`);
      if (stderr) {
        console.log(`[FFmpeg Temporary] FFmpeg stderr:`, stderr.substring(0, 500));
      }
    } catch (ffmpegError) {
      console.error(`[FFmpeg Temporary] FFmpeg error:`, ffmpegError.stderr || ffmpegError.message);
      throw new Error(`FFmpeg failed: ${ffmpegError.message}`);
    }
    console.log(`[FFmpeg Temporary] Uploading to temporary storage (expires in ${expiryHours} hours)...`);
    const videoPath = await objectStorageService.uploadTemporaryVideo(outputFile, expiryHours);
    const expiryDate = /* @__PURE__ */ new Date();
    expiryDate.setHours(expiryDate.getHours() + expiryHours);
    console.log(`[FFmpeg Temporary] Upload complete! Path: ${videoPath}`);
    console.log(`[FFmpeg Temporary] Expires at: ${expiryDate.toISOString()}`);
    try {
      await rm(tempDir, { recursive: true, force: true });
      console.log(`[FFmpeg Temporary] Cleanup successful`);
    } catch (cleanupError) {
      console.error(`[FFmpeg Temporary] Cleanup failed:`, cleanupError);
    }
    return {
      videoPath,
      expiresAt: expiryDate.toISOString()
    };
  } catch (error) {
    console.error(`[FFmpeg Temporary] Error during merge process:`, error);
    try {
      if (existsSync2(tempDir)) {
        await rm(tempDir, { recursive: true, force: true });
        console.log(`[FFmpeg Temporary] Error cleanup successful`);
      }
    } catch (cleanupError) {
      console.error(`[FFmpeg Temporary] Error cleanup failed:`, cleanupError);
    }
    throw new Error(`Failed to merge videos with FFmpeg: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
}
var execAsync2, objectStorageService;
var init_videoMergerFFmpeg = __esm({
  "server/videoMergerFFmpeg.ts"() {
    "use strict";
    init_objectStorage();
    init_cloudinary();
    execAsync2 = promisify2(exec2);
    objectStorageService = new ObjectStorageService();
  }
});

// server/googleDriveOAuth.ts
var googleDriveOAuth_exports = {};
__export(googleDriveOAuth_exports, {
  exchangeCodeForToken: () => exchangeCodeForToken,
  generateAuthUrl: () => generateAuthUrl,
  getDirectDownloadLinkOAuth: () => getDirectDownloadLinkOAuth,
  getEmbedLink: () => getEmbedLink,
  uploadVideoToGoogleDriveOAuth: () => uploadVideoToGoogleDriveOAuth
});
import { google as google2 } from "googleapis";
import fs3 from "fs";
function getOAuth2Client(config, redirectUri) {
  const oauth2Client = new google2.auth.OAuth2(
    config.clientId,
    config.clientSecret,
    redirectUri || "http://localhost:8080"
  );
  oauth2Client.setCredentials({
    refresh_token: config.refreshToken
  });
  return oauth2Client;
}
async function uploadVideoToGoogleDriveOAuth(filePath, fileName) {
  try {
    const clientId = process.env.GOOGLE_DRIVE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_DRIVE_CLIENT_SECRET;
    const refreshToken = process.env.GOOGLE_DRIVE_REFRESH_TOKEN;
    if (!clientId || !clientSecret || !refreshToken) {
      throw new Error(
        "Missing Google Drive OAuth credentials. Please set GOOGLE_DRIVE_CLIENT_ID, GOOGLE_DRIVE_CLIENT_SECRET, and GOOGLE_DRIVE_REFRESH_TOKEN environment variables."
      );
    }
    const auth = getOAuth2Client({ clientId, clientSecret, refreshToken });
    const drive = google2.drive({ version: "v3", auth });
    console.log(`[Google Drive OAuth] Uploading file: ${fileName}`);
    const fileMetadata = {
      name: fileName
    };
    const media = {
      mimeType: "video/mp4",
      body: fs3.createReadStream(filePath)
    };
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media,
      fields: "id, webViewLink, webContentLink"
    });
    if (!response.data.id) {
      throw new Error("Upload succeeded but no file ID returned");
    }
    console.log(`[Google Drive OAuth] File uploaded successfully. ID: ${response.data.id}`);
    await drive.permissions.create({
      fileId: response.data.id,
      requestBody: {
        role: "reader",
        type: "anyone"
      }
    });
    console.log(`[Google Drive OAuth] File permissions set to public`);
    return {
      id: response.data.id,
      webViewLink: response.data.webViewLink || "",
      webContentLink: response.data.webContentLink || ""
    };
  } catch (error) {
    console.error("[Google Drive OAuth] Upload error:", error);
    throw error;
  }
}
function getDirectDownloadLinkOAuth(fileId) {
  return `https://drive.google.com/uc?export=view&id=${fileId}`;
}
function getEmbedLink(fileId) {
  return `https://drive.google.com/file/d/${fileId}/preview`;
}
async function generateAuthUrl() {
  const clientId = process.env.GOOGLE_DRIVE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_DRIVE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error("Missing GOOGLE_DRIVE_CLIENT_ID or GOOGLE_DRIVE_CLIENT_SECRET");
  }
  const oauth2Client = new google2.auth.OAuth2(
    clientId,
    clientSecret,
    "http://localhost:8080"
  );
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/drive.file"],
    prompt: "consent"
  });
  return authUrl;
}
async function exchangeCodeForToken(code) {
  const clientId = process.env.GOOGLE_DRIVE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_DRIVE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error("Missing GOOGLE_DRIVE_CLIENT_ID or GOOGLE_DRIVE_CLIENT_SECRET");
  }
  const oauth2Client = new google2.auth.OAuth2(
    clientId,
    clientSecret,
    "http://localhost:8080"
  );
  const { tokens } = await oauth2Client.getToken(code);
  if (!tokens.refresh_token) {
    throw new Error("No refresh token received. Make sure to use prompt=consent in the auth URL.");
  }
  return tokens.refresh_token;
}
var init_googleDriveOAuth = __esm({
  "server/googleDriveOAuth.ts"() {
    "use strict";
  }
});

// server/index.ts
init_db();
import express2 from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import compression from "compression";

// server/routes.ts
init_storage();
init_db();
init_schema();
import { createServer } from "http";
import crypto3 from "crypto";
import { authenticator } from "otplib";
import * as QRCode from "qrcode";

// server/openai-script.ts
init_storage();
var MEGALLM_MODELS = [
  "gpt-4o-mini",
  "gemini-2.0-flash-001",
  "claude-3.5-sonnet"
];
async function generateScript(storyAbout, numberOfPrompts, finalStep) {
  const MAX_RETRIES_PER_MODEL = 2;
  const TIMEOUT_MS = 12e4;
  const appSettings2 = await storage.getAppSettings();
  const apiKey = appSettings2?.scriptApiKey || process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error("Script API key not configured. Please set it in Admin Panel > App Settings or add OPENAI_API_KEY environment variable.");
  }
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
  for (let modelIndex = 0; modelIndex < MEGALLM_MODELS.length; modelIndex++) {
    const currentModel = MEGALLM_MODELS[modelIndex];
    for (let attempt = 1; attempt <= MAX_RETRIES_PER_MODEL; attempt++) {
      try {
        console.log(`[Script Generator] Model ${modelIndex + 1}/${MEGALLM_MODELS.length} (${currentModel}), Attempt ${attempt}/${MAX_RETRIES_PER_MODEL}`);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
        try {
          const response = await fetch("https://ai.megallm.io/v1/chat/completions", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${apiKey}`,
              "Content-Type": "application/json"
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
              max_tokens: 16e3
            }),
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API request failed: ${response.status} ${response.statusText} - ${errorText}`);
          }
          const data = await response.json();
          if (!data || typeof data !== "object") {
            throw new Error("Invalid API response format");
          }
          if (!data.choices || !Array.isArray(data.choices) || data.choices.length === 0) {
            throw new Error("API response missing choices array");
          }
          const messageContent = data.choices[0]?.message?.content;
          if (!messageContent || typeof messageContent !== "string") {
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
          if (fetchError instanceof Error && fetchError.name === "AbortError") {
            throw new Error(`Request timeout after ${TIMEOUT_MS}ms`);
          }
          throw fetchError;
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        lastError = errorMessage;
        console.error(`[Script Generator] Model ${currentModel}, Attempt ${attempt} failed:`, errorMessage);
        if (attempt === MAX_RETRIES_PER_MODEL) {
          console.log(`[Script Generator] Model ${currentModel} exhausted, switching to next model...`);
          break;
        }
        const waitMs = 1e3;
        console.log(`[Script Generator] Waiting ${waitMs}ms before retry...`);
        await new Promise((resolve) => setTimeout(resolve, waitMs));
      }
    }
  }
  throw new Error(`Failed to generate script after trying all ${MEGALLM_MODELS.length} models. Last error: ${lastError}`);
}

// server/veo3.ts
var VEO3_BASE_URL = "https://aisandbox-pa.googleapis.com/v1/video";
async function checkVideoStatus(operationName, sceneId, apiKey, retryCount = 0) {
  const MAX_RETRIES2 = 3;
  let trimmedApiKey = apiKey.trim();
  if (trimmedApiKey.startsWith("Bearer ")) {
    trimmedApiKey = trimmedApiKey.substring(7);
  }
  const requestBody = {
    operations: [{
      operation: {
        name: operationName
      },
      sceneId,
      status: "MEDIA_GENERATION_STATUS_PENDING"
    }]
  };
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3e4);
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
    const responseText = await response.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (jsonError) {
      const isHtmlError = responseText.trim().startsWith("<") || responseText.includes("<html");
      if (isHtmlError) {
        console.error(`[VEO3] API returned HTML error page instead of JSON. Token may be rate limited.`);
        console.error(`[VEO3] Raw response:`, responseText.substring(0, 500));
        throw new Error("API returned HTML error page. Token may be rate limited. Retrying with different token...");
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
    if (operationData.operation?.error?.message === "PUBLIC_ERROR_HIGH_TRAFFIC") {
      console.log(`[VEO3] \u26A0\uFE0F PUBLIC_ERROR_HIGH_TRAFFIC detected - signaling for auto-retry with new token`);
      return {
        status: "PENDING",
        error: operationData.operation.error.message,
        errorCode: operationData.operation.error.code,
        remainingCredits: data.remainingCredits,
        needsTokenRetry: true
        // Signal to trigger auto-retry with different token
      };
    }
    const errorMessage = operationData.operation?.error?.message || "";
    const errorCode = operationData.operation?.error?.code;
    if (errorCode === 13 || errorMessage.includes("LMRoot") || errorMessage.includes("Gemini model")) {
      console.log(`[VEO3] \u26A0\uFE0F LMRoot/Gemini error detected (code: ${errorCode}) - signaling for auto-retry with new token`);
      return {
        status: "PENDING",
        error: errorMessage,
        errorCode,
        remainingCredits: data.remainingCredits,
        needsTokenRetry: true
        // Signal to trigger auto-retry with different token
      };
    }
    if (operationData.operation?.error?.message === "PUBLIC_ERROR_UNSAFE_GENERATION") {
      if (retryCount >= 5) {
        console.log(`[VEO3] \u274C PUBLIC_ERROR_UNSAFE_GENERATION - Max retry attempts (5) reached, marking as FAILED`);
        return {
          status: "MEDIA_GENERATION_STATUS_FAILED",
          error: "Content Policy Violation: Your image or prompt contains content that violates our safety guidelines. This may include adult/suggestive content, violence, or other prohibited material. Please use a different image or modify your prompt and try again.",
          errorCode: operationData.operation.error.code,
          remainingCredits: data.remainingCredits
        };
      }
      console.log(`[VEO3] \u26A0\uFE0F PUBLIC_ERROR_UNSAFE_GENERATION detected (attempt ${retryCount + 1}/5) - returning PENDING status to allow retry`);
      return {
        status: "PENDING",
        error: operationData.operation.error.message,
        errorCode: operationData.operation.error.code,
        remainingCredits: data.remainingCredits
      };
    }
    if (operationData.operation?.error?.message === "PUBLIC_ERROR_MINOR") {
      if (retryCount >= 20) {
        console.log(`[VEO3] \u274C PUBLIC_ERROR_MINOR - Max retry attempts (20) reached, marking as FAILED`);
        return {
          status: "MEDIA_GENERATION_STATUS_FAILED",
          error: "Child Safety Policy: Your image appears to contain a minor (person under 18). For child safety protection, video generation with images of minors is not permitted. Please use an image of an adult instead.",
          errorCode: operationData.operation.error.code,
          remainingCredits: data.remainingCredits
        };
      }
      console.log(`[VEO3] \u26A0\uFE0F PUBLIC_ERROR_MINOR detected (attempt ${retryCount + 1}/20) - returning PENDING status to allow retry`);
      return {
        status: "PENDING",
        error: operationData.operation.error.message,
        errorCode: operationData.operation.error.code,
        remainingCredits: data.remainingCredits
      };
    }
    let videoUrl;
    if (operationData.operation?.metadata?.video?.fifeUrl) {
      videoUrl = operationData.operation.metadata.video.fifeUrl;
    } else if (operationData.operation.videoUrl) {
      videoUrl = operationData.operation.videoUrl;
    } else if (operationData.operation.fileUrl) {
      videoUrl = operationData.operation.fileUrl;
    } else if (operationData.operation.downloadUrl) {
      videoUrl = operationData.operation.downloadUrl;
    }
    if (videoUrl) {
      const originalUrl = videoUrl;
      videoUrl = videoUrl.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
      console.log(`[VEO3] Found video URL`);
      console.log(`[VEO3] Original length: ${originalUrl.length}, Decoded length: ${videoUrl.length}`);
      console.log(`[VEO3] URL starts with: ${videoUrl.substring(0, 100)}`);
      console.log(`[VEO3] Has &: ${videoUrl.includes("&")}, Has &amp;: ${videoUrl.includes("&amp;")}`);
    } else {
      console.log(`[VEO3] No video URL found in response`);
    }
    return {
      status: operationData.status,
      videoUrl,
      error: operationData.operation.error?.message,
      errorCode: operationData.operation.error?.code,
      remainingCredits: data.remainingCredits
    };
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === "AbortError") {
      if (retryCount < MAX_RETRIES2) {
        const waitTime = Math.pow(2, retryCount) * 1e3;
        console.log(`[VEO3] Status check timeout for ${sceneId}, retrying in ${waitTime}ms (attempt ${retryCount + 1}/${MAX_RETRIES2})`);
        await new Promise((resolve) => setTimeout(resolve, waitTime));
        return checkVideoStatus(operationName, sceneId, apiKey, retryCount + 1);
      } else {
        console.error(`[VEO3] Status check timeout after ${MAX_RETRIES2} retries for ${sceneId}`);
        return { status: "PENDING" };
      }
    }
    throw error;
  }
}

// server/backgroundVideoGen.ts
init_storage();
init_cloudinary();
import crypto from "crypto";
function getVideoBuffer(videoId) {
  return null;
}
var activeJobs = /* @__PURE__ */ new Map();
var WHISK_BASE_URL = "https://aisandbox-pa.googleapis.com/v1";
async function generateWhiskImage(apiKey, prompt, aspectRatio) {
  const workflowId = crypto.randomUUID();
  const sessionId = `;${Date.now()}`;
  const seed = Math.floor(Math.random() * 1e6);
  const imageAspectRatio = aspectRatio === "portrait" ? "IMAGE_ASPECT_RATIO_PORTRAIT" : "IMAGE_ASPECT_RATIO_LANDSCAPE";
  const requestBody = {
    clientContext: {
      workflowId,
      tool: "BACKBONE",
      sessionId
    },
    imageModelSettings: {
      imageModel: "IMAGEN_3_5",
      aspectRatio: imageAspectRatio
    },
    seed,
    prompt,
    mediaCategory: "MEDIA_CATEGORY_BOARD"
  };
  console.log(`[Whisk Image] Generating image for prompt: "${prompt.substring(0, 50)}..."`);
  const response = await fetch(`${WHISK_BASE_URL}/whisk:generateImage`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`[Whisk Image] API error ${response.status}:`, errorText);
    throw new Error(`Image generation failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }
  const data = await response.json();
  if (!data.imagePanels || data.imagePanels.length === 0 || !data.imagePanels[0].generatedImages || data.imagePanels[0].generatedImages.length === 0) {
    throw new Error("No image generated from Whisk API");
  }
  const generatedImage = data.imagePanels[0].generatedImages[0];
  console.log(`[Whisk Image] Image generated successfully. MediaGenerationId: ${generatedImage.mediaGenerationId}`);
  return {
    encodedImage: generatedImage.encodedImage,
    mediaGenerationId: generatedImage.mediaGenerationId,
    workflowId: data.workflowId || workflowId
  };
}
async function startWhiskVideoGeneration(apiKey, prompt, encodedImage, mediaGenerationId, workflowId) {
  const sessionId = `;${Date.now()}`;
  const requestBody = {
    clientContext: {
      sessionId,
      tool: "BACKBONE",
      workflowId
    },
    promptImageInput: {
      prompt,
      rawBytes: encodedImage,
      mediaGenerationId
    },
    modelNameType: "VEO_3_1_I2V_12STEP",
    modelKey: "",
    userInstructions: prompt,
    loopVideo: false
  };
  console.log(`[Whisk Video] Starting video generation...`);
  const response = await fetch(`${WHISK_BASE_URL}/whisk:generateVideo`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`[Whisk Video] API error ${response.status}:`, errorText);
    throw new Error(`Video generation start failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }
  const data = await response.json();
  if (!data.operation?.operation?.name) {
    console.error(`[Whisk Video] Unexpected response:`, JSON.stringify(data));
    throw new Error("No operation name returned from video generation");
  }
  const operationName = data.operation.operation.name;
  console.log(`[Whisk Video] Video generation started. Operation: ${operationName}`);
  return operationName;
}
async function checkWhiskVideoStatus(apiKey, operationName, videoId, directToUser = false) {
  const requestBody = {
    operations: [{
      operation: {
        name: operationName
      }
    }]
  };
  const response = await fetch(`${WHISK_BASE_URL}:runVideoFxSingleClipsStatusCheck`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`[Whisk Status] API error ${response.status}:`, errorText);
    throw new Error(`Status check failed: ${response.status}`);
  }
  const data = await response.json();
  const logData = JSON.stringify(data, (key, value) => {
    if (typeof value === "string" && value.length > 100) {
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
  if (nestedOperation?.error) {
    return {
      done: true,
      error: nestedOperation.error.message || "Video generation failed"
    };
  }
  const extractRawBytes = (encodedVideo) => {
    if (!encodedVideo) return void 0;
    if (typeof encodedVideo === "string") return encodedVideo;
    if (typeof encodedVideo === "object" && encodedVideo.rawBytes) return encodedVideo.rawBytes;
    return void 0;
  };
  const isSuccessful = operationData.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL" || nestedOperation?.done === true;
  if (isSuccessful) {
    let videoUrl;
    let base64Video;
    for (const [key, value] of Object.entries(operationData)) {
      if (key !== "status" && key !== "operation" && typeof value === "string" && value.length > 1e3) {
        console.log(`[Whisk Status] Found base64 data in direct field "${key}" (${value.length} chars)`);
        base64Video = value;
        break;
      }
    }
    if (!base64Video && nestedOperation) {
      if (nestedOperation.response?.videoResult?.video?.uri) {
        videoUrl = nestedOperation.response.videoResult.video.uri;
      }
      if (!videoUrl) {
        const generatedVideo = nestedOperation.response?.generatedVideo;
        if (Array.isArray(generatedVideo) && generatedVideo.length > 0) {
          const firstVideo = generatedVideo[0];
          base64Video = extractRawBytes(firstVideo.encodedVideo) || firstVideo.rawBytes;
          if (!videoUrl && firstVideo.videoUrl) {
            videoUrl = firstVideo.videoUrl;
          }
          console.log(`[Whisk Status] Found rawBytes in generatedVideo array: ${base64Video ? "yes" : "no"}`);
        } else if (generatedVideo && typeof generatedVideo === "object" && !Array.isArray(generatedVideo)) {
          base64Video = extractRawBytes(generatedVideo.encodedVideo) || generatedVideo.rawBytes;
          if (!videoUrl && generatedVideo.videoUrl) {
            videoUrl = generatedVideo.videoUrl;
          }
          console.log(`[Whisk Status] Found rawBytes in generatedVideo object: ${base64Video ? "yes" : "no"}`);
        }
        if (!base64Video) {
          const video = nestedOperation.response?.videoResult?.video;
          if (video) {
            base64Video = extractRawBytes(video.encodedVideo) || video.rawBytes;
            console.log(`[Whisk Status] Found rawBytes in videoResult: ${base64Video ? "yes" : "no"}`);
          }
        }
        if (!base64Video) {
          base64Video = nestedOperation.response?.rawBytes || operationData.rawBytes || data.rawBytes;
          if (base64Video) {
            console.log(`[Whisk Status] Found rawBytes at top level`);
          }
        }
      }
    }
    if (base64Video) {
      if (directToUser) {
        console.log(`[Whisk Status] Direct to user mode - returning raw base64 (${(base64Video.length / 1024 / 1024).toFixed(2)}MB)`);
        return { done: true, videoData: base64Video };
      }
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
    console.log(`[Whisk Status] Operation successful but no video found. Keys in operationData:`, Object.keys(operationData));
    return { done: true, error: "Video completed but no URL found" };
  }
  return { done: false };
}
async function startBackgroundVideoGeneration(videoId, prompt, aspectRatio, _sessionCookie, _cookieId, userId) {
  activeJobs.set(videoId, {
    videoId,
    status: "processing",
    startedAt: Date.now(),
    stage: "image_generation"
  });
  (async () => {
    let tokenId;
    try {
      console.log(`[BackgroundGen] Starting video ${videoId} - "${prompt.substring(0, 50)}..."`);
      const appSettings2 = await storage.getAppSettings();
      const directToUser = appSettings2?.storageMethod === "direct_to_user";
      if (directToUser) {
        console.log(`[BackgroundGen] Direct to user mode - video will not be stored in database`);
      }
      if (userId && !directToUser) {
        await storage.updateVideoHistoryStatus(videoId, userId, "processing");
      }
      const token = await storage.getNextRotationToken();
      if (!token) {
        throw new Error("No active API tokens available");
      }
      tokenId = token.id;
      const apiKey = token.token;
      console.log(`[BackgroundGen] Using token: ${token.label}`);
      await storage.updateTokenUsage(token.id);
      activeJobs.set(videoId, {
        videoId,
        status: "processing",
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now(),
        stage: "image_generation"
      });
      const imageResult = await generateWhiskImage(apiKey, prompt, aspectRatio);
      console.log(`[BackgroundGen] Image generated for video ${videoId}`);
      activeJobs.set(videoId, {
        videoId,
        status: "processing",
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now(),
        stage: "video_generation"
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
        status: "processing",
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now(),
        stage: "status_polling"
      });
      const maxPolls = 60;
      const pollInterval = 1e4;
      let pollCount = 0;
      while (pollCount < maxPolls) {
        pollCount++;
        console.log(`[BackgroundGen] Video ${videoId} - Poll ${pollCount}/${maxPolls}`);
        const status = await checkWhiskVideoStatus(apiKey, operationName, videoId, directToUser);
        if (status.done) {
          if (directToUser && status.videoData) {
            console.log(`[BackgroundGen] Video ${videoId} completed! (direct to user - no database storage)`);
            activeJobs.set(videoId, {
              videoId,
              status: "completed",
              videoData: status.videoData,
              // Raw base64 for direct delivery
              startedAt: activeJobs.get(videoId)?.startedAt || Date.now()
            });
            if (userId) {
              await storage.incrementDailyVideoCount(userId);
              await storage.incrementTotalVideosGenerated();
            }
            return;
          }
          if (status.videoUrl) {
            console.log(`[BackgroundGen] Video ${videoId} completed!`);
            activeJobs.set(videoId, {
              videoId,
              status: "completed",
              videoUrl: status.videoUrl,
              startedAt: activeJobs.get(videoId)?.startedAt || Date.now()
            });
            if (userId) {
              await storage.updateVideoHistoryStatus(videoId, userId, "completed", status.videoUrl);
              await storage.incrementDailyVideoCount(userId);
              await storage.incrementTotalVideosGenerated();
            }
            return;
          } else {
            throw new Error(status.error || "Video generation failed");
          }
        }
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
      throw new Error("Video generation timed out after 10 minutes");
    } catch (error) {
      const errorMsg = error?.message || "Unknown error";
      console.error(`[BackgroundGen] Video ${videoId} error: ${errorMsg}`);
      activeJobs.set(videoId, {
        videoId,
        status: "failed",
        error: errorMsg,
        startedAt: activeJobs.get(videoId)?.startedAt || Date.now()
      });
      if (userId) {
        await storage.updateVideoHistoryStatus(videoId, userId, "failed", void 0, errorMsg);
      }
      if (tokenId) {
        storage.recordTokenError(tokenId);
      }
    }
    setTimeout(() => {
      activeJobs.delete(videoId);
    }, 10 * 60 * 1e3);
  })();
}
function getJobStatus(videoId) {
  return activeJobs.get(videoId) || null;
}

// server/routes.ts
init_bulkQueueFlow();

// server/falai.ts
async function mergeVideosWithFalAI(videoUrls) {
  const apiKey = process.env.FAL_API_KEY;
  if (!apiKey) {
    throw new Error("FAL_API_KEY environment variable is not set");
  }
  if (videoUrls.length === 0) {
    throw new Error("No video URLs provided for merging");
  }
  console.log(`[fal.ai] Starting merge of ${videoUrls.length} videos`);
  console.log(`[fal.ai] Video URLs:`, videoUrls);
  const requestBody = {
    video_urls: videoUrls
  };
  try {
    const response = await fetch("https://fal.run/fal-ai/ffmpeg-api/merge-videos", {
      method: "POST",
      headers: {
        "Authorization": `Key ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[fal.ai] Error response:`, errorText);
      throw new Error(`fal.ai API error: ${response.status} - ${errorText}`);
    }
    const data = await response.json();
    console.log(`[fal.ai] Merge response:`, JSON.stringify(data, null, 2));
    if (!data.video || !data.video.url) {
      throw new Error("No video URL in fal.ai response");
    }
    const mergedVideoUrl = data.video.url;
    console.log(`[fal.ai] Video merged successfully!`);
    console.log(`[fal.ai] Merged video URL: ${mergedVideoUrl}`);
    console.log(`[fal.ai] File size: ${data.video.file_size} bytes`);
    return mergedVideoUrl;
  } catch (error) {
    console.error(`[fal.ai] Error merging videos:`, error);
    throw new Error(`Failed to merge videos with fal.ai: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
}

// server/routes.ts
import { z as z2 } from "zod";
import { desc as desc2, sql as sql3, eq as eq3, and as and3, or, inArray as inArray2 } from "drizzle-orm";
import archiver from "archiver";
import https from "https";
import http from "http";

// server/planEnforcement.ts
var VOICE_CHARACTER_LIMITS = {
  free: {
    limit: 1e4,
    // 10K characters
    resetDays: 10
  },
  scale: {
    limit: 5e4,
    // 50K characters
    resetDays: 10
  },
  empire: {
    limit: 1e6,
    // 1 million characters
    resetDays: 10
  },
  enterprise: {
    limit: 5e6,
    // 5 million characters (can be customized)
    resetDays: 10
  }
};
var PLAN_CONFIGS = {
  free: {
    name: "Free",
    dailyVideoLimit: 0,
    // Free users have limited access
    allowedTools: ["veo", "voiceTools"],
    // VEO 3 + Voice Tools
    bulkGeneration: {
      maxBatch: 0,
      delaySeconds: 0,
      maxPrompts: 0
    }
  },
  scale: {
    name: "Scale",
    price: "900 PKR",
    duration: "10 days",
    dailyVideoLimit: 1e3,
    allowedTools: ["veo", "bulk", "voiceTools"],
    // VEO 3 + Bulk generation + Voice Tools
    bulkGeneration: {
      maxBatch: 7,
      delaySeconds: 30,
      maxPrompts: 50
    }
  },
  empire: {
    name: "Empire",
    price: "1500 PKR",
    duration: "10 days",
    dailyVideoLimit: 2e3,
    allowedTools: ["veo", "bulk", "script", "textToImage", "imageToVideo", "voiceTools"],
    // All tools
    bulkGeneration: {
      maxBatch: 100,
      delaySeconds: 15,
      maxPrompts: 100
    }
  },
  enterprise: {
    name: "Enterprise",
    price: "Custom",
    duration: "Custom",
    dailyVideoLimit: 2e4,
    // Default, will be overridden by user's custom limit
    allowedTools: ["veo", "bulk", "script", "textToImage", "imageToVideo", "voiceTools"],
    // All tools
    bulkGeneration: {
      maxBatch: 100,
      delaySeconds: 10,
      maxPrompts: 500
    }
  }
};
function isPlanExpired(user) {
  if (user.isAdmin) {
    return false;
  }
  if (user.planType === "free") {
    return false;
  }
  if (user.planExpiry) {
    const expiryDate = new Date(user.planExpiry);
    const now = /* @__PURE__ */ new Date();
    return now > expiryDate;
  }
  return false;
}
function hasReachedDailyLimit(user) {
  if (user.isAdmin) {
    return false;
  }
  const config = PLAN_CONFIGS[user.planType];
  if (!config) {
    return true;
  }
  const limit = user.planType === "enterprise" && user.dailyVideoLimit ? user.dailyVideoLimit : config.dailyVideoLimit;
  return user.dailyVideoCount >= limit;
}
function getRemainingVideos(user) {
  if (user.isAdmin) {
    return Infinity;
  }
  const config = PLAN_CONFIGS[user.planType];
  if (!config) {
    return 0;
  }
  const limit = user.planType === "enterprise" && user.dailyVideoLimit ? user.dailyVideoLimit : config.dailyVideoLimit;
  const remaining = limit - user.dailyVideoCount;
  return Math.max(0, remaining);
}
function canAccessTool(user, tool) {
  if (user.isAdmin) {
    return { allowed: true };
  }
  if (isPlanExpired(user)) {
    return {
      allowed: false,
      reason: "Your plan has expired. Please contact admin to renew."
    };
  }
  const config = PLAN_CONFIGS[user.planType];
  if (!config) {
    return {
      allowed: false,
      reason: "Invalid plan type. Please contact admin."
    };
  }
  if (!config.allowedTools.includes(tool)) {
    return {
      allowed: false,
      reason: `This tool is not available on your ${config.name} plan. Please upgrade to access this feature.`
    };
  }
  return { allowed: true };
}
function canGenerateVideo(user) {
  if (user.isAdmin) {
    return { allowed: true };
  }
  if (isPlanExpired(user)) {
    return {
      allowed: false,
      reason: "Your plan has expired. Please contact admin to renew."
    };
  }
  if (hasReachedDailyLimit(user)) {
    const config = PLAN_CONFIGS[user.planType];
    const limit = user.planType === "enterprise" && user.dailyVideoLimit ? user.dailyVideoLimit : config.dailyVideoLimit;
    return {
      allowed: false,
      reason: `You have reached your daily limit of ${limit} videos. Limit resets at midnight.`
    };
  }
  const remaining = getRemainingVideos(user);
  return {
    allowed: true,
    remainingVideos: remaining
  };
}
function canBulkGenerate(user, videoCount) {
  if (user.isAdmin) {
    return { allowed: true };
  }
  const toolCheck = canAccessTool(user, "bulk");
  if (!toolCheck.allowed) {
    return toolCheck;
  }
  const config = PLAN_CONFIGS[user.planType];
  const maxPrompts = user.planType === "enterprise" && user.bulkMaxPrompts ? user.bulkMaxPrompts : config.bulkGeneration.maxPrompts;
  if (videoCount > maxPrompts) {
    return {
      allowed: false,
      reason: `Your ${config.name} plan allows a maximum of ${maxPrompts} prompts in total. Please reduce the number of prompts.`
    };
  }
  if (config.bulkGeneration.maxBatch > 0 && videoCount > config.bulkGeneration.maxBatch) {
  }
  const remaining = getRemainingVideos(user);
  if (videoCount > remaining) {
    return {
      allowed: false,
      reason: `You have ${remaining} videos remaining today. Cannot generate ${videoCount} videos.`
    };
  }
  return {
    allowed: true,
    remainingVideos: remaining
  };
}
function getVoiceCharacterLimit(user) {
  if (user.isAdmin) {
    return Infinity;
  }
  const planType = user.planType;
  const config = VOICE_CHARACTER_LIMITS[planType];
  return config?.limit ?? VOICE_CHARACTER_LIMITS.free.limit;
}
function getVoiceCharacterUsage(user) {
  const limit = getVoiceCharacterLimit(user);
  const used = user.voiceCharactersUsed ?? 0;
  const remaining = Math.max(0, limit - used);
  const planType = user.planType;
  const resetDays = VOICE_CHARACTER_LIMITS[planType]?.resetDays ?? 10;
  return {
    used,
    limit: limit === Infinity ? -1 : limit,
    // -1 means unlimited
    remaining: limit === Infinity ? -1 : remaining,
    resetDate: user.voiceCharactersResetDate ?? null,
    resetDays
  };
}
function canUseVoiceCharacters(user, characterCount) {
  if (user.isAdmin) {
    return { allowed: true };
  }
  if (isPlanExpired(user)) {
    return {
      allowed: false,
      reason: "Your plan has expired. Please contact admin to renew."
    };
  }
  const toolCheck = canAccessTool(user, "voiceTools");
  if (!toolCheck.allowed) {
    return toolCheck;
  }
  const limit = getVoiceCharacterLimit(user);
  if (limit === Infinity || limit <= 0) {
    return { allowed: true };
  }
  const used = user.voiceCharactersUsed ?? 0;
  const remaining = limit - used;
  if (characterCount > remaining) {
    const planType = user.planType;
    const config = VOICE_CHARACTER_LIMITS[planType];
    return {
      allowed: false,
      reason: `Character limit exceeded. You have ${remaining.toLocaleString()} characters remaining out of ${limit.toLocaleString()}. Limit resets every ${config?.resetDays ?? 10} days.`
    };
  }
  return { allowed: true };
}

// server/routes.ts
init_bulkQueue();
var httpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 50,
  // Increased for 100 users
  keepAliveMsecs: 3e4
});
var httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 50,
  // Increased for 100 users
  keepAliveMsecs: 3e4
});
var activeZipDownloads = 0;
var MAX_CONCURRENT_ZIP_DOWNLOADS = 10;
var audioCache = /* @__PURE__ */ new Map();
var AUDIO_CACHE_TTL = 5 * 60 * 1e3;
setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of audioCache.entries()) {
    if (now - entry.timestamp > AUDIO_CACHE_TTL) {
      audioCache.delete(id);
    }
  }
}, 6e4);
var userCache = /* @__PURE__ */ new Map();
var USER_CACHE_TTL = 3e4;
setInterval(() => {
  const now = Date.now();
  const entries = Array.from(userCache.entries());
  for (const [userId, entry] of entries) {
    if (now - entry.timestamp > USER_CACHE_TTL * 2) {
      userCache.delete(userId);
    }
  }
}, 6e4);
async function getCachedUser(userId) {
  const cached = userCache.get(userId);
  const now = Date.now();
  if (cached && now - cached.timestamp < USER_CACHE_TTL) {
    return cached.user;
  }
  const user = await storage.getUser(userId);
  if (user) {
    userCache.set(userId, { user, timestamp: now });
  }
  return user;
}
var requireAuth = async (req, res, next) => {
  if (!req.session || !req.session.userId) {
    console.log(`[Security] Unauthorized access attempt to ${req.path} - no session`);
    return res.status(401).json({ error: "Authentication required" });
  }
  const user = await getCachedUser(req.session.userId);
  if (!user) {
    console.log(`[Security] Invalid session - user not found: ${req.session.userId}`);
    req.session.destroy(() => {
    });
    return res.status(401).json({ error: "Session expired" });
  }
  if (!user.isAccountActive) {
    console.log(`[Security] Blocked inactive user: ${user.username}`);
    req.session.destroy(() => {
    });
    return res.status(403).json({ error: "Account deactivated" });
  }
  next();
};
var requireAdmin = async (req, res, next) => {
  if (!req.session || !req.session.userId) {
    console.log(`[Security] Admin access denied - no session: ${req.path}`);
    return res.status(401).json({ error: "Authentication required" });
  }
  const user = await getCachedUser(req.session.userId);
  if (!user) {
    console.log(`[Security] Admin access denied - invalid user: ${req.session.userId}`);
    req.session.destroy(() => {
    });
    return res.status(401).json({ error: "Session expired" });
  }
  if (!user.isAccountActive) {
    console.log(`[Security] Admin access denied - inactive account: ${user.username}`);
    req.session.destroy(() => {
    });
    return res.status(403).json({ error: "Account deactivated" });
  }
  if (!user.isAdmin) {
    console.warn(`[SECURITY ALERT] Non-admin user attempted admin access: ${user.username} at ${req.path}`);
    return res.status(403).json({ error: "Access denied" });
  }
  console.log(`[Admin] ${user.username} accessed: ${req.method} ${req.path}`);
  next();
};
function isAuthenticationError(error) {
  const errorMessage = error?.message || error?.toString() || "";
  const authErrorPatterns = [
    "invalid authentication",
    "authentication credentials",
    "OAuth 2 access token",
    "authentication credential",
    "invalid credentials",
    "unauthorized",
    "401",
    "authentication failed"
  ];
  return authErrorPatterns.some(
    (pattern) => errorMessage.toLowerCase().includes(pattern.toLowerCase())
  );
}
async function handleTokenError(tokenId, error) {
  if (!tokenId) return;
  if (isAuthenticationError(error)) {
    console.log(`[Auto-Disable] Authentication error detected for token ${tokenId}. Disabling token permanently.`);
    await storage.toggleApiTokenStatus(tokenId, false);
    console.log(`[Auto-Disable] Token ${tokenId} has been disabled due to authentication error: ${error.message || error}`);
  } else {
    storage.recordTokenError(tokenId);
  }
}
async function getNextTokenExcluding(excludeIds) {
  const allTokens = await storage.getActiveApiTokens();
  const availableTokens = allTokens.filter((t) => !excludeIds.has(t.id) && !storage.isTokenInCooldown(t.id)).sort((a, b) => {
    const aTime = a.lastUsedAt ? new Date(a.lastUsedAt).getTime() : 0;
    const bTime = b.lastUsedAt ? new Date(b.lastUsedAt).getTime() : 0;
    return aTime - bTime;
  });
  return availableTokens[0];
}
async function retryVeoGeneration(payload, maxRetries = 20, initialToken) {
  let attemptNumber = 0;
  let rotationToken = initialToken;
  let lastError = "";
  const disabledTokenIds = /* @__PURE__ */ new Set();
  while (attemptNumber < maxRetries) {
    attemptNumber++;
    try {
      console.log(`[VEO Retry] Attempt ${attemptNumber}/${maxRetries}`);
      let apiKey;
      if (attemptNumber === 1 && initialToken && !disabledTokenIds.has(initialToken.id)) {
        rotationToken = initialToken;
        apiKey = rotationToken.token;
        console.log(`[VEO Retry] Using INITIAL token: ${rotationToken.label} (ID: ${rotationToken.id}) for attempt ${attemptNumber}`);
      } else {
        rotationToken = await getNextTokenExcluding(disabledTokenIds);
        if (!rotationToken) {
          lastError = `No active API tokens available after excluding ${disabledTokenIds.size} disabled tokens. All tokens exhausted.`;
          console.error(`[VEO Retry] ${lastError}`);
          return { success: false, error: lastError };
        }
        apiKey = rotationToken.token;
        console.log(`[VEO Retry] Using NEXT token: ${rotationToken.label} (ID: ${rotationToken.id}) for attempt ${attemptNumber}${disabledTokenIds.size > 0 ? ` (excluding ${disabledTokenIds.size} disabled)` : ""}`);
        await storage.updateTokenUsage(rotationToken.id);
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 18e4);
      const response = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timeout);
      let data;
      try {
        data = await response.json();
      } catch (jsonError) {
        const textResponse = await response.text();
        lastError = `Invalid JSON response from VEO API (got HTML): ${textResponse.substring(0, 200)}`;
        console.error(`[VEO Retry] Attempt ${attemptNumber}:`, lastError);
        await handleTokenError(rotationToken?.id, new Error(lastError));
        if (isAuthenticationError(new Error(lastError))) {
          console.log(`[VEO Retry] Auth error - token ${rotationToken?.id} auto-disabled`);
          if (rotationToken) {
            disabledTokenIds.add(rotationToken.id);
          }
        }
        if (attemptNumber < maxRetries) {
          console.log(`[VEO Retry] Retrying in 500ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      if (!response.ok) {
        lastError = data.error?.message || `API error (${response.status})`;
        console.error(`[VEO Retry] Attempt ${attemptNumber} failed:`, lastError);
        await handleTokenError(rotationToken?.id, new Error(lastError));
        if (isAuthenticationError(new Error(lastError))) {
          console.log(`[VEO Retry] Authentication error detected - token ${rotationToken?.id} auto-disabled, retrying with different token...`);
          if (rotationToken) {
            disabledTokenIds.add(rotationToken.id);
            console.log(`[VEO Retry] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
          }
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        if (attemptNumber < maxRetries) {
          console.log(`[VEO Retry] Retrying in 500ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      const operationName = data.operations?.[0]?.operation?.name;
      if (!operationName) {
        lastError = "No operation name returned from VEO API";
        console.error(`[VEO Retry] Attempt ${attemptNumber} failed:`, lastError);
        await handleTokenError(rotationToken?.id, new Error(lastError));
        if (isAuthenticationError(new Error(lastError))) {
          if (rotationToken) {
            disabledTokenIds.add(rotationToken.id);
            console.log(`[VEO Retry] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
          }
        }
        if (attemptNumber < maxRetries) {
          console.log(`[VEO Retry] Retrying in 500ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      console.log(`[VEO Retry] \u2705 SUCCESS on attempt ${attemptNumber}`);
      return { success: true, data, token: rotationToken };
    } catch (error) {
      lastError = error.message || String(error);
      console.error(`[VEO Retry] Attempt ${attemptNumber} error:`, error);
      await handleTokenError(rotationToken?.id, error);
      if (isAuthenticationError(error)) {
        if (rotationToken) {
          disabledTokenIds.add(rotationToken.id);
          console.log(`[VEO Retry] Added token ${rotationToken.id} to exclusion list. Total excluded: ${disabledTokenIds.size}`);
        }
      }
      if (attemptNumber < maxRetries) {
        console.log(`[VEO Retry] Retrying in 500ms with different token...`);
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      if (!rotationToken && !process.env.VEO3_API_KEY) {
        return { success: false, error: `No active API tokens available - all tokens may be disabled (Failed after ${maxRetries} attempts)` };
      }
      return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
    }
  }
  if (!rotationToken && !process.env.VEO3_API_KEY) {
    return { success: false, error: `No active API tokens available - all tokens may be disabled (Failed after ${maxRetries} attempts)` };
  }
  return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
}
async function retryImageToVideoGeneration(imageBase64, mimeType, videoPayload, maxRetries = 20, initialToken) {
  let attemptNumber = 0;
  let rotationToken = initialToken;
  let lastError = "";
  const disabledTokenIds = /* @__PURE__ */ new Set();
  while (attemptNumber < maxRetries) {
    attemptNumber++;
    try {
      console.log(`[Image-to-Video Retry] Attempt ${attemptNumber}/${maxRetries}`);
      let apiKey;
      if (attemptNumber === 1 && initialToken && !disabledTokenIds.has(initialToken.id)) {
        rotationToken = initialToken;
        apiKey = rotationToken.token;
        console.log(`[Image-to-Video Retry] Using INITIAL token: ${rotationToken.label} (ID: ${rotationToken.id})`);
      } else {
        rotationToken = await getNextTokenExcluding(disabledTokenIds);
        if (!rotationToken) {
          lastError = `No active API tokens available after excluding ${disabledTokenIds.size} disabled tokens.`;
          console.error(`[Image-to-Video Retry] ${lastError}`);
          return { success: false, error: lastError };
        }
        apiKey = rotationToken.token;
        console.log(`[Image-to-Video Retry] Using NEXT token: ${rotationToken.label} (ID: ${rotationToken.id})${disabledTokenIds.size > 0 ? ` (excluding ${disabledTokenIds.size} disabled)` : ""}`);
        await storage.updateTokenUsage(rotationToken.id);
      }
      console.log(`[Image-to-Video Retry] Step 1: Uploading image...`);
      const uploadPayload = {
        imageInput: {
          rawImageBytes: imageBase64,
          mimeType
        }
      };
      const uploadController = new AbortController();
      const uploadTimeout = setTimeout(() => uploadController.abort(), 12e4);
      const uploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(uploadPayload),
        signal: uploadController.signal
      });
      clearTimeout(uploadTimeout);
      if (!uploadResponse.ok) {
        const errorText = await uploadResponse.text();
        lastError = `Image upload failed: ${uploadResponse.statusText} - ${errorText}`;
        console.error(`[Image-to-Video Retry] Attempt ${attemptNumber}:`, lastError);
        await handleTokenError(rotationToken?.id, new Error(lastError));
        if (isAuthenticationError(new Error(lastError))) {
          console.log(`[Image-to-Video Retry] Auth error - token ${rotationToken?.id} auto-disabled`);
          if (rotationToken) {
            disabledTokenIds.add(rotationToken.id);
          }
        }
        if (attemptNumber < maxRetries) {
          console.log(`[Image-to-Video Retry] Retrying in 500ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      let uploadData;
      const uploadResponseText = await uploadResponse.text();
      try {
        uploadData = JSON.parse(uploadResponseText);
      } catch (jsonError) {
        const isHtmlError = uploadResponseText.trim().startsWith("<") || uploadResponseText.includes("<html");
        lastError = isHtmlError ? `API returned HTML error page (rate limited or unavailable). Token may be exhausted.` : `Invalid JSON response from API: ${uploadResponseText.substring(0, 200)}`;
        console.error(`[Image-to-Video Retry] Attempt ${attemptNumber}:`, lastError);
        console.error(`[Image-to-Video Retry] Raw response:`, uploadResponseText.substring(0, 500));
        await handleTokenError(rotationToken?.id, new Error(lastError));
        if (isHtmlError && rotationToken) {
          console.log(`[Image-to-Video Retry] HTML error - disabling token ${rotationToken.label} and trying another`);
          disabledTokenIds.add(rotationToken.id);
        }
        if (attemptNumber < maxRetries) {
          console.log(`[Image-to-Video Retry] Retrying in 1s with different token...`);
          await new Promise((resolve) => setTimeout(resolve, 1e3));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      const mediaGenId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
      if (!mediaGenId) {
        lastError = "No media generation ID returned from image upload";
        console.error(`[Image-to-Video Retry] Attempt ${attemptNumber}:`, lastError);
        if (attemptNumber < maxRetries) {
          console.log(`[Image-to-Video Retry] Retrying in 500ms...`);
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      console.log(`[Image-to-Video Retry] Image uploaded. Media ID: ${mediaGenId}`);
      console.log(`[Image-to-Video Retry] Step 2: Generating video...`);
      const payloadWithMedia = JSON.parse(JSON.stringify(videoPayload));
      payloadWithMedia.requests[0].startImage.mediaId = mediaGenId;
      const videoController = new AbortController();
      const videoTimeout = setTimeout(() => videoController.abort(), 18e4);
      const videoResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoStartImage", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payloadWithMedia),
        signal: videoController.signal
      });
      clearTimeout(videoTimeout);
      let videoData;
      const videoResponseText = await videoResponse.text();
      try {
        videoData = JSON.parse(videoResponseText);
      } catch (jsonError) {
        const isHtmlError = videoResponseText.trim().startsWith("<") || videoResponseText.includes("<html");
        lastError = isHtmlError ? `API returned HTML error page during video generation. Token may be rate limited.` : `Invalid JSON response from video API: ${videoResponseText.substring(0, 200)}`;
        console.error(`[Image-to-Video Retry] Attempt ${attemptNumber}:`, lastError);
        console.error(`[Image-to-Video Retry] Raw response:`, videoResponseText.substring(0, 500));
        await handleTokenError(rotationToken?.id, new Error(lastError));
        if (isHtmlError && rotationToken) {
          console.log(`[Image-to-Video Retry] HTML error - disabling token ${rotationToken.label} and trying another`);
          disabledTokenIds.add(rotationToken.id);
        }
        if (attemptNumber < maxRetries) {
          console.log(`[Image-to-Video Retry] Retrying in 1s with different token...`);
          await new Promise((resolve) => setTimeout(resolve, 1e3));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      if (!videoResponse.ok) {
        lastError = videoData.error?.message || `Video generation failed (${videoResponse.status})`;
        console.error(`[Image-to-Video Retry] Attempt ${attemptNumber}:`, lastError);
        await handleTokenError(rotationToken?.id, new Error(lastError));
        if (isAuthenticationError(new Error(lastError))) {
          if (rotationToken) {
            disabledTokenIds.add(rotationToken.id);
          }
        }
        if (attemptNumber < maxRetries) {
          console.log(`[Image-to-Video Retry] Retrying in 500ms with different token...`);
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      const operationName = videoData.operations?.[0]?.operation?.name;
      if (!operationName) {
        lastError = "No operation name returned from VEO API";
        console.error(`[Image-to-Video Retry] Attempt ${attemptNumber}:`, lastError);
        if (attemptNumber < maxRetries) {
          console.log(`[Image-to-Video Retry] Retrying in 500ms...`);
          await new Promise((resolve) => setTimeout(resolve, 500));
          continue;
        }
        return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
      }
      console.log(`[Image-to-Video Retry] \u2705 SUCCESS on attempt ${attemptNumber}`);
      return { success: true, data: videoData, mediaGenId, token: rotationToken };
    } catch (error) {
      lastError = error.message || String(error);
      console.error(`[Image-to-Video Retry] Attempt ${attemptNumber} error:`, error);
      await handleTokenError(rotationToken?.id, error);
      if (isAuthenticationError(error)) {
        if (rotationToken) {
          disabledTokenIds.add(rotationToken.id);
        }
      }
      if (attemptNumber < maxRetries) {
        console.log(`[Image-to-Video Retry] Retrying in 500ms with different token...`);
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      if (!rotationToken && !process.env.VEO3_API_KEY) {
        return { success: false, error: `No active API tokens available - all tokens may be disabled (Failed after ${maxRetries} attempts)` };
      }
      return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
    }
  }
  if (!rotationToken && !process.env.VEO3_API_KEY) {
    return { success: false, error: `No active API tokens available - all tokens may be disabled (Failed after ${maxRetries} attempts)` };
  }
  return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
}
async function retryTextToImageGeneration(prompt, aspectRatio, previousScenePrompt, model, generateWithWhisk, generateWithGemPix, generateWithGemPixPro, generateWithFalAI, maxRetries = 20, initialToken, referenceMediaIds) {
  let attemptNumber = 0;
  let rotationToken = initialToken;
  let lastError = "";
  const disabledTokenIds = /* @__PURE__ */ new Set();
  while (attemptNumber < maxRetries) {
    attemptNumber++;
    try {
      console.log(`[Text-to-Image Retry] Attempt ${attemptNumber}/${maxRetries}`);
      let apiKey;
      if (referenceMediaIds && referenceMediaIds.length > 0 && initialToken) {
        if (attemptNumber > 3) {
          console.log(`[Text-to-Image Retry] referenceMediaIds requires same token - returning to frontend after 3 attempts`);
          return { success: false, error: `Failed after 3 attempts with same token (referenceMediaIds requires matching token). Frontend should retry with new mediaIds.` };
        }
        rotationToken = initialToken;
        apiKey = rotationToken.token;
        console.log(`[Text-to-Image Retry] Using SAME token (required for ${referenceMediaIds.length} referenceMediaIds): ${rotationToken.label} (ID: ${rotationToken.id}) - attempt ${attemptNumber}/3`);
      } else if (attemptNumber === 1 && initialToken && !disabledTokenIds.has(initialToken.id)) {
        rotationToken = initialToken;
        apiKey = rotationToken.token;
        console.log(`[Text-to-Image Retry] Using INITIAL token: ${rotationToken.label} (ID: ${rotationToken.id})`);
      } else {
        rotationToken = await getNextTokenExcluding(disabledTokenIds);
        if (!rotationToken) {
          apiKey = process.env.GOOGLE_AI_API_KEY;
          if (!apiKey) {
            lastError = `No active API tokens available after excluding ${disabledTokenIds.size} disabled tokens.`;
            console.error(`[Text-to-Image Retry] ${lastError}`);
            return { success: false, error: lastError };
          }
          console.log("[Text-to-Image Retry] Using environment variable GOOGLE_AI_API_KEY");
        } else {
          apiKey = rotationToken.token;
          console.log(`[Text-to-Image Retry] Using NEXT token: ${rotationToken.label} (ID: ${rotationToken.id})${disabledTokenIds.size > 0 ? ` (excluding ${disabledTokenIds.size} disabled)` : ""}`);
          await storage.updateTokenUsage(rotationToken.id);
        }
      }
      let base64Image;
      if (model === "nanoBana") {
        base64Image = await generateWithGemPix(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds);
      } else if (model === "nanoBanaPro") {
        base64Image = await generateWithGemPixPro(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds);
      } else if (model === "imagen4") {
        base64Image = await generateWithFalAI(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds);
      } else {
        base64Image = await generateWithWhisk(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds);
      }
      console.log(`[Text-to-Image Retry] Image generated successfully on attempt ${attemptNumber}`);
      return { success: true, base64Image, token: rotationToken };
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      console.error(`[Text-to-Image Retry] Attempt ${attemptNumber}:`, lastError);
      await handleTokenError(rotationToken?.id, error);
      if (isAuthenticationError(error)) {
        console.log(`[Text-to-Image Retry] Auth error - token ${rotationToken?.id} auto-disabled`);
        if (rotationToken) {
          disabledTokenIds.add(rotationToken.id);
        }
      }
      if (attemptNumber < maxRetries) {
        console.log(`[Text-to-Image Retry] Retrying in 500ms with different token...`);
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      if (!rotationToken && !process.env.GOOGLE_AI_API_KEY) {
        return { success: false, error: `No active API tokens available - all tokens may be disabled (Failed after ${maxRetries} attempts)` };
      }
      return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
    }
  }
  if (!rotationToken && !process.env.GOOGLE_AI_API_KEY) {
    return { success: false, error: `No active API tokens available - all tokens may be disabled (Failed after ${maxRetries} attempts)` };
  }
  return { success: false, error: `${lastError} (Failed after ${maxRetries} attempts)` };
}
async function registerRoutes(app2) {
  app2.get("/loaderio-34c6b917514b779ecc940b8a20a020fd.txt", (_req, res) => {
    res.type("text/plain");
    res.send("loaderio-34c6b917514b779ecc940b8a20a020fd");
  });
  app2.get("/loaderio-34c6b917514b779ecc940b8a20a020fd.html", (_req, res) => {
    res.type("text/html");
    res.send("loaderio-34c6b917514b779ecc940b8a20a020fd");
  });
  app2.get("/loaderio-34c6b917514b779ecc940b8a20a020fd/", (_req, res) => {
    res.type("text/plain");
    res.send("loaderio-34c6b917514b779ecc940b8a20a020fd");
  });
  function getClientIp(req) {
    let ip = "";
    const xForwardedFor = req.headers["x-forwarded-for"];
    if (xForwardedFor) {
      const ips = xForwardedFor.split(",");
      ip = ips[0].trim();
    } else {
      const xRealIp = req.headers["x-real-ip"];
      if (xRealIp) {
        ip = xRealIp;
      } else {
        ip = req.ip || req.connection?.remoteAddress || "unknown";
      }
    }
    ip = ip.replace(/^\[/, "").replace(/\]:\d+$/, "").replace(/:\d+$/, "");
    if (ip.startsWith("::ffff:")) {
      ip = ip.substring(7);
    }
    return ip.trim();
  }
  app2.post("/api/login", async (req, res) => {
    try {
      await new Promise((resolve) => setTimeout(resolve, 100 + Math.random() * 200));
      const validationResult = loginSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { username, password } = validationResult.data;
      const sanitizedUsername = username.trim().substring(0, 50);
      const user = await storage.getUserByUsername(sanitizedUsername);
      if (!user) {
        console.log(`[Security] Failed login attempt for non-existent user: ${sanitizedUsername}`);
        return res.status(401).json({ error: "Invalid username or password" });
      }
      const isPasswordValid = await storage.verifyPassword(user, password);
      if (!isPasswordValid) {
        console.log(`[Security] Failed login attempt for user: ${sanitizedUsername} - incorrect password`);
        return res.status(401).json({ error: "Invalid username or password" });
      }
      if (!user.isAccountActive) {
        console.log(`[Security] Login blocked - account deactivated: ${sanitizedUsername}`);
        return res.status(403).json({
          error: "Account deactivated. Please contact admin."
        });
      }
      const clientIp = getClientIp(req);
      if (user.isAdmin) {
        const twoFactorCode = req.body.twoFactorCode;
        if (user.twoFactorEnabled && user.twoFactorSecret) {
          if (!twoFactorCode) {
            console.log(`[Security] 2FA code required for admin: ${sanitizedUsername}`);
            return res.status(200).json({
              requires2FA: true,
              message: "Please enter your 2FA code"
            });
          }
          const isValid2FA = authenticator.check(twoFactorCode, user.twoFactorSecret);
          if (!isValid2FA) {
            console.log(`[Security] Invalid 2FA code for admin: ${sanitizedUsername}`);
            return res.status(401).json({ error: "Invalid 2FA code" });
          }
          console.log(`[Security] 2FA verified for admin: ${sanitizedUsername}`);
        } else {
          console.log(`[Security] Admin ${sanitizedUsername} needs to setup 2FA`);
          const tempSecret = authenticator.generateSecret();
          req.session.pending2FASetup = {
            userId: user.id,
            secret: tempSecret
          };
          await new Promise((resolve, reject) => {
            req.session.save((err) => {
              if (err) reject(err);
              else resolve();
            });
          });
          const otpauthUrl = authenticator.keyuri(user.username, "VeoVideoGenerator", tempSecret);
          const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
          return res.status(200).json({
            requires2FASetup: true,
            secret: tempSecret,
            qrCode: qrCodeDataUrl,
            message: "Please scan the QR code with your authenticator app and enter the code to complete setup"
          });
        }
      }
      console.log(`[Security] Successful login: ${sanitizedUsername} from IP: ${clientIp}`);
      req.session.regenerate((err) => {
        if (err) {
          console.error("[Security] Session regeneration failed:", err);
          return res.status(500).json({ error: "Login failed" });
        }
        req.session.userId = user.id;
        req.session.save((saveErr) => {
          if (saveErr) {
            console.error("[Security] Session save failed:", saveErr);
            return res.status(500).json({ error: "Login failed" });
          }
          res.json({
            success: true,
            user: {
              id: user.id,
              username: user.username,
              isAdmin: user.isAdmin
            }
          });
        });
      });
    } catch (error) {
      console.error("Error in /api/login:", error);
      res.status(500).json({ error: "Login failed" });
    }
  });
  app2.post("/api/2fa/verify-setup", async (req, res) => {
    try {
      const { code, username, password } = req.body;
      if (!code || !username || !password) {
        return res.status(400).json({ error: "Code, username and password are required" });
      }
      const user = await storage.getUserByUsername(username.trim());
      if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      const isPasswordValid = await storage.verifyPassword(user, password);
      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      const pending2FA = req.session.pending2FASetup;
      if (!pending2FA || pending2FA.userId !== user.id) {
        return res.status(400).json({ error: "No pending 2FA setup found. Please start login again." });
      }
      const isValid = authenticator.check(code, pending2FA.secret);
      if (!isValid) {
        return res.status(401).json({ error: "Invalid verification code" });
      }
      await db.execute(sql3`
        UPDATE users 
        SET two_factor_secret = ${pending2FA.secret}, 
            two_factor_enabled = true 
        WHERE id = ${user.id}
      `);
      delete req.session.pending2FASetup;
      console.log(`[Security] 2FA enabled for admin: ${user.username}`);
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).json({ error: "Login failed" });
        }
        req.session.userId = user.id;
        req.session.save((saveErr) => {
          if (saveErr) {
            return res.status(500).json({ error: "Login failed" });
          }
          res.json({
            success: true,
            message: "2FA enabled successfully",
            user: {
              id: user.id,
              username: user.username,
              isAdmin: user.isAdmin
            }
          });
        });
      });
    } catch (error) {
      console.error("Error in /api/2fa/verify-setup:", error);
      res.status(500).json({ error: "2FA setup failed" });
    }
  });
  app2.post("/api/2fa/disable", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { code } = req.body;
      const user = await storage.getUser(req.session.userId);
      if (!user || !user.twoFactorSecret) {
        return res.status(400).json({ error: "2FA is not enabled" });
      }
      const isValid = authenticator.check(code, user.twoFactorSecret);
      if (!isValid) {
        return res.status(401).json({ error: "Invalid 2FA code" });
      }
      await db.execute(sql3`
        UPDATE users 
        SET two_factor_secret = NULL, 
            two_factor_enabled = false 
        WHERE id = ${user.id}
      `);
      console.log(`[Security] 2FA disabled for admin: ${user.username}`);
      res.json({ success: true, message: "2FA disabled" });
    } catch (error) {
      console.error("Error disabling 2FA:", error);
      res.status(500).json({ error: "Failed to disable 2FA" });
    }
  });
  app2.post("/api/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: "Logout failed" });
      }
      res.json({ success: true });
    });
  });
  app2.get("/api/session", async (req, res) => {
    if (!req.session.userId) {
      return res.json({ authenticated: false });
    }
    const user = await storage.getUser(req.session.userId);
    if (!user) {
      req.session.userId = void 0;
      return res.json({ authenticated: false });
    }
    res.json({
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        planType: user.planType,
        planStatus: user.planStatus,
        planExpiry: user.planExpiry,
        dailyVideoCount: user.dailyVideoCount
      }
    });
  });
  app2.get("/api/user/me", requireAuth, async (req, res) => {
    try {
      const user = await storage.getUser(req.session.userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        planType: user.planType,
        planStatus: user.planStatus,
        planExpiry: user.planExpiry,
        planStartDate: user.planStartDate,
        dailyVideoCount: user.dailyVideoCount,
        dailyResetDate: user.dailyResetDate
      });
    } catch (error) {
      console.error("Error in GET /api/user/me:", error);
      res.status(500).json({ error: "Failed to fetch user details" });
    }
  });
  app2.get("/api/user/voice-usage", requireAuth, async (req, res) => {
    try {
      const user = await storage.checkAndResetVoiceCharacters(req.session.userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const usage = getVoiceCharacterUsage(user);
      res.json({
        used: usage.used,
        limit: usage.limit,
        remaining: usage.remaining,
        resetDate: usage.resetDate,
        resetDays: usage.resetDays,
        planType: user.planType,
        isAdmin: user.isAdmin
      });
    } catch (error) {
      console.error("Error in GET /api/user/voice-usage:", error);
      res.status(500).json({ error: "Failed to fetch voice usage" });
    }
  });
  app2.get("/api/users", requireAdmin, async (req, res) => {
    try {
      const [users2, videoStatsMap] = await Promise.all([
        storage.getAllUsers(),
        storage.getAllUsersVideoStats()
      ]);
      const usersWithStats = users2.map((user) => {
        const videoStats = videoStatsMap.get(user.id) || {
          completed: 0,
          failed: 0,
          pending: 0,
          total: 0
        };
        return {
          id: user.id,
          username: user.username,
          isAdmin: user.isAdmin,
          planType: user.planType,
          planStatus: user.planStatus,
          planExpiry: user.planExpiry,
          apiToken: user.apiToken,
          allowedIp1: user.allowedIp1,
          allowedIp2: user.allowedIp2,
          isAccountActive: user.isAccountActive,
          dailyVideoLimit: user.dailyVideoLimit,
          bulkMaxBatch: user.bulkMaxBatch,
          bulkDelaySeconds: user.bulkDelaySeconds,
          bulkMaxPrompts: user.bulkMaxPrompts,
          videoStats
        };
      });
      res.json({ users: usersWithStats });
    } catch (error) {
      console.error("Error in GET /api/users:", error);
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });
  app2.post("/api/users", requireAdmin, async (req, res) => {
    try {
      const validationResult = insertUserSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { username, password, isAdmin, planType, dailyVideoLimit, expiryDays, bulkMaxBatch, bulkDelaySeconds, bulkMaxPrompts } = validationResult.data;
      const existingUser = await storage.getUserByUsername(username);
      if (existingUser) {
        return res.status(409).json({ error: "Username already exists" });
      }
      const newUser = await storage.createUser({
        username,
        password,
        isAdmin,
        planType,
        dailyVideoLimit,
        expiryDays,
        bulkMaxBatch,
        bulkDelaySeconds,
        bulkMaxPrompts
      });
      res.json({
        success: true,
        user: {
          id: newUser.id,
          username: newUser.username,
          isAdmin: newUser.isAdmin,
          planType: newUser.planType,
          planStatus: newUser.planStatus,
          planExpiry: newUser.planExpiry
        }
      });
    } catch (error) {
      console.error("Error in /api/users:", error);
      res.status(500).json({ error: "Failed to create user" });
    }
  });
  app2.patch("/api/users/:id/plan", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const validationResult = updateUserPlanSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const updatedUser = await storage.updateUserPlan(id, validationResult.data);
      if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({
        success: true,
        user: {
          id: updatedUser.id,
          username: updatedUser.username,
          isAdmin: updatedUser.isAdmin,
          planType: updatedUser.planType,
          planStatus: updatedUser.planStatus,
          planExpiry: updatedUser.planExpiry,
          apiToken: updatedUser.apiToken
        }
      });
    } catch (error) {
      console.error("Error in PATCH /api/users/:id/plan:", error);
      res.status(500).json({ error: "Failed to update user plan" });
    }
  });
  app2.patch("/api/users/:id/token", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const validationResult = updateUserApiTokenSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const updatedUser = await storage.updateUserApiToken(id, validationResult.data);
      if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({
        success: true,
        user: {
          id: updatedUser.id,
          username: updatedUser.username,
          isAdmin: updatedUser.isAdmin,
          planType: updatedUser.planType,
          planStatus: updatedUser.planStatus,
          planExpiry: updatedUser.planExpiry,
          apiToken: updatedUser.apiToken
        }
      });
    } catch (error) {
      console.error("Error in PATCH /api/users/:id/token:", error);
      res.status(500).json({ error: "Failed to update user API token" });
    }
  });
  app2.delete("/api/users/:id", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      if (id === req.session.userId) {
        return res.status(400).json({ error: "Cannot delete your own account" });
      }
      await storage.deleteUser(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error in DELETE /api/users/:id:", error);
      res.status(500).json({ error: "Failed to delete user" });
    }
  });
  app2.post("/api/users/:id/reactivate", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const updatedUser = await storage.reactivateUserAccount(id);
      if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({
        success: true,
        message: "User account reactivated and IP restrictions reset",
        user: {
          id: updatedUser.id,
          username: updatedUser.username,
          isAccountActive: updatedUser.isAccountActive,
          allowedIp1: updatedUser.allowedIp1,
          allowedIp2: updatedUser.allowedIp2
        }
      });
    } catch (error) {
      console.error("Error in POST /api/users/:id/reactivate:", error);
      res.status(500).json({ error: "Failed to reactivate user account" });
    }
  });
  app2.post("/api/admin/extend-all-expiry", requireAdmin, async (req, res) => {
    try {
      const { days } = req.body;
      if (days === void 0 || days === null || typeof days !== "number" || days === 0) {
        return res.status(400).json({ error: "Days must be a non-zero number" });
      }
      const action = days > 0 ? "Extended" : "Reduced";
      const dayCount = Math.abs(days);
      console.log(`[Admin] ${action} all users' expiry by ${dayCount} day(s)`);
      const updatedCount = await storage.extendAllUsersExpiry(days);
      res.json({
        success: true,
        message: `${action} expiry for ${updatedCount} users by ${dayCount} day(s)`,
        updatedCount
      });
    } catch (error) {
      console.error("Error in POST /api/admin/extend-all-expiry:", error);
      res.status(500).json({ error: "Failed to update users' expiry" });
    }
  });
  app2.post("/api/users/:id/reset-video-count", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const user = await storage.getUser(id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      await storage.resetDailyVideoCount(id);
      res.json({
        success: true,
        message: "Daily video count has been reset to 0"
      });
    } catch (error) {
      console.error("Error in POST /api/users/:id/reset-video-count:", error);
      res.status(500).json({ error: "Failed to reset daily video count" });
    }
  });
  app2.post("/api/admin/clear-user-data/:userId", requireAdmin, async (req, res) => {
    try {
      const { userId } = req.params;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      console.log(`[Admin] Clearing data for user ${user.username} (${userId})`);
      const allVideos = await storage.getUserVideoHistory(userId);
      const videosToDelete = allVideos.filter((video) => video.status !== "completed");
      console.log(`[Admin] Found ${videosToDelete.length} non-completed videos to delete for ${user.username}`);
      let deletedCount = 0;
      for (const video of videosToDelete) {
        try {
          await storage.deleteVideoHistoryById(video.id);
          deletedCount++;
        } catch (err) {
          console.error(`[Admin] Failed to delete video ${video.id}:`, err);
        }
      }
      await storage.resetDailyVideoCount(userId);
      console.log(`[Admin] Successfully deleted ${deletedCount} videos for ${user.username}`);
      res.json({
        success: true,
        deletedCount,
        message: `Deleted ${deletedCount} non-completed videos. Completed videos preserved.`
      });
    } catch (error) {
      console.error("Error in POST /api/admin/clear-user-data:", error);
      res.status(500).json({ error: "Failed to clear user data" });
    }
  });
  app2.post("/api/admin/clear-pending-videos/:userId", requireAdmin, async (req, res) => {
    try {
      const { userId } = req.params;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      console.log(`[Admin] Clearing PENDING videos for user ${user.username} (${userId})`);
      try {
        stopAllProcessing(userId);
        console.log(`[Admin] Stopped bulk queue for user ${user.username}`);
      } catch (err) {
        console.error(`[Admin] Failed to stop bulk queue:`, err);
      }
      const allVideos = await db.select().from(videoHistory).where(
        and3(
          eq3(videoHistory.userId, userId),
          or(
            eq3(videoHistory.status, "pending"),
            eq3(videoHistory.status, "generating"),
            eq3(videoHistory.status, "queued"),
            eq3(videoHistory.status, "retrying"),
            eq3(videoHistory.status, "initializing")
          )
        )
      );
      console.log(`[Admin] Found ${allVideos.length} pending/in-progress videos to delete for ${user.username}`);
      let deletedCount = 0;
      for (const video of allVideos) {
        try {
          await storage.deleteVideoHistoryById(video.id);
          deletedCount++;
        } catch (err) {
          console.error(`[Admin] Failed to delete pending video ${video.id}:`, err);
        }
      }
      console.log(`[Admin] Successfully deleted ${deletedCount} pending videos for ${user.username}`);
      res.json({
        success: true,
        deletedCount,
        message: `Deleted ${deletedCount} pending/in-progress videos for ${user.username}.`
      });
    } catch (error) {
      console.error("Error in POST /api/admin/clear-pending-videos:", error);
      res.status(500).json({ error: "Failed to clear pending videos" });
    }
  });
  app2.post("/api/admin/force-reset-queue/:userId", requireAdmin, async (req, res) => {
    try {
      const { userId } = req.params;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      console.log(`[Admin] Force resetting bulk queue for user ${user.username} (${userId})`);
      const { forceResetQueue: forceResetQueue2 } = await Promise.resolve().then(() => (init_bulkQueue(), bulkQueue_exports));
      const result = forceResetQueue2(userId);
      console.log(`[Admin] Force reset complete for ${user.username}:`, result);
      res.json({
        success: true,
        ...result,
        username: user.username
      });
    } catch (error) {
      console.error("Error in POST /api/admin/force-reset-queue:", error);
      res.status(500).json({ error: "Failed to force reset queue" });
    }
  });
  app2.delete("/api/users/:id/plan", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const updatedUser = await storage.removePlan(id);
      if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({
        success: true,
        user: {
          id: updatedUser.id,
          username: updatedUser.username,
          isAdmin: updatedUser.isAdmin,
          planType: updatedUser.planType,
          planStatus: updatedUser.planStatus,
          planExpiry: updatedUser.planExpiry,
          apiToken: updatedUser.apiToken
        }
      });
    } catch (error) {
      console.error("Error in DELETE /api/users/:id/plan:", error);
      res.status(500).json({ error: "Failed to remove user plan" });
    }
  });
  app2.get("/api/tokens", requireAdmin, async (req, res) => {
    try {
      const tokens = await storage.getAllApiTokens();
      res.json({ tokens });
    } catch (error) {
      console.error("Error in GET /api/tokens:", error);
      res.status(500).json({ error: "Failed to fetch API tokens" });
    }
  });
  app2.post("/api/tokens", requireAdmin, async (req, res) => {
    try {
      const validationResult = insertApiTokenSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const newToken = await storage.addApiToken(validationResult.data);
      res.json({ success: true, token: newToken });
    } catch (error) {
      console.error("Error in POST /api/tokens:", error);
      res.status(500).json({ error: "Failed to add API token" });
    }
  });
  app2.delete("/api/tokens/:id", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteApiToken(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error in DELETE /api/tokens/:id:", error);
      res.status(500).json({ error: "Failed to delete API token" });
    }
  });
  app2.patch("/api/tokens/:id/toggle", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;
      const updatedToken = await storage.toggleApiTokenStatus(id, isActive);
      if (!updatedToken) {
        return res.status(404).json({ error: "Token not found" });
      }
      res.json({ success: true, token: updatedToken });
    } catch (error) {
      console.error("Error in PATCH /api/tokens/:id/toggle:", error);
      res.status(500).json({ error: "Failed to update token status" });
    }
  });
  app2.get("/api/token-settings", requireAdmin, async (req, res) => {
    try {
      const settings = await storage.getTokenSettings();
      res.json({ settings });
    } catch (error) {
      console.error("Error in GET /api/token-settings:", error);
      res.status(500).json({ error: "Failed to fetch token settings" });
    }
  });
  app2.put("/api/token-settings", requireAdmin, async (req, res) => {
    try {
      const validationResult = updateTokenSettingsSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const updatedSettings = await storage.updateTokenSettings(validationResult.data);
      res.json({ success: true, settings: updatedSettings });
    } catch (error) {
      console.error("Error in PUT /api/token-settings:", error);
      res.status(500).json({ error: "Failed to update token settings" });
    }
  });
  app2.get("/api/plan-availability", async (req, res) => {
    try {
      const availability = await storage.getPlanAvailability();
      res.json({ availability });
    } catch (error) {
      console.error("Error in GET /api/plan-availability:", error);
      res.status(500).json({ error: "Failed to fetch plan availability" });
    }
  });
  app2.put("/api/plan-availability", requireAdmin, async (req, res) => {
    try {
      const { updatePlanAvailabilitySchema: updatePlanAvailabilitySchema2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const validationResult = updatePlanAvailabilitySchema2.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const updatedAvailability = await storage.updatePlanAvailability(validationResult.data);
      res.json({ success: true, availability: updatedAvailability });
    } catch (error) {
      console.error("Error in PUT /api/plan-availability:", error);
      res.status(500).json({ error: "Failed to update plan availability" });
    }
  });
  app2.get("/api/pricing-plans", async (req, res) => {
    try {
      const plans = await storage.getActivePricingPlans();
      res.json({ plans });
    } catch (error) {
      console.error("Error in GET /api/pricing-plans:", error);
      res.status(500).json({ error: "Failed to fetch pricing plans" });
    }
  });
  app2.get("/api/admin/pricing-plans", requireAuth, requireAdmin, async (req, res) => {
    try {
      const plans = await storage.getAllPricingPlans();
      res.json({ plans });
    } catch (error) {
      console.error("Error in GET /api/admin/pricing-plans:", error);
      res.status(500).json({ error: "Failed to fetch pricing plans" });
    }
  });
  app2.post("/api/admin/pricing-plans", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { insertPricingPlanSchema: insertPricingPlanSchema2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const validationResult = insertPricingPlanSchema2.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const newPlan = await storage.createPricingPlan(validationResult.data);
      res.json({ success: true, plan: newPlan });
    } catch (error) {
      console.error("Error in POST /api/admin/pricing-plans:", error);
      res.status(500).json({ error: "Failed to create pricing plan" });
    }
  });
  app2.patch("/api/admin/pricing-plans/:planId", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { planId } = req.params;
      const { updatePricingPlanSchema: updatePricingPlanSchema2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const validationResult = updatePricingPlanSchema2.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const updatedPlan = await storage.updatePricingPlan(planId, validationResult.data);
      if (!updatedPlan) {
        return res.status(404).json({ error: "Plan not found" });
      }
      res.json({ success: true, plan: updatedPlan });
    } catch (error) {
      console.error("Error in PATCH /api/admin/pricing-plans:", error);
      res.status(500).json({ error: "Failed to update pricing plan" });
    }
  });
  app2.delete("/api/admin/pricing-plans/:planId", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { planId } = req.params;
      await storage.deletePricingPlan(planId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error in DELETE /api/admin/pricing-plans:", error);
      res.status(500).json({ error: "Failed to delete pricing plan" });
    }
  });
  app2.post("/api/admin/pricing-plans/reorder", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { planIds } = req.body;
      if (!Array.isArray(planIds)) {
        return res.status(400).json({ error: "planIds must be an array" });
      }
      await storage.reorderPricingPlans(planIds);
      res.json({ success: true });
    } catch (error) {
      console.error("Error in POST /api/admin/pricing-plans/reorder:", error);
      res.status(500).json({ error: "Failed to reorder pricing plans" });
    }
  });
  app2.get("/api/app-settings", async (req, res) => {
    try {
      const settings = await storage.getAppSettings();
      if (!settings) {
        return res.status(404).json({ error: "Settings not found" });
      }
      const publicSettings = {
        id: settings.id,
        whatsappUrl: settings.whatsappUrl,
        enableVideoMerge: settings.enableVideoMerge,
        logoUrl: settings.logoUrl,
        updatedAt: settings.updatedAt
      };
      res.json({ settings: publicSettings });
    } catch (error) {
      console.error("Error in GET /api/app-settings:", error);
      res.status(500).json({ error: "Failed to fetch app settings" });
    }
  });
  app2.get("/api/logo", async (req, res) => {
    try {
      const settings = await storage.getAppSettings();
      const logoUrl = settings?.logoUrl || "/veo3-logo.png";
      res.json({ logoUrl });
    } catch (error) {
      console.error("Error in GET /api/logo:", error);
      res.json({ logoUrl: "/veo3-logo.png" });
    }
  });
  app2.get("/api/video-preview/:videoId", async (req, res) => {
    try {
      const { videoId } = req.params;
      let buffer = getVideoBuffer(videoId);
      if (!buffer) {
        buffer = getVideoBufferFromBulk(videoId);
      }
      if (!buffer) {
        const { getDirectVideo: getDirectVideo2 } = await Promise.resolve().then(() => (init_bulkQueueFlow(), bulkQueueFlow_exports));
        const base64 = await getDirectVideo2(videoId);
        if (base64) {
          buffer = Buffer.from(base64, "base64");
        }
      }
      if (!buffer) {
        return res.status(404).json({ error: "Video not found or expired" });
      }
      res.setHeader("Content-Type", "video/mp4");
      res.setHeader("Content-Length", buffer.length);
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
      res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
      res.setHeader("Accept-Ranges", "bytes");
      res.send(buffer);
    } catch (error) {
      console.error("Error streaming video:", error);
      res.status(500).json({ error: "Failed to stream video" });
    }
  });
  app2.get("/api/local-video/:videoId", async (req, res) => {
    try {
      const { videoId } = req.params;
      const { getVideoStream: getVideoStream2, getVideoMetadata: getVideoMetadata2, videoExists: videoExists2, getVideoPath: getVideoPath2 } = await Promise.resolve().then(() => (init_localDiskStorage(), localDiskStorage_exports));
      const fs5 = await import("fs");
      if (!videoExists2(videoId)) {
        return res.status(404).json({ error: "Video not found or expired" });
      }
      const metadata = getVideoMetadata2(videoId);
      if (!metadata) {
        return res.status(404).json({ error: "Video not found" });
      }
      const videoPath = getVideoPath2(videoId);
      if (!videoPath) {
        return res.status(404).json({ error: "Video file not found" });
      }
      const fileSize = metadata.sizeBytes;
      const etag = `"${videoId}-${fileSize}"`;
      if (req.headers["if-none-match"] === etag) {
        return res.status(304).end();
      }
      res.setHeader("ETag", etag);
      res.setHeader("Cache-Control", "public, max-age=3600");
      res.setHeader("Accept-Ranges", "bytes");
      res.setHeader("Content-Type", "video/mp4");
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
      res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Range");
      const range = req.headers.range;
      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunkSize = end - start + 1;
        res.status(206);
        res.setHeader("Content-Range", `bytes ${start}-${end}/${fileSize}`);
        res.setHeader("Content-Length", chunkSize);
        const stream = fs5.createReadStream(videoPath, { start, end });
        stream.pipe(res);
      } else {
        res.setHeader("Content-Length", fileSize);
        const stream = getVideoStream2(videoId);
        if (!stream) {
          return res.status(404).json({ error: "Video stream failed" });
        }
        stream.pipe(res);
      }
    } catch (error) {
      console.error("Error streaming local video:", error);
      res.status(500).json({ error: "Failed to stream video" });
    }
  });
  app2.get("/api/admin/local-storage-stats", requireAdmin, async (req, res) => {
    try {
      const { getStorageStats: getStorageStats2, listAllVideos: listAllVideos2 } = await Promise.resolve().then(() => (init_localDiskStorage(), localDiskStorage_exports));
      const stats = await getStorageStats2();
      const videos = listAllVideos2();
      res.json({
        stats,
        recentVideos: videos.slice(0, 20).map((v) => ({
          id: v.id,
          createdAt: new Date(v.createdAt).toISOString(),
          expiresAt: new Date(v.expiresAt).toISOString(),
          sizeMB: Math.round(v.sizeBytes / 1024 / 1024 * 10) / 10,
          userId: v.userId
        }))
      });
    } catch (error) {
      console.error("Error getting local storage stats:", error);
      res.status(500).json({ error: "Failed to get storage stats" });
    }
  });
  app2.post("/api/admin/local-storage-cleanup", requireAdmin, async (req, res) => {
    try {
      const { cleanupExpiredVideos: cleanupExpiredVideos2 } = await Promise.resolve().then(() => (init_localDiskStorage(), localDiskStorage_exports));
      const deletedCount = await cleanupExpiredVideos2();
      res.json({ success: true, deletedCount });
    } catch (error) {
      console.error("Error during local storage cleanup:", error);
      res.status(500).json({ error: "Cleanup failed" });
    }
  });
  app2.get("/api/stats", async (req, res) => {
    try {
      const totalVideos = await storage.getTotalVideosGenerated();
      res.json({ totalVideosGenerated: totalVideos });
    } catch (error) {
      console.error("Error in GET /api/stats:", error);
      res.json({ totalVideosGenerated: 0 });
    }
  });
  app2.get("/api/admin/app-settings", requireAdmin, async (req, res) => {
    try {
      const settings = await storage.getAppSettings();
      res.json({ settings });
    } catch (error) {
      console.error("Error in GET /api/admin/app-settings:", error);
      res.status(500).json({ error: "Failed to fetch app settings" });
    }
  });
  app2.put("/api/app-settings", requireAdmin, async (req, res) => {
    try {
      const { updateAppSettingsSchema: updateAppSettingsSchema2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const validationResult = updateAppSettingsSchema2.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const updatedSettings = await storage.updateAppSettings(validationResult.data);
      res.json({ success: true, settings: updatedSettings });
    } catch (error) {
      console.error("Error in PUT /api/app-settings:", error);
      res.status(500).json({ error: "Failed to update app settings" });
    }
  });
  app2.get("/api/tool-maintenance", async (req, res) => {
    try {
      const maintenance = await storage.getToolMaintenance();
      res.json({ maintenance });
    } catch (error) {
      console.error("Error in GET /api/tool-maintenance:", error);
      res.status(500).json({ error: "Failed to fetch tool maintenance status" });
    }
  });
  app2.put("/api/tool-maintenance", requireAdmin, async (req, res) => {
    try {
      const { updateToolMaintenanceSchema: updateToolMaintenanceSchema2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const validationResult = updateToolMaintenanceSchema2.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const updatedMaintenance = await storage.updateToolMaintenance(validationResult.data);
      res.json({ success: true, maintenance: updatedMaintenance });
    } catch (error) {
      console.error("Error in PUT /api/tool-maintenance:", error);
      res.status(500).json({ error: "Failed to update tool maintenance status" });
    }
  });
  app2.get("/api/admin/system-metrics", requireAdmin, async (req, res) => {
    try {
      const { getSystemMetrics: getSystemMetrics2 } = await Promise.resolve().then(() => (init_systemMetrics(), systemMetrics_exports));
      const metrics = await getSystemMetrics2();
      res.json(metrics);
    } catch (error) {
      console.error("Error fetching system metrics:", error);
      res.status(500).json({ error: "Failed to fetch system metrics" });
    }
  });
  app2.get("/api/admin/system-metrics/stream", requireAdmin, async (req, res) => {
    try {
      const { getSystemMetrics: getSystemMetrics2 } = await Promise.resolve().then(() => (init_systemMetrics(), systemMetrics_exports));
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.flushHeaders();
      try {
        const initialMetrics = await getSystemMetrics2();
        res.write(`data: ${JSON.stringify(initialMetrics)}

`);
      } catch (error) {
        console.error("Error sending initial metrics:", error);
      }
      const interval = setInterval(async () => {
        try {
          const metrics = await getSystemMetrics2();
          res.write(`data: ${JSON.stringify(metrics)}

`);
        } catch (error) {
          console.error("Error streaming metrics:", error);
          clearInterval(interval);
          res.end();
        }
      }, 3e3);
      const keepAlive = setInterval(() => {
        res.write(": keepalive\n\n");
      }, 15e3);
      req.on("close", () => {
        clearInterval(interval);
        clearInterval(keepAlive);
        console.log("SSE client disconnected from system metrics stream");
      });
    } catch (error) {
      console.error("Error in system metrics stream:", error);
      res.status(500).json({ error: "Failed to stream system metrics" });
    }
  });
  app2.post("/api/tokens/bulk-replace", requireAdmin, async (req, res) => {
    try {
      console.log("[Bulk Replace] Request body:", req.body);
      const validationResult = bulkReplaceTokensSchema.safeParse(req.body);
      if (!validationResult.success) {
        console.error("[Bulk Replace] Validation failed:", validationResult.error.errors);
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const tokensText = validationResult.data.tokens.trim();
      const tokenLines = tokensText.split("\n").map((line) => line.trim()).filter((line) => line.length > 0).map((line) => {
        return line.replace(/^Bearer\s+/i, "");
      });
      console.log("[Bulk Replace] Parsed token lines:", tokenLines.length);
      if (tokenLines.length === 0) {
        console.error("[Bulk Replace] No valid tokens found");
        return res.status(400).json({
          error: "No valid tokens found",
          details: ["Please enter at least one token"]
        });
      }
      console.log("[Bulk Replace] Calling storage.replaceAllTokens...");
      const newTokens = await storage.replaceAllTokens(tokenLines);
      console.log("[Bulk Replace] Successfully replaced tokens:", newTokens.length);
      res.json({ success: true, tokens: newTokens, count: newTokens.length });
    } catch (error) {
      console.error("[Bulk Replace] Error details:", error);
      console.error("[Bulk Replace] Error stack:", error instanceof Error ? error.stack : "No stack trace");
      res.status(500).json({
        error: "Failed to replace tokens",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/admin/credits", requireAdmin, async (req, res) => {
    try {
      const allTokens = await storage.getAllApiTokens();
      const activeTokens = allTokens.filter((t) => t.isActive);
      const perTokenSnapshots = await storage.getLatestCreditsSnapshotsPerToken();
      const totalCredits = perTokenSnapshots.reduce((sum, snapshot) => {
        const credits = snapshot.remainingCredits;
        return sum + (credits !== null && credits !== void 0 ? credits : 0);
      }, 0);
      const doFreshCheck = req.query.refresh === "true";
      let checkedToken = null;
      let latestSnapshot = null;
      if (doFreshCheck) {
        try {
          const token = await storage.getNextRotationToken();
          if (token) {
            checkedToken = token;
            const pingResult = await checkVideoStatus("test-ping", "test-scene", token.token);
            if (pingResult.remainingCredits !== void 0) {
              latestSnapshot = await storage.addCreditsSnapshot(
                pingResult.remainingCredits,
                "manual_check",
                token.id
              );
            }
          }
        } catch (error) {
          console.error("[Admin Credits] Fresh check failed:", error);
        }
      }
      const updatedPerTokenSnapshots = await storage.getLatestCreditsSnapshotsPerToken();
      const updatedTotalCredits = updatedPerTokenSnapshots.reduce((sum, snapshot) => {
        const credits = snapshot.remainingCredits;
        return sum + (credits !== null && credits !== void 0 ? credits : 0);
      }, 0);
      const recentSnapshots = await storage.getRecentCreditsSnapshots(20);
      const overallLatestSnapshot = await storage.getLatestCreditsSnapshot();
      const tokensWithDetails = updatedPerTokenSnapshots.length;
      res.json({
        totalCredits: updatedTotalCredits || totalCredits || 0,
        perTokenSnapshots: updatedPerTokenSnapshots,
        lastUpdated: latestSnapshot?.recordedAt || overallLatestSnapshot?.recordedAt || null,
        history: recentSnapshots,
        tokenInfo: {
          totalTokens: allTokens.length,
          activeTokens: activeTokens.length,
          tokensWithDetails,
          checkedTokenName: checkedToken?.label || null
        }
      });
    } catch (error) {
      console.error("Error fetching credits:", error);
      res.status(500).json({
        error: "Failed to fetch credits",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/admin/dashboard-stats", requireAuth, requireAdmin, async (req, res) => {
    try {
      const nowUtc = /* @__PURE__ */ new Date();
      const todayPrefix = nowUtc.toISOString().split("T")[0];
      const todayStatsQuery = await db.select({
        status: videoHistory.status,
        count: sql3`count(*)::int`
      }).from(videoHistory).where(sql3`DATE(${videoHistory.createdAt}) = ${todayPrefix}::date`).groupBy(videoHistory.status);
      const todayStats = {
        total: 0,
        completed: 0,
        failed: 0,
        pending: 0
      };
      todayStatsQuery.forEach((row) => {
        todayStats.total += row.count;
        if (row.status === "completed") todayStats.completed = row.count;
        if (row.status === "failed") todayStats.failed = row.count;
        if (row.status === "pending") todayStats.pending = row.count;
      });
      const tokenStatsQuery = await db.select({
        tokenUsed: videoHistory.tokenUsed,
        status: videoHistory.status,
        count: sql3`count(*)::int`
      }).from(videoHistory).where(sql3`${videoHistory.tokenUsed} IS NOT NULL`).groupBy(videoHistory.tokenUsed, videoHistory.status);
      const allTokens = await storage.getAllApiTokens();
      const tokenMap = new Map(allTokens.map((t) => [t.id, t.label]));
      const tokenStatsMap = /* @__PURE__ */ new Map();
      tokenStatsQuery.forEach((row) => {
        if (!row.tokenUsed) return;
        if (!tokenStatsMap.has(row.tokenUsed)) {
          tokenStatsMap.set(row.tokenUsed, {
            tokenId: row.tokenUsed,
            label: tokenMap.get(row.tokenUsed) || row.tokenUsed,
            total: 0,
            completed: 0,
            failed: 0
          });
        }
        const stats = tokenStatsMap.get(row.tokenUsed);
        stats.total += row.count;
        if (row.status === "completed") stats.completed = row.count;
        if (row.status === "failed") stats.failed = row.count;
      });
      const tokenStats = Array.from(tokenStatsMap.values()).sort((a, b) => b.total - a.total);
      res.json({
        todayStats,
        tokenStats
      });
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({
        error: "Failed to fetch dashboard stats",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/admin/messages", requireAuth, requireAdmin, async (req, res) => {
    try {
      const messages = await storage.getAllAdminMessages();
      res.json({ messages });
    } catch (error) {
      console.error("Error fetching admin messages:", error);
      res.status(500).json({ error: "Failed to fetch messages" });
    }
  });
  app2.post("/api/admin/messages", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { title, message } = req.body;
      if (!title || !message) {
        return res.status(400).json({ error: "Title and message are required" });
      }
      const newMessage = await storage.createAdminMessage(title, message);
      res.json({ message: newMessage });
    } catch (error) {
      console.error("Error creating admin message:", error);
      res.status(500).json({ error: "Failed to create message" });
    }
  });
  app2.put("/api/admin/messages/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { title, message, isActive } = req.body;
      if (!title || !message) {
        return res.status(400).json({ error: "Title and message are required" });
      }
      const updatedMessage = await storage.updateAdminMessage(id, title, message, isActive ?? true);
      if (!updatedMessage) {
        return res.status(404).json({ error: "Message not found" });
      }
      res.json({ message: updatedMessage });
    } catch (error) {
      console.error("Error updating admin message:", error);
      res.status(500).json({ error: "Failed to update message" });
    }
  });
  app2.patch("/api/admin/messages/:id/toggle", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;
      const updatedMessage = await storage.toggleAdminMessageStatus(id, isActive);
      if (!updatedMessage) {
        return res.status(404).json({ error: "Message not found" });
      }
      res.json({ message: updatedMessage });
    } catch (error) {
      console.error("Error toggling message status:", error);
      res.status(500).json({ error: "Failed to toggle message status" });
    }
  });
  app2.delete("/api/admin/messages/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteAdminMessage(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting admin message:", error);
      res.status(500).json({ error: "Failed to delete message" });
    }
  });
  app2.get("/api/messages", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const messages = await storage.getActiveAdminMessages();
      const readMessageIds = await storage.getUserReadMessageIds(userId);
      const messagesWithReadStatus = messages.map((msg) => ({
        ...msg,
        isRead: readMessageIds.includes(msg.id)
      }));
      res.json({ messages: messagesWithReadStatus });
    } catch (error) {
      console.error("Error fetching messages:", error);
      res.status(500).json({ error: "Failed to fetch messages" });
    }
  });
  app2.get("/api/messages/unread-count", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const count = await storage.getUnreadMessagesCount(userId);
      res.json({ count });
    } catch (error) {
      console.error("Error fetching unread count:", error);
      res.status(500).json({ error: "Failed to fetch unread count" });
    }
  });
  app2.post("/api/messages/:id/read", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const { id } = req.params;
      await storage.markMessageAsRead(userId, id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error marking message as read:", error);
      res.status(500).json({ error: "Failed to mark message as read" });
    }
  });
  app2.post("/api/messages/mark-all-read", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      await storage.markAllMessagesAsRead(userId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error marking all messages as read:", error);
      res.status(500).json({ error: "Failed to mark all messages as read" });
    }
  });
  app2.get("/api/admin/resellers", requireAuth, requireAdmin, async (req, res) => {
    try {
      const allResellers = await storage.getAllResellers();
      res.json({ resellers: allResellers });
    } catch (error) {
      console.error("Error fetching resellers:", error);
      res.status(500).json({ error: "Failed to fetch resellers" });
    }
  });
  app2.get("/api/admin/resellers/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const reseller = await storage.getResellerById(id);
      if (!reseller) {
        return res.status(404).json({ error: "Reseller not found" });
      }
      res.json({ reseller });
    } catch (error) {
      console.error("Error fetching reseller:", error);
      res.status(500).json({ error: "Failed to fetch reseller" });
    }
  });
  app2.post("/api/admin/resellers", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { username, password, creditBalance } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
      }
      const existingReseller = await storage.getResellerByUsername(username);
      if (existingReseller) {
        return res.status(400).json({ error: "Reseller username already exists" });
      }
      const existingUser = await storage.getUserByUsername(username);
      if (existingUser) {
        return res.status(400).json({ error: "Username already exists as a regular user" });
      }
      const reseller = await storage.createReseller({
        username,
        password,
        creditBalance: creditBalance || 0
      });
      res.json({ reseller });
    } catch (error) {
      console.error("Error creating reseller:", error);
      res.status(500).json({ error: "Failed to create reseller" });
    }
  });
  app2.post("/api/admin/resellers/:id/add-credits", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { amount, reason } = req.body;
      if (!amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: "Valid positive credit amount is required" });
      }
      const updatedReseller = await storage.updateResellerCredits(
        id,
        amount,
        reason || `Admin added ${amount} credits`
      );
      if (!updatedReseller) {
        return res.status(404).json({ error: "Reseller not found" });
      }
      res.json({ reseller: updatedReseller });
    } catch (error) {
      console.error("Error adding credits to reseller:", error);
      res.status(500).json({ error: "Failed to add credits" });
    }
  });
  app2.post("/api/admin/resellers/:id/remove-credits", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { amount, reason } = req.body;
      if (!amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: "Valid positive credit amount is required" });
      }
      const updatedReseller = await storage.updateResellerCredits(
        id,
        -amount,
        reason || `Admin removed ${amount} credits`
      );
      if (!updatedReseller) {
        return res.status(404).json({ error: "Reseller not found" });
      }
      res.json({ reseller: updatedReseller });
    } catch (error) {
      console.error("Error removing credits from reseller:", error);
      if (error.message === "Insufficient credits") {
        return res.status(400).json({ error: "Insufficient credits to remove" });
      }
      res.status(500).json({ error: "Failed to remove credits" });
    }
  });
  app2.patch("/api/admin/resellers/:id/toggle", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;
      const updatedReseller = await storage.toggleResellerStatus(id, isActive);
      if (!updatedReseller) {
        return res.status(404).json({ error: "Reseller not found" });
      }
      res.json({ reseller: updatedReseller });
    } catch (error) {
      console.error("Error toggling reseller status:", error);
      res.status(500).json({ error: "Failed to toggle reseller status" });
    }
  });
  app2.delete("/api/admin/resellers/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteReseller(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting reseller:", error);
      res.status(500).json({ error: "Failed to delete reseller" });
    }
  });
  app2.get("/api/admin/resellers/:id/ledger", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const ledger = await storage.getResellerCreditLedger(id);
      res.json({ ledger });
    } catch (error) {
      console.error("Error fetching reseller ledger:", error);
      res.status(500).json({ error: "Failed to fetch credit ledger" });
    }
  });
  app2.get("/api/admin/resellers/:id/users", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const users2 = await storage.getResellerUsers(id);
      res.json({ users: users2 });
    } catch (error) {
      console.error("Error fetching reseller users:", error);
      res.status(500).json({ error: "Failed to fetch reseller users" });
    }
  });
  app2.get("/api/admin/flow-cookies", requireAuth, requireAdmin, async (req, res) => {
    try {
      const cookies = await storage.getAllFlowCookies();
      res.json({ cookies });
    } catch (error) {
      console.error("Error fetching flow cookies:", error);
      res.status(500).json({ error: "Failed to fetch flow cookies" });
    }
  });
  app2.post("/api/admin/flow-cookies", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { label, cookieData } = req.body;
      if (!label || !cookieData) {
        return res.status(400).json({ error: "Label and cookie data are required" });
      }
      const cookie = await storage.addFlowCookie(label, cookieData);
      res.json({ cookie });
    } catch (error) {
      console.error("Error adding flow cookie:", error);
      res.status(500).json({ error: "Failed to add flow cookie" });
    }
  });
  app2.post("/api/admin/flow-cookies/bulk", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { cookies } = req.body;
      if (!cookies) {
        return res.status(400).json({ error: "Cookies data is required" });
      }
      const addedCookies = await storage.bulkAddFlowCookies(cookies);
      res.json({ cookies: addedCookies, count: addedCookies.length });
    } catch (error) {
      console.error("Error bulk adding flow cookies:", error);
      res.status(500).json({ error: "Failed to bulk add flow cookies" });
    }
  });
  app2.patch("/api/admin/flow-cookies/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      const cookie = await storage.updateFlowCookie(id, updates);
      if (!cookie) {
        return res.status(404).json({ error: "Flow cookie not found" });
      }
      res.json({ cookie });
    } catch (error) {
      console.error("Error updating flow cookie:", error);
      res.status(500).json({ error: "Failed to update flow cookie" });
    }
  });
  app2.patch("/api/admin/flow-cookies/:id/toggle", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;
      const cookie = await storage.toggleFlowCookieStatus(id, isActive);
      if (!cookie) {
        return res.status(404).json({ error: "Flow cookie not found" });
      }
      res.json({ cookie });
    } catch (error) {
      console.error("Error toggling flow cookie status:", error);
      res.status(500).json({ error: "Failed to toggle flow cookie status" });
    }
  });
  app2.delete("/api/admin/flow-cookies/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteFlowCookie(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting flow cookie:", error);
      res.status(500).json({ error: "Failed to delete flow cookie" });
    }
  });
  app2.delete("/api/admin/flow-cookies", requireAuth, requireAdmin, async (req, res) => {
    try {
      const count = await storage.deleteAllFlowCookies();
      res.json({ success: true, deletedCount: count });
    } catch (error) {
      console.error("Error deleting all flow cookies:", error);
      res.status(500).json({ error: "Failed to delete all flow cookies" });
    }
  });
  app2.get("/api/admin/zyphra-tokens", requireAuth, requireAdmin, async (req, res) => {
    try {
      const tokens = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports)).then((m) => m.getAllZyphraTokens());
      res.json({ tokens });
    } catch (error) {
      console.error("Error fetching Zyphra tokens:", error);
      res.status(500).json({ error: "Failed to fetch Zyphra tokens" });
    }
  });
  app2.post("/api/admin/zyphra-tokens", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { apiKey, label, minutesLimit } = req.body;
      if (!apiKey || !label) {
        return res.status(400).json({ error: "API key and label are required" });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const token = await zyphra.addZyphraToken(apiKey, label, minutesLimit || 100);
      res.json({ token: token[0] });
    } catch (error) {
      console.error("Error adding Zyphra token:", error);
      if (error.message?.includes("duplicate")) {
        return res.status(400).json({ error: "API key already exists" });
      }
      res.status(500).json({ error: "Failed to add Zyphra token" });
    }
  });
  app2.post("/api/admin/zyphra-tokens/bulk", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { tokens: tokensInput } = req.body;
      if (!tokensInput) {
        return res.status(400).json({ error: "Tokens are required" });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const lines = tokensInput.split("\n").filter((line) => line.trim());
      const added = [];
      const errors = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const parts = line.split(",").map((p) => p.trim());
        const apiKey = parts[0];
        const label = parts[1] || `Zyphra Key ${i + 1}`;
        const minutesLimit = parseInt(parts[2]) || 100;
        try {
          const token = await zyphra.addZyphraToken(apiKey, label, minutesLimit);
          added.push(token[0]);
        } catch (err) {
          errors.push(`Line ${i + 1}: ${err.message?.includes("duplicate") ? "Duplicate key" : "Failed to add"}`);
        }
      }
      res.json({ added, errors, totalAdded: added.length, totalErrors: errors.length });
    } catch (error) {
      console.error("Error bulk adding Zyphra tokens:", error);
      res.status(500).json({ error: "Failed to bulk add Zyphra tokens" });
    }
  });
  app2.patch("/api/admin/zyphra-tokens/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const token = await zyphra.updateZyphraToken(id, updates);
      if (token.length === 0) {
        return res.status(404).json({ error: "Token not found" });
      }
      res.json({ token: token[0] });
    } catch (error) {
      console.error("Error updating Zyphra token:", error);
      res.status(500).json({ error: "Failed to update Zyphra token" });
    }
  });
  app2.delete("/api/admin/zyphra-tokens/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      await zyphra.deleteZyphraToken(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting Zyphra token:", error);
      res.status(500).json({ error: "Failed to delete Zyphra token" });
    }
  });
  app2.post("/api/admin/zyphra-tokens/reset-usage", requireAuth, requireAdmin, async (req, res) => {
    try {
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      await zyphra.resetAllTokenUsage();
      res.json({ success: true });
    } catch (error) {
      console.error("Error resetting Zyphra token usage:", error);
      res.status(500).json({ error: "Failed to reset token usage" });
    }
  });
  app2.post("/api/admin/zyphra-tokens/:id/reset", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      await zyphra.resetTokenUsage(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error resetting Zyphra token usage:", error);
      res.status(500).json({ error: "Failed to reset token usage" });
    }
  });
  app2.post("/api/admin/zyphra/tts", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { text: text2, speakingRate, model, languageIsoCode, mimeType, emotion, pitchStd, defaultVoiceName } = req.body;
      if (!text2 || text2.trim().length === 0) {
        return res.status(400).json({ error: "Text is required" });
      }
      if (text2.length > 1e4) {
        return res.status(400).json({ error: "Text exceeds 10,000 character limit" });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const result = await zyphra.generateSpeechWithRetry({
        text: text2,
        speakingRate,
        model,
        languageIsoCode,
        mimeType: mimeType || "audio/wav",
        emotion,
        pitchStd,
        defaultVoiceName
      });
      if (!result.success) {
        return res.status(500).json({ error: result.error });
      }
      const audioId = crypto3.randomUUID();
      audioCache.set(audioId, {
        buffer: result.audioData,
        mimeType: result.mimeType || "audio/wav",
        timestamp: Date.now(),
        userId: req.session.userId
        // Admin-generated audio
      });
      let tokenRemaining = 0;
      let tokenLabel = "";
      if (result.tokenId) {
        const tokens = await zyphra.getAllZyphraTokens();
        const usedToken = tokens.find((t) => t.id === result.tokenId);
        if (usedToken) {
          tokenRemaining = Math.max(0, usedToken.minutesLimit - usedToken.minutesUsed);
          tokenLabel = usedToken.label;
        }
      }
      res.json({
        success: true,
        audioId,
        mimeType: result.mimeType,
        minutesUsed: result.minutesUsed,
        tokenRemaining,
        tokenLabel
      });
    } catch (error) {
      console.error("Error generating speech:", error);
      res.status(500).json({ error: "Failed to generate speech" });
    }
  });
  app2.get("/api/admin/zyphra/audio/:audioId", requireAuth, requireAdmin, (req, res) => {
    const { audioId } = req.params;
    const cached = audioCache.get(audioId);
    if (!cached) {
      return res.status(404).json({ error: "Audio not found or expired" });
    }
    res.setHeader("Content-Type", cached.mimeType);
    res.setHeader("Content-Length", cached.buffer.length);
    res.setHeader("Cache-Control", "no-cache");
    res.send(cached.buffer);
  });
  app2.post("/api/admin/zyphra/clone-voice", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { text: text2, referenceAudioBase64, speakingRate, languageIsoCode, mimeType, model } = req.body;
      if (!text2 || text2.trim().length === 0) {
        return res.status(400).json({ error: "Text is required" });
      }
      if (text2.length > 1e4) {
        return res.status(400).json({ error: "Text exceeds 10,000 character limit" });
      }
      if (!referenceAudioBase64) {
        return res.status(400).json({ error: "Reference audio is required for voice cloning" });
      }
      const maxBase64Size = 10 * 1024 * 1024 * 1.33;
      if (referenceAudioBase64.length > maxBase64Size) {
        return res.status(400).json({ error: "Reference audio file exceeds 10MB limit" });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const result = await zyphra.cloneVoiceWithRetry(text2, referenceAudioBase64, {
        speakingRate,
        languageIsoCode,
        mimeType: mimeType || "audio/wav",
        model
      });
      if (!result.success) {
        return res.status(500).json({ error: result.error });
      }
      const audioId = crypto3.randomUUID();
      audioCache.set(audioId, {
        buffer: result.audioData,
        mimeType: result.mimeType || "audio/wav",
        timestamp: Date.now(),
        userId: req.session.userId
        // Admin-generated audio
      });
      let tokenRemaining = 0;
      let tokenLabel = "";
      if (result.tokenId) {
        const tokens = await zyphra.getAllZyphraTokens();
        const usedToken = tokens.find((t) => t.id === result.tokenId);
        if (usedToken) {
          tokenRemaining = Math.max(0, usedToken.minutesLimit - usedToken.minutesUsed);
          tokenLabel = usedToken.label;
        }
      }
      res.json({
        success: true,
        audioId,
        mimeType: result.mimeType,
        minutesUsed: result.minutesUsed,
        tokenRemaining,
        tokenLabel
      });
    } catch (error) {
      console.error("Error cloning voice:", error);
      res.status(500).json({ error: "Failed to clone voice" });
    }
  });
  app2.get("/api/admin/zyphra/voices", requireAuth, requireAdmin, async (req, res) => {
    try {
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      res.json({
        voices: zyphra.DEFAULT_VOICES,
        languages: zyphra.SUPPORTED_LANGUAGES
      });
    } catch (error) {
      console.error("Error fetching voices:", error);
      res.status(500).json({ error: "Failed to fetch voices" });
    }
  });
  app2.get("/api/zyphra/voices", requireAuth, async (req, res) => {
    try {
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      res.json({
        voices: zyphra.DEFAULT_VOICES,
        languages: zyphra.SUPPORTED_LANGUAGES
      });
    } catch (error) {
      console.error("Error fetching voices:", error);
      res.status(500).json({ error: "Failed to fetch voices" });
    }
  });
  app2.post("/api/zyphra/tts", requireAuth, async (req, res) => {
    try {
      const freshUser = await storage.checkAndResetVoiceCharacters(req.session.userId);
      if (!freshUser) {
        return res.status(401).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(freshUser, "voiceTools");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const { text: text2, speakingRate, languageIsoCode, defaultVoiceName } = req.body;
      if (!text2) {
        return res.status(400).json({ error: "Text is required" });
      }
      if (text2.length > 5e3 && !freshUser.isAdmin) {
        return res.status(400).json({ error: "Text exceeds maximum length of 5000 characters" });
      }
      const charCheck = canUseVoiceCharacters(freshUser, text2.length);
      if (!charCheck.allowed) {
        return res.status(403).json({ error: charCheck.reason });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const result = await zyphra.generateSpeechWithRetry({
        text: text2,
        speakingRate: speakingRate || 15,
        languageIsoCode: languageIsoCode || "en-us",
        defaultVoiceName: defaultVoiceName || "American Female"
      });
      if (!result.success) {
        return res.status(500).json({ error: result.error });
      }
      await storage.incrementVoiceCharacters(req.session.userId, text2.length);
      const audioId = crypto3.randomUUID();
      audioCache.set(audioId, {
        buffer: result.audioData,
        mimeType: result.mimeType || "audio/wav",
        timestamp: Date.now(),
        userId: req.session.userId
      });
      const updatedUser = await storage.getUser(req.session.userId);
      const usage = updatedUser ? getVoiceCharacterUsage(updatedUser) : null;
      console.log(`[Voice TTS] User: ${freshUser.username} (Plan: ${freshUser.planType}) generated audio, chars: ${text2.length}`);
      res.json({
        success: true,
        audioId,
        mimeType: result.mimeType,
        minutesUsed: result.minutesUsed,
        voiceCharacterUsage: usage
      });
    } catch (error) {
      console.error("Error generating speech:", error);
      res.status(500).json({ error: "Failed to generate speech" });
    }
  });
  app2.get("/api/zyphra/audio/:audioId", requireAuth, (req, res) => {
    const { audioId } = req.params;
    const cached = audioCache.get(audioId);
    if (!cached) {
      return res.status(404).json({ error: "Audio not found or expired" });
    }
    if (cached.userId !== req.session.userId) {
      console.warn(`[Security] User ${req.session.userId} attempted to access audio owned by ${cached.userId}`);
      return res.status(403).json({ error: "Access denied" });
    }
    res.setHeader("Content-Type", cached.mimeType);
    res.setHeader("Content-Disposition", `attachment; filename="speech.wav"`);
    res.send(cached.buffer);
  });
  app2.post("/api/zyphra/clone-voice", requireAuth, async (req, res) => {
    try {
      const freshUser = await storage.checkAndResetVoiceCharacters(req.session.userId);
      if (!freshUser) {
        return res.status(401).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(freshUser, "voiceTools");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const { text: text2, referenceAudioBase64, speakingRate, languageIsoCode, mimeType, model } = req.body;
      if (!text2) {
        return res.status(400).json({ error: "Text is required" });
      }
      if (text2.length > 5e3 && !freshUser.isAdmin) {
        return res.status(400).json({ error: "Text exceeds maximum length of 5000 characters" });
      }
      const charCheck = canUseVoiceCharacters(freshUser, text2.length);
      if (!charCheck.allowed) {
        return res.status(403).json({ error: charCheck.reason });
      }
      if (!referenceAudioBase64) {
        return res.status(400).json({ error: "Reference audio is required for voice cloning" });
      }
      const maxBase64Size = 10 * 1024 * 1024 * 1.33;
      if (referenceAudioBase64.length > maxBase64Size) {
        return res.status(400).json({ error: "Reference audio file exceeds 10MB limit" });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const result = await zyphra.cloneVoiceWithRetry(text2, referenceAudioBase64, {
        speakingRate,
        languageIsoCode,
        mimeType: mimeType || "audio/wav",
        model
      });
      if (!result.success) {
        return res.status(500).json({ error: result.error });
      }
      await storage.incrementVoiceCharacters(req.session.userId, text2.length);
      const audioId = crypto3.randomUUID();
      audioCache.set(audioId, {
        buffer: result.audioData,
        mimeType: result.mimeType || "audio/wav",
        timestamp: Date.now(),
        userId: req.session.userId
      });
      const updatedUser = await storage.getUser(req.session.userId);
      const usage = updatedUser ? getVoiceCharacterUsage(updatedUser) : null;
      console.log(`[Voice Cloning] User: ${freshUser.username} (Plan: ${freshUser.planType}) cloned voice, chars: ${text2.length}`);
      res.json({
        success: true,
        audioId,
        mimeType: result.mimeType,
        minutesUsed: result.minutesUsed,
        voiceCharacterUsage: usage
      });
    } catch (error) {
      console.error("Error cloning voice:", error);
      res.status(500).json({ error: "Failed to clone voice" });
    }
  });
  app2.get("/api/top-voices", requireAuth, async (req, res) => {
    try {
      const { topVoices: topVoices2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const voices = await db.select().from(topVoices2).where(eq3(topVoices2.isActive, true)).orderBy(topVoices2.sortOrder);
      res.json(voices);
    } catch (error) {
      console.error("Error fetching top voices:", error);
      res.status(500).json({ error: "Failed to fetch top voices" });
    }
  });
  app2.get("/api/admin/top-voices", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { topVoices: topVoices2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const voices = await db.select().from(topVoices2).orderBy(topVoices2.sortOrder);
      res.json(voices);
    } catch (error) {
      console.error("Error fetching top voices:", error);
      res.status(500).json({ error: "Failed to fetch top voices" });
    }
  });
  app2.post("/api/admin/top-voices", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { topVoices: topVoices2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const { name, description, demoAudioUrl, demoAudioBase64, sortOrder } = req.body;
      if (!name || !demoAudioUrl) {
        return res.status(400).json({ error: "Name and demo audio URL are required" });
      }
      const [voice] = await db.insert(topVoices2).values({
        name,
        description: description || null,
        demoAudioUrl,
        demoAudioBase64: demoAudioBase64 || null,
        sortOrder: sortOrder || 0
      }).returning();
      res.json(voice);
    } catch (error) {
      console.error("Error adding top voice:", error);
      res.status(500).json({ error: "Failed to add top voice" });
    }
  });
  app2.patch("/api/admin/top-voices/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { topVoices: topVoices2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const { id } = req.params;
      const updates = req.body;
      const [voice] = await db.update(topVoices2).set(updates).where(eq3(topVoices2.id, id)).returning();
      if (!voice) {
        return res.status(404).json({ error: "Voice not found" });
      }
      res.json(voice);
    } catch (error) {
      console.error("Error updating top voice:", error);
      res.status(500).json({ error: "Failed to update top voice" });
    }
  });
  app2.delete("/api/admin/top-voices/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { topVoices: topVoices2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const { id } = req.params;
      await db.delete(topVoices2).where(eq3(topVoices2.id, id));
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting top voice:", error);
      res.status(500).json({ error: "Failed to delete top voice" });
    }
  });
  app2.post("/api/top-voices/:id/generate", requireAuth, async (req, res) => {
    try {
      const freshUser = await storage.checkAndResetVoiceCharacters(req.session.userId);
      if (!freshUser) {
        return res.status(401).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(freshUser, "voiceTools");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const { topVoices: topVoices2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const { id } = req.params;
      const { text: text2, speakingRate, languageIsoCode } = req.body;
      if (!text2 || text2.trim().length === 0) {
        return res.status(400).json({ error: "Text is required" });
      }
      const maxLength = freshUser.isAdmin ? 1e4 : 5e3;
      if (text2.length > maxLength) {
        return res.status(400).json({ error: `Text exceeds ${maxLength} character limit` });
      }
      const charCheck = canUseVoiceCharacters(freshUser, text2.length);
      if (!charCheck.allowed) {
        return res.status(403).json({ error: charCheck.reason });
      }
      const [voice] = await db.select().from(topVoices2).where(eq3(topVoices2.id, id));
      if (!voice || !voice.isActive) {
        return res.status(404).json({ error: "Voice not found" });
      }
      let referenceAudioBase64 = voice.demoAudioBase64;
      if (!referenceAudioBase64 && voice.demoAudioUrl) {
        try {
          const response = await fetch(voice.demoAudioUrl);
          if (response.ok) {
            const arrayBuffer = await response.arrayBuffer();
            referenceAudioBase64 = Buffer.from(arrayBuffer).toString("base64");
          }
        } catch (fetchError) {
          console.error("Error fetching demo audio:", fetchError);
          return res.status(500).json({ error: "Failed to fetch demo audio for cloning" });
        }
      }
      if (!referenceAudioBase64) {
        return res.status(500).json({ error: "No demo audio available for cloning" });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const result = await zyphra.cloneVoiceWithRetry(text2, referenceAudioBase64, {
        speakingRate,
        languageIsoCode,
        mimeType: "audio/wav"
      });
      if (!result.success) {
        return res.status(500).json({ error: result.error });
      }
      await storage.incrementVoiceCharacters(req.session.userId, text2.length);
      const audioId = crypto3.randomUUID();
      audioCache.set(audioId, {
        buffer: result.audioData,
        mimeType: result.mimeType || "audio/wav",
        timestamp: Date.now(),
        userId: req.session.userId
      });
      const updatedUser = await storage.getUser(req.session.userId);
      const usage = updatedUser ? getVoiceCharacterUsage(updatedUser) : null;
      console.log(`[Top Voice] User: ${freshUser.username} (Plan: ${freshUser.planType}) generated audio, chars: ${text2.length}`);
      res.json({
        success: true,
        audioId,
        mimeType: result.mimeType,
        voiceName: voice.name,
        voiceCharacterUsage: usage
      });
    } catch (error) {
      console.error("Error generating from top voice:", error);
      res.status(500).json({ error: "Failed to generate audio" });
    }
  });
  app2.get("/api/top-voices/audio/:audioId", requireAuth, (req, res) => {
    const { audioId } = req.params;
    const cached = audioCache.get(audioId);
    if (!cached) {
      return res.status(404).json({ error: "Audio not found or expired" });
    }
    if (cached.userId !== req.session.userId) {
      console.warn(`[Security] User ${req.session.userId} attempted to access top voice audio owned by ${cached.userId}`);
      return res.status(403).json({ error: "Access denied" });
    }
    res.setHeader("Content-Type", cached.mimeType);
    res.setHeader("Content-Length", cached.buffer.length);
    res.setHeader("Cache-Control", "no-cache");
    res.send(cached.buffer);
  });
  app2.get("/api/community-voices", requireAuth, async (req, res) => {
    try {
      const voices = await storage.getAllCommunityVoices();
      const userId = req.session.userId;
      const likedIds = userId ? await storage.getUserLikedVoiceIds(userId) : [];
      res.json({ voices, likedIds });
    } catch (error) {
      console.error("Error fetching community voices:", error);
      res.status(500).json({ error: "Failed to fetch community voices" });
    }
  });
  app2.get("/api/community-voices/top", requireAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 10;
      const voices = await storage.getTopCommunityVoices(limit);
      const userId = req.session.userId;
      const likedIds = userId ? await storage.getUserLikedVoiceIds(userId) : [];
      res.json({ voices, likedIds });
    } catch (error) {
      console.error("Error fetching top community voices:", error);
      res.status(500).json({ error: "Failed to fetch top community voices" });
    }
  });
  app2.post("/api/community-voices", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }
      const { name, description, language, gender, demoAudioBase64 } = req.body;
      if (!name || name.length < 2) {
        return res.status(400).json({ error: "Name must be at least 2 characters" });
      }
      if (!demoAudioBase64) {
        return res.status(400).json({ error: "Demo audio is required" });
      }
      if (!language) {
        return res.status(400).json({ error: "Language is required" });
      }
      if (!gender || !["Male", "Female"].includes(gender)) {
        return res.status(400).json({ error: "Gender must be Male or Female" });
      }
      const audioBuffer = Buffer.from(demoAudioBase64, "base64");
      const actualFileSizeBytes = audioBuffer.length;
      if (actualFileSizeBytes > 5 * 1024 * 1024) {
        return res.status(400).json({ error: "File must be less than 5MB" });
      }
      let actualDurationSeconds = 0;
      try {
        const mm2 = await import("music-metadata");
        const metadata = await mm2.parseBuffer(audioBuffer);
        actualDurationSeconds = metadata.format.duration || 0;
      } catch (parseError) {
        console.error("Error parsing audio metadata:", parseError);
        return res.status(400).json({ error: "Could not parse audio file. Please upload a valid audio file." });
      }
      if (actualDurationSeconds < 10) {
        return res.status(400).json({ error: `Audio must be at least 10 seconds (detected: ${actualDurationSeconds.toFixed(1)}s)` });
      }
      const voice = await storage.createCommunityVoice(
        { name, description, language, gender, demoAudioBase64, durationSeconds: Math.floor(actualDurationSeconds), fileSizeBytes: actualFileSizeBytes },
        userId,
        user.username
      );
      res.json({ success: true, voice });
    } catch (error) {
      console.error("Error creating community voice:", error);
      res.status(500).json({ error: "Failed to create community voice" });
    }
  });
  app2.post("/api/community-voices/:id/like", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const voiceId = req.params.id;
      const voice = await storage.getCommunityVoiceById(voiceId);
      if (!voice) {
        return res.status(404).json({ error: "Voice not found" });
      }
      const result = await storage.toggleCommunityVoiceLike(voiceId, userId);
      res.json(result);
    } catch (error) {
      console.error("Error toggling like:", error);
      res.status(500).json({ error: "Failed to toggle like" });
    }
  });
  app2.delete("/api/community-voices/:id", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const voiceId = req.params.id;
      const voice = await storage.getCommunityVoiceById(voiceId);
      if (!voice) {
        return res.status(404).json({ error: "Voice not found" });
      }
      const user = await storage.getUser(userId);
      if (voice.creatorId !== userId && !user?.isAdmin) {
        return res.status(403).json({ error: "Not authorized to delete this voice" });
      }
      await storage.deleteCommunityVoice(voiceId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting community voice:", error);
      res.status(500).json({ error: "Failed to delete community voice" });
    }
  });
  app2.post("/api/community-voices/:id/generate", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const freshUser = await storage.checkAndResetVoiceCharacters(userId);
      if (!freshUser) {
        return res.status(401).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(freshUser, "voiceTools");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const voiceId = req.params.id;
      const voice = await storage.getCommunityVoiceById(voiceId);
      if (!voice) {
        return res.status(404).json({ error: "Voice not found" });
      }
      const { text: text2, speakingRate = 10 } = req.body;
      if (!text2 || text2.trim().length === 0) {
        return res.status(400).json({ error: "Text is required" });
      }
      const maxLength = freshUser.isAdmin ? 1e4 : 5e3;
      if (text2.length > maxLength) {
        return res.status(400).json({ error: `Text exceeds ${maxLength} character limit` });
      }
      const charCheck = canUseVoiceCharacters(freshUser, text2.length);
      if (!charCheck.allowed) {
        return res.status(403).json({ error: charCheck.reason });
      }
      const zyphra = await Promise.resolve().then(() => (init_zyphra(), zyphra_exports));
      const result = await zyphra.cloneVoiceWithRetry(text2, voice.demoAudioBase64, {
        speakingRate,
        languageIsoCode: "en-us",
        mimeType: "audio/wav",
        model: "zonos-v0.1-transformer"
      });
      if (!result.success || !result.audioData) {
        return res.status(500).json({ error: result.error || "Failed to generate audio" });
      }
      await storage.incrementVoiceCharacters(userId, text2.length);
      const audioId = `community_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      audioCache.set(audioId, {
        buffer: result.audioData,
        mimeType: result.mimeType || "audio/wav",
        timestamp: Date.now(),
        userId: req.session.userId
      });
      const updatedUser = await storage.getUser(userId);
      const usage = updatedUser ? getVoiceCharacterUsage(updatedUser) : null;
      console.log(`[Community Voice] User: ${freshUser.username} (Plan: ${freshUser.planType}) generated audio, chars: ${text2.length}`);
      res.json({
        success: true,
        audioId,
        mimeType: result.mimeType,
        voiceName: voice.name,
        voiceCharacterUsage: usage
      });
    } catch (error) {
      console.error("Error generating from community voice:", error);
      res.status(500).json({ error: "Failed to generate audio" });
    }
  });
  app2.get("/api/community-voices/audio/:audioId", requireAuth, (req, res) => {
    const { audioId } = req.params;
    const cached = audioCache.get(audioId);
    if (!cached) {
      return res.status(404).json({ error: "Audio not found or expired" });
    }
    if (cached.userId !== req.session.userId) {
      console.warn(`[Security] User ${req.session.userId} attempted to access community voice audio owned by ${cached.userId}`);
      return res.status(403).json({ error: "Access denied" });
    }
    res.setHeader("Content-Type", cached.mimeType);
    res.setHeader("Content-Length", cached.buffer.length);
    res.setHeader("Cache-Control", "no-cache");
    res.send(cached.buffer);
  });
  app2.post("/api/reseller/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
      }
      const reseller = await storage.getResellerByUsername(username);
      if (!reseller) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      if (!reseller.isActive) {
        return res.status(403).json({ error: "Account is inactive" });
      }
      const isValidPassword = await storage.verifyResellerPassword(reseller, password);
      if (!isValidPassword) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      req.session.resellerId = reseller.id;
      req.session.isReseller = true;
      res.json({
        reseller: {
          id: reseller.id,
          username: reseller.username,
          creditBalance: reseller.creditBalance,
          isActive: reseller.isActive
        }
      });
    } catch (error) {
      console.error("Reseller login error:", error);
      res.status(500).json({ error: "Login failed" });
    }
  });
  app2.post("/api/reseller/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: "Logout failed" });
      }
      res.json({ success: true });
    });
  });
  app2.get("/api/reseller/session", async (req, res) => {
    try {
      if (!req.session.resellerId || !req.session.isReseller) {
        return res.json({ authenticated: false });
      }
      const reseller = await storage.getResellerById(req.session.resellerId);
      if (!reseller || !reseller.isActive) {
        req.session.destroy(() => {
        });
        return res.json({ authenticated: false });
      }
      res.json({
        authenticated: true,
        reseller: {
          id: reseller.id,
          username: reseller.username,
          creditBalance: reseller.creditBalance
        }
      });
    } catch (error) {
      console.error("Error getting reseller session:", error);
      res.status(500).json({ error: "Failed to get session" });
    }
  });
  const requireReseller = async (req, res, next) => {
    if (!req.session.resellerId || !req.session.isReseller) {
      return res.status(401).json({ error: "Reseller authentication required" });
    }
    const reseller = await storage.getResellerById(req.session.resellerId);
    if (!reseller) {
      req.session.destroy(() => {
      });
      return res.status(401).json({ error: "Session expired" });
    }
    if (!reseller.isActive) {
      req.session.destroy(() => {
      });
      return res.status(403).json({ error: "Account is inactive" });
    }
    next();
  };
  app2.get("/api/reseller/credits", requireReseller, async (req, res) => {
    try {
      const reseller = await storage.getResellerById(req.session.resellerId);
      if (!reseller) {
        return res.status(404).json({ error: "Reseller not found" });
      }
      res.json({ creditBalance: reseller.creditBalance });
    } catch (error) {
      console.error("Error fetching reseller credits:", error);
      res.status(500).json({ error: "Failed to fetch credits" });
    }
  });
  app2.get("/api/reseller/ledger", requireReseller, async (req, res) => {
    try {
      const ledger = await storage.getResellerCreditLedger(req.session.resellerId);
      res.json({ ledger });
    } catch (error) {
      console.error("Error fetching reseller ledger:", error);
      res.status(500).json({ error: "Failed to fetch ledger" });
    }
  });
  app2.get("/api/reseller/users", requireReseller, async (req, res) => {
    try {
      const users2 = await storage.getResellerUsers(req.session.resellerId);
      res.json({ users: users2 });
    } catch (error) {
      console.error("Error fetching reseller users:", error);
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });
  app2.post("/api/reseller/users", requireReseller, async (req, res) => {
    try {
      const { username, password, planType } = req.body;
      if (!username || !password || !planType) {
        return res.status(400).json({ error: "Username, password, and plan type are required" });
      }
      if (planType !== "scale" && planType !== "empire") {
        return res.status(400).json({ error: "Plan type must be 'scale' or 'empire'" });
      }
      const result = await storage.createUserByReseller(req.session.resellerId, {
        username,
        password,
        planType
      });
      res.json({
        user: {
          id: result.user.id,
          username: result.user.username,
          planType: result.user.planType
        },
        creditCost: result.resellerUser.creditCost
      });
    } catch (error) {
      console.error("Error creating user by reseller:", error);
      if (error.message.includes("Insufficient credits")) {
        return res.status(400).json({ error: error.message });
      }
      if (error.message === "Username already exists") {
        return res.status(400).json({ error: "Username already exists" });
      }
      if (error.message === "Reseller account is inactive") {
        return res.status(403).json({ error: "Your account is inactive" });
      }
      res.status(500).json({ error: "Failed to create user" });
    }
  });
  app2.get("/api/admin/video-history", requireAuth, requireAdmin, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit) || 100, 500);
      const offset = parseInt(req.query.offset) || 0;
      const videos = await db.select().from(videoHistory).orderBy(desc2(videoHistory.createdAt)).limit(limit).offset(offset);
      res.json({ videos, limit, offset });
    } catch (error) {
      console.error("Error fetching all video history:", error);
      res.status(500).json({
        error: "Failed to fetch video history",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/video-history", requireAuth, async (req, res) => {
    const startTime = Date.now();
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      console.log(`[VideoHistory] Starting query for user ${userId}`);
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }
      const defaultLimit = user.bulkMaxPrompts || 100;
      const limit = Math.min(parseInt(req.query.limit) || defaultLimit, 500);
      const offset = parseInt(req.query.offset) || 0;
      const videos = await db.select({
        id: videoHistory.id,
        prompt: videoHistory.prompt,
        videoUrl: videoHistory.videoUrl,
        status: videoHistory.status,
        createdAt: videoHistory.createdAt,
        title: videoHistory.title,
        errorMessage: videoHistory.errorMessage,
        retryCount: videoHistory.retryCount,
        operationName: videoHistory.operationName,
        sceneId: videoHistory.sceneId,
        tokenUsed: videoHistory.tokenUsed
      }).from(videoHistory).where(
        and3(
          eq3(videoHistory.userId, userId),
          eq3(videoHistory.deletedByUser, false)
        )
      ).orderBy(desc2(videoHistory.createdAt)).limit(limit).offset(offset);
      const duration = Date.now() - startTime;
      console.log(`[VideoHistory] Query completed in ${duration}ms, found ${videos.length} videos`);
      res.json({ videos, limit, offset });
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`[VideoHistory] Error after ${duration}ms:`, error);
      res.status(500).json({
        error: "Failed to fetch video history",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/video-history", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const videoCheck = canGenerateVideo(user);
      if (!videoCheck.allowed) {
        return res.status(403).json({ error: videoCheck.reason });
      }
      const schema = z2.object({
        prompt: z2.string().min(10, "Prompt must be at least 10 characters"),
        aspectRatio: z2.enum(["landscape", "portrait"]),
        videoUrl: z2.string().optional(),
        status: z2.enum(["pending", "completed", "failed", "queued"]),
        title: z2.string().optional(),
        tokenUsed: z2.string().optional()
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const video = await storage.addVideoHistory({
        userId,
        ...validationResult.data
      });
      res.json({ video });
    } catch (error) {
      console.error("Error saving video history:", error);
      res.status(500).json({
        error: "Failed to save video history",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.delete("/api/video-history/:id", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const videoId = req.params.id;
      if (!videoId) {
        return res.status(400).json({ error: "Video ID is required" });
      }
      const video = await storage.getVideoById(videoId);
      if (!video) {
        return res.status(404).json({ error: "Video not found" });
      }
      if (video.userId !== userId) {
        return res.status(403).json({ error: "Not authorized to delete this video" });
      }
      if (video.videoUrl) {
        try {
          const { ObjectStorageService: ObjectStorageService2 } = await Promise.resolve().then(() => (init_objectStorage(), objectStorage_exports));
          const objectStorageService2 = new ObjectStorageService2();
          const file = await objectStorageService2.getObjectEntityFile(video.videoUrl);
          await file.delete();
          console.log(`[API] Deleted video file: ${video.videoUrl}`);
        } catch (error) {
          console.warn(`[API] Could not delete video file ${video.videoUrl}:`, error instanceof Error ? error.message : "Unknown error");
        }
      }
      await db.update(videoHistory).set({
        deletedByUser: true,
        deletedAt: sql3`now()::text`
      }).where(
        and3(
          eq3(videoHistory.id, videoId),
          eq3(videoHistory.userId, userId)
        )
      );
      console.log(`[API] User ${userId}: Deleted video ${videoId}`);
      res.json({
        success: true,
        message: "Video deleted successfully"
      });
    } catch (error) {
      console.error("Error deleting video:", error);
      res.status(500).json({
        error: "Failed to delete video",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.delete("/api/video-history", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const videos = await db.select().from(videoHistory).where(
        and3(
          eq3(videoHistory.userId, userId),
          eq3(videoHistory.deletedByUser, false)
          // Only fetch non-deleted videos
        )
      );
      console.log(`[API] User ${userId}: Found ${videos.length} videos to soft delete`);
      const { ObjectStorageService: ObjectStorageService2 } = await Promise.resolve().then(() => (init_objectStorage(), objectStorage_exports));
      const objectStorageService2 = new ObjectStorageService2();
      let deletedFilesCount = 0;
      for (const video of videos) {
        if (video.videoUrl) {
          try {
            const file = await objectStorageService2.getObjectEntityFile(video.videoUrl);
            await file.delete();
            deletedFilesCount++;
            console.log(`[API] Deleted video file: ${video.videoUrl}`);
          } catch (error) {
            console.warn(`[API] Could not delete video file ${video.videoUrl}:`, error instanceof Error ? error.message : "Unknown error");
          }
        }
      }
      await db.update(videoHistory).set({
        deletedByUser: true,
        deletedAt: sql3`now()::text`
      }).where(
        and3(
          eq3(videoHistory.userId, userId),
          eq3(videoHistory.deletedByUser, false)
        )
      );
      console.log(`[API] User ${userId}: Soft deleted ${videos.length} video history records, deleted ${deletedFilesCount} files from storage`);
      res.json({
        success: true,
        message: "All video history cleared successfully",
        deletedRecords: videos.length,
        deletedFiles: deletedFilesCount
      });
    } catch (error) {
      console.error("Error clearing video history:", error);
      res.status(500).json({
        error: "Failed to clear video history",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/bulk-generate", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const { stopFlowQueue: stopFlowQueue2 } = await Promise.resolve().then(() => (init_bulkQueueFlow(), bulkQueueFlow_exports));
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const schema = z2.object({
        prompts: z2.array(z2.string().min(10, "Each prompt must be at least 10 characters")).min(1).max(500),
        aspectRatio: z2.enum(["landscape", "portrait"])
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { prompts, aspectRatio } = validationResult.data;
      const bulkCheck = canBulkGenerate(user, prompts.length);
      if (!bulkCheck.allowed) {
        return res.status(403).json({ error: bulkCheck.reason });
      }
      const activeCookies = await storage.getActiveFlowCookies();
      if (activeCookies.length === 0) {
        return res.status(400).json({ error: "No Flow Cookies available. Please add cookies in Admin panel." });
      }
      const { addToFlowQueue: addToFlowQueue2 } = await Promise.resolve().then(() => (init_bulkQueueFlow(), bulkQueueFlow_exports));
      console.log(`[Bulk Generate] Starting bulk generation for ${prompts.length} videos using Flow Cookies (User: ${user.username})`);
      try {
        stopFlowQueue2(userId);
        const deleteResult = await db.delete(videoHistory).where(
          and3(
            eq3(videoHistory.userId, userId),
            or(
              eq3(videoHistory.status, "pending"),
              eq3(videoHistory.status, "generating"),
              eq3(videoHistory.status, "queued"),
              eq3(videoHistory.status, "retrying"),
              eq3(videoHistory.status, "processing"),
              eq3(videoHistory.status, "initializing")
            )
          )
        ).returning({ id: videoHistory.id });
        if (deleteResult.length > 0) {
          console.log(`[Bulk Generate] Fast-cleared ${deleteResult.length} stuck/pending videos for user ${userId}`);
        }
      } catch (clearError) {
        console.error("[Bulk Generate] Error auto-clearing stuck videos:", clearError);
      }
      const videoIds = [];
      const queuedVideos = [];
      for (let i = 0; i < prompts.length; i++) {
        const prompt = prompts[i];
        const video = await storage.addVideoHistory({
          userId,
          prompt,
          aspectRatio,
          status: "pending",
          title: `Bulk Flow ${aspectRatio} video ${i + 1}`
        });
        videoIds.push(video.id);
        queuedVideos.push({
          videoId: video.id,
          prompt,
          aspectRatio,
          sceneNumber: i + 1,
          userId
        });
      }
      await addToFlowQueue2(queuedVideos, false);
      console.log(`[Bulk Generate] Created ${videoIds.length} videos and added to Flow queue (batch size: 10)`);
      res.json({
        success: true,
        videoIds,
        message: `Started generating ${prompts.length} videos using Flow Cookies. Processing in batches of 10.`
      });
    } catch (error) {
      console.error("Error starting bulk generation:", error);
      res.status(500).json({
        error: "Failed to start bulk generation",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/bulk-generate/stop", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        res.status(401).json({ error: "Not authenticated" });
        return;
      }
      const { stopFlowQueue: stopFlowQueue2 } = await Promise.resolve().then(() => (init_bulkQueueFlow(), bulkQueueFlow_exports));
      const result = stopFlowQueue2(userId);
      console.log(`[API] User ${userId}: Bulk processing stopped. Cleared ${result.remaining} videos.`);
      res.json({ stopped: result.stopped, clearedVideos: result.remaining });
    } catch (error) {
      console.error("Error stopping bulk processing:", error);
      res.status(500).json({
        error: "Failed to stop bulk processing",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  const statusCache = /* @__PURE__ */ new Map();
  const STATUS_CACHE_TTL = 5e3;
  app2.get("/api/bulk-generate/status", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        res.status(401).json({ error: "Not authenticated" });
        return;
      }
      const cached = statusCache.get(userId);
      const now = Date.now();
      if (cached && now - cached.timestamp < STATUS_CACHE_TTL) {
        return res.json(cached.data);
      }
      const { getFlowQueueStatus: getFlowQueueStatus2 } = await Promise.resolve().then(() => (init_bulkQueueFlow(), bulkQueueFlow_exports));
      const status = getFlowQueueStatus2(userId);
      let videos;
      if (status.batchVideoIds && status.batchVideoIds.length > 0) {
        videos = await db.select({
          id: videoHistory.id,
          prompt: videoHistory.prompt,
          status: videoHistory.status,
          videoUrl: videoHistory.videoUrl,
          errorMessage: videoHistory.errorMessage,
          tokenUsed: videoHistory.tokenUsed
        }).from(videoHistory).where(inArray2(videoHistory.id, status.batchVideoIds));
      } else {
        videos = await db.select({
          id: videoHistory.id,
          prompt: videoHistory.prompt,
          status: videoHistory.status,
          videoUrl: videoHistory.videoUrl,
          errorMessage: videoHistory.errorMessage,
          tokenUsed: videoHistory.tokenUsed
        }).from(videoHistory).where(and3(
          eq3(videoHistory.userId, userId),
          eq3(videoHistory.deletedByUser, false)
        )).orderBy(desc2(videoHistory.createdAt)).limit(100);
      }
      const mapStatus = (dbStatus) => {
        switch (dbStatus) {
          case "completed":
            return "completed";
          case "failed":
            return "failed";
          case "generating":
          case "queued":
          case "retrying":
          case "initializing":
            return "processing";
          default:
            return "pending";
        }
      };
      const results = videos.map((video) => ({
        id: video.id,
        prompt: video.prompt,
        status: mapStatus(video.status),
        videoUrl: video.videoUrl || void 0,
        error: video.errorMessage || void 0,
        tokenLabel: video.tokenUsed || null
      }));
      const response = {
        ...status,
        results
      };
      statusCache.set(userId, { data: response, timestamp: now });
      res.json(response);
    } catch (error) {
      console.error("Error getting queue status:", error);
      res.status(500).json({
        error: "Failed to get queue status",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.patch("/api/video-history/:id", requireAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const schema = z2.object({
        status: z2.enum(["pending", "completed", "failed", "queued"]),
        videoUrl: z2.string().optional()
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { status, videoUrl } = validationResult.data;
      const updated = await storage.updateVideoHistoryStatus(id, userId, status, videoUrl);
      if (!updated) {
        return res.status(404).json({ error: "Video history entry not found or access denied" });
      }
      res.json({ video: updated });
    } catch (error) {
      console.error("Error updating video history:", error);
      res.status(500).json({
        error: "Failed to update video history",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/videos/download-zip", async (req, res) => {
    if (activeZipDownloads >= MAX_CONCURRENT_ZIP_DOWNLOADS) {
      console.log(`[ZIP Download] Rejected - too many active downloads (${activeZipDownloads}/${MAX_CONCURRENT_ZIP_DOWNLOADS})`);
      return res.status(503).json({
        error: "Server busy",
        message: "Too many downloads in progress. Please try again in a few seconds."
      });
    }
    activeZipDownloads++;
    console.log(`[ZIP Download] Started (active: ${activeZipDownloads}/${MAX_CONCURRENT_ZIP_DOWNLOADS})`);
    try {
      const schema = z2.object({
        videoIds: z2.array(z2.string()).min(1, "At least one video must be selected").max(200, "Maximum 200 videos can be downloaded at once")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        activeZipDownloads--;
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { videoIds } = validationResult.data;
      const videos = await Promise.all(
        videoIds.map((id) => storage.getVideoById(id))
      );
      const validVideos = videos.filter(
        (v) => v !== void 0 && v.videoUrl !== null && v.status === "completed"
      );
      if (validVideos.length === 0) {
        activeZipDownloads--;
        return res.status(404).json({ error: "No valid videos found" });
      }
      console.log(`[ZIP Download] Downloading ${validVideos.length} videos (active: ${activeZipDownloads})`);
      const timestamp = (/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-");
      res.setHeader("Content-Type", "application/zip");
      res.setHeader("Content-Disposition", `attachment; filename="videos-${timestamp}.zip"`);
      const archive = archiver("zip", {
        zlib: { level: 0 },
        // No compression for faster processing
        highWaterMark: 1024 * 1024 * 4
        // 4MB buffer for better throughput
      });
      archive.pipe(res);
      archive.on("error", (err) => {
        console.error("[ZIP Download] Archive error:", err);
        if (!res.headersSent) {
          res.status(500).json({ error: "Failed to create ZIP archive" });
        }
      });
      let successCount = 0;
      const PARALLEL_DOWNLOADS = 10;
      const VIDEO_FETCH_TIMEOUT = 6e4;
      for (let batchStart = 0; batchStart < validVideos.length; batchStart += PARALLEL_DOWNLOADS) {
        const batchEnd = Math.min(batchStart + PARALLEL_DOWNLOADS, validVideos.length);
        const batch = validVideos.slice(batchStart, batchEnd);
        console.log(`[ZIP Download] Processing batch ${Math.floor(batchStart / PARALLEL_DOWNLOADS) + 1} (${batchStart + 1}-${batchEnd}/${validVideos.length})`);
        await Promise.all(
          batch.map(async (video, batchIndex) => {
            const i = batchStart + batchIndex;
            if (!video || !video.videoUrl) return;
            try {
              const safePrompt = video.prompt?.substring(0, 50).replace(/[^a-zA-Z0-9]/g, "_") || "video";
              const filename = `${i + 1}_${safePrompt}_${video.id}.mp4`;
              await new Promise((resolve) => {
                const isHttps = video.videoUrl.startsWith("https");
                const protocol = isHttps ? https : http;
                const agent = isHttps ? httpsAgent : httpAgent;
                const timeoutId = setTimeout(() => {
                  console.error(`[ZIP Download] Timeout for video ${i + 1}: ${filename}`);
                  resolve();
                }, VIDEO_FETCH_TIMEOUT);
                const request = protocol.get(video.videoUrl, { agent }, (response) => {
                  if (response.statusCode === 200) {
                    archive.append(response, { name: filename });
                    response.on("end", () => {
                      clearTimeout(timeoutId);
                      successCount++;
                      resolve();
                    });
                    response.on("error", () => {
                      clearTimeout(timeoutId);
                      resolve();
                    });
                  } else {
                    clearTimeout(timeoutId);
                    console.error(`[ZIP Download] Failed to fetch video ${i + 1}: ${response.statusCode}`);
                    resolve();
                  }
                });
                request.on("error", (err) => {
                  clearTimeout(timeoutId);
                  console.error(`[ZIP Download] Request error for video ${i + 1}:`, err.message);
                  resolve();
                });
                request.setTimeout(VIDEO_FETCH_TIMEOUT, () => {
                  clearTimeout(timeoutId);
                  request.destroy();
                  resolve();
                });
              });
            } catch (error) {
              console.error(`[ZIP Download] Error adding video ${i + 1} to archive:`, error);
            }
          })
        );
      }
      console.log(`[ZIP Download] Successfully added ${successCount}/${validVideos.length} videos to ZIP`);
      await archive.finalize();
      activeZipDownloads--;
      console.log(`[ZIP Download] Complete (active: ${activeZipDownloads})`);
    } catch (error) {
      activeZipDownloads--;
      console.error("Error creating ZIP download:", error);
      if (!res.headersSent) {
        res.status(500).json({
          error: "Failed to create ZIP download",
          message: error instanceof Error ? error.message : "Unknown error"
        });
      }
    }
  });
  app2.post("/api/videos/confirm-download", requireAuth, async (req, res) => {
    try {
      const { videoId } = req.body;
      if (!videoId) {
        return res.status(400).json({ error: "Missing videoId" });
      }
      const { deleteDirectVideo: deleteDirectVideo2 } = await Promise.resolve().then(() => (init_bulkQueueFlow(), bulkQueueFlow_exports));
      const deleted = await deleteDirectVideo2(videoId);
      res.json({ success: true, deleted });
    } catch (error) {
      console.error("[Confirm Download] Error:", error);
      res.status(500).json({ error: "Failed to confirm download" });
    }
  });
  app2.get("/api/videos/download-single", requireAuth, async (req, res) => {
    try {
      const videoUrl = req.query.videoUrl;
      const filename = req.query.filename;
      if (!videoUrl || !filename) {
        return res.status(400).json({ error: "Missing videoUrl or filename" });
      }
      console.log(`[Single Download] Downloading: ${filename} from ${videoUrl.substring(0, 80)}...`);
      if (videoUrl.startsWith("direct:")) {
        const videoId = videoUrl.replace("direct:", "");
        const { getDirectVideo: getDirectVideo2 } = await Promise.resolve().then(() => (init_bulkQueueFlow(), bulkQueueFlow_exports));
        const base64 = await getDirectVideo2(videoId);
        if (base64) {
          console.log(`[Single Download] Serving direct video from temp file: ${videoId}`);
          const buffer = Buffer.from(base64, "base64");
          res.setHeader("Content-Type", "video/mp4");
          res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
          res.setHeader("Content-Length", buffer.length);
          res.send(buffer);
          console.log(`[Single Download] Complete: ${filename} (${buffer.length} bytes)`);
          return;
        } else {
          console.error(`[Single Download] Direct video not found or expired: ${videoId}`);
          return res.status(404).json({ error: "Video expired or already downloaded. Please regenerate." });
        }
      }
      if (videoUrl.startsWith("/api/video-preview/")) {
        const videoId = videoUrl.replace("/api/video-preview/", "");
        const buffer = getVideoBuffer(videoId);
        if (buffer) {
          console.log(`[Single Download] Serving from memory buffer: ${videoId} (${buffer.length} bytes)`);
          res.setHeader("Content-Type", "video/mp4");
          res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
          res.setHeader("Content-Length", buffer.length);
          res.send(buffer);
          console.log(`[Single Download] Complete: ${filename}`);
          return;
        } else {
          console.error(`[Single Download] Video buffer not found: ${videoId}`);
          return res.status(404).json({ error: "Video not found or expired" });
        }
      }
      if (videoUrl.startsWith("/api/local-video/")) {
        const videoId = videoUrl.replace("/api/local-video/", "");
        const { getVideoPath: getVideoPath2, getVideoMetadata: getVideoMetadata2 } = await Promise.resolve().then(() => (init_localDiskStorage(), localDiskStorage_exports));
        const videoPath = getVideoPath2(videoId);
        const metadata = getVideoMetadata2(videoId);
        if (videoPath) {
          console.log(`[Single Download] Serving from local disk: ${videoId}`);
          const fs5 = await import("fs");
          const stat = fs5.statSync(videoPath);
          res.setHeader("Content-Type", "video/mp4");
          res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
          res.setHeader("Content-Length", stat.size);
          const readStream = fs5.createReadStream(videoPath);
          readStream.pipe(res);
          readStream.on("end", () => {
            console.log(`[Single Download] Complete: ${filename} (${stat.size} bytes)`);
          });
          readStream.on("error", (err) => {
            console.error(`[Single Download] Stream error:`, err);
            if (!res.headersSent) {
              res.status(500).json({ error: "Failed to stream video" });
            }
          });
          return;
        } else {
          console.error(`[Single Download] Local disk video not found or expired: ${videoId}`);
          return res.status(404).json({ error: "Video expired or deleted. Local disk videos expire after 3 hours." });
        }
      }
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12e4);
      try {
        const response = await fetch(videoUrl, {
          signal: controller.signal,
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          }
        });
        clearTimeout(timeoutId);
        if (!response.ok) {
          console.error(`[Single Download] Failed to fetch video: ${response.status} ${response.statusText}`);
          return res.status(500).json({ error: `Failed to download video: ${response.status}` });
        }
        res.setHeader("Content-Type", "video/mp4");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        const contentLength = response.headers.get("content-length");
        if (contentLength) {
          res.setHeader("Content-Length", contentLength);
        }
        if (response.body) {
          const reader = response.body.getReader();
          const pump = async () => {
            const { done, value } = await reader.read();
            if (done) {
              res.end();
              return;
            }
            if (!res.writableEnded) {
              res.write(Buffer.from(value));
              return pump();
            }
          };
          await pump();
          console.log(`[Single Download] Complete: ${filename}`);
        } else {
          res.status(500).json({ error: "No response body" });
        }
      } catch (fetchError) {
        clearTimeout(timeoutId);
        if (fetchError.name === "AbortError") {
          console.error(`[Single Download] Timeout for ${filename}`);
          if (!res.headersSent) {
            res.status(504).json({ error: "Download timeout - video took too long" });
          }
        } else {
          throw fetchError;
        }
      }
    } catch (error) {
      console.error("Error in single video download:", error);
      if (!res.headersSent) {
        res.status(500).json({
          error: "Failed to download video",
          message: error instanceof Error ? error.message : "Unknown error"
        });
      }
    }
  });
  app2.get("/api/images/download-proxy", requireAuth, async (req, res) => {
    try {
      const imageUrl = req.query.imageUrl;
      const filename = req.query.filename || `image-${Date.now()}.png`;
      if (!imageUrl) {
        return res.status(400).json({ error: "Missing imageUrl" });
      }
      console.log(`[Image Download] Downloading: ${filename}`);
      let contentType = "image/png";
      if (imageUrl.includes(".jpg") || imageUrl.includes(".jpeg")) {
        contentType = "image/jpeg";
      } else if (imageUrl.includes(".webp")) {
        contentType = "image/webp";
      } else if (imageUrl.includes(".gif")) {
        contentType = "image/gif";
      }
      res.setHeader("Content-Type", contentType);
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      const isHttps = imageUrl.startsWith("https");
      const protocol = isHttps ? https : http;
      const agent = isHttps ? httpsAgent : httpAgent;
      const IMAGE_TIMEOUT = 3e4;
      const request = protocol.get(imageUrl, { agent }, (imageResponse) => {
        if (imageResponse.statusCode === 200) {
          imageResponse.pipe(res);
        } else {
          console.error(`[Image Download] Failed to fetch image: ${imageResponse.statusCode}`);
          if (!res.headersSent) {
            res.status(500).json({ error: "Failed to download image" });
          }
        }
      });
      request.on("error", (err) => {
        console.error(`[Image Download] Request error:`, err);
        if (!res.headersSent) {
          res.status(500).json({ error: "Failed to download image" });
        }
      });
      request.setTimeout(IMAGE_TIMEOUT, () => {
        request.destroy();
        console.error(`[Image Download] Timeout for ${filename}`);
        if (!res.headersSent) {
          res.status(504).json({ error: "Image download timeout" });
        }
      });
    } catch (error) {
      console.error("Error in image download proxy:", error);
      if (!res.headersSent) {
        res.status(500).json({
          error: "Failed to download image",
          message: error instanceof Error ? error.message : "Unknown error"
        });
      }
    }
  });
  app2.post("/api/generate-script", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "script");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const schema = z2.object({
        storyAbout: z2.string().min(5, "Story description must be at least 5 characters"),
        numberOfPrompts: z2.number().min(1).max(39),
        finalStep: z2.string().min(5, "Final step must be at least 5 characters")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { storyAbout, numberOfPrompts, finalStep } = validationResult.data;
      console.log(`[Script Generator] User: ${user.username}, Plan: ${user.planType}`);
      const script = await generateScript(storyAbout, numberOfPrompts, finalStep);
      res.json({ script });
    } catch (error) {
      console.error("Error in /api/generate-script:", error);
      res.status(500).json({
        error: "Failed to generate script",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/script-to-prompts", requireAdmin, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const schema = z2.object({
        script: z2.string().min(10, "Script must be at least 10 characters"),
        numberOfScenes: z2.number().min(1).max(20),
        style: z2.string().optional().default("Disney Pixar 3D animation style")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { script, numberOfScenes, style } = validationResult.data;
      const appSettingsData = await storage.getAppSettings();
      const geminiApiKey = appSettingsData?.geminiApiKey;
      if (!geminiApiKey) {
        return res.status(400).json({
          error: "Gemini API key not configured. Please add it in Admin Settings."
        });
      }
      console.log(`[Script-to-Prompts] Processing script with ${numberOfScenes} scenes, style: ${style}`);
      const { GoogleGenAI } = await import("@google/genai");
      const ai = new GoogleGenAI({ apiKey: geminiApiKey });
      const systemPrompt = `You are an expert at converting narrative scripts into visual image prompts for AI image generation.

Your task is to analyze the provided script and create exactly ${numberOfScenes} image prompts that capture the key moments of the story.

IMPORTANT RULES:
1. Each prompt should describe a SINGLE static scene/frame that can be generated as an image
2. Use the style: "${style}" for all prompts
3. Include specific visual details: characters, environment, lighting, camera angle, mood
4. Each prompt should flow naturally into the next to create visual continuity
5. For video transitions: Scene N's END frame should seamlessly connect to Scene N+1's START frame
6. Focus on character consistency - describe characters consistently across all scenes
7. Include specific colors, textures, and atmospheric details

OUTPUT FORMAT:
Return a JSON array with exactly ${numberOfScenes} objects. Each object should have:
- "sceneNumber": number (1 to ${numberOfScenes})
- "prompt": string (the detailed image prompt, 100-200 words)
- "description": string (brief summary of what happens in this scene, 10-20 words)

Example output format:
[
  {
    "sceneNumber": 1,
    "prompt": "A cozy woodland cottage at golden hour, ${style}, a small rabbit character with fluffy white fur and big blue eyes standing at the door, warm sunlight filtering through oak trees, autumn leaves scattered on the ground, peaceful atmosphere, cinematic composition",
    "description": "Rabbit character at home during sunset"
  }
]

Only respond with the JSON array, no additional text.`;
      const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
        contents: [
          { role: "user", parts: [{ text: systemPrompt + "\n\nSCRIPT TO CONVERT:\n" + script }] }
        ]
      });
      let prompts;
      try {
        const responseText = response.text || "";
        const jsonMatch = responseText.match(/\[[\s\S]*\]/);
        if (!jsonMatch) {
          throw new Error("No JSON array found in response");
        }
        prompts = JSON.parse(jsonMatch[0]);
        if (!Array.isArray(prompts) || prompts.length === 0) {
          throw new Error("Invalid prompts array");
        }
      } catch (parseError) {
        console.error("[Script-to-Prompts] Failed to parse Gemini response:", parseError);
        return res.status(500).json({
          error: "Failed to parse AI response",
          message: parseError instanceof Error ? parseError.message : "Unknown error"
        });
      }
      console.log(`[Script-to-Prompts] Generated ${prompts.length} image prompts`);
      res.json({
        success: true,
        prompts,
        totalScenes: prompts.length
      });
    } catch (error) {
      console.error("Error in /api/script-to-prompts:", error);
      res.status(500).json({
        error: "Failed to convert script to prompts",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  async function generateWithWhisk(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds) {
    const apiUrl = "https://aisandbox-pa.googleapis.com/v1/whisk:generateImage";
    let finalPrompt = prompt;
    if (previousScenePrompt) {
      const simplifiedContext = previousScenePrompt.substring(0, 200).trim();
      finalPrompt = `Continuing from previous scene (${simplifiedContext}...). ${prompt}`;
      console.log(`[Whisk] Added simplified previous scene context for continuity`);
    }
    const requestBody = {
      clientContext: {
        workflowId: "f76a7144-2d6e-436b-9c64-5707bf091ef8",
        tool: "BACKBONE",
        sessionId: `;${Date.now()}`
      },
      imageModelSettings: {
        imageModel: "IMAGEN_3_5",
        aspectRatio
      },
      prompt: finalPrompt,
      mediaCategory: "MEDIA_CATEGORY_BOARD"
    };
    if (referenceMediaIds && referenceMediaIds.length > 0) {
      requestBody.imageInputs = referenceMediaIds.map((mediaId) => ({
        name: mediaId,
        imageInputType: "IMAGE_INPUT_TYPE_REFERENCE"
      }));
      console.log(`[Whisk] Added ${referenceMediaIds.length} reference images with media IDs`);
    }
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[Whisk] API error ${response.status}:`, errorText);
      throw new Error(`Whisk API returned ${response.status}: ${response.statusText}`);
    }
    const result = await response.json();
    console.log(`[Whisk] Received response from Google AI`);
    let base64Image;
    if (result.imagePanels && result.imagePanels.length > 0) {
      const firstPanel = result.imagePanels[0];
      if (firstPanel.generatedImages && firstPanel.generatedImages.length > 0) {
        const firstImage = firstPanel.generatedImages[0];
        base64Image = firstImage.encodedImage || firstImage.image;
        console.log(`[Whisk] Extracted image from imagePanels structure`);
      }
    }
    if (!base64Image) {
      base64Image = result.encodedImage || result.image?.base64 || result.base64 || result.imageData || result.data;
    }
    if (!base64Image) {
      console.error("[Whisk] No base64 image data in response:", JSON.stringify(result, null, 2));
      throw new Error("No image data received from Whisk API");
    }
    return base64Image;
  }
  async function generateWithGemPix(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds) {
    const projectId = process.env.GEM_PIX_PROJECT_ID || "881d362b-300e-4b8b-aab4-0dab0cf875d8";
    const apiUrl = `https://aisandbox-pa.googleapis.com/v1/projects/${projectId}/flowMedia:batchGenerateImages`;
    let finalPrompt = prompt;
    if (previousScenePrompt) {
      const simplifiedContext = previousScenePrompt.substring(0, 200).trim();
      finalPrompt = `Continuing from previous scene (${simplifiedContext}...). ${prompt}`;
      console.log(`[GEM_PIX] Added simplified previous scene context for continuity`);
    }
    const seed = Math.floor(Math.random() * 1e6);
    const imageInputs = referenceMediaIds && referenceMediaIds.length > 0 ? referenceMediaIds.map((mediaId) => ({
      name: mediaId,
      imageInputType: "IMAGE_INPUT_TYPE_REFERENCE"
    })) : [];
    if (referenceMediaIds && referenceMediaIds.length > 0) {
      console.log(`[GEM_PIX] Added ${referenceMediaIds.length} reference images with media IDs`);
    }
    const requestBody = {
      requests: [{
        clientContext: {
          sessionId: `;${Date.now()}`
        },
        seed,
        imageModelName: "GEM_PIX",
        imageAspectRatio: aspectRatio,
        prompt: finalPrompt,
        imageInputs
      }]
    };
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[GEM_PIX] API error ${response.status}:`, errorText);
      throw new Error(`GEM_PIX API returned ${response.status}: ${response.statusText}`);
    }
    const result = await response.json();
    console.log(`[GEM_PIX] Received response from Google AI`);
    let base64Image;
    if (result.media && result.media.length > 0) {
      const mediaItem = result.media[0];
      if (mediaItem.image?.generatedImage?.encodedImage) {
        base64Image = mediaItem.image.generatedImage.encodedImage;
        console.log(`[GEM_PIX] Extracted base64 from media[0].image.generatedImage.encodedImage`);
      } else if (mediaItem.image) {
        base64Image = mediaItem.image;
        console.log(`[GEM_PIX] Extracted image directly from media[0].image`);
      }
    } else if (result.responses && result.responses.length > 0) {
      const firstResponse = result.responses[0];
      if (firstResponse.generatedImages && firstResponse.generatedImages.length > 0) {
        const firstImage = firstResponse.generatedImages[0];
        base64Image = firstImage.encodedImage || firstImage.image;
        console.log(`[GEM_PIX] Extracted image from batch responses structure`);
      }
    }
    if (!base64Image) {
      console.error("[GEM_PIX] No base64 image data in response:", JSON.stringify(result, null, 2));
      throw new Error("No image data received from GEM_PIX API");
    }
    return base64Image;
  }
  async function generateWithGemPixPro(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds) {
    const projectId = process.env.GEM_PIX_PROJECT_ID || "adc73f1d-c784-4817-8db0-4961c1f0f3ca";
    const apiUrl = `https://aisandbox-pa.googleapis.com/v1/projects/${projectId}/flowMedia:batchGenerateImages`;
    let finalPrompt = prompt;
    if (previousScenePrompt) {
      const simplifiedContext = previousScenePrompt.substring(0, 200).trim();
      finalPrompt = `Continuing from previous scene (${simplifiedContext}...). ${prompt}`;
      console.log(`[GEM_PIX_2] Added simplified previous scene context for continuity`);
    }
    const seed = Math.floor(Math.random() * 1e6);
    const imageInputs = referenceMediaIds && referenceMediaIds.length > 0 ? referenceMediaIds.map((mediaId) => ({
      name: mediaId,
      imageInputType: "IMAGE_INPUT_TYPE_REFERENCE"
    })) : [];
    if (referenceMediaIds && referenceMediaIds.length > 0) {
      console.log(`[GEM_PIX_2] Added ${referenceMediaIds.length} reference images with media IDs`);
    }
    const requestBody = {
      requests: [{
        clientContext: {
          sessionId: `;${Date.now()}`
        },
        seed,
        imageModelName: "GEM_PIX_2",
        imageAspectRatio: aspectRatio,
        prompt: finalPrompt,
        imageInputs
      }]
    };
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[GEM_PIX_2] API error ${response.status}:`, errorText);
      throw new Error(`GEM_PIX_2 API returned ${response.status}: ${response.statusText}`);
    }
    const result = await response.json();
    console.log(`[GEM_PIX_2] Received response from Google AI`);
    let base64Image;
    if (result.media && result.media.length > 0) {
      const mediaItem = result.media[0];
      if (mediaItem.image?.generatedImage?.encodedImage) {
        base64Image = mediaItem.image.generatedImage.encodedImage;
        console.log(`[GEM_PIX_2] Extracted base64 from media[0].image.generatedImage.encodedImage`);
      } else if (mediaItem.image) {
        base64Image = mediaItem.image;
        console.log(`[GEM_PIX_2] Extracted image directly from media[0].image`);
      }
    } else if (result.responses && result.responses.length > 0) {
      const firstResponse = result.responses[0];
      if (firstResponse.generatedImages && firstResponse.generatedImages.length > 0) {
        const firstImage = firstResponse.generatedImages[0];
        base64Image = firstImage.encodedImage || firstImage.image;
        console.log(`[GEM_PIX_2] Extracted image from batch responses structure`);
      }
    }
    if (!base64Image) {
      console.error("[GEM_PIX_2] No base64 image data in response:", JSON.stringify(result, null, 2));
      throw new Error("No image data received from GEM_PIX_2 API");
    }
    return base64Image;
  }
  async function generateWithImagen4(apiKey, prompt, aspectRatio, previousScenePrompt, referenceMediaIds) {
    const projectId = process.env.GEM_PIX_PROJECT_ID || "881d362b-300e-4b8b-aab4-0dab0cf875d8";
    const apiUrl = `https://aisandbox-pa.googleapis.com/v1/projects/${projectId}/flowMedia:batchGenerateImages`;
    let finalPrompt = prompt;
    if (previousScenePrompt) {
      const simplifiedContext = previousScenePrompt.substring(0, 200).trim();
      finalPrompt = `Continuing from previous scene (${simplifiedContext}...). ${prompt}`;
      console.log(`[IMAGEN_4] Added simplified previous scene context for continuity`);
    }
    const seed = Math.floor(Math.random() * 1e6);
    const imageInputs = referenceMediaIds && referenceMediaIds.length > 0 ? referenceMediaIds.map((mediaId) => ({
      name: mediaId,
      imageInputType: "IMAGE_INPUT_TYPE_REFERENCE"
    })) : [];
    if (referenceMediaIds && referenceMediaIds.length > 0) {
      console.log(`[IMAGEN_4] Added ${referenceMediaIds.length} reference images with media IDs`);
    }
    const requestBody = {
      requests: [{
        clientContext: {
          sessionId: `;${Date.now()}`
        },
        seed,
        imageModelName: "IMAGEN_3_5",
        imageAspectRatio: aspectRatio,
        prompt: finalPrompt,
        imageInputs
      }]
    };
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[IMAGEN_4] API error ${response.status}:`, errorText);
      throw new Error(`IMAGEN_4 API returned ${response.status}: ${response.statusText}`);
    }
    const result = await response.json();
    console.log(`[IMAGEN_4] Received response from Google AI`);
    let base64Image;
    if (result.media && result.media.length > 0) {
      const mediaItem = result.media[0];
      if (mediaItem.image?.generatedImage?.encodedImage) {
        base64Image = mediaItem.image.generatedImage.encodedImage;
        console.log(`[IMAGEN_4] Extracted base64 from media[0].image.generatedImage.encodedImage`);
      } else if (mediaItem.image) {
        base64Image = mediaItem.image;
        console.log(`[IMAGEN_4] Extracted image directly from media[0].image`);
      }
    } else if (result.responses && result.responses.length > 0) {
      const firstResponse = result.responses[0];
      if (firstResponse.generatedImages && firstResponse.generatedImages.length > 0) {
        const firstImage = firstResponse.generatedImages[0];
        base64Image = firstImage.encodedImage || firstImage.image;
        console.log(`[IMAGEN_4] Extracted image from batch responses structure`);
      }
    }
    if (!base64Image) {
      console.error("[IMAGEN_4] No base64 image data in response:", JSON.stringify(result, null, 2));
      throw new Error("No image data received from IMAGEN_4 API");
    }
    return base64Image;
  }
  app2.post("/api/convert-image-to-media-id", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const schema = z2.object({
        imageBase64: z2.string().min(1, "Image data is required"),
        imageMimeType: z2.string().min(1, "MIME type is required"),
        tokenIndex: z2.number().optional()
        // For batch mode: ensures different token per request
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { imageBase64, imageMimeType, tokenIndex } = validationResult.data;
      console.log(`[Image to Media ID] Converting image (${imageMimeType}), tokenIndex: ${tokenIndex ?? "auto"}`);
      let rotationToken;
      if (tokenIndex !== void 0) {
        rotationToken = await storage.getTokenByIndex(tokenIndex);
        console.log(`[Image to Media ID] Batch mode - using token index ${tokenIndex}`);
      } else {
        rotationToken = await storage.getNextRotationToken();
      }
      const apiKey = rotationToken?.token || process.env.GEMINI_API_KEY;
      const tokenId = rotationToken?.id;
      if (!apiKey) {
        return res.status(500).json({
          error: "No API key configured for image upload"
        });
      }
      console.log(`[Image to Media ID] Using token: ${rotationToken?.label || "ENV"} (ID: ${tokenId || "N/A"})`);
      const uploadPayload = {
        imageInput: {
          rawImageBytes: imageBase64,
          mimeType: imageMimeType
        }
      };
      const uploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(uploadPayload)
      });
      if (!uploadResponse.ok) {
        const errorText = await uploadResponse.text();
        console.error(`[Image to Media ID] Upload failed: ${errorText}`);
        return res.status(500).json({
          error: "Failed to upload image to Google AI",
          details: errorText
        });
      }
      const uploadData = await uploadResponse.json();
      const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
      if (!mediaId) {
        console.error("[Image to Media ID] No media ID in response:", uploadData);
        return res.status(500).json({
          error: "No media ID returned from upload"
        });
      }
      console.log(`[Image to Media ID] Success! Media ID: ${mediaId}, Token ID: ${tokenId}`);
      res.json({
        mediaId,
        tokenId: tokenId || null,
        tokenLabel: rotationToken?.label || "ENV",
        success: true
      });
    } catch (error) {
      console.error("Error in /api/convert-image-to-media-id:", error);
      res.status(500).json({
        error: "Failed to convert image to media ID",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/text-to-image", requireAuth, async (req, res) => {
    let rotationToken;
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "textToImage");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const schema = z2.object({
        prompt: z2.string().min(3, "Prompt must be at least 3 characters"),
        aspectRatio: z2.enum(["IMAGE_ASPECT_RATIO_LANDSCAPE", "IMAGE_ASPECT_RATIO_PORTRAIT", "IMAGE_ASPECT_RATIO_SQUARE"]).default("IMAGE_ASPECT_RATIO_LANDSCAPE"),
        previousScenePrompt: z2.string().optional(),
        model: z2.enum(["whisk", "nanoBana", "nanoBanaPro", "imagen4"]).default("whisk"),
        referenceMediaId: z2.string().optional(),
        // Legacy: single media ID
        referenceMediaIds: z2.array(z2.string()).max(5).optional(),
        // New: multiple media IDs
        tokenId: z2.string().optional()
        // For token consistency - use the same token that generated the media ID
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { prompt, aspectRatio, previousScenePrompt, model, referenceMediaId, referenceMediaIds, tokenId } = validationResult.data;
      const mediaIds = referenceMediaIds && referenceMediaIds.length > 0 ? referenceMediaIds : referenceMediaId ? [referenceMediaId] : void 0;
      console.log(`[Text to Image] User: ${user.username}, Plan: ${user.planType}, Model: ${model}, Aspect Ratio: ${aspectRatio}, Prompt: ${prompt}`);
      if (previousScenePrompt) {
        console.log(`[Text to Image] Previous scene prompt: ${previousScenePrompt}`);
      }
      if (mediaIds && mediaIds.length > 0) {
        console.log(`[Text to Image] ${mediaIds.length} reference media IDs provided`);
      }
      if (tokenId) {
        console.log(`[Text to Image] Using specific token ID for consistency: ${tokenId}`);
      }
      if (tokenId) {
        const specificToken = await storage.getTokenById(tokenId);
        if (specificToken && specificToken.isActive) {
          rotationToken = specificToken;
          console.log(`[Token Consistency] Using matched token: ${specificToken.label} (ID: ${specificToken.id})`);
        } else {
          console.log(`[Token Consistency] Specified token ${tokenId} not found or inactive, falling back to rotation`);
          rotationToken = await storage.getNextRotationToken();
        }
      } else {
        rotationToken = await storage.getNextRotationToken();
      }
      if (rotationToken) {
        console.log(`[Token Rotation] Using initial token: ${rotationToken.label} (ID: ${rotationToken.id})`);
        await storage.updateTokenUsage(rotationToken.id);
      } else {
        console.log("[Token Rotation] No active tokens found, will use environment variable if available");
      }
      const result = await retryTextToImageGeneration(
        prompt,
        aspectRatio,
        previousScenePrompt,
        model,
        generateWithWhisk,
        generateWithGemPix,
        generateWithGemPixPro,
        generateWithImagen4,
        10,
        rotationToken,
        mediaIds
      );
      if (!result.success) {
        throw new Error(result.error);
      }
      const base64Image = result.base64Image;
      rotationToken = result.token;
      const extension = "png";
      const dataUrl = `data:image/${extension};base64,${base64Image}`;
      console.log(`[Text to Image] Image generated successfully (no Cloudinary upload)`);
      res.json({
        imageUrl: dataUrl,
        prompt,
        aspectRatio,
        model,
        tokenUsed: rotationToken?.label,
        success: true
      });
    } catch (error) {
      console.error("Error in /api/text-to-image:", error);
      res.status(500).json({
        error: "Failed to generate image",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/text-to-image/batch", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "textToImage");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const schema = z2.object({
        prompts: z2.array(z2.string().min(3)).min(1).max(50),
        aspectRatio: z2.enum(["IMAGE_ASPECT_RATIO_LANDSCAPE", "IMAGE_ASPECT_RATIO_PORTRAIT", "IMAGE_ASPECT_RATIO_SQUARE"]).default("IMAGE_ASPECT_RATIO_LANDSCAPE"),
        model: z2.enum(["whisk", "nanoBana", "nanoBanaPro", "imagen4"]).default("nanoBana"),
        referenceImageBase64: z2.string().optional(),
        // Legacy: single image
        referenceImageMimeType: z2.string().optional(),
        referenceImagesData: z2.array(z2.object({
          base64: z2.string(),
          mimeType: z2.string()
        })).max(5).optional(),
        // New: multiple images
        isRetry: z2.boolean().optional().default(false)
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({ error: "Invalid input", details: validationResult.error.errors });
      }
      const { prompts, aspectRatio, model, referenceImageBase64, referenceImageMimeType, referenceImagesData, isRetry } = validationResult.data;
      const refImages = referenceImagesData && referenceImagesData.length > 0 ? referenceImagesData : referenceImageBase64 && referenceImageMimeType ? [{ base64: referenceImageBase64, mimeType: referenceImageMimeType }] : [];
      const tokenOffset = isRetry ? Math.floor(Math.random() * 1e3) : 0;
      console.log(`[Batch Text-to-Image] Starting batch of ${prompts.length} images, Model: ${model}, User: ${user.username}${isRetry ? " (RETRY with offset " + tokenOffset + ")" : ""}`);
      const batchStartTime = Date.now();
      const activeTokens = await storage.getActiveApiTokens();
      if (activeTokens.length === 0) {
        return res.status(500).json({ error: "No active API tokens available" });
      }
      console.log(`[Batch Text-to-Image] Using ${activeTokens.length} active tokens for distribution`);
      let mediaIdDataList = [];
      if (refImages.length > 0 && model !== "whisk") {
        console.log(`[Batch Phase 1] Generating media IDs for ${prompts.length} prompts with ${refImages.length} reference images each...`);
        const mediaIdPromises = prompts.map(async (_, promptIndex) => {
          const token = activeTokens[(promptIndex + tokenOffset) % activeTokens.length];
          console.log(`[Phase 1] Prompt ${promptIndex}: Using Token ${token.label} (ID: ${token.id}) for ALL ${refImages.length} media ID uploads`);
          try {
            const uploadPromises = refImages.map(async (refImage, imgIndex) => {
              const uploadPayload = {
                imageInput: {
                  rawImageBytes: refImage.base64,
                  mimeType: refImage.mimeType
                }
              };
              const uploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
                method: "POST",
                headers: {
                  "Authorization": `Bearer ${token.token}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify(uploadPayload)
              });
              if (uploadResponse.ok) {
                const uploadData = await uploadResponse.json();
                const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
                console.log(`[Phase 1] Prompt ${promptIndex} Image ${imgIndex}: MediaID generated with Token ${token.label}`);
                return mediaId;
              }
              console.error(`[Phase 1] Prompt ${promptIndex} Image ${imgIndex} failed: ${uploadResponse.status}`);
              return null;
            });
            const mediaIds = (await Promise.all(uploadPromises)).filter((id) => id !== null);
            if (mediaIds.length > 0) {
              console.log(`[Phase 1] Prompt ${promptIndex}: Generated ${mediaIds.length}/${refImages.length} media IDs with SAME Token ${token.label}`);
              return { mediaIds, token, promptIndex };
            }
            return null;
          } catch (error) {
            console.error(`[Batch Phase 1] Prompt ${promptIndex} error:`, error);
            return null;
          }
        });
        const results2 = await Promise.all(mediaIdPromises);
        mediaIdDataList = results2.filter((r) => r !== null);
        console.log(`[Batch Phase 1] Generated media IDs for ${mediaIdDataList.length}/${prompts.length} prompts`);
      }
      console.log(`[Batch Phase 2] Generating ${prompts.length} images in parallel...`);
      const generateSingleImage = async (prompt, index2) => {
        const mediaIdData = mediaIdDataList.find((m) => m.promptIndex === index2);
        const token = mediaIdData?.token || activeTokens[(index2 + tokenOffset) % activeTokens.length];
        const referenceMediaIds = mediaIdData?.mediaIds || [];
        try {
          const result = await retryTextToImageGeneration(
            prompt,
            aspectRatio,
            void 0,
            // previousScenePrompt
            model,
            generateWithWhisk,
            generateWithGemPix,
            generateWithGemPixPro,
            generateWithImagen4,
            3,
            // Max 3 retries per image in batch mode
            token,
            referenceMediaIds.length > 0 ? referenceMediaIds : void 0
          );
          if (result.success) {
            const dataUrl = `data:image/png;base64,${result.base64Image}`;
            return { prompt, status: "success", imageUrl: dataUrl, tokenUsed: token.label };
          }
          return { prompt, status: "failed", error: result.error, tokenUsed: token.label };
        } catch (error) {
          return { prompt, status: "failed", error: error.message || "Unknown error", tokenUsed: token.label };
        }
      };
      const imagePromises = prompts.map((prompt, index2) => generateSingleImage(prompt.trim(), index2));
      const batchResults = await Promise.allSettled(imagePromises);
      const results = batchResults.map((result, index2) => {
        if (result.status === "fulfilled") {
          return result.value;
        }
        return { prompt: prompts[index2], status: "failed", error: result.reason?.message || "Unknown error" };
      });
      const successCount = results.filter((r) => r.status === "success").length;
      const failedCount = results.filter((r) => r.status === "failed").length;
      const duration = ((Date.now() - batchStartTime) / 1e3).toFixed(1);
      console.log(`[Batch Complete] ${successCount}/${prompts.length} succeeded, ${failedCount} failed, Duration: ${duration}s`);
      res.json({
        success: true,
        results,
        summary: {
          total: prompts.length,
          success: successCount,
          failed: failedCount,
          duration: `${duration}s`
        }
      });
    } catch (error) {
      console.error("Error in /api/text-to-image/batch:", error);
      res.status(500).json({
        error: "Batch generation failed",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/text-to-image/batch-stream", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "textToImage");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const schema = z2.object({
        prompts: z2.array(z2.string().min(3)).min(1).max(50),
        aspectRatio: z2.enum(["IMAGE_ASPECT_RATIO_LANDSCAPE", "IMAGE_ASPECT_RATIO_PORTRAIT", "IMAGE_ASPECT_RATIO_SQUARE"]).default("IMAGE_ASPECT_RATIO_LANDSCAPE"),
        model: z2.enum(["whisk", "nanoBana", "nanoBanaPro", "imagen4"]).default("nanoBana"),
        referenceImageBase64: z2.string().optional(),
        referenceImageMimeType: z2.string().optional(),
        referenceImagesData: z2.array(z2.object({
          base64: z2.string(),
          mimeType: z2.string()
        })).max(5).optional(),
        isRetry: z2.boolean().optional().default(false)
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({ error: "Invalid input", details: validationResult.error.errors });
      }
      const { prompts, aspectRatio, model, referenceImageBase64, referenceImageMimeType, referenceImagesData, isRetry } = validationResult.data;
      const tokenOffset = isRetry ? Math.floor(Math.random() * 1e3) : 0;
      console.log(`[Batch Stream] Starting streaming batch of ${prompts.length} images, Model: ${model}, User: ${user.username}`);
      const batchStartTime = Date.now();
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.setHeader("Transfer-Encoding", "chunked");
      if (res.socket) {
        res.socket.setNoDelay(true);
        res.socket.setTimeout(0);
      }
      res.flushHeaders();
      const sendEvent = (event, data) => {
        const eventStr = `event: ${event}
data: ${JSON.stringify(data)}

`;
        res.write(eventStr);
        console.log(`[SSE] Sent ${event} event, index: ${data.index ?? "N/A"}`);
      };
      const activeTokens = await storage.getActiveApiTokens();
      if (activeTokens.length === 0) {
        sendEvent("error", { error: "No active API tokens available" });
        res.end();
        return;
      }
      let mediaIdDataList = [];
      const refImages = referenceImagesData && referenceImagesData.length > 0 ? referenceImagesData : referenceImageBase64 && referenceImageMimeType ? [{ base64: referenceImageBase64, mimeType: referenceImageMimeType }] : [];
      if (refImages.length > 0 && model !== "whisk") {
        console.log(`[Batch Stream Phase 1] Generating media IDs for ${prompts.length} prompts with ${refImages.length} reference images each...`);
        sendEvent("phase", { phase: "mediaIds", message: `Preparing ${refImages.length} reference images...` });
        const mediaIdPromises = prompts.map(async (_, promptIndex) => {
          const token = activeTokens[(promptIndex + tokenOffset) % activeTokens.length];
          console.log(`[Phase 1] Prompt ${promptIndex}: Using Token ${token.label} (ID: ${token.id}) for ALL ${refImages.length} media ID uploads`);
          const mediaIds = [];
          for (let imgIndex = 0; imgIndex < refImages.length; imgIndex++) {
            const refImg = refImages[imgIndex];
            try {
              const uploadPayload = {
                imageInput: {
                  rawImageBytes: refImg.base64,
                  mimeType: refImg.mimeType
                }
              };
              const uploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
                method: "POST",
                headers: {
                  "Authorization": `Bearer ${token.token}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify(uploadPayload)
              });
              if (uploadResponse.ok) {
                const uploadData = await uploadResponse.json();
                const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
                console.log(`[Phase 1] Prompt ${promptIndex}, Image ${imgIndex + 1}: Media ID created with Token ${token.label}`);
                mediaIds.push(mediaId);
              } else {
                console.log(`[Phase 1] Prompt ${promptIndex}, Image ${imgIndex + 1}: Upload failed with Token ${token.label}`);
              }
            } catch (error) {
              console.log(`[Phase 1] Prompt ${promptIndex}, Image ${imgIndex + 1}: Upload error:`, error);
            }
          }
          if (mediaIds.length > 0) {
            console.log(`[Phase 1] Prompt ${promptIndex}: Created ${mediaIds.length}/${refImages.length} media IDs with Token ${token.label}`);
            return { mediaIds, token, promptIndex };
          }
          return null;
        });
        const results = await Promise.all(mediaIdPromises);
        mediaIdDataList = results.filter((r) => r !== null);
      }
      sendEvent("phase", { phase: "generation", message: "Generating images..." });
      let successCount = 0;
      let failedCount = 0;
      const generateAndStream = async (prompt, index2) => {
        const mediaIdData = mediaIdDataList.find((m) => m.promptIndex === index2);
        const token = mediaIdData?.token || activeTokens[(index2 + tokenOffset) % activeTokens.length];
        const referenceMediaIds = mediaIdData?.mediaIds || [];
        if (mediaIdData?.token) {
          console.log(`[Phase 2] Prompt ${index2}: Using SAME Token ${token.label} (ID: ${token.id}) from Phase 1 - Has ${referenceMediaIds.length} mediaIds`);
        } else {
          console.log(`[Phase 2] Prompt ${index2}: Using FALLBACK Token ${token.label} (ID: ${token.id}) - No mediaIdData found`);
        }
        try {
          const result = await retryTextToImageGeneration(
            prompt,
            aspectRatio,
            void 0,
            model,
            generateWithWhisk,
            generateWithGemPix,
            generateWithGemPixPro,
            generateWithImagen4,
            3,
            token,
            referenceMediaIds.length > 0 ? referenceMediaIds : void 0
          );
          if (result.success) {
            const dataUrl = `data:image/png;base64,${result.base64Image}`;
            successCount++;
            sendEvent("image", {
              index: index2,
              prompt,
              status: "success",
              imageUrl: dataUrl,
              progress: { current: successCount + failedCount, total: prompts.length }
            });
          } else {
            failedCount++;
            sendEvent("image", {
              index: index2,
              prompt,
              status: "failed",
              error: result.error,
              progress: { current: successCount + failedCount, total: prompts.length }
            });
          }
        } catch (error) {
          failedCount++;
          sendEvent("image", {
            index: index2,
            prompt,
            status: "failed",
            error: error.message || "Unknown error",
            progress: { current: successCount + failedCount, total: prompts.length }
          });
        }
      };
      const staggerDelay = 30;
      const staggeredPromises = prompts.map((prompt, index2) => {
        return new Promise((resolve) => {
          setTimeout(async () => {
            await generateAndStream(prompt.trim(), index2);
            resolve();
          }, index2 * staggerDelay);
        });
      });
      await Promise.all(staggeredPromises);
      const duration = ((Date.now() - batchStartTime) / 1e3).toFixed(1);
      console.log(`[Batch Stream Complete] ${successCount}/${prompts.length} succeeded in ${duration}s`);
      sendEvent("complete", {
        success: true,
        summary: {
          total: prompts.length,
          success: successCount,
          failed: failedCount,
          duration: `${duration}s`
        }
      });
      res.end();
    } catch (error) {
      console.error("Error in /api/text-to-image/batch-stream:", error);
      res.write(`event: error
data: ${JSON.stringify({ error: "Batch generation failed" })}

`);
      res.end();
    }
  });
  app2.post("/api/generate-veo-video", requireAuth, async (req, res) => {
    let rotationToken;
    try {
      const schema = z2.object({
        prompt: z2.string().min(10, "Prompt must be at least 10 characters"),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { prompt, aspectRatio } = validationResult.data;
      const user = await storage.getUser(req.session.userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "veo");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const videoCheck = canGenerateVideo(user);
      if (!videoCheck.allowed) {
        return res.status(403).json({ error: videoCheck.reason });
      }
      console.log(`[VEO Direct] Request received - User: ${user.username}, Aspect Ratio: ${aspectRatio}, Prompt: ${prompt}`);
      let apiKey;
      rotationToken = await storage.getNextRotationToken();
      if (rotationToken) {
        apiKey = rotationToken.token;
        console.log(`[Token Rotation] Using token: ${rotationToken.label} (ID: ${rotationToken.id})`);
        await storage.updateTokenUsage(rotationToken.id);
      } else {
        apiKey = process.env.VEO3_API_KEY;
        console.log("[Token Rotation] No active tokens found, using environment variable VEO3_API_KEY");
      }
      if (!apiKey) {
        return res.status(500).json({
          error: "No API key configured. Please add tokens in the admin panel or set VEO3_API_KEY environment variable."
        });
      }
      const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
      const sceneId = `veo-${Date.now()}`;
      const seed = Math.floor(Math.random() * 1e5);
      const payload = {
        clientContext: {
          projectId: veoProjectId,
          tool: "PINHOLE",
          userPaygateTier: "PAYGATE_TIER_TWO"
        },
        requests: [{
          aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
          seed,
          textInput: {
            prompt
          },
          videoModelKey: aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
          metadata: {
            sceneId
          }
        }]
      };
      console.log(`[VEO Direct] === TEXT-TO-VIDEO GENERATION (with Auto-Retry) ===`);
      console.log(`[VEO Direct] User: ${user.username} (Plan: ${user.planType})`);
      console.log(`[VEO Direct] Scene ID: ${sceneId}`);
      console.log(`[VEO Direct] Aspect Ratio: ${aspectRatio} (${aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE"})`);
      console.log(`[VEO Direct] Video Model: ${aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra"}`);
      console.log(`[VEO Direct] Seed: ${seed}`);
      console.log(`[VEO Direct] Prompt: "${prompt}"`);
      console.log(`[VEO Direct] Initial Token: ${rotationToken?.label || "Environment Variable"} (ID: ${rotationToken?.id || "N/A"})`);
      console.log(`[VEO Direct] Full Payload:`, JSON.stringify(payload, null, 2));
      const result = await retryVeoGeneration(payload, 20, rotationToken);
      if (!result.success) {
        throw new Error(result.error);
      }
      const operationName = result.data.operations[0].operation.name;
      rotationToken = result.token;
      if (result.data.remainingCredits !== void 0) {
        try {
          await storage.addCreditsSnapshot(result.data.remainingCredits, "veo_generation", rotationToken?.id);
        } catch (error) {
          console.error("[Credits Snapshot] Failed to record:", error);
        }
      }
      res.json({
        operationName,
        sceneId,
        status: "PENDING",
        tokenId: rotationToken?.id || null,
        remainingCredits: result.data.remainingCredits
      });
    } catch (error) {
      console.error("Error in /api/generate-veo-video:", error);
      res.status(500).json({
        error: "Failed to start video generation",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/start-video-generation", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const schema = z2.object({
        prompt: z2.string().min(1, "Prompt is required"),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid request",
          details: validationResult.error.errors.map((e) => e.message).join(", ")
        });
      }
      const { prompt, aspectRatio } = validationResult.data;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "veo");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const videoCheck = canGenerateVideo(user);
      if (!videoCheck.allowed) {
        return res.status(403).json({ error: videoCheck.reason });
      }
      const activeTokens = await storage.getActiveApiTokens();
      if (!activeTokens || activeTokens.length === 0) {
        return res.status(500).json({
          error: "No active API tokens available. Please add API Tokens in admin settings."
        });
      }
      const videoEntry = await storage.addVideoHistory({
        userId: String(user.id),
        prompt,
        aspectRatio,
        status: "pending",
        title: `VEO ${aspectRatio} video`
      });
      console.log(`[Background Video] Created video entry ${videoEntry.id} - starting background generation with Whisk API`);
      startBackgroundVideoGeneration(
        videoEntry.id,
        prompt,
        aspectRatio,
        void 0,
        void 0,
        user.id
      );
      res.json({
        success: true,
        videoId: videoEntry.id,
        message: "Video generation started. Poll /api/video-status/:id for updates."
      });
    } catch (error) {
      console.error("Error in /api/start-video-generation:", error);
      res.status(500).json({
        error: "Failed to start video generation",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/video-status/:id", requireAuth, async (req, res) => {
    try {
      const videoId = req.params.id;
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const jobStatus = getJobStatus(videoId);
      if (jobStatus) {
        const response = {
          videoId: jobStatus.videoId,
          status: jobStatus.status,
          error: jobStatus.error,
          elapsedSeconds: Math.floor((Date.now() - jobStatus.startedAt) / 1e3)
        };
        if (jobStatus.videoData) {
          response.videoData = jobStatus.videoData;
          console.log(`[API] Returning direct video data (${(jobStatus.videoData.length / 1024 / 1024).toFixed(2)}MB) for video ${videoId}`);
        } else if (jobStatus.videoUrl) {
          response.videoUrl = jobStatus.videoUrl;
        }
        return res.json(response);
      }
      const video = await storage.getVideoById(videoId);
      if (!video) {
        return res.status(404).json({ error: "Video not found" });
      }
      if (video.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      res.json({
        videoId: video.id,
        status: video.status,
        videoUrl: video.videoUrl,
        error: video.errorMessage,
        prompt: video.prompt,
        aspectRatio: video.aspectRatio
      });
    } catch (error) {
      console.error("Error in /api/video-status:", error);
      res.status(500).json({ error: "Failed to get video status" });
    }
  });
  app2.post("/api/generate-image-to-video", requireAuth, requireAdmin, async (req, res) => {
    let rotationToken;
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "imageToVideo");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const videoCheck = canGenerateVideo(user);
      if (!videoCheck.allowed) {
        return res.status(403).json({ error: videoCheck.reason });
      }
      const schema = z2.object({
        imageBase64: z2.string().min(100, "Image data required"),
        mimeType: z2.string().default("image/jpeg"),
        prompt: z2.string().min(10, "Prompt must be at least 10 characters"),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { imageBase64, mimeType, prompt, aspectRatio } = validationResult.data;
      console.log(`[Image to Video] User: ${user.username}, Plan: ${user.planType}, Request received - Aspect Ratio: ${aspectRatio}`);
      rotationToken = await storage.getNextRotationToken();
      if (!rotationToken) {
        return res.status(500).json({
          error: "No API tokens configured. Please add tokens in the admin panel."
        });
      }
      console.log(`[Token Rotation] Using initial token: ${rotationToken.label} (ID: ${rotationToken.id})`);
      await storage.updateTokenUsage(rotationToken.id);
      const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
      const sceneId = crypto3.randomUUID();
      const sessionId = `;${Date.now()}`;
      const seed = Math.floor(Math.random() * 1e5);
      const videoPayload = {
        clientContext: {
          sessionId,
          projectId: veoProjectId,
          tool: "PINHOLE",
          userPaygateTier: "PAYGATE_TIER_TWO"
        },
        requests: [{
          aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
          seed,
          textInput: {
            prompt
          },
          videoModelKey: aspectRatio === "portrait" ? "veo_3_1_i2v_s_fast_portrait_ultra" : "veo_3_1_i2v_s_fast_ultra",
          startImage: {
            mediaId: ""
            // Will be filled by retry function
          },
          metadata: {
            sceneId
          }
        }]
      };
      console.log(`[Image to Video] === IMAGE-TO-VIDEO GENERATION (VEO 3.1 with Auto-Retry) ===`);
      console.log(`[Image to Video] User: ${user.username} (Plan: ${user.planType})`);
      console.log(`[Image to Video] Scene ID: ${sceneId}`);
      console.log(`[Image to Video] Session ID: ${sessionId}`);
      console.log(`[Image to Video] Seed: ${seed}`);
      console.log(`[Image to Video] Aspect Ratio: ${aspectRatio} (${aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE"})`);
      console.log(`[Image to Video] Video Model: ${aspectRatio === "portrait" ? "veo_3_1_i2v_s_fast_portrait_ultra" : "veo_3_1_i2v_s_fast_ultra"}`);
      console.log(`[Image to Video] Prompt: "${prompt}"`);
      console.log(`[Image to Video] Initial Token: ${rotationToken?.label || "N/A"} (ID: ${rotationToken?.id || "N/A"})`);
      const result = await retryImageToVideoGeneration(imageBase64, mimeType, videoPayload, 20, rotationToken);
      if (!result.success) {
        throw new Error(result.error);
      }
      const videoData = result.data;
      const mediaGenId = result.mediaGenId;
      rotationToken = result.token;
      const operationName = videoData.operations?.[0]?.operation?.name;
      console.log(`[Image to Video] \u2705 Video generation started. Operation: ${operationName}`);
      const imageExtension = mimeType.includes("jpeg") ? "jpg" : "png";
      const referenceImageUrl = `data:image/${imageExtension};base64,${imageBase64}`;
      const historyEntry = await storage.addVideoHistory({
        userId,
        prompt,
        aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
        status: "pending",
        title: `Image to Video ${aspectRatio}`,
        tokenUsed: rotationToken?.id,
        referenceImageUrl
        // Store reference image URL
      });
      if (videoData.remainingCredits !== void 0) {
        try {
          await storage.addCreditsSnapshot(videoData.remainingCredits, "image_to_video", rotationToken?.id);
        } catch (error) {
          console.error("[Credits Snapshot] Failed to record:", error);
        }
      }
      res.json({
        operationName,
        sceneId,
        status: "PENDING",
        tokenId: rotationToken?.id || null,
        historyId: historyEntry.id,
        remainingCredits: videoData.remainingCredits
      });
    } catch (error) {
      console.error("Error in /api/generate-image-to-video:", error);
      await handleTokenError(rotationToken?.id, error);
      const userFriendlyError = "Video generation failed due to content policy. Your image may contain children, celebrities, copyrighted characters, inappropriate content, or other material that violates Google's content guidelines. Please try with a different image.";
      res.status(500).json({
        error: userFriendlyError
      });
    }
  });
  app2.post("/api/regenerate-video", requireAuth, async (req, res) => {
    let rotationToken;
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const schema = z2.object({
        videoId: z2.string(),
        prompt: z2.string().min(10, "Prompt must be at least 10 characters"),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape"),
        projectId: z2.string().optional(),
        sceneNumber: z2.number().optional()
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { videoId, prompt, aspectRatio, projectId, sceneNumber } = validationResult.data;
      const existingVideo = await storage.getVideoById(videoId);
      if (existingVideo?.metadata && typeof existingVideo.metadata === "object" && "mergedVideoIds" in existingVideo.metadata) {
        return res.status(400).json({
          error: "Merged videos cannot be regenerated. Please generate individual videos instead."
        });
      }
      const updatedVideo = await storage.updateVideoHistoryStatus(videoId, userId, "pending");
      if (!updatedVideo) {
        return res.status(404).json({
          error: "Video not found or you don't have permission to regenerate it"
        });
      }
      let apiKey;
      if (sceneNumber !== void 0 && sceneNumber > 0) {
        rotationToken = await storage.getTokenByIndex(sceneNumber - 1);
        if (rotationToken) {
          apiKey = rotationToken.token;
          console.log(`[Token Rotation] Using token ${rotationToken.label} for video ${sceneNumber} (round-robin)`);
          await storage.updateTokenUsage(rotationToken.id);
        }
      } else {
        rotationToken = await storage.getNextRotationToken();
        if (rotationToken) {
          apiKey = rotationToken.token;
          console.log(`[Token Rotation] Using token: ${rotationToken.label} (ID: ${rotationToken.id})`);
          await storage.updateTokenUsage(rotationToken.id);
        }
      }
      if (!apiKey) {
        apiKey = process.env.VEO3_API_KEY;
        console.log("[Token Rotation] No active tokens found, using environment variable VEO3_API_KEY");
      }
      if (!apiKey) {
        return res.status(500).json({
          error: "No API key configured. Please add tokens in the admin panel or set VEO3_API_KEY environment variable."
        });
      }
      const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
      const seed = Math.floor(Math.random() * 1e5);
      const isCharacterVideo = existingVideo?.referenceImageUrl ? true : false;
      let veoResponse;
      let payload;
      let data;
      let finalSceneId = `regenerate-${videoId}-${Date.now()}`;
      if (isCharacterVideo && existingVideo?.referenceImageUrl) {
        console.log(`[VEO Regenerate] Character video detected - using reference image API with token rotation`);
        const imageUrl = existingVideo.referenceImageUrl;
        let lastError = "";
        const MAX_TOKEN_ATTEMPTS = 10;
        let success = false;
        let attemptCount = 0;
        const allTokens = await storage.getAllApiTokens();
        const activeTokens = allTokens.filter((t) => t.isActive);
        if (activeTokens.length === 0) {
          return res.status(500).json({
            error: "No active tokens available for regeneration",
            message: "Please add or enable API tokens in admin panel"
          });
        }
        console.log(`[VEO Regenerate] Found ${activeTokens.length} active tokens to try`);
        const shuffledTokens = [...activeTokens].sort(() => Math.random() - 0.5);
        for (let tokenAttempt = 0; tokenAttempt < Math.min(MAX_TOKEN_ATTEMPTS, shuffledTokens.length) && !success; tokenAttempt++) {
          const currentToken = shuffledTokens[tokenAttempt];
          attemptCount++;
          if (tokenAttempt > 0) {
            const delayMs = 1e3;
            console.log(`[VEO Regenerate] Waiting ${delayMs}ms before next attempt...`);
            await new Promise((resolve) => setTimeout(resolve, delayMs));
          }
          console.log(`[VEO Regenerate] Token attempt ${tokenAttempt + 1}/${Math.min(MAX_TOKEN_ATTEMPTS, shuffledTokens.length)}: ${currentToken.label}`);
          try {
            const uploadPayload = {
              image: { imageUrl },
              mimeType: "image/jpeg"
            };
            console.log(`[VEO Regenerate] Uploading image with token ${currentToken.label}...`);
            const uploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/images:upload", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${currentToken.token}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify(uploadPayload)
            });
            if (!uploadResponse.ok) {
              const uploadText = await uploadResponse.text();
              lastError = `Image upload failed (${uploadResponse.status})`;
              console.log(`[VEO Regenerate] \u26A0\uFE0F ${lastError} with ${currentToken.label} - trying next token...`);
              continue;
            }
            const uploadData = await uploadResponse.json();
            const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
            if (!mediaId) {
              lastError = `No mediaId returned`;
              console.log(`[VEO Regenerate] \u26A0\uFE0F ${lastError} with ${currentToken.label} - trying next token...`);
              continue;
            }
            console.log(`[VEO Regenerate] \u2713 Image uploaded with token ${currentToken.label}, mediaId: ${mediaId}`);
            finalSceneId = `regenerate-${videoId}-${Date.now()}`;
            payload = {
              clientContext: {
                sessionId: `regen-session-${Date.now()}`,
                projectId: veoProjectId,
                tool: "PINHOLE",
                userPaygateTier: "PAYGATE_TIER_TWO"
              },
              requests: [{
                aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                metadata: { sceneId: finalSceneId },
                referenceImages: [
                  { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId },
                  { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId }
                ],
                seed,
                textInput: { prompt },
                videoModelKey: "veo_3_0_r2v_fast_ultra"
              }]
            };
            console.log(`[VEO Regenerate] Generating character video ${videoId} with token ${currentToken.label}`);
            veoResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoReferenceImages", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${currentToken.token}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify(payload)
            });
            data = await veoResponse.json();
            if (!veoResponse.ok || !data.operations || data.operations.length === 0) {
              lastError = data?.error?.message || `API error`;
              console.log(`[VEO Regenerate] \u26A0\uFE0F ${lastError} with ${currentToken.label} - trying next token...`);
              continue;
            }
            rotationToken = currentToken;
            success = true;
            console.log(`[VEO Regenerate] \u2705 Successfully started with token ${currentToken.label}`);
          } catch (tokenError) {
            lastError = tokenError instanceof Error ? tokenError.message : "Unknown error";
            console.log(`[VEO Regenerate] \u26A0\uFE0F Error with token ${currentToken.label}: ${lastError} - trying next token...`);
            continue;
          }
        }
        if (!success) {
          await storage.updateVideoHistoryStatus(videoId, userId, "failed");
          return res.status(500).json({
            error: `Failed after trying ${attemptCount} tokens. API may be temporarily unavailable.`,
            message: lastError
          });
        }
      } else {
        payload = {
          clientContext: {
            projectId: veoProjectId,
            tool: "PINHOLE",
            userPaygateTier: "PAYGATE_TIER_TWO"
          },
          requests: [{
            aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
            seed,
            textInput: { prompt },
            videoModelKey: aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
            metadata: { sceneId: finalSceneId }
          }]
        };
        console.log(`[VEO Regenerate] Regenerating text video ${videoId} (scene ${sceneNumber || "N/A"}) with prompt:`, prompt);
        veoResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload)
        });
        data = await veoResponse.json();
        if (!veoResponse.ok) {
          console.error("[VEO Regenerate] Error response:", data);
          await storage.updateVideoHistoryStatus(videoId, userId, "failed");
          const responseError = new Error(data?.error?.message || "VEO API error");
          await handleTokenError(rotationToken?.id, responseError);
          return res.status(500).json({
            error: "VEO API error",
            details: data
          });
        }
        if (!data.operations || data.operations.length === 0) {
          await storage.updateVideoHistoryStatus(videoId, userId, "failed");
          await handleTokenError(rotationToken?.id, new Error("No operations returned from VEO API"));
          return res.status(500).json({ error: "No operations returned from VEO API" });
        }
      }
      const operation = data.operations[0];
      const operationName = operation.operation.name;
      console.log(`[VEO Regenerate] Started regeneration - Operation: ${operationName}, Scene ID: ${finalSceneId}`);
      if (rotationToken) {
        try {
          await storage.updateVideoHistoryFields(videoId, { tokenUsed: rotationToken.id });
        } catch (err) {
          console.error("Failed to update video history with token ID:", err);
        }
      }
      (async () => {
        try {
          let completed = false;
          let attempts = 0;
          const maxAttempts = 120;
          const retryAttempt = 16;
          let currentOperationName = operationName;
          let currentSceneId = finalSceneId;
          let currentApiKey = apiKey;
          let currentRotationToken = rotationToken;
          let hasRetriedWithNewToken = false;
          while (!completed && attempts < maxAttempts) {
            await new Promise((resolve) => setTimeout(resolve, 15e3));
            attempts++;
            if (attempts === retryAttempt && !completed && !hasRetriedWithNewToken) {
              console.log(`[VEO Regenerate] Video ${videoId} not completed after 4 minutes, trying with next API token...`);
              if (currentRotationToken) {
                storage.recordTokenError(currentRotationToken.id);
              }
              try {
                const nextToken = await storage.getNextRotationToken();
                if (nextToken && nextToken.id !== currentRotationToken?.id) {
                  console.log(`[Token Rotation] Switching to next token: ${nextToken.label} (ID: ${nextToken.id})`);
                  currentApiKey = nextToken.token;
                  currentRotationToken = nextToken;
                  await storage.updateTokenUsage(nextToken.id);
                  let retryResponse;
                  let newPayload;
                  const retrySceneId = `retry-${videoId}-${Date.now()}`;
                  if (isCharacterVideo && existingVideo?.referenceImageUrl) {
                    console.log(`[VEO Regenerate] Character video retry - using reference image API`);
                    const uploadPayload = {
                      image: { imageUrl: existingVideo.referenceImageUrl },
                      mimeType: "image/jpeg"
                    };
                    const uploadResp = await fetch("https://aisandbox-pa.googleapis.com/v1/images:upload", {
                      method: "POST",
                      headers: {
                        "Authorization": `Bearer ${currentApiKey}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify(uploadPayload)
                    });
                    if (uploadResp.ok) {
                      const uploadData = await uploadResp.json();
                      const retryMediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
                      if (retryMediaId) {
                        newPayload = {
                          clientContext: {
                            sessionId: `retry-session-${Date.now()}`,
                            projectId: process.env.VEO3_PROJECT_ID || "06ad4933-483d-4ef6-b1d9-7a8bc21219cb",
                            tool: "PINHOLE",
                            userPaygateTier: "PAYGATE_TIER_TWO"
                          },
                          requests: [{
                            aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                            metadata: { sceneId: retrySceneId },
                            referenceImages: [
                              { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId: retryMediaId },
                              { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId: retryMediaId }
                            ],
                            seed: Math.floor(Math.random() * 1e5),
                            textInput: { prompt },
                            videoModelKey: "veo_3_0_r2v_fast_ultra"
                          }]
                        };
                        retryResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoReferenceImages", {
                          method: "POST",
                          headers: {
                            "Authorization": `Bearer ${currentApiKey}`,
                            "Content-Type": "application/json"
                          },
                          body: JSON.stringify(newPayload)
                        });
                      } else {
                        throw new Error("No mediaId from retry upload");
                      }
                    } else {
                      throw new Error("Retry image upload failed");
                    }
                  } else {
                    newPayload = {
                      clientContext: {
                        projectId: process.env.VEO3_PROJECT_ID || "06ad4933-483d-4ef6-b1d9-7a8bc21219cb",
                        tool: "PINHOLE",
                        userPaygateTier: "PAYGATE_TIER_TWO"
                      },
                      requests: [{
                        aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                        seed: Math.floor(Math.random() * 1e5),
                        textInput: { prompt },
                        videoModelKey: aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                        metadata: { sceneId: retrySceneId }
                      }]
                    };
                    retryResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
                      method: "POST",
                      headers: {
                        "Authorization": `Bearer ${currentApiKey}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify(newPayload)
                    });
                  }
                  const retryData = await retryResponse.json();
                  if (retryResponse.ok && retryData.operations && retryData.operations.length > 0) {
                    currentOperationName = retryData.operations[0].operation.name;
                    currentSceneId = retrySceneId;
                    hasRetriedWithNewToken = true;
                    await storage.updateVideoHistoryFields(videoId, { tokenUsed: nextToken.id });
                    console.log(`[VEO Regenerate] Retrying video ${videoId} with new token - Operation: ${currentOperationName}`);
                  } else {
                    console.error(`[VEO Regenerate] Failed to retry with new token:`, retryData);
                  }
                } else {
                  console.log(`[VEO Regenerate] No other tokens available for retry`);
                }
              } catch (retryError) {
                console.error(`[VEO Regenerate] Error retrying with new token:`, retryError);
              }
            }
            try {
              const statusResult = await checkVideoStatus(currentOperationName, currentSceneId, currentApiKey);
              if (statusResult.status === "COMPLETED" || statusResult.status === "MEDIA_GENERATION_STATUS_COMPLETE" || statusResult.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
                completed = true;
                if (statusResult.videoUrl) {
                  try {
                    console.log(`[VEO Regenerate] Video ${videoId} completed, saving URL directly`);
                    await storage.updateVideoHistoryFields(videoId, {
                      videoUrl: statusResult.videoUrl,
                      status: "completed"
                    });
                    console.log(`[VEO Regenerate] Video ${videoId} completed successfully${hasRetriedWithNewToken ? " (after token retry)" : ""}`);
                  } catch (saveError) {
                    console.error(`[VEO Regenerate] Failed to save video ${videoId}:`, saveError);
                    throw saveError;
                  }
                }
              } else if (statusResult.status === "FAILED" || statusResult.status === "MEDIA_GENERATION_STATUS_FAILED") {
                completed = true;
                await storage.updateVideoHistoryFields(videoId, { status: "failed" });
                console.error(`[VEO Regenerate] Video ${videoId} failed`);
                if (currentRotationToken) {
                  storage.recordTokenError(currentRotationToken.id);
                }
              }
            } catch (pollError) {
              console.error(`[VEO Regenerate] Error polling status for ${videoId}:`, pollError);
            }
          }
          if (!completed) {
            console.error(`[VEO Regenerate] Video ${videoId} timed out after 4 minutes`);
            await storage.updateVideoHistoryFields(videoId, { status: "failed" });
            if (currentRotationToken) {
              storage.recordTokenError(currentRotationToken.id);
            }
          }
        } catch (bgError) {
          console.error(`[VEO Regenerate] Background polling error for ${videoId}:`, bgError);
        }
      })();
      res.json({
        success: true,
        operationName,
        sceneId: finalSceneId,
        videoId,
        message: "Video regeneration started and will complete in background",
        tokenId: rotationToken?.id || null,
        tokenLabel: rotationToken?.label || null
      });
    } catch (error) {
      console.error("Error in /api/regenerate-video:", error);
      await handleTokenError(rotationToken?.id, error);
      res.status(500).json({
        error: "Failed to regenerate video",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/regenerate-all-failed", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      console.log(`[Regenerate All Failed] Starting for user ${userId}`);
      const failedVideos = await db.select().from(videoHistory).where(and3(
        eq3(videoHistory.userId, userId),
        eq3(videoHistory.status, "failed"),
        eq3(videoHistory.deletedByUser, false)
      )).orderBy(desc2(videoHistory.createdAt));
      if (failedVideos.length === 0) {
        return res.json({
          success: true,
          count: 0,
          message: "No failed videos to regenerate"
        });
      }
      console.log(`[Regenerate All Failed] Found ${failedVideos.length} failed videos without video URLs`);
      console.log(`[Regenerate All Failed] Video IDs to regenerate:`, failedVideos.map((v) => v.id).join(", "));
      let successCount = 0;
      for (const video of failedVideos) {
        try {
          if (video.videoUrl || video.status !== "failed") {
            console.log(`[Regenerate All Failed] Skipping video ${video.id} - already has URL or not failed (status: ${video.status})`);
            continue;
          }
          console.log(`[Regenerate All Failed] Processing video ${video.id} - status: ${video.status}, videoUrl: ${video.videoUrl || "null"}`);
          await storage.updateVideoHistoryFields(video.id, {
            status: "pending",
            videoUrl: null
          });
          (async () => {
            let currentRotationToken;
            try {
              const prompt = video.prompt || "";
              const aspectRatio = video.aspectRatio || "landscape";
              const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
              const sceneId = `regenerate-all-${video.id}-${Date.now()}`;
              const seed = Math.floor(Math.random() * 1e5);
              const isCharVideo = video.referenceImageUrl ? true : false;
              let veoResp;
              let payload;
              let operationName;
              if (isCharVideo && video.referenceImageUrl) {
                console.log(`[Regenerate All Failed] Character video detected - using reference image API with token rotation`);
                const allTokens = await storage.getAllApiTokens();
                const activeTokens = allTokens.filter((t) => t.isActive);
                if (activeTokens.length === 0) {
                  console.error(`[Regenerate All Failed] No active tokens for video ${video.id}`);
                  await storage.updateVideoHistoryFields(video.id, { status: "failed", errorMessage: "No active tokens available" });
                  return;
                }
                const shuffledTokens = [...activeTokens].sort(() => Math.random() - 0.5);
                const MAX_TOKEN_ATTEMPTS = 10;
                let lastError = "";
                let success = false;
                for (let tokenAttempt = 0; tokenAttempt < Math.min(MAX_TOKEN_ATTEMPTS, shuffledTokens.length) && !success; tokenAttempt++) {
                  const currentToken = shuffledTokens[tokenAttempt];
                  if (tokenAttempt > 0) {
                    await new Promise((resolve) => setTimeout(resolve, 1e3));
                  }
                  console.log(`[Regenerate All Failed] Video ${video.id} - Token attempt ${tokenAttempt + 1}/${MAX_TOKEN_ATTEMPTS}: ${currentToken.label}`);
                  try {
                    const uploadPayload = {
                      image: { imageUrl: video.referenceImageUrl },
                      mimeType: "image/jpeg"
                    };
                    const uploadResp = await fetch("https://aisandbox-pa.googleapis.com/v1/images:upload", {
                      method: "POST",
                      headers: {
                        "Authorization": `Bearer ${currentToken.token}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify(uploadPayload)
                    });
                    if (!uploadResp.ok) {
                      lastError = `Image upload failed: ${uploadResp.status}`;
                      console.log(`[Regenerate All Failed] \u26A0\uFE0F ${lastError} with ${currentToken.label} - trying next token...`);
                      continue;
                    }
                    const uploadData = await uploadResp.json();
                    const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
                    if (!mediaId) {
                      lastError = "No mediaId returned";
                      console.log(`[Regenerate All Failed] \u26A0\uFE0F ${lastError} with ${currentToken.label} - trying next token...`);
                      continue;
                    }
                    payload = {
                      clientContext: {
                        sessionId: `regen-all-session-${Date.now()}`,
                        projectId: veoProjectId,
                        tool: "PINHOLE",
                        userPaygateTier: "PAYGATE_TIER_TWO"
                      },
                      requests: [{
                        aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                        metadata: { sceneId },
                        referenceImages: [
                          { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId },
                          { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId }
                        ],
                        seed,
                        textInput: { prompt },
                        videoModelKey: "veo_3_0_r2v_fast_ultra"
                      }]
                    };
                    veoResp = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoReferenceImages", {
                      method: "POST",
                      headers: {
                        "Authorization": `Bearer ${currentToken.token}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify(payload)
                    });
                    const result = await veoResp.json();
                    if (!veoResp.ok || !result.operations || result.operations.length === 0) {
                      lastError = result?.error?.message || "API error";
                      console.log(`[Regenerate All Failed] \u26A0\uFE0F ${lastError} with ${currentToken.label} - trying next token...`);
                      continue;
                    }
                    operationName = result.operations[0].operation.name;
                    currentRotationToken = currentToken;
                    success = true;
                    console.log(`[Regenerate All Failed] \u2705 Video ${video.id} started with token ${currentToken.label}`);
                  } catch (tokenError) {
                    lastError = tokenError instanceof Error ? tokenError.message : "Unknown error";
                    console.log(`[Regenerate All Failed] \u26A0\uFE0F Error with ${currentToken.label}: ${lastError} - trying next token...`);
                    continue;
                  }
                }
                if (!success) {
                  console.error(`[Regenerate All Failed] \u274C All tokens failed for video ${video.id}. Last error: ${lastError}`);
                  await storage.updateVideoHistoryFields(video.id, {
                    status: "failed",
                    errorMessage: `Failed after trying ${MAX_TOKEN_ATTEMPTS} tokens: ${lastError}`
                  });
                  return;
                }
              } else {
                currentRotationToken = await storage.getNextRotationToken();
                if (!currentRotationToken) {
                  console.error(`[Regenerate All Failed] No API token available for text video ${video.id}`);
                  await storage.updateVideoHistoryFields(video.id, { status: "failed" });
                  return;
                }
                console.log(`[Regenerate All Failed] Text video ${video.id} with token ${currentRotationToken.label}`);
                payload = {
                  clientContext: {
                    projectId: veoProjectId,
                    tool: "PINHOLE",
                    userPaygateTier: "PAYGATE_TIER_TWO"
                  },
                  requests: [{
                    aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                    seed,
                    textInput: { prompt },
                    videoModelKey: aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                    metadata: { sceneId }
                  }]
                };
                veoResp = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
                  method: "POST",
                  headers: {
                    "Authorization": `Bearer ${currentRotationToken.token}`,
                    "Content-Type": "application/json"
                  },
                  body: JSON.stringify(payload)
                });
                const textResult = await veoResp.json();
                if (!veoResp.ok || !textResult.operations || textResult.operations.length === 0) {
                  throw new Error(textResult?.error?.message || "Failed to start video generation");
                }
                operationName = textResult.operations[0].operation.name;
              }
              if (!operationName || !currentRotationToken) {
                throw new Error("Failed to get operation name or token");
              }
              await storage.updateVideoHistoryFields(video.id, {
                tokenUsed: currentRotationToken.id,
                status: "pending"
              });
              console.log(`[Regenerate All Failed] Polling status for video ${video.id}`);
              const maxAttempts = 16;
              const pollInterval = 15e3;
              let completed = false;
              const apiKey = currentRotationToken.token;
              for (let attempt = 0; attempt < maxAttempts && !completed; attempt++) {
                await new Promise((resolve) => setTimeout(resolve, pollInterval));
                try {
                  const status = await checkVideoStatus(operationName, sceneId, apiKey);
                  if (status.status === "COMPLETED" || status.status === "MEDIA_GENERATION_STATUS_COMPLETE" || status.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
                    if (status.videoUrl) {
                      await storage.updateVideoHistoryFields(video.id, {
                        videoUrl: status.videoUrl,
                        status: "completed"
                      });
                      console.log(`[Regenerate All Failed] Video ${video.id} completed successfully (no Cloudinary upload)`);
                      completed = true;
                    }
                  } else if (status.status === "FAILED" || status.status === "MEDIA_GENERATION_STATUS_FAILED") {
                    console.error(`[Regenerate All Failed] Video ${video.id} failed:`, status.error);
                    await storage.updateVideoHistoryFields(video.id, { status: "failed" });
                    completed = true;
                  }
                } catch (pollError) {
                  console.error(`[Regenerate All Failed] Error polling status for ${video.id}:`, pollError);
                }
              }
              if (!completed) {
                console.error(`[Regenerate All Failed] Video ${video.id} timed out`);
                await storage.updateVideoHistoryFields(video.id, { status: "failed" });
              }
            } catch (bgError) {
              const errorMessage = bgError instanceof Error ? bgError.message : String(bgError);
              console.error(`[Regenerate All Failed] Background error for ${video.id}:`, bgError);
              if (errorMessage.includes("Resource has been exhausted") || errorMessage.includes("check quota") || errorMessage.includes("quota exceeded")) {
                console.log(`[Regenerate All Failed] Quota exhausted for video ${video.id} - marking as pending for later retry`);
                await storage.updateVideoHistoryFields(video.id, {
                  status: "pending",
                  videoUrl: null
                });
              } else {
                await storage.updateVideoHistoryFields(video.id, { status: "failed" });
              }
            }
          })();
          successCount++;
          if (successCount < failedVideos.length) {
            await new Promise((resolve) => setTimeout(resolve, 2e3));
          }
        } catch (error) {
          console.error(`[Regenerate All Failed] Error starting regeneration for ${video.id}:`, error);
        }
      }
      res.json({
        success: true,
        count: successCount,
        message: `${successCount} video(s) regeneration started`
      });
    } catch (error) {
      console.error("[Regenerate All Failed] Error:", error);
      res.status(500).json({
        error: "Failed to regenerate videos",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/mark-all-processing-failed", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      console.log(`[Delete Processing] Starting for user ${userId}`);
      const allVideos = await storage.getUserVideoHistory(userId);
      const processingVideos = allVideos.filter(
        (video) => video.status === "pending" || video.status === "processing" || video.status === "retrying" || video.status === "queued"
      );
      if (processingVideos.length === 0) {
        return res.json({
          success: true,
          count: 0,
          message: "No processing videos to delete"
        });
      }
      console.log(`[Delete Processing] Found ${processingVideos.length} processing videos to delete`);
      let deletedCount = 0;
      for (const video of processingVideos) {
        try {
          await storage.deleteVideoHistoryById(video.id);
          deletedCount++;
        } catch (err) {
          console.error(`[Delete Processing] Error deleting video ${video.id}:`, err);
        }
      }
      console.log(`[Delete Processing] Successfully deleted ${deletedCount} videos`);
      res.json({
        success: true,
        count: deletedCount,
        message: `${deletedCount} video(s) deleted permanently`
      });
    } catch (error) {
      console.error("[Delete Processing] Error:", error);
      res.status(500).json({
        error: "Failed to delete processing videos",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/regenerate-image-to-video", requireAuth, requireAdmin, async (req, res) => {
    let rotationToken;
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const schema = z2.object({
        videoId: z2.string(),
        prompt: z2.string().min(3, "Prompt must be at least 3 characters"),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape"),
        referenceImageUrl: z2.string().url("Invalid reference image URL")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { videoId, prompt, aspectRatio, referenceImageUrl } = validationResult.data;
      const existingVideo = await storage.getVideoById(videoId);
      if (existingVideo?.metadata && typeof existingVideo.metadata === "object" && "mergedVideoIds" in existingVideo.metadata) {
        return res.status(400).json({
          error: "Merged videos cannot be regenerated. Please generate individual videos instead."
        });
      }
      const updatedVideo = await storage.updateVideoHistoryStatus(videoId, userId, "pending");
      if (!updatedVideo) {
        return res.status(404).json({
          error: "Video not found or you don't have permission to regenerate it"
        });
      }
      rotationToken = await storage.getNextRotationToken();
      if (!rotationToken) {
        return res.status(500).json({
          error: "No API tokens configured. Please add tokens in the admin panel."
        });
      }
      const apiKey = rotationToken.token;
      console.log(`[Image to Video Regenerate] Using token: ${rotationToken.label} (ID: ${rotationToken.id})`);
      await storage.updateTokenUsage(rotationToken.id);
      const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
      const sceneId = crypto3.randomUUID();
      console.log(`[Image to Video Regenerate] Fetching image from: ${referenceImageUrl}`);
      const imageResponse = await fetch(referenceImageUrl);
      if (!imageResponse.ok) {
        throw new Error(`Failed to fetch image from Cloudinary: ${imageResponse.statusText}`);
      }
      const imageBuffer = await imageResponse.arrayBuffer();
      const imageBase64 = Buffer.from(imageBuffer).toString("base64");
      const mimeType = referenceImageUrl.includes(".png") ? "image/png" : "image/jpeg";
      console.log(`[Image to Video Regenerate] Step 1: Uploading image to Google AI...`);
      const uploadPayload = {
        imageInput: {
          rawImageBytes: imageBase64,
          mimeType
        }
      };
      const uploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(uploadPayload)
      });
      if (!uploadResponse.ok) {
        const errorText = await uploadResponse.text();
        console.error(`[Image to Video Regenerate] Image upload failed: ${errorText}`);
        throw new Error(`Image upload failed: ${uploadResponse.statusText}`);
      }
      const uploadData = await uploadResponse.json();
      const mediaGenId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
      if (!mediaGenId) {
        throw new Error("No media generation ID returned from image upload");
      }
      console.log(`[Image to Video Regenerate] Image uploaded. Media ID: ${mediaGenId}`);
      console.log(`[Image to Video Regenerate] Step 2: Generating video...`);
      const sessionId = `;${Date.now()}`;
      const seed = Math.floor(Math.random() * 1e5);
      const videoPayload = {
        clientContext: {
          sessionId,
          projectId: veoProjectId,
          tool: "PINHOLE",
          userPaygateTier: "PAYGATE_TIER_TWO"
        },
        requests: [{
          aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
          seed,
          textInput: {
            prompt
          },
          videoModelKey: aspectRatio === "portrait" ? "veo_3_1_i2v_s_fast_portrait_ultra" : "veo_3_1_i2v_s_fast_ultra",
          startImage: {
            mediaId: mediaGenId
          },
          metadata: {
            sceneId
          }
        }]
      };
      console.log(`[Image to Video Regenerate] === REGENERATION DETAILS (VEO 3.1) ===`);
      console.log(`[Image to Video Regenerate] Video ID: ${videoId}`);
      console.log(`[Image to Video Regenerate] Scene ID: ${sceneId}`);
      console.log(`[Image to Video Regenerate] Session ID: ${sessionId}`);
      console.log(`[Image to Video Regenerate] Seed: ${seed}`);
      console.log(`[Image to Video Regenerate] Aspect Ratio: ${aspectRatio} (${aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE"})`);
      console.log(`[Image to Video Regenerate] Video Model: ${aspectRatio === "portrait" ? "veo_3_1_i2v_s_fast_portrait_ultra" : "veo_3_1_i2v_s_fast_ultra"}`);
      console.log(`[Image to Video Regenerate] Reference Image Media ID: ${mediaGenId}`);
      console.log(`[Image to Video Regenerate] Reference Image URL: ${referenceImageUrl}`);
      console.log(`[Image to Video Regenerate] Prompt: "${prompt}"`);
      console.log(`[Image to Video Regenerate] Token: ${rotationToken?.label || "Environment Variable"} (ID: ${rotationToken?.id || "N/A"})`);
      console.log(`[Image to Video Regenerate] Full Payload:`, JSON.stringify(videoPayload, null, 2));
      const videoResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoStartImage", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(videoPayload)
      });
      if (!videoResponse.ok) {
        const errorText = await videoResponse.text();
        console.error(`[Image to Video Regenerate] Video generation failed: ${errorText}`);
        throw new Error(`Video generation failed: ${videoResponse.statusText}`);
      }
      const videoData = await videoResponse.json();
      const operationName = videoData.operations?.[0]?.operation?.name;
      if (!operationName) {
        throw new Error("No operation name returned from VEO API");
      }
      console.log(`[Image to Video Regenerate] Video generation started. Operation: ${operationName}`);
      (async () => {
        try {
          const maxWaitTime = 4 * 60 * 1e3;
          const pollInterval = 15e3;
          const startTime = Date.now();
          let completed = false;
          let currentOperationName = operationName;
          let currentSceneId = sceneId;
          let currentApiKey = apiKey;
          let currentRotationToken = rotationToken;
          while (!completed && Date.now() - startTime < maxWaitTime) {
            await new Promise((resolve) => setTimeout(resolve, pollInterval));
            try {
              const statusResult = await checkVideoStatus(currentOperationName, currentSceneId, currentApiKey);
              if (statusResult.status === "COMPLETED" || statusResult.status === "MEDIA_GENERATION_STATUS_COMPLETE" || statusResult.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
                completed = true;
                if (statusResult.videoUrl) {
                  try {
                    console.log(`[Image to Video Regenerate] Video ${videoId} completed, saving URL directly (no Cloudinary)`);
                    await storage.updateVideoHistoryFields(videoId, {
                      videoUrl: statusResult.videoUrl,
                      status: "completed"
                    });
                    console.log(`[Image to Video Regenerate] Video ${videoId} completed successfully`);
                  } catch (saveError) {
                    console.error(`[Image to Video Regenerate] Failed to save video ${videoId}:`, saveError);
                    throw saveError;
                  }
                }
              } else if (statusResult.status === "FAILED" || statusResult.status === "MEDIA_GENERATION_STATUS_FAILED") {
                completed = true;
                await storage.updateVideoHistoryFields(videoId, { status: "failed" });
                console.error(`[Image to Video Regenerate] Video ${videoId} failed`);
                if (currentRotationToken) {
                  storage.recordTokenError(currentRotationToken.id);
                }
              }
            } catch (pollError) {
              console.error(`[Image to Video Regenerate] Error polling status for ${videoId}:`, pollError);
            }
          }
          if (!completed) {
            console.error(`[Image to Video Regenerate] Video ${videoId} timed out after 4 minutes`);
            await storage.updateVideoHistoryFields(videoId, { status: "failed" });
            if (currentRotationToken) {
              storage.recordTokenError(currentRotationToken.id);
            }
          }
        } catch (bgError) {
          console.error(`[Image to Video Regenerate] Background polling error for ${videoId}:`, bgError);
        }
      })();
      res.json({
        success: true,
        operationName,
        sceneId,
        videoId,
        message: "Image to video regeneration started",
        tokenId: rotationToken?.id || null,
        tokenLabel: rotationToken?.label || null
      });
    } catch (error) {
      console.error("Error in /api/regenerate-image-to-video:", error);
      await handleTokenError(rotationToken?.id, error);
      const userFriendlyError = "Video generation failed due to content policy. Your image may contain children, celebrities, copyrighted characters, inappropriate content, or other material that violates Google's content guidelines. Please try with a different image.";
      res.status(500).json({
        error: userFriendlyError
      });
    }
  });
  app2.post("/api/check-video-status", async (req, res) => {
    let rotationToken;
    try {
      const schema = z2.object({
        operationName: z2.string(),
        sceneId: z2.string(),
        tokenId: z2.string().optional(),
        // Optional: use specific token if provided
        historyId: z2.string().optional()
        // Optional: update history when video completes
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { operationName, sceneId, tokenId, historyId } = validationResult.data;
      console.log(`[Status Check Debug] Received tokenId: ${tokenId} (type: ${typeof tokenId})`);
      let apiKey;
      if (tokenId) {
        const specificToken = await storage.getTokenById(tokenId);
        if (specificToken) {
          rotationToken = specificToken;
          apiKey = specificToken.token;
          console.log(`[Status Check] Using specific token: ${specificToken.label} (ID: ${specificToken.id})`);
          await storage.updateTokenUsage(specificToken.id);
        } else {
          console.log(`[Status Check] Requested token ${tokenId} not found, falling back to rotation`);
          rotationToken = await storage.getNextRotationToken();
          if (rotationToken) {
            apiKey = rotationToken.token;
            console.log(`[Token Rotation] Using token: ${rotationToken.label} (ID: ${rotationToken.id})`);
            await storage.updateTokenUsage(rotationToken.id);
          }
        }
      } else {
        rotationToken = await storage.getNextRotationToken();
        if (rotationToken) {
          apiKey = rotationToken.token;
          console.log(`[Token Rotation] Using token: ${rotationToken.label} (ID: ${rotationToken.id})`);
          await storage.updateTokenUsage(rotationToken.id);
        }
      }
      if (!rotationToken) {
        apiKey = process.env.VEO3_API_KEY;
        console.log("[Token Rotation] No active tokens found, using environment variable VEO3_API_KEY");
      }
      if (!apiKey) {
        return res.status(500).json({
          error: "No API key configured. Please add tokens in the admin panel or set VEO3_API_KEY environment variable."
        });
      }
      const status = await checkVideoStatus(operationName, sceneId, apiKey);
      if (status.status === "FAILED" || status.status === "MEDIA_GENERATION_STATUS_FAILED") {
        if (rotationToken) {
          storage.recordTokenError(rotationToken.id);
        }
      }
      if (status.videoUrl && (status.status === "COMPLETED" || status.status === "MEDIA_GENERATION_STATUS_COMPLETE" || status.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL")) {
        console.log(`[Video Status] Video completed for ${sceneId} (no Cloudinary upload)`);
        if (historyId) {
          try {
            await storage.updateVideoHistoryFields(historyId, {
              videoUrl: status.videoUrl,
              status: "completed"
            });
            console.log(`[Video Status] Updated history ${historyId} with completed video`);
          } catch (err) {
            console.error(`[Video Status] Failed to update history ${historyId}:`, err);
          }
        }
      }
      if (historyId && (status.status === "FAILED" || status.status === "MEDIA_GENERATION_STATUS_FAILED")) {
        try {
          await storage.updateVideoHistoryFields(historyId, {
            status: "failed",
            errorMessage: status.error || "Video generation failed"
          });
          console.log(`[Video Status] Updated history ${historyId} with failed status`);
        } catch (err) {
          console.error(`[Video Status] Failed to update history ${historyId}:`, err);
        }
      }
      res.json(status);
    } catch (error) {
      console.error("Error in /api/check-video-status:", error);
      await handleTokenError(rotationToken?.id, error);
      res.status(500).json({
        error: "Failed to check video status",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/check-videos-batch", async (req, res) => {
    try {
      const schema = z2.object({
        videos: z2.array(z2.object({
          operationName: z2.string(),
          sceneId: z2.string(),
          tokenId: z2.string().nullable().optional(),
          historyId: z2.string().nullable().optional()
        }))
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { videos } = validationResult.data;
      console.log(`[Batch Status Check] Checking ${videos.length} videos with SAME TOKEN...`);
      const tokenCache = /* @__PURE__ */ new Map();
      const results = await Promise.all(videos.map(async (video) => {
        try {
          let apiKey;
          let tokenLabel = "unknown";
          if (video.tokenId) {
            if (tokenCache.has(video.tokenId)) {
              const cached = tokenCache.get(video.tokenId);
              if (cached) {
                apiKey = cached.token;
                tokenLabel = cached.label;
              }
            } else {
              const specificToken = await storage.getTokenById(video.tokenId);
              if (specificToken) {
                tokenCache.set(video.tokenId, { token: specificToken.token, label: specificToken.label });
                apiKey = specificToken.token;
                tokenLabel = specificToken.label;
              } else {
                tokenCache.set(video.tokenId, null);
              }
            }
          }
          if (!apiKey && !video.tokenId) {
            apiKey = process.env.VEO3_API_KEY;
            tokenLabel = "env";
          }
          if (!apiKey) {
            console.log(`[Batch Status] \u26A0\uFE0F Token ${video.tokenId} not found for video ${video.sceneId}`);
            return {
              sceneId: video.sceneId,
              historyId: video.historyId,
              status: "PROCESSING",
              error: "Original token not available"
            };
          }
          const status = await checkVideoStatus(video.operationName, video.sceneId, apiKey);
          if (status.status === "COMPLETED" || status.status === "MEDIA_GENERATION_STATUS_COMPLETE" || status.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
            if (video.historyId && status.videoUrl) {
              await storage.updateVideoHistoryFields(video.historyId, {
                status: "completed",
                videoUrl: status.videoUrl
              });
            }
            console.log(`[Batch Status] \u2705 Video ${video.sceneId} completed`);
            return {
              sceneId: video.sceneId,
              historyId: video.historyId,
              status: "COMPLETED",
              videoUrl: status.videoUrl
            };
          }
          if (status.needsTokenRetry && video.historyId) {
            const errorType = status.error?.includes("LMRoot") || status.error?.includes("Gemini") ? "LMRoot/Gemini Error" : "HIGH_TRAFFIC";
            console.log(`[Batch Status] \u{1F504} ${errorType} for ${video.sceneId} - triggering auto-retry with new token`);
            const videoHistory2 = await storage.getVideoById(video.historyId);
            if (videoHistory2) {
              const currentRetryCount = videoHistory2.retryCount || 0;
              const MAX_RETRIES2 = 3;
              if (currentRetryCount >= MAX_RETRIES2) {
                console.log(`[Batch Status] \u274C Max retries (${MAX_RETRIES2}) reached for ${video.sceneId} - marking as failed`);
                await storage.updateVideoHistoryFields(video.historyId, {
                  status: "failed",
                  errorMessage: `${errorType} - Failed after ${MAX_RETRIES2} auto-retries`
                });
                return {
                  sceneId: video.sceneId,
                  historyId: video.historyId,
                  status: "FAILED",
                  error: `Failed after ${MAX_RETRIES2} auto-retries (${errorType})`
                };
              }
              await storage.updateVideoHistoryFields(video.historyId, {
                status: "pending",
                retryCount: currentRetryCount + 1,
                lastRetryAt: (/* @__PURE__ */ new Date()).toISOString()
              });
              const usedTokenIds = /* @__PURE__ */ new Set();
              if (video.tokenId) usedTokenIds.add(video.tokenId);
              const veoProjectId = process.env.VEO3_PROJECT_ID || "08ea5ad2-6dad-43cc-9963-072a0d1c7d36";
              const prompt = videoHistory2.prompt;
              const aspectRatio = videoHistory2.aspectRatio || "landscape";
              let lastRetryError = "";
              const INTERNAL_RETRIES = 10;
              for (let tokenAttempt = 0; tokenAttempt < INTERNAL_RETRIES; tokenAttempt++) {
                if (tokenAttempt > 0) {
                  await new Promise((resolve) => setTimeout(resolve, 1e3));
                }
                const newToken = await getNextTokenExcluding(usedTokenIds);
                if (!newToken) {
                  console.log(`[Batch Retry] \u26A0\uFE0F No more tokens available (tried ${usedTokenIds.size} tokens) for ${video.sceneId}`);
                  if (tokenAttempt === 0) {
                    return {
                      sceneId: video.sceneId,
                      historyId: video.historyId,
                      status: "PROCESSING",
                      error: "Waiting for available token"
                    };
                  }
                  break;
                }
                usedTokenIds.add(newToken.id);
                console.log(`[Batch Retry] \u{1F504} Token attempt ${tokenAttempt + 1}/${INTERNAL_RETRIES} (total used: ${usedTokenIds.size}): ${newToken.label} for ${video.sceneId}`);
                try {
                  const newSceneId = `retry-${video.historyId}-${Date.now()}`;
                  const seed = Math.floor(Math.random() * 1e5);
                  let veoResp;
                  if (videoHistory2.referenceImageUrl) {
                    console.log(`[Batch Retry] Character video - uploading image with token ${newToken.label}`);
                    const uploadPayload = {
                      image: { imageUrl: videoHistory2.referenceImageUrl },
                      mimeType: "image/jpeg"
                    };
                    const uploadResp = await fetch("https://aisandbox-pa.googleapis.com/v1/images:upload", {
                      method: "POST",
                      headers: {
                        "Authorization": `Bearer ${newToken.token}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify(uploadPayload)
                    });
                    if (!uploadResp.ok) {
                      const uploadText = await uploadResp.text();
                      lastRetryError = `Image upload failed with token ${newToken.label}: ${uploadResp.status}`;
                      console.log(`[Batch Retry] \u26A0\uFE0F ${lastRetryError} - trying next token...`);
                      await handleTokenError(newToken.id, new Error(lastRetryError));
                      continue;
                    }
                    const uploadData = await uploadResp.json();
                    const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
                    if (!mediaId) {
                      lastRetryError = `No mediaId returned from upload with token ${newToken.label}`;
                      console.log(`[Batch Retry] \u26A0\uFE0F ${lastRetryError} - trying next token...`);
                      continue;
                    }
                    console.log(`[Batch Retry] \u2713 Image uploaded with token ${newToken.label}, mediaId: ${mediaId}`);
                    const payload = {
                      clientContext: {
                        sessionId: `retry-session-${Date.now()}`,
                        projectId: veoProjectId,
                        tool: "PINHOLE",
                        userPaygateTier: "PAYGATE_TIER_TWO"
                      },
                      requests: [{
                        aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                        metadata: { sceneId: newSceneId },
                        referenceImages: [
                          { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId },
                          { imageUsageType: "IMAGE_USAGE_TYPE_ASSET", mediaId }
                        ],
                        seed,
                        textInput: { prompt },
                        videoModelKey: "veo_3_0_r2v_fast_ultra"
                      }]
                    };
                    veoResp = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoReferenceImages", {
                      method: "POST",
                      headers: {
                        "Authorization": `Bearer ${newToken.token}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify(payload)
                    });
                  } else {
                    const payload = {
                      clientContext: {
                        projectId: veoProjectId,
                        tool: "PINHOLE",
                        userPaygateTier: "PAYGATE_TIER_TWO"
                      },
                      requests: [{
                        aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                        seed,
                        textInput: { prompt },
                        videoModelKey: aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
                        metadata: { sceneId: newSceneId }
                      }]
                    };
                    veoResp = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
                      method: "POST",
                      headers: {
                        "Authorization": `Bearer ${newToken.token}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify(payload)
                    });
                  }
                  const result = await veoResp.json();
                  if (!veoResp.ok || !result.operations || result.operations.length === 0) {
                    lastRetryError = result?.error?.message || `API error with token ${newToken.label}`;
                    console.log(`[Batch Retry] \u26A0\uFE0F ${lastRetryError} - trying next token...`);
                    await handleTokenError(newToken.id, new Error(lastRetryError));
                    continue;
                  }
                  const newOperationName = result.operations[0].operation.name;
                  await storage.updateVideoHistoryFields(video.historyId, {
                    operationName: newOperationName,
                    sceneId: newSceneId,
                    tokenUsed: newToken.id,
                    status: "pending"
                  });
                  await storage.updateTokenUsage(newToken.id);
                  console.log(`[Batch Retry] \u2705 Started retry for ${video.historyId} with token ${newToken.label} - new operation: ${newOperationName}`);
                  return {
                    sceneId: video.sceneId,
                    historyId: video.historyId,
                    status: "RETRYING",
                    newOperationName,
                    newSceneId,
                    tokenId: newToken.id,
                    message: `Auto-retrying with token ${newToken.label} (attempt ${currentRetryCount + 1}/${MAX_RETRIES2})`
                  };
                } catch (tokenError) {
                  lastRetryError = tokenError instanceof Error ? tokenError.message : "Unknown error";
                  console.log(`[Batch Retry] \u26A0\uFE0F Error with token ${newToken.label}: ${lastRetryError} - trying next token...`);
                  await handleTokenError(newToken.id, tokenError instanceof Error ? tokenError : new Error(lastRetryError));
                  continue;
                }
              }
              console.error(`[Batch Retry] \u274C All ${usedTokenIds.size} tokens failed for ${video.historyId}. Last error: ${lastRetryError}`);
              await storage.updateVideoHistoryFields(video.historyId, {
                status: "failed",
                errorMessage: `Auto-retry failed after trying ${usedTokenIds.size} tokens: ${lastRetryError}`
              });
              return {
                sceneId: video.sceneId,
                historyId: video.historyId,
                status: "FAILED",
                error: `Auto-retry failed after trying ${usedTokenIds.size} tokens: ${lastRetryError}`
              };
            }
          }
          if (status.status === "PENDING" || status.status === "PROCESSING" || status.status === "MEDIA_GENERATION_STATUS_PENDING" || status.status === "MEDIA_GENERATION_STATUS_PROCESSING") {
            return {
              sceneId: video.sceneId,
              historyId: video.historyId,
              status: "PROCESSING"
            };
          }
          if (status.status === "FAILED" || status.status === "MEDIA_GENERATION_STATUS_FAILED" || status.error) {
            const errorMsg = status.error || "Video generation failed";
            if (video.historyId) {
              await storage.updateVideoHistoryFields(video.historyId, {
                status: "failed",
                errorMessage: errorMsg
              });
            }
            console.log(`[Batch Status] \u274C Video ${video.sceneId} failed: ${errorMsg}`);
            return {
              sceneId: video.sceneId,
              historyId: video.historyId,
              status: "FAILED",
              error: errorMsg
            };
          }
          return {
            sceneId: video.sceneId,
            historyId: video.historyId,
            status: status.status || "UNKNOWN"
          };
        } catch (error) {
          const errMsg = error instanceof Error ? error.message : "Unknown error";
          console.error(`[Batch Status] Error checking ${video.sceneId}:`, errMsg);
          return {
            sceneId: video.sceneId,
            historyId: video.historyId,
            status: "PROCESSING",
            error: errMsg
          };
        }
      }));
      console.log(`[Batch Status Check] Completed. Results: ${results.filter((r) => r.status === "COMPLETED").length} completed, ${results.filter((r) => r.status === "PROCESSING").length} processing, ${results.filter((r) => r.status === "RETRYING").length} retrying, ${results.filter((r) => r.status === "FAILED").length} failed`);
      res.json({ results });
    } catch (error) {
      console.error("Error in /api/check-videos-batch:", error);
      res.status(500).json({
        error: "Failed to check video statuses",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/merge-videos", requireAuth, async (req, res) => {
    try {
      const schema = z2.object({
        videos: z2.array(z2.object({
          sceneNumber: z2.number(),
          videoUrl: z2.string()
        }))
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { videos } = validationResult.data;
      const userId = req.session.userId;
      if (videos.length === 0) {
        return res.status(400).json({
          error: "No videos to merge"
        });
      }
      console.log(`[Merge Videos] Starting merge of ${videos.length} videos using fal.ai`);
      const sortedVideos = [...videos].sort((a, b) => a.sceneNumber - b.sceneNumber);
      const videoUrls = sortedVideos.map((v) => v.videoUrl);
      const mergedVideoUrl = await mergeVideosWithFalAI(videoUrls);
      console.log(`[Merge Videos] Videos merged successfully with fal.ai`);
      console.log(`[Merge Videos] Merged video URL: ${mergedVideoUrl}`);
      res.json({
        success: true,
        mergedVideoUrl
      });
    } catch (error) {
      console.error("Error in /api/merge-videos:", error);
      res.status(500).json({
        error: "Failed to merge videos",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/merge-selected-videos", requireAuth, async (req, res) => {
    try {
      const schema = z2.object({
        videoIds: z2.array(z2.string()).min(2).max(30)
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { videoIds } = validationResult.data;
      const userId = req.session.userId;
      console.log(`[Merge Selected] Starting FFmpeg merge of ${videoIds.length} selected videos for user ${userId}`);
      const userVideos = await storage.getUserVideoHistory(userId);
      const videoUrls = [];
      for (const videoId of videoIds) {
        const video = userVideos.find((v) => v.id === videoId);
        if (!video) {
          return res.status(403).json({
            error: "Forbidden",
            message: `Video ${videoId} not found or does not belong to you`
          });
        }
        if (video.status !== "completed" || !video.videoUrl) {
          return res.status(400).json({
            error: "Invalid video",
            message: `Video ${videoId} is not completed or has no URL`
          });
        }
        const isCloudinary = video.videoUrl.startsWith("https://res.cloudinary.com/");
        const isGoogleStorage = video.videoUrl.startsWith("https://storage.googleapis.com/");
        if (!isCloudinary && !isGoogleStorage) {
          return res.status(400).json({
            error: "Invalid video URL",
            message: `Video ${videoId} has an invalid URL`
          });
        }
        videoUrls.push(video.videoUrl);
      }
      console.log(`[Merge Selected] All videos verified, proceeding with merge`);
      const mergeHistoryEntry = await storage.addVideoHistory({
        userId,
        prompt: `Merged video from ${videoIds.length} selected videos`,
        aspectRatio: "16:9",
        status: "pending",
        metadata: JSON.stringify({ mergedVideoIds: videoIds }),
        title: `Merged Video (${videoIds.length} clips)`
      });
      try {
        const { mergeVideosWithFFmpeg: mergeVideosWithFFmpeg2 } = await Promise.resolve().then(() => (init_videoMergerFFmpeg(), videoMergerFFmpeg_exports));
        const mergedVideoUrl = await mergeVideosWithFFmpeg2(videoUrls);
        console.log(`[Merge Selected] Videos merged successfully with FFmpeg`);
        console.log(`[Merge Selected] Merged video URL: ${mergedVideoUrl}`);
        await storage.updateVideoHistoryFields(mergeHistoryEntry.id, {
          status: "completed",
          videoUrl: mergedVideoUrl
        });
        res.json({
          success: true,
          mergedVideoUrl,
          historyId: mergeHistoryEntry.id
        });
      } catch (mergeError) {
        console.error("[Merge Selected] Merge failed:", mergeError);
        await storage.updateVideoHistoryFields(mergeHistoryEntry.id, {
          status: "failed"
        });
        throw mergeError;
      }
    } catch (error) {
      console.error("Error in /api/merge-selected-videos:", error);
      res.status(500).json({
        error: "Failed to merge selected videos",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/retry-merge/:id", requireAuth, async (req, res) => {
    try {
      const videoId = req.params.id;
      const userId = req.session.userId;
      console.log(`[Retry Merge] Starting retry for merge video ${videoId} by user ${userId}`);
      const userVideos = await storage.getUserVideoHistory(userId);
      const mergeVideo = userVideos.find((v) => v.id === videoId);
      if (!mergeVideo) {
        return res.status(404).json({
          error: "Video not found",
          message: "Merge video not found or does not belong to you"
        });
      }
      if (!mergeVideo.metadata) {
        return res.status(400).json({
          error: "Invalid merge video",
          message: "This video does not have merge metadata"
        });
      }
      const metadata = JSON.parse(mergeVideo.metadata);
      const videoIds = metadata.mergedVideoIds;
      if (!videoIds || !Array.isArray(videoIds) || videoIds.length < 2) {
        return res.status(400).json({
          error: "Invalid metadata",
          message: "Merge metadata is invalid or missing video IDs"
        });
      }
      console.log(`[Retry Merge] Retrying merge of ${videoIds.length} videos`);
      const videoUrls = [];
      for (const id of videoIds) {
        const video = userVideos.find((v) => v.id === id);
        if (!video || video.status !== "completed" || !video.videoUrl) {
          return res.status(400).json({
            error: "Invalid source videos",
            message: `One or more source videos are no longer available or completed`
          });
        }
        const isCloudinary = video.videoUrl.startsWith("https://res.cloudinary.com/");
        const isGoogleStorage = video.videoUrl.startsWith("https://storage.googleapis.com/");
        if (!isCloudinary && !isGoogleStorage) {
          return res.status(400).json({
            error: "Invalid video URL",
            message: `Video ${id} has an invalid URL`
          });
        }
        videoUrls.push(video.videoUrl);
      }
      await storage.updateVideoHistoryFields(videoId, {
        status: "pending",
        videoUrl: null
      });
      res.json({
        success: true,
        message: "Merge retry started",
        videoId
      });
      (async () => {
        try {
          const { mergeVideosWithFFmpeg: mergeVideosWithFFmpeg2 } = await Promise.resolve().then(() => (init_videoMergerFFmpeg(), videoMergerFFmpeg_exports));
          const mergedVideoUrl = await mergeVideosWithFFmpeg2(videoUrls);
          console.log(`[Retry Merge] Retry successful for video ${videoId}`);
          await storage.updateVideoHistoryFields(videoId, {
            status: "completed",
            videoUrl: mergedVideoUrl
          });
        } catch (mergeError) {
          console.error(`[Retry Merge] Retry failed for video ${videoId}:`, mergeError);
          await storage.updateVideoHistoryFields(videoId, {
            status: "failed"
          });
        }
      })();
    } catch (error) {
      console.error("Error in /api/retry-merge:", error);
      res.status(500).json({
        error: "Failed to retry merge",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/merge-videos-temporary", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      const { videoIds, expiryHours = 24 } = req.body;
      if (!Array.isArray(videoIds) || videoIds.length < 2) {
        return res.status(400).json({
          error: "Invalid input",
          message: "Please provide at least 2 video IDs to merge"
        });
      }
      if (videoIds.length > 30) {
        return res.status(400).json({
          error: "Too many videos",
          message: "Cannot merge more than 30 videos at once"
        });
      }
      console.log(`[Merge Temporary] Starting temporary merge of ${videoIds.length} videos for user ${userId}`);
      const userVideos = await storage.getUserVideoHistory(userId);
      const videoUrls = [];
      for (const id of videoIds) {
        const video = userVideos.find((v) => v.id === id);
        if (!video || video.status !== "completed" || !video.videoUrl) {
          return res.status(400).json({
            error: "Invalid video selection",
            message: `Video ${id} is not available or not completed`
          });
        }
        const isCloudinary = video.videoUrl.startsWith("https://res.cloudinary.com/");
        const isGoogleStorage = video.videoUrl.startsWith("https://storage.googleapis.com/");
        if (!isCloudinary && !isGoogleStorage) {
          return res.status(400).json({
            error: "Invalid video URL",
            message: `Video ${id} has an invalid URL`
          });
        }
        videoUrls.push(video.videoUrl);
      }
      console.log(`[Merge Temporary] All videos verified, starting FFmpeg merge`);
      const { mergeVideosWithFFmpegTemporary: mergeVideosWithFFmpegTemporary2 } = await Promise.resolve().then(() => (init_videoMergerFFmpeg(), videoMergerFFmpeg_exports));
      const { videoPath, expiresAt } = await mergeVideosWithFFmpegTemporary2(videoUrls, expiryHours);
      console.log(`[Merge Temporary] Merge complete!`);
      console.log(`[Merge Temporary] Video path: ${videoPath}`);
      console.log(`[Merge Temporary] Expires at: ${expiresAt}`);
      res.json({
        success: true,
        videoPath,
        expiresAt,
        previewUrl: videoPath,
        message: `Video will be available for ${expiryHours} hours`
      });
    } catch (error) {
      console.error("Error in /api/merge-videos-temporary:", error);
      res.status(500).json({
        error: "Failed to merge videos temporarily",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/temp-video-info", requireAuth, async (req, res) => {
    try {
      const { videoPath } = req.query;
      if (!videoPath || typeof videoPath !== "string") {
        return res.status(400).json({
          error: "Invalid input",
          message: "videoPath is required"
        });
      }
      const { ObjectStorageService: ObjectStorageService2 } = await Promise.resolve().then(() => (init_objectStorage(), objectStorage_exports));
      const objectStorageService2 = new ObjectStorageService2();
      const info = await objectStorageService2.getVideoExpiryInfo(videoPath);
      res.json({
        success: true,
        ...info
      });
    } catch (error) {
      console.error("Error in /api/temp-video-info:", error);
      res.status(500).json({
        error: "Failed to get video info",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/cleanup-expired-videos", requireAdmin, async (req, res) => {
    try {
      console.log(`[Cleanup] Starting cleanup of expired videos`);
      const { ObjectStorageService: ObjectStorageService2 } = await Promise.resolve().then(() => (init_objectStorage(), objectStorage_exports));
      const objectStorageService2 = new ObjectStorageService2();
      const deletedCount = await objectStorageService2.cleanupExpiredVideos();
      console.log(`[Cleanup] Cleanup complete, deleted ${deletedCount} videos`);
      res.json({
        success: true,
        deletedCount,
        message: `Deleted ${deletedCount} expired videos`
      });
    } catch (error) {
      console.error("Error in /api/cleanup-expired-videos:", error);
      res.status(500).json({
        error: "Failed to cleanup expired videos",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/admin/logs", requireAdmin, async (req, res) => {
    try {
      const lines = parseInt(req.query.lines) || 200;
      const { exec: exec3 } = await import("child_process");
      const { promisify: promisify3 } = await import("util");
      const fs5 = await import("fs/promises");
      const path6 = await import("path");
      const execAsync3 = promisify3(exec3);
      let logs = "";
      try {
        const { stdout } = await execAsync3(`pm2 logs videoapp --lines ${lines} --nostream 2>/dev/null || pm2 logs --lines ${lines} --nostream 2>/dev/null || echo "PM2 not available"`);
        if (stdout && !stdout.includes("PM2 not available")) {
          logs = stdout;
        } else {
          try {
            const logsDir = "/tmp/logs";
            const files = await fs5.readdir(logsDir);
            const appLogFiles = files.filter((f) => f.startsWith("Start_application_")).sort().reverse();
            if (appLogFiles.length > 0) {
              const latestLogFile = path6.join(logsDir, appLogFiles[0]);
              const logContent = await fs5.readFile(latestLogFile, "utf-8");
              const allLines = logContent.split("\n");
              const lastLines = allLines.slice(-lines);
              logs = `=== Real-time Application Logs (Last ${lines} lines) ===
=== File: ${appLogFiles[0]} ===
=== Auto-refreshing every 3 seconds ===

` + lastLines.join("\n");
            } else {
              logs = "=== No log files found ===\n\nWaiting for application to generate logs...";
            }
          } catch (fsError) {
            logs = `=== Recent Server Activity ===

Server is running in ${process.env.NODE_ENV || "development"} mode
Uptime: ${process.uptime().toFixed(0)} seconds

Console logs are being captured in real-time.
Check the Console panel for detailed output.

Error: ${fsError instanceof Error ? fsError.message : String(fsError)}`;
          }
        }
      } catch (error) {
        logs = `=== Logs Not Available ===

Error: ${error instanceof Error ? error.message : String(error)}`;
      }
      res.json({
        logs,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        lines
      });
    } catch (error) {
      console.error("Error in /api/admin/logs:", error);
      res.status(500).json({
        error: "Failed to fetch logs",
        message: error instanceof Error ? error.message : "Unknown error",
        logs: `Error fetching logs: ${error instanceof Error ? error.message : String(error)}`
      });
    }
  });
  app2.get("/api/admin/database-backup", requireAdmin, async (req, res) => {
    try {
      console.log("[Database Backup] Admin requested database backup");
      const { users: users2, apiTokens: apiTokens2, tokenSettings: tokenSettings2, planAvailability: planAvailability2, appSettings: appSettings2, toolMaintenance: toolMaintenance2, characters: characters2, adminMessages: adminMessages2, resellers: resellers2, resellerUsers: resellerUsers2, resellerCreditLedger: resellerCreditLedger2, videoHistory: videoHistory2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const videoCountResult = await db.select({ count: sql3`count(*)` }).from(videoHistory2);
      const videoCount = Number(videoCountResult[0]?.count || 0);
      const [
        usersData,
        apiTokensData,
        tokenSettingsData,
        planAvailabilityData,
        appSettingsData,
        toolMaintenanceData,
        charactersData,
        adminMessagesData,
        resellersData,
        resellerUsersData,
        resellerCreditLedgerData
      ] = await Promise.all([
        db.select().from(users2),
        db.select().from(apiTokens2),
        db.select().from(tokenSettings2),
        db.select().from(planAvailability2),
        db.select().from(appSettings2),
        db.select().from(toolMaintenance2),
        db.select().from(characters2),
        db.select().from(adminMessages2),
        db.select().from(resellers2),
        db.select().from(resellerUsers2),
        db.select().from(resellerCreditLedger2)
      ]);
      const backup = {
        exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
        version: "1.0",
        note: "Video history excluded due to size. Use /api/admin/database-backup-videos for video data.",
        tables: {
          users: usersData,
          apiTokens: apiTokensData,
          tokenSettings: tokenSettingsData,
          planAvailability: planAvailabilityData,
          appSettings: appSettingsData,
          toolMaintenance: toolMaintenanceData,
          characters: charactersData,
          adminMessages: adminMessagesData,
          resellers: resellersData,
          resellerUsers: resellerUsersData,
          resellerCreditLedger: resellerCreditLedgerData
        },
        stats: {
          users: usersData.length,
          apiTokens: apiTokensData.length,
          videoHistory: videoCount,
          characters: charactersData.length,
          resellers: resellersData.length,
          resellerUsers: resellerUsersData.length
        }
      };
      const filename = `database-backup-${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.json`;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      console.log(`[Database Backup] Backup created with ${usersData.length} users (${videoCount} videos excluded)`);
      res.json(backup);
    } catch (error) {
      console.error("Error in /api/admin/database-backup:", error);
      res.status(500).json({
        error: "Failed to create database backup",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/admin/database-backup-sql", requireAdmin, async (req, res) => {
    try {
      console.log("[Database Backup SQL] Admin requested SQL database backup");
      const { getTableColumns } = await import("drizzle-orm");
      const { users: users2, apiTokens: apiTokens2, tokenSettings: tokenSettings2, planAvailability: planAvailability2, appSettings: appSettings2, toolMaintenance: toolMaintenance2, characters: characters2, adminMessages: adminMessages2, resellers: resellers2, resellerUsers: resellerUsers2, resellerCreditLedger: resellerCreditLedger2, videoHistory: videoHistory2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const videoCountResult = await db.select({ count: sql3`count(*)` }).from(videoHistory2);
      const videoCount = Number(videoCountResult[0]?.count || 0);
      const [
        usersData,
        apiTokensData,
        tokenSettingsData,
        planAvailabilityData,
        appSettingsData,
        toolMaintenanceData,
        charactersData,
        adminMessagesData,
        resellersData,
        resellerUsersData,
        resellerCreditLedgerData
      ] = await Promise.all([
        db.select().from(users2),
        db.select().from(apiTokens2),
        db.select().from(tokenSettings2),
        db.select().from(planAvailability2),
        db.select().from(appSettings2),
        db.select().from(toolMaintenance2),
        db.select().from(characters2),
        db.select().from(adminMessages2),
        db.select().from(resellers2),
        db.select().from(resellerUsers2),
        db.select().from(resellerCreditLedger2)
      ]);
      const escapeValue = (val, colType) => {
        if (val === null || val === void 0) return "NULL";
        if (typeof val === "boolean") return val ? "TRUE" : "FALSE";
        if (typeof val === "number") return String(val);
        if (val instanceof Date) return `'${val.toISOString()}'`;
        if (Buffer.isBuffer(val)) return `E'\\\\x${val.toString("hex")}'`;
        if (Array.isArray(val)) {
          const arrayVals = val.map((v) => typeof v === "string" ? `'${v.replace(/'/g, "''")}'` : String(v));
          return `ARRAY[${arrayVals.join(", ")}]::text[]`;
        }
        if (typeof val === "object") {
          const jsonStr = JSON.stringify(val).replace(/'/g, "''");
          return `'${jsonStr}'::jsonb`;
        }
        return `'${String(val).replace(/'/g, "''")}'`;
      };
      const generateInserts = (tableName, table, data) => {
        if (data.length === 0) return `-- No data in ${tableName}
`;
        const columns = getTableColumns(table);
        const columnEntries = Object.entries(columns);
        let sqlOutput = `-- Table: ${tableName} (${data.length} rows)
`;
        for (const row of data) {
          const colNames = columnEntries.map(([, col]) => `"${col.name}"`);
          const values = columnEntries.map(([key, col]) => escapeValue(row[key], col.dataType));
          sqlOutput += `INSERT INTO "${tableName}" (${colNames.join(", ")}) VALUES (${values.join(", ")});
`;
        }
        return sqlOutput + "\n";
      };
      let sqlContent = `-- Database Backup SQL Export
`;
      sqlContent += `-- Generated at: ${(/* @__PURE__ */ new Date()).toISOString()}
`;
      sqlContent += `-- Note: Video history excluded due to size (${videoCount} videos)
`;
      sqlContent += `-- Stats: ${usersData.length} users, ${apiTokensData.length} tokens, ${charactersData.length} characters

`;
      sqlContent += `BEGIN;

`;
      sqlContent += generateInserts("users", users2, usersData);
      sqlContent += generateInserts("api_tokens", apiTokens2, apiTokensData);
      sqlContent += generateInserts("token_settings", tokenSettings2, tokenSettingsData);
      sqlContent += generateInserts("plan_availability", planAvailability2, planAvailabilityData);
      sqlContent += generateInserts("app_settings", appSettings2, appSettingsData);
      sqlContent += generateInserts("tool_maintenance", toolMaintenance2, toolMaintenanceData);
      sqlContent += generateInserts("characters", characters2, charactersData);
      sqlContent += generateInserts("admin_messages", adminMessages2, adminMessagesData);
      sqlContent += generateInserts("resellers", resellers2, resellersData);
      sqlContent += generateInserts("reseller_users", resellerUsers2, resellerUsersData);
      sqlContent += generateInserts("reseller_credit_ledger", resellerCreditLedger2, resellerCreditLedgerData);
      sqlContent += `COMMIT;
`;
      const filename = `database-backup-${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.sql`;
      res.setHeader("Content-Type", "application/sql");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      console.log(`[Database Backup SQL] SQL backup created with ${usersData.length} users`);
      res.send(sqlContent);
    } catch (error) {
      console.error("Error in /api/admin/database-backup-sql:", error);
      res.status(500).json({
        error: "Failed to create SQL database backup",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/admin/database-backup-csv", requireAdmin, async (req, res) => {
    try {
      console.log("[Database Backup CSV] Admin requested CSV database backup");
      const archiver2 = await import("archiver");
      const { users: users2, apiTokens: apiTokens2, tokenSettings: tokenSettings2, planAvailability: planAvailability2, appSettings: appSettings2, toolMaintenance: toolMaintenance2, characters: characters2, adminMessages: adminMessages2, resellers: resellers2, resellerUsers: resellerUsers2, resellerCreditLedger: resellerCreditLedger2, videoHistory: videoHistory2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const videoCountResult = await db.select({ count: sql3`count(*)` }).from(videoHistory2);
      const videoCount = Number(videoCountResult[0]?.count || 0);
      const [
        usersData,
        apiTokensData,
        tokenSettingsData,
        planAvailabilityData,
        appSettingsData,
        toolMaintenanceData,
        charactersData,
        adminMessagesData,
        resellersData,
        resellerUsersData,
        resellerCreditLedgerData
      ] = await Promise.all([
        db.select().from(users2),
        db.select().from(apiTokens2),
        db.select().from(tokenSettings2),
        db.select().from(planAvailability2),
        db.select().from(appSettings2),
        db.select().from(toolMaintenance2),
        db.select().from(characters2),
        db.select().from(adminMessages2),
        db.select().from(resellers2),
        db.select().from(resellerUsers2),
        db.select().from(resellerCreditLedger2)
      ]);
      const toCsv = (data) => {
        if (data.length === 0) return "";
        const headers = Object.keys(data[0]);
        const escapeCell = (val) => {
          if (val === null || val === void 0) return "";
          if (typeof val === "object") {
            const str2 = JSON.stringify(val);
            return `"${str2.replace(/"/g, '""')}"`;
          }
          const str = String(val);
          if (str.includes(",") || str.includes('"') || str.includes("\n")) {
            return `"${str.replace(/"/g, '""')}"`;
          }
          return str;
        };
        const rows = data.map((row) => headers.map((h) => escapeCell(row[h])).join(","));
        return [headers.join(","), ...rows].join("\n");
      };
      const filename = `database-backup-${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.zip`;
      res.setHeader("Content-Type", "application/zip");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      const archive = archiver2.default("zip", { zlib: { level: 9 } });
      const archiveComplete = new Promise((resolve, reject) => {
        archive.on("error", (err) => {
          console.error("[Database Backup CSV] Archive error:", err);
          reject(err);
        });
        archive.on("close", () => {
          console.log(`[Database Backup CSV] Archive closed, ${archive.pointer()} bytes written`);
          resolve();
        });
      });
      archive.pipe(res);
      const tables = [
        { name: "users", data: usersData },
        { name: "api_tokens", data: apiTokensData },
        { name: "token_settings", data: tokenSettingsData },
        { name: "plan_availability", data: planAvailabilityData },
        { name: "app_settings", data: appSettingsData },
        { name: "tool_maintenance", data: toolMaintenanceData },
        { name: "characters", data: charactersData },
        { name: "admin_messages", data: adminMessagesData },
        { name: "resellers", data: resellersData },
        { name: "reseller_users", data: resellerUsersData },
        { name: "reseller_credit_ledger", data: resellerCreditLedgerData }
      ];
      for (const table of tables) {
        const csv = toCsv(table.data);
        if (csv) {
          archive.append(csv, { name: `${table.name}.csv` });
        }
      }
      const readme = `Database Backup - CSV Export
Generated at: ${(/* @__PURE__ */ new Date()).toISOString()}
Note: Video history excluded due to size (${videoCount} videos)

Stats:
- Users: ${usersData.length}
- API Tokens: ${apiTokensData.length}
- Characters: ${charactersData.length}
- Resellers: ${resellersData.length}
- Reseller Users: ${resellerUsersData.length}
`;
      archive.append(readme, { name: "README.txt" });
      await archive.finalize();
      await archiveComplete;
      console.log(`[Database Backup CSV] CSV backup created with ${usersData.length} users (${videoCount} videos excluded)`);
    } catch (error) {
      console.error("Error in /api/admin/database-backup-csv:", error);
      if (!res.headersSent) {
        res.status(500).json({
          error: "Failed to create CSV database backup",
          message: error instanceof Error ? error.message : "Unknown error"
        });
      }
    }
  });
  app2.get("/api/google-drive/auth-url", requireAdmin, async (req, res) => {
    try {
      const { generateAuthUrl: generateAuthUrl2 } = await Promise.resolve().then(() => (init_googleDriveOAuth(), googleDriveOAuth_exports));
      const authUrl = await generateAuthUrl2();
      res.json({ authUrl });
    } catch (error) {
      console.error("Error generating auth URL:", error);
      res.status(500).json({
        error: "Failed to generate auth URL",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/google-drive/exchange-token", requireAdmin, async (req, res) => {
    try {
      const { code } = req.body;
      if (!code) {
        return res.status(400).json({ error: "Authorization code required" });
      }
      const { exchangeCodeForToken: exchangeCodeForToken2 } = await Promise.resolve().then(() => (init_googleDriveOAuth(), googleDriveOAuth_exports));
      const refreshToken = await exchangeCodeForToken2(code);
      res.json({
        refreshToken,
        message: "Add this token to your secrets as GOOGLE_DRIVE_REFRESH_TOKEN"
      });
    } catch (error) {
      console.error("Error exchanging token:", error);
      res.status(500).json({
        error: "Failed to exchange token",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/characters", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const characters2 = await storage.getUserCharacters(userId);
      res.json({ characters: characters2 });
    } catch (error) {
      console.error("Error fetching characters:", error);
      res.status(500).json({
        error: "Failed to fetch characters",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/characters", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolMaintenance2 = await storage.getToolMaintenance();
      if (!toolMaintenance2?.characterConsistencyActive && !user.isAdmin) {
        return res.status(503).json({
          error: "Tool unavailable",
          message: "Character Consistency tool is currently under maintenance. Please try again later."
        });
      }
      const schema = z2.object({
        name: z2.string().min(1, "Character name is required"),
        characterType: z2.literal("text"),
        description: z2.string().min(10, "Character description must be at least 10 characters")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { name, description } = validationResult.data;
      console.log(`[Character Create] User: ${userId}, Name: ${name}, Type: text`);
      console.log(`[Character Create] Description length: ${description.length} chars`);
      const character = await storage.addCharacter({
        userId,
        name,
        characterType: "text",
        imageUrl: null,
        mediaId: null,
        uploadTokenId: null,
        description
      });
      return res.json({
        character,
        message: "Character created successfully"
      });
    } catch (error) {
      console.error("Error creating character:", error);
      res.status(500).json({
        error: "Failed to create character",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.delete("/api/characters/:id", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const characterId = req.params.id;
      const character = await storage.getCharacterById(characterId);
      if (!character) {
        return res.status(404).json({ error: "Character not found" });
      }
      if (character.userId !== userId) {
        return res.status(403).json({ error: "Not authorized to delete this character" });
      }
      await storage.deleteCharacter(characterId, userId);
      console.log(`[Character Delete] User: ${userId}, Character: ${character.name} (${characterId})`);
      res.json({ message: "Character deleted successfully" });
    } catch (error) {
      console.error("Error deleting character:", error);
      res.status(500).json({
        error: "Failed to delete character",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/generate-character-video", requireAuth, async (req, res) => {
    let rotationToken;
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "imageToVideo");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const schema = z2.object({
        characterId: z2.string().min(1, "Character ID is required"),
        prompt: z2.string().min(3, "Prompt must be at least 3 characters"),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { characterId, prompt, aspectRatio } = validationResult.data;
      const character = await storage.getCharacterById(characterId);
      if (!character) {
        return res.status(404).json({ error: "Character not found" });
      }
      if (character.userId !== userId) {
        return res.status(403).json({ error: "Not authorized to use this character" });
      }
      console.log(`[Character Video] User: ${user.username}, Character: ${character.name}, Prompt: ${prompt}`);
      console.log(`[Character Video] Character mediaId: ${character.mediaId}`);
      console.log(`[Character Video] Upload token ID: ${character.uploadTokenId}`);
      if (character.uploadTokenId) {
        rotationToken = await storage.getTokenById(character.uploadTokenId);
        if (rotationToken) {
          console.log(`[Token Reuse] Using same token that uploaded character: ${rotationToken.label} (ID: ${rotationToken.id})`);
          await storage.updateTokenUsage(rotationToken.id);
        } else {
          console.error(`[Token Error] Upload token ${character.uploadTokenId} not found! Character may be unusable.`);
          return res.status(500).json({
            error: "Character upload token no longer available",
            details: "Please re-upload this character to fix the issue"
          });
        }
      } else {
        console.warn("[Token Warning] Character has no uploadTokenId, using fallback token");
        rotationToken = await storage.getNextRotationToken();
        if (rotationToken) {
          console.log(`[Token Rotation] Using fallback token: ${rotationToken.label} (ID: ${rotationToken.id})`);
          await storage.updateTokenUsage(rotationToken.id);
        }
      }
      const apiKey = rotationToken?.token || process.env.VEO3_API_KEY;
      if (!apiKey) {
        return res.status(500).json({ error: "No API key configured" });
      }
      const veoProjectId = process.env.VEO3_PROJECT_ID || "08ea5ad2-6dad-43cc-9963-072a0d1c7d36";
      const sessionId = `session-${Date.now()}`;
      const sceneId = `character-video-${Date.now()}`;
      const seed = Math.floor(Math.random() * 1e5);
      const payload = {
        clientContext: {
          sessionId,
          projectId: veoProjectId,
          tool: "PINHOLE",
          userPaygateTier: "PAYGATE_TIER_TWO"
        },
        requests: [{
          aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
          metadata: {
            sceneId
          },
          referenceImages: [
            {
              imageUsageType: "IMAGE_USAGE_TYPE_ASSET",
              mediaId: character.mediaId
            },
            {
              imageUsageType: "IMAGE_USAGE_TYPE_ASSET",
              mediaId: character.mediaId
            }
          ],
          seed,
          textInput: {
            prompt
          },
          videoModelKey: "veo_3_0_r2v_fast_ultra"
        }]
      };
      console.log(`[Character Video] Request payload:`, JSON.stringify(payload, null, 2));
      const response = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoReferenceImages", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });
      const result = await response.json();
      console.log(`[Character Video] API Response status: ${response.status}`);
      console.log(`[Character Video] API Response:`, JSON.stringify(result, null, 2));
      if (!response.ok || !result.operations || result.operations.length === 0) {
        const errorMsg = result?.error?.message || "Failed to start video generation";
        console.error(`[Character Video] Error: ${errorMsg}`, result);
        throw new Error(errorMsg);
      }
      const operationName = result.operations[0].operation.name;
      await storage.incrementDailyVideoCount(userId);
      const historyEntry = await storage.addVideoHistory({
        userId,
        prompt: `[Character: ${character.name}] ${prompt}`,
        aspectRatio,
        status: "pending",
        tokenUsed: rotationToken?.id || null,
        referenceImageUrl: character.imageUrl
      });
      console.log(`[Character Video] Operation started: ${operationName}`);
      res.json({
        operationName,
        sceneId,
        historyId: historyEntry.id,
        tokenId: rotationToken?.id || null,
        characterName: character.name
      });
    } catch (error) {
      await handleTokenError(rotationToken?.id, error);
      console.error("Error generating character video:", error);
      res.status(500).json({
        error: "Failed to generate character video",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/character-bulk-generate", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "imageToVideo");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const toolMaintenance2 = await storage.getToolMaintenance();
      if (!toolMaintenance2?.characterConsistencyActive && !user.isAdmin) {
        return res.status(503).json({
          error: "Tool unavailable",
          message: "Character Consistency tool is currently under maintenance. Please try again later."
        });
      }
      const schema = z2.object({
        characterId: z2.string().min(1, "Character ID is required"),
        prompts: z2.array(z2.string().min(3, "Each prompt must be at least 3 characters")).min(1).max(100),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape"),
        lockSeed: z2.boolean().default(false)
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid input",
          details: validationResult.error.errors
        });
      }
      const { characterId, prompts, aspectRatio, lockSeed } = validationResult.data;
      const character = await storage.getCharacterById(characterId);
      if (!character) {
        return res.status(404).json({ error: "Character not found" });
      }
      if (character.userId !== userId) {
        return res.status(403).json({ error: "Not authorized to use this character" });
      }
      const lockedSeed = lockSeed ? Math.floor(Math.random() * 1e5) : null;
      console.log(`[Character Bulk] User: ${user.username}, Character: ${character.name} (Type: ${character.characterType}), Prompts: ${prompts.length}, Lock Seed: ${lockSeed}${lockSeed ? ` (seed: ${lockedSeed})` : ""}`);
      try {
        stopAllProcessing(userId);
        const deleteResult = await db.delete(videoHistory).where(
          and3(
            eq3(videoHistory.userId, userId),
            or(
              eq3(videoHistory.status, "pending"),
              eq3(videoHistory.status, "generating"),
              eq3(videoHistory.status, "queued"),
              eq3(videoHistory.status, "retrying"),
              eq3(videoHistory.status, "initializing")
            )
          )
        ).returning({ id: videoHistory.id });
        if (deleteResult.length > 0) {
          console.log(`[Character Bulk] Fast-cleared ${deleteResult.length} stuck/pending videos for user ${user.username}`);
        }
      } catch (error) {
        console.error("[Character Bulk] Error auto-clearing stuck videos:", error);
      }
      const results = [];
      if (character.characterType === "text") {
        console.log(`[Character Bulk Text] Using Whisk flow (Image \u2192 Video) - ${prompts.length} videos`);
        const allActiveTokens = await storage.getActiveApiTokens();
        if (allActiveTokens.length === 0) {
          throw new Error("No active API tokens available");
        }
        console.log(`[Character Bulk Text] Available tokens: ${allActiveTokens.length} for ${prompts.length} videos`);
        const WHISK_BASE_URL3 = "https://aisandbox-pa.googleapis.com/v1";
        const batchTimestamp = Date.now();
        const allItems = [];
        const DB_BATCH_SIZE = 10;
        for (let dbBatchStart = 0; dbBatchStart < prompts.length; dbBatchStart += DB_BATCH_SIZE) {
          const dbBatchEnd = Math.min(dbBatchStart + DB_BATCH_SIZE, prompts.length);
          const dbBatchPrompts = prompts.slice(dbBatchStart, dbBatchEnd);
          const dbBatchResults = await Promise.all(
            dbBatchPrompts.map(async (currentPrompt, dbIdx) => {
              const globalIdx = dbBatchStart + dbIdx;
              const augmentedPrompt = `${currentPrompt}

Character details: ${character.description || ""}`;
              const seed = lockedSeed !== null ? lockedSeed : Math.floor(Math.random() * 1e5);
              const sceneId = `character-bulk-text-${batchTimestamp}-${globalIdx}`;
              const token = allActiveTokens[globalIdx % allActiveTokens.length];
              const historyEntry = await storage.addVideoHistory({
                userId,
                prompt: `[Character: ${character.name}] ${augmentedPrompt}`,
                aspectRatio,
                status: "pending",
                tokenUsed: token.id,
                referenceImageUrl: null
              });
              return {
                index: globalIdx,
                prompt: currentPrompt,
                augmentedPrompt,
                sceneId,
                seed,
                historyId: historyEntry.id,
                token
              };
            })
          );
          allItems.push(...dbBatchResults);
        }
        console.log(`[Character Bulk Text] Created ${allItems.length} history entries - starting Whisk flow`);
        const generateWhiskImage3 = async (apiKey, prompt, aspectRatio2, seed) => {
          const workflowId = crypto3.randomUUID();
          const sessionId = `;${Date.now()}`;
          const imageAspectRatio = aspectRatio2 === "portrait" || aspectRatio2 === "9:16" ? "IMAGE_ASPECT_RATIO_PORTRAIT" : "IMAGE_ASPECT_RATIO_LANDSCAPE";
          const requestBody = {
            clientContext: {
              workflowId,
              tool: "BACKBONE",
              sessionId
            },
            imageModelSettings: {
              imageModel: "IMAGEN_3_5",
              aspectRatio: imageAspectRatio
            },
            seed,
            prompt,
            mediaCategory: "MEDIA_CATEGORY_BOARD"
          };
          const response = await fetch(`${WHISK_BASE_URL3}/whisk:generateImage`, {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${apiKey}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify(requestBody)
          });
          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Image generation failed: ${response.status} - ${errorText.substring(0, 200)}`);
          }
          const data = await response.json();
          if (!data.imagePanels || data.imagePanels.length === 0 || !data.imagePanels[0].generatedImages || data.imagePanels[0].generatedImages.length === 0) {
            throw new Error("No image generated from Whisk API");
          }
          const generatedImage = data.imagePanels[0].generatedImages[0];
          return {
            encodedImage: generatedImage.encodedImage,
            mediaGenerationId: generatedImage.mediaGenerationId,
            workflowId: data.workflowId || workflowId
          };
        };
        const startWhiskVideoGeneration3 = async (apiKey, prompt, encodedImage, mediaGenerationId, workflowId) => {
          const sessionId = `;${Date.now()}`;
          const requestBody = {
            clientContext: {
              sessionId,
              tool: "BACKBONE",
              workflowId
            },
            promptImageInput: {
              prompt,
              rawBytes: encodedImage,
              mediaGenerationId
            },
            modelNameType: "VEO_3_1_I2V_12STEP",
            modelKey: "",
            userInstructions: prompt,
            loopVideo: false
          };
          const response = await fetch(`${WHISK_BASE_URL3}/whisk:generateVideo`, {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${apiKey}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify(requestBody)
          });
          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Video generation start failed: ${response.status} - ${errorText.substring(0, 200)}`);
          }
          const data = await response.json();
          if (!data.operation?.operation?.name) {
            throw new Error("No operation name returned from video generation");
          }
          return data.operation.operation.name;
        };
        const processTextVideo = async (item) => {
          const maxRetries = 20;
          const usedTokenIds = /* @__PURE__ */ new Set();
          let currentToken = item.token;
          usedTokenIds.add(currentToken.id);
          const shuffledTokens = [...allActiveTokens].sort(() => Math.random() - 0.5);
          for (let attempt = 1; attempt <= maxRetries; attempt++) {
            if (attempt > 1) {
              const jitter = 200 + Math.random() * 300;
              await new Promise((resolve) => setTimeout(resolve, jitter));
              const unusedToken = shuffledTokens.find((t) => !usedTokenIds.has(t.id));
              if (unusedToken) {
                currentToken = unusedToken;
                usedTokenIds.add(currentToken.id);
              } else {
                currentToken = shuffledTokens[Math.floor(Math.random() * shuffledTokens.length)];
              }
            }
            console.log(`[Character Bulk Text] Video ${item.index + 1}: Attempt ${attempt}/${maxRetries} with token ${currentToken.label}`);
            try {
              const imageResult = await generateWhiskImage3(
                currentToken.token,
                item.augmentedPrompt,
                aspectRatio,
                item.seed
              );
              console.log(`[Character Bulk Text] Video ${item.index + 1}: Image generated, starting video...`);
              const operationName = await startWhiskVideoGeneration3(
                currentToken.token,
                item.augmentedPrompt,
                imageResult.encodedImage,
                imageResult.mediaGenerationId,
                imageResult.workflowId
              );
              item.operationName = operationName;
              await storage.updateVideoHistoryFields(item.historyId, {
                operationName: item.operationName,
                sceneId: item.sceneId,
                tokenUsed: currentToken.id
              });
              await storage.incrementDailyVideoCount(userId);
              console.log(`[Character Bulk Text] Video ${item.index + 1} started successfully with token ${currentToken.label}`);
              return;
            } catch (retryError) {
              const errorMsg = retryError instanceof Error ? retryError.message : "Unknown error";
              console.error(`[Character Bulk Text] Video ${item.index + 1} attempt ${attempt} failed:`, errorMsg);
              if (attempt === maxRetries) {
                item.error = `${errorMsg} (Failed after ${maxRetries} attempts)`;
                await storage.updateVideoHistoryFields(item.historyId, {
                  status: "failed",
                  errorMessage: item.error
                });
              }
            }
          }
        };
        const startTime = Date.now();
        await Promise.all(allItems.map((item) => processTextVideo(item)));
        const elapsed = Date.now() - startTime;
        console.log(`[Character Bulk Text] Whisk flow complete in ${elapsed}ms`);
        for (const item of allItems) {
          if (item.operationName) {
            results.push({
              prompt: item.augmentedPrompt,
              operationName: item.operationName,
              sceneId: item.sceneId,
              historyId: item.historyId,
              tokenId: item.token.id
            });
          } else {
            results.push({
              prompt: item.augmentedPrompt,
              error: item.error || "Unknown error"
            });
          }
        }
      } else {
        console.log(`[Character Bulk] Image-based character flow - FULL PARALLEL with PER-VIDEO TOKEN`);
        console.log(`[Character Bulk] Total prompts: ${prompts.length} - Each gets unique token`);
        console.log(`[Character Bulk] Step 1: Pre-downloading character image...`);
        if (!character.imageUrl) {
          throw new Error("Character has no image URL");
        }
        const imageResponse = await fetch(character.imageUrl);
        if (!imageResponse.ok) {
          throw new Error(`Failed to fetch character image: ${imageResponse.statusText}`);
        }
        const imageBuffer = Buffer.from(await imageResponse.arrayBuffer());
        const imageBase64 = imageBuffer.toString("base64");
        const imageMimeType = character.imageUrl.includes(".png") ? "image/png" : "image/jpeg";
        console.log(`[Character Bulk] Image pre-downloaded (${Math.round(imageBuffer.length / 1024)}KB)`);
        const allActiveTokens = await storage.getActiveApiTokens();
        if (allActiveTokens.length === 0) {
          throw new Error("No active API tokens available");
        }
        console.log(`[Character Bulk] Available tokens: ${allActiveTokens.length} for ${prompts.length} videos`);
        const veoProjectId = process.env.VEO3_PROJECT_ID || "08ea5ad2-6dad-43cc-9963-072a0d1c7d36";
        const DB_BATCH_SIZE = 10;
        console.log(`[Character Bulk] Creating history entries for ${prompts.length} videos...`);
        const allItems = [];
        for (let dbBatchStart = 0; dbBatchStart < prompts.length; dbBatchStart += DB_BATCH_SIZE) {
          const dbBatchEnd = Math.min(dbBatchStart + DB_BATCH_SIZE, prompts.length);
          const dbBatchPrompts = prompts.slice(dbBatchStart, dbBatchEnd);
          const dbBatchResults = await Promise.all(
            dbBatchPrompts.map(async (currentPrompt, dbIdx) => {
              const globalIdx = dbBatchStart + dbIdx;
              const characterInfo = character.name ? `

Character: ${character.name}` : "";
              const augmentedPrompt = `${currentPrompt}${characterInfo}`;
              const seed = lockedSeed !== null ? lockedSeed : Math.floor(Math.random() * 1e5);
              const sceneId = `character-bulk-${Date.now()}-${globalIdx}`;
              const token = allActiveTokens[globalIdx % allActiveTokens.length];
              const historyEntry = await storage.addVideoHistory({
                userId,
                prompt: augmentedPrompt,
                aspectRatio,
                status: "pending",
                tokenUsed: token.id,
                referenceImageUrl: character.imageUrl
              });
              return {
                index: globalIdx,
                prompt: currentPrompt,
                augmentedPrompt,
                sceneId,
                seed,
                historyId: historyEntry.id,
                token
              };
            })
          );
          allItems.push(...dbBatchResults);
        }
        console.log(`[Character Bulk] Created ${allItems.length} history entries`);
        console.log(`[Character Bulk] Starting PARALLEL processing of ${allItems.length} videos...`);
        const startTime = Date.now();
        const processVideo = async (item) => {
          const maxRetries = 20;
          const usedTokenIds = /* @__PURE__ */ new Set();
          let currentToken = item.token;
          usedTokenIds.add(currentToken.id);
          const shuffledTokens = [...allActiveTokens].sort(() => Math.random() - 0.5);
          for (let attempt = 1; attempt <= maxRetries; attempt++) {
            if (attempt > 1) {
              await new Promise((resolve) => setTimeout(resolve, 1e3));
              const unusedToken = shuffledTokens.find((t) => !usedTokenIds.has(t.id));
              if (unusedToken) {
                currentToken = unusedToken;
                usedTokenIds.add(currentToken.id);
              } else {
                currentToken = shuffledTokens[Math.floor(Math.random() * shuffledTokens.length)];
              }
            }
            console.log(`[Character Bulk] Video ${item.index + 1}: Attempt ${attempt}/${maxRetries} with token ${currentToken.label}`);
            try {
              const uploadPayload = {
                imageInput: {
                  rawImageBytes: imageBase64,
                  mimeType: imageMimeType
                }
              };
              const uploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
                method: "POST",
                headers: {
                  "Authorization": `Bearer ${currentToken.token}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify(uploadPayload)
              });
              if (!uploadResponse.ok) {
                const uploadText = await uploadResponse.text();
                if (isAuthenticationError(new Error(uploadText))) {
                  await storage.toggleApiTokenStatus(currentToken.id, false);
                }
                throw new Error(`Upload failed: ${uploadResponse.status}`);
              }
              const uploadData = await uploadResponse.json();
              const mediaId = uploadData.mediaGenerationId?.mediaGenerationId || uploadData.mediaGenerationId;
              if (!mediaId) {
                throw new Error("No mediaId returned");
              }
              item.mediaId = mediaId;
              const payload = {
                clientContext: {
                  sessionId: `session-${Date.now()}-${item.index}`,
                  projectId: veoProjectId,
                  tool: "PINHOLE",
                  userPaygateTier: "PAYGATE_TIER_TWO"
                },
                requests: [{
                  aspectRatio: aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
                  metadata: { sceneId: item.sceneId },
                  referenceImages: [
                    {
                      imageUsageType: "IMAGE_USAGE_TYPE_ASSET",
                      mediaId
                    },
                    {
                      imageUsageType: "IMAGE_USAGE_TYPE_ASSET",
                      mediaId
                    }
                  ],
                  seed: item.seed,
                  textInput: { prompt: item.augmentedPrompt },
                  videoModelKey: "veo_3_0_r2v_fast_ultra"
                }]
              };
              const genResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoReferenceImages", {
                method: "POST",
                headers: {
                  "Authorization": `Bearer ${currentToken.token}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
              });
              const genResult = await genResponse.json();
              if (!genResponse.ok || !genResult.operations?.[0]?.operation?.name) {
                const errorMsg = genResult?.error?.message || "Video gen failed";
                if (isAuthenticationError(new Error(errorMsg))) {
                  await storage.toggleApiTokenStatus(currentToken.id, false);
                }
                throw new Error(errorMsg);
              }
              item.operationName = genResult.operations[0].operation.name;
              await storage.updateVideoHistoryFields(item.historyId, {
                operationName: item.operationName,
                sceneId: item.sceneId,
                tokenUsed: currentToken.id
              });
              await storage.incrementDailyVideoCount(userId);
              console.log(`[Character Bulk] \u2705 Video ${item.index + 1}/${prompts.length} started (token: ${currentToken.label})`);
              return;
            } catch (err) {
              const errMsg = err instanceof Error ? err.message : "Unknown error";
              if (attempt === maxRetries) {
                item.error = `Failed after ${maxRetries} attempts: ${errMsg}`;
                await storage.updateVideoHistoryStatus(item.historyId, userId, "failed", void 0, item.error);
                console.error(`[Character Bulk] \u274C Video ${item.index + 1} failed: ${errMsg}`);
              } else {
                await new Promise((r) => setTimeout(r, 100));
              }
            }
          }
        };
        await Promise.all(allItems.map((item) => processVideo(item)));
        const elapsed = ((Date.now() - startTime) / 1e3).toFixed(1);
        const successCount = allItems.filter((i) => i.operationName).length;
        const failCount = allItems.filter((i) => i.error).length;
        console.log(`
[Character Bulk] ========== PARALLEL COMPLETE ==========`);
        console.log(`[Character Bulk] Time: ${elapsed}s for ${prompts.length} videos`);
        console.log(`[Character Bulk] Success: ${successCount}, Failed: ${failCount}`);
        for (const item of allItems) {
          if (item.operationName) {
            results.push({
              prompt: item.augmentedPrompt,
              operationName: item.operationName,
              sceneId: item.sceneId,
              historyId: item.historyId,
              tokenId: item.token.id
            });
          } else if (item.error) {
            results.push({
              prompt: item.augmentedPrompt,
              error: item.error,
              historyId: item.historyId
            });
          }
        }
      }
      res.json({
        results,
        characterName: character.name,
        totalVideos: prompts.length,
        successfulStarts: results.filter((r) => r.operationName).length,
        failedStarts: results.filter((r) => r.error).length
      });
    } catch (error) {
      console.error("Error in character bulk generation:", error);
      res.status(500).json({
        error: "Failed to generate character videos",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/script-to-frames/generate-videos-stream", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const toolCheck = canAccessTool(user, "veo");
      if (!toolCheck.allowed) {
        return res.status(403).json({ error: toolCheck.reason });
      }
      const schema = z2.object({
        scenes: z2.array(z2.object({
          sceneNumber: z2.number(),
          videoPrompt: z2.string().min(3),
          startImageBase64: z2.string(),
          startImageMimeType: z2.string(),
          endImageBase64: z2.string(),
          endImageMimeType: z2.string()
        })).min(1).max(50),
        aspectRatio: z2.enum(["landscape", "portrait"]).default("landscape")
      });
      const validationResult = schema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({ error: "Invalid input", details: validationResult.error.errors });
      }
      const { scenes, aspectRatio } = validationResult.data;
      console.log(`[Script-to-Frames Video PARALLEL] Starting batch of ${scenes.length} videos, User: ${user.username}`);
      const batchStartTime = Date.now();
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.setHeader("Transfer-Encoding", "chunked");
      if (res.socket) {
        res.socket.setNoDelay(true);
        res.socket.setTimeout(0);
      }
      res.flushHeaders();
      const sendEvent = (event, data) => {
        res.write(`event: ${event}
data: ${JSON.stringify(data)}

`);
      };
      const activeTokens = await storage.getActiveApiTokens();
      if (activeTokens.length === 0) {
        sendEvent("error", { error: "No active API tokens available" });
        res.end();
        return;
      }
      const videoAspectRatio = aspectRatio === "landscape" ? "VIDEO_ASPECT_RATIO_LANDSCAPE" : "VIDEO_ASPECT_RATIO_PORTRAIT";
      const videoModelKey = "veo_3_1_i2v_s_fast_ultra_fl";
      const sceneTokenAssignments = scenes.map((scene, index2) => {
        const token = activeTokens[index2 % activeTokens.length];
        return { scene, token, apiKey: token.token };
      });
      console.log(`[Script-to-Frames PARALLEL] Token assignments:`);
      sceneTokenAssignments.forEach(({ scene, token }) => {
        console.log(`  Scene ${scene.sceneNumber} -> Token ${token.label}`);
      });
      const processScene = async (scene, initialToken, initialApiKey, sceneIndex) => {
        const MAX_SILENT_RETRIES2 = 3;
        const excludedTokenIds = /* @__PURE__ */ new Set();
        let currentToken = initialToken;
        let currentApiKey = initialApiKey;
        let silentRetryCount = 0;
        while (silentRetryCount <= MAX_SILENT_RETRIES2) {
          console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Using Token ${currentToken.label} (ID: ${currentToken.id})${silentRetryCount > 0 ? ` [Silent Retry ${silentRetryCount}/${MAX_SILENT_RETRIES2}]` : ""}`);
          sendEvent("status", {
            sceneNumber: scene.sceneNumber,
            status: "uploading",
            message: silentRetryCount > 0 ? `Retrying with new token...` : "Uploading start/end images...",
            tokenLabel: currentToken.label
          });
          try {
            console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Uploading start image...`);
            const startUploadPayload = {
              imageInput: {
                rawImageBytes: scene.startImageBase64,
                mimeType: scene.startImageMimeType
              }
            };
            const startUploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${currentApiKey}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify(startUploadPayload)
            });
            if (!startUploadResponse.ok) {
              const errorText = await startUploadResponse.text();
              throw new Error(`Start image upload failed: ${startUploadResponse.statusText} - ${errorText.substring(0, 200)}`);
            }
            const startUploadData = await startUploadResponse.json();
            const startMediaId = startUploadData.mediaGenerationId?.mediaGenerationId || startUploadData.mediaGenerationId;
            if (!startMediaId) {
              throw new Error("No media ID returned for start image");
            }
            console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Start image uploaded. Media ID: ${startMediaId}`);
            console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Uploading end image with SAME token...`);
            const endUploadPayload = {
              imageInput: {
                rawImageBytes: scene.endImageBase64,
                mimeType: scene.endImageMimeType
              }
            };
            const endUploadResponse = await fetch("https://aisandbox-pa.googleapis.com/v1:uploadUserImage", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${currentApiKey}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify(endUploadPayload)
            });
            if (!endUploadResponse.ok) {
              const errorText = await endUploadResponse.text();
              throw new Error(`End image upload failed: ${endUploadResponse.statusText} - ${errorText.substring(0, 200)}`);
            }
            const endUploadData = await endUploadResponse.json();
            const endMediaId = endUploadData.mediaGenerationId?.mediaGenerationId || endUploadData.mediaGenerationId;
            if (!endMediaId) {
              throw new Error("No media ID returned for end image");
            }
            console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: End image uploaded. Media ID: ${endMediaId}`);
            sendEvent("status", {
              sceneNumber: scene.sceneNumber,
              status: "generating",
              message: "Generating video...",
              tokenLabel: currentToken.label
            });
            console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Generating video with start/end images using SAME token...`);
            const videoPayload = {
              clientContext: {
                sessionId: `;${Date.now()}`,
                projectId: crypto3.randomUUID(),
                tool: "PINHOLE",
                userPaygateTier: "PAYGATE_TIER_TWO"
              },
              requests: [{
                aspectRatio: videoAspectRatio,
                seed: Math.floor(Math.random() * 1e5),
                textInput: { prompt: scene.videoPrompt },
                videoModelKey,
                startImage: { mediaId: startMediaId },
                endImage: { mediaId: endMediaId },
                metadata: { sceneId: `scene-${scene.sceneNumber}` }
              }]
            };
            const videoResponse = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoStartAndEndImage", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${currentApiKey}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify(videoPayload)
            });
            if (!videoResponse.ok) {
              const errorData = await videoResponse.json().catch(() => ({}));
              throw new Error(errorData.error?.message || `Video generation failed (${videoResponse.status})`);
            }
            const videoData = await videoResponse.json();
            const operationName = videoData.operations?.[0]?.operation?.name;
            if (!operationName) {
              throw new Error("No operation name returned from video generation");
            }
            console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Video generation started. Operation: ${operationName}`);
            await storage.updateTokenUsage(currentToken.id);
            sendEvent("status", {
              sceneNumber: scene.sceneNumber,
              status: "processing",
              message: "Video processing (~2 min)...",
              operationName,
              tokenLabel: currentToken.label
            });
            console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Waiting for video completion...`);
            const sceneIdForStatus = `scene-${scene.sceneNumber}`;
            const maxWaitTime = 3e5;
            const pollInterval = 15e3;
            const startWaitTime = Date.now();
            await new Promise((resolve) => setTimeout(resolve, 15e3));
            let videoUrl;
            let pollAttempts = 0;
            let needsSilentRetry = false;
            while (Date.now() - startWaitTime < maxWaitTime) {
              pollAttempts++;
              try {
                const statusResult = await checkVideoStatus(operationName, sceneIdForStatus, currentApiKey);
                console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber} poll ${pollAttempts}: ${statusResult.status}`);
                if (statusResult.needsTokenRetry) {
                  console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: needsTokenRetry detected! Initiating silent fast retry...`);
                  needsSilentRetry = true;
                  break;
                }
                if (statusResult.status === "COMPLETED" || statusResult.status === "MEDIA_GENERATION_STATUS_COMPLETE" || statusResult.status === "MEDIA_GENERATION_STATUS_SUCCESSFUL") {
                  if (statusResult.videoUrl) {
                    videoUrl = statusResult.videoUrl;
                    console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Video completed! URL received.`);
                    break;
                  }
                } else if (statusResult.status === "MEDIA_GENERATION_STATUS_FAILED" || statusResult.status === "FAILED") {
                  if (statusResult.error?.includes("INVALID_ARGUMENT") || statusResult.errorCode === 3) {
                    console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: INVALID_ARGUMENT error - token mismatch, triggering silent retry...`);
                    needsSilentRetry = true;
                    break;
                  }
                  throw new Error(statusResult.error || "Video generation failed");
                }
                await new Promise((resolve) => setTimeout(resolve, pollInterval));
              } catch (pollError) {
                console.error(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber} poll error:`, pollError);
                if (pollError.message?.includes("failed") && !pollError.message?.includes("INVALID_ARGUMENT")) {
                  throw pollError;
                }
                await new Promise((resolve) => setTimeout(resolve, pollInterval));
              }
            }
            if (needsSilentRetry) {
              silentRetryCount++;
              if (silentRetryCount > MAX_SILENT_RETRIES2) {
                console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Max silent retries (${MAX_SILENT_RETRIES2}) exceeded`);
                break;
              }
              const availableTokens = activeTokens.filter((t) => !excludedTokenIds.has(t.id));
              if (availableTokens.length === 0) {
                console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: No alternate tokens, retrying with same token ${currentToken.label}...`);
              } else if (availableTokens.length === 1 && availableTokens[0].id === currentToken.id) {
                console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Only current token available, retrying with ${currentToken.label}...`);
              } else {
                excludedTokenIds.add(currentToken.id);
                console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Excluding failed token ${currentToken.label}, switching to new token...`);
                const filteredTokens = availableTokens.filter((t) => t.id !== currentToken.id);
                if (filteredTokens.length > 0) {
                  currentToken = filteredTokens[(sceneIndex + silentRetryCount) % filteredTokens.length];
                  currentApiKey = currentToken.token;
                }
              }
              console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Silent retry ${silentRetryCount}/${MAX_SILENT_RETRIES2} with token ${currentToken.label}`);
              const retryDelay = Math.pow(2, silentRetryCount) * 1e3;
              await new Promise((resolve) => setTimeout(resolve, retryDelay));
              continue;
            }
            if (!videoUrl) {
              throw new Error("Video generation timed out after 5 minutes");
            }
            sendEvent("video", {
              sceneNumber: scene.sceneNumber,
              status: "completed",
              operationName,
              videoUrl,
              tokenId: currentToken.id,
              tokenLabel: currentToken.label
            });
            return { success: true, sceneNumber: scene.sceneNumber, videoUrl };
          } catch (error) {
            const errorMsg = error.message || "";
            const shouldSilentRetry = errorMsg.includes("INVALID_ARGUMENT") || errorMsg.includes("LMRoot") || errorMsg.includes("code 13") || errorMsg.includes("HIGH_TRAFFIC");
            if (shouldSilentRetry && silentRetryCount < MAX_SILENT_RETRIES2) {
              silentRetryCount++;
              console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Error triggered silent retry ${silentRetryCount}/${MAX_SILENT_RETRIES2}: ${errorMsg.substring(0, 100)}`);
              const availableTokens = activeTokens.filter((t) => !excludedTokenIds.has(t.id));
              if (availableTokens.length === 0) {
                console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: No alternate tokens, retrying with same token...`);
              } else if (availableTokens.length === 1 && availableTokens[0].id === currentToken.id) {
                console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Only current token available, retrying...`);
              } else {
                excludedTokenIds.add(currentToken.id);
                const filteredTokens = availableTokens.filter((t) => t.id !== currentToken.id);
                if (filteredTokens.length > 0) {
                  currentToken = filteredTokens[(sceneIndex + silentRetryCount) % filteredTokens.length];
                  currentApiKey = currentToken.token;
                  console.log(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: Switching to token ${currentToken.label}`);
                }
              }
              const retryDelay = Math.pow(2, silentRetryCount) * 1e3;
              await new Promise((resolve) => setTimeout(resolve, retryDelay));
              continue;
            }
            console.error(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber} failed:`, error);
            await handleTokenError(currentToken.id, error);
            sendEvent("video", {
              sceneNumber: scene.sceneNumber,
              status: "failed",
              error: error.message || "Unknown error",
              tokenLabel: currentToken.label
            });
            return { success: false, sceneNumber: scene.sceneNumber, error: error.message };
          }
        }
        console.error(`[Script-to-Frames PARALLEL] Scene ${scene.sceneNumber}: All retry attempts exhausted`);
        sendEvent("video", {
          sceneNumber: scene.sceneNumber,
          status: "failed",
          error: `Failed after ${MAX_SILENT_RETRIES2} silent retries`,
          tokenLabel: currentToken.label
        });
        return { success: false, sceneNumber: scene.sceneNumber, error: `Failed after ${MAX_SILENT_RETRIES2} silent retries` };
      };
      sceneTokenAssignments.forEach(({ scene, token }) => {
        sendEvent("status", {
          sceneNumber: scene.sceneNumber,
          status: "pending",
          message: "Waiting to start...",
          tokenLabel: token.label,
          progress: { current: 0, total: scenes.length }
        });
      });
      console.log(`[Script-to-Frames PARALLEL] Starting ${scenes.length} scene workers in parallel...`);
      const workers = sceneTokenAssignments.map(
        ({ scene, token, apiKey }, index2) => processScene(scene, token, apiKey, index2)
      );
      const results = await Promise.allSettled(workers);
      const successCount = results.filter((r) => r.status === "fulfilled" && r.value?.success).length;
      const failedCount = results.filter((r) => r.status === "rejected" || r.status === "fulfilled" && !r.value?.success).length;
      const duration = ((Date.now() - batchStartTime) / 1e3).toFixed(1);
      console.log(`[Script-to-Frames PARALLEL Complete] ${successCount}/${scenes.length} succeeded in ${duration}s`);
      sendEvent("complete", {
        success: true,
        summary: {
          total: scenes.length,
          success: successCount,
          failed: failedCount,
          duration: `${duration}s`
        }
      });
      res.end();
    } catch (error) {
      console.error("Error in /api/script-to-frames/generate-videos-stream:", error);
      res.write(`event: error
data: ${JSON.stringify({ error: "Batch video generation failed" })}

`);
      res.end();
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs4 from "fs";
import path5 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path4 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      ),
      await import("@replit/vite-plugin-dev-banner").then(
        (m) => m.devBanner()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path4.resolve(import.meta.dirname, "client", "src"),
      "@shared": path4.resolve(import.meta.dirname, "shared"),
      "@assets": path4.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path4.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path4.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log3(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path5.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs4.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const possiblePaths = [
    path5.resolve(import.meta.dirname, "public"),
    path5.resolve(process.cwd(), "dist", "public"),
    path5.resolve(import.meta.dirname, "..", "dist", "public")
  ];
  let distPath = "";
  for (const p of possiblePaths) {
    if (fs4.existsSync(p)) {
      distPath = p;
      console.log(`[Static] Serving static files from: ${distPath}`);
      break;
    }
  }
  if (!distPath) {
    throw new Error(
      `Could not find the build directory. Tried: ${possiblePaths.join(", ")}. Make sure to build the client first.`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path5.resolve(distPath, "index.html"));
  });
}

// server/index.ts
import crypto4 from "crypto";
process.on("uncaughtException", (error) => {
  console.error("[CRITICAL] Uncaught Exception (server still running):", error.message);
  if (error.stack) {
    console.error("[CRITICAL] Stack:", error.stack);
  }
});
process.on("unhandledRejection", (reason, promise) => {
  console.error("[CRITICAL] Unhandled Rejection at:", promise);
  console.error("[CRITICAL] Reason:", reason);
});
var app = express2();
var SESSION_SECRET = process.env.SESSION_SECRET || crypto4.randomBytes(64).toString("hex");
if (!process.env.SESSION_SECRET) {
  console.warn("[SECURITY] WARNING: Using auto-generated session secret. Set SESSION_SECRET env var for production!");
}
app.use((req, res, next) => {
  if (req.path === "/health" || req.path === "/" && req.headers["user-agent"]?.includes("kube-probe")) {
    return res.status(200).send("OK");
  }
  next();
});
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
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(compression({
  level: 6,
  // Balanced compression (1-9, higher = more compression but slower)
  threshold: 1024,
  // Only compress responses > 1KB
  filter: (req, res) => {
    if (req.path.includes("/local-video/") || req.path.includes("/stream-video/")) {
      return false;
    }
    if (req.path.includes("/stream") || req.headers.accept === "text/event-stream") {
      return false;
    }
    return compression.filter(req, res);
  }
}));
var globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  // 15 minutes
  max: 1e3,
  // Limit each IP to 1000 requests per window
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === "/health" || req.path.startsWith("/assets")
});
app.use(globalLimiter);
var loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  // 15 minutes
  max: 5,
  // Only 5 login attempts per window
  message: { error: "Too many login attempts. Please try again after 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
  // Don't count successful logins
});
app.use("/api/login", loginLimiter);
var adminLimiter = rateLimit({
  windowMs: 60 * 1e3,
  // 1 minute
  max: 100,
  message: { error: "Too many admin requests, please slow down." },
  standardHeaders: true,
  legacyHeaders: false
});
app.use("/api/admin", adminLimiter);
var generationLimiter = rateLimit({
  windowMs: 60 * 1e3,
  // 1 minute
  max: 30,
  message: { error: "Too many generation requests. Please wait before generating more." },
  standardHeaders: true,
  legacyHeaders: false
});
app.use("/api/generate", generationLimiter);
app.use("/api/text-to-image", generationLimiter);
app.use("/api/text-to-speech", generationLimiter);
app.use("/api/image-to-video", generationLimiter);
var PgStore = connectPgSimple(session);
app.set("trust proxy", 1);
app.use(express2.json({
  limit: "50mb",
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express2.urlencoded({ limit: "50mb", extended: false }));
var isProduction = process.env.NODE_ENV === "production";
app.use(
  session({
    secret: SESSION_SECRET,
    name: isProduction ? "__Host-session" : "session",
    // Secure prefix only in production (requires HTTPS)
    resave: false,
    saveUninitialized: false,
    store: new PgStore({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true,
      ttl: 24 * 60 * 60,
      // 1 day session TTL (reduced from 7 days for security)
      pruneSessionInterval: 300,
      // Clean expired sessions every 5 minutes (reduced frequency for VPS DB stability)
      errorLog: (error) => {
        console.error("[Session Store] Error (non-fatal):", error.message);
      }
    }),
    rolling: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1e3,
      // 1 day (reduced from 7 days)
      httpOnly: true,
      // Prevents JavaScript access to cookie
      secure: isProduction,
      // HTTPS only in production
      sameSite: isProduction ? "strict" : "lax",
      // Strict in production, lax in development
      path: "/"
    }
  })
);
console.log(`[Security] Session configured - Production mode: ${isProduction}`);
app.use((req, res, next) => {
  const start = Date.now();
  const path6 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path6.startsWith("/api")) {
      let logLine = `${req.method} ${path6} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log3(logLine);
    }
  });
  next();
});
(async () => {
  const { storage: storage2 } = await Promise.resolve().then(() => (init_storage(), storage_exports));
  await storage2.initializeDefaultAdmin();
  await storage2.initializeTokenSettings();
  await storage2.initializeAutoRetrySettings();
  await storage2.initializePlanAvailability();
  await storage2.initializeAppSettings();
  await storage2.initializeToolMaintenance();
  try {
    const { initLocalDiskStorage: initLocalDiskStorage2 } = await Promise.resolve().then(() => (init_localDiskStorage(), localDiskStorage_exports));
    await initLocalDiskStorage2();
    console.log("[LocalDisk] Local disk storage initialized");
  } catch (localDiskError) {
    console.error("[LocalDisk] Failed to initialize local disk storage:", localDiskError);
  }
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    console.error(`[Error Handler] ${status}: ${message}`);
    if (err.stack && process.env.NODE_ENV !== "production") {
      console.error(`[Error Stack] ${err.stack}`);
    }
    res.status(status).json({ message });
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  let lastCleanupDate = "";
  const checkAndCleanupHistory = async () => {
    try {
      const now = /* @__PURE__ */ new Date();
      const pktTime = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Karachi" }));
      const currentDate = pktTime.toLocaleDateString("en-US", { timeZone: "Asia/Karachi" });
      const currentHour = pktTime.getHours();
      const currentMinute = pktTime.getMinutes();
      if (currentHour === 0 && currentMinute === 0 && currentDate !== lastCleanupDate) {
        console.log(`[Daily Cleanup] Running cleanup tasks at midnight PKT (${currentDate})`);
        const newTotal = await storage2.incrementTotalVideosGeneratedBy(2e4);
        console.log(`[Daily Cleanup] Total videos counter incremented by 20,000. New total: ${newTotal}`);
        await storage2.checkAndResetDailyCounts();
        console.log("[Daily Cleanup] Daily video counts reset successfully");
        await storage2.clearAllVideoHistory();
        console.log("[Daily Cleanup] Video history cleared successfully");
        try {
          const { ObjectStorageService: ObjectStorageService2 } = await Promise.resolve().then(() => (init_objectStorage(), objectStorage_exports));
          const objectStorageService2 = new ObjectStorageService2();
          const deletedCount = await objectStorageService2.cleanupExpiredVideos();
          console.log(`[Daily Cleanup] Deleted ${deletedCount} expired temporary videos`);
        } catch (tempVideoError) {
          console.error("[Daily Cleanup] Error cleaning up temporary videos:", tempVideoError);
        }
        lastCleanupDate = currentDate;
        console.log("[Daily Cleanup] All cleanup tasks completed");
      }
    } catch (error) {
      console.error("[Daily Cleanup] Error during cleanup:", error);
    }
  };
  const checkAndCleanupTempVideos = async () => {
    try {
      const { ObjectStorageService: ObjectStorageService2 } = await Promise.resolve().then(() => (init_objectStorage(), objectStorage_exports));
      const objectStorageService2 = new ObjectStorageService2();
      const deletedCount = await objectStorageService2.cleanupExpiredVideos();
      if (deletedCount > 0) {
        console.log(`[Hourly Cleanup] Deleted ${deletedCount} expired temporary videos`);
      }
    } catch (error) {
      console.error("[Hourly Cleanup] Error cleaning up temporary videos:", error);
    }
  };
  setInterval(checkAndCleanupHistory, 6e4);
  console.log("[Daily Cleanup] History cleanup job scheduled for midnight PKT");
  setInterval(checkAndCleanupTempVideos, 60 * 60 * 1e3);
  console.log("[Hourly Cleanup] Temporary video cleanup scheduled (runs every hour)");
  const cleanupOldLogs = async () => {
    try {
      const fs5 = await import("fs");
      const path6 = await import("path");
      const logDir = "/tmp/logs";
      if (!fs5.existsSync(logDir)) return;
      const files = fs5.readdirSync(logDir);
      const oneDayAgo = Date.now() - 24 * 60 * 60 * 1e3;
      let deletedCount = 0;
      for (const file of files) {
        const filePath = path6.join(logDir, file);
        try {
          const stats = fs5.statSync(filePath);
          if (stats.mtime.getTime() < oneDayAgo) {
            fs5.unlinkSync(filePath);
            deletedCount++;
          }
        } catch (e) {
        }
      }
      if (deletedCount > 0) {
        console.log(`[Log Cleanup] Deleted ${deletedCount} log files older than 1 day`);
      }
    } catch (error) {
      console.error("[Log Cleanup] Error:", error);
    }
  };
  setInterval(cleanupOldLogs, 20 * 60 * 1e3);
  cleanupOldLogs();
  console.log("[Log Cleanup] Old log file cleanup scheduled (runs every 20 minutes)");
  const checkAndTimeoutPendingVideos = async () => {
    const retryDbOp = async (fn, maxRetries = 3) => {
      for (let i = 0; i < maxRetries; i++) {
        try {
          return await fn();
        } catch (e) {
          if (i === maxRetries - 1) throw e;
          await new Promise((r) => setTimeout(r, 1e3 * Math.pow(2, i)));
        }
      }
      return null;
    };
    try {
      const { db: db2 } = await Promise.resolve().then(() => (init_db(), db_exports));
      const { videoHistory: videoHistory2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const { sql: sql4 } = await import("drizzle-orm");
      const timedOutVideos = await retryDbOp(() => db2.execute(sql4`
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
      const stuckVideos = await retryDbOp(() => db2.execute(sql4`
        SELECT id, retry_count, prompt, aspect_ratio, user_id, error_message, 
               operation_name, scene_id, token_used, reference_image_url
        FROM video_history 
        WHERE status = 'pending' 
        AND (NOW() - updated_at::timestamp) > INTERVAL '30 minutes'
      `));
      if (!stuckVideos || !stuckVideos.rows || stuckVideos.rows.length === 0) {
        return;
      }
      console.log(`[Timeout Cleanup] Found ${stuckVideos.rows.length} stuck videos - marking as failed`);
      for (const video of stuckVideos.rows) {
        try {
          await retryDbOp(() => db2.execute(sql4`
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
    } catch (error) {
      console.error("[Timeout Cleanup] Error in cleanup logic:", error);
    }
  };
  setInterval(checkAndTimeoutPendingVideos, 2 * 60 * 1e3);
  console.log("[Timeout Cleanup] Pending video timeout job scheduled (runs every 2 minutes)");
  const autoRetryFailedVideos = async () => {
    try {
      const settings = await storage2.getAutoRetrySettings();
      if (!settings || !settings.enableAutoRetry) {
        return;
      }
      const eligibleVideos = await storage2.getEligibleFailedVideosForRetry();
      if (eligibleVideos.length === 0) {
        return;
      }
      console.log(`[Auto-Retry] Found ${eligibleVideos.length} failed videos eligible for retry`);
      console.log(`[Auto-Retry] \u{1F3B2} Pre-assigning ${eligibleVideos.length} unique tokens to videos...`);
      const videosWithTokens = [];
      for (const video of eligibleVideos) {
        const token = await storage2.getNextRotationToken();
        if (token) {
          await storage2.updateTokenUsage(token.id);
          videosWithTokens.push({ video, token });
          console.log(`[Auto-Retry] \u2705 Video ${video.id.substring(0, 8)} \u2192 Token: ${token.label}`);
        } else {
          videosWithTokens.push({ video, token: void 0 });
          console.log(`[Auto-Retry] \u26A0\uFE0F Video ${video.id.substring(0, 8)} \u2192 No token (will use env fallback)`);
        }
      }
      const retryPromises = videosWithTokens.map(async ({ video, token }) => {
        try {
          await storage2.markVideoAsRetrying(video.id);
          console.log(`[Auto-Retry] \u{1F504} Retrying video ${video.id.substring(0, 8)} with token ${token?.label || "ENV"} (attempt ${video.retryCount + 1}/${settings.maxRetryAttempts})`);
          const apiKey = token?.token || process.env.VEO3_API_KEY;
          if (!apiKey) {
            throw new Error("No API key available for retry");
          }
          const veoProjectId = process.env.VEO3_PROJECT_ID || "5fdc3f34-d4c6-4afb-853a-aba4390bafdc";
          const sceneId = `auto-retry-${video.id}-${Date.now()}`;
          const seed = Math.floor(Math.random() * 1e5);
          await storage2.updateVideoHistoryStatus(video.id, video.userId, "pending");
          const payload = {
            clientContext: {
              projectId: veoProjectId,
              tool: "PINHOLE",
              userPaygateTier: "PAYGATE_TIER_TWO"
            },
            requests: [{
              aspectRatio: video.aspectRatio === "portrait" ? "VIDEO_ASPECT_RATIO_PORTRAIT" : "VIDEO_ASPECT_RATIO_LANDSCAPE",
              seed,
              textInput: { prompt: video.prompt },
              videoModelKey: video.aspectRatio === "portrait" ? "veo_3_1_t2v_fast_portrait_ultra" : "veo_3_1_t2v_fast_ultra",
              metadata: { sceneId }
            }]
          };
          const response = await fetch("https://aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${apiKey}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
          });
          if (!response.ok) {
            const errorText = await response.text();
            console.error(`[Auto-Retry] \u274C VEO API failed for video ${video.id.substring(0, 8)}:`, errorText);
            await storage2.updateVideoHistoryStatus(video.id, video.userId, "failed", void 0, `VEO API error: ${errorText}`);
            if (token) {
              await storage2.recordTokenError(token.id);
            }
            return;
          }
          const data = await response.json();
          const operationName = data.operations?.[0]?.operation?.name;
          if (!operationName) {
            throw new Error("No operation name in VEO response");
          }
          const { startBackgroundPolling: startBackgroundPolling2 } = await Promise.resolve().then(() => (init_bulkQueue(), bulkQueue_exports));
          startBackgroundPolling2(video.id, video.userId, operationName, sceneId, apiKey, token);
          console.log(`[Auto-Retry] \u2705 Video ${video.id.substring(0, 8)} queued with operation ${operationName}`);
        } catch (error) {
          console.error(`[Auto-Retry] \u274C Error retrying video ${video.id.substring(0, 8)}:`, error);
          await storage2.updateVideoHistoryStatus(video.id, video.userId, "failed", void 0, `Retry error: ${error instanceof Error ? error.message : "Unknown error"}`);
        }
      });
      await Promise.all(retryPromises);
      console.log(`[Auto-Retry] \u{1F389} Completed processing ${videosWithTokens.length} videos with token rotation`);
    } catch (error) {
      console.error("[Auto-Retry] Error in auto-retry job:", error);
    }
  };
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log3(`serving on port ${port}`);
  });
})();
