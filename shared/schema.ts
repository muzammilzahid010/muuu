import { sql } from "drizzle-orm";
import { pgTable, text, varchar, boolean, integer, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  isAdmin: boolean("is_admin").notNull().default(false),
  planType: text("plan_type").notNull().default("free"),
  planStatus: text("plan_status").notNull().default("active"),
  planStartDate: text("plan_start_date").default(sql`null`),
  planExpiry: text("plan_expiry").default(sql`null`),
  dailyVideoCount: integer("daily_video_count").notNull().default(0),
  dailyVideoLimit: integer("daily_video_limit"), // Custom limit for enterprise users (null = use default plan limits)
  bulkMaxBatch: integer("bulk_max_batch"), // Custom bulk batch size for enterprise users
  bulkDelaySeconds: integer("bulk_delay_seconds"), // Custom delay between batches for enterprise users
  bulkMaxPrompts: integer("bulk_max_prompts"), // Custom max prompts for enterprise users
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
  voiceCharactersResetDate: text("voice_characters_reset_date").default(sql`null`),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  isAdmin: true,
}).extend({
  planType: z.enum(["free", "scale", "empire", "enterprise"]).optional(),
  planStartDate: z.string().optional(),
  planExpiry: z.string().optional(),
  dailyVideoLimit: z.number().int().min(0).optional(), // Custom limit for enterprise users (0 = unlimited)
  expiryDays: z.number().int().min(1).optional(), // Custom expiry duration for enterprise users
  bulkMaxBatch: z.number().int().min(1).optional(), // Custom bulk batch size for enterprise users
  bulkDelaySeconds: z.number().int().min(0).optional(), // Custom delay between batches for enterprise users
  bulkMaxPrompts: z.number().int().min(1).optional(), // Custom max prompts for enterprise users
});

export const updateUserPlanSchema = z.object({
  planType: z.enum(["free", "scale", "empire", "enterprise"]),
  planStatus: z.enum(["active", "expired", "cancelled"]),
  planStartDate: z.string().optional(),
  planExpiry: z.string().optional(),
  dailyVideoLimit: z.number().int().min(0).optional(), // Custom limit for enterprise users (0 = unlimited)
  expiryDays: z.number().int().min(1).optional(), // Custom expiry duration for enterprise users (recalculates planExpiry)
  bulkMaxBatch: z.number().int().min(1).optional(), // Custom bulk batch size for enterprise users
  bulkDelaySeconds: z.number().int().min(0).optional(), // Custom delay between batches for enterprise users
  bulkMaxPrompts: z.number().int().min(1).optional(), // Custom max prompts for enterprise users
});

export const updateUserApiTokenSchema = z.object({
  apiToken: z.string(),
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type UpdateUserPlan = z.infer<typeof updateUserPlanSchema>;
export type UpdateUserApiToken = z.infer<typeof updateUserApiTokenSchema>;

export const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

export type LoginInput = z.infer<typeof loginSchema>;

// API Token Pool for automatic rotation
export const apiTokens = pgTable("api_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  token: text("token").notNull().unique(),
  label: text("label").notNull(),
  isActive: boolean("is_active").notNull().default(true),
  lastUsedAt: text("last_used_at"),
  requestCount: text("request_count").notNull().default("0"),
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

// Token rotation settings
export const tokenSettings = pgTable("token_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  rotationEnabled: boolean("rotation_enabled").notNull().default(false),
  rotationIntervalMinutes: text("rotation_interval_minutes").notNull().default("60"),
  maxRequestsPerToken: text("max_requests_per_token").notNull().default("1000"),
  videosPerBatch: text("videos_per_batch").notNull().default("10"),
  batchDelaySeconds: text("batch_delay_seconds").notNull().default("20"),
  nextRotationIndex: integer("next_rotation_index").notNull().default(0), // Track which token to use next
});

export const insertApiTokenSchema = createInsertSchema(apiTokens).pick({
  token: true,
  label: true,
});

export const bulkReplaceTokensSchema = z.object({
  tokens: z.string().min(1, "Please enter at least one token"),
});

export const updateTokenSettingsSchema = z.object({
  rotationEnabled: z.boolean().optional(),
  rotationIntervalMinutes: z.string().optional(),
  maxRequestsPerToken: z.string().optional(),
  videosPerBatch: z.string().optional(),
  batchDelaySeconds: z.string().optional(),
  // nextRotationIndex is INTERNAL ONLY - not exposed to admin panel
  // Only the rotation algorithm should update this field
});

export type ApiToken = typeof apiTokens.$inferSelect;
export type InsertApiToken = z.infer<typeof insertApiTokenSchema>;
export type BulkReplaceTokens = z.infer<typeof bulkReplaceTokensSchema>;
export type TokenSettings = typeof tokenSettings.$inferSelect;
export type UpdateTokenSettings = z.infer<typeof updateTokenSettingsSchema>;

// Video history schema for storing generated videos
// Indexes added for 1000+ user optimization
export const videoHistory = pgTable("video_history", {
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
  metadata: text("metadata"), // JSON string for merge info: { mergedVideoIds: string[] }
  errorMessage: text("error_message"), // Store error details for failed videos
  referenceImageUrl: text("reference_image_url"), // Reference image for image-to-video generation
  retryCount: integer("retry_count").notNull().default(0), // Track auto-retry attempts
  lastRetryAt: text("last_retry_at"), // Last auto-retry timestamp
  deletedByUser: boolean("deleted_by_user").notNull().default(false), // Soft delete flag - hidden from user but visible to admin
  deletedAt: text("deleted_at"), // Timestamp when user deleted this video
  operationName: text("operation_name"), // VEO API operation name for status polling
  sceneId: text("scene_id"), // VEO API scene ID for status polling
}, (table) => [
  index("video_history_user_id_idx").on(table.userId),
  index("video_history_status_idx").on(table.status),
  index("video_history_created_at_idx").on(table.createdAt),
  index("video_history_user_status_idx").on(table.userId, table.status),
]);

export const insertVideoHistorySchema = createInsertSchema(videoHistory).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type VideoHistory = typeof videoHistory.$inferSelect;
export type InsertVideoHistory = z.infer<typeof insertVideoHistorySchema>;

// Auto-retry settings for automatic video regeneration
export const autoRetrySettings = pgTable("auto_retry_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  enableAutoRetry: boolean("enable_auto_retry").notNull().default(false),
  maxRetryAttempts: integer("max_retry_attempts").notNull().default(3),
  retryDelayMinutes: integer("retry_delay_minutes").notNull().default(5),
  updatedAt: text("updated_at").notNull().default(sql`now()::text`),
});

export const updateAutoRetrySettingsSchema = z.object({
  enableAutoRetry: z.boolean(),
  maxRetryAttempts: z.number().int().min(1).max(10),
  retryDelayMinutes: z.number().int().min(1).max(60),
});

export type AutoRetrySettings = typeof autoRetrySettings.$inferSelect;
export type UpdateAutoRetrySettings = z.infer<typeof updateAutoRetrySettingsSchema>;

// Plan availability settings
export const planAvailability = pgTable("plan_availability", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scalePlanAvailable: boolean("scale_plan_available").notNull().default(true),
  empirePlanAvailable: boolean("empire_plan_available").notNull().default(true),
  updatedAt: text("updated_at").notNull().default(sql`now()::text`),
});

export const updatePlanAvailabilitySchema = z.object({
  scalePlanAvailable: z.boolean(),
  empirePlanAvailable: z.boolean(),
});

export type PlanAvailability = typeof planAvailability.$inferSelect;
export type UpdatePlanAvailability = z.infer<typeof updatePlanAvailabilitySchema>;

// App settings
export const appSettings = pgTable("app_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  whatsappUrl: text("whatsapp_url").notNull().default("https://api.whatsapp.com/send?phone=&text=Contact Support"),
  scriptApiKey: text("script_api_key"),
  geminiApiKey: text("gemini_api_key"), // Gemini API key for script to image prompts
  cloudinaryCloudName: text("cloudinary_cloud_name").notNull().default("dfk0nvgff"),
  cloudinaryUploadPreset: text("cloudinary_upload_preset").notNull().default("demo123"),
  // Feature toggles
  enableVideoMerge: boolean("enable_video_merge").notNull().default(true), // Show/hide merge videos feature
  // Branding
  logoUrl: text("logo_url"), // Custom logo URL for the application
  // Stats tracking (never resets)
  totalVideosGenerated: integer("total_videos_generated").notNull().default(0), // Permanent counter for total videos
  // Browser Pool Settings
  browserPoolMaxContexts: integer("browser_pool_max_contexts").notNull().default(50), // Global max contexts
  browserPoolMaxPerUser: integer("browser_pool_max_per_user").notNull().default(5), // Per-user limit
  // Google Drive Settings (for video upload fallback)
  googleDriveCredentials: text("google_drive_credentials"), // Service account JSON
  googleDriveFolderId: text("google_drive_folder_id"), // Shared Drive or Folder ID for uploads
  // Storage method preference: "cloudinary", "google_drive", "cloudinary_with_fallback", or "direct_to_user"
  storageMethod: text("storage_method").notNull().default("cloudinary_with_fallback"),
  updatedAt: text("updated_at").notNull().default(sql`now()::text`),
});

export const updateAppSettingsSchema = z.object({
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
  storageMethod: z.enum(["cloudinary", "google_drive", "cloudinary_with_fallback", "direct_to_user", "local_disk"]).optional(),
});

export type AppSettings = typeof appSettings.$inferSelect;
export type UpdateAppSettings = z.infer<typeof updateAppSettingsSchema>;

// Tool maintenance status
export const toolMaintenance = pgTable("tool_maintenance", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  veoGeneratorActive: boolean("veo_generator_active").notNull().default(true),
  bulkGeneratorActive: boolean("bulk_generator_active").notNull().default(true),
  textToImageActive: boolean("text_to_image_active").notNull().default(true),
  imageToVideoActive: boolean("image_to_video_active").notNull().default(true),
  scriptCreatorActive: boolean("script_creator_active").notNull().default(true),
  characterConsistencyActive: boolean("character_consistency_active").notNull().default(true),
  updatedAt: text("updated_at").notNull().default(sql`now()::text`),
});

export const updateToolMaintenanceSchema = z.object({
  veoGeneratorActive: z.boolean(),
  bulkGeneratorActive: z.boolean(),
  textToImageActive: z.boolean(),
  imageToVideoActive: z.boolean(),
  scriptCreatorActive: z.boolean(),
  characterConsistencyActive: z.boolean(),
});

export type ToolMaintenance = typeof toolMaintenance.$inferSelect;
export type UpdateToolMaintenance = z.infer<typeof updateToolMaintenanceSchema>;

// Credits snapshots for admin monitoring
export const creditsSnapshots = pgTable("credits_snapshots", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  remainingCredits: integer("remaining_credits").notNull(),
  tokenId: varchar("token_id"), // Which API token these credits belong to
  source: text("source").notNull(), // e.g., "manual_check", "veo_generation", "image_to_video"
  recordedAt: text("recorded_at").notNull().default(sql`now()::text`),
});

export type CreditsSnapshot = typeof creditsSnapshots.$inferSelect;

// Image history for text-to-image generation
export const imageHistory = pgTable("image_history", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  prompt: text("prompt").notNull(),
  aspectRatio: text("aspect_ratio").notNull(),
  model: text("model").notNull().default("whisk"),
  imageUrl: text("image_url"),
  status: text("status").notNull().default("pending"),
  createdAt: text("created_at").notNull().default(sql`now()::text`),
  errorMessage: text("error_message"),
  tokenUsed: varchar("token_used").references(() => apiTokens.id),
});

export type ImageHistory = typeof imageHistory.$inferSelect;

// Character storage for character-consistent video generation
export const characters = pgTable("characters", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  name: text("name").notNull(),
  characterType: text("character_type").notNull().default("image"), // 'image' or 'text'
  imageUrl: text("image_url"), // URL to stored character image (nullable for text-based characters)
  mediaId: text("media_id"), // Google AI media generation ID for reference (nullable for text-based characters)
  uploadTokenId: varchar("upload_token_id").references(() => apiTokens.id), // Token used to upload this image (nullable for text-based characters)
  description: text("description"), // Text description for text-based characters (nullable for image-based characters)
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const insertCharacterSchema = createInsertSchema(characters).omit({
  id: true,
  createdAt: true,
}).extend({
  characterType: z.enum(["image", "text"]),
}).refine(
  (data) => {
    // Image-based characters must have imageUrl and mediaId
    if (data.characterType === "image") {
      return !!data.imageUrl && !!data.mediaId;
    }
    // Text-based characters must have description
    if (data.characterType === "text") {
      return !!data.description && data.description.trim().length > 0;
    }
    return false;
  },
  {
    message: "Image characters must have imageUrl and mediaId. Text characters must have description.",
  }
);

export type Character = typeof characters.$inferSelect;
export type InsertCharacter = z.infer<typeof insertCharacterSchema>;

// Admin messages for notifications
export const adminMessages = pgTable("admin_messages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  message: text("message").notNull(),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const insertAdminMessageSchema = createInsertSchema(adminMessages).omit({
  id: true,
  createdAt: true,
});

export type AdminMessage = typeof adminMessages.$inferSelect;
export type InsertAdminMessage = z.infer<typeof insertAdminMessageSchema>;

// User read messages tracking (to track which messages each user has read)
export const userReadMessages = pgTable("user_read_messages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  messageId: varchar("message_id").notNull().references(() => adminMessages.id),
  readAt: text("read_at").notNull().default(sql`now()::text`),
});

// Reseller accounts for creating user subscriptions
export const resellers = pgTable("resellers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  creditBalance: integer("credit_balance").notNull().default(0),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const insertResellerSchema = createInsertSchema(resellers).pick({
  username: true,
  password: true,
}).extend({
  creditBalance: z.number().int().min(0).optional(),
});

export const updateResellerSchema = z.object({
  creditBalance: z.number().int().min(0).optional(),
  isActive: z.boolean().optional(),
});

export type Reseller = typeof resellers.$inferSelect;
export type InsertReseller = z.infer<typeof insertResellerSchema>;
export type UpdateReseller = z.infer<typeof updateResellerSchema>;

// Reseller credit ledger for tracking all credit changes
export const resellerCreditLedger = pgTable("reseller_credit_ledger", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  resellerId: varchar("reseller_id").notNull().references(() => resellers.id),
  creditChange: integer("credit_change").notNull(), // positive for additions, negative for deductions
  balanceAfter: integer("balance_after").notNull(),
  reason: text("reason").notNull(), // e.g., "Admin added credits", "Created Scale user: john123"
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export type ResellerCreditLedger = typeof resellerCreditLedger.$inferSelect;

// Track which users were created by which reseller
export const resellerUsers = pgTable("reseller_users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  resellerId: varchar("reseller_id").notNull().references(() => resellers.id),
  userId: varchar("user_id").notNull().references(() => users.id),
  planType: text("plan_type").notNull(), // scale or empire
  creditCost: integer("credit_cost").notNull(), // 900 for scale, 1500 for empire
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export type ResellerUser = typeof resellerUsers.$inferSelect;

// Schema for reseller creating a user
export const resellerCreateUserSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  planType: z.enum(["scale", "empire"]),
});

export type ResellerCreateUser = z.infer<typeof resellerCreateUserSchema>;

// Reseller login schema
export const resellerLoginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

export type ResellerLoginInput = z.infer<typeof resellerLoginSchema>;

// Flow Cookies for Google Labs Flow automation (multiple accounts)
export const flowCookies = pgTable("flow_cookies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  label: text("label").notNull(),
  cookieData: text("cookie_data").notNull(), // JSON string or semicolon-separated cookies
  isActive: boolean("is_active").notNull().default(true),
  lastUsedAt: text("last_used_at"),
  successCount: integer("success_count").notNull().default(0),
  failCount: integer("fail_count").notNull().default(0),
  expiredCount: integer("expired_count").notNull().default(0), // Track cookie expired errors
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const insertFlowCookieSchema = createInsertSchema(flowCookies).pick({
  label: true,
  cookieData: true,
});

export const updateFlowCookieSchema = z.object({
  label: z.string().optional(),
  cookieData: z.string().optional(),
  isActive: z.boolean().optional(),
});

export const bulkAddFlowCookiesSchema = z.object({
  cookies: z.string().min(1, "Please enter at least one cookie"),
});

export type FlowCookie = typeof flowCookies.$inferSelect;
export type InsertFlowCookie = z.infer<typeof insertFlowCookieSchema>;
export type UpdateFlowCookie = z.infer<typeof updateFlowCookieSchema>;
export type BulkAddFlowCookies = z.infer<typeof bulkAddFlowCookiesSchema>;

// Zyphra API Tokens for Voice Cloning and Text-to-Speech
export const zyphraTokens = pgTable("zyphra_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  apiKey: text("api_key").notNull().unique(),
  label: text("label").notNull(),
  isActive: boolean("is_active").notNull().default(true),
  minutesUsed: integer("minutes_used").notNull().default(0),
  minutesLimit: integer("minutes_limit").notNull().default(100),
  lastUsedAt: text("last_used_at"),
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const insertZyphraTokenSchema = createInsertSchema(zyphraTokens).pick({
  apiKey: true,
  label: true,
  minutesLimit: true,
});

export const updateZyphraTokenSchema = z.object({
  label: z.string().optional(),
  isActive: z.boolean().optional(),
  minutesUsed: z.number().int().min(0).optional(),
  minutesLimit: z.number().int().min(1).optional(),
});

export const bulkAddZyphraTokensSchema = z.object({
  tokens: z.string().min(1, "Please enter at least one API key"),
});

export type ZyphraToken = typeof zyphraTokens.$inferSelect;
export type InsertZyphraToken = z.infer<typeof insertZyphraTokenSchema>;
export type UpdateZyphraToken = z.infer<typeof updateZyphraTokenSchema>;
export type BulkAddZyphraTokens = z.infer<typeof bulkAddZyphraTokensSchema>;

// Top Voices for admin-curated voice presets
export const topVoices = pgTable("top_voices", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description"),
  demoAudioUrl: text("demo_audio_url").notNull(),
  demoAudioBase64: text("demo_audio_base64"), // For caching the demo audio
  isActive: boolean("is_active").notNull().default(true),
  sortOrder: integer("sort_order").notNull().default(0),
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const insertTopVoiceSchema = createInsertSchema(topVoices).pick({
  name: true,
  description: true,
  demoAudioUrl: true,
  demoAudioBase64: true,
  sortOrder: true,
});

export const updateTopVoiceSchema = z.object({
  name: z.string().optional(),
  description: z.string().optional(),
  demoAudioUrl: z.string().optional(),
  demoAudioBase64: z.string().optional(),
  isActive: z.boolean().optional(),
  sortOrder: z.number().int().optional(),
});

export type TopVoice = typeof topVoices.$inferSelect;
export type InsertTopVoice = z.infer<typeof insertTopVoiceSchema>;
export type UpdateTopVoice = z.infer<typeof updateTopVoiceSchema>;

// Community Voices - user-created voices shared with all users
export const communityVoices = pgTable("community_voices", {
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
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const communityVoiceLikes = pgTable("community_voice_likes", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  voiceId: varchar("voice_id").notNull().references(() => communityVoices.id),
  userId: varchar("user_id").notNull().references(() => users.id),
  createdAt: text("created_at").notNull().default(sql`now()::text`),
});

export const insertCommunityVoiceSchema = createInsertSchema(communityVoices).pick({
  name: true,
  description: true,
  language: true,
  gender: true,
  demoAudioBase64: true,
  durationSeconds: true,
  fileSizeBytes: true,
}).extend({
  name: z.string().min(2, "Name must be at least 2 characters"),
  language: z.string().min(1, "Language is required"),
  gender: z.enum(["Male", "Female"]),
  demoAudioBase64: z.string().min(1, "Demo audio is required"),
  durationSeconds: z.number().min(10, "Audio must be at least 10 seconds"),
  fileSizeBytes: z.number().max(5 * 1024 * 1024, "File must be less than 5MB"),
});

export type CommunityVoice = typeof communityVoices.$inferSelect;
export type InsertCommunityVoice = z.infer<typeof insertCommunityVoiceSchema>;
export type CommunityVoiceLike = typeof communityVoiceLikes.$inferSelect;

// Pricing Plans - Admin-configurable pricing plans
export const pricingPlans = pgTable("pricing_plans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(), // e.g., "Scale", "Empire", "Enterprise"
  subtitle: text("subtitle"), // e.g., "For starters", "For professionals"
  displayPrice: text("display_price").notNull(), // e.g., "900", "1500", "Custom"
  currency: text("currency").notNull().default("PKR"), // e.g., "PKR", "USD"
  period: text("period"), // e.g., "per 10 days"
  alternatePrice: text("alternate_price"), // e.g., "$10 USD for International"
  badge: text("badge"), // e.g., "Popular", "Best Value"
  badgeColor: text("badge_color").default("default"), // e.g., "default", "orange", "purple"
  iconType: text("icon_type").notNull().default("zap"), // lucide icon name
  highlightBorder: boolean("highlight_border").notNull().default(false),
  featuresIntro: text("features_intro"), // e.g., "WHAT'S INCLUDED", "EVERYTHING IN SCALE, PLUS"
  features: text("features").notNull().default("[]"), // JSON array of feature objects
  buttonText: text("button_text").notNull().default("Get Started"),
  buttonAction: text("button_action").notNull().default("payment_dialog"), // payment_dialog, contact_sales, disabled
  position: integer("position").notNull().default(0),
  isActive: boolean("is_active").notNull().default(true),
  dailyCharactersLimit: integer("daily_characters_limit"), // Optional daily character limit for voice features
  createdAt: text("created_at").notNull().default(sql`now()::text`),
  updatedAt: text("updated_at").notNull().default(sql`now()::text`),
});

// Feature object structure for reference:
// { icon: string, text: string, included: boolean, subtext?: string }

export const insertPricingPlanSchema = createInsertSchema(pricingPlans).pick({
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
  dailyCharactersLimit: true,
}).extend({
  name: z.string().min(1, "Name is required"),
  displayPrice: z.string().min(1, "Price is required"),
  features: z.string().optional().default("[]"),
  dailyCharactersLimit: z.number().int().min(0).optional().nullable(),
});

export const updatePricingPlanSchema = z.object({
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
  dailyCharactersLimit: z.number().int().min(0).optional().nullable(),
});

export type PricingPlan = typeof pricingPlans.$inferSelect;
export type InsertPricingPlan = z.infer<typeof insertPricingPlanSchema>;
export type UpdatePricingPlan = z.infer<typeof updatePricingPlanSchema>;
