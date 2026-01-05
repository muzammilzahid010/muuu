# Cartoon Story Video Generator

## Overview

This is a full-stack web application for generating animated videos and images using AI services. The platform allows users to create Disney Pixar-style 3D animation scenes through various tools including video generation, bulk processing, script creation, text-to-image, and image-to-video conversion. It features a tiered subscription system with plan-based access control and comprehensive admin management.

**Character Consistent Videos**: Uses text-based character descriptions (not images). Users create characters by entering a name and detailed description (minimum 10 characters). During bulk video generation, the character description is automatically appended to each prompt as "Character details: [description]". This approach uses the existing text-to-video API and doesn't consume API tokens during character creation.

## User Preferences

Preferred communication style: Simple, everyday language.

**CRITICAL - Database Rule**: NEVER make any database changes (schema updates, migrations, table modifications, data changes) without FIRST asking the user for confirmation. Always explain what changes will be made and wait for explicit approval before proceeding.

## System Architecture

### Tech Stack
- **Frontend**: React with TypeScript, Vite build tool, Wouter for routing
- **Backend**: Express.js with TypeScript (ESM modules)
- **Database**: PostgreSQL via Neon serverless with Drizzle ORM
- **Styling**: Tailwind CSS with custom design system using Radix UI components
- **State Management**: TanStack Query (React Query) for server state
- **Session Management**: Express sessions with in-memory store

### Frontend Architecture

**Component Structure**:
- Page-based routing with dedicated pages for each tool (VeoGenerator, BulkGenerator, ScriptCreator, TextToImage, ImageToVideo, CharacterConsistent, History, Admin, Pricing)
- Shared UI component library in `client/src/components/ui/` using Radix UI primitives
- Custom components: WhatsAppButton, SystemMonitor
- Path aliases: `@/` for client source, `@shared/` for shared code, `@assets/` for attached assets

**Design System**:
- Custom Tailwind configuration with HSL color variables for theming
- Light/dark mode support via CSS variables
- Custom border radius, elevate effects (hover/active states)
- Typography using Inter, Quicksand, Fira Code, and Geist Mono fonts

**State Management Pattern**:
- TanStack Query for API calls with custom query client
- Session-based authentication state
- Local storage for persisting bulk generation results
- Real-time polling for video generation status updates

### Backend Architecture

**API Structure**:
- RESTful endpoints in `server/routes.ts`
- Session-based authentication with username/password (bcrypt hashing)
- Role-based access control (admin vs regular users)
- Plan-based feature gating (free, scale, empire tiers)

**Core Services**:
- `storage.ts`: Database abstraction layer for all CRUD operations
- `veo3.ts`: Google VEO 3.1 API integration for video generation
- `openai-script.ts`: Script generation using megallm.io (OpenAI-compatible)
- `cloudinary.ts`: Video/image upload to Cloudinary CDN
- `falai.ts`: Video merging using fal.ai FFmpeg API
- `videoMergerFFmpeg.ts`: Local FFmpeg video merging
- `objectStorage.ts`: Replit Object Storage integration
- `googleDrive.ts` / `googleDriveOAuth.ts`: Google Drive upload for large files
- `bulkQueue.ts`: Queue management for bulk video generation

**Plan Enforcement System**:
- Three-tier system: Free (limited), Scale (1000 videos/day), Empire (2000 videos/day)
- Feature flags per plan (VEO only, bulk generation, all tools)
- Daily video count tracking with automatic reset
- Daily characters limit per plan (configurable in admin panel for voice features)
- Plan expiry and status management

**Video Generation Pipeline**:
1. User submits prompt with aspect ratio
2. Request sent to VEO 3.1 API with assigned token
3. Backend polls for completion status
4. Video uploaded to configured storage (Cloudinary/Google Drive)
5. Entry saved to video history with metadata
6. Frontend polls for updates until completion

**Video Storage System**:
- Configurable storage method in Admin Settings:
  - **Cloudinary Only**: Fast CDN delivery, may have rate limits
  - **Google Drive Only**: Unlimited storage with service account
  - **Cloudinary + Drive Fallback**: Uses Cloudinary first, falls back to Drive if Cloudinary fails (default)
- Google Drive requires service account JSON credentials
- Credentials can be set via Admin Dashboard or environment variable (GOOGLE_DRIVE_CREDENTIALS)
- All video uploads go through `uploadBase64VideoWithFallback()` in cloudinary.ts

**Bulk Generation Queue**:
- User-specific queues to prevent interference
- Configurable delays between requests (plan-dependent)
- Token assignment and rotation
- Retry logic with instant retries and polling retries
- Background processing with status updates
- Stop/resume functionality

### Database Schema

**Core Tables**:

`users`:
- Authentication: username, password (bcrypt)
- Authorization: isAdmin, isAccountActive
- Plan management: planType, planStatus, planStartDate, planExpiry
- Usage tracking: dailyVideoCount, dailyResetDate
- API configuration: apiToken, allowedIp1, allowedIp2

`apiTokens`:
- VEO API token management
- Label, priority, maxConcurrent
- Status tracking (enabled, hasError, inUse)
- User assignment capabilities

`videoHistory`:
- Prompt, aspectRatio, videoUrl
- Status tracking (pending, processing, completed, failed)
- Scene metadata (sceneNumber, totalScenes)
- Timestamps and user association
- Token tracking

`tokenSettings`:
- Global token usage configuration
- Concurrent request limits

`autoRetrySettings`:
- Automatic retry configuration
- Enabled/disabled state

`planAvailability`:
- Plan purchase availability flags

`appSettings`:
- Global app configuration
- Cloudinary credentials
- Script API key
- WhatsApp URL
- Feature flags (enableVideoMerge)

`toolMaintenance`:
- Per-tool maintenance mode flags
- Controls access to individual features

`creditsSnapshots`:
- Historical credit usage tracking

`characters`:
- Character consistency feature
- Image storage and metadata

### External Dependencies

**AI Services**:
- **Google VEO 3.1**: Video generation API (`aisandbox-pa.googleapis.com`)
- **megallm.io**: OpenAI-compatible script generation
- **Google Gemini**: Text-to-image generation (Whisk, nanoBana, Imagen 4 models)
- **fal.ai**: FFmpeg-based video merging

**Storage & CDN**:
- **Cloudinary**: Video and image hosting with upload API
- **Replit Object Storage**: File storage via Google Cloud Storage
- **Google Drive**: Large file uploads (service account & OAuth)

**Database**:
- **Neon PostgreSQL**: Serverless PostgreSQL with WebSocket connections
- **Drizzle ORM**: Type-safe database queries

**Infrastructure**:
- **Vite**: Frontend build and dev server
- **Express**: Backend API server
- **Node.js**: Runtime with ESM modules
- **TypeScript**: Type safety across full stack

**Development Tools**:
- Replit-specific plugins (cartographer, dev-banner, runtime-error-modal)
- System monitoring (systeminformation package)
- Archiver for ZIP downloads

**Security & Session**:
- **Helmet**: Security headers (CSP, XSS protection, clickjacking prevention)
- **Rate Limiting**: Login (5/15min), API (1000/15min), Admin (100/min), Generation (30/min)
- **Session Security**: 
  - Secure cookies (httpOnly, sameSite=strict in production)
  - Session regeneration after login (prevents session fixation)
  - 24-hour session expiry with automatic cleanup
  - PostgreSQL-backed session store
- **Authentication**:
  - bcrypt password hashing
  - Timing attack prevention (random delays)
  - Input sanitization
  - Brute force protection via rate limiting
- **Admin Protection**:
  - Server-side admin validation on EVERY request (cannot be bypassed via dev tools)
  - All admin endpoints require database-verified isAdmin flag
  - Audit logging for all admin actions
  - Security alerts for unauthorized access attempts