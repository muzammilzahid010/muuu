import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "@shared/schema";

neonConfig.webSocketConstructor = ws;

// Neon connection pooler optimizations for high-concurrency VPS deployments
neonConfig.pipelineConnect = false; // Disable pipelining for better compatibility
neonConfig.useSecureWebSocket = true;
neonConfig.wsProxy = (host) => host; // Direct WebSocket connections

// Build DATABASE_URL from individual PG* env vars if they exist (for production)
// Otherwise fall back to DATABASE_URL (for development)
function getDatabaseUrl(): string {
  const { PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE, DATABASE_URL } = process.env;
  
  // If we have all the individual PG* variables, construct the URL
  // This is needed because production deployment may not resolve internal hostnames
  if (PGHOST && PGPORT && PGUSER && PGPASSWORD && PGDATABASE) {
    return `postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}?sslmode=require`;
  }
  
  // Fall back to DATABASE_URL
  if (DATABASE_URL) {
    return DATABASE_URL;
  }
  
  throw new Error(
    "Database configuration missing. Set DATABASE_URL or individual PG* variables.",
  );
}

const databaseUrl = getDatabaseUrl();

// Configure connection pool with higher limits for VPS with 100+ users
// Note: Neon free tier supports ~100 concurrent connections via pooler
export const pool = new Pool({ 
  connectionString: databaseUrl,
  max: 50,                    // Increased from 20 to 50 connections
  idleTimeoutMillis: 60000,   // Keep idle connections longer (60s)
  connectionTimeoutMillis: 30000, // Wait longer for connection (30s for Asia latency)
});

export const db = drizzle({ client: pool, schema });

// Retry wrapper for critical database operations (handles transient connection errors)
export async function withRetry<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  delayMs: number = 1000
): Promise<T> {
  let lastError: Error | null = null;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error: any) {
      lastError = error;
      const isTimeoutError = error.message?.includes('timeout') || 
                             error.message?.includes('connect');
      
      if (isTimeoutError && attempt < maxRetries) {
        console.log(`[DB Retry] Attempt ${attempt} failed, retrying in ${delayMs}ms...`);
        await new Promise(resolve => setTimeout(resolve, delayMs * attempt));
        continue;
      }
      throw error;
    }
  }
  
  throw lastError;
}
