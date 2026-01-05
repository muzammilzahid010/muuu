// Replit Object Storage integration for video hosting
import { Storage, File } from "@google-cloud/storage";
import { Response } from "express";
import { randomUUID } from "crypto";
import { createReadStream } from "fs";

const REPLIT_SIDECAR_ENDPOINT = "http://127.0.0.1:1106";

export const objectStorageClient = new Storage({
  credentials: {
    audience: "replit",
    subject_token_type: "access_token",
    token_url: `${REPLIT_SIDECAR_ENDPOINT}/token`,
    type: "external_account",
    credential_source: {
      url: `${REPLIT_SIDECAR_ENDPOINT}/credential`,
      format: {
        type: "json",
        subject_token_field_name: "access_token",
      },
    },
    universe_domain: "googleapis.com",
  },
  projectId: "",
});

export class ObjectNotFoundError extends Error {
  constructor() {
    super("Object not found");
    this.name = "ObjectNotFoundError";
    Object.setPrototypeOf(this, ObjectNotFoundError.prototype);
  }
}

export class ObjectStorageService {
  getPrivateObjectDir(): string {
    const dir = process.env.PRIVATE_OBJECT_DIR || "";
    if (!dir) {
      throw new Error(
        "PRIVATE_OBJECT_DIR not set. Create a bucket in 'Object Storage' " +
          "pane and set PRIVATE_OBJECT_DIR env var."
      );
    }
    return dir;
  }

  async downloadObject(file: File, res: Response, cacheTtlSec: number = 3600) {
    try {
      const [metadata] = await file.getMetadata();
      res.set({
        "Content-Type": metadata.contentType || "application/octet-stream",
        "Content-Length": metadata.size,
        "Cache-Control": `public, max-age=${cacheTtlSec}`,
        "Accept-Ranges": "bytes",
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

  async getObjectEntityFile(objectPath: string): Promise<File> {
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

  async uploadMergedVideo(localFilePath: string): Promise<string> {
    const privateObjectDir = this.getPrivateObjectDir();
    const videoId = randomUUID();
    const fullPath = `${privateObjectDir}/merged/${videoId}.mp4`;

    console.log(`[Object Storage] Uploading to: ${fullPath}`);

    const { bucketName, objectName } = parseObjectPath(fullPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(objectName);

    // Use pipeline to stream file to object storage
    await new Promise<void>((resolve, reject) => {
      const readStream = createReadStream(localFilePath);
      const writeStream = file.createWriteStream({
        metadata: {
          contentType: "video/mp4",
        },
        public: true,
      });

      readStream
        .pipe(writeStream)
        .on('error', reject)
        .on('finish', resolve);
    });

    console.log(`[Object Storage] Upload complete`);
    return `/videos/merged/${videoId}.mp4`;
  }

  async uploadTemporaryVideo(localFilePath: string, expiryHours: number = 24): Promise<string> {
    const privateObjectDir = this.getPrivateObjectDir();
    const videoId = randomUUID();
    const fullPath = `${privateObjectDir}/temp/${videoId}.mp4`;

    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + expiryHours);

    console.log(`[Object Storage] Uploading temporary video to: ${fullPath}`);
    console.log(`[Object Storage] Video will expire at: ${expiryDate.toISOString()}`);

    const { bucketName, objectName } = parseObjectPath(fullPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(objectName);

    // Use pipeline to stream file to object storage
    await new Promise<void>((resolve, reject) => {
      const readStream = createReadStream(localFilePath);
      const writeStream = file.createWriteStream({
        metadata: {
          contentType: "video/mp4",
          metadata: {
            expiresAt: expiryDate.toISOString(),
            isTemporary: "true",
          },
        },
        public: true,
      });

      readStream
        .pipe(writeStream)
        .on('error', reject)
        .on('finish', resolve);
    });

    console.log(`[Object Storage] Temporary video upload complete`);
    return `/videos/temp/${videoId}.mp4`;
  }

  async cleanupExpiredVideos(): Promise<number> {
    const privateObjectDir = this.getPrivateObjectDir();
    const tempPath = `${privateObjectDir}/temp/`;
    
    console.log(`[Object Storage] Starting cleanup of expired videos in: ${tempPath}`);

    const { bucketName, objectName } = parseObjectPath(tempPath);
    const bucket = objectStorageClient.bucket(bucketName);

    try {
      const [files] = await bucket.getFiles({ prefix: objectName });
      let deletedCount = 0;
      const now = new Date();

      for (const file of files) {
        try {
          const [metadata] = await file.getMetadata();
          const expiresAt = metadata.metadata?.expiresAt;

          if (expiresAt && typeof expiresAt === 'string' && new Date(expiresAt) < now) {
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

  async getVideoExpiryInfo(videoPath: string): Promise<{ expiresAt: string | null; isExpired: boolean }> {
    try {
      const file = await this.getObjectEntityFile(videoPath);
      const [metadata] = await file.getMetadata();
      const expiresAtRaw = metadata.metadata?.expiresAt;
      const expiresAt = typeof expiresAtRaw === 'string' ? expiresAtRaw : null;
      const isExpired = expiresAt ? new Date(expiresAt) < new Date() : false;

      return { expiresAt, isExpired };
    } catch (error) {
      return { expiresAt: null, isExpired: false };
    }
  }
}

function parseObjectPath(path: string): {
  bucketName: string;
  objectName: string;
} {
  if (!path.startsWith("/")) {
    path = `/${path}`;
  }
  const pathParts = path.split("/");
  if (pathParts.length < 3) {
    throw new Error("Invalid path: must contain at least a bucket name");
  }

  const bucketName = pathParts[1];
  const objectName = pathParts.slice(2).join("/");

  return {
    bucketName,
    objectName,
  };
}
