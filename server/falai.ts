// fal.ai FFmpeg API integration for video merging
// Uses fal-ai/ffmpeg-api/merge-videos model

interface FalMergeRequest {
  video_urls: string[];
}

interface FalMergeResponse {
  video: {
    url: string;
    content_type: string;
    file_name: string;
    file_size: number;
  };
  timings?: any;
}

export async function mergeVideosWithFalAI(videoUrls: string[]): Promise<string> {
  const apiKey = process.env.FAL_API_KEY;
  
  if (!apiKey) {
    throw new Error('FAL_API_KEY environment variable is not set');
  }

  if (videoUrls.length === 0) {
    throw new Error('No video URLs provided for merging');
  }

  console.log(`[fal.ai] Starting merge of ${videoUrls.length} videos`);
  console.log(`[fal.ai] Video URLs:`, videoUrls);

  const requestBody: FalMergeRequest = {
    video_urls: videoUrls
  };

  try {
    // Call fal.ai merge-videos API
    const response = await fetch('https://fal.run/fal-ai/ffmpeg-api/merge-videos', {
      method: 'POST',
      headers: {
        'Authorization': `Key ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[fal.ai] Error response:`, errorText);
      throw new Error(`fal.ai API error: ${response.status} - ${errorText}`);
    }

    const data: FalMergeResponse = await response.json();
    console.log(`[fal.ai] Merge response:`, JSON.stringify(data, null, 2));

    if (!data.video || !data.video.url) {
      throw new Error('No video URL in fal.ai response');
    }

    const mergedVideoUrl = data.video.url;
    console.log(`[fal.ai] Video merged successfully!`);
    console.log(`[fal.ai] Merged video URL: ${mergedVideoUrl}`);
    console.log(`[fal.ai] File size: ${data.video.file_size} bytes`);

    return mergedVideoUrl;
  } catch (error) {
    console.error(`[fal.ai] Error merging videos:`, error);
    throw new Error(`Failed to merge videos with fal.ai: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}
