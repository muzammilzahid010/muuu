// Convert base64 data URL to Blob URL for better video playback
export function dataUrlToBlobUrl(dataUrl: string): string | null {
  try {
    if (!dataUrl.startsWith('data:')) return null;
    const [header, base64Data] = dataUrl.split(',');
    if (!header || !base64Data) return null;
    const mimeMatch = header.match(/data:([^;]+)/);
    const mimeType = mimeMatch ? mimeMatch[1] : 'video/mp4';
    const byteString = atob(base64Data);
    const ab = new ArrayBuffer(byteString.length);
    const ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
      ia[i] = byteString.charCodeAt(i);
    }
    const blob = new Blob([ab], { type: mimeType });
    return URL.createObjectURL(blob);
  } catch (e) {
    console.error('Failed to convert data URL to Blob URL:', e);
    return null;
  }
}

// Get display URL - converts data URLs to blob URLs, returns normal URLs unchanged
export function getDisplayVideoUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  if (url.startsWith('data:')) {
    return dataUrlToBlobUrl(url) || url;
  }
  return url;
}
