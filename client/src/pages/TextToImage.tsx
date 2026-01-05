import { useState, useRef, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import AnimatedDotsBackground from "@/components/AnimatedDotsBackground";
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

import { alpha } from '@mui/material/styles';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import IconButton from '@mui/material/IconButton';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Chip from '@mui/material/Chip';
import Card from '@mui/material/Card';
import CardMedia from '@mui/material/CardMedia';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { Image as ImageIcon, Sparkles, Download, X, Upload, Monitor, Smartphone, Square, Layers, RefreshCw, AlertCircle, Loader2, Archive, Trash2, CheckCircle, ExternalLink } from "lucide-react";
import LinearProgress from '@mui/material/LinearProgress';
import CardContent from '@mui/material/CardContent';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Grid from '@mui/material/Grid';

type AspectRatio = "IMAGE_ASPECT_RATIO_LANDSCAPE" | "IMAGE_ASPECT_RATIO_PORTRAIT" | "IMAGE_ASPECT_RATIO_SQUARE";
type Model = "whisk";

interface BatchImageResult {
  prompt: string;
  status: 'pending' | 'generating' | 'success' | 'failed';
  imageUrl?: string;
  error?: string;
  retryCount: number;
}

export default function TextToImage() {
  const { toast } = useToast();
  const [mode, setMode] = useState<'single' | 'batch'>('single');
  const [prompt, setPrompt] = useState("");
  const [batchPrompts, setBatchPrompts] = useState("");
  const [aspectRatio, setAspectRatio] = useState<AspectRatio>("IMAGE_ASPECT_RATIO_LANDSCAPE");
  const [selectedModel, setSelectedModel] = useState<Model>("whisk");
  const [generatedImage, setGeneratedImage] = useState<string | null>(null);
  const [batchResults, setBatchResults] = useState<BatchImageResult[]>([]);
  const [isBatchGenerating, setIsBatchGenerating] = useState(false);
  const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0 });
  const [isDownloadingZip, setIsDownloadingZip] = useState(false);
  const [referenceImages, setReferenceImages] = useState<File[]>([]);
  const [referenceImagePreviews, setReferenceImagePreviews] = useState<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const MAX_REFERENCE_IMAGES = 5;

  // Get card height based on aspect ratio
  const getCardHeight = () => {
    switch (aspectRatio) {
      case "IMAGE_ASPECT_RATIO_PORTRAIT":
        return 280; // Taller for portrait (9:16)
      case "IMAGE_ASPECT_RATIO_SQUARE":
        return 220; // Medium for square (1:1)
      case "IMAGE_ASPECT_RATIO_LANDSCAPE":
      default:
        return 160; // Shorter for landscape (16:9)
    }
  };

  useEffect(() => {
    if (selectedModel === "whisk" && referenceImages.length > 0) {
      setReferenceImages([]);
      setReferenceImagePreviews([]);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  }, [selectedModel, referenceImages.length]);

  // Clear results when switching modes
  useEffect(() => {
    setBatchResults([]);
    setGeneratedImage(null);
  }, [mode]);

  const convertImageToBase64 = (file: File): Promise<{ base64: string; mimeType: string }> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const result = reader.result as string;
        const base64 = result.split(',')[1];
        resolve({ base64, mimeType: file.type });
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  };

  // Convert any image format to PNG
  const convertToPng = (file: File): Promise<File> => {
    return new Promise((resolve, reject) => {
      if (file.type === 'image/png') {
        resolve(file);
        return;
      }
      
      const img = new Image();
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      img.onload = () => {
        canvas.width = img.width;
        canvas.height = img.height;
        ctx?.drawImage(img, 0, 0);
        canvas.toBlob((blob) => {
          if (blob) {
            const pngFile = new File([blob], file.name.replace(/\.[^.]+$/, '.png'), { type: 'image/png' });
            resolve(pngFile);
          } else {
            reject(new Error('Failed to convert image to PNG'));
          }
        }, 'image/png', 1.0);
      };
      
      img.onerror = () => reject(new Error('Failed to load image'));
      img.src = URL.createObjectURL(file);
    });
  };

  const handleImageSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    const remainingSlots = MAX_REFERENCE_IMAGES - referenceImages.length;
    if (remainingSlots <= 0) {
      toast({
        title: "Maximum Images Reached",
        description: `You can only add up to ${MAX_REFERENCE_IMAGES} reference images.`,
        variant: "destructive",
      });
      return;
    }

    const filesToAdd = Array.from(files).slice(0, remainingSlots);
    const validFiles: File[] = [];
    const newPreviews: string[] = [];
    let convertedCount = 0;

    for (const file of filesToAdd) {
      if (!file.type.startsWith('image/')) {
        toast({
          title: "Invalid File",
          description: `${file.name} is not an image file.`,
          variant: "destructive",
        });
        continue;
      }
      
      try {
        // Convert to PNG if not already PNG
        const pngFile = await convertToPng(file);
        if (file.type !== 'image/png') {
          convertedCount++;
        }
        validFiles.push(pngFile);
      } catch (error) {
        toast({
          title: "Conversion Failed",
          description: `Failed to convert ${file.name} to PNG`,
          variant: "destructive",
        });
      }
    }

    if (convertedCount > 0) {
      toast({
        title: "Images Converted",
        description: `${convertedCount} image(s) converted to PNG format`,
        variant: "default",
      });
    }

    if (validFiles.length === 0) return;

    validFiles.forEach(file => {
      const reader = new FileReader();
      reader.onloadend = () => {
        newPreviews.push(reader.result as string);
        if (newPreviews.length === validFiles.length) {
          setReferenceImages(prev => [...prev, ...validFiles]);
          setReferenceImagePreviews(prev => [...prev, ...newPreviews]);
        }
      };
      reader.readAsDataURL(file);
    });

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleRemoveImage = (indexToRemove: number) => {
    setReferenceImages(prev => prev.filter((_, index) => index !== indexToRemove));
    setReferenceImagePreviews(prev => prev.filter((_, index) => index !== indexToRemove));
  };

  const handleClearAllImages = () => {
    setReferenceImages([]);
    setReferenceImagePreviews([]);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const generateMutation = useMutation({
    mutationFn: async ({ imagePrompt, ratio, model, refImages }: { imagePrompt: string; ratio: string; model: string; refImages: File[] }) => {
      let referenceMediaIds: string[] = [];
      let tokenId: string | undefined;

      if (refImages.length > 0 && model !== 'whisk') {
        for (const refImage of refImages) {
          const { base64, mimeType } = await convertImageToBase64(refImage);
          const conversionResponse = await fetch('/api/convert-image-to-media-id', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ 
              imageBase64: base64, 
              imageMimeType: mimeType,
              tokenId: tokenId
            }),
          });

          if (!conversionResponse.ok) {
            const error = await conversionResponse.json();
            throw new Error(error.error || 'Failed to convert reference image');
          }

          const conversionData = await conversionResponse.json();
          referenceMediaIds.push(conversionData.mediaId);
          if (!tokenId) {
            tokenId = conversionData.tokenId;
          }
          console.log(`[Token Consistency] Media ID: ${conversionData.mediaId}, Token ID: ${tokenId}`);
        }
      }

      const requestBody: any = {
        prompt: imagePrompt,
        aspectRatio: ratio,
        model: model
      };
      
      if (referenceMediaIds.length > 0 && model !== 'whisk') {
        requestBody.referenceMediaIds = referenceMediaIds;
        if (tokenId) {
          requestBody.tokenId = tokenId;
        }
      }

      const response = await fetch('/api/text-to-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to generate image');
      }

      return response.json();
    },
    onSuccess: (data) => {
      setGeneratedImage(data.imageUrl);
      toast({ title: "Image Generated!", description: "Your image has been created successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Generation Failed", description: error.message, variant: "destructive" });
    },
  });

  const handleGenerate = () => {
    if (!prompt.trim()) {
      toast({ title: "Prompt Required", description: "Please enter a prompt for the image.", variant: "destructive" });
      return;
    }
    generateMutation.mutate({ imagePrompt: prompt, ratio: aspectRatio, model: selectedModel, refImages: referenceImages });
  };

  const handleDownload = async () => {
    if (!generatedImage) return;
    
    try {
      const filename = `generated-image-${Date.now()}.png`;
      
      // Handle base64 data URLs directly
      if (generatedImage.startsWith('data:')) {
        const link = document.createElement('a');
        link.href = generatedImage;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        toast({ title: "Downloaded!", description: "Image saved to your device." });
      } else {
        // For external URLs, use backend proxy and fetch as blob
        toast({ title: "Downloading...", description: "Please wait..." });
        const proxyUrl = `/api/images/download-proxy?imageUrl=${encodeURIComponent(generatedImage)}&filename=${encodeURIComponent(filename)}`;
        
        const response = await fetch(proxyUrl, { credentials: 'include' });
        if (!response.ok) {
          throw new Error('Download failed');
        }
        
        const blob = await response.blob();
        const blobUrl = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = blobUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Clean up blob URL
        URL.revokeObjectURL(blobUrl);
        toast({ title: "Downloaded!", description: "Image saved to your device." });
      }
    } catch (error) {
      console.error('Download failed:', error);
      // Fallback: open in new tab if download fails
      window.open(generatedImage, '_blank');
      toast({ title: "Download Issue", description: "Opening image in new tab instead.", variant: "default" });
    }
  };

  const handleDownloadAllAsZip = async () => {
    const successfulImages = batchResults.filter(r => r.status === 'success' && r.imageUrl);
    if (successfulImages.length === 0) {
      toast({ title: "No Images", description: "No images available to download.", variant: "destructive" });
      return;
    }

    setIsDownloadingZip(true);
    
    try {
      const zip = new JSZip();
      
      // Process all images in parallel for maximum speed
      await Promise.all(
        successfulImages.map(async (result, index) => {
          if (result.imageUrl) {
            try {
              // Handle base64 data URLs
              if (result.imageUrl.startsWith('data:')) {
                const base64Data = result.imageUrl.split(',')[1];
                const binaryData = atob(base64Data);
                const bytes = new Uint8Array(binaryData.length);
                for (let i = 0; i < binaryData.length; i++) {
                  bytes[i] = binaryData.charCodeAt(i);
                }
                zip.file(`image_${index + 1}.png`, bytes);
              } else {
                // Handle regular URLs
                const response = await fetch(result.imageUrl);
                const blob = await response.blob();
                zip.file(`image_${index + 1}.png`, blob);
              }
            } catch (error) {
              console.error(`Failed to add image ${index + 1} to zip:`, error);
            }
          }
        })
      );

      // Generate zip with maximum compression speed
      const zipBlob = await zip.generateAsync({ 
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 1 } // Level 1 for fastest compression
      });

      // Download the zip file
      saveAs(zipBlob, `batch_images_${Date.now()}.zip`);
      toast({ title: "Download Complete!", description: `${successfulImages.length} images downloaded as ZIP.` });
    } catch (error) {
      console.error('Failed to create zip:', error);
      toast({ title: "Download Failed", description: "Failed to create ZIP file.", variant: "destructive" });
    } finally {
      setIsDownloadingZip(false);
    }
  };

  const handleBatchGenerate = async () => {
    const prompts = batchPrompts.split('\n').filter(p => p.trim());
    if (prompts.length === 0) {
      toast({ title: "Prompts Required", description: "Please enter at least one prompt.", variant: "destructive" });
      return;
    }

    if (prompts.length > 50) {
      toast({ title: "Limit Exceeded", description: "Maximum 50 images can be generated at once. Please reduce the number of prompts.", variant: "destructive" });
      return;
    }

    setIsBatchGenerating(true);
    setBatchProgress({ current: 0, total: prompts.length });

    // Initialize batch results with generating status (all start together)
    const initialResults: BatchImageResult[] = prompts.map(p => ({
      prompt: p.trim(),
      status: 'generating',
      retryCount: 0
    }));
    setBatchResults(initialResults);

    console.log(`[Batch Stream] Starting streaming batch for ${prompts.length} images...`);
    const startTime = Date.now();

    try {
      // Prepare request body
      const requestBody: any = {
        prompts: prompts.map(p => p.trim()),
        aspectRatio: aspectRatio,
        model: selectedModel
      };

      // Add reference images data if available (except for whisk model)
      if (referenceImages.length > 0 && selectedModel !== 'whisk') {
        const referenceImagesData = await Promise.all(
          referenceImages.map(async (img) => {
            const { base64, mimeType } = await convertImageToBase64(img);
            return { base64, mimeType };
          })
        );
        requestBody.referenceImagesData = referenceImagesData;
        console.log(`[Batch Stream] Including ${referenceImages.length} reference images for all ${prompts.length} prompts`);
      }

      // Use streaming endpoint with fetch for SSE
      const response = await fetch('/api/text-to-image/batch-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (!reader) throw new Error('No response body');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.startsWith('event: ')) {
            const eventType = line.slice(7);
            // Next line should be data
            if (i + 1 < lines.length && lines[i + 1].startsWith('data: ')) {
              const dataStr = lines[i + 1].slice(6);
              i++; // Skip the data line in next iteration
              try {
                const data = JSON.parse(dataStr);
                
                if (eventType === 'image') {
                  // Update specific image result as it arrives
                  setBatchResults(prev => {
                    const newResults = [...prev];
                    newResults[data.index] = {
                      prompt: data.prompt,
                      status: data.status,
                      imageUrl: data.imageUrl,
                      error: data.error,
                      retryCount: 0
                    };
                    return newResults;
                  });
                  setBatchProgress({ current: data.progress.current, total: data.progress.total });
                  console.log(`[Batch Stream] Image ${data.index + 1} received: ${data.status}`);
                } else if (eventType === 'complete') {
                  const duration = ((Date.now() - startTime) / 1000).toFixed(1);
                  console.log(`[Batch Stream Complete] ${data.summary.success}/${data.summary.total} in ${duration}s`);
                  toast({ 
                    title: "Batch Complete!", 
                    description: `${data.summary.success}/${data.summary.total} images generated` 
                  });
                } else if (eventType === 'error') {
                  throw new Error(data.error);
                }
              } catch (e) {
                // Ignore parse errors for incomplete data
              }
            }
          } else if (line.startsWith('data: ')) {
            // Handle data without event prefix
            try {
              const data = JSON.parse(line.slice(6));
              if (data.index !== undefined) {
                setBatchResults(prev => {
                  const newResults = [...prev];
                  newResults[data.index] = {
                    prompt: data.prompt,
                    status: data.status,
                    imageUrl: data.imageUrl,
                    error: data.error,
                    retryCount: 0
                  };
                  return newResults;
                });
                if (data.progress) {
                  setBatchProgress({ current: data.progress.current, total: data.progress.total });
                }
              }
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }
    } catch (error: any) {
      console.error('[Batch Stream] Error:', error);
      
      // Mark remaining generating items as failed
      setBatchResults(prev => prev.map(r => 
        r.status === 'generating' ? { ...r, status: 'failed' as const, error: error.message || 'Batch processing failed' } : r
      ));
      
      toast({ 
        title: "Batch Failed", 
        description: error.message || "Failed to process batch", 
        variant: "destructive" 
      });
    } finally {
      setIsBatchGenerating(false);
    }
  };

  // Retry only failed images with streaming
  const handleRetryFailed = async () => {
    const failedResults = batchResults.filter(r => r.status === 'failed');
    if (failedResults.length === 0) return;

    // Build mapping of failed prompt to original index
    const failedIndexMap: Map<string, number> = new Map();
    batchResults.forEach((r, idx) => {
      if (r.status === 'failed') {
        failedIndexMap.set(r.prompt, idx);
      }
    });

    const failedPrompts = failedResults.map(r => r.prompt);
    console.log(`[Retry Stream] Retrying ${failedPrompts.length} failed images with streaming...`);

    setIsBatchGenerating(true);

    // Mark failed ones as generating
    setBatchResults(prev => prev.map(r => 
      r.status === 'failed' ? { ...r, status: 'generating' as const, error: undefined } : r
    ));

    try {
      const requestBody: any = {
        prompts: failedPrompts,
        aspectRatio,
        model: selectedModel,
        isRetry: true
      };

      if (referenceImages.length > 0) {
        const referenceImagesData = await Promise.all(
          referenceImages.map(async (img) => {
            const { base64, mimeType } = await convertImageToBase64(img);
            return { base64, mimeType };
          })
        );
        requestBody.referenceImagesData = referenceImagesData;
      }

      const response = await fetch('/api/text-to-image/batch-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (!reader) throw new Error('No response body');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            const eventType = line.slice(7);
            const dataLineIndex = lines.indexOf(line) + 1;
            if (dataLineIndex < lines.length && lines[dataLineIndex].startsWith('data: ')) {
              try {
                const data = JSON.parse(lines[dataLineIndex].slice(6));
                
                if (eventType === 'image') {
                  // Map back to original index
                  const originalIndex = failedIndexMap.get(data.prompt);
                  if (originalIndex !== undefined) {
                    setBatchResults(prev => {
                      const newResults = [...prev];
                      newResults[originalIndex] = {
                        prompt: data.prompt,
                        status: data.status,
                        imageUrl: data.imageUrl,
                        error: data.error,
                        retryCount: (newResults[originalIndex].retryCount || 0) + 1
                      };
                      return newResults;
                    });
                  }
                  console.log(`[Retry Stream] Image received: ${data.status}`);
                } else if (eventType === 'complete') {
                  toast({ 
                    title: "Retry Complete!", 
                    description: `${data.summary.success}/${data.summary.total} images generated` 
                  });
                } else if (eventType === 'error') {
                  throw new Error(data.error);
                }
              } catch (e) {}
            }
          }
        }
      }
    } catch (error: any) {
      console.error('[Retry Stream] Error:', error);
      setBatchResults(prev => prev.map(r => 
        r.status === 'generating' ? { ...r, status: 'failed' as const, error: error.message } : r
      ));
      toast({ 
        title: "Retry Failed", 
        description: error.message || "Failed to retry images", 
        variant: "destructive" 
      });
    } finally {
      setIsBatchGenerating(false);
    }
  };

  // Regenerate a single image
  const handleRegenerateImage = async (index: number) => {
    const targetResult = batchResults[index];
    if (!targetResult) return;

    console.log(`[Regenerate] Regenerating image at index ${index}: "${targetResult.prompt.substring(0, 50)}..."`);

    // Mark as generating
    setBatchResults(prev => prev.map((r, i) => 
      i === index ? { ...r, status: 'generating' as const, error: undefined } : r
    ));

    try {
      const requestBody: any = {
        prompts: [targetResult.prompt],
        aspectRatio,
        model: selectedModel,
        isRetry: true  // Use different token
      };

      if (referenceImages.length > 0) {
        const referenceImagesData = await Promise.all(
          referenceImages.map(async (img) => {
            const { base64, mimeType } = await convertImageToBase64(img);
            return { base64, mimeType };
          })
        );
        requestBody.referenceImagesData = referenceImagesData;
      }

      const response = await fetch('/api/text-to-image/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      const result = data.results[0];

      // Update the specific item
      setBatchResults(prev => prev.map((r, i) => 
        i === index ? {
          prompt: result.prompt,
          status: result.status,
          imageUrl: result.imageUrl,
          error: result.error,
          retryCount: r.retryCount + 1
        } : r
      ));

      if (result.status === 'success') {
        toast({ title: "Image Regenerated!", description: "New image generated successfully" });
      } else {
        toast({ title: "Regeneration Failed", description: result.error || "Failed to regenerate", variant: "destructive" });
      }
    } catch (error: any) {
      console.error('[Regenerate] Error:', error);
      setBatchResults(prev => prev.map((r, i) => 
        i === index ? { ...r, status: 'failed' as const, error: error.message } : r
      ));
      toast({ title: "Regeneration Failed", description: error.message, variant: "destructive" });
    }
  };

  // Delete a single image from results
  const handleDeleteImage = (index: number) => {
    setBatchResults(prev => prev.filter((_, i) => i !== index));
    toast({ title: "Image Removed", description: "Image removed from results" });
  };

  return (
    <UserPanelLayout>
      <Box sx={{ position: 'relative', minHeight: '100vh' }}>
        <AnimatedDotsBackground />
        <Box sx={{ position: 'relative', zIndex: 1, maxWidth: mode === 'single' ? 1400 : 900, mx: 'auto' }}>
          <Stack spacing={3}>
            <Box>
            <Typography variant="h5" sx={{ fontWeight: 700, color: '#1a1a2e', mb: 0.5 }}>
              Create AI Images
            </Typography>
            <Typography variant="body2" sx={{ color: '#64748b', mb: 2 }}>
              Describe your image and let AI bring it to life
            </Typography>
            
            {/* Mode Tabs */}
            <Box sx={{ 
              bgcolor: '#1f2937', 
              borderRadius: 2, 
              p: 0.5, 
              display: 'inline-flex',
              gap: 0.5
            }}>
              <Button
                onClick={() => setMode('single')}
                startIcon={<ImageIcon size={16} />}
                sx={{
                  px: 3,
                  py: 1,
                  borderRadius: 1.5,
                  textTransform: 'none',
                  fontWeight: 500,
                  fontSize: '0.875rem',
                  color: mode === 'single' ? '#1f2937' : '#9ca3af',
                  bgcolor: mode === 'single' ? 'white' : 'transparent',
                  '&:hover': {
                    bgcolor: mode === 'single' ? 'white' : 'rgba(255,255,255,0.1)',
                  }
                }}
              >
                Single Image
              </Button>
              <Button
                onClick={() => setMode('batch')}
                startIcon={<Layers size={16} />}
                sx={{
                  px: 3,
                  py: 1,
                  borderRadius: 1.5,
                  textTransform: 'none',
                  fontWeight: 500,
                  fontSize: '0.875rem',
                  color: mode === 'batch' ? '#1f2937' : '#9ca3af',
                  bgcolor: mode === 'batch' ? 'white' : 'transparent',
                  '&:hover': {
                    bgcolor: mode === 'batch' ? 'white' : 'rgba(255,255,255,0.1)',
                  }
                }}
              >
                Batch Mode
              </Button>
            </Box>
          </Box>

          {/* Two-Column Layout for Single Mode */}
          {mode === 'single' ? (
            <Grid container spacing={3}>
              {/* Left Column - Form */}
              <Grid size={{ xs: 12, lg: 6 }}>
                <Paper
                  elevation={0}
                  sx={{
                    p: { xs: 3, md: 4 },
                    borderRadius: 3,
                    border: '1px solid rgba(0,0,0,0.08)',
                    backgroundColor: '#ffffff'
                  }}
                >
                  <Stack spacing={3}>
                    {/* Single image form fields - remove extra conditional since we're already in single mode */}
                    <Box>
                      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: '#374151' }}>
                        Image Prompt
                        <Chip label="Required" size="small" sx={{ ml: 1, height: 20, fontSize: '0.7rem', bgcolor: alpha('#374151', 0.1), color: '#374151' }} />
                      </Typography>
                      <TextField
                        fullWidth
                        multiline
                        rows={4}
                        placeholder="Describe your image... e.g., 'A futuristic city at sunset with flying cars and neon lights'"
                        value={prompt}
                        onChange={(e) => setPrompt(e.target.value)}
                        disabled={generateMutation.isPending}
                        data-testid="input-prompt"
                        sx={{
                          '& .MuiOutlinedInput-root': {
                            borderRadius: 2,
                            '& fieldset': { borderColor: '#e5e7eb' },
                            '&:hover fieldset': { borderColor: '#374151' },
                            '&.Mui-focused fieldset': { borderColor: '#374151' }
                          }
                        }}
                      />
                    </Box>

                    <Box>
                      <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, color: '#374151' }}>
                        Aspect Ratio
                      </Typography>
                      <ToggleButtonGroup
                        value={aspectRatio}
                        exclusive
                        onChange={(_, value) => value && setAspectRatio(value)}
                        disabled={generateMutation.isPending}
                        sx={{ gap: 1, flexWrap: 'wrap' }}
                      >
                        <ToggleButton
                          value="IMAGE_ASPECT_RATIO_LANDSCAPE"
                          data-testid="button-landscape"
                          sx={{
                            px: 3, py: 1.5, borderRadius: '12px !important',
                            border: '1px solid #e5e7eb !important', textTransform: 'none',
                            '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                          }}
                        >
                          <Monitor size={18} style={{ marginRight: 8 }} />
                          Landscape
                        </ToggleButton>
                        <ToggleButton
                          value="IMAGE_ASPECT_RATIO_PORTRAIT"
                          data-testid="button-portrait"
                          sx={{
                            px: 3, py: 1.5, borderRadius: '12px !important',
                            border: '1px solid #e5e7eb !important', textTransform: 'none',
                            '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                          }}
                        >
                          <Smartphone size={18} style={{ marginRight: 8 }} />
                          Portrait
                        </ToggleButton>
                        <ToggleButton
                          value="IMAGE_ASPECT_RATIO_SQUARE"
                          data-testid="button-square"
                          sx={{
                            px: 3, py: 1.5, borderRadius: '12px !important',
                            border: '1px solid #e5e7eb !important', textTransform: 'none',
                            '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                          }}
                        >
                          <Square size={18} style={{ marginRight: 8 }} />
                          Square
                        </ToggleButton>
                      </ToggleButtonGroup>
                    </Box>

                    {selectedModel !== 'whisk' && (
                      <Box>
                        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151' }}>
                            Reference Images (PNG only, up to {MAX_REFERENCE_IMAGES})
                          </Typography>
                          {referenceImages.length > 0 && (
                            <Button
                              size="small"
                              onClick={handleClearAllImages}
                              startIcon={<Trash2 size={14} />}
                              sx={{ color: '#ef4444', textTransform: 'none', fontSize: '0.75rem' }}
                            >
                              Clear All
                            </Button>
                          )}
                        </Stack>
                        <input
                          type="file"
                          accept="image/png,.png"
                          multiple
                          onChange={handleImageSelect}
                          ref={fileInputRef}
                          style={{ display: 'none' }}
                          id="reference-image-input"
                        />
                        <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ gap: 1 }}>
                          {referenceImagePreviews.map((preview, index) => (
                            <Box key={index} sx={{ position: 'relative', display: 'inline-block' }}>
                              <img
                                src={preview}
                                alt={`Reference ${index + 1}`}
                                style={{ width: 80, height: 80, objectFit: 'cover', borderRadius: 8, border: '1px solid #e5e7eb' }}
                              />
                              <IconButton
                                onClick={() => handleRemoveImage(index)}
                                sx={{ position: 'absolute', top: -6, right: -6, bgcolor: '#ef4444', color: 'white', '&:hover': { bgcolor: '#dc2626' }, width: 20, height: 20 }}
                                size="small"
                              >
                                <X size={12} />
                              </IconButton>
                            </Box>
                          ))}
                          {referenceImages.length < MAX_REFERENCE_IMAGES && (
                            <label htmlFor="reference-image-input">
                              <Box
                                component="span"
                                sx={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'center',
                                  width: 80,
                                  height: 80,
                                  border: '2px dashed #e5e7eb',
                                  borderRadius: 2,
                                  cursor: 'pointer',
                                  '&:hover': { borderColor: '#374151', bgcolor: alpha('#374151', 0.05) }
                                }}
                              >
                                <Upload size={24} color="#9ca3af" />
                              </Box>
                            </label>
                          )}
                        </Stack>
                        <Typography variant="caption" sx={{ color: '#9ca3af', mt: 1, display: 'block' }}>
                          {referenceImages.length}/{MAX_REFERENCE_IMAGES} images added
                        </Typography>
                      </Box>
                    )}

                    <Button
                      variant="contained"
                      size="large"
                      onClick={handleGenerate}
                      disabled={generateMutation.isPending || !prompt.trim()}
                      startIcon={generateMutation.isPending ? <CircularProgress size={20} sx={{ color: 'white' }} /> : <Sparkles size={20} />}
                      data-testid="button-generate"
                      sx={{
                        py: 1.5, borderRadius: 2, textTransform: 'none', fontWeight: 600, fontSize: '1rem',
                        color: 'white',
                        bgcolor: '#374151',
                        '&:hover': { bgcolor: '#1f2937' },
                        '&:disabled': { 
                          bgcolor: '#6b7280',
                          color: 'white',
                        }
                      }}
                    >
                      {generateMutation.isPending ? 'Generating...' : 'Generate Image'}
                    </Button>
                  </Stack>
                </Paper>
              </Grid>

              {/* Right Column - Image Preview */}
              <Grid size={{ xs: 12, lg: 6 }}>
                <Paper
                  elevation={0}
                  sx={{
                    p: { xs: 3, md: 4 },
                    borderRadius: 3,
                    border: '1px solid rgba(0,0,0,0.08)',
                    backgroundColor: '#ffffff',
                    minHeight: 400,
                    display: 'flex',
                    flexDirection: 'column'
                  }}
                >
                  {generatedImage ? (
                    <Stack spacing={3} sx={{ flex: 1 }}>
                      <Stack direction="row" alignItems="center" justifyContent="space-between">
                        <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>Generated Image</Typography>
                        <Chip label="Ready" color="success" size="small" />
                      </Stack>

                      <Box sx={{ borderRadius: 2, overflow: 'hidden', bgcolor: '#f8fafc', flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <img src={generatedImage} alt="Generated" style={{ maxWidth: '100%', maxHeight: 350, objectFit: 'contain', display: 'block' }} />
                      </Box>

                      <Stack direction="row" spacing={2}>
                        <Button
                          variant="contained"
                          onClick={handleDownload}
                          startIcon={<Download size={18} />}
                          data-testid="button-download"
                          sx={{ flex: 1, py: 1.5, borderRadius: 2, textTransform: 'none', fontWeight: 600, bgcolor: '#374151', '&:hover': { bgcolor: '#1f2937' } }}
                        >
                          Download Image
                        </Button>
                        <Button
                          variant="outlined"
                          onClick={() => { setGeneratedImage(null); setPrompt(''); }}
                          startIcon={<RefreshCw size={18} />}
                          data-testid="button-new"
                          sx={{ flex: 1, py: 1.5, borderRadius: 2, textTransform: 'none', fontWeight: 600, borderColor: '#e5e7eb', color: '#374151', '&:hover': { borderColor: '#374151', color: '#1f2937' } }}
                        >
                          Generate New
                        </Button>
                      </Stack>
                    </Stack>
                  ) : generateMutation.isPending ? (
                    <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
                      <Box
                        sx={{
                          width: 120,
                          height: 120,
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          background: 'linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%)',
                          mb: 3
                        }}
                      >
                        <CircularProgress size={60} thickness={3} sx={{ color: '#374151' }} />
                      </Box>
                      <Typography variant="h6" sx={{ fontWeight: 600, color: '#1e293b', mb: 1 }}>
                        Generating Image...
                      </Typography>
                      <Typography variant="body2" sx={{ color: '#64748b' }}>
                        This may take a few seconds
                      </Typography>
                    </Box>
                  ) : (
                    <Box 
                      sx={{ 
                        flex: 1, 
                        display: 'flex', 
                        flexDirection: 'column', 
                        justifyContent: 'center', 
                        alignItems: 'center',
                        bgcolor: '#f8fafc',
                        borderRadius: 2,
                        p: 4
                      }}
                    >
                      <Box
                        sx={{
                          width: 80,
                          height: 80,
                          borderRadius: 2,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          bgcolor: '#e2e8f0',
                          mb: 2
                        }}
                      >
                        <ImageIcon size={40} color="#94a3b8" />
                      </Box>
                      <Typography variant="h6" sx={{ fontWeight: 600, color: '#64748b', mb: 0.5 }}>
                        Image Preview
                      </Typography>
                      <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                        Your generated image will appear here
                      </Typography>
                    </Box>
                  )}
                </Paper>
              </Grid>
            </Grid>
          ) : (
            /* Batch Mode - Single Column Layout */
            <Paper
              elevation={0}
              sx={{
                p: { xs: 3, md: 4 },
                borderRadius: 3,
                border: '1px solid rgba(0,0,0,0.08)',
                backgroundColor: '#ffffff'
              }}
            >
              <Stack spacing={3}>
                {/* Batch mode content - extracted from original */}
                <Box>
                  <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: '#374151' }}>
                    Image Prompts (One per line)
                    <Chip label="Required" size="small" sx={{ ml: 1, height: 20, fontSize: '0.7rem', bgcolor: alpha('#374151', 0.1), color: '#374151' }} />
                  </Typography>
                  <TextField
                    fullWidth
                    multiline
                    rows={8}
                    placeholder={`Enter one prompt per line:\nA sunset over the ocean\nA mountain landscape with snow\nA modern city at night`}
                    value={batchPrompts}
                    onChange={(e) => setBatchPrompts(e.target.value)}
                    disabled={isBatchGenerating}
                    data-testid="input-batch-prompts"
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        borderRadius: 2,
                        '& fieldset': { borderColor: '#e5e7eb' },
                        '&:hover fieldset': { borderColor: '#374151' },
                        '&.Mui-focused fieldset': { borderColor: '#374151' }
                      }
                    }}
                  />
                  <Typography variant="caption" sx={{ color: '#9ca3af', mt: 0.5, display: 'block' }}>
                    {batchPrompts.split('\n').filter(p => p.trim()).length} prompts entered
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, color: '#374151' }}>
                    Aspect Ratio
                  </Typography>
                  <ToggleButtonGroup
                    value={aspectRatio}
                    exclusive
                    onChange={(_, value) => value && setAspectRatio(value)}
                    disabled={isBatchGenerating}
                    sx={{ gap: 1, flexWrap: 'wrap' }}
                  >
                    <ToggleButton
                      value="IMAGE_ASPECT_RATIO_LANDSCAPE"
                      sx={{
                        px: 3, py: 1.5, borderRadius: '12px !important',
                        border: '1px solid #e5e7eb !important', textTransform: 'none',
                        '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                      }}
                    >
                      <Monitor size={18} style={{ marginRight: 8 }} />
                      Landscape
                    </ToggleButton>
                    <ToggleButton
                      value="IMAGE_ASPECT_RATIO_PORTRAIT"
                      sx={{
                        px: 3, py: 1.5, borderRadius: '12px !important',
                        border: '1px solid #e5e7eb !important', textTransform: 'none',
                        '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                      }}
                    >
                      <Smartphone size={18} style={{ marginRight: 8 }} />
                      Portrait
                    </ToggleButton>
                    <ToggleButton
                      value="IMAGE_ASPECT_RATIO_SQUARE"
                      sx={{
                        px: 3, py: 1.5, borderRadius: '12px !important',
                        border: '1px solid #e5e7eb !important', textTransform: 'none',
                        '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                      }}
                    >
                      <Square size={18} style={{ marginRight: 8 }} />
                      Square
                    </ToggleButton>
                  </ToggleButtonGroup>
                </Box>

                {selectedModel !== 'whisk' && (
                  <Box>
                    <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151' }}>
                        Reference Images (PNG only, up to {MAX_REFERENCE_IMAGES})
                        <Chip label="Same for all" size="small" sx={{ ml: 1, height: 20, fontSize: '0.7rem', bgcolor: alpha('#374151', 0.1), color: '#374151' }} />
                      </Typography>
                      {referenceImages.length > 0 && !isBatchGenerating && (
                        <Button
                          size="small"
                          onClick={handleClearAllImages}
                          startIcon={<Trash2 size={14} />}
                          sx={{ color: '#ef4444', textTransform: 'none', fontSize: '0.75rem' }}
                        >
                          Clear All
                        </Button>
                      )}
                    </Stack>
                    <input
                      type="file"
                      accept="image/png,.png"
                      multiple
                      onChange={handleImageSelect}
                      ref={fileInputRef}
                      style={{ display: 'none' }}
                      id="batch-reference-image-input"
                      disabled={isBatchGenerating}
                    />
                    <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ gap: 1 }}>
                      {referenceImagePreviews.map((preview, index) => (
                        <Box key={index} sx={{ position: 'relative', display: 'inline-block' }}>
                          <img
                            src={preview}
                            alt={`Reference ${index + 1}`}
                            style={{ width: 80, height: 80, objectFit: 'cover', borderRadius: 8, border: '1px solid #e5e7eb' }}
                          />
                          {!isBatchGenerating && (
                            <IconButton
                              onClick={() => handleRemoveImage(index)}
                              sx={{ position: 'absolute', top: -6, right: -6, bgcolor: '#ef4444', color: 'white', '&:hover': { bgcolor: '#dc2626' }, width: 20, height: 20 }}
                              size="small"
                            >
                              <X size={12} />
                            </IconButton>
                          )}
                        </Box>
                      ))}
                      {referenceImages.length < MAX_REFERENCE_IMAGES && !isBatchGenerating && (
                        <label htmlFor="batch-reference-image-input">
                          <Box
                            component="span"
                            sx={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              width: 80,
                              height: 80,
                              border: '2px dashed #e5e7eb',
                              borderRadius: 2,
                              cursor: 'pointer',
                              '&:hover': { borderColor: '#374151', bgcolor: alpha('#374151', 0.05) }
                            }}
                          >
                            <Upload size={24} color="#9ca3af" />
                          </Box>
                        </label>
                      )}
                    </Stack>
                    <Typography variant="caption" sx={{ color: '#9ca3af', mt: 1, display: 'block' }}>
                      {referenceImages.length}/{MAX_REFERENCE_IMAGES} images added - These will be used for all batch images
                    </Typography>
                  </Box>
                )}

                {isBatchGenerating && (
                  <Box sx={{ p: 2, bgcolor: alpha('#374151', 0.05), borderRadius: 2 }}>
                    <Stack direction="row" alignItems="center" spacing={2}>
                      <CircularProgress size={24} sx={{ color: '#374151' }} />
                      <Typography variant="body2" sx={{ color: '#374151', fontWeight: 500 }}>
                        Generating image {batchProgress.current} of {batchProgress.total}...
                      </Typography>
                    </Stack>
                  </Box>
                )}

                <Button
                  variant="contained"
                  size="large"
                  onClick={handleBatchGenerate}
                  disabled={isBatchGenerating || !batchPrompts.trim()}
                  startIcon={isBatchGenerating ? <CircularProgress size={20} sx={{ color: 'white' }} /> : <Sparkles size={20} />}
                  data-testid="button-batch-generate"
                  sx={{
                    py: 1.5, borderRadius: 2, textTransform: 'none', fontWeight: 600, fontSize: '1rem',
                    color: 'white',
                    bgcolor: '#374151',
                    '&:hover': { bgcolor: '#1f2937' },
                    '&:disabled': { 
                      bgcolor: '#6b7280',
                      color: 'white',
                    }
                  }}
                >
                  {isBatchGenerating ? `Generating ${batchProgress.current}/${batchProgress.total}...` : 'Generate All Images'}
                </Button>
              </Stack>
            </Paper>
          )}

          {/* Batch Results - Only shown for batch mode */}
          {mode === 'batch' && batchResults.length > 0 && (
            <Paper
              elevation={0}
              sx={{ p: { xs: 3, md: 4 }, borderRadius: 3, border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff' }}
            >
              <Stack spacing={3}>
                {/* Header with badges and action buttons */}
                <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={2}>
                  <Stack direction="row" alignItems="center" spacing={2} flexWrap="wrap">
                    <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
                      Generated Images
                    </Typography>
                    <Chip 
                      label={`${batchResults.filter(r => r.status === 'success').length} completed`} 
                      size="small" 
                      sx={{ bgcolor: alpha('#22c55e', 0.1), color: '#22c55e', fontWeight: 600 }} 
                    />
                    {batchResults.filter(r => r.status === 'generating' || r.status === 'pending').length > 0 && (
                      <Chip 
                        label={`${batchResults.filter(r => r.status === 'generating' || r.status === 'pending').length} processing`} 
                        size="small" 
                        sx={{ bgcolor: alpha('#f59e0b', 0.1), color: '#f59e0b', fontWeight: 600 }} 
                      />
                    )}
                    {batchResults.filter(r => r.status === 'failed').length > 0 && (
                      <Chip 
                        label={`${batchResults.filter(r => r.status === 'failed').length} failed`} 
                        size="small" 
                        sx={{ bgcolor: alpha('#ef4444', 0.1), color: '#ef4444', fontWeight: 600 }} 
                      />
                    )}
                  </Stack>
                  <Stack direction="row" spacing={1} flexWrap="wrap">
                    {batchResults.filter(r => r.status === 'failed').length > 0 && !isBatchGenerating && (
                      <Button
                        variant="contained"
                        size="small"
                        onClick={handleRetryFailed}
                        startIcon={<RefreshCw size={16} />}
                        sx={{ 
                          bgcolor: '#dc2626', 
                          color: 'white',
                          textTransform: 'none',
                          fontWeight: 600,
                          '&:hover': { bgcolor: '#b91c1c' }
                        }}
                      >
                        Retry Failed
                      </Button>
                    )}
                    {batchResults.filter(r => r.status === 'success').length > 0 && !isBatchGenerating && (
                      <Button
                        variant="contained"
                        size="small"
                        onClick={handleDownloadAllAsZip}
                        disabled={isDownloadingZip}
                        startIcon={isDownloadingZip ? <CircularProgress size={14} color="inherit" /> : <Archive size={16} />}
                        data-testid="button-download-zip"
                        sx={{ 
                          bgcolor: '#22c55e', 
                          color: 'white',
                          textTransform: 'none',
                          fontWeight: 600,
                          '&:hover': { bgcolor: '#16a34a' }
                        }}
                      >
                        {isDownloadingZip ? 'Creating ZIP...' : 'Download All as ZIP'}
                      </Button>
                    )}
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={() => setBatchResults([])}
                      startIcon={<X size={16} />}
                      sx={{ borderColor: '#e5e7eb', color: '#374151', textTransform: 'none', fontWeight: 600 }}
                    >
                      Clear
                    </Button>
                  </Stack>
                </Stack>

                {/* Card Grid */}
                <Grid container spacing={2}>
                  {batchResults.map((result, index) => (
                    <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={index}>
                      <Card 
                        elevation={0} 
                        sx={{ 
                          border: '1px solid rgba(0,0,0,0.08)', 
                          borderRadius: 3,
                          overflow: 'hidden',
                          transition: 'all 0.2s ease',
                          '&:hover': { 
                            boxShadow: '0 8px 24px rgba(0,0,0,0.1)',
                            transform: 'translateY(-2px)'
                          }
                        }}
                      >
                        <Box sx={{ position: 'relative' }}>
                          {/* Image Number Badge */}
                          <Chip
                            label={`Image ${String(index + 1).padStart(2, '0')}`}
                            size="small"
                            sx={{
                              position: 'absolute',
                              top: 8,
                              left: 8,
                              zIndex: 10,
                              bgcolor: 'rgba(0,0,0,0.7)',
                              color: 'white',
                              fontWeight: 600,
                              fontSize: '0.7rem'
                            }}
                          />

                          {/* Done Badge for Completed */}
                          {result.status === 'success' && result.imageUrl && (
                            <Chip
                              icon={<CheckCircle size={12} />}
                              label="Done"
                              size="small"
                              sx={{
                                position: 'absolute',
                                top: 8,
                                right: 8,
                                zIndex: 10,
                                bgcolor: alpha('#22c55e', 0.9),
                                color: 'white',
                                fontWeight: 600,
                                fontSize: '0.65rem',
                                '& .MuiChip-icon': { color: 'white' }
                              }}
                            />
                          )}

                          {/* Delete Button */}
                          {(result.status === 'success' || result.status === 'failed') && (
                            <IconButton
                              size="small"
                              onClick={() => handleDeleteImage(index)}
                              sx={{ 
                                position: 'absolute', 
                                top: result.status === 'success' ? 40 : 8, 
                                right: 8, 
                                bgcolor: 'rgba(239, 68, 68, 0.9)',
                                color: 'white',
                                zIndex: 10,
                                '&:hover': { bgcolor: '#dc2626' },
                                width: 26,
                                height: 26
                              }}
                              data-testid={`button-delete-image-${index}`}
                            >
                              <Trash2 size={12} />
                            </IconButton>
                          )}

                          {/* Processing State */}
                          {(result.status === 'generating' || result.status === 'pending') ? (
                            <Box sx={{ 
                              height: getCardHeight(), 
                              background: 'linear-gradient(135deg, #fef3c7 0%, #fde68a 100%)',
                              display: 'flex', 
                              flexDirection: 'column', 
                              alignItems: 'center', 
                              justifyContent: 'center', 
                              gap: 1.5,
                              position: 'relative',
                              overflow: 'hidden'
                            }}>
                              <Box sx={{
                                position: 'absolute',
                                top: 0,
                                left: 0,
                                right: 0,
                                height: 3,
                              }}>
                                <LinearProgress 
                                  sx={{ 
                                    height: 3, 
                                    bgcolor: 'rgba(217,119,6,0.2)',
                                    '& .MuiLinearProgress-bar': { bgcolor: '#d97706' }
                                  }} 
                                />
                              </Box>
                              <Box sx={{ 
                                width: 56, 
                                height: 56, 
                                borderRadius: '50%', 
                                bgcolor: 'white', 
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'center',
                                boxShadow: '0 4px 12px rgba(217,119,6,0.3)'
                              }}>
                                <CircularProgress size={28} sx={{ color: '#d97706' }} />
                              </Box>
                              <Typography variant="caption" sx={{ color: '#92400e', fontWeight: 600, letterSpacing: 0.5 }}>
                                Generating...
                              </Typography>
                              {result.retryCount > 0 && (
                                <Typography variant="caption" sx={{ color: '#b45309', fontSize: '0.65rem' }}>
                                  Retry {result.retryCount}/10
                                </Typography>
                              )}
                            </Box>
                          ) : result.status === 'failed' ? (
                            /* Error State */
                            <Box sx={{ 
                              height: getCardHeight(), 
                              background: 'linear-gradient(135deg, #fee2e2 0%, #fecaca 100%)',
                              display: 'flex', 
                              flexDirection: 'column',
                              alignItems: 'center', 
                              justifyContent: 'center', 
                              p: 2,
                              gap: 1
                            }}>
                              <Box sx={{ 
                                width: 48, 
                                height: 48, 
                                borderRadius: '50%', 
                                bgcolor: 'white', 
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'center',
                                boxShadow: '0 4px 12px rgba(239,68,68,0.2)'
                              }}>
                                <X size={24} color="#dc2626" />
                              </Box>
                              <Typography variant="caption" sx={{ 
                                color: '#991b1b', 
                                textAlign: 'center',
                                fontWeight: 500,
                                lineHeight: 1.4,
                                maxWidth: '90%'
                              }}>
                                {result.error && result.error.length > 50 ? result.error.substring(0, 50) + '...' : (result.error || 'Failed')}
                              </Typography>
                              <Button
                                size="small"
                                variant="contained"
                                onClick={() => handleRegenerateImage(index)}
                                startIcon={<RefreshCw size={12} />}
                                sx={{ 
                                  bgcolor: '#3b82f6', 
                                  color: 'white', 
                                  textTransform: 'none', 
                                  fontSize: '0.7rem',
                                  fontWeight: 600,
                                  '&:hover': { bgcolor: '#2563eb' }
                                }}
                                data-testid={`button-retry-single-${index}`}
                              >
                                Retry
                              </Button>
                            </Box>
                          ) : (
                            /* Completed State with Image */
                            <Box sx={{ height: getCardHeight(), bgcolor: '#f1f5f9', position: 'relative' }}>
                              <img
                                src={result.imageUrl}
                                alt={`Generated ${index + 1}`}
                                loading="lazy"
                                decoding="async"
                                style={{ 
                                  width: '100%', 
                                  height: '100%', 
                                  objectFit: 'cover',
                                  display: 'block'
                                }}
                              />
                            </Box>
                          )}
                        </Box>

                        <CardContent sx={{ p: 2, bgcolor: '#fafafa' }}>
                          <Stack spacing={1.5}>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                color: '#374151',
                                fontWeight: 500,
                                lineHeight: 1.5,
                                display: '-webkit-box',
                                WebkitLineClamp: 2,
                                WebkitBoxOrient: 'vertical',
                                overflow: 'hidden',
                                minHeight: 42
                              }}
                            >
                              {result.prompt}
                            </Typography>
                            
                            {result.status === 'success' && result.imageUrl && (
                              <Stack direction="row" spacing={1}>
                                <Button
                                  size="small"
                                  variant="outlined"
                                  startIcon={<Download size={14} />}
                                  onClick={async () => {
                                    const filename = `image-${index + 1}.png`;
                                    try {
                                      toast({ title: "Downloading...", description: "Please wait..." });
                                      const proxyUrl = `/api/images/download-proxy?imageUrl=${encodeURIComponent(result.imageUrl!)}&filename=${encodeURIComponent(filename)}`;
                                      const response = await fetch(proxyUrl, { credentials: 'include' });
                                      if (!response.ok) throw new Error('Download failed');
                                      const blob = await response.blob();
                                      const blobUrl = URL.createObjectURL(blob);
                                      const link = document.createElement('a');
                                      link.href = blobUrl;
                                      link.download = filename;
                                      document.body.appendChild(link);
                                      link.click();
                                      document.body.removeChild(link);
                                      URL.revokeObjectURL(blobUrl);
                                      toast({ title: "Downloaded!", description: "Image saved." });
                                    } catch (error) {
                                      window.open(result.imageUrl, '_blank');
                                      toast({ title: "Download Issue", description: "Opening in new tab.", variant: "default" });
                                    }
                                  }}
                                  sx={{
                                    flex: 1,
                                    borderRadius: 2,
                                    textTransform: 'none',
                                    fontWeight: 600,
                                    fontSize: '0.75rem',
                                    borderColor: '#374151',
                                    color: '#374151',
                                    '&:hover': { 
                                      borderColor: '#1f2937',
                                      bgcolor: alpha('#374151', 0.05)
                                    }
                                  }}
                                  data-testid={`button-download-image-${index}`}
                                >
                                  Download
                                </Button>
                                <IconButton
                                  size="small"
                                  onClick={() => window.open(result.imageUrl, '_blank')}
                                  sx={{
                                    border: '1px solid #e5e7eb',
                                    borderRadius: 2,
                                    '&:hover': { 
                                      borderColor: '#374151',
                                      bgcolor: alpha('#374151', 0.05)
                                    }
                                  }}
                                >
                                  <ExternalLink size={14} />
                                </IconButton>
                                <IconButton
                                  size="small"
                                  onClick={() => handleRegenerateImage(index)}
                                  sx={{
                                    border: '1px solid #3b82f6',
                                    borderRadius: 2,
                                    color: '#3b82f6',
                                    '&:hover': { 
                                      borderColor: '#2563eb',
                                      bgcolor: alpha('#3b82f6', 0.05)
                                    }
                                  }}
                                  data-testid={`button-regenerate-image-${index}`}
                                >
                                  <RefreshCw size={14} />
                                </IconButton>
                              </Stack>
                            )}
                          </Stack>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Stack>
            </Paper>
          )}
          </Stack>
        </Box>
      </Box>
    </UserPanelLayout>
  );
}
