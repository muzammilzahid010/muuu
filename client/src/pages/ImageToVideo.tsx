import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import AnimatedDotsBackground from "@/components/AnimatedDotsBackground";
import { motion, AnimatePresence } from "framer-motion";

import { alpha } from '@mui/material/styles';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import LinearProgress from '@mui/material/LinearProgress';
import Alert from '@mui/material/Alert';
import IconButton from '@mui/material/IconButton';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Chip from '@mui/material/Chip';
import { ImagePlay, Sparkles, Download, X, Upload, Monitor, Smartphone, RefreshCw, Play, Video, Loader2 } from "lucide-react";

type AspectRatio = "landscape" | "portrait";

export default function ImageToVideo() {
  const [prompt, setPrompt] = useState("");
  const [aspectRatio, setAspectRatio] = useState<AspectRatio>("landscape");
  const [isGenerating, setIsGenerating] = useState(false);
  const [videoUrl, setVideoUrl] = useState<string | null>(null);
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [retryCount, setRetryCount] = useState(0);
  const [retryMessage, setRetryMessage] = useState<string | null>(null);
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const MAX_RETRIES = 10;

  // Determine if we should show expanded (two-column) layout
  const showExpandedLayout = isGenerating || videoUrl !== null;

  const { data: session, isLoading: sessionLoading } = useQuery<{
    authenticated: boolean;
    user?: { id: string; username: string; isAdmin: boolean };
  }>({
    queryKey: ["/api/session"],
  });

  useEffect(() => {
    if (!sessionLoading && session && !session.authenticated) {
      toast({
        title: "Authentication required",
        description: "Please log in to generate videos.",
        variant: "destructive",
      });
      setLocation("/login");
    }
  }, [session, sessionLoading, setLocation, toast]);

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

  const handleImageSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        toast({ title: "Invalid File", description: "Please select an image file", variant: "destructive" });
        if (fileInputRef.current) fileInputRef.current.value = '';
        return;
      }
      
      try {
        // Convert to PNG if not already PNG
        const pngFile = await convertToPng(file);
        if (file.type !== 'image/png') {
          toast({ title: "Image Converted", description: "Your image has been converted to PNG format", variant: "default" });
        }
        setSelectedImage(pngFile);
        const reader = new FileReader();
        reader.onloadend = () => setImagePreview(reader.result as string);
        reader.readAsDataURL(pngFile);
      } catch (error) {
        toast({ title: "Conversion Failed", description: "Failed to convert image to PNG", variant: "destructive" });
        if (fileInputRef.current) fileInputRef.current.value = '';
      }
    }
  };

  const handleRemoveImage = () => {
    setSelectedImage(null);
    setImagePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

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

  const generateVideoWithRetry = async (currentRetry: number = 0): Promise<boolean> => {
    const { base64: imageBase64, mimeType: imageMimeType } = await convertImageToBase64(selectedImage!);
    setProgress(20);

    const response = await fetch('/api/generate-image-to-video', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ prompt, aspectRatio, imageBase64, imageMimeType }),
    });

    const data = await response.json();
    setProgress(40);

    if (!response.ok) {
      const errorMsg = data.error || '';
      if (errorMsg.includes('UNSAFE') || errorMsg.includes('PUBLIC_ERROR') || errorMsg.includes('policy') || errorMsg.includes('content')) {
        throw new Error('Video generation failed due to content policy. Your image may contain children, celebrities, copyrighted characters, inappropriate content, or other material that violates Google\'s content guidelines. Please try with a different image.');
      }
      throw new Error(data.error || 'Failed to start video generation from image');
    }

    const { operationName, sceneId, tokenId, historyId } = data;

    let completed = false;
    let attempts = 0;
    const maxAttempts = 16;

    while (!completed && attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 15000));
      attempts++;
      setProgress(Math.min(40 + (attempts * 4), 95));

      const statusResponse = await fetch('/api/check-video-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ operationName, sceneId, tokenId, historyId }),
      });

      const statusData = await statusResponse.json();

      if (statusData.status === 'COMPLETED' || statusData.status === 'MEDIA_GENERATION_STATUS_COMPLETE' || statusData.status === 'MEDIA_GENERATION_STATUS_SUCCESSFUL') {
        setVideoUrl(statusData.videoUrl);
        setProgress(100);
        completed = true;
        setRetryMessage(null);
        toast({ title: "Video generated!", description: "Your video is ready." });
        return true;
      } else if (statusData.status === 'FAILED' || statusData.status === 'MEDIA_GENERATION_STATUS_FAILED') {
        const errorMsg = statusData.error || '';
        const isContentPolicyError = errorMsg.includes('UNSAFE') || errorMsg.includes('PUBLIC_ERROR') || statusData.errorCode;
        if (isContentPolicyError) {
          if (currentRetry < MAX_RETRIES - 1) {
            setRetryCount(currentRetry + 1);
            setRetryMessage(`Auto-retry ${currentRetry + 1}/${MAX_RETRIES} - Retrying generation...`);
            setProgress(10);
            await new Promise(resolve => setTimeout(resolve, 2000));
            return generateVideoWithRetry(currentRetry + 1);
          }
          throw new Error('Video generation failed due to content policy. Your image may contain children, celebrities, copyrighted characters, inappropriate content, or other material that violates Google\'s content guidelines. Please try with a different image.');
        }
        throw new Error(statusData.error || 'Video generation failed');
      } else if (statusData.error && (statusData.error.includes('UNSAFE') || statusData.error.includes('PUBLIC_ERROR') || statusData.errorCode)) {
        if (currentRetry < MAX_RETRIES - 1) {
          setRetryCount(currentRetry + 1);
          setRetryMessage(`Auto-retry ${currentRetry + 1}/${MAX_RETRIES} - Retrying generation...`);
          setProgress(10);
          await new Promise(resolve => setTimeout(resolve, 2000));
          return generateVideoWithRetry(currentRetry + 1);
        }
        throw new Error('Video generation failed due to content policy. Your image may contain children, celebrities, copyrighted characters, inappropriate content, or other material that violates Google\'s content guidelines. Please try with a different image.');
      }
    }

    if (!completed) throw new Error('Video generation timed out');
    return false;
  };

  const handleGenerate = async () => {
    if (!prompt.trim()) {
      toast({ title: "Prompt required", description: "Please enter a video prompt", variant: "destructive" });
      return;
    }

    if (!selectedImage) {
      toast({ title: "Image required", description: "Please select an image to convert to video", variant: "destructive" });
      return;
    }

    setIsGenerating(true);
    setVideoUrl(null);
    setError(null);
    setProgress(10);
    setRetryCount(0);
    setRetryMessage(null);

    try {
      await generateVideoWithRetry(0);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to generate video';
      setError(errorMessage);
      toast({ title: "Generation failed", description: errorMessage, variant: "destructive" });
    } finally {
      setIsGenerating(false);
      setRetryMessage(null);
    }
  };

  const handleGenerateNew = () => {
    setVideoUrl(null);
    setPrompt('');
    handleRemoveImage();
    setError(null);
    setProgress(0);
  };

  if (sessionLoading) {
    return (
      <UserPanelLayout>
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress />
        </Box>
      </UserPanelLayout>
    );
  }

  // Form content - reused in both layouts
  const formContent = (
    <Paper elevation={0} sx={{ p: { xs: 3, md: 4 }, borderRadius: 3, border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff', height: '100%' }}>
      <Stack spacing={3}>
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, color: '#374151' }}>
            Upload Image
            <Chip label="Required" size="small" sx={{ ml: 1, height: 20, fontSize: '0.7rem', bgcolor: alpha('#ef4444', 0.1), color: '#ef4444' }} />
          </Typography>
          <input type="file" accept="image/png" onChange={handleImageSelect} ref={fileInputRef} style={{ display: 'none' }} id="image-input" disabled={isGenerating} />
          {imagePreview ? (
            <Box sx={{ position: 'relative', display: 'inline-block' }}>
              <img src={imagePreview} alt="Selected" style={{ maxWidth: '100%', maxHeight: 200, borderRadius: 12, border: '1px solid #e5e7eb' }} />
              {!isGenerating && (
                <IconButton onClick={handleRemoveImage} sx={{ position: 'absolute', top: -8, right: -8, bgcolor: '#ef4444', color: 'white', '&:hover': { bgcolor: '#dc2626' } }} size="small">
                  <X size={16} />
                </IconButton>
              )}
            </Box>
          ) : (
            <label htmlFor="image-input">
              <Paper elevation={0} sx={{ p: 3, border: '2px dashed #e5e7eb', borderRadius: 2, cursor: 'pointer', textAlign: 'center', '&:hover': { borderColor: '#374151', bgcolor: alpha('#374151', 0.02) } }}>
                <Upload size={32} color="#9ca3af" style={{ marginBottom: 8 }} />
                <Typography variant="body2" sx={{ color: '#6b7280' }}>Click to upload PNG image only</Typography>
              </Paper>
            </label>
          )}
        </Box>

        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: '#374151' }}>Video Prompt</Typography>
          <TextField
            fullWidth
            multiline
            rows={3}
            placeholder="Describe how you want the image to animate..."
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            disabled={isGenerating}
            data-testid="input-prompt"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
          />
        </Box>

        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, color: '#374151' }}>Aspect Ratio</Typography>
          <ToggleButtonGroup value={aspectRatio} exclusive onChange={(_, value) => value && setAspectRatio(value)} disabled={isGenerating} sx={{ gap: 0.5 }}>
            <ToggleButton value="landscape" sx={{ px: 1.5, py: 0.6, fontSize: '0.8rem', borderRadius: '8px !important', border: '1px solid #e5e7eb !important', textTransform: 'none', '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151', '&:hover': { bgcolor: alpha('#374151', 0.15) } } }}>
              <Monitor size={14} style={{ marginRight: 5 }} />16:9
            </ToggleButton>
            <ToggleButton value="portrait" sx={{ px: 1.5, py: 0.6, fontSize: '0.8rem', borderRadius: '8px !important', border: '1px solid #e5e7eb !important', textTransform: 'none', '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151', '&:hover': { bgcolor: alpha('#374151', 0.15) } } }}>
              <Smartphone size={14} style={{ marginRight: 5 }} />9:16
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>

        {error && <Alert severity="error" onClose={() => setError(null)} sx={{ borderRadius: 2 }}>{error}</Alert>}

        <Button
          variant="contained"
          size="large"
          onClick={handleGenerate}
          disabled={isGenerating || !prompt.trim() || !selectedImage}
          startIcon={isGenerating ? <CircularProgress size={18} sx={{ color: 'white' }} /> : <Sparkles size={18} />}
          data-testid="button-generate"
          sx={{
            width: '100%',
            py: 1.5,
            borderRadius: 2,
            textTransform: 'none',
            fontWeight: 600,
            fontSize: '1rem',
            color: 'white',
            bgcolor: '#374151',
            '&:hover': { bgcolor: '#1f2937' },
            '&:disabled': { bgcolor: '#9ca3af', color: 'rgba(255,255,255,0.7)' },
          }}
        >
          {isGenerating ? 'Generating...' : 'Generate Video'}
        </Button>
      </Stack>
    </Paper>
  );

  // Video preview content
  const videoPreviewContent = (
    <Paper 
      elevation={0} 
      sx={{ 
        p: { xs: 3, md: 4 }, 
        borderRadius: 3, 
        border: '1px solid rgba(0,0,0,0.08)', 
        backgroundColor: '#ffffff',
        height: '100%',
        display: 'flex',
        flexDirection: 'column'
      }}
    >
      {isGenerating && !videoUrl ? (
        // Loading/Generating state
        <Stack spacing={3} sx={{ height: '100%', justifyContent: 'center' }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
              Generating Video
            </Typography>
            <Chip 
              label={retryCount > 0 ? `Retry ${retryCount}/${MAX_RETRIES}` : "Processing"} 
              size="small" 
              sx={{ 
                bgcolor: retryCount > 0 ? alpha('#f59e0b', 0.1) : alpha('#374151', 0.1),
                color: retryCount > 0 ? '#f59e0b' : '#374151'
              }} 
            />
          </Stack>

          {/* Animated placeholder - respects aspect ratio */}
          <Box 
            sx={{ 
              width: aspectRatio === 'portrait' ? '60%' : '100%',
              mx: 'auto',
              aspectRatio: aspectRatio === 'landscape' ? '16/9' : '9/16',
              maxHeight: aspectRatio === 'portrait' ? 450 : 300,
              borderRadius: 2, 
              overflow: 'hidden', 
              bgcolor: '#f8fafc',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              border: '1px solid #e5e7eb'
            }}
          >
            <motion.div
              animate={{ 
                scale: [1, 1.1, 1],
                opacity: [0.5, 1, 0.5]
              }}
              transition={{ 
                duration: 2,
                repeat: Infinity,
                ease: "easeInOut"
              }}
            >
              <Box sx={{ 
                p: 3, 
                borderRadius: '50%', 
                bgcolor: alpha('#374151', 0.1),
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Video size={48} color="#374151" />
              </Box>
            </motion.div>
            <Typography variant="body1" sx={{ mt: 3, color: '#374151', fontWeight: 600 }}>
              {retryMessage || 'Creating your video...'}
            </Typography>
            <Typography variant="body2" sx={{ mt: 1, color: '#9ca3af' }}>
              This may take a few minutes
            </Typography>
          </Box>

          {/* Progress bar */}
          <Box sx={{ p: 2, bgcolor: alpha('#374151', 0.05), borderRadius: 2 }}>
            <Stack spacing={1.5}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="body2" sx={{ fontWeight: 500, color: '#374151' }}>
                  Progress
                </Typography>
                <Typography variant="body2" sx={{ color: '#64748b', fontWeight: 600 }}>{progress}%</Typography>
              </Stack>
              <LinearProgress 
                variant="determinate" 
                value={progress} 
                sx={{ 
                  height: 8, 
                  borderRadius: 4, 
                  bgcolor: alpha('#374151', 0.1), 
                  '& .MuiLinearProgress-bar': { 
                    borderRadius: 4, 
                    bgcolor: retryCount > 0 ? '#f59e0b' : '#374151' 
                  } 
                }} 
              />
            </Stack>
          </Box>
        </Stack>
      ) : videoUrl ? (
        // Video ready state
        <Stack spacing={3} sx={{ height: '100%' }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>Your Generated Video</Typography>
            <Chip label="Ready" color="success" size="small" />
          </Stack>
          
          <Box sx={{ 
            width: aspectRatio === 'portrait' ? '60%' : '100%',
            mx: 'auto',
            borderRadius: 2, 
            overflow: 'hidden', 
            bgcolor: '#000', 
            aspectRatio: aspectRatio === 'landscape' ? '16/9' : '9/16', 
            maxHeight: aspectRatio === 'portrait' ? 450 : 400,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <video src={videoUrl} controls style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
          </Box>
          
          <Stack direction="row" spacing={2}>
            <Button 
              variant="contained" 
              onClick={() => {
                const filename = `image-to-video-${Date.now()}.mp4`;
                const downloadUrl = `/api/videos/download-single?videoUrl=${encodeURIComponent(videoUrl)}&filename=${encodeURIComponent(filename)}`;
                const link = document.createElement('a');
                link.href = downloadUrl;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
              }} 
              startIcon={<Download size={18} />} 
              sx={{ flex: 1, py: 1.5, borderRadius: 2, textTransform: 'none', fontWeight: 600, bgcolor: '#374151', '&:hover': { bgcolor: '#1f2937' } }}
            >
              Download Video
            </Button>
            <Button 
              variant="outlined" 
              onClick={handleGenerateNew} 
              startIcon={<RefreshCw size={18} />} 
              sx={{ flex: 1, py: 1.5, borderRadius: 2, textTransform: 'none', fontWeight: 600, borderColor: '#e5e7eb', color: '#374151', '&:hover': { borderColor: '#374151', bgcolor: alpha('#374151', 0.05) } }}
            >
              Generate New
            </Button>
          </Stack>
        </Stack>
      ) : null}
    </Paper>
  );

  return (
    <UserPanelLayout>
      <Box sx={{ position: 'relative', minHeight: '100vh' }}>
        <AnimatedDotsBackground />
        <Box sx={{ position: 'relative', zIndex: 1, maxWidth: 1400, mx: 'auto' }}>
          <Stack spacing={3}>
            {/* Header */}
          <Box>
            <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }}>
              <Box
                sx={{
                  p: 1.5,
                  borderRadius: 2,
                  background: 'linear-gradient(135deg, #374151 0%, #4b5563 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 4px 12px rgba(55, 65, 81, 0.3)'
                }}
              >
                <ImagePlay size={24} color="white" />
              </Box>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                  Image to Video
                </Typography>
                <Typography variant="body2" sx={{ color: '#64748b' }}>
                  Transform your images into AI-generated videos
                </Typography>
              </Box>
            </Stack>
          </Box>

          {/* Main Content - Animated Layout */}
          <AnimatePresence mode="wait">
            {!showExpandedLayout ? (
              // Centered layout when not generating
              <motion.div
                key="centered"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, x: -50 }}
                transition={{ duration: 0.4, ease: "easeOut" }}
              >
                <Box sx={{ maxWidth: 700, mx: 'auto' }}>
                  {formContent}
                </Box>
              </motion.div>
            ) : (
              // Two-column layout when generating or video is ready
              <motion.div
                key="expanded"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.4, ease: "easeOut" }}
              >
                <Grid container spacing={3}>
                  {/* Left Column - Form */}
                  <Grid size={{ xs: 12, lg: 5 }}>
                    <motion.div
                      initial={{ x: 100, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      transition={{ duration: 0.5, ease: "easeOut", delay: 0.1 }}
                    >
                      {formContent}
                    </motion.div>
                  </Grid>

                  {/* Right Column - Video Preview */}
                  <Grid size={{ xs: 12, lg: 7 }}>
                    <motion.div
                      initial={{ x: 100, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      transition={{ duration: 0.5, ease: "easeOut", delay: 0.2 }}
                      style={{ height: '100%' }}
                    >
                      {videoPreviewContent}
                    </motion.div>
                  </Grid>
                </Grid>
              </motion.div>
            )}
          </AnimatePresence>
          </Stack>
        </Box>
      </Box>
    </UserPanelLayout>
  );
}
