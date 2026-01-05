import React, { useState, useEffect, useMemo } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import { getDisplayVideoUrl } from "@/lib/videoUtils";

import { alpha, keyframes } from '@mui/material/styles';
import Box from '@mui/material/Box';
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
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Chip from '@mui/material/Chip';
import Fade from '@mui/material/Fade';
import Zoom from '@mui/material/Zoom';
import Grow from '@mui/material/Grow';
import Grid from '@mui/material/Grid';
import { Video, Sparkles, Download, Play, RefreshCw, Monitor, Smartphone, X, Wand2, CheckCircle } from "lucide-react";

const fadeInUp = keyframes`
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const pulse = keyframes`
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.8;
    transform: scale(1.05);
  }
`;

const shimmer = keyframes`
  0% {
    background-position: -200% 0;
  }
  100% {
    background-position: 200% 0;
  }
`;

const float = keyframes`
  0%, 100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-10px);
  }
`;

const spin = keyframes`
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
`;

const scaleIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.9);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const successPulse = keyframes`
  0% {
    box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4);
  }
  70% {
    box-shadow: 0 0 0 20px rgba(34, 197, 94, 0);
  }
  100% {
    box-shadow: 0 0 0 0 rgba(34, 197, 94, 0);
  }
`;

const lightBeam = keyframes`
  0% {
    transform: translateX(-100%) skewX(-15deg);
  }
  100% {
    transform: translateX(300%) skewX(-15deg);
  }
`;

const borderGlow = keyframes`
  0%, 100% {
    opacity: 0.5;
  }
  50% {
    opacity: 1;
  }
`;

const particleFloat = keyframes`
  0%, 100% {
    transform: translateY(0) scale(1);
    opacity: 0.6;
  }
  50% {
    transform: translateY(-8px) scale(1.2);
    opacity: 1;
  }
`;

const glowPulse = keyframes`
  0%, 100% {
    box-shadow: 0 0 20px rgba(99, 102, 241, 0.3), 0 0 40px rgba(99, 102, 241, 0.2), 0 0 60px rgba(99, 102, 241, 0.1);
  }
  50% {
    box-shadow: 0 0 30px rgba(99, 102, 241, 0.5), 0 0 60px rgba(99, 102, 241, 0.3), 0 0 90px rgba(99, 102, 241, 0.2);
  }
`;

const floatDot = keyframes`
  0%, 100% {
    transform: translateY(0) translateX(0);
    opacity: 0.4;
  }
  25% {
    transform: translateY(-30px) translateX(15px);
    opacity: 0.7;
  }
  50% {
    transform: translateY(-50px) translateX(-20px);
    opacity: 0.5;
  }
  75% {
    transform: translateY(-20px) translateX(25px);
    opacity: 0.8;
  }
`;

const pulseDot = keyframes`
  0%, 100% {
    transform: scale(1) translateY(0);
    opacity: 0.5;
  }
  50% {
    transform: scale(1.5) translateY(-20px);
    opacity: 0.8;
  }
`;

const staticDots = Array.from({ length: 30 }, (_, i) => ({
  id: i,
  left: (i * 17 + 7) % 100,
  top: (i * 23 + 11) % 100,
  size: 4 + (i % 5) * 1.5,
  delay: (i % 8) * 0.5,
  duration: 4 + (i % 4),
  type: i % 2 === 0 ? 'float' : 'pulse'
}));

const AnimatedDotsBackground = React.memo(() => {
  return (
    <Box
      sx={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        overflow: 'hidden',
        pointerEvents: 'none',
        zIndex: 0,
        minHeight: '100vh'
      }}
    >
      {staticDots.map((dot) => (
        <Box
          key={dot.id}
          sx={{
            position: 'absolute',
            left: `${dot.left}%`,
            top: `${dot.top}%`,
            width: dot.size,
            height: dot.size,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #64748b 0%, #94a3b8 100%)',
            opacity: 0.5,
            animation: dot.type === 'float' 
              ? `${floatDot} ${dot.duration}s ease-in-out infinite`
              : `${pulseDot} ${dot.duration}s ease-in-out infinite`,
            animationDelay: `${dot.delay}s`,
            boxShadow: '0 0 8px rgba(100, 116, 139, 0.4)'
          }}
        />
      ))}
    </Box>
  );
});

type AspectRatio = "landscape" | "portrait";
type InputMode = "text" | "json";

export default function VeoGenerator() {
  const [prompt, setPrompt] = useState("");
  const [inputMode, setInputMode] = useState<InputMode>("text");
  const [aspectRatio, setAspectRatio] = useState<AspectRatio>("landscape");
  const [isGenerating, setIsGenerating] = useState(false);
  const [videoUrl, setVideoUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [videoModalOpen, setVideoModalOpen] = useState(false);
  const { toast } = useToast();
  const [, setLocation] = useLocation();

  // Convert data URL to Blob URL for better video playback
  const displayVideoUrl = useMemo(() => getDisplayVideoUrl(videoUrl), [videoUrl]);

  // Cleanup blob URL when component unmounts or videoUrl changes
  useEffect(() => {
    return () => {
      if (displayVideoUrl && displayVideoUrl.startsWith('blob:')) {
        URL.revokeObjectURL(displayVideoUrl);
      }
    };
  }, [displayVideoUrl]);

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

  const parsePrompt = (): string => {
    if (inputMode === "json") {
      try {
        // Validate JSON and send as-is to VEO3
        JSON.parse(prompt);
        return prompt.trim();
      } catch {
        return '';
      }
    }
    return prompt.trim();
  };

  const handleGenerate = async () => {
    const finalPrompt = parsePrompt();
    
    if (!finalPrompt) {
      toast({
        title: inputMode === "json" ? "Invalid JSON" : "Prompt required",
        description: inputMode === "json" ? "Please enter valid JSON with a prompt field" : "Please enter a video prompt",
        variant: "destructive",
      });
      return;
    }

    setIsGenerating(true);
    setVideoUrl(null);
    setError(null);
    setProgress(10);

    try {
      // Start video generation (returns immediately with video ID)
      const startResponse = await fetch('/api/start-video-generation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ prompt: finalPrompt, aspectRatio }),
      });

      if (!startResponse.ok) {
        const errorData = await startResponse.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to start video generation');
      }

      const startData = await startResponse.json();
      const videoId = startData.videoId;
      
      if (!videoId) {
        throw new Error('No video ID returned');
      }

      console.log(`[VeoGenerator] Video generation started. ID: ${videoId}`);
      setProgress(20);

      // Poll for status every 20 seconds
      const pollInterval = 20000; // 20 seconds
      const maxPolls = 30; // 10 minutes max (30 * 20s)
      let pollCount = 0;

      const pollForStatus = async (): Promise<void> => {
        pollCount++;
        
        try {
          const statusResponse = await fetch(`/api/video-status/${videoId}`, {
            credentials: 'include',
          });

          if (!statusResponse.ok) {
            throw new Error('Failed to check video status');
          }

          const statusData = await statusResponse.json();
          console.log(`[VeoGenerator] Poll ${pollCount}: status=${statusData.status}, elapsed=${statusData.elapsedSeconds}s`);

          // Update progress based on status
          if (statusData.status === 'processing') {
            setProgress(Math.min(20 + (pollCount * 3), 90));
          }

          // Handle direct base64 data (no database storage)
          if (statusData.status === 'completed' && statusData.videoData) {
            setProgress(100);
            // Convert raw base64 to data URL for display
            const dataUrl = `data:video/mp4;base64,${statusData.videoData}`;
            setVideoUrl(dataUrl);
            setIsGenerating(false);
            toast({ title: "Video generated!", description: "Your video is ready to watch and download." });
            return;
          }
          
          // Handle cloud storage URL
          if (statusData.status === 'completed' && statusData.videoUrl) {
            setProgress(100);
            setVideoUrl(statusData.videoUrl);
            setIsGenerating(false);
            toast({ title: "Video generated!", description: "Your video is ready to watch and download." });
            return;
          }

          if (statusData.status === 'failed') {
            throw new Error(statusData.error || 'Video generation failed');
          }

          // Still processing - continue polling
          if (pollCount < maxPolls && (statusData.status === 'pending' || statusData.status === 'processing')) {
            setTimeout(pollForStatus, pollInterval);
          } else if (pollCount >= maxPolls) {
            throw new Error('Video generation timed out. Check history for status.');
          }
        } catch (pollError) {
          console.error('[VeoGenerator] Poll error:', pollError);
          const pollErrorMessage = pollError instanceof Error ? pollError.message : 'Video generation failed';
          
          // Log page buttons when cookie error occurs
          if (pollErrorMessage.toLowerCase().includes('cookie') || pollErrorMessage.toLowerCase().includes('expired') || pollErrorMessage.toLowerCase().includes('not logged in')) {
            console.log('[VeoGenerator] Cookie/Auth Error - Page State:', {
              error: pollErrorMessage,
              prompt: prompt,
              aspectRatio: aspectRatio,
              buttons: {
                'input-prompt': { exists: !!document.querySelector('[data-testid="input-prompt"]'), disabled: (document.querySelector('[data-testid="input-prompt"]') as HTMLInputElement)?.disabled },
                'button-landscape': { exists: !!document.querySelector('[data-testid="button-landscape"]'), disabled: (document.querySelector('[data-testid="button-landscape"]') as HTMLButtonElement)?.disabled },
                'button-portrait': { exists: !!document.querySelector('[data-testid="button-portrait"]'), disabled: (document.querySelector('[data-testid="button-portrait"]') as HTMLButtonElement)?.disabled },
                'button-generate': { exists: !!document.querySelector('[data-testid="button-generate"]'), disabled: (document.querySelector('[data-testid="button-generate"]') as HTMLButtonElement)?.disabled },
                'button-download': { exists: !!document.querySelector('[data-testid="button-download"]'), disabled: (document.querySelector('[data-testid="button-download"]') as HTMLButtonElement)?.disabled },
                'button-new': { exists: !!document.querySelector('[data-testid="button-new"]'), disabled: (document.querySelector('[data-testid="button-new"]') as HTMLButtonElement)?.disabled },
              }
            });
          }
          
          setError(pollErrorMessage);
          setIsGenerating(false);
          toast({ title: "Generation failed", description: pollErrorMessage, variant: "destructive" });
        }
      };

      // Start polling after initial delay
      setTimeout(pollForStatus, pollInterval);

    } catch (err) {
      console.error("Error generating video:", err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to generate video';
      
      // Log page buttons when cookie error occurs
      if (errorMessage.toLowerCase().includes('cookie') || errorMessage.toLowerCase().includes('expired') || errorMessage.toLowerCase().includes('not logged in')) {
        console.log('[VeoGenerator] Cookie/Auth Error - Page State:', {
          error: errorMessage,
          prompt: prompt,
          aspectRatio: aspectRatio,
          buttons: {
            'input-prompt': { exists: !!document.querySelector('[data-testid="input-prompt"]'), disabled: (document.querySelector('[data-testid="input-prompt"]') as HTMLInputElement)?.disabled },
            'button-landscape': { exists: !!document.querySelector('[data-testid="button-landscape"]'), disabled: (document.querySelector('[data-testid="button-landscape"]') as HTMLButtonElement)?.disabled },
            'button-portrait': { exists: !!document.querySelector('[data-testid="button-portrait"]'), disabled: (document.querySelector('[data-testid="button-portrait"]') as HTMLButtonElement)?.disabled },
            'button-generate': { exists: !!document.querySelector('[data-testid="button-generate"]'), disabled: (document.querySelector('[data-testid="button-generate"]') as HTMLButtonElement)?.disabled },
            'button-download': { exists: !!document.querySelector('[data-testid="button-download"]'), disabled: (document.querySelector('[data-testid="button-download"]') as HTMLButtonElement)?.disabled },
            'button-new': { exists: !!document.querySelector('[data-testid="button-new"]'), disabled: (document.querySelector('[data-testid="button-new"]') as HTMLButtonElement)?.disabled },
          }
        });
      }
      
      setError(errorMessage);
      setIsGenerating(false);
      toast({ title: "Generation failed", description: errorMessage, variant: "destructive" });
    }
  };

  const handleDownload = () => {
    if (videoUrl) {
      const filename = `veo3-video-${Date.now()}.mp4`;
      
      // For data URLs (direct mode), download directly from browser
      if (videoUrl.startsWith('data:')) {
        const link = document.createElement('a');
        link.href = videoUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        return;
      }
      
      // For cloud URLs, use server proxy
      const downloadUrl = `/api/videos/download-single?videoUrl=${encodeURIComponent(videoUrl)}&filename=${encodeURIComponent(filename)}`;
      
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      toast({ title: "Download started", description: "Your video is being downloaded" });
    }
  };

  if (sessionLoading) {
    return (
      <UserPanelLayout>
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress sx={{ color: '#374151' }} />
        </Box>
      </UserPanelLayout>
    );
  }

  return (
    <UserPanelLayout>
      <AnimatedDotsBackground />
      <Box sx={{ maxWidth: 1400, mx: 'auto', position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <Fade in timeout={600}>
          <Box sx={{ animation: `${fadeInUp} 0.6s ease-out`, mb: 3 }}>
            <Stack direction="row" alignItems="center" spacing={2}>
              <Box
                sx={{
                  width: 52,
                  height: 52,
                  borderRadius: 2.5,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 4px 16px rgba(55, 65, 81, 0.2)',
                  background: 'linear-gradient(135deg, #374151 0%, #1f2937 100%)',
                }}
              >
                <Video size={26} color="white" />
              </Box>
              <Box>
                <Typography 
                  variant="h5" 
                  sx={{ 
                    fontWeight: 700, 
                    color: '#1a1a2e',
                    background: 'linear-gradient(135deg, #374151 0%, #1a1a2e 100%)',
                    backgroundClip: 'text',
                    WebkitBackgroundClip: 'text',
                    WebkitTextFillColor: 'transparent'
                  }}
                >
                  VEO3.1 Video Generator
                </Typography>
                <Typography variant="body2" sx={{ color: '#64748b' }}>
                  Create stunning AI videos with Google's VEO 3.1 model
                </Typography>
              </Box>
            </Stack>
          </Box>
        </Fade>

        {/* Two Column Layout */}
        <Grid container spacing={3}>
          {/* Left Column - Form */}
          <Grid size={{ xs: 12, lg: 6 }}>
            <Grow in timeout={800}>
              <Paper
              elevation={0}
              sx={{
                p: { xs: 3, md: 4 },
                borderRadius: 3,
                border: '1px solid rgba(0,0,0,0.08)',
                backgroundColor: '#ffffff',
                transition: 'all 0.3s ease',
                '&:hover': {
                  boxShadow: '0 8px 30px rgba(0,0,0,0.08)',
                  transform: 'translateY(-2px)'
                }
              }}
            >
            <Stack spacing={3}>
              <Box>
                <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151' }}>
                    {inputMode === "text" ? "Video Prompt" : "JSON Prompt"}
                    <Chip label="Required" size="small" sx={{ ml: 1, height: 20, fontSize: '0.7rem', bgcolor: alpha('#374151', 0.1), color: '#374151' }} />
                  </Typography>
                  <ToggleButtonGroup
                    value={inputMode}
                    exclusive
                    onChange={(_, value) => value && setInputMode(value)}
                    disabled={isGenerating}
                    size="small"
                    sx={{ gap: 0.5 }}
                  >
                    <ToggleButton 
                      value="text"
                      data-testid="button-text-mode"
                      sx={{ 
                        px: 1.5, py: 0.3, fontSize: '0.75rem', borderRadius: '6px !important', 
                        border: '1px solid #e5e7eb !important', textTransform: 'none',
                        '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                      }}
                    >
                      Text
                    </ToggleButton>
                    <ToggleButton 
                      value="json"
                      data-testid="button-json-mode"
                      sx={{ 
                        px: 1.5, py: 0.3, fontSize: '0.75rem', borderRadius: '6px !important', 
                        border: '1px solid #e5e7eb !important', textTransform: 'none',
                        '&.Mui-selected': { bgcolor: alpha('#374151', 0.1), borderColor: '#374151 !important', color: '#374151' }
                      }}
                    >
                      JSON
                    </ToggleButton>
                  </ToggleButtonGroup>
                </Stack>
                <TextField
                  fullWidth
                  multiline
                  rows={4}
                  placeholder={inputMode === "text" 
                    ? "Describe your video... e.g., 'A majestic eagle soaring through golden sunset clouds over mountain peaks'"
                    : '{"prompt": "A majestic eagle soaring through golden sunset clouds over mountain peaks"}'}
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  disabled={isGenerating}
                  data-testid="input-prompt"
                  sx={{
                    '& .MuiOutlinedInput-root': {
                      borderRadius: 2,
                      fontFamily: inputMode === "json" ? 'monospace' : 'inherit',
                      '& fieldset': { borderColor: '#e5e7eb' },
                      '&:hover fieldset': { borderColor: '#374151' },
                      '&.Mui-focused fieldset': { borderColor: '#374151' }
                    }
                  }}
                />
                {inputMode === "json" && (
                  <Typography variant="caption" sx={{ color: '#9ca3af', mt: 0.5, display: 'block' }}>
                    {(() => {
                      const parsed = parsePrompt();
                      return parsed ? `Valid prompt: "${parsed.substring(0, 50)}${parsed.length > 50 ? '...' : ''}"` : "Enter valid JSON with prompt or text field";
                    })()}
                  </Typography>
                )}
              </Box>

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, color: '#374151' }}>
                  Aspect Ratio
                </Typography>
                <ToggleButtonGroup
                  value={aspectRatio}
                  exclusive
                  onChange={(_, value) => value && setAspectRatio(value)}
                  disabled={isGenerating}
                  size="small"
                  sx={{ gap: 0.5 }}
                >
                  <ToggleButton
                    value="landscape"
                    data-testid="button-landscape"
                    sx={{
                      px: 1.5,
                      py: 0.6,
                      fontSize: '0.8rem',
                      borderRadius: '8px !important',
                      border: '1px solid #e5e7eb !important',
                      textTransform: 'none',
                      '&.Mui-selected': {
                        bgcolor: alpha('#374151', 0.1),
                        borderColor: '#374151 !important',
                        color: '#374151',
                        '&:hover': { bgcolor: alpha('#374151', 0.15) }
                      }
                    }}
                  >
                    <Monitor size={14} style={{ marginRight: 5 }} />
                    16:9
                  </ToggleButton>
                  <Tooltip title="Portrait not supported" arrow>
                    <span>
                      <ToggleButton
                        value="portrait"
                        data-testid="button-portrait"
                        disabled
                        sx={{
                          px: 1.5,
                          py: 0.6,
                          fontSize: '0.8rem',
                          borderRadius: '8px !important',
                          border: '1px solid #e5e7eb !important',
                          textTransform: 'none',
                          opacity: 0.5,
                          cursor: 'not-allowed',
                          '&.Mui-disabled': {
                            border: '1px solid #e5e7eb !important',
                            color: '#9ca3af',
                          }
                        }}
                      >
                        <Smartphone size={14} style={{ marginRight: 5 }} />
                        9:16
                      </ToggleButton>
                    </span>
                  </Tooltip>
                </ToggleButtonGroup>
              </Box>

              {/* Simple Clean Button */}
              <Button
                variant="contained"
                size="large"
                onClick={handleGenerate}
                disabled={isGenerating || !prompt.trim()}
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
                  '&:hover': {
                    bgcolor: '#1f2937',
                  },
                  '&:disabled': { 
                    bgcolor: '#9ca3af',
                    color: 'rgba(255,255,255,0.7)',
                  },
                }}
              >
                {isGenerating ? 'Generating...' : 'Generate Video'}
              </Button>
            </Stack>
          </Paper>
          </Grow>
          </Grid>

          {/* Right Column - Video Preview */}
          <Grid size={{ xs: 12, lg: 6 }}>
            <Grow in timeout={1000}>
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
                {displayVideoUrl ? (
                  <Stack spacing={3} sx={{ flex: 1 }}>
                    <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ flexWrap: 'wrap', gap: 1 }}>
                      <Stack direction="row" alignItems="center" spacing={1.5}>
                        <CheckCircle size={22} color="#22c55e" />
                        <Typography variant="h6" sx={{ fontWeight: 600, color: '#1e293b' }}>
                          Video Generated
                        </Typography>
                      </Stack>
                      <Chip 
                        label="Ready" 
                        size="small" 
                        sx={{ 
                          bgcolor: '#dcfce7', 
                          color: '#16a34a',
                          fontWeight: 500
                        }} 
                      />
                    </Stack>

                    <Box
                      sx={{
                        position: 'relative',
                        borderRadius: 2,
                        overflow: 'hidden',
                        bgcolor: '#0f172a',
                        aspectRatio: aspectRatio === 'landscape' ? '16/9' : '9/16',
                        maxHeight: 350,
                        cursor: 'pointer',
                        border: '1px solid #e2e8f0',
                        flex: 1
                      }}
                      onClick={() => setVideoModalOpen(true)}
                    >
                      <video
                        src={displayVideoUrl || undefined}
                        controls
                        style={{ width: '100%', height: '100%', objectFit: 'contain' }}
                      />
                    </Box>

                    <Stack direction="row" spacing={2}>
                      <Button
                        variant="contained"
                        onClick={handleDownload}
                        startIcon={<Download size={18} />}
                        data-testid="button-download"
                        sx={{
                          flex: 1,
                          py: 1.5,
                          borderRadius: 2,
                          textTransform: 'none',
                          fontWeight: 600,
                          color: 'white',
                          bgcolor: '#374151',
                          '&:hover': { bgcolor: '#1f2937' }
                        }}
                      >
                        Download
                      </Button>
                      <Button
                        variant="outlined"
                        onClick={() => { setVideoUrl(null); setPrompt(''); }}
                        startIcon={<RefreshCw size={18} />}
                        data-testid="button-new"
                        sx={{
                          flex: 1,
                          py: 1.5,
                          borderRadius: 2,
                          textTransform: 'none',
                          fontWeight: 600,
                          borderColor: '#e2e8f0',
                          color: '#475569',
                          '&:hover': { borderColor: '#374151', color: '#374151', bgcolor: 'transparent' }
                        }}
                      >
                        New Video
                      </Button>
                    </Stack>
                  </Stack>
                ) : isGenerating ? (
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
                      Generating Video...
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#64748b', mb: 2 }}>
                      {progress}% Complete
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={progress}
                      sx={{
                        width: '80%',
                        height: 8,
                        borderRadius: 4,
                        bgcolor: '#e2e8f0',
                        '& .MuiLinearProgress-bar': {
                          borderRadius: 4,
                          bgcolor: '#374151'
                        }
                      }}
                    />
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
                      border: '2px dashed #e2e8f0'
                    }}
                  >
                    <Box
                      sx={{
                        width: 100,
                        height: 100,
                        borderRadius: '50%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        background: 'linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%)',
                        mb: 3
                      }}
                    >
                      <Video size={48} color="#94a3b8" />
                    </Box>
                    <Typography variant="h6" sx={{ fontWeight: 600, color: '#64748b', mb: 1 }}>
                      Video Preview
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#94a3b8', textAlign: 'center', maxWidth: 280 }}>
                      Enter your prompt and click "Generate Video" to create your AI video
                    </Typography>
                  </Box>
                )}
              </Paper>
            </Grow>
          </Grid>
        </Grid>
      </Box>

      <Dialog
        open={videoModalOpen}
        onClose={() => setVideoModalOpen(false)}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: {
            borderRadius: 3,
            bgcolor: '#000',
            overflow: 'hidden'
          }
        }}
      >
        <IconButton
          onClick={() => setVideoModalOpen(false)}
          sx={{
            position: 'absolute',
            top: 8,
            right: 8,
            color: 'white',
            bgcolor: 'rgba(0,0,0,0.5)',
            zIndex: 1,
            '&:hover': { bgcolor: 'rgba(0,0,0,0.7)' }
          }}
        >
          <X size={24} />
        </IconButton>
        <DialogContent sx={{ p: 0 }}>
          {displayVideoUrl && (
            <video
              src={displayVideoUrl}
              controls
              autoPlay
              style={{ width: '100%', height: 'auto', display: 'block' }}
            />
          )}
        </DialogContent>
      </Dialog>
    </UserPanelLayout>
  );
}
