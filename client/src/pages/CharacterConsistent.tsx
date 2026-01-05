import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import AnimatedDotsBackground from "@/components/AnimatedDotsBackground";
import type { Character } from "@shared/schema";

import { alpha } from '@mui/material/styles';
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
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardMedia from '@mui/material/CardMedia';
import CardContent from '@mui/material/CardContent';
import CardActions from '@mui/material/CardActions';
import Avatar from '@mui/material/Avatar';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import Divider from '@mui/material/Divider';
import { Users, Sparkles, Trash2, UserPlus, Play, Lock, CheckCircle, Download, ExternalLink, RefreshCw, FileText, X } from "lucide-react";

// Video Preview Component with CORS handling for different URL types
function VideoPreview({ videoUrl, height }: { videoUrl: string; height: number }) {
  const [loadState, setLoadState] = useState<'loading' | 'ready' | 'error'>('loading');
  const [actualUrl, setActualUrl] = useState<string>('');
  const videoRef = useRef<HTMLVideoElement>(null);
  
  useEffect(() => {
    setLoadState('loading');
    
    // Convert direct: URLs to proxy endpoint with CORS headers
    if (videoUrl.startsWith('direct:')) {
      const videoId = videoUrl.replace('direct:', '');
      setActualUrl(`/api/video-preview/${videoId}`);
    } else if (videoUrl.startsWith('/api/local-video/')) {
      setActualUrl(videoUrl);
    } else if (videoUrl.startsWith('blob:')) {
      setActualUrl(videoUrl);
    } else {
      setActualUrl(videoUrl);
    }
  }, [videoUrl]);
  
  if (!actualUrl) {
    return (
      <Box sx={{ height, bgcolor: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <CircularProgress size={32} sx={{ color: '#3b82f6' }} />
      </Box>
    );
  }
  
  return (
    <Box sx={{ height, bgcolor: '#000', position: 'relative', overflow: 'hidden' }}>
      {loadState === 'loading' && (
        <Box sx={{ 
          position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', bgcolor: 'rgba(0,0,0,0.8)', zIndex: 10, gap: 1
        }}>
          <CircularProgress size={32} sx={{ color: '#3b82f6' }} />
          <Typography variant="caption" sx={{ color: '#93c5fd' }}>Loading...</Typography>
        </Box>
      )}
      
      {loadState === 'error' && (
        <Box sx={{ 
          position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', bgcolor: '#1a1a1a', zIndex: 10, gap: 1
        }}>
          <Play size={32} color="#6b7280" />
          <Typography variant="caption" sx={{ color: '#9ca3af' }}>Click to play</Typography>
        </Box>
      )}
      
      <video 
        ref={videoRef}
        src={actualUrl}
        controls 
        preload="metadata"
        playsInline
        muted
        crossOrigin="anonymous"
        onLoadedData={() => setLoadState('ready')}
        onCanPlay={() => setLoadState('ready')}
        onError={() => setLoadState('error')}
        style={{ 
          width: '100%', height: '100%', objectFit: 'cover',
          opacity: loadState === 'ready' ? 1 : 0.3
        }} 
      />
    </Box>
  );
}

export default function CharacterConsistent() {
  const [characterName, setCharacterName] = useState("");
  const [characterDescription, setCharacterDescription] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [selectedCharacterId, setSelectedCharacterId] = useState<string | null>(null);
  const [prompts, setPrompts] = useState("");
  const [lockSeed, setLockSeed] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRetrying, setIsRetrying] = useState(false);
  const [generatedVideos, setGeneratedVideos] = useState<Array<{ prompt: string; videoUrl: string; error?: string; status?: 'processing' | 'completed' | 'failed'; operationName?: string }>>([]);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const { toast } = useToast();
  const [, setLocation] = useLocation();

  const { data: session, isLoading: sessionLoading } = useQuery<{
    authenticated: boolean;
    user?: { id: string; username: string; isAdmin: boolean };
  }>({
    queryKey: ["/api/session"],
  });

  const { data: charactersData, isLoading: charactersLoading } = useQuery<{ characters: Character[] }>({
    queryKey: ["/api/characters"],
    enabled: !!session?.authenticated,
  });


  useEffect(() => {
    if (!sessionLoading && session && !session.authenticated) {
      toast({ title: "Authentication required", description: "Please log in to use character-consistent video generation.", variant: "destructive" });
      setLocation("/login");
    }
  }, [session, sessionLoading, setLocation, toast]);

  const deleteMutation = useMutation({
    mutationFn: async (characterId: string) => apiRequest("DELETE", `/api/characters/${characterId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/characters"] });
      toast({ title: "Character deleted", description: "Character has been removed." });
      if (selectedCharacterId) setSelectedCharacterId(null);
    },
    onError: (error: Error) => {
      toast({ title: "Delete failed", description: error.message, variant: "destructive" });
    },
  });

  const handleAddCharacter = async () => {
    if (!characterName.trim() || !characterDescription.trim()) {
      toast({ title: "Missing info", description: "Please provide both name and description", variant: "destructive" });
      return;
    }

    if (characterDescription.trim().length < 10) {
      toast({ title: "Description too short", description: "Please provide a more detailed character description (at least 10 characters)", variant: "destructive" });
      return;
    }

    setIsUploading(true);

    try {
      console.log(`[Character Create] Creating text-based character: ${characterName}`);
      
      const response = await fetch('/api/characters', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: characterName,
          characterType: 'text',
          description: characterDescription.trim()
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Failed to create character' }));
        throw new Error(errorData.error || 'Failed to create character');
      }

      console.log(`[Character Create] Success!`);
      queryClient.invalidateQueries({ queryKey: ["/api/characters"] });
      toast({ title: "Character added", description: `${characterName} has been added.` });
      setCharacterName("");
      setCharacterDescription("");
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to create character';
      toast({ title: "Failed to add character", description: errorMessage, variant: "destructive" });
    } finally {
      setIsUploading(false);
    }
  };

  const handleGenerate = async () => {
    if (!selectedCharacterId) {
      toast({ title: "Select character", description: "Please select a character first", variant: "destructive" });
      return;
    }

    const promptList = prompts.split('\n').map(p => p.trim()).filter(p => p.length > 0);
    if (promptList.length === 0) {
      toast({ title: "No prompts", description: "Please enter at least one prompt", variant: "destructive" });
      return;
    }

    setIsGenerating(true);
    setError(null);
    setProgress(0);
    
    // Initialize all videos as "processing"
    const initialVideos = promptList.map(prompt => ({ 
      prompt, 
      videoUrl: '', 
      status: 'processing' as const,
      operationName: '' 
    }));
    setGeneratedVideos(initialVideos);

    try {
      console.log(`[Character Videos] Starting batch request for ${promptList.length} videos...`);
      
      // SINGLE BATCH REQUEST - Backend handles:
      // 1. Per-video token rotation
      // 2. Image upload with each token
      // 3. Fresh mediaId for each video
      // 4. Video generation with same token
      // 5. All retries (up to 20)
      const batchResponse = await fetch('/api/character-bulk-generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          characterId: selectedCharacterId,
          prompts: promptList,
          aspectRatio: 'landscape',
          lockSeed,
        }),
      });

      if (!batchResponse.ok) {
        const errorData = await batchResponse.json().catch(() => ({ error: 'Batch generation failed' }));
        throw new Error(errorData.error || errorData.message || 'Failed to start batch generation');
      }

      const batchData = await batchResponse.json();
      console.log(`[Character Videos] Batch started: ${batchData.successfulStarts}/${batchData.totalVideos} successful`);

      // Process batch results
      const results = batchData.results || [];
      const pendingOps: Array<{ index: number; prompt: string; operationName: string; sceneId: string; tokenId: string; historyId: string }> = [];
      
      results.forEach((result: { prompt: string; operationName?: string; sceneId?: string; tokenId?: string; historyId?: string; error?: string }, idx: number) => {
        if (result.operationName) {
          pendingOps.push({
            index: idx,
            prompt: result.prompt,
            operationName: result.operationName,
            sceneId: result.sceneId || '',
            tokenId: result.tokenId || '',
            historyId: result.historyId || ''
          });
        } else if (result.error) {
          setGeneratedVideos(prev => {
            const updated = [...prev];
            updated[idx] = { ...updated[idx], error: result.error, status: 'failed' as const };
            return updated;
          });
        }
      });

      const failedCount = results.filter((r: { error?: string }) => r.error).length;
      let completedCount = failedCount;
      setProgress((completedCount / promptList.length) * 100);

      // Poll for all pending operations using batch endpoint
      const pollInterval = 3000; // 3 seconds
      const maxPolls = 60; // 3 minutes max
      let pollCount = 0;

      while (pendingOps.length > 0 && pollCount < maxPolls) {
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        pollCount++;

        try {
          const statusResponse = await fetch('/api/check-videos-batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              videos: pendingOps.map(op => ({
                operationName: op.operationName,
                sceneId: op.sceneId,
                tokenId: op.tokenId,
                historyId: op.historyId
              }))
            }),
          });

          if (statusResponse.ok) {
            const statusData = await statusResponse.json();
            const statusResults = statusData.results || [];

            const nowCompleted: typeof pendingOps = [];
            
            statusResults.forEach((result: { 
              sceneId: string; 
              historyId?: string;
              status: string; 
              videoUrl?: string; 
              error?: string;
              newOperationName?: string;
              newSceneId?: string;
              tokenId?: string;
            }, idx: number) => {
              const pendingOp = pendingOps[idx];
              if (!pendingOp) return;

              const statusLower = result.status?.toLowerCase() || '';
              
              if (statusLower === 'completed' && result.videoUrl) {
                setGeneratedVideos(prev => {
                  const updated = [...prev];
                  updated[pendingOp.index] = { 
                    ...updated[pendingOp.index], 
                    videoUrl: result.videoUrl || '', 
                    status: 'completed' as const 
                  };
                  return updated;
                });
                nowCompleted.push(pendingOp);
              } else if (statusLower === 'retrying' && result.newOperationName) {
                // Backend is retrying with new token - update pendingOps with new details
                console.log(`[Character Videos] Video ${pendingOp.index + 1} retrying with new token`);
                pendingOp.operationName = result.newOperationName;
                if (result.newSceneId) pendingOp.sceneId = result.newSceneId;
                if (result.tokenId) pendingOp.tokenId = result.tokenId;
                // Keep polling - don't mark as completed
              } else if (statusLower === 'failed' || result.error) {
                setGeneratedVideos(prev => {
                  const updated = [...prev];
                  updated[pendingOp.index] = { 
                    ...updated[pendingOp.index], 
                    error: result.error || 'Generation failed', 
                    status: 'failed' as const 
                  };
                  return updated;
                });
                nowCompleted.push(pendingOp);
              }
            });

            // Remove completed from pending
            nowCompleted.forEach(completed => {
              const idx = pendingOps.findIndex(p => p.operationName === completed.operationName);
              if (idx !== -1) pendingOps.splice(idx, 1);
            });

            completedCount += nowCompleted.length;
            setProgress((completedCount / promptList.length) * 100);
          }
        } catch (err) {
          console.log(`[Character Videos] Status check failed, continuing...`);
        }

        console.log(`[Character Videos] Poll ${pollCount}: ${pendingOps.length} pending, ${completedCount} done`);
      }

      // Mark any remaining as timed out
      if (pendingOps.length > 0) {
        setGeneratedVideos(prev => {
          const updated = [...prev];
          pendingOps.forEach(op => {
            updated[op.index] = { ...updated[op.index], error: 'Generation timed out', status: 'failed' as const };
          });
          return updated;
        });
      }

      setProgress(100);
      toast({ title: "Generation complete", description: `Processed ${promptList.length} videos.` });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate videos');
      toast({ title: "Error", description: err instanceof Error ? err.message : 'Failed to generate videos', variant: "destructive" });
    } finally {
      setIsGenerating(false);
    }
  };

  // Retry all failed videos with different tokens
  const handleRetryFailed = async () => {
    const failedVideos = generatedVideos
      .map((video, index) => ({ ...video, originalIndex: index }))
      .filter(video => video.error || video.status === 'failed');

    if (failedVideos.length === 0) {
      toast({ title: "No failed videos", description: "There are no failed videos to retry." });
      return;
    }

    if (!selectedCharacterId) {
      toast({ title: "Select character", description: "Please select a character first", variant: "destructive" });
      return;
    }

    setIsRetrying(true);
    setError(null);

    // Mark failed videos as processing again
    setGeneratedVideos(prev => {
      const updated = [...prev];
      failedVideos.forEach(fv => {
        updated[fv.originalIndex] = { 
          ...updated[fv.originalIndex], 
          error: undefined, 
          status: 'processing' as const,
          videoUrl: ''
        };
      });
      return updated;
    });

    try {
      const promptList = failedVideos.map(v => v.prompt);
      console.log(`[Character Videos] Retrying ${promptList.length} failed videos with different tokens...`);

      // Send retry request - backend will use different tokens for each
      const batchResponse = await fetch('/api/character-bulk-generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          characterId: selectedCharacterId,
          prompts: promptList,
          aspectRatio: 'landscape',
          lockSeed,
        }),
      });

      if (!batchResponse.ok) {
        const errorData = await batchResponse.json().catch(() => ({ error: 'Retry batch failed' }));
        throw new Error(errorData.error || errorData.message || 'Failed to retry videos');
      }

      const batchData = await batchResponse.json();
      console.log(`[Character Videos] Retry batch started: ${batchData.successfulStarts}/${batchData.totalVideos} successful`);

      // Map results back to original indices
      const results = batchData.results || [];
      const pendingOps: Array<{ index: number; prompt: string; operationName: string; sceneId: string; tokenId: string; historyId: string }> = [];

      results.forEach((result: { prompt: string; operationName?: string; sceneId?: string; tokenId?: string; historyId?: string; error?: string }, idx: number) => {
        const originalIndex = failedVideos[idx]?.originalIndex;
        if (originalIndex === undefined) return;

        if (result.operationName) {
          pendingOps.push({
            index: originalIndex,
            prompt: result.prompt,
            operationName: result.operationName,
            sceneId: result.sceneId || '',
            tokenId: result.tokenId || '',
            historyId: result.historyId || ''
          });
        } else if (result.error) {
          setGeneratedVideos(prev => {
            const updated = [...prev];
            updated[originalIndex] = { ...updated[originalIndex], error: result.error, status: 'failed' as const };
            return updated;
          });
        }
      });

      // Poll for pending operations
      const pollInterval = 3000;
      const maxPolls = 60;
      let pollCount = 0;

      while (pendingOps.length > 0 && pollCount < maxPolls) {
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        pollCount++;

        try {
          const statusResponse = await fetch('/api/check-videos-batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              videos: pendingOps.map(op => ({
                operationName: op.operationName,
                sceneId: op.sceneId,
                tokenId: op.tokenId,
                historyId: op.historyId
              }))
            }),
          });

          if (statusResponse.ok) {
            const statusData = await statusResponse.json();
            const statusResults = statusData.results || [];
            const nowCompleted: typeof pendingOps = [];

            statusResults.forEach((result: { 
              sceneId: string; 
              status: string; 
              videoUrl?: string; 
              error?: string;
              newOperationName?: string;
              newSceneId?: string;
              tokenId?: string;
            }, idx: number) => {
              const pendingOp = pendingOps[idx];
              if (!pendingOp) return;

              const statusLower = result.status?.toLowerCase() || '';

              if (statusLower === 'completed' && result.videoUrl) {
                setGeneratedVideos(prev => {
                  const updated = [...prev];
                  updated[pendingOp.index] = { 
                    ...updated[pendingOp.index], 
                    videoUrl: result.videoUrl || '', 
                    status: 'completed' as const,
                    error: undefined
                  };
                  return updated;
                });
                nowCompleted.push(pendingOp);
              } else if (statusLower === 'retrying' && result.newOperationName) {
                console.log(`[Character Videos Retry] Video ${pendingOp.index + 1} retrying with new token`);
                pendingOp.operationName = result.newOperationName;
                if (result.newSceneId) pendingOp.sceneId = result.newSceneId;
                if (result.tokenId) pendingOp.tokenId = result.tokenId;
              } else if (statusLower === 'failed' || result.error) {
                setGeneratedVideos(prev => {
                  const updated = [...prev];
                  updated[pendingOp.index] = { 
                    ...updated[pendingOp.index], 
                    error: result.error || 'Retry failed', 
                    status: 'failed' as const 
                  };
                  return updated;
                });
                nowCompleted.push(pendingOp);
              }
            });

            nowCompleted.forEach(completed => {
              const idx = pendingOps.findIndex(p => p.operationName === completed.operationName);
              if (idx !== -1) pendingOps.splice(idx, 1);
            });
          }
        } catch (err) {
          console.log(`[Character Videos Retry] Status check failed, continuing...`);
        }

        console.log(`[Character Videos Retry] Poll ${pollCount}: ${pendingOps.length} pending`);
      }

      // Mark remaining as timed out
      if (pendingOps.length > 0) {
        setGeneratedVideos(prev => {
          const updated = [...prev];
          pendingOps.forEach(op => {
            updated[op.index] = { ...updated[op.index], error: 'Retry timed out', status: 'failed' as const };
          });
          return updated;
        });
      }

      const successCount = failedVideos.length - generatedVideos.filter(v => v.error || v.status === 'failed').length;
      toast({ title: "Retry complete", description: `Retried ${failedVideos.length} videos.` });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to retry videos');
      toast({ title: "Retry Error", description: err instanceof Error ? err.message : 'Failed to retry videos', variant: "destructive" });
    } finally {
      setIsRetrying(false);
    }
  };

  // Regenerate a single video by index
  const handleRegenerateSingle = async (videoIndex: number) => {
    const video = generatedVideos[videoIndex];
    if (!video || !selectedCharacterId) {
      toast({ title: "Error", description: "Cannot regenerate video", variant: "destructive" });
      return;
    }

    // Mark this video as processing
    setGeneratedVideos(prev => {
      const updated = [...prev];
      updated[videoIndex] = { 
        ...updated[videoIndex], 
        error: undefined, 
        status: 'processing' as const,
        videoUrl: ''
      };
      return updated;
    });

    try {
      console.log(`[Character Videos] Regenerating video ${videoIndex + 1}: "${video.prompt}"`);

      const batchResponse = await fetch('/api/character-bulk-generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          characterId: selectedCharacterId,
          prompts: [video.prompt],
          aspectRatio: 'landscape',
          lockSeed,
        }),
      });

      if (!batchResponse.ok) {
        const errorData = await batchResponse.json().catch(() => ({ error: 'Regeneration failed' }));
        throw new Error(errorData.error || 'Failed to regenerate video');
      }

      const batchData = await batchResponse.json();
      const results = batchData.results || [];
      const result = results[0];

      if (!result?.operationName) {
        throw new Error(result?.error || 'Failed to start regeneration');
      }

      // Poll for this single video
      const pollInterval = 3000;
      const maxPolls = 60;
      let pollCount = 0;
      let operationName = result.operationName;
      let sceneId = result.sceneId || '';
      let tokenId = result.tokenId || '';
      let historyId = result.historyId || '';

      while (pollCount < maxPolls) {
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        pollCount++;

        try {
          const statusResponse = await fetch('/api/check-videos-batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              videos: [{ operationName, sceneId, tokenId, historyId }]
            }),
          });

          if (statusResponse.ok) {
            const statusData = await statusResponse.json();
            const statusResult = statusData.results?.[0];
            const statusLower = statusResult?.status?.toLowerCase() || '';

            if (statusLower === 'completed' && statusResult.videoUrl) {
              setGeneratedVideos(prev => {
                const updated = [...prev];
                updated[videoIndex] = { 
                  ...updated[videoIndex], 
                  videoUrl: statusResult.videoUrl, 
                  status: 'completed' as const,
                  error: undefined
                };
                return updated;
              });
              toast({ title: "Regenerated!", description: `Scene ${videoIndex + 1} has been regenerated.` });
              return;
            } else if (statusLower === 'retrying' && statusResult.newOperationName) {
              operationName = statusResult.newOperationName;
              if (statusResult.newSceneId) sceneId = statusResult.newSceneId;
              if (statusResult.tokenId) tokenId = statusResult.tokenId;
            } else if (statusLower === 'failed' || statusResult.error) {
              throw new Error(statusResult.error || 'Regeneration failed');
            }
          }
        } catch (err) {
          if (err instanceof Error && err.message !== 'Regeneration failed') {
            console.log(`[Character Videos] Status check failed, continuing...`);
          } else {
            throw err;
          }
        }
      }

      // Timeout
      throw new Error('Regeneration timed out');
    } catch (err) {
      setGeneratedVideos(prev => {
        const updated = [...prev];
        updated[videoIndex] = { 
          ...updated[videoIndex], 
          error: err instanceof Error ? err.message : 'Regeneration failed', 
          status: 'failed' as const 
        };
        return updated;
      });
      toast({ title: "Regeneration failed", description: err instanceof Error ? err.message : 'Failed to regenerate', variant: "destructive" });
    }
  };

  const characters = charactersData?.characters || [];

  if (sessionLoading || charactersLoading) {
    return (
      <UserPanelLayout>
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress />
        </Box>
      </UserPanelLayout>
    );
  }

  return (
    <UserPanelLayout>
      <Box sx={{ position: 'relative', minHeight: '100vh' }}>
        <AnimatedDotsBackground />
        <Box sx={{ position: 'relative', zIndex: 1, maxWidth: 1200, mx: 'auto' }}>
          <Stack spacing={3}>
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
                <Users size={24} color="white" />
              </Box>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                  Character Consistent Videos
                </Typography>
                <Typography variant="body2" sx={{ color: '#64748b' }}>
                  Generate videos with consistent character appearance
                </Typography>
              </Box>
            </Stack>
          </Box>

          <Grid container spacing={3}>
            <Grid size={{ xs: 12, md: 4 }}>
              <Paper elevation={0} sx={{ p: 3, borderRadius: 3, border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff', height: '100%' }}>
                <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e', mb: 3 }}>Your Characters</Typography>

                <Stack spacing={2} sx={{ mb: 3 }}>
                  {characters.length === 0 ? (
                    <Typography variant="body2" sx={{ color: '#9ca3af', textAlign: 'center', py: 4 }}>
                      No characters yet. Add one below.
                    </Typography>
                  ) : (
                    characters.map((char) => (
                      <Paper
                        key={char.id}
                        elevation={0}
                        onClick={() => setSelectedCharacterId(char.id)}
                        sx={{
                          p: 2,
                          borderRadius: 2,
                          border: `1px solid ${selectedCharacterId === char.id ? '#374151' : '#e5e7eb'}`,
                          bgcolor: selectedCharacterId === char.id ? alpha('#374151', 0.05) : 'transparent',
                          cursor: 'pointer',
                          '&:hover': { borderColor: '#374151' }
                        }}
                      >
                        <Stack direction="row" alignItems="flex-start" spacing={2}>
                          <Avatar sx={{ width: 40, height: 40, bgcolor: '#374151' }}>
                            <FileText size={20} />
                          </Avatar>
                          <Box sx={{ flex: 1, minWidth: 0 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{char.name}</Typography>
                            {char.description && (
                              <Typography variant="caption" sx={{ color: '#6b7280', display: 'block', mt: 0.5, lineHeight: 1.4 }}>
                                {char.description.length > 60 ? char.description.substring(0, 60) + '...' : char.description}
                              </Typography>
                            )}
                          </Box>
                          <IconButton size="small" onClick={(e) => { e.stopPropagation(); deleteMutation.mutate(char.id); }} sx={{ color: '#ef4444' }}>
                            <Trash2 size={16} />
                          </IconButton>
                        </Stack>
                      </Paper>
                    ))
                  )}
                </Stack>

                <Divider sx={{ my: 3 }} />

                <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151', mb: 2 }}>Add New Character</Typography>
                <Stack spacing={2}>
                  <TextField
                    fullWidth
                    size="small"
                    placeholder="Character name"
                    value={characterName}
                    onChange={(e) => setCharacterName(e.target.value)}
                    disabled={isUploading}
                    data-testid="input-character-name"
                    sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
                  />

                  <TextField
                    fullWidth
                    multiline
                    rows={4}
                    placeholder="Describe your character in detail...&#10;&#10;Example: A young woman with long black hair, wearing a red dress, elegant and graceful appearance, fair skin, brown eyes"
                    value={characterDescription}
                    onChange={(e) => setCharacterDescription(e.target.value)}
                    disabled={isUploading}
                    data-testid="input-character-description"
                    sx={{ 
                      '& .MuiOutlinedInput-root': { 
                        borderRadius: 2,
                        '& .MuiInputBase-input': {
                          color: '#1f2937',
                        },
                        '& .MuiInputBase-input::placeholder': {
                          color: '#6b7280',
                          opacity: 1,
                        }
                      } 
                    }}
                  />
                  <Typography variant="caption" sx={{ color: '#9ca3af', mt: -1 }}>
                    This description will be combined with each video prompt for consistent character appearance.
                  </Typography>

                  <Button
                    variant="contained"
                    onClick={handleAddCharacter}
                    disabled={isUploading || !characterName.trim() || !characterDescription.trim()}
                    startIcon={isUploading ? <CircularProgress size={18} sx={{ color: 'white' }} /> : <UserPlus size={18} />}
                    data-testid="button-add-character"
                    sx={{ 
                      width: '100%',
                      borderRadius: 2, 
                      textTransform: 'none', 
                      fontWeight: 600, 
                      bgcolor: '#374151', 
                      '&:hover': { bgcolor: '#1f2937' },
                      '&:disabled': { 
                        bgcolor: '#9ca3af',
                        color: 'rgba(255,255,255,0.7)',
                      },
                    }}
                  >
                    {isUploading ? 'Adding...' : 'Add Character'}
                  </Button>
                </Stack>
              </Paper>
            </Grid>

            <Grid size={{ xs: 12, md: 8 }}>
              <Paper elevation={0} sx={{ p: 3, borderRadius: 3, border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff' }}>
                <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e', mb: 3 }}>Generate Videos</Typography>

                {!selectedCharacterId && (
                  <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
                    Select a character from the left panel to start generating videos.
                  </Alert>
                )}

                <Stack spacing={3}>
                  <Box>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151' }}>
                        Video Prompts (one per line)
                      </Typography>
                      <Chip 
                        label={`${prompts.split('\n').filter(p => p.trim().length > 0).length} prompts`}
                        size="small"
                        sx={{ 
                          bgcolor: alpha('#374151', 0.1), 
                          color: '#374151', 
                          fontWeight: 600,
                          fontSize: '0.75rem'
                        }}
                      />
                    </Stack>
                    <TextField
                      fullWidth
                      multiline
                      rows={6}
                      placeholder="Character walking through a garden&#10;Character dancing at a party&#10;Character cooking in a kitchen..."
                      value={prompts}
                      onChange={(e) => setPrompts(e.target.value)}
                      disabled={isGenerating || !selectedCharacterId}
                      sx={{ 
                        '& .MuiOutlinedInput-root': { 
                          borderRadius: 2, 
                          fontFamily: 'monospace',
                          color: '#1f2937',
                          '& .MuiInputBase-input': {
                            color: '#1f2937',
                          },
                          '& .MuiInputBase-input::placeholder': {
                            color: '#6b7280',
                            opacity: 1,
                          }
                        } 
                      }}
                    />
                  </Box>

                  <FormControlLabel
                    control={<Switch checked={lockSeed} onChange={(e) => setLockSeed(e.target.checked)} sx={{ '& .Mui-checked': { color: '#374151' }, '& .Mui-checked + .MuiSwitch-track': { bgcolor: '#374151' } }} />}
                    label="Lock seed for consistency"
                    disabled={!selectedCharacterId}
                  />

                  {error && <Alert severity="error" onClose={() => setError(null)} sx={{ borderRadius: 2 }}>{error}</Alert>}

                  {isGenerating && (
                    <Box>
                      <LinearProgress variant="determinate" value={progress} sx={{ height: 8, borderRadius: 4, bgcolor: alpha('#374151', 0.1), '& .MuiLinearProgress-bar': { borderRadius: 4, bgcolor: '#374151' } }} />
                      <Typography variant="caption" sx={{ color: '#64748b', mt: 0.5 }}>{Math.round(progress)}% complete</Typography>
                    </Box>
                  )}

                  <Button
                    variant="contained"
                    size="large"
                    onClick={handleGenerate}
                    disabled={isGenerating || !selectedCharacterId || !prompts.trim()}
                    startIcon={isGenerating ? <CircularProgress size={18} sx={{ color: 'white' }} /> : <Sparkles size={18} />}
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
                    {isGenerating ? 'Generating...' : 'Generate Videos'}
                  </Button>
                </Stack>

                {generatedVideos.length > 0 && (
                  <Box sx={{ mt: 4 }}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
                      <Stack direction="row" alignItems="center" spacing={2}>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                          Generated Videos
                        </Typography>
                        <Stack direction="row" spacing={1}>
                          <Chip 
                            size="small" 
                            label={`${generatedVideos.filter(v => v.status === 'completed').length} completed`}
                            sx={{ bgcolor: alpha('#22c55e', 0.1), color: '#16a34a', fontWeight: 600, fontSize: '0.7rem' }}
                          />
                          {generatedVideos.filter(v => v.status === 'processing' || (!v.videoUrl && !v.error)).length > 0 && (
                            <Chip 
                              size="small" 
                              label={`${generatedVideos.filter(v => v.status === 'processing' || (!v.videoUrl && !v.error)).length} processing`}
                              sx={{ bgcolor: alpha('#f59e0b', 0.1), color: '#d97706', fontWeight: 600, fontSize: '0.7rem' }}
                            />
                          )}
                          {generatedVideos.filter(v => v.error).length > 0 && (
                            <Chip 
                              size="small" 
                              label={`${generatedVideos.filter(v => v.error).length} failed`}
                              sx={{ bgcolor: alpha('#ef4444', 0.1), color: '#dc2626', fontWeight: 600, fontSize: '0.7rem' }}
                            />
                          )}
                        </Stack>
                      </Stack>
                      {/* Retry All Failed Button */}
                      {generatedVideos.filter(v => v.error || v.status === 'failed').length > 0 && !isGenerating && !isRetrying && (
                        <Button
                          variant="contained"
                          size="small"
                          onClick={handleRetryFailed}
                          startIcon={<RefreshCw size={14} />}
                          data-testid="button-retry-all-failed"
                          sx={{
                            textTransform: 'none',
                            fontWeight: 600,
                            fontSize: '0.75rem',
                            bgcolor: '#dc2626',
                            color: 'white',
                            borderRadius: 2,
                            px: 2,
                            '&:hover': {
                              bgcolor: '#b91c1c',
                            },
                          }}
                        >
                          Retry All Failed ({generatedVideos.filter(v => v.error || v.status === 'failed').length})
                        </Button>
                      )}
                      {isRetrying && (
                        <Button
                          variant="contained"
                          size="small"
                          disabled
                          startIcon={<CircularProgress size={14} sx={{ color: 'white' }} />}
                          sx={{
                            textTransform: 'none',
                            fontWeight: 600,
                            fontSize: '0.75rem',
                            bgcolor: '#9ca3af',
                            color: 'white',
                            borderRadius: 2,
                            px: 2,
                          }}
                        >
                          Retrying...
                        </Button>
                      )}
                    </Stack>

                    <Grid container spacing={2.5}>
                      {generatedVideos.map((video, index) => (
                        <Grid size={{ xs: 12, sm: 6, lg: 4 }} key={index}>
                          <Card 
                            elevation={0} 
                            sx={{ 
                              border: '1px solid rgba(0,0,0,0.08)', 
                              borderRadius: 3,
                              overflow: 'hidden',
                              transition: 'all 0.2s ease-in-out',
                              '&:hover': {
                                transform: 'translateY(-4px)',
                                boxShadow: '0 12px 24px rgba(0,0,0,0.1)',
                                borderColor: 'rgba(0,0,0,0.12)'
                              }
                            }}
                          >
                            <Box sx={{ position: 'relative' }}>
                              <Chip
                                label={`Scene ${String(index + 1).padStart(2, '0')}`}
                                size="small"
                                sx={{
                                  position: 'absolute',
                                  top: 8,
                                  left: 8,
                                  zIndex: 10,
                                  bgcolor: 'rgba(0,0,0,0.7)',
                                  color: 'white',
                                  fontWeight: 700,
                                  fontSize: '0.65rem',
                                  backdropFilter: 'blur(4px)',
                                  '& .MuiChip-label': { px: 1 }
                                }}
                              />

                              {video.status === 'completed' && video.videoUrl && (
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

                              {video.status === 'processing' || (!video.videoUrl && !video.error) ? (
                                <Box sx={{ 
                                  height: 160, // Landscape 16:9 for VEO3 videos
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
                                </Box>
                              ) : video.error ? (
                                <Box sx={{ 
                                  height: 160, // Landscape 16:9 for VEO3 videos
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
                                    {video.error.length > 60 ? video.error.substring(0, 60) + '...' : video.error}
                                  </Typography>
                                </Box>
                              ) : (
                                <VideoPreview videoUrl={video.videoUrl} height={160} />
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
                                  {video.prompt}
                                </Typography>
                                
                                {video.status === 'completed' && video.videoUrl && (
                                  <Stack direction="row" spacing={1}>
                                    <Button
                                      size="small"
                                      variant="outlined"
                                      startIcon={<Download size={14} />}
                                      onClick={() => {
                                        const filename = `scene-${index + 1}.mp4`;
                                        const downloadUrl = `/api/videos/download-single?videoUrl=${encodeURIComponent(video.videoUrl!)}&filename=${encodeURIComponent(filename)}`;
                                        const link = document.createElement('a');
                                        link.href = downloadUrl;
                                        link.download = filename;
                                        document.body.appendChild(link);
                                        link.click();
                                        document.body.removeChild(link);
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
                                      data-testid={`button-download-video-${index}`}
                                    >
                                      Download
                                    </Button>
                                    <IconButton
                                      size="small"
                                      onClick={() => handleRegenerateSingle(index)}
                                      title="Regenerate this video"
                                      sx={{
                                        border: '1px solid #e5e7eb',
                                        borderRadius: 2,
                                        '&:hover': { 
                                          borderColor: '#6366f1',
                                          bgcolor: alpha('#6366f1', 0.05)
                                        }
                                      }}
                                      data-testid={`button-regenerate-video-${index}`}
                                    >
                                      <RefreshCw size={14} />
                                    </IconButton>
                                    <IconButton
                                      size="small"
                                      onClick={() => window.open(video.videoUrl, '_blank')}
                                      sx={{
                                        border: '1px solid #e5e7eb',
                                        borderRadius: 2,
                                        '&:hover': { 
                                          borderColor: '#374151',
                                          bgcolor: alpha('#374151', 0.05)
                                        }
                                      }}
                                      data-testid={`button-external-link-video-${index}`}
                                    >
                                      <ExternalLink size={14} />
                                    </IconButton>
                                  </Stack>
                                )}
                                
                                {video.status === 'failed' && video.error && (
                                  <Button
                                    size="small"
                                    variant="outlined"
                                    startIcon={<RefreshCw size={14} />}
                                    onClick={() => handleRegenerateSingle(index)}
                                    sx={{
                                      width: '100%',
                                      borderRadius: 2,
                                      textTransform: 'none',
                                      fontWeight: 600,
                                      fontSize: '0.75rem',
                                      borderColor: '#6366f1',
                                      color: '#6366f1',
                                      '&:hover': { 
                                        borderColor: '#4f46e5',
                                        bgcolor: alpha('#6366f1', 0.05)
                                      }
                                    }}
                                    data-testid={`button-retry-failed-video-${index}`}
                                  >
                                    Regenerate
                                  </Button>
                                )}
                              </Stack>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                )}
              </Paper>
            </Grid>
          </Grid>
          </Stack>
        </Box>
      </Box>
    </UserPanelLayout>
  );
}
