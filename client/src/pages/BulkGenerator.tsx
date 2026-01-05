import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { queryClient } from "@/lib/queryClient";
import { canAccessTool, getPlanConfig, getRemainingVideos } from "@/lib/planUtils";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import AnimatedDotsBackground from "@/components/AnimatedDotsBackground";
import JSZip from "jszip";

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
import Chip from '@mui/material/Chip';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Tooltip from '@mui/material/Tooltip';
import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import IconButton from '@mui/material/IconButton';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { Layers, Sparkles, StopCircle, Monitor, Smartphone, CheckCircle, XCircle, Clock, Lock, Crown, Download, ExternalLink, X, Archive, AlertTriangle, ListOrdered, RefreshCw, Play } from "lucide-react";

type AspectRatio = "landscape" | "portrait";

interface VideoGenerationStatus {
  id?: string;
  clientId?: string; // Stable client-side key for React rendering
  prompt: string;
  status: "pending" | "processing" | "completed" | "failed";
  videoUrl?: string;
  error?: string;
  tokenLabel?: string | null;
}

const STORAGE_KEY = 'bulkGeneratorResults';
const BATCH_IDS_KEY = 'bulkGeneratorBatchIds';

// Proper Video Preview Component with loading/error states
function VideoPreview({ videoUrl, height }: { videoUrl: string; height: number }) {
  const [loadState, setLoadState] = useState<'loading' | 'ready' | 'error'>('loading');
  const [actualUrl, setActualUrl] = useState<string>('');
  const videoRef = useRef<HTMLVideoElement>(null);
  
  useEffect(() => {
    // Reset state when URL changes
    setLoadState('loading');
    
    // Convert direct: URLs to proxy endpoint with CORS headers
    if (videoUrl.startsWith('direct:')) {
      const videoId = videoUrl.replace('direct:', '');
      setActualUrl(`/api/video-preview/${videoId}`);
    } else if (videoUrl.startsWith('/api/local-video/')) {
      // Local disk storage URLs - already have CORS headers
      setActualUrl(videoUrl);
    } else if (videoUrl.startsWith('blob:')) {
      // Blob URLs work directly
      setActualUrl(videoUrl);
    } else {
      // External URLs (Cloudinary, etc) - use as-is
      setActualUrl(videoUrl);
    }
  }, [videoUrl]);
  
  // Don't render until we have an actual URL
  if (!actualUrl) {
    return (
      <Box sx={{ height, bgcolor: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <CircularProgress size={32} sx={{ color: '#3b82f6' }} />
      </Box>
    );
  }
  
  return (
    <Box sx={{ height, bgcolor: '#000', position: 'relative', overflow: 'hidden' }}>
      {/* Loading overlay - shown until video is ready */}
      {loadState === 'loading' && (
        <Box sx={{ 
          position: 'absolute', 
          inset: 0, 
          display: 'flex', 
          flexDirection: 'column',
          alignItems: 'center', 
          justifyContent: 'center',
          bgcolor: 'rgba(0,0,0,0.8)',
          zIndex: 10,
          gap: 1
        }}>
          <CircularProgress size={32} sx={{ color: '#3b82f6' }} />
          <Typography variant="caption" sx={{ color: '#93c5fd' }}>
            Loading preview...
          </Typography>
        </Box>
      )}
      
      {/* Error state */}
      {loadState === 'error' && (
        <Box sx={{ 
          position: 'absolute', 
          inset: 0, 
          display: 'flex', 
          flexDirection: 'column',
          alignItems: 'center', 
          justifyContent: 'center',
          bgcolor: '#1a1a1a',
          zIndex: 10,
          gap: 1
        }}>
          <Play size={32} color="#6b7280" />
          <Typography variant="caption" sx={{ color: '#9ca3af', textAlign: 'center', px: 2 }}>
            Click to play
          </Typography>
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
          width: '100%', 
          height: '100%', 
          objectFit: 'cover',
          opacity: loadState === 'ready' ? 1 : 0.3
        }} 
      />
    </Box>
  );
}

export default function BulkGenerator() {
  const [prompts, setPrompts] = useState("");
  const [aspectRatio, setAspectRatio] = useState<AspectRatio>("landscape");
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationProgress, setGenerationProgress] = useState<VideoGenerationStatus[]>([]);
  const [currentBatchIds, setCurrentBatchIds] = useState<string[]>([]);
  const [autoDownload, setAutoDownload] = useState(false);
  const [isDownloadingZip, setIsDownloadingZip] = useState(false);
  const [isDownloadingSequential, setIsDownloadingSequential] = useState(false);
  const [isRegeneratingFailed, setIsRegeneratingFailed] = useState(false);
  const [showLeaveWarning, setShowLeaveWarning] = useState(false);
  const [pendingNavigation, setPendingNavigation] = useState<string | null>(null);
  const [showGenerateWarning, setShowGenerateWarning] = useState(false);
  
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const downloadedVideosRef = useRef<Set<string>>(new Set());

  const { data: session, isLoading: sessionLoading } = useQuery<{
    authenticated: boolean;
    user?: { id: string; username: string; isAdmin: boolean; planType: string; planStatus: string; planExpiry: string | null; dailyVideoCount: number };
  }>({
    queryKey: ["/api/session"],
  });

  const { data: queueStatus } = useQuery<{ 
    queueLength: number; 
    isProcessing: boolean;
    results?: VideoGenerationStatus[];
  }>({
    queryKey: ["/api/bulk-generate/status"],
    refetchInterval: isGenerating ? false : 10000,
    enabled: session?.authenticated === true,
  });

  // Track blob URLs for cleanup
  const blobUrlsRef = useRef<Set<string>>(new Set());
  
  // Track if initial load from server has been done (prevents infinite loop)
  const initialLoadDoneRef = useRef<boolean>(false);
  
  // CRITICAL: Stable keys for React rendering - never changes during a batch
  // This prevents video remounting when server IDs arrive
  const stableKeysRef = useRef<string[]>([]);

  // Cleanup polling timeout and blob URLs on unmount
  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearTimeout(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      // Revoke all blob URLs to free browser memory
      blobUrlsRef.current.forEach(url => {
        try { URL.revokeObjectURL(url); } catch (e) {}
      });
      blobUrlsRef.current.clear();
    };
  }, []);

  // Check if there are completed videos that might need downloading
  const hasCompletedVideos = generationProgress.some(v => v.status === 'completed' && v.videoUrl);

  // Track which direct: URLs we've already fetched
  const fetchedDirectUrlsRef = useRef<Set<string>>(new Set());

  // Track which videos are currently being fetched
  const fetchingVideosRef = useRef<Set<string>>(new Set());
  
  // Fetch direct: URLs to blob URLs ONE AT A TIME to avoid overwhelming the browser
  useEffect(() => {
    const fetchNextVideo = async () => {
      // Find the first video that needs fetching and isn't already being fetched
      const videoToFetch = generationProgress.find(
        v => v.status === 'completed' && 
        v.videoUrl?.startsWith('direct:') && 
        v.id &&
        !fetchedDirectUrlsRef.current.has(v.id) &&
        !fetchingVideosRef.current.has(v.id)
      );

      if (!videoToFetch || !videoToFetch.id || !videoToFetch.videoUrl) return;

      // Mark as currently fetching
      fetchingVideosRef.current.add(videoToFetch.id);

      try {
        const downloadUrl = `/api/videos/download-single?videoUrl=${encodeURIComponent(videoToFetch.videoUrl)}&filename=temp.mp4`;
        const response = await fetch(downloadUrl, { credentials: 'include' });
        
        if (response.ok) {
          const blob = await response.blob();
          const blobUrl = URL.createObjectURL(blob);
          blobUrlsRef.current.add(blobUrl);
          
          // Mark as successfully fetched
          fetchedDirectUrlsRef.current.add(videoToFetch.id);
          
          // Confirm download to clear server cache
          const videoId = videoToFetch.videoUrl.replace('direct:', '');
          fetch('/api/videos/confirm-download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ videoId })
          }).catch(() => {});
          
          // Update state with blob URL
          setGenerationProgress(prev => prev.map(v => {
            if (v.id === videoToFetch.id) {
              return { ...v, videoUrl: blobUrl };
            }
            return v;
          }));
          
          console.log(`[BulkGen] Converted video ${videoToFetch.id.slice(0, 8)} to blob URL`);
        }
      } catch (error) {
        console.error(`Failed to fetch video ${videoToFetch.id}:`, error);
      } finally {
        // Remove from currently fetching
        fetchingVideosRef.current.delete(videoToFetch.id!);
      }
    };

    // Check every 500ms for videos to fetch (sequential, not parallel)
    const interval = setInterval(fetchNextVideo, 500);
    // Also run immediately
    fetchNextVideo();
    
    return () => clearInterval(interval);
  }, [generationProgress]);

  // Browser beforeunload warning
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasCompletedVideos) {
        e.preventDefault();
        e.returnValue = '';
        return '';
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [hasCompletedVideos]);

  // Safe navigation handler
  const handleSafeNavigation = (path: string) => {
    if (hasCompletedVideos) {
      setPendingNavigation(path);
      setShowLeaveWarning(true);
    } else {
      setLocation(path);
    }
  };

  const confirmLeave = () => {
    setShowLeaveWarning(false);
    if (pendingNavigation) {
      setLocation(pendingNavigation);
      setPendingNavigation(null);
    }
  };

  const cancelLeave = () => {
    setShowLeaveWarning(false);
    setPendingNavigation(null);
  };

  const stopMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/bulk-generate/stop", { method: "POST", credentials: "include" });
      if (!response.ok) throw new Error("Failed to stop processing");
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Processing stopped", description: "All bulk video processing has been stopped." });
      queryClient.invalidateQueries({ queryKey: ["/api/bulk-generate/status"] });
      setIsGenerating(false);
    },
    onError: (error: any) => {
      toast({ title: "Failed to stop processing", description: error.message, variant: "destructive" });
    },
  });

  const user = session?.user;
  const toolAccess = user ? canAccessTool(user, "bulk") : { allowed: false };
  const planConfig = user ? getPlanConfig(user) : null;
  const remainingVideos = user ? getRemainingVideos(user) : 0;
  const isQueueActive = queueStatus?.isProcessing || (queueStatus?.queueLength ?? 0) > 0;

  // Get card height based on aspect ratio
  const getCardHeight = () => {
    return aspectRatio === "portrait" ? 280 : 160; // Portrait is taller (9:16), Landscape is shorter (16:9)
  };

  useEffect(() => {
    if (!sessionLoading && session && !session.authenticated) {
      toast({ title: "Authentication required", description: "Please log in to use bulk generator.", variant: "destructive" });
      setLocation("/login");
    }
  }, [session, sessionLoading, setLocation, toast]);

  // Load batch IDs from localStorage on mount
  useEffect(() => {
    const savedIds = localStorage.getItem(BATCH_IDS_KEY);
    if (savedIds) {
      try {
        setCurrentBatchIds(JSON.parse(savedIds));
      } catch (e) {
        console.error('Failed to parse saved batch IDs:', e);
      }
    }
  }, []);

  // Load generation progress from server, filtered by current batch IDs
  // CRITICAL: Only run for PAGE RELOAD recovery - NOT during active generation
  // The polling in handleGenerate handles updates during active generation
  useEffect(() => {
    // SKIP if we're actively generating - poll in handleGenerate handles this
    if (isGenerating) return;
    
    if (queueStatus?.results && Array.isArray(queueStatus.results) && currentBatchIds.length > 0) {
      // Build a map of server results by ID
      const serverResultsMap = new Map<string, VideoGenerationStatus>();
      queueStatus.results.forEach(r => {
        if (r.id && currentBatchIds.includes(r.id)) {
          serverResultsMap.set(r.id, r);
        }
      });
      
      if (serverResultsMap.size > 0) {
        // Update items IN-PLACE - preserve order, clientId, and blob URLs
        setGenerationProgress(prev => {
          // If we have no previous items AND we haven't done initial load yet (page reload case)
          if (prev.length === 0 && !initialLoadDoneRef.current) {
            initialLoadDoneRef.current = true; // Mark as done to prevent infinite loop
            const timestamp = Date.now(); // Capture once for all items
            
            // CRITICAL: Create stable keys for page reload case too
            const validIds = currentBatchIds.filter(id => serverResultsMap.has(id));
            stableKeysRef.current = validIds.map((_, idx) => `reload-${timestamp}-${idx}`);
            
            // Sort by currentBatchIds order and create items with stable clientIds
            return validIds.map((id, idx) => {
              const serverData = serverResultsMap.get(id)!;
              return {
                id,
                prompt: serverData.prompt || '',
                status: serverData.status || 'pending',
                videoUrl: serverData.videoUrl,
                error: serverData.error,
                tokenLabel: serverData.tokenLabel,
                clientId: stableKeysRef.current[idx]
              } as VideoGenerationStatus;
            });
          }
          
          // STRUCTURAL SHARING: Only clone items that actually changed
          // This preserves React element identity for unchanged items
          let hasAnyChange = false;
          const newArray = prev.map(item => {
            if (!item.id) return item;
            
            const serverData = serverResultsMap.get(item.id);
            if (!serverData) return item;
            
            // CRITICAL: Never revert terminal states (completed/failed) to non-terminal states
            // This prevents race conditions where stale poll data overwrites newer state
            const isTerminal = item.status === 'completed' || item.status === 'failed';
            const serverIsTerminal = serverData.status === 'completed' || serverData.status === 'failed';
            if (isTerminal && !serverIsTerminal) {
              return item; // Keep local terminal state, ignore stale server data
            }
            
            // Only update if changed
            const statusChanged = item.status !== serverData.status;
            const urlChanged = !item.videoUrl && serverData.videoUrl;
            const errorChanged = item.error !== serverData.error;
            
            if (!statusChanged && !urlChanged && !errorChanged) {
              return item; // Return SAME reference - no clone
            }
            
            hasAnyChange = true;
            return {
              ...item,
              status: serverData.status,
              videoUrl: item.videoUrl?.startsWith('blob:') ? item.videoUrl : serverData.videoUrl,
              error: serverData.error,
              tokenLabel: serverData.tokenLabel
            };
          });
          
          // If nothing changed, return SAME array reference
          return hasAnyChange ? newArray : prev;
        });
      }
    }
  }, [queueStatus?.results, currentBatchIds, isGenerating]);

  // Auto-clear localStorage when batch is complete and not processing
  useEffect(() => {
    if (generationProgress.length > 0 && !isGenerating && !queueStatus?.isProcessing) {
      // Check if all videos are finished (completed or failed)
      const pendingOrProcessing = generationProgress.filter(
        p => p.status === 'pending' || p.status === 'processing'
      );
      
      if (pendingOrProcessing.length === 0) {
        // All done - clear localStorage so old results don't show on next visit
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(BATCH_IDS_KEY);
      }
    }
  }, [generationProgress, isGenerating, queueStatus?.isProcessing]);

  // Only save to localStorage while actively generating (not after completion)
  useEffect(() => {
    if (generationProgress.length > 0 && isGenerating) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(generationProgress));
    }
  }, [generationProgress, isGenerating]);

  const parsePrompts = (): { promptList: string[]; shortPrompts: string[] } => {
    const allLines = prompts.split('\n').map(p => p.trim());
    return {
      promptList: allLines.filter(p => p.length >= 10),
      shortPrompts: allLines.filter(p => p.length > 0 && p.length < 10)
    };
  };

  const handleGenerate = async () => {
    const { promptList, shortPrompts } = parsePrompts();
    
    if (promptList.length === 0) {
      toast({ title: "No valid prompts", description: "Each prompt must be at least 10 characters long", variant: "destructive" });
      return;
    }
    
    // Warn about short prompts that will be skipped
    if (shortPrompts.length > 0) {
      toast({ 
        title: "Some prompts skipped", 
        description: `${shortPrompts.length} prompts were too short (min 10 chars). Processing ${promptList.length} valid prompts.`,
        variant: "default"
      });
    }

    if (promptList.length > remainingVideos) {
      toast({ title: "Limit exceeded", description: `You can only generate ${remainingVideos} more videos today`, variant: "destructive" });
      return;
    }

    // CRITICAL: Clear old state before starting new batch to prevent confusion
    setGenerationProgress([]);
    setCurrentBatchIds([]);
    fetchedDirectUrlsRef.current.clear();
    downloadedVideosRef.current.clear();
    blobUrlsRef.current.forEach(url => {
      try { URL.revokeObjectURL(url); } catch (e) {}
    });
    blobUrlsRef.current.clear();
    initialLoadDoneRef.current = false; // Reset for new batch
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(BATCH_IDS_KEY);
    
    setIsGenerating(true);
    
    // CRITICAL: Create stable keys ONCE at batch start - these NEVER change during the batch
    // This prevents React from remounting video elements when server IDs arrive
    const batchTimestamp = Date.now();
    stableKeysRef.current = promptList.map((_, idx) => `stable-${batchTimestamp}-${idx}`);
    
    // Generate progress items with stable clientIds matching stableKeysRef
    setGenerationProgress(promptList.map((prompt, idx) => ({ 
      prompt, 
      status: "pending",
      clientId: stableKeysRef.current[idx] // Use the stable key
    })));

    try {
      const response = await fetch("/api/bulk-generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ prompts: promptList, aspectRatio }),
      });

      if (!response.ok) {
        const data = await response.json();
        // Parse detailed error message from server
        let errorMessage = data.error || 'Failed to start bulk generation';
        
        if (data.details && Array.isArray(data.details)) {
          const detailMessages = data.details.map((d: any) => d.message).join('. ');
          errorMessage = detailMessages || errorMessage;
        } else if (data.message) {
          errorMessage = data.message;
        }
        
        throw new Error(errorMessage);
      }

      // Get video IDs from response and store them
      const responseData = await response.json();
      const batchVideoIds = responseData.videoIds || [];
      setCurrentBatchIds(batchVideoIds);
      localStorage.setItem(BATCH_IDS_KEY, JSON.stringify(batchVideoIds));
      
      // CRITICAL: Link server IDs to initial items by index (prompt order = server ID order)
      setGenerationProgress(prev => prev.map((item, idx) => ({
        ...item,
        id: batchVideoIds[idx] || item.id // Add server ID to each item
      })));

      // Clear any existing timeout before starting new one
      if (pollingIntervalRef.current) {
        clearTimeout(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }

      let pollRetryCount = 0;
      const MAX_POLL_RETRIES = 10;
      let pollCount = 0;
      
      // ADAPTIVE POLLING: Start fast, then slow down to reduce requests
      // First 3 polls: 5s, then 10s, after 10 polls: 15s
      const getAdaptiveInterval = (count: number) => {
        if (count < 3) return 5000;   // Quick initial updates
        if (count < 10) return 10000; // Slow down after initial burst
        return 15000;                  // Long-term polling
      };

      const pollStatus = async () => {
        try {
          const statusResponse = await fetch("/api/bulk-generate/status", { credentials: "include" });
          
          // Check if response is JSON (not HTML error page)
          const contentType = statusResponse.headers.get('content-type');
          if (!contentType || !contentType.includes('application/json')) {
            pollRetryCount++;
            if (pollRetryCount >= MAX_POLL_RETRIES) {
              console.error("Max poll retries reached, stopping polling");
              pollingIntervalRef.current = null;
              setIsGenerating(false);
              return;
            }
            // Schedule next poll with current interval
            pollingIntervalRef.current = setTimeout(pollStatus, getAdaptiveInterval(pollCount));
            return;
          }
          
          const statusData = await statusResponse.json();
          pollRetryCount = 0; // Reset retry count on success
          pollCount++;

          if (statusData.results && batchVideoIds.length > 0) {
            // Build a map of server results by ID for quick lookup
            const serverResultsMap = new Map<string, VideoGenerationStatus>();
            statusData.results.forEach((r: VideoGenerationStatus) => {
              if (r.id) serverResultsMap.set(r.id, r);
            });
            
            // CRITICAL: Update items IN-PLACE - never replace the array, only update changed fields
            setGenerationProgress(prev => prev.map(item => {
              if (!item.id) return item; // No server ID yet, keep as-is
              
              const serverData = serverResultsMap.get(item.id);
              if (!serverData) return item; // Not in this poll response, keep existing data
              
              // Only update if something changed (status, videoUrl, error, tokenLabel)
              const hasChanged = 
                item.status !== serverData.status ||
                (!item.videoUrl && serverData.videoUrl) ||
                item.error !== serverData.error ||
                item.tokenLabel !== serverData.tokenLabel;
              
              if (!hasChanged) return item; // No change, return same reference
              
              // Update only changed fields, PRESERVE clientId and existing blobUrl
              return {
                ...item,
                status: serverData.status,
                videoUrl: item.videoUrl?.startsWith('blob:') ? item.videoUrl : serverData.videoUrl,
                error: serverData.error,
                tokenLabel: serverData.tokenLabel
                // clientId is preserved from item, never overwritten
              };
            }));
          }

          if (!statusData.isProcessing && statusData.queueLength === 0) {
            pollingIntervalRef.current = null;
            setIsGenerating(false);
            toast({ title: "Bulk generation complete", description: "All videos have been processed." });
            return; // Stop polling
          }
          
          // Schedule next poll with adaptive interval
          pollingIntervalRef.current = setTimeout(pollStatus, getAdaptiveInterval(pollCount));
        } catch (error) {
          // Silent retry - just increment counter
          pollRetryCount++;
          if (pollRetryCount >= MAX_POLL_RETRIES) {
            console.error("Max poll retries reached");
            pollingIntervalRef.current = null;
            setIsGenerating(false);
            return;
          }
          // Schedule retry
          pollingIntervalRef.current = setTimeout(pollStatus, getAdaptiveInterval(pollCount));
        }
      };
      
      // Start first poll after 5 seconds
      pollingIntervalRef.current = setTimeout(pollStatus, 5000);

      toast({ title: "Bulk generation started", description: `Processing ${promptList.length} videos...` });
    } catch (error) {
      setIsGenerating(false);
      toast({ title: "Generation failed", description: error instanceof Error ? error.message : "An error occurred", variant: "destructive" });
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed": return <CheckCircle size={16} color="#10b981" />;
      case "failed": return <XCircle size={16} color="#ef4444" />;
      case "processing": return <CircularProgress size={14} />;
      default: return <Clock size={16} color="#6b7280" />;
    }
  };

  const handleClearResults = () => {
    setGenerationProgress([]);
    setCurrentBatchIds([]);
    downloadedVideosRef.current.clear();
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(BATCH_IDS_KEY);
    toast({ title: "Results cleared", description: "Generation progress has been cleared." });
  };

  // Download single video
  const downloadVideo = async (videoUrl: string, filename: string): Promise<boolean> => {
    try {
      // Handle direct: URLs (from direct_to_user mode) - use server download endpoint
      if (videoUrl.startsWith('direct:')) {
        const downloadUrl = `/api/videos/download-single?videoUrl=${encodeURIComponent(videoUrl)}&filename=${encodeURIComponent(filename)}`;
        const response = await fetch(downloadUrl, { credentials: 'include' });
        
        if (!response.ok) {
          console.error('Direct video download failed:', response.status);
          return false;
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        return true;
      }
      
      // Handle data: URLs (base64) - direct browser download
      if (videoUrl.startsWith('data:')) {
        const a = document.createElement('a');
        a.href = videoUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        return true;
      }
      
      // Try fetch first (handles most cases)
      const response = await fetch(videoUrl, { 
        mode: 'cors',
        credentials: 'omit' // Don't send credentials to external URLs
      });
      
      if (!response.ok) {
        console.error('Video fetch failed:', response.status, '- trying direct link');
        // Fallback: use direct link approach
        return downloadViaDirect(videoUrl, filename);
      }
      
      const blob = await response.blob();
      
      // Verify blob size - video should be more than 1KB
      if (blob.size < 1000) {
        console.error('Video blob too small:', blob.size, '- trying direct link');
        return downloadViaDirect(videoUrl, filename);
      }
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      return true;
    } catch (error) {
      console.error('Fetch download failed:', error, '- trying direct link');
      return downloadViaDirect(videoUrl, filename);
    }
  };

  // Fallback download using direct link (opens in new tab for user to save)
  const downloadViaDirect = (videoUrl: string, filename: string): boolean => {
    try {
      // For Cloudinary URLs, add fl_attachment to force download
      let downloadUrl = videoUrl;
      if (videoUrl.includes('cloudinary.com')) {
        downloadUrl = videoUrl.replace('/upload/', `/upload/fl_attachment:${filename}/`);
      }
      
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = filename;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      return true;
    } catch (error) {
      console.error('Direct download failed:', error);
      return false;
    }
  };

  // Download all completed videos as ZIP
  const handleDownloadAllZip = async () => {
    const completedVideos = generationProgress.filter(v => v.status === 'completed' && v.videoUrl);
    if (completedVideos.length === 0) {
      toast({ title: "No videos to download", description: "No completed videos available.", variant: "destructive" });
      return;
    }

    setIsDownloadingZip(true);
    try {
      const zip = new JSZip();
      
      for (let i = 0; i < completedVideos.length; i++) {
        const video = completedVideos[i];
        if (video.videoUrl) {
          const response = await fetch(video.videoUrl);
          const blob = await response.blob();
          const sceneNum = String(generationProgress.indexOf(video) + 1).padStart(2, '0');
          zip.file(`Scene_${sceneNum}.mp4`, blob);
        }
      }

      const zipBlob = await zip.generateAsync({ type: 'blob' });
      const url = window.URL.createObjectURL(zipBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `bulk_videos_${Date.now()}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      toast({ title: "Download complete", description: `${completedVideos.length} videos downloaded as ZIP.` });
    } catch (error) {
      console.error('Failed to create ZIP:', error);
      toast({ title: "Download failed", description: "Failed to create ZIP file.", variant: "destructive" });
    } finally {
      setIsDownloadingZip(false);
    }
  };

  // Download videos in batches (parallel) for faster downloads
  const handleDownloadSequential = async () => {
    const completedVideos = generationProgress
      .map((v, i) => ({ ...v, originalIndex: i }))
      .filter(v => v.status === 'completed' && v.videoUrl);
    
    if (completedVideos.length === 0) {
      toast({ title: "No videos to download", description: "No completed videos available.", variant: "destructive" });
      return;
    }

    setIsDownloadingSequential(true);
    toast({ title: "Batch download started", description: `Downloading ${completedVideos.length} videos...` });

    let successCount = 0;
    let failCount = 0;

    try {
      const BATCH_SIZE = 4;
      for (let i = 0; i < completedVideos.length; i += BATCH_SIZE) {
        const batch = completedVideos.slice(i, i + BATCH_SIZE);
        const results = await Promise.all(
          batch.map(async (video) => {
            const sceneNum = String(video.originalIndex + 1).padStart(2, '0');
            const success = await downloadVideo(video.videoUrl!, `Scene_${sceneNum}.mp4`);
            return success;
          })
        );
        successCount += results.filter(r => r).length;
        failCount += results.filter(r => !r).length;
        // Small delay between batches
        if (i + BATCH_SIZE < completedVideos.length) {
          await new Promise(resolve => setTimeout(resolve, 200));
        }
      }
      
      if (failCount > 0) {
        toast({ 
          title: "Download partially complete", 
          description: `${successCount} downloaded, ${failCount} failed (videos may have expired).`,
          variant: "destructive"
        });
      } else {
        toast({ title: "Download complete", description: `All ${successCount} videos downloaded.` });
      }
    } catch (error) {
      console.error('Failed to download videos:', error);
      toast({ title: "Download failed", description: "Some videos failed to download.", variant: "destructive" });
    } finally {
      setIsDownloadingSequential(false);
    }
  };

  // Regenerate all failed videos
  const handleRegenerateAllFailed = async () => {
    const failedVideos = generationProgress.filter(p => p.status === "failed");
    if (failedVideos.length === 0) {
      toast({ title: "No failed videos", description: "There are no failed videos to regenerate", variant: "destructive" });
      return;
    }

    const failedPrompts = failedVideos.map(v => v.prompt);
    
    if (failedPrompts.length > remainingVideos) {
      toast({ 
        title: "Limit exceeded", 
        description: `You need ${failedPrompts.length} videos but only have ${remainingVideos} remaining today`, 
        variant: "destructive" 
      });
      return;
    }

    setIsRegeneratingFailed(true);
    
    // Keep completed videos, reset failed ones to pending
    const updatedProgress = generationProgress.map(p => 
      p.status === 'failed' ? { ...p, status: 'pending' as const, error: undefined, videoUrl: undefined } : p
    );
    setGenerationProgress(updatedProgress);
    setIsGenerating(true);

    try {
      const response = await fetch("/api/bulk-generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ prompts: failedPrompts, aspectRatio }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to start regeneration');
      }

      const responseData = await response.json();
      const newVideoIds = responseData.videoIds || [];
      
      // Merge new video IDs with existing batch
      const existingCompletedIds = currentBatchIds.filter((id, idx) => 
        generationProgress[idx]?.status === 'completed'
      );
      const mergedIds = [...existingCompletedIds, ...newVideoIds];
      setCurrentBatchIds(mergedIds);
      localStorage.setItem(BATCH_IDS_KEY, JSON.stringify(mergedIds));

      // Start polling for status updates
      if (pollingIntervalRef.current) {
        clearTimeout(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }

      let pollRetryCount = 0;
      const MAX_POLL_RETRIES = 10;
      let pollCount = 0;
      
      // ADAPTIVE POLLING: Start fast, then slow down
      const getAdaptiveInterval = (count: number) => {
        if (count < 3) return 5000;
        if (count < 10) return 10000;
        return 15000;
      };

      const pollStatus = async () => {
        try {
          const statusResponse = await fetch("/api/bulk-generate/status", { credentials: "include" });
          const contentType = statusResponse.headers.get('content-type');
          if (!contentType || !contentType.includes('application/json')) {
            pollRetryCount++;
            if (pollRetryCount >= MAX_POLL_RETRIES) {
              pollingIntervalRef.current = null;
              setIsGenerating(false);
              setIsRegeneratingFailed(false);
              return;
            }
            pollingIntervalRef.current = setTimeout(pollStatus, getAdaptiveInterval(pollCount));
            return;
          }
          
          const statusData = await statusResponse.json();
          pollRetryCount = 0;
          pollCount++;

          if (statusData.results) {
            // Update progress with new results, keeping completed videos in place
            setGenerationProgress(prev => {
              const updated = [...prev];
              statusData.results.forEach((result: VideoGenerationStatus) => {
                const existingIdx = updated.findIndex(p => p.id === result.id);
                if (existingIdx !== -1) {
                  updated[existingIdx] = result;
                } else {
                  // Find first pending item without ID and update it
                  const pendingIdx = updated.findIndex(p => p.status === 'pending' && !p.id && p.prompt === result.prompt);
                  if (pendingIdx !== -1) {
                    updated[pendingIdx] = result;
                  }
                }
              });
              return updated;
            });
          }

          if (!statusData.isProcessing && statusData.queueLength === 0) {
            pollingIntervalRef.current = null;
            setIsGenerating(false);
            setIsRegeneratingFailed(false);
            toast({ title: "Regeneration complete", description: `${failedPrompts.length} videos reprocessed.` });
            return;
          }
          
          pollingIntervalRef.current = setTimeout(pollStatus, getAdaptiveInterval(pollCount));
        } catch {
          pollRetryCount++;
          if (pollRetryCount >= MAX_POLL_RETRIES) {
            pollingIntervalRef.current = null;
            setIsGenerating(false);
            setIsRegeneratingFailed(false);
            return;
          }
          pollingIntervalRef.current = setTimeout(pollStatus, getAdaptiveInterval(pollCount));
        }
      };
      
      pollingIntervalRef.current = setTimeout(pollStatus, 5000);

      toast({ title: "Regenerating failed videos", description: `Retrying ${failedPrompts.length} videos...` });
    } catch (error) {
      setIsGenerating(false);
      setIsRegeneratingFailed(false);
      // Restore failed status
      setGenerationProgress(generationProgress);
      toast({ title: "Regeneration failed", description: error instanceof Error ? error.message : "An error occurred", variant: "destructive" });
    }
  };

  // Check if all videos are processed (completed or failed)
  const allVideosProcessed = generationProgress.length > 0 && 
    generationProgress.every(v => v.status === 'completed' || v.status === 'failed');

  // Auto-download videos as they complete
  useEffect(() => {
    if (!autoDownload) return;

    generationProgress.forEach((video, index) => {
      if (video.status === 'completed' && video.videoUrl && video.id && !downloadedVideosRef.current.has(video.id)) {
        downloadedVideosRef.current.add(video.id);
        const sceneNum = String(index + 1).padStart(2, '0');
        downloadVideo(video.videoUrl, `Scene_${sceneNum}.mp4`);
      }
    });
  }, [generationProgress, autoDownload]);

  const completedCount = generationProgress.filter(p => p.status === "completed").length;
  const failedCount = generationProgress.filter(p => p.status === "failed").length;
  const progress = generationProgress.length > 0 ? ((completedCount + failedCount) / generationProgress.length) * 100 : 0;

  if (sessionLoading) {
    return (
      <UserPanelLayout>
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress />
        </Box>
      </UserPanelLayout>
    );
  }

  if (!toolAccess.allowed) {
    return (
      <UserPanelLayout>
        <Box sx={{ maxWidth: 600, mx: 'auto', textAlign: 'center', py: 8 }}>
          <Box sx={{ p: 3, borderRadius: 3, bgcolor: alpha('#f59e0b', 0.1), display: 'inline-flex', mb: 3 }}>
            <Lock size={48} color="#f59e0b" />
          </Box>
          <Typography variant="h5" sx={{ fontWeight: 700, color: '#1a1a2e', mb: 2 }}>
            Upgrade Required
          </Typography>
          <Typography variant="body1" sx={{ color: '#64748b', mb: 4 }}>
            Bulk video generation is available on Scale, Empire, and Enterprise plans.
          </Typography>
          <Button
            variant="contained"
            onClick={() => setLocation('/pricing')}
            startIcon={<Crown size={20} />}
            sx={{ borderRadius: 2, textTransform: 'none', fontWeight: 600, background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}
          >
            View Plans
          </Button>
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
            {/* Header */}
          <Box sx={{ mb: 1 }}>
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
                <Layers size={26} color="white" />
              </Box>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                  Bulk Video Generator
                </Typography>
                <Typography variant="body2" sx={{ color: '#64748b' }}>
                  Generate multiple videos at once
                </Typography>
              </Box>
              <Chip 
                label={remainingVideos === Infinity ? 'Unlimited videos' : `${remainingVideos} videos remaining`} 
                size="small" 
                sx={{ ml: 'auto', bgcolor: alpha('#374151', 0.1), color: '#374151' }} 
              />
            </Stack>
          </Box>

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
                <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#374151', mb: 1 }}>
                  Enter Prompts (one per line)
                  <Chip label="Required" size="small" sx={{ ml: 1, height: 20, fontSize: '0.7rem', bgcolor: alpha('#374151', 0.1), color: '#374151' }} />
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  rows={6}
                  placeholder="A cat playing piano in a jazz club\nA rocket launching into space with aurora borealis\nA chef cooking in a futuristic kitchen..."
                  value={prompts}
                  onChange={(e) => setPrompts(e.target.value)}
                  disabled={isGenerating}
                  data-testid="input-prompts"
                  sx={{ 
                    '& .MuiOutlinedInput-root': { 
                      borderRadius: 2, 
                      fontFamily: 'monospace',
                      '& fieldset': { borderColor: '#e5e7eb' },
                      '&:hover fieldset': { borderColor: '#374151' },
                      '&.Mui-focused fieldset': { borderColor: '#374151' }
                    } 
                  }}
                />
                <Typography variant="caption" sx={{ color: '#9ca3af', mt: 0.5, display: 'block' }}>
                  {(() => {
                    const validPrompts = prompts.split('\n').filter(p => p.trim().length >= 10).length;
                    const emptyLines = prompts.split('\n').filter(p => p.trim().length === 0).length;
                    const shortPrompts = prompts.split('\n').filter(p => p.trim().length > 0 && p.trim().length < 10).length;
                    
                    if (shortPrompts > 0 || emptyLines > 0) {
                      return `${validPrompts} valid prompts (${shortPrompts > 0 ? `${shortPrompts} too short, ` : ''}${emptyLines > 0 ? `${emptyLines} empty` : ''})`.replace(/, \)$/, ')');
                    }
                    return `${validPrompts} prompts entered`;
                  })()}
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
                  disabled={isGenerating} 
                  size="small"
                  sx={{ gap: 0.5 }}
                >
                  <ToggleButton 
                    value="landscape" 
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

              {/* Generate Button - Full Width like VEO Generator */}
              <Button
                variant="contained"
                size="large"
                onClick={() => setShowGenerateWarning(true)}
                disabled={isGenerating || !prompts.trim()}
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
                {isGenerating ? 'Generating...' : 'Generate Videos'}
              </Button>
              
              {isGenerating && (
                <Button
                  variant="outlined"
                  onClick={() => stopMutation.mutate()}
                  startIcon={<StopCircle size={18} />}
                  sx={{ 
                    width: '100%',
                    borderRadius: 2, 
                    textTransform: 'none', 
                    fontWeight: 600, 
                    borderColor: '#ef4444', 
                    color: '#ef4444', 
                    '&:hover': { borderColor: '#dc2626', bgcolor: alpha('#ef4444', 0.05) } 
                  }}
                >
                  Stop Generation
                </Button>
              )}
            </Stack>
          </Paper>

          {generationProgress.length > 0 && (
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
                <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={1}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
                    Generation Progress
                  </Typography>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Chip label={`${completedCount} completed`} size="small" sx={{ bgcolor: alpha('#10b981', 0.1), color: '#10b981' }} />
                    <Chip label={`${failedCount} failed`} size="small" sx={{ bgcolor: alpha('#ef4444', 0.1), color: '#ef4444' }} />
                    {!isGenerating && (
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={handleClearResults}
                        data-testid="button-clear-results"
                        sx={{
                          ml: 1,
                          borderRadius: 1.5,
                          textTransform: 'none',
                          fontSize: '0.75rem',
                          py: 0.3,
                          px: 1.5,
                          borderColor: '#9ca3af',
                          color: '#6b7280',
                          '&:hover': { borderColor: '#6b7280', bgcolor: alpha('#6b7280', 0.05) }
                        }}
                      >
                        Clear
                      </Button>
                    )}
                  </Stack>
                </Stack>

                <Box>
                  <LinearProgress 
                    variant="determinate" 
                    value={progress} 
                    sx={{ 
                      height: 8, 
                      borderRadius: 4, 
                      bgcolor: alpha('#374151', 0.1), 
                      '& .MuiLinearProgress-bar': { borderRadius: 4, bgcolor: '#374151' } 
                    }} 
                  />
                  <Typography variant="caption" sx={{ color: '#64748b', mt: 0.5, display: 'block' }}>
                    {Math.round(progress)}% complete
                  </Typography>
                </Box>

                {/* Generated Videos Grid */}
                <Box>
                  <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={2} sx={{ mb: 2 }}>
                    <Stack direction="row" alignItems="center" spacing={2} flexWrap="wrap" gap={1}>
                      <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
                        Generated Videos
                      </Typography>
                      <Chip 
                        label={`${completedCount} completed`} 
                        size="small" 
                        sx={{ bgcolor: alpha('#22c55e', 0.1), color: '#22c55e', fontWeight: 600 }} 
                      />
                      {generationProgress.filter(v => v.status === 'processing' || v.status === 'pending').length > 0 && (
                        <Chip 
                          label={`${generationProgress.filter(v => v.status === 'processing' || v.status === 'pending').length} processing`} 
                          size="small" 
                          sx={{ bgcolor: alpha('#f59e0b', 0.1), color: '#f59e0b', fontWeight: 600 }} 
                        />
                      )}
                    </Stack>
                    
                    <Stack direction="row" alignItems="center" spacing={2} flexWrap="wrap" gap={1}>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={autoDownload}
                            onChange={(e) => setAutoDownload(e.target.checked)}
                            size="small"
                            data-testid="switch-auto-download"
                          />
                        }
                        label={
                          <Typography variant="body2" sx={{ color: '#64748b', fontSize: '0.8rem' }}>
                            Auto Download
                          </Typography>
                        }
                        sx={{ mr: 1 }}
                      />
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={handleDownloadAllZip}
                        disabled={completedCount === 0 || isDownloadingZip}
                        startIcon={isDownloadingZip ? <CircularProgress size={14} /> : <Archive size={14} />}
                        data-testid="button-download-zip"
                        sx={{
                          borderRadius: 1.5,
                          textTransform: 'none',
                          fontSize: '0.75rem',
                          py: 0.5,
                          px: 1.5,
                          borderColor: '#374151',
                          color: '#374151',
                          '&:hover': { borderColor: '#1f2937', bgcolor: alpha('#374151', 0.05) },
                          '&.Mui-disabled': { borderColor: '#d1d5db', color: '#9ca3af' }
                        }}
                      >
                        {isDownloadingZip ? 'Creating ZIP...' : 'Download All as ZIP'}
                      </Button>
                      <Tooltip 
                        title={!allVideosProcessed ? "Wait for all videos to be processed" : ""} 
                        arrow
                      >
                        <span>
                          <Button
                            size="small"
                            variant="outlined"
                            onClick={handleDownloadSequential}
                            disabled={!allVideosProcessed || completedCount === 0 || isDownloadingSequential}
                            startIcon={isDownloadingSequential ? <CircularProgress size={14} /> : <ListOrdered size={14} />}
                            data-testid="button-download-sequential"
                            sx={{
                              borderRadius: 1.5,
                              textTransform: 'none',
                              fontSize: '0.75rem',
                              py: 0.5,
                              px: 1.5,
                              borderColor: '#374151',
                              color: '#374151',
                              '&:hover': { borderColor: '#1f2937', bgcolor: alpha('#374151', 0.05) },
                              '&.Mui-disabled': { borderColor: '#d1d5db', color: '#9ca3af' }
                            }}
                          >
                            {isDownloadingSequential ? 'Downloading...' : 'Download Sequential'}
                          </Button>
                        </span>
                      </Tooltip>
                      {failedCount > 0 && (
                        <Tooltip 
                          title={isGenerating ? "Wait for current generation to complete" : `Retry ${failedCount} failed video${failedCount > 1 ? 's' : ''}`} 
                          arrow
                        >
                          <span>
                            <Button
                              size="small"
                              variant="outlined"
                              onClick={handleRegenerateAllFailed}
                              disabled={isGenerating || isRegeneratingFailed}
                              startIcon={isRegeneratingFailed ? <CircularProgress size={14} /> : <RefreshCw size={14} />}
                              data-testid="button-regenerate-failed"
                              sx={{
                                borderRadius: 1.5,
                                textTransform: 'none',
                                fontSize: '0.75rem',
                                py: 0.5,
                                px: 1.5,
                                borderColor: '#ef4444',
                                color: '#ef4444',
                                '&:hover': { borderColor: '#dc2626', bgcolor: alpha('#ef4444', 0.05) },
                                '&.Mui-disabled': { borderColor: '#d1d5db', color: '#9ca3af' }
                              }}
                            >
                              {isRegeneratingFailed ? 'Retrying...' : `Retry ${failedCount} Failed`}
                            </Button>
                          </span>
                        </Tooltip>
                      )}
                    </Stack>
                  </Stack>

                  {/* Download in progress message */}
                  {isDownloadingSequential && (
                    <Box sx={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: 1.5, 
                      p: 1.5, 
                      mb: 2, 
                      bgcolor: alpha('#3b82f6', 0.1), 
                      borderRadius: 2,
                      border: '1px solid',
                      borderColor: alpha('#3b82f6', 0.2)
                    }}>
                      <CircularProgress size={18} sx={{ color: '#3b82f6' }} />
                      <Typography variant="body2" sx={{ color: '#3b82f6', fontWeight: 500 }}>
                        Downloading {completedCount} videos in batches... Please wait.
                      </Typography>
                    </Box>
                  )}

                  <Grid container spacing={2}>
                    {generationProgress.map((item, index) => (
                      <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={stableKeysRef.current[index] || item.clientId || `scene-${index}`}>
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
                            {/* Scene Badge */}
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
                                fontWeight: 600,
                                fontSize: '0.7rem'
                              }}
                            />

                            {/* Done Badge for Completed */}
                            {item.status === 'completed' && item.videoUrl && (
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

                            {/* Processing State */}
                            {(item.status === 'processing' || item.status === 'pending') ? (
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
                              </Box>
                            ) : item.status === 'failed' ? (
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
                                  {(() => {
                                    // Safely convert error to string (handles object, string, null, undefined)
                                    const errorStr = typeof item.error === 'string' 
                                      ? item.error 
                                      : (item.error ? JSON.stringify(item.error) : 'Failed');
                                    return errorStr.length > 60 ? errorStr.substring(0, 60) + '...' : errorStr;
                                  })()}
                                </Typography>
                              </Box>
                            ) : item.videoUrl ? (
                              /* Completed State with Video */
                              <VideoPreview videoUrl={item.videoUrl} height={getCardHeight()} />
                            ) : (
                              /* Completed but waiting for videoUrl */
                              <Box sx={{ 
                                height: getCardHeight(), 
                                background: 'linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%)',
                                display: 'flex', 
                                flexDirection: 'column', 
                                alignItems: 'center', 
                                justifyContent: 'center', 
                                gap: 1.5
                              }}>
                                <Box sx={{ 
                                  width: 56, 
                                  height: 56, 
                                  borderRadius: '50%', 
                                  bgcolor: 'white', 
                                  display: 'flex', 
                                  alignItems: 'center', 
                                  justifyContent: 'center',
                                  boxShadow: '0 4px 12px rgba(59,130,246,0.3)'
                                }}>
                                  <CircularProgress size={28} sx={{ color: '#3b82f6' }} />
                                </Box>
                                <Typography variant="caption" sx={{ color: '#1e40af', fontWeight: 600 }}>
                                  Loading video...
                                </Typography>
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
                                {item.prompt}
                              </Typography>
                              
                              {item.status === 'completed' && item.videoUrl && (
                                <Stack direction="row" spacing={1}>
                                  <Button
                                    size="small"
                                    variant="outlined"
                                    startIcon={<Download size={14} />}
                                    onClick={() => {
                                      const filename = `scene-${index + 1}.mp4`;
                                      const downloadUrl = `/api/videos/download-single?videoUrl=${encodeURIComponent(item.videoUrl!)}&filename=${encodeURIComponent(filename)}`;
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
                                  >
                                    Download
                                  </Button>
                                  <IconButton
                                    size="small"
                                    onClick={() => window.open(item.videoUrl, '_blank')}
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
                                </Stack>
                              )}
                            </Stack>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              </Stack>
            </Paper>
          )}
          </Stack>
        </Box>
      </Box>

      {/* Leave Warning Dialog */}
      <Dialog
        open={showLeaveWarning}
        onClose={cancelLeave}
        PaperProps={{
          sx: {
            borderRadius: 3,
            maxWidth: 420,
            p: 1
          }
        }}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5, pb: 1 }}>
          <Box sx={{ p: 1, borderRadius: 2, bgcolor: alpha('#f59e0b', 0.1), display: 'flex' }}>
            <AlertTriangle size={24} color="#f59e0b" />
          </Box>
          <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
            Download Your Videos
          </Typography>
        </DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ color: '#64748b', lineHeight: 1.6 }}>
            Please download your videos before leaving this page or refreshing. 
            Your generated videos are stored temporarily and will not be saved in your history.
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button
            onClick={cancelLeave}
            variant="outlined"
            sx={{
              borderRadius: 2,
              textTransform: 'none',
              fontWeight: 600,
              borderColor: '#e5e7eb',
              color: '#64748b',
              '&:hover': { borderColor: '#9ca3af', bgcolor: alpha('#9ca3af', 0.05) }
            }}
          >
            Stay on Page
          </Button>
          <Button
            onClick={confirmLeave}
            variant="contained"
            sx={{
              borderRadius: 2,
              textTransform: 'none',
              fontWeight: 600,
              bgcolor: '#ef4444',
              '&:hover': { bgcolor: '#dc2626' }
            }}
          >
            Leave Anyway
          </Button>
        </DialogActions>
      </Dialog>

      {/* Generate Warning Dialog */}
      <Dialog
        open={showGenerateWarning}
        onClose={() => setShowGenerateWarning(false)}
        PaperProps={{
          sx: {
            borderRadius: 3,
            maxWidth: 480,
            p: 1
          }
        }}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5, pb: 1 }}>
          <Box sx={{ p: 1, borderRadius: 2, bgcolor: alpha('#3b82f6', 0.1), display: 'flex' }}>
            <AlertTriangle size={24} color="#3b82f6" />
          </Box>
          <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
            Video Storage Information
          </Typography>
        </DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ color: '#374151', lineHeight: 1.7, mb: 2 }}>
            Before you start generating, please keep in mind:
          </DialogContentText>
          <Box component="ul" sx={{ pl: 2.5, color: '#64748b', lineHeight: 1.8, m: 0 }}>
            <li style={{ marginBottom: '8px' }}>
              <strong style={{ color: '#374151' }}>3-Hour Storage</strong> — Your videos will be securely stored for 3 hours and remain accessible in your history during this period.
            </li>
            <li style={{ marginBottom: '8px' }}>
              <strong style={{ color: '#374151' }}>Download Recommended</strong> — For permanent access, we recommend downloading your videos before the storage period expires.
            </li>
            <li>
              <strong style={{ color: '#374151' }}>Auto Download Available</strong> — Enable "Auto Download" to automatically save each video as soon as it completes.
            </li>
          </Box>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button
            onClick={() => setShowGenerateWarning(false)}
            variant="outlined"
            sx={{
              borderRadius: 2,
              textTransform: 'none',
              fontWeight: 600,
              borderColor: '#e5e7eb',
              color: '#64748b',
              '&:hover': { borderColor: '#9ca3af', bgcolor: alpha('#9ca3af', 0.05) }
            }}
          >
            Cancel
          </Button>
          <Button
            onClick={() => {
              setShowGenerateWarning(false);
              handleGenerate();
            }}
            variant="contained"
            startIcon={<Sparkles size={16} />}
            sx={{
              borderRadius: 2,
              textTransform: 'none',
              fontWeight: 600,
              bgcolor: '#374151',
              '&:hover': { bgcolor: '#1f2937' }
            }}
          >
            I Understand, Generate Videos
          </Button>
        </DialogActions>
      </Dialog>
    </UserPanelLayout>
  );
}
