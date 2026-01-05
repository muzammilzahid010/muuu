import { useEffect, useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient } from "@/lib/queryClient";
import { useLocation } from "wouter";
import { useToast } from "@/hooks/use-toast";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import type { VideoHistory } from "@shared/schema";

import { alpha, styled } from '@mui/material/styles';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import LinearProgress from '@mui/material/LinearProgress';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import IconButton from '@mui/material/IconButton';
import Checkbox from '@mui/material/Checkbox';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Tooltip from '@mui/material/Tooltip';
import Divider from '@mui/material/Divider';
import InputBase from '@mui/material/InputBase';
import TextField from '@mui/material/TextField';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Pagination from '@mui/material/Pagination';
import { 
  History as HistoryIcon, 
  Download, 
  Trash2, 
  RefreshCw, 
  Play, 
  CheckCircle, 
  XCircle, 
  Clock, 
  Video,
  ExternalLink,
  Search,
  Film,
  Sparkles,
  Calendar,
  User,
  Filter,
  LayoutGrid,
  List,
  Eye,
  Link2,
  RotateCcw,
  ChevronDown
} from "lucide-react";

// Number of videos per page for pagination
const VIDEOS_PER_PAGE = 24;

// Helper function to detect Google Drive URLs and extract file ID
function getGoogleDriveFileId(url: string): string | null {
  if (!url) return null;
  
  // Pattern 1: drive.google.com/file/d/{fileId}/...
  const driveFileMatch = url.match(/drive\.google\.com\/file\/d\/([^\/\?]+)/);
  if (driveFileMatch) return driveFileMatch[1];
  
  // Pattern 2: drive.usercontent.google.com/download?id={fileId}
  const driveDownloadMatch = url.match(/drive\.usercontent\.google\.com\/download\?id=([^&]+)/);
  if (driveDownloadMatch) return driveDownloadMatch[1];
  
  // Pattern 3: docs.google.com/uc?id={fileId}
  const docsMatch = url.match(/docs\.google\.com\/uc\?.*id=([^&]+)/);
  if (docsMatch) return docsMatch[1];
  
  return null;
}

// Check if URL is from Google Drive
function isGoogleDriveUrl(url: string): boolean {
  return getGoogleDriveFileId(url) !== null;
}

// Get the view URL for Google Drive
function getGoogleDrivePreviewUrl(url: string): string {
  const fileId = getGoogleDriveFileId(url);
  if (fileId) {
    return `https://drive.google.com/file/d/${fileId}/view`;
  }
  return url;
}

interface TabPanelProps {
  children?: React.ReactNode;
  value: number;
  index: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

export default function History() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [selectedVideos, setSelectedVideos] = useState<Set<string>>(new Set());
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [videoToDelete, setVideoToDelete] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [previewVideo, setPreviewVideo] = useState<VideoHistory | null>(null);
  
  // New states for additional features
  const [regeneratingVideoId, setRegeneratingVideoId] = useState<string | null>(null);
  const [isRegeneratingAll, setIsRegeneratingAll] = useState(false);
  const [downloadMenuAnchor, setDownloadMenuAnchor] = useState<null | HTMLElement>(null);
  const [clearAllDialogOpen, setClearAllDialogOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  
  // Lazy loading state - videos load one by one automatically
  const [loadedVideoIndices, setLoadedVideoIndices] = useState<Set<number>>(new Set());

  const { data: session, isLoading: sessionLoading } = useQuery<{
    authenticated: boolean;
    user?: { id: string; username: string; isAdmin: boolean };
  }>({
    queryKey: ["/api/session"],
  });

  const { data, isLoading, refetch, error } = useQuery<{ videos: VideoHistory[]; limit: number; offset: number }>({
    queryKey: ["/api/video-history"],
    queryFn: async () => {
      const response = await fetch("/api/video-history", { credentials: "include" });
      if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("Session expired");
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    },
    enabled: session?.authenticated === true,
    staleTime: 5000,
    refetchOnWindowFocus: true,
  });

  const deleteMutation = useMutation({
    mutationFn: async (videoId: string) => {
      const response = await fetch(`/api/video-history/${videoId}`, { method: "DELETE", credentials: "include" });
      if (!response.ok) throw new Error("Failed to delete");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/video-history"] });
      toast({ title: "Video deleted", description: "Video has been removed from history." });
      setDeleteDialogOpen(false);
      setVideoToDelete(null);
    },
    onError: (error: any) => {
      toast({ title: "Delete failed", description: error.message, variant: "destructive" });
    },
  });

  // Regenerate single video mutation
  const regenerateMutation = useMutation({
    mutationFn: async (videoId: string) => {
      const response = await fetch("/api/regenerate-video", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ videoId }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Failed to regenerate");
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/video-history"] });
      toast({ title: "Regeneration started", description: "Video is being regenerated. Check back soon!" });
      setRegeneratingVideoId(null);
    },
    onError: (error: any) => {
      toast({ title: "Regeneration failed", description: error.message, variant: "destructive" });
      setRegeneratingVideoId(null);
    },
  });

  // Regenerate all failed videos mutation
  const regenerateAllFailedMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/regenerate-all-failed", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Failed to regenerate");
      }
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/video-history"] });
      toast({ 
        title: "Regeneration started", 
        description: `${data.count || 0} failed videos are being regenerated.`
      });
      setIsRegeneratingAll(false);
    },
    onError: (error: any) => {
      toast({ title: "Regeneration failed", description: error.message, variant: "destructive" });
      setIsRegeneratingAll(false);
    },
  });

  // Clear all history mutation
  const clearAllMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/video-history", {
        method: "DELETE",
        credentials: "include",
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Failed to clear history");
      }
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/video-history"] });
      toast({ 
        title: "History cleared", 
        description: `${data.deletedRecords || 0} videos removed from history.`
      });
      setClearAllDialogOpen(false);
    },
    onError: (error: any) => {
      toast({ title: "Clear failed", description: error.message, variant: "destructive" });
      setClearAllDialogOpen(false);
    },
  });

  const videos = data?.videos || [];
  
  const filteredVideos = useMemo(() => {
    let result = videos;
    
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      result = result.filter(v => 
        v.prompt.toLowerCase().includes(query) || 
        (v.title && v.title.toLowerCase().includes(query))
      );
    }
    
    switch (activeTab) {
      case 1:
        return result.filter(v => v.status === 'completed');
      case 2:
        return result.filter(v => v.status === 'pending' || v.status === 'queued');
      case 3:
        return result.filter(v => v.status === 'failed');
      default:
        return result;
    }
  }, [videos, activeTab, searchQuery]);

  // Pagination calculations
  const totalPages = Math.ceil(filteredVideos.length / VIDEOS_PER_PAGE);
  const paginatedVideos = useMemo(() => {
    const startIndex = (currentPage - 1) * VIDEOS_PER_PAGE;
    const endIndex = startIndex + VIDEOS_PER_PAGE;
    return filteredVideos.slice(startIndex, endIndex);
  }, [filteredVideos, currentPage]);

  // Reset page when tab or search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [activeTab, searchQuery]);

  // Lazy load videos one by one (300ms delay between each)
  useEffect(() => {
    // Reset loaded indices when page changes
    setLoadedVideoIndices(new Set());
    
    if (paginatedVideos.length === 0) return;
    
    let cancelled = false;
    let currentIndex = 0;
    
    const loadNextVideo = () => {
      if (cancelled || currentIndex >= paginatedVideos.length) return;
      
      const indexToLoad = currentIndex;
      setLoadedVideoIndices(prev => {
        const newSet = new Set(prev);
        newSet.add(indexToLoad);
        return newSet;
      });
      currentIndex++;
      
      if (currentIndex < paginatedVideos.length) {
        setTimeout(loadNextVideo, 300);
      }
    };
    
    // Start loading first video immediately
    loadNextVideo();
    
    return () => {
      cancelled = true;
    };
  }, [paginatedVideos.length, currentPage, activeTab, searchQuery]);

  const completedVideos = videos.filter(v => v.status === 'completed');
  const pendingVideos = videos.filter(v => v.status === 'pending' || v.status === 'queued');
  const failedVideos = videos.filter(v => v.status === 'failed');

  const handleSelectVideo = (videoId: string) => {
    const newSelected = new Set(selectedVideos);
    if (newSelected.has(videoId)) {
      newSelected.delete(videoId);
    } else {
      newSelected.add(videoId);
    }
    setSelectedVideos(newSelected);
  };

  const handleSelectAll = () => {
    const currentVideos = filteredVideos.filter(v => v.status === 'completed');
    if (selectedVideos.size === currentVideos.length) {
      setSelectedVideos(new Set());
    } else {
      setSelectedVideos(new Set(currentVideos.map(v => v.id)));
    }
  };

  const handleDeleteClick = (videoId: string) => {
    setVideoToDelete(videoId);
    setDeleteDialogOpen(true);
  };

  const handleConfirmDelete = () => {
    if (videoToDelete) {
      deleteMutation.mutate(videoToDelete);
    }
  };

  const handleDownload = (video: VideoHistory) => {
    if (!video.videoUrl) return;
    const filename = `video-${video.id}.mp4`;
    const downloadUrl = `/api/videos/download-single?videoUrl=${encodeURIComponent(video.videoUrl)}&filename=${encodeURIComponent(filename)}`;
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Regenerate single video handler
  const handleRegenerate = (videoId: string) => {
    setRegeneratingVideoId(videoId);
    regenerateMutation.mutate(videoId);
  };

  // Regenerate all failed videos handler
  const handleRegenerateAllFailed = () => {
    if (failedVideos.length === 0) {
      toast({ title: "No failed videos", description: "There are no failed videos to regenerate." });
      return;
    }
    setIsRegeneratingAll(true);
    regenerateAllFailedMutation.mutate();
  };

  // Download all video links as text file
  const handleDownloadAllLinks = () => {
    const videosWithUrls = completedVideos.filter(v => v.videoUrl);
    if (videosWithUrls.length === 0) {
      toast({ title: "No videos", description: "No completed videos to download links from." });
      return;
    }
    
    const links = videosWithUrls.map((v) => v.videoUrl).join('\n');
    const blob = new Blob([links], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `video-links-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast({ title: "Links downloaded", description: `${videosWithUrls.length} video links saved to file.` });
    setDownloadMenuAnchor(null);
  };

  if (sessionLoading || isLoading) {
    return (
      <UserPanelLayout>
        <Box sx={{ 
          display: 'flex', 
          flexDirection: 'column',
          justifyContent: 'center', 
          alignItems: 'center', 
          minHeight: 500,
          gap: 3
        }}>
          <Box sx={{
            width: 80,
            height: 80,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 8px 32px rgba(99, 102, 241, 0.3)'
          }}>
            <Film size={36} color="white" />
          </Box>
          <Stack alignItems="center" spacing={1}>
            <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
              Loading Your Videos
            </Typography>
            <Typography variant="body2" sx={{ color: '#64748b' }}>
              Please wait while we fetch your history...
            </Typography>
          </Stack>
          <LinearProgress sx={{ width: 200, borderRadius: 2 }} />
        </Box>
      </UserPanelLayout>
    );
  }

  return (
    <UserPanelLayout>
      <Box sx={{ maxWidth: 1400, mx: 'auto' }}>
        <Stack spacing={4}>
          {/* Hero Header */}
          <Paper
            elevation={0}
            sx={{
              p: 4,
              borderRadius: 4,
              background: 'linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4c1d95 100%)',
              position: 'relative',
              overflow: 'hidden'
            }}
          >
            {/* Background Pattern */}
            <Box sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              opacity: 0.1,
              backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.4'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
            }} />
            
            <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" alignItems={{ xs: 'flex-start', md: 'center' }} spacing={3} sx={{ position: 'relative', zIndex: 1 }}>
              <Stack direction="row" alignItems="center" spacing={3}>
                <Box
                  sx={{
                    width: 72,
                    height: 72,
                    borderRadius: 3,
                    background: 'rgba(255,255,255,0.15)',
                    backdropFilter: 'blur(10px)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '1px solid rgba(255,255,255,0.2)'
                  }}
                >
                  <Film size={36} color="white" />
                </Box>
                <Box>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: 'white', letterSpacing: -0.5 }}>
                    Video Library
                  </Typography>
                  <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.7)', mt: 0.5 }}>
                    Your AI-generated masterpieces
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(251, 191, 36, 0.9)', mt: 0.5, display: 'block' }}>
                    Note: History resets daily at 12:00 AM midnight
                  </Typography>
                </Box>
              </Stack>

              {/* Stats Cards */}
              <Stack direction="row" spacing={2}>
                <Box sx={{ 
                  px: 3, 
                  py: 2, 
                  borderRadius: 2, 
                  bgcolor: 'rgba(255,255,255,0.1)', 
                  backdropFilter: 'blur(10px)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  minWidth: 100,
                  textAlign: 'center'
                }}>
                  <Typography variant="h4" sx={{ fontWeight: 700, color: 'white' }}>
                    {videos.length}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', textTransform: 'uppercase', letterSpacing: 1 }}>
                    Total
                  </Typography>
                </Box>
                <Box sx={{ 
                  px: 3, 
                  py: 2, 
                  borderRadius: 2, 
                  bgcolor: 'rgba(34, 197, 94, 0.2)', 
                  backdropFilter: 'blur(10px)',
                  border: '1px solid rgba(34, 197, 94, 0.3)',
                  minWidth: 100,
                  textAlign: 'center'
                }}>
                  <Typography variant="h4" sx={{ fontWeight: 700, color: '#4ade80' }}>
                    {completedVideos.length}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', textTransform: 'uppercase', letterSpacing: 1 }}>
                    Ready
                  </Typography>
                </Box>
                {pendingVideos.length > 0 && (
                  <Box sx={{ 
                    px: 3, 
                    py: 2, 
                    borderRadius: 2, 
                    bgcolor: 'rgba(251, 191, 36, 0.2)', 
                    backdropFilter: 'blur(10px)',
                    border: '1px solid rgba(251, 191, 36, 0.3)',
                    minWidth: 100,
                    textAlign: 'center'
                  }}>
                    <Typography variant="h4" sx={{ fontWeight: 700, color: '#fbbf24' }}>
                      {pendingVideos.length}
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', textTransform: 'uppercase', letterSpacing: 1 }}>
                      Processing
                    </Typography>
                  </Box>
                )}
              </Stack>
            </Stack>
          </Paper>

          {/* Toolbar */}
          <Paper
            elevation={0}
            sx={{
              p: 2,
              borderRadius: 3,
              border: '1px solid rgba(0,0,0,0.08)',
              bgcolor: 'white'
            }}
          >
            <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ xs: 'stretch', sm: 'center' }} spacing={2}>
              {/* Search */}
              <Box sx={{ 
                display: 'flex', 
                alignItems: 'center', 
                bgcolor: '#f8fafc', 
                borderRadius: 2, 
                px: 2,
                py: 1,
                flex: 1,
                maxWidth: { sm: 400 }
              }}>
                <Search size={18} color="#64748b" />
                <InputBase
                  placeholder="Search videos by prompt or character..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  sx={{ ml: 1.5, flex: 1, fontSize: '0.9rem' }}
                  data-testid="input-search-videos"
                />
              </Box>

              {/* Actions */}
              <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ gap: 1 }}>
                {/* Regenerate All Failed Button */}
                {failedVideos.length > 0 && (
                  <Button
                    variant="contained"
                    size="small"
                    onClick={handleRegenerateAllFailed}
                    disabled={isRegeneratingAll || regenerateAllFailedMutation.isPending}
                    startIcon={isRegeneratingAll ? <CircularProgress size={14} color="inherit" /> : <RotateCcw size={16} />}
                    sx={{ 
                      borderRadius: 2, 
                      textTransform: 'none',
                      bgcolor: '#ef4444',
                      '&:hover': { bgcolor: '#dc2626' }
                    }}
                    data-testid="button-regenerate-all-failed"
                  >
                    Regenerate All Failed ({failedVideos.length})
                  </Button>
                )}

                {/* Download Options Menu */}
                {completedVideos.length > 0 && (
                  <>
                    <Button
                      variant="contained"
                      size="small"
                      onClick={(e) => setDownloadMenuAnchor(e.currentTarget)}
                      endIcon={<ChevronDown size={16} />}
                      startIcon={<Download size={16} />}
                      sx={{ 
                        borderRadius: 2, 
                        textTransform: 'none',
                        bgcolor: '#22c55e',
                        '&:hover': { bgcolor: '#16a34a' }
                      }}
                      data-testid="button-download-options"
                    >
                      Download Options
                    </Button>
                    <Menu
                      anchorEl={downloadMenuAnchor}
                      open={Boolean(downloadMenuAnchor)}
                      onClose={() => setDownloadMenuAnchor(null)}
                      PaperProps={{
                        sx: { borderRadius: 2, minWidth: 220, mt: 1 }
                      }}
                    >
                      <MenuItem onClick={handleDownloadAllLinks} data-testid="menu-download-links">
                        <ListItemIcon><Link2 size={18} /></ListItemIcon>
                        <ListItemText primary="Download All Links" secondary="Save as text file" />
                      </MenuItem>
                    </Menu>
                  </>
                )}

                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => refetch()}
                  startIcon={<RefreshCw size={16} />}
                  sx={{ 
                    borderRadius: 2, 
                    textTransform: 'none',
                    borderColor: '#e5e7eb',
                    color: '#374151'
                  }}
                  data-testid="button-refresh-history"
                >
                  Refresh
                </Button>

                {/* Clear All History Button */}
                {videos.length > 0 && (
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => setClearAllDialogOpen(true)}
                    disabled={clearAllMutation.isPending}
                    startIcon={clearAllMutation.isPending ? <CircularProgress size={14} color="inherit" /> : <Trash2 size={16} />}
                    sx={{ 
                      borderRadius: 2, 
                      textTransform: 'none',
                      borderColor: '#fca5a5',
                      color: '#dc2626',
                      '&:hover': { 
                        borderColor: '#ef4444',
                        bgcolor: 'rgba(239, 68, 68, 0.04)'
                      }
                    }}
                    data-testid="button-clear-all-history"
                  >
                    Clear All
                  </Button>
                )}
              </Stack>
            </Stack>
          </Paper>

          {/* Tabs & Content */}
          <Paper
            elevation={0}
            sx={{
              borderRadius: 3,
              border: '1px solid rgba(0,0,0,0.08)',
              bgcolor: 'white',
              overflow: 'hidden'
            }}
          >
            <Box sx={{ borderBottom: '1px solid rgba(0,0,0,0.08)', px: 2 }}>
              <Tabs 
                value={activeTab} 
                onChange={(_, v) => setActiveTab(v)}
                sx={{
                  '& .MuiTab-root': {
                    textTransform: 'none',
                    fontWeight: 600,
                    minHeight: 56,
                    fontSize: '0.9rem'
                  },
                  '& .Mui-selected': {
                    color: '#6366f1'
                  },
                  '& .MuiTabs-indicator': {
                    bgcolor: '#6366f1',
                    height: 3,
                    borderRadius: '3px 3px 0 0'
                  }
                }}
              >
                <Tab 
                  label={
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <LayoutGrid size={16} />
                      <span>All Videos</span>
                      <Chip label={videos.length} size="small" sx={{ height: 20, fontSize: '0.7rem' }} />
                    </Stack>
                  } 
                />
                <Tab 
                  label={
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <CheckCircle size={16} />
                      <span>Completed</span>
                      <Chip label={completedVideos.length} size="small" sx={{ height: 20, fontSize: '0.7rem', bgcolor: alpha('#22c55e', 0.1), color: '#22c55e' }} />
                    </Stack>
                  } 
                />
                <Tab 
                  label={
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <Clock size={16} />
                      <span>Processing</span>
                      {pendingVideos.length > 0 && (
                        <Chip label={pendingVideos.length} size="small" sx={{ height: 20, fontSize: '0.7rem', bgcolor: alpha('#f59e0b', 0.1), color: '#f59e0b' }} />
                      )}
                    </Stack>
                  } 
                />
                <Tab 
                  label={
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <XCircle size={16} />
                      <span>Failed</span>
                      {failedVideos.length > 0 && (
                        <Chip label={failedVideos.length} size="small" sx={{ height: 20, fontSize: '0.7rem', bgcolor: alpha('#ef4444', 0.1), color: '#ef4444' }} />
                      )}
                    </Stack>
                  } 
                />
              </Tabs>
            </Box>

            <Box sx={{ p: 3 }}>
              {error && (
                <Alert severity="error" sx={{ borderRadius: 2, mb: 3 }}>
                  Failed to load video history. Please try again.
                </Alert>
              )}

              {filteredVideos.length === 0 ? (
                <Box sx={{ 
                  py: 8, 
                  textAlign: 'center',
                  background: 'linear-gradient(180deg, #fafafa 0%, #ffffff 100%)',
                  borderRadius: 3
                }}>
                  <Box sx={{
                    width: 100,
                    height: 100,
                    borderRadius: '50%',
                    background: 'linear-gradient(135deg, #e0e7ff 0%, #c7d2fe 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    mx: 'auto',
                    mb: 3
                  }}>
                    <Video size={48} color="#6366f1" />
                  </Box>
                  <Typography variant="h5" sx={{ fontWeight: 700, color: '#1a1a2e', mb: 1 }}>
                    {searchQuery ? 'No matching videos' : 'No videos yet'}
                  </Typography>
                  <Typography variant="body1" sx={{ color: '#64748b', mb: 4, maxWidth: 400, mx: 'auto' }}>
                    {searchQuery 
                      ? 'Try adjusting your search query to find what you\'re looking for.'
                      : 'Start creating amazing AI videos and they will appear here in your library.'
                    }
                  </Typography>
                  {!searchQuery && (
                    <Button 
                      variant="contained" 
                      size="large"
                      onClick={() => setLocation('/veo-generator')} 
                      startIcon={<Sparkles size={20} />}
                      sx={{ 
                        borderRadius: 3, 
                        textTransform: 'none', 
                        px: 4,
                        py: 1.5,
                        fontWeight: 600,
                        background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
                        boxShadow: '0 4px 20px rgba(99, 102, 241, 0.3)',
                        '&:hover': { 
                          background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
                          boxShadow: '0 6px 24px rgba(99, 102, 241, 0.4)'
                        } 
                      }}
                    >
                      Create Your First Video
                    </Button>
                  )}
                </Box>
              ) : (
                <>
                  {/* Select All for completed videos */}
                  {filteredVideos.some(v => v.status === 'completed') && (
                    <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
                      <Typography variant="body2" sx={{ color: '#64748b' }}>
                        Showing {paginatedVideos.length} of {filteredVideos.length} video{filteredVideos.length !== 1 ? 's' : ''}
                        {totalPages > 1 && ` (Page ${currentPage} of ${totalPages})`}
                      </Typography>
                      <Button 
                        size="small" 
                        onClick={handleSelectAll} 
                        sx={{ textTransform: 'none', color: '#6366f1' }}
                      >
                        {selectedVideos.size === filteredVideos.filter(v => v.status === 'completed').length ? 'Deselect All' : 'Select All'}
                      </Button>
                    </Stack>
                  )}

                  <Grid container spacing={3}>
                    {paginatedVideos.map((video, index) => (
                      <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={video.id}>
                        <Card 
                          elevation={0} 
                          sx={{ 
                            border: '1px solid rgba(0,0,0,0.08)', 
                            borderRadius: 3,
                            overflow: 'hidden',
                            transition: 'all 0.3s ease',
                            position: 'relative',
                            '&:hover': { 
                              borderColor: '#6366f1',
                              boxShadow: '0 12px 40px rgba(99, 102, 241, 0.15)',
                              transform: 'translateY(-4px)'
                            }
                          }}
                        >
                          {/* Video Preview Area */}
                          <Box sx={{ position: 'relative' }}>
                            {/* Selection Checkbox */}
                            {video.status === 'completed' && (
                              <Box sx={{ position: 'absolute', top: 8, left: 8, zIndex: 10 }}>
                                <Checkbox
                                  checked={selectedVideos.has(video.id)}
                                  onChange={() => handleSelectVideo(video.id)}
                                  size="small"
                                  sx={{ 
                                    bgcolor: 'rgba(255,255,255,0.9)',
                                    borderRadius: 1,
                                    p: 0.5,
                                    '&.Mui-checked': { color: '#6366f1' },
                                    '&:hover': { bgcolor: 'white' }
                                  }}
                                />
                              </Box>
                            )}

                            {/* Scene Number Badge - oldest video = Scene 01, newest video = highest scene */}
                            <Chip
                              label={`Scene ${String(filteredVideos.length - ((currentPage - 1) * VIDEOS_PER_PAGE + index)).padStart(2, '0')}`}
                              size="small"
                              sx={{
                                position: 'absolute',
                                top: 8,
                                right: 8,
                                zIndex: 10,
                                bgcolor: 'rgba(0,0,0,0.75)',
                                color: 'white',
                                fontWeight: 700,
                                fontSize: '0.65rem',
                                backdropFilter: 'blur(4px)'
                              }}
                            />

                            {/* Video Content */}
                            {video.status === 'completed' && video.videoUrl ? (
                              <Box 
                                sx={{ 
                                  height: 180, 
                                  bgcolor: '#0a0a0a',
                                  position: 'relative',
                                  cursor: 'pointer',
                                  '&:hover .play-overlay': {
                                    opacity: 1
                                  }
                                }}
                                onClick={() => setPreviewVideo(video)}
                              >
                                {isGoogleDriveUrl(video.videoUrl!) ? (
                                  <Box sx={{ 
                                    width: '100%', 
                                    height: '100%', 
                                    display: 'flex',
                                    flexDirection: 'column',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)'
                                  }}>
                                    <Video size={40} style={{ color: '#8b5cf6', marginBottom: 8 }} />
                                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.65rem' }}>
                                      Google Drive
                                    </Typography>
                                  </Box>
                                ) : loadedVideoIndices.has(index) ? (
                                  <video 
                                    src={video.videoUrl} 
                                    style={{ 
                                      width: '100%', 
                                      height: '100%', 
                                      objectFit: 'cover' 
                                    }}
                                    controls
                                    preload="metadata"
                                  />
                                ) : (
                                  <Box sx={{ 
                                    width: '100%', 
                                    height: '100%', 
                                    display: 'flex',
                                    flexDirection: 'column',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)'
                                  }}>
                                    <CircularProgress size={24} sx={{ color: '#8b5cf6', mb: 1 }} />
                                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.6rem' }}>
                                      Loading...
                                    </Typography>
                                  </Box>
                                )}
                                {/* Status Badge */}
                                <Chip
                                  icon={<CheckCircle size={12} />}
                                  label="Ready"
                                  size="small"
                                  sx={{
                                    position: 'absolute',
                                    bottom: 8,
                                    left: 8,
                                    bgcolor: alpha('#22c55e', 0.95),
                                    color: 'white',
                                    fontWeight: 600,
                                    fontSize: '0.65rem',
                                    '& .MuiChip-icon': { color: 'white' }
                                  }}
                                />
                              </Box>
                            ) : video.status === 'failed' ? (
                              <Box sx={{ 
                                height: 180, 
                                background: 'linear-gradient(135deg, #fee2e2 0%, #fecaca 100%)',
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
                                  boxShadow: '0 4px 12px rgba(239,68,68,0.2)'
                                }}>
                                  <XCircle size={28} color="#dc2626" />
                                </Box>
                                <Typography variant="caption" sx={{ color: '#991b1b', fontWeight: 600 }}>
                                  Generation Failed
                                </Typography>
                              </Box>
                            ) : (
                              <Box sx={{ 
                                height: 180, 
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
                                <Typography variant="caption" sx={{ color: '#92400e', fontWeight: 600 }}>
                                  Generating...
                                </Typography>
                              </Box>
                            )}
                          </Box>

                          {/* Card Content */}
                          <CardContent sx={{ p: 2.5 }}>
                            <Stack spacing={2}>
                              {/* Prompt */}
                              <Typography 
                                variant="body2" 
                                sx={{ 
                                  color: '#1a1a2e',
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

                              {/* Metadata */}
                              <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={1}>
                                {video.title && (
                                  <Chip
                                    icon={<Film size={12} />}
                                    label={video.title}
                                    size="small"
                                    sx={{ 
                                      bgcolor: alpha('#8b5cf6', 0.1), 
                                      color: '#7c3aed',
                                      fontWeight: 500,
                                      '& .MuiChip-icon': { color: '#8b5cf6' }
                                    }}
                                  />
                                )}
                                {video.createdAt && (
                                  <Typography variant="caption" sx={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                    <Calendar size={12} />
                                    {formatDate(video.createdAt)}
                                  </Typography>
                                )}
                              </Stack>

                              {/* Action Buttons */}
                              {video.status === 'completed' && video.videoUrl && (
                                <Stack direction="row" spacing={1}>
                                  <Button
                                    size="small"
                                    variant="contained"
                                    startIcon={<Download size={14} />}
                                    onClick={() => handleDownload(video)}
                                    sx={{
                                      flex: 1,
                                      borderRadius: 2,
                                      textTransform: 'none',
                                      fontWeight: 600,
                                      fontSize: '0.75rem',
                                      bgcolor: '#374151',
                                      '&:hover': { bgcolor: '#1f2937' }
                                    }}
                                    data-testid={`button-download-video-${video.id}`}
                                  >
                                    Download
                                  </Button>
                                  <Tooltip title="Preview">
                                    <IconButton
                                      size="small"
                                      onClick={() => setPreviewVideo(video)}
                                      sx={{
                                        border: '1px solid #e5e7eb',
                                        borderRadius: 2,
                                        '&:hover': { borderColor: '#6366f1', bgcolor: alpha('#6366f1', 0.05) }
                                      }}
                                    >
                                      <Eye size={16} />
                                    </IconButton>
                                  </Tooltip>
                                  <Tooltip title="Delete">
                                    <IconButton
                                      size="small"
                                      onClick={() => handleDeleteClick(video.id)}
                                      sx={{
                                        border: '1px solid #fecaca',
                                        borderRadius: 2,
                                        color: '#ef4444',
                                        '&:hover': { borderColor: '#ef4444', bgcolor: alpha('#ef4444', 0.05) }
                                      }}
                                      data-testid={`button-delete-video-${video.id}`}
                                    >
                                      <Trash2 size={16} />
                                    </IconButton>
                                  </Tooltip>
                                </Stack>
                              )}

                              {video.status === 'failed' && (
                                <Stack direction="row" spacing={1}>
                                  <Button
                                    size="small"
                                    variant="contained"
                                    startIcon={regeneratingVideoId === video.id ? <CircularProgress size={14} color="inherit" /> : <RotateCcw size={14} />}
                                    onClick={() => handleRegenerate(video.id)}
                                    disabled={regeneratingVideoId === video.id || regenerateMutation.isPending}
                                    sx={{
                                      flex: 1,
                                      borderRadius: 2,
                                      textTransform: 'none',
                                      fontWeight: 600,
                                      fontSize: '0.75rem',
                                      bgcolor: '#6366f1',
                                      '&:hover': { bgcolor: '#4f46e5' }
                                    }}
                                    data-testid={`button-regenerate-video-${video.id}`}
                                  >
                                    {regeneratingVideoId === video.id ? 'Starting...' : 'Regenerate'}
                                  </Button>
                                  <Tooltip title="Delete">
                                    <IconButton
                                      size="small"
                                      onClick={() => handleDeleteClick(video.id)}
                                      sx={{
                                        border: '1px solid #fecaca',
                                        borderRadius: 2,
                                        color: '#ef4444',
                                        '&:hover': { borderColor: '#ef4444', bgcolor: alpha('#ef4444', 0.05) }
                                      }}
                                      data-testid={`button-delete-failed-video-${video.id}`}
                                    >
                                      <Trash2 size={16} />
                                    </IconButton>
                                  </Tooltip>
                                </Stack>
                              )}
                            </Stack>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>

                  {/* Pagination Controls */}
                  {totalPages > 1 && (
                    <Stack direction="row" justifyContent="center" sx={{ mt: 4, mb: 2 }}>
                      <Pagination
                        count={totalPages}
                        page={currentPage}
                        onChange={(_, page) => {
                          setCurrentPage(page);
                          // Scroll to top of video grid
                          window.scrollTo({ top: 400, behavior: 'smooth' });
                        }}
                        color="primary"
                        size="large"
                        showFirstButton
                        showLastButton
                        sx={{
                          '& .MuiPaginationItem-root': {
                            borderRadius: 2,
                            fontWeight: 600,
                          },
                          '& .MuiPaginationItem-root.Mui-selected': {
                            bgcolor: '#6366f1',
                            color: 'white',
                            '&:hover': { bgcolor: '#4f46e5' }
                          }
                        }}
                        data-testid="pagination-videos"
                      />
                    </Stack>
                  )}
                </>
              )}
            </Box>
          </Paper>
        </Stack>
      </Box>

      {/* Delete Confirmation Dialog */}
      <Dialog 
        open={deleteDialogOpen} 
        onClose={() => setDeleteDialogOpen(false)}
        PaperProps={{
          sx: { borderRadius: 3, maxWidth: 400 }
        }}
      >
        <DialogTitle sx={{ pb: 1 }}>
          <Stack direction="row" alignItems="center" spacing={2}>
            <Box sx={{ 
              width: 48, 
              height: 48, 
              borderRadius: 2, 
              bgcolor: alpha('#ef4444', 0.1),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Trash2 size={24} color="#ef4444" />
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>Delete Video?</Typography>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <Typography sx={{ color: '#64748b' }}>
            This action cannot be undone. The video will be permanently removed from your library.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 3, pt: 1 }}>
          <Button 
            onClick={() => setDeleteDialogOpen(false)} 
            sx={{ textTransform: 'none', borderRadius: 2, px: 3 }}
          >
            Cancel
          </Button>
          <Button 
            onClick={handleConfirmDelete} 
            variant="contained"
            disabled={deleteMutation.isPending}
            sx={{ 
              textTransform: 'none', 
              borderRadius: 2, 
              px: 3,
              bgcolor: '#ef4444',
              '&:hover': { bgcolor: '#dc2626' }
            }}
          >
            {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Video Preview Dialog */}
      <Dialog 
        open={!!previewVideo} 
        onClose={() => setPreviewVideo(null)}
        maxWidth="md"
        fullWidth
        PaperProps={{
          sx: { borderRadius: 3, bgcolor: '#0a0a0a', overflow: 'hidden' }
        }}
      >
        {previewVideo && (
          <>
            <Box sx={{ position: 'relative' }}>
              {previewVideo.videoUrl && isGoogleDriveUrl(previewVideo.videoUrl) ? (
                <Box sx={{ 
                  width: '100%', 
                  height: '50vh',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
                  gap: 2
                }}>
                  <Video size={64} style={{ color: '#8b5cf6' }} />
                  <Typography variant="h6" sx={{ color: 'white', fontWeight: 600 }}>
                    Google Drive Video
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)', textAlign: 'center', px: 4 }}>
                    Click "Open in Google Drive" to watch this video
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#fbbf24', textAlign: 'center', px: 4, mt: 1 }}>
                    Note: Preview will be available 10 minutes after video generation
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)', textAlign: 'center', px: 4 }}>
                    (This appears when Cloudinary upload fails and video is stored on Google Drive)
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<ExternalLink size={18} />}
                    onClick={() => window.open(getGoogleDrivePreviewUrl(previewVideo.videoUrl!), '_blank')}
                    sx={{
                      mt: 2,
                      borderRadius: 2,
                      textTransform: 'none',
                      fontWeight: 600,
                      bgcolor: '#8b5cf6',
                      '&:hover': { bgcolor: '#7c3aed' }
                    }}
                  >
                    Open in Google Drive
                  </Button>
                </Box>
              ) : (
                <video 
                  src={previewVideo.videoUrl || ''} 
                  controls 
                  autoPlay
                  style={{ 
                    width: '100%', 
                    maxHeight: '70vh',
                    display: 'block'
                  }}
                />
              )}
              <IconButton
                onClick={() => setPreviewVideo(null)}
                sx={{
                  position: 'absolute',
                  top: 16,
                  right: 16,
                  bgcolor: 'rgba(0,0,0,0.6)',
                  color: 'white',
                  '&:hover': { bgcolor: 'rgba(0,0,0,0.8)' }
                }}
              >
                <XCircle size={24} />
              </IconButton>
            </Box>
            <Box sx={{ p: 3, bgcolor: 'white' }}>
              <Stack spacing={2}>
                <Typography variant="body1" sx={{ fontWeight: 500, color: '#1a1a2e' }}>
                  {previewVideo.prompt}
                </Typography>
                <Stack direction="row" spacing={2}>
                  <Button
                    variant="contained"
                    startIcon={<Download size={16} />}
                    onClick={() => {
                      handleDownload(previewVideo);
                      setPreviewVideo(null);
                    }}
                    sx={{
                      borderRadius: 2,
                      textTransform: 'none',
                      fontWeight: 600,
                      bgcolor: '#374151',
                      '&:hover': { bgcolor: '#1f2937' }
                    }}
                  >
                    Download Video
                  </Button>
                  {previewVideo.videoUrl && (
                    <Button
                      variant="outlined"
                      startIcon={<ExternalLink size={16} />}
                      onClick={() => window.open(previewVideo.videoUrl!, '_blank')}
                      sx={{
                        borderRadius: 2,
                        textTransform: 'none',
                        fontWeight: 600,
                        borderColor: '#e5e7eb',
                        color: '#374151'
                      }}
                    >
                      Open in New Tab
                    </Button>
                  )}
                </Stack>
              </Stack>
            </Box>
          </>
        )}
      </Dialog>

      {/* Clear All History Confirmation Dialog */}
      <Dialog 
        open={clearAllDialogOpen} 
        onClose={() => setClearAllDialogOpen(false)}
        PaperProps={{
          sx: { borderRadius: 3, maxWidth: 420 }
        }}
      >
        <DialogTitle sx={{ pb: 1 }}>
          <Stack direction="row" alignItems="center" spacing={2}>
            <Box sx={{ 
              width: 48, 
              height: 48, 
              borderRadius: 2, 
              bgcolor: alpha('#ef4444', 0.1),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Trash2 size={24} color="#ef4444" />
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>Clear All History</Typography>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <Typography sx={{ color: '#64748b', mb: 2 }}>
            Are you sure you want to clear all video history? This will remove all {videos.length} videos from your history.
          </Typography>
          <Typography variant="body2" sx={{ color: '#ef4444', fontWeight: 500 }}>
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 3, pt: 1 }}>
          <Button 
            onClick={() => setClearAllDialogOpen(false)} 
            sx={{ textTransform: 'none', borderRadius: 2, px: 3 }}
          >
            Cancel
          </Button>
          <Button 
            onClick={() => clearAllMutation.mutate()}
            variant="contained"
            disabled={clearAllMutation.isPending}
            startIcon={clearAllMutation.isPending ? <CircularProgress size={14} color="inherit" /> : <Trash2 size={16} />}
            sx={{ 
              textTransform: 'none', 
              borderRadius: 2, 
              px: 3,
              bgcolor: '#ef4444',
              '&:hover': { bgcolor: '#dc2626' }
            }}
            data-testid="button-confirm-clear-all"
          >
            {clearAllMutation.isPending ? 'Clearing...' : 'Clear All History'}
          </Button>
        </DialogActions>
      </Dialog>
    </UserPanelLayout>
  );
}
