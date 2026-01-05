import { useState } from 'react';
import { useLocation, Link } from 'wouter';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '@/lib/queryClient';
import veo3LogoImage from "@assets/353a7b8a-2fec-4a2e-9fd9-76aa79711acb_removalai_preview_1764969657371.png";

import { alpha } from '@mui/material/styles';
import Box from '@mui/material/Box';
import Drawer from '@mui/material/Drawer';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import Divider from '@mui/material/Divider';
import Avatar from '@mui/material/Avatar';
import Stack from '@mui/material/Stack';
import IconButton from '@mui/material/IconButton';
import Button from '@mui/material/Button';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Badge from '@mui/material/Badge';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Popover from '@mui/material/Popover';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import useMediaQuery from '@mui/material/useMediaQuery';
import { useTheme } from '@mui/material/styles';
import {
  Home,
  Video,
  Image,
  FileText,
  Users,
  History,
  Settings,
  Bell,
  ChevronDown,
  Menu as MenuIcon,
  X,
  Sparkles,
  ImagePlay,
  Volume2,
  Layers,
  LogOut,
  Crown,
  PlayCircle,
  Check,
  MessageCircle,
  Film,
  AlertTriangle,
  Mic,
  AudioLines
} from 'lucide-react';

const BULK_STORAGE_KEY = 'bulkGeneratorResults';

const drawerWidth = 260;

const menuItems = [
  { id: 'home', title: 'Dashboard', icon: Home, path: '/' }
];

const playgroundItems = [
  { id: 'veo3-generator', title: 'VEO3.1 Video Generator', icon: Video, path: '/veo-generator' },
  { id: 'bulk-generator', title: 'Bulk Video Generator', icon: Layers, path: '/bulk-generator' },
  { id: 'text-to-image', title: 'Text to Image', icon: Image, path: '/text-to-image' },
  { id: 'script-creator', title: 'Script Creator', icon: FileText, path: '/script-creator' },
  { id: 'character-videos', title: 'Character Videos', icon: Users, path: '/character-consistent' },
  { id: 'community-voices', title: 'Community Voices', icon: Mic, path: '/community-voices' }
];

const productItems = [
  { id: 'history', title: 'History', icon: History, path: '/history' }
];

interface UserPanelLayoutProps {
  children: React.ReactNode;
}

interface UserMessage {
  id: string;
  title: string;
  message: string;
  isRead: boolean;
  createdAt: string;
}

export default function UserPanelLayout({ children }: UserPanelLayoutProps) {
  const theme = useTheme();
  const [location, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const isMobile = useMediaQuery('(max-width: 900px)');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [notificationAnchor, setNotificationAnchor] = useState<null | HTMLElement>(null);
  const [showBulkLeaveWarning, setShowBulkLeaveWarning] = useState(false);
  const [pendingNavPath, setPendingNavPath] = useState<string | null>(null);
  const menuOpen = Boolean(anchorEl);
  const notificationOpen = Boolean(notificationAnchor);

  const { data: session } = useQuery<{
    authenticated: boolean;
    user?: { username: string; isAdmin: boolean; planType?: string };
  }>({
    queryKey: ['/api/session'],
  });

  const { data: messagesData } = useQuery<{ messages: UserMessage[] }>({
    queryKey: ['/api/user/messages'],
    refetchInterval: 30000,
  });

  const markReadMutation = useMutation({
    mutationFn: async (messageId: string) => {
      return apiRequest('POST', `/api/user/messages/${messageId}/read`, {});
    },
    onMutate: async (messageId: string) => {
      await queryClient.cancelQueries({ queryKey: ['/api/user/messages'] });
      const previousData = queryClient.getQueryData<{ messages: UserMessage[] }>(['/api/user/messages']);
      
      if (previousData?.messages) {
        queryClient.setQueryData<{ messages: UserMessage[] }>(['/api/user/messages'], {
          messages: previousData.messages.map(msg => 
            msg.id === messageId ? { ...msg, isRead: true } : msg
          )
        });
      }
      
      return { previousData };
    },
    onError: (err, messageId, context) => {
      if (context?.previousData) {
        queryClient.setQueryData(['/api/user/messages'], context.previousData);
      }
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/user/messages'] });
    },
  });

  const unreadCount = messagesData?.messages?.filter(m => !m.isRead).length || 0;

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleProfileClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleNotificationClick = (event: React.MouseEvent<HTMLElement>) => {
    setNotificationAnchor(event.currentTarget);
  };

  const handleNotificationClose = () => {
    setNotificationAnchor(null);
  };

  const handleMarkAsRead = (messageId: string) => {
    markReadMutation.mutate(messageId);
  };

  const handleLogout = async () => {
    handleMenuClose();
    try {
      await apiRequest('POST', '/api/logout', {});
      queryClient.setQueryData(['/api/session'], { authenticated: false });
      queryClient.invalidateQueries({ queryKey: ['/api/session'] });
      queryClient.clear();
      setLocation('/login');
    } catch (error) {
      console.error('Logout error:', error);
      setLocation('/login');
    }
  };

  // Check if bulk generator has completed videos
  const hasBulkVideosToDownload = () => {
    if (location !== '/bulk-generator') return false;
    try {
      const savedResults = localStorage.getItem(BULK_STORAGE_KEY);
      if (savedResults) {
        const results = JSON.parse(savedResults);
        return results.some((v: any) => v.status === 'completed' && v.videoUrl);
      }
    } catch (e) {
      console.error('Failed to check bulk videos:', e);
    }
    return false;
  };

  const handleNavigation = (path: string) => {
    // Check if leaving bulk generator with completed videos
    if (hasBulkVideosToDownload() && path !== '/bulk-generator') {
      setPendingNavPath(path);
      setShowBulkLeaveWarning(true);
      return;
    }
    
    setLocation(path);
    if (isMobile) {
      setMobileOpen(false);
    }
  };

  const confirmBulkLeave = () => {
    setShowBulkLeaveWarning(false);
    if (pendingNavPath) {
      setLocation(pendingNavPath);
      setPendingNavPath(null);
      if (isMobile) {
        setMobileOpen(false);
      }
    }
  };

  const cancelBulkLeave = () => {
    setShowBulkLeaveWarning(false);
    setPendingNavPath(null);
  };

  const isActive = (path: string) => {
    return location === path;
  };

  const renderMenuItem = (item: { id: string; title: string; icon: any; path: string }) => {
    const active = isActive(item.path);
    const Icon = item.icon;

    return (
      <ListItem key={item.id} disablePadding sx={{ mb: 0.5 }}>
        <ListItemButton
          onClick={() => handleNavigation(item.path)}
          sx={{
            minHeight: 44,
            pl: 2.5,
            pr: 2,
            borderRadius: 2,
            transition: 'all 0.2s ease',
            backgroundColor: active ? alpha('#374151', 0.1) : 'transparent',
            color: active ? '#374151' : '#374151',
            '&:hover': {
              backgroundColor: active ? alpha('#374151', 0.15) : alpha('#374151', 0.05)
            }
          }}
        >
          <ListItemIcon sx={{ color: active ? '#374151' : '#6b7280', minWidth: 40 }}>
            <Icon size={20} />
          </ListItemIcon>
          <ListItemText
            primary={item.title}
            primaryTypographyProps={{
              fontSize: 14,
              fontWeight: active ? 600 : 500
            }}
          />
        </ListItemButton>
      </ListItem>
    );
  };

  const drawerContent = (
    <Box
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        bgcolor: '#ffffff',
        borderRight: '1px solid rgba(0,0,0,0.08)'
      }}
    >
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(0,0,0,0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}
      >
        <img 
          src={veo3LogoImage} 
          alt="VEO3 Logo" 
          style={{ 
            height: 45, 
            width: 'auto'
          }}
        />
        {isMobile && (
          <IconButton onClick={handleDrawerToggle} size="small" sx={{ color: '#6b7280' }}>
            <X size={20} />
          </IconButton>
        )}
      </Box>

      <Box sx={{ flex: 1, overflow: 'auto', p: 1.5 }}>
        <List sx={{ p: 0 }}>
          {menuItems.map((item) => renderMenuItem(item))}
        </List>

        <Divider sx={{ my: 2, borderColor: 'rgba(0,0,0,0.08)' }} />

        <Typography
          variant="caption"
          sx={{
            px: 2.5,
            py: 1,
            color: '#9ca3af',
            fontWeight: 600,
            fontSize: '0.7rem',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}
        >
          Playground
        </Typography>
        <List sx={{ p: 0, mt: 0.5 }}>
          {playgroundItems.map((item) => renderMenuItem(item))}
        </List>

        <Divider sx={{ my: 2, borderColor: 'rgba(0,0,0,0.08)' }} />
        <Typography
          variant="caption"
          sx={{
            px: 2.5,
            py: 1,
            color: '#9ca3af',
            fontWeight: 600,
            fontSize: '0.7rem',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}
        >
          Voice Tools
        </Typography>
        <List sx={{ p: 0, mt: 0.5 }}>
          {renderMenuItem({ id: 'voice-cloning', title: 'Voice Cloning', icon: Mic, path: '/voice-cloning' })}
          {renderMenuItem({ id: 'text-to-speech', title: 'Text to Speech', icon: AudioLines, path: '/text-to-speech' })}
          {renderMenuItem({ id: 'community-voices', title: 'Community Voices', icon: Users, path: '/community-voices' })}
        </List>

        {session?.user?.isAdmin && (
          <>
            <Divider sx={{ my: 2, borderColor: 'rgba(0,0,0,0.08)' }} />
            <Typography
              variant="caption"
              sx={{
                px: 2.5,
                py: 1,
                color: '#9ca3af',
                fontWeight: 600,
                fontSize: '0.7rem',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}
            >
              Admin Tools
            </Typography>
            <List sx={{ p: 0, mt: 0.5 }}>
              {renderMenuItem({ id: 'image-to-video', title: 'Image to Video', icon: ImagePlay, path: '/image-to-video' })}
              {renderMenuItem({ id: 'script-to-frames', title: 'Script to Frames', icon: Film, path: '/script-to-frames' })}
            </List>
          </>
        )}

        <Divider sx={{ my: 2, borderColor: 'rgba(0,0,0,0.08)' }} />
        <List sx={{ p: 0 }}>
          {productItems.map((item) => renderMenuItem(item))}
        </List>
      </Box>

      <Box sx={{ p: 2, borderTop: '1px solid rgba(0,0,0,0.08)' }}>
        <Button
          variant="contained"
          fullWidth
          onClick={() => setLocation('/pricing')}
          startIcon={<Crown size={18} />}
          sx={{
            borderRadius: 2,
            py: 1.5,
            fontWeight: 600,
            textTransform: 'none',
            background: 'linear-gradient(135deg, #374151 0%, #1f2937 100%)',
            boxShadow: '0 4px 12px rgba(55, 65, 81, 0.3)',
            '&:hover': {
              background: 'linear-gradient(135deg, #1f2937 0%, #374151 100%)',
              boxShadow: '0 6px 20px rgba(55, 65, 81, 0.4)'
            }
          }}
        >
          Upgrade Plan
        </Button>

        <Stack
          direction="row"
          spacing={1.5}
          alignItems="center"
          sx={{
            mt: 2,
            p: 1.5,
            borderRadius: 2,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            '&:hover': { bgcolor: alpha('#374151', 0.05) }
          }}
        >
          <Avatar
            sx={{
              width: 32,
              height: 32,
              background: 'linear-gradient(135deg, #374151 0%, #4b5563 100%)',
              fontWeight: 600,
              fontSize: 14
            }}
          >
            {session?.user?.username?.charAt(0).toUpperCase() || 'U'}
          </Avatar>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#1a1a2e', fontSize: '0.875rem' }}>
              {session?.user?.username || 'User'}
            </Typography>
            <Typography variant="caption" sx={{ color: '#9ca3af', fontSize: '0.75rem' }}>
              {session?.user?.isAdmin ? 'Admin' : session?.user?.planType ? session.user.planType.charAt(0).toUpperCase() + session.user.planType.slice(1) : 'Member'}
            </Typography>
          </Box>
          <ChevronDown size={16} color="#9ca3af" />
        </Stack>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', height: '100vh', bgcolor: '#f8fafc', overflow: 'hidden' }}>
      {isMobile ? (
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{ keepMounted: true }}
          sx={{
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
              borderRight: 'none'
            }
          }}
        >
          {drawerContent}
        </Drawer>
      ) : (
        <Drawer
          variant="permanent"
          sx={{
            width: drawerWidth,
            flexShrink: 0,
            '& .MuiDrawer-paper': {
              width: drawerWidth,
              boxSizing: 'border-box',
              borderRight: 'none'
            }
          }}
          open
        >
          {drawerContent}
        </Drawer>
      )}

      <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
        <AppBar
          position="sticky"
          elevation={0}
          sx={{
            bgcolor: alpha('#ffffff', 0.95),
            borderBottom: '1px solid rgba(0,0,0,0.08)',
            backdropFilter: 'blur(20px)'
          }}
        >
          <Toolbar sx={{ minHeight: { xs: 64, md: 72 }, px: { xs: 2, md: 3 }, justifyContent: 'space-between' }}>
            {isMobile && (
              <IconButton onClick={handleDrawerToggle} sx={{ color: '#374151' }}>
                <MenuIcon size={24} />
              </IconButton>
            )}
            
            <Box sx={{ flex: 1 }} />

            <Stack direction="row" spacing={1.5} alignItems="center">
              <IconButton
                onClick={handleNotificationClick}
                sx={{
                  color: '#6b7280',
                  borderRadius: 2,
                  '&:hover': {
                    bgcolor: alpha('#374151', 0.1),
                    color: '#374151'
                  }
                }}
                data-testid="button-notifications"
              >
                <Badge badgeContent={unreadCount} color="error">
                  <Bell size={22} />
                </Badge>
              </IconButton>

              <Stack
                direction="row"
                spacing={1.5}
                alignItems="center"
                onClick={handleProfileClick}
                sx={{
                  px: 1.5,
                  py: 1,
                  borderRadius: 2,
                  cursor: 'pointer',
                  '&:hover': { bgcolor: alpha('#374151', 0.08) }
                }}
              >
                <Avatar
                  sx={{
                    width: 40,
                    height: 40,
                    background: 'linear-gradient(135deg, #374151 0%, #4b5563 100%)',
                    fontWeight: 700
                  }}
                >
                  {session?.user?.username?.charAt(0).toUpperCase() || 'U'}
                </Avatar>
                <Box sx={{ display: { xs: 'none', sm: 'block' } }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#1a1a2e' }}>
                    {session?.user?.username || 'User'}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#9ca3af' }}>
                    {session?.user?.isAdmin ? 'Admin' : session?.user?.planType ? session.user.planType.charAt(0).toUpperCase() + session.user.planType.slice(1) : 'Member'}
                  </Typography>
                </Box>
                <ChevronDown size={18} color="#9ca3af" />
              </Stack>
            </Stack>
          </Toolbar>
        </AppBar>

        <Menu
          anchorEl={anchorEl}
          open={menuOpen}
          onClose={handleMenuClose}
          PaperProps={{
            elevation: 8,
            sx: {
              mt: 1.5,
              minWidth: 200,
              borderRadius: 2,
              border: '1px solid rgba(0,0,0,0.08)',
              boxShadow: '0 8px 24px rgba(0,0,0,0.12)'
            }
          }}
        >
          <MenuItem onClick={() => { handleMenuClose(); setLocation('/admin'); }}>
            <Settings size={18} style={{ marginRight: 12 }} />
            Settings
          </MenuItem>
          <Divider />
          <MenuItem onClick={handleLogout} sx={{ color: '#ef4444' }}>
            <LogOut size={18} style={{ marginRight: 12 }} />
            Logout
          </MenuItem>
        </Menu>

        <Popover
          open={notificationOpen}
          anchorEl={notificationAnchor}
          onClose={handleNotificationClose}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'right',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'right',
          }}
          PaperProps={{
            elevation: 8,
            sx: {
              mt: 1.5,
              width: 360,
              maxHeight: 480,
              borderRadius: 2,
              border: '1px solid rgba(0,0,0,0.08)',
              boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
              overflow: 'hidden'
            }
          }}
        >
          <Box sx={{ p: 2, borderBottom: '1px solid rgba(0,0,0,0.08)', bgcolor: '#f9fafb' }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600, color: '#1f2937' }}>
              Notifications
            </Typography>
            {unreadCount > 0 && (
              <Typography variant="caption" sx={{ color: '#6b7280' }}>
                {unreadCount} unread message{unreadCount > 1 ? 's' : ''}
              </Typography>
            )}
          </Box>
          <Box sx={{ maxHeight: 380, overflowY: 'auto' }}>
            {(!messagesData?.messages || messagesData.messages.length === 0) ? (
              <Box sx={{ p: 4, textAlign: 'center' }}>
                <MessageCircle size={32} color="#9ca3af" style={{ margin: '0 auto 8px' }} />
                <Typography variant="body2" sx={{ color: '#6b7280' }}>
                  No notifications yet
                </Typography>
              </Box>
            ) : (
              messagesData.messages.map((msg) => (
                <Box
                  key={msg.id}
                  sx={{
                    p: 2,
                    borderBottom: '1px solid rgba(0,0,0,0.06)',
                    bgcolor: msg.isRead ? 'transparent' : alpha('#374151', 0.05),
                    transition: 'background-color 0.2s',
                    '&:hover': {
                      bgcolor: alpha('#374151', 0.08)
                    }
                  }}
                  data-testid={`notification-${msg.id}`}
                >
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 0.5 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#1f2937', flex: 1 }}>
                      {msg.title}
                    </Typography>
                    {!msg.isRead && (
                      <IconButton
                        size="small"
                        onClick={() => handleMarkAsRead(msg.id)}
                        sx={{ ml: 1, color: '#374151' }}
                        data-testid={`button-mark-read-${msg.id}`}
                      >
                        <Check size={16} />
                      </IconButton>
                    )}
                  </Box>
                  <Typography variant="body2" sx={{ color: '#6b7280', whiteSpace: 'pre-wrap', mb: 1 }}>
                    {msg.message}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#9ca3af' }}>
                    {new Date(msg.createdAt).toLocaleString()}
                  </Typography>
                </Box>
              ))
            )}
          </Box>
        </Popover>

        <Box sx={{ flex: 1, p: { xs: 2, md: 3 }, overflow: 'auto', minHeight: 0 }}>
          {children}
        </Box>
      </Box>

      {/* Bulk Generator Leave Warning Dialog */}
      <Dialog
        open={showBulkLeaveWarning}
        onClose={cancelBulkLeave}
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
            Please download your videos before leaving this page. 
            Your generated videos are stored temporarily and will not be saved in your history.
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button
            onClick={cancelBulkLeave}
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
            onClick={confirmBulkLeave}
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
    </Box>
  );
}
