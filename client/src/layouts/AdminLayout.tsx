import { useState } from 'react';
import { useLocation, Link } from 'wouter';
import { useTheme, alpha } from '@mui/material/styles';
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
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import useMediaQuery from '@mui/material/useMediaQuery';
import { 
  LayoutDashboard, 
  Users, 
  Key, 
  Settings, 
  FileText, 
  Wrench, 
  DollarSign, 
  HistoryIcon, 
  Activity, 
  Menu as MenuIcon, 
  X, 
  LogOut, 
  ChevronDown, 
  Bell, 
  Home 
} from 'lucide-react';

const drawerWidth = 260;

// Gray theme colors matching other pages
const grayTheme = {
  primary: '#374151',
  primaryDark: '#1f2937',
  primaryLight: '#4b5563',
  sidebar: '#1f2937',
  sidebarHover: '#374151',
  text: '#1f2937',
  textSecondary: '#6b7280',
  border: '#e5e7eb',
  background: '#f9fafb',
  cardBg: '#ffffff',
};

interface AdminLayoutProps {
  children: React.ReactNode;
}

const mainMenuItems = [
  { id: 'dashboard', title: 'Dashboard', icon: LayoutDashboard, path: '/admin' },
  { id: 'users', title: 'User Management', icon: Users, path: '/admin?tab=users' },
  { id: 'tokens', title: 'API Tokens', icon: Key, path: '/admin?tab=tokens' },
  { id: 'plans', title: 'Plan Settings', icon: DollarSign, path: '/admin?tab=plans' },
  { id: 'history', title: 'Video History', icon: HistoryIcon, path: '/admin?tab=history' },
];

const settingsMenuItems = [
  { id: 'app-settings', title: 'App Settings', icon: Settings, path: '/admin?tab=settings' },
  { id: 'maintenance', title: 'Maintenance', icon: Wrench, path: '/admin?tab=maintenance' },
  { id: 'system', title: 'System Monitor', icon: Activity, path: '/admin?tab=system' },
];

export default function AdminLayout({ children }: AdminLayoutProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [location, setLocation] = useLocation();

  const handleMobileOpen = () => setMobileOpen(true);
  const handleMobileClose = () => setMobileOpen(false);
  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleMenuClose = () => setAnchorEl(null);

  const isActive = (path: string) => {
    if (path === '/admin') {
      return location === '/admin' && !location.includes('?');
    }
    return location.includes(path.split('?tab=')[1] || '');
  };

  const renderMenuItem = (item: typeof mainMenuItems[0]) => {
    const active = isActive(item.path);
    const Icon = item.icon;
    return (
      <ListItem key={item.id} disablePadding sx={{ mb: 0.5 }}>
        <ListItemButton
          onClick={() => {
            setLocation(item.path);
            if (isMobile) handleMobileClose();
          }}
          sx={{
            minHeight: 44,
            pl: 2.5,
            pr: 2,
            borderRadius: 2,
            transition: 'all 0.2s ease',
            backgroundColor: active ? 'rgba(255,255,255,0.15)' : 'transparent',
            color: active ? '#ffffff' : 'rgba(255,255,255,0.7)',
            '&:hover': {
              backgroundColor: active ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.1)'
            },
            '& .MuiListItemIcon-root': {
              color: active ? '#ffffff' : 'rgba(255,255,255,0.6)',
              minWidth: 40
            }
          }}
        >
          <ListItemIcon>
            <Icon size={20} />
          </ListItemIcon>
          <ListItemText
            primary={item.title}
            primaryTypographyProps={{ fontSize: 14, fontWeight: active ? 600 : 500 }}
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
        bgcolor: grayTheme.sidebar,
        borderRight: 'none'
      }}
    >
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(255,255,255,0.1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}
      >
        <Typography variant="h6" sx={{ fontWeight: 700, color: '#ffffff' }}>
          VEO3.1 Admin
        </Typography>
        {isMobile && (
          <IconButton onClick={handleMobileClose} size="small" sx={{ color: 'rgba(255,255,255,0.7)' }}>
            <X size={20} />
          </IconButton>
        )}
      </Box>

      <Box sx={{ flex: 1, overflow: 'auto', p: 1.5 }}>
        <List sx={{ p: 0 }}>{mainMenuItems.map(renderMenuItem)}</List>

        <Divider sx={{ my: 2, borderColor: 'rgba(255,255,255,0.1)' }} />

        <Typography
          variant="caption"
          sx={{
            px: 2.5,
            py: 1,
            color: 'rgba(255,255,255,0.5)',
            fontWeight: 600,
            fontSize: '0.7rem',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            display: 'block'
          }}
        >
          Management
        </Typography>
        <List sx={{ p: 0, mt: 0.5 }}>{settingsMenuItems.map(renderMenuItem)}</List>
      </Box>

      <Box sx={{ p: 2, borderTop: '1px solid rgba(255,255,255,0.1)' }}>
        <Button
          variant="outlined"
          fullWidth
          startIcon={<Home size={18} />}
          onClick={() => setLocation('/')}
          sx={{
            borderRadius: 2,
            py: 1.5,
            fontWeight: 600,
            textTransform: 'none',
            color: '#ffffff',
            borderColor: 'rgba(255,255,255,0.3)',
            '&:hover': {
              borderColor: '#ffffff',
              bgcolor: 'rgba(255,255,255,0.1)'
            }
          }}
        >
          Back to App
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
            '&:hover': { bgcolor: 'rgba(255,255,255,0.1)' } 
          }}
        >
          <Avatar 
            sx={{ 
              width: 32, 
              height: 32, 
              background: `linear-gradient(135deg, ${grayTheme.primary} 0%, ${grayTheme.primaryLight} 100%)`, 
              fontWeight: 600, 
              fontSize: 14 
            }}
          >
            AD
          </Avatar>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#ffffff', fontSize: '0.875rem' }}>
              Admin
            </Typography>
            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.75rem' }}>
              Control Center
            </Typography>
          </Box>
        </Stack>
      </Box>
    </Box>
  );

  return (
    <Box
      sx={{
        minHeight: '100vh',
        bgcolor: grayTheme.background,
        display: 'flex',
        color: grayTheme.text
      }}
    >
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={handleMobileClose}
        ModalProps={{ keepMounted: true }}
        sx={{
          display: { xs: 'block', md: 'none' },
          '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth, borderRight: 'none', bgcolor: grayTheme.sidebar }
        }}
      >
        {drawerContent}
      </Drawer>

      <Drawer
        variant="permanent"
        sx={{
          display: { xs: 'none', md: 'block' },
          '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth, borderRight: 'none', transition: 'width 0.3s cubic-bezier(0.4, 0, 0.2, 1)', bgcolor: grayTheme.sidebar }
        }}
        open
      >
        {drawerContent}
      </Drawer>

      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <AppBar
          position="sticky"
          elevation={0}
          sx={{
            bgcolor: grayTheme.primary,
            borderBottom: `1px solid ${grayTheme.primaryLight}`,
            backdropFilter: 'blur(20px) saturate(180%)',
            transition: 'all 0.3s ease',
            boxShadow: 'none'
          }}
        >
          <Toolbar sx={{ minHeight: { xs: 64, md: 72 }, px: { xs: 2, md: 3 } }}>
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ flex: 1 }}>
              {isMobile && (
                <IconButton
                  onClick={handleMobileOpen}
                  sx={{
                    color: 'rgba(255,255,255,0.8)',
                    borderRadius: 2,
                    '&:hover': { bgcolor: 'rgba(255,255,255,0.1)', color: '#ffffff' }
                  }}
                >
                  <MenuIcon size={22} />
                </IconButton>
              )}
              <Typography variant="h6" sx={{ fontWeight: 600, color: '#ffffff' }}>
                Admin Panel
              </Typography>
            </Stack>

            <Stack direction="row" spacing={1.5} alignItems="center">
              <Stack
                direction="row"
                spacing={1.5}
                alignItems="center"
                onClick={handleMenuClick}
                sx={{ px: 1.5, py: 1, borderRadius: 2, cursor: 'pointer', '&:hover': { bgcolor: 'rgba(255,255,255,0.1)' } }}
              >
                <Avatar 
                  sx={{ 
                    width: 40, 
                    height: 40, 
                    background: `linear-gradient(135deg, ${grayTheme.primaryLight} 0%, ${grayTheme.primary} 100%)`, 
                    fontWeight: 700, 
                    fontSize: 15 
                  }}
                >
                  AD
                </Avatar>
                <Box sx={{ display: { xs: 'none', sm: 'block' } }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, color: '#ffffff', lineHeight: 1.2 }}>
                    Admin
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.75rem' }}>
                    Control Center
                  </Typography>
                </Box>
                <ChevronDown size={18} color="rgba(255,255,255,0.7)" />
              </Stack>
            </Stack>
          </Toolbar>

          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={handleMenuClose}
            onClick={handleMenuClose}
            PaperProps={{ 
              elevation: 8, 
              sx: { 
                mt: 1.5, 
                minWidth: 200, 
                borderRadius: 2,
                bgcolor: grayTheme.cardBg,
                border: `1px solid ${grayTheme.border}`
              } 
            }}
            transformOrigin={{ horizontal: 'right', vertical: 'top' }}
            anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
          >
            <MenuItem onClick={() => setLocation('/')} sx={{ color: grayTheme.text }}>
              <Stack direction="row" spacing={1.5} alignItems="center" sx={{ width: '100%' }}>
                <Home size={18} />
                <Typography variant="body2">Back to App</Typography>
              </Stack>
            </MenuItem>
            <Divider sx={{ borderColor: grayTheme.border }} />
            <MenuItem onClick={() => setLocation('/login')} sx={{ color: grayTheme.text }}>
              <Stack direction="row" spacing={1.5} alignItems="center" sx={{ width: '100%' }}>
                <LogOut size={18} />
                <Typography variant="body2">Logout</Typography>
              </Stack>
            </MenuItem>
          </Menu>
        </AppBar>

        <Box
          component="main"
          sx={{
            flex: 1,
            p: { xs: 2, md: 3 },
            bgcolor: grayTheme.background
          }}
        >
          {children}
        </Box>
      </Box>
    </Box>
  );
}
