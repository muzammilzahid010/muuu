import { useState } from 'react';
import { useLocation } from 'wouter';
import { useForm } from 'react-hook-form';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';

import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Checkbox from '@mui/material/Checkbox';
import Divider from '@mui/material/Divider';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormHelperText from '@mui/material/FormHelperText';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import InputLabel from '@mui/material/InputLabel';
import OutlinedInput from '@mui/material/OutlinedInput';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import MuiLink from '@mui/material/Link';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { DollarSign, MessageCircle, Loader2, Shield, Copy, Check } from 'lucide-react';
import type { AppSettings } from '@shared/schema';

interface LoginForm {
  username: string;
  password: string;
}

interface TwoFactorSetupData {
  secret: string;
  qrCode: string;
}

type LoginStep = 'credentials' | '2fa-setup' | '2fa-verify';

export default function Login() {
  const [, setLocation] = useLocation();
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [loginStep, setLoginStep] = useState<LoginStep>('credentials');
  const [twoFactorSetupData, setTwoFactorSetupData] = useState<TwoFactorSetupData | null>(null);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [savedCredentials, setSavedCredentials] = useState<LoginForm | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: session, isLoading: sessionLoading } = useQuery<{
    authenticated: boolean;
    user?: { username: string; isAdmin: boolean };
  }>({
    queryKey: ['/api/session'],
  });

  const { data: settingsData } = useQuery<{ settings?: AppSettings }>({
    queryKey: ['/api/app-settings'],
  });

  const whatsappUrl = settingsData?.settings?.whatsappUrl || 'https://api.whatsapp.com/send?phone=&text=Hello, I need support';

  const {
    register,
    handleSubmit,
    formState: { errors },
    getValues
  } = useForm<LoginForm>({
    defaultValues: {
      username: '',
      password: ''
    }
  });

  const handleLoginSuccess = async (data: { user: { id: string; username: string; isAdmin: boolean } }) => {
    queryClient.setQueryData(['/api/session'], { 
      authenticated: true, 
      user: data.user 
    });
    await queryClient.invalidateQueries({ queryKey: ['/api/session'] });
    
    toast({
      title: 'Login Successful',
      description: `Welcome back, ${data.user.username}!`,
    });
    
    setTimeout(() => {
      if (data.user.isAdmin) {
        setLocation('/admin');
      } else {
        setLocation('/veo-generator');
      }
    }, 150);
  };

  const loginMutation = useMutation({
    mutationFn: async (data: LoginForm & { twoFactorCode?: string }) => {
      const response = await apiRequest('POST', '/api/login', data);
      return response.json();
    },
    onSuccess: async (data) => {
      if (data.requires2FASetup) {
        setTwoFactorSetupData({
          secret: data.secret,
          qrCode: data.qrCode
        });
        setSavedCredentials(getValues());
        setLoginStep('2fa-setup');
        toast({
          title: '2FA Setup Required',
          description: 'Please scan the QR code with your authenticator app',
        });
      } else if (data.requires2FA) {
        setSavedCredentials(getValues());
        setLoginStep('2fa-verify');
        toast({
          title: '2FA Required',
          description: 'Please enter your 2FA code',
        });
      } else if (data.success && data.user) {
        await handleLoginSuccess(data);
      }
    },
    onError: (error: Error) => {
      setLoginError(error.message || 'Invalid username or password');
      toast({
        variant: 'destructive',
        title: 'Login Failed',
        description: error.message || 'Invalid username or password',
      });
    }
  });

  const verify2FASetupMutation = useMutation({
    mutationFn: async () => {
      if (!savedCredentials) throw new Error('Missing credentials');
      const response = await apiRequest('POST', '/api/2fa/verify-setup', {
        username: savedCredentials.username,
        password: savedCredentials.password,
        code: twoFactorCode
      });
      return response.json();
    },
    onSuccess: async (data) => {
      if (data.success && data.user) {
        toast({
          title: '2FA Enabled',
          description: 'Two-factor authentication has been enabled for your account',
        });
        await handleLoginSuccess(data);
      }
    },
    onError: (error: Error) => {
      setLoginError(error.message || 'Invalid verification code');
      toast({
        variant: 'destructive',
        title: 'Verification Failed',
        description: error.message || 'Invalid verification code',
      });
    }
  });

  const onSubmit = (data: LoginForm) => {
    setLoginError('');
    loginMutation.mutate(data);
  };

  const handleVerify2FA = () => {
    setLoginError('');
    if (!savedCredentials) return;
    loginMutation.mutate({ ...savedCredentials, twoFactorCode });
  };

  const handleSetup2FA = () => {
    setLoginError('');
    verify2FASetupMutation.mutate();
  };

  const copySecret = () => {
    if (twoFactorSetupData?.secret) {
      navigator.clipboard.writeText(twoFactorSetupData.secret);
      setSecretCopied(true);
      setTimeout(() => setSecretCopied(false), 2000);
    }
  };

  if (sessionLoading) {
    return (
      <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'linear-gradient(135deg, #64748b 0%, #475569 50%, #334155 100%)' }}>
        <Loader2 className="w-8 h-8 animate-spin text-white" />
      </Box>
    );
  }

  if (session?.authenticated) {
    setLocation(session.user?.isAdmin ? '/admin' : '/veo-generator');
    return null;
  }

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #64748b 0%, #475569 50%, #334155 100%)',
        padding: { xs: 2, sm: 3 },
        position: 'relative',
        '&::before': {
          content: '""',
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'radial-gradient(circle at 20% 50%, rgba(255,255,255,0.15) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(255,255,255,0.1) 0%, transparent 50%)',
          pointerEvents: 'none'
        }
      }}
    >
      <Card
        sx={{
          width: '100%',
          maxWidth: 480,
          borderRadius: 4,
          boxShadow: '0 24px 64px rgba(0,0,0,0.25)',
          position: 'relative',
          zIndex: 1,
          overflow: 'visible',
          backgroundColor: '#ffffff',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: -2,
            left: -2,
            right: -2,
            bottom: -2,
            background: 'linear-gradient(135deg, rgba(255,255,255,0.3), rgba(255,255,255,0.1))',
            borderRadius: 4,
            zIndex: -1,
            opacity: 0.5
          }
        }}
      >
        <CardContent sx={{ p: { xs: 3, sm: 4, md: 5 } }}>
          {loginStep === 'credentials' && (
            <Stack spacing={1} sx={{ mb: 4, textAlign: 'center' }}>
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                Welcome back
              </Typography>
              <Typography variant="body1" sx={{ color: '#64748b' }}>
                Sign in to your VEO3.pk account
              </Typography>
            </Stack>
          )}

          {loginStep === '2fa-setup' && (
            <Stack spacing={1} sx={{ mb: 4, textAlign: 'center' }}>
              <Shield size={48} className="mx-auto text-green-600 mb-2" />
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                Setup 2FA
              </Typography>
              <Typography variant="body1" sx={{ color: '#64748b' }}>
                Scan the QR code with your authenticator app
              </Typography>
            </Stack>
          )}

          {loginStep === '2fa-verify' && (
            <Stack spacing={1} sx={{ mb: 4, textAlign: 'center' }}>
              <Shield size={48} className="mx-auto text-blue-600 mb-2" />
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                Enter 2FA Code
              </Typography>
              <Typography variant="body1" sx={{ color: '#64748b' }}>
                Enter the code from your authenticator app
              </Typography>
            </Stack>
          )}

          {loginError && (
            <Alert severity="error" sx={{ mb: 3 }} onClose={() => setLoginError('')}>
              {loginError}
            </Alert>
          )}

          {loginStep === '2fa-setup' && twoFactorSetupData && (
            <Stack spacing={3} sx={{ mb: 3 }}>
              <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                <Box
                  component="img"
                  src={twoFactorSetupData.qrCode}
                  alt="2FA QR Code"
                  sx={{
                    width: 200,
                    height: 200,
                    border: '4px solid #e5e7eb',
                    borderRadius: 2
                  }}
                />
              </Box>
              
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="body2" sx={{ color: '#64748b', mb: 1 }}>
                  Or enter this secret manually:
                </Typography>
                <Stack direction="row" spacing={1} justifyContent="center" alignItems="center">
                  <Typography
                    variant="body2"
                    sx={{
                      fontFamily: 'monospace',
                      backgroundColor: '#f3f4f6',
                      px: 2,
                      py: 1,
                      borderRadius: 1,
                      wordBreak: 'break-all'
                    }}
                  >
                    {twoFactorSetupData.secret}
                  </Typography>
                  <IconButton onClick={copySecret} size="small">
                    {secretCopied ? <Check size={16} className="text-green-600" /> : <Copy size={16} />}
                  </IconButton>
                </Stack>
              </Box>

              <Box>
                <InputLabel sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                  Enter verification code
                </InputLabel>
                <OutlinedInput
                  value={twoFactorCode}
                  onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  fullWidth
                  inputProps={{ maxLength: 6, style: { textAlign: 'center', letterSpacing: '0.5em', fontSize: '1.5rem' } }}
                  data-testid="input-2fa-setup-code"
                  sx={{
                    '& .MuiOutlinedInput-input': { py: 1.5 },
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: '#e5e7eb' }
                  }}
                />
              </Box>

              <Button
                fullWidth
                variant="contained"
                size="large"
                onClick={handleSetup2FA}
                disabled={twoFactorCode.length !== 6 || verify2FASetupMutation.isPending}
                data-testid="button-complete-2fa-setup"
                sx={{
                  py: 1.5,
                  textTransform: 'none',
                  fontWeight: 600,
                  fontSize: '1rem',
                  borderRadius: 2,
                  backgroundColor: '#16a34a',
                  '&:hover': { backgroundColor: '#15803d' }
                }}
              >
                {verify2FASetupMutation.isPending ? (
                  <CircularProgress size={24} sx={{ color: 'white' }} />
                ) : (
                  'Complete Setup & Login'
                )}
              </Button>

              <Button
                fullWidth
                variant="text"
                onClick={() => {
                  setLoginStep('credentials');
                  setTwoFactorCode('');
                  setTwoFactorSetupData(null);
                }}
                sx={{ textTransform: 'none', color: '#64748b' }}
              >
                Back to Login
              </Button>
            </Stack>
          )}

          {loginStep === '2fa-verify' && (
            <Stack spacing={3} sx={{ mb: 3 }}>
              <Box>
                <InputLabel sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                  2FA Code
                </InputLabel>
                <OutlinedInput
                  value={twoFactorCode}
                  onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  fullWidth
                  inputProps={{ maxLength: 6, style: { textAlign: 'center', letterSpacing: '0.5em', fontSize: '1.5rem' } }}
                  data-testid="input-2fa-code"
                  sx={{
                    '& .MuiOutlinedInput-input': { py: 1.5 },
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: '#e5e7eb' }
                  }}
                />
              </Box>

              <Button
                fullWidth
                variant="contained"
                size="large"
                onClick={handleVerify2FA}
                disabled={twoFactorCode.length !== 6 || loginMutation.isPending}
                data-testid="button-verify-2fa"
                sx={{
                  py: 1.5,
                  textTransform: 'none',
                  fontWeight: 600,
                  fontSize: '1rem',
                  borderRadius: 2,
                  backgroundColor: '#374151',
                  '&:hover': { backgroundColor: '#1f2937' }
                }}
              >
                {loginMutation.isPending ? (
                  <CircularProgress size={24} sx={{ color: 'white' }} />
                ) : (
                  'Verify & Login'
                )}
              </Button>

              <Button
                fullWidth
                variant="text"
                onClick={() => {
                  setLoginStep('credentials');
                  setTwoFactorCode('');
                }}
                sx={{ textTransform: 'none', color: '#64748b' }}
              >
                Back to Login
              </Button>
            </Stack>
          )}

          {loginStep === 'credentials' && (
          <>
          <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
            <Stack spacing={2.5}>
              <Box>
                <InputLabel htmlFor="username" sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                  Username
                </InputLabel>
                <OutlinedInput
                  {...register('username', { required: 'Username is required' })}
                  id="username"
                  data-testid="input-username"
                  placeholder="Enter your username"
                  fullWidth
                  error={Boolean(errors.username)}
                  sx={{
                    '& .MuiOutlinedInput-input': { py: 1.5 },
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: '#e5e7eb' },
                    '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#374151' }
                  }}
                />
                {errors.username && (
                  <FormHelperText error sx={{ mt: 0.5 }}>
                    {errors.username.message}
                  </FormHelperText>
                )}
              </Box>

              <Box>
                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                  <InputLabel htmlFor="password" sx={{ fontWeight: 500, color: '#374151' }}>
                    Password
                  </InputLabel>
                  <MuiLink
                    href="#"
                    underline="hover"
                    variant="caption"
                    sx={{
                      fontWeight: 500,
                      color: '#374151',
                      '&:hover': { color: '#1f2937' }
                    }}
                  >
                    Forgot password?
                  </MuiLink>
                </Stack>
                <OutlinedInput
                  {...register('password', { required: 'Password is required' })}
                  id="password"
                  data-testid="input-password"
                  type={isPasswordVisible ? 'text' : 'password'}
                  placeholder="Enter your password"
                  fullWidth
                  error={Boolean(errors.password)}
                  endAdornment={
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setIsPasswordVisible(!isPasswordVisible)}
                        edge="end"
                        aria-label="toggle password visibility"
                        sx={{ color: '#9ca3af' }}
                        data-testid="button-toggle-password"
                      >
                        {isPasswordVisible ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  }
                  sx={{
                    '& .MuiOutlinedInput-input': { py: 1.5 },
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: '#e5e7eb' },
                    '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#374151' }
                  }}
                />
                {errors.password && (
                  <FormHelperText error sx={{ mt: 0.5 }}>
                    {errors.password.message}
                  </FormHelperText>
                )}
              </Box>

              <FormControlLabel
                control={
                  <Checkbox
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    size="small"
                    sx={{ color: '#9ca3af', '&.Mui-checked': { color: '#374151' } }}
                    data-testid="checkbox-remember"
                  />
                }
                label={
                  <Typography variant="body2" sx={{ color: '#64748b' }}>
                    Remember me for 30 days
                  </Typography>
                }
              />

              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={loginMutation.isPending}
                data-testid="button-signin"
                sx={{
                  py: 1.5,
                  mt: 1,
                  textTransform: 'none',
                  fontWeight: 600,
                  fontSize: '1rem',
                  borderRadius: 2,
                  backgroundColor: '#374151',
                  boxShadow: '0 4px 14px rgba(55, 65, 81, 0.4)',
                  '&:hover': {
                    boxShadow: '0 6px 20px rgba(55, 65, 81, 0.5)',
                    transform: 'translateY(-1px)',
                    backgroundColor: '#1f2937'
                  },
                  '&:disabled': {
                    backgroundColor: '#374151',
                    opacity: 0.7
                  },
                  transition: 'all 0.2s ease-in-out'
                }}
              >
                {loginMutation.isPending ? (
                  <CircularProgress size={24} sx={{ color: 'white' }} />
                ) : (
                  'Sign In'
                )}
              </Button>
            </Stack>
          </Box>

          <Divider sx={{ my: 3 }}>
            <Typography variant="body2" sx={{ color: '#9ca3af', px: 2 }}>
              or
            </Typography>
          </Divider>

          <Stack direction="row" spacing={2}>
            <Button
              variant="outlined"
              fullWidth
              size="large"
              onClick={() => setLocation('/pricing')}
              data-testid="button-plans"
              startIcon={<DollarSign size={18} />}
              sx={{
                py: 1.5,
                borderColor: '#e5e7eb',
                color: '#374151',
                textTransform: 'none',
                fontWeight: 500,
                borderRadius: 2,
                '&:hover': {
                  borderColor: '#374151',
                  backgroundColor: 'rgba(25, 118, 210, 0.04)'
                }
              }}
            >
              Plans
            </Button>
            <Button
              variant="outlined"
              fullWidth
              size="large"
              component="a"
              href={whatsappUrl}
              target="_blank"
              rel="noopener noreferrer"
              data-testid="button-support"
              startIcon={<MessageCircle size={18} />}
              sx={{
                py: 1.5,
                borderColor: '#e5e7eb',
                color: '#374151',
                textTransform: 'none',
                fontWeight: 500,
                borderRadius: 2,
                '&:hover': {
                  borderColor: '#25d366',
                  color: '#25d366',
                  backgroundColor: 'rgba(37, 211, 102, 0.04)'
                }
              }}
            >
              Support
            </Button>
          </Stack>

          <Typography variant="caption" sx={{ mt: 3, display: 'block', textAlign: 'center', color: '#9ca3af' }}>
            By continuing, you agree to our{' '}
            <MuiLink href="#" underline="hover" sx={{ color: '#374151' }}>
              Terms of Service
            </MuiLink>{' '}
            and{' '}
            <MuiLink href="#" underline="hover" sx={{ color: '#374151' }}>
              Privacy Policy
            </MuiLink>
          </Typography>
          </>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}
