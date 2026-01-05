import { useState, useRef } from 'react';
import { useLocation } from 'wouter';
import { useForm } from 'react-hook-form';
import { useMutation, useQuery } from '@tanstack/react-query';
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
import LinearProgress from '@mui/material/LinearProgress';
import MuiLink from '@mui/material/Link';
import { Visibility, VisibilityOff } from '@mui/icons-material';

interface SignupForm {
  firstName: string;
  lastName: string;
  username: string;
  password: string;
  confirmPassword: string;
}

function PasswordStrengthIndicator({ password }: { password: string }) {
  const getStrength = (pwd: string) => {
    if (!pwd) return { value: 0, label: '', color: 'inherit' };
    let strength = 0;
    if (pwd.length >= 8) strength++;
    if (pwd.length >= 12) strength++;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++;
    if (/[0-9]/.test(pwd)) strength++;
    if (/[^A-Za-z0-9]/.test(pwd)) strength++;

    if (strength <= 2) return { value: 33, label: 'Weak', color: '#DE3730' };
    if (strength <= 3) return { value: 66, label: 'Medium', color: '#f59e0b' };
    return { value: 100, label: 'Strong', color: '#22c55e' };
  };

  const strength = getStrength(password);

  if (!password) return null;

  return (
    <Box sx={{ mt: 1 }}>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 0.5 }}>
        <Typography variant="caption" sx={{ color: '#64748b' }}>
          Password strength
        </Typography>
        <Typography variant="caption" sx={{ color: strength.color, fontWeight: 600 }}>
          {strength.label}
        </Typography>
      </Stack>
      <LinearProgress
        variant="determinate"
        value={strength.value}
        sx={{
          height: 4,
          borderRadius: 2,
          backgroundColor: '#e5e7eb',
          '& .MuiLinearProgress-bar': {
            backgroundColor: strength.color,
            borderRadius: 2
          }
        }}
      />
    </Box>
  );
}

export default function Signup() {
  const [, setLocation] = useLocation();
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const [isConfirmPasswordVisible, setIsConfirmPasswordVisible] = useState(false);
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [signupError, setSignupError] = useState('');
  const [signupSuccess, setSignupSuccess] = useState(false);
  const { toast } = useToast();

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors }
  } = useForm<SignupForm>({
    defaultValues: {
      firstName: '',
      lastName: '',
      username: '',
      password: '',
      confirmPassword: ''
    }
  });

  const password = watch('password');
  const confirmPassword = watch('confirmPassword');

  const signupMutation = useMutation({
    mutationFn: async (data: SignupForm) => {
      const response = await apiRequest('POST', '/api/register', {
        username: data.username,
        password: data.password,
        firstName: data.firstName,
        lastName: data.lastName
      });
      return response.json();
    },
    onSuccess: () => {
      setSignupSuccess(true);
      toast({
        title: 'Account Created!',
        description: 'Your account has been created successfully. Redirecting to login...',
      });
      setTimeout(() => {
        setLocation('/login');
      }, 2000);
    },
    onError: (error: Error) => {
      setSignupError(error.message || 'Registration failed. Please try again.');
      toast({
        variant: 'destructive',
        title: 'Registration Failed',
        description: error.message || 'Please try again.',
      });
    }
  });

  const onSubmit = (data: SignupForm) => {
    setSignupError('');
    setSignupSuccess(false);

    if (data.password !== data.confirmPassword) {
      setSignupError('Passwords do not match');
      return;
    }

    if (!acceptedTerms) {
      setSignupError('Please accept the Terms of Service and Privacy Policy');
      return;
    }

    signupMutation.mutate(data);
  };

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
        overflow: 'hidden',
        '&::before': {
          content: '""',
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'radial-gradient(circle at 20% 50%, rgba(255, 255, 255, 0.15) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(255, 255, 255, 0.1) 0%, transparent 50%)',
          pointerEvents: 'none',
          animation: 'pulse 8s ease-in-out infinite'
        },
        '@keyframes pulse': {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.8 }
        }
      }}
    >
      <Card
        sx={{
          width: '100%',
          maxWidth: 520,
          borderRadius: 4,
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.25)',
          position: 'relative',
          zIndex: 1,
          overflow: 'visible',
          backdropFilter: 'blur(10px)',
          backgroundColor: 'rgba(255, 255, 255, 0.98)',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: -2,
            left: -2,
            right: -2,
            bottom: -2,
            background: 'linear-gradient(135deg, rgba(66, 165, 245, 0.3), rgba(124, 58, 237, 0.2))',
            borderRadius: 4,
            zIndex: -1,
            opacity: 0.3
          }
        }}
      >
        <CardContent sx={{ p: { xs: 3, sm: 4, md: 5 } }}>
          <Stack spacing={1} sx={{ mb: 4, textAlign: 'center' }}>
            <Typography variant="h4" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
              Create your account
            </Typography>
            <Typography variant="body1" sx={{ color: '#64748b' }}>
              Start your journey with VEO3.pk today
            </Typography>
          </Stack>

          {signupSuccess && (
            <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSignupSuccess(false)}>
              Account created successfully! Redirecting to login...
            </Alert>
          )}

          {signupError && (
            <Alert severity="error" sx={{ mb: 3 }} onClose={() => setSignupError('')}>
              {signupError}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
            <Stack spacing={2.5}>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                <Box sx={{ flex: 1 }}>
                  <InputLabel htmlFor="firstName" sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                    First name
                  </InputLabel>
                  <OutlinedInput
                    {...register('firstName', { required: 'First name is required' })}
                    id="firstName"
                    data-testid="input-firstname"
                    placeholder="John"
                    fullWidth
                    error={Boolean(errors.firstName)}
                    sx={{
                      '& .MuiOutlinedInput-input': { py: 1.5 },
                      '& .MuiOutlinedInput-notchedOutline': { borderColor: '#e5e7eb' },
                      '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#374151' }
                    }}
                  />
                  {errors.firstName && (
                    <FormHelperText error sx={{ mt: 0.5 }}>
                      {errors.firstName.message}
                    </FormHelperText>
                  )}
                </Box>

                <Box sx={{ flex: 1 }}>
                  <InputLabel htmlFor="lastName" sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                    Last name
                  </InputLabel>
                  <OutlinedInput
                    {...register('lastName', { required: 'Last name is required' })}
                    id="lastName"
                    data-testid="input-lastname"
                    placeholder="Doe"
                    fullWidth
                    error={Boolean(errors.lastName)}
                    sx={{
                      '& .MuiOutlinedInput-input': { py: 1.5 },
                      '& .MuiOutlinedInput-notchedOutline': { borderColor: '#e5e7eb' },
                      '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#374151' }
                    }}
                  />
                  {errors.lastName && (
                    <FormHelperText error sx={{ mt: 0.5 }}>
                      {errors.lastName.message}
                    </FormHelperText>
                  )}
                </Box>
              </Stack>

              <Box>
                <InputLabel htmlFor="username" sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                  Username
                </InputLabel>
                <OutlinedInput
                  {...register('username', { 
                    required: 'Username is required',
                    minLength: { value: 3, message: 'Username must be at least 3 characters' }
                  })}
                  id="username"
                  data-testid="input-username"
                  placeholder="johndoe"
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
                <InputLabel htmlFor="password" sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                  Password
                </InputLabel>
                <OutlinedInput
                  {...register('password', { 
                    required: 'Password is required',
                    minLength: { value: 6, message: 'Password must be at least 6 characters' }
                  })}
                  id="password"
                  data-testid="input-password"
                  type={isPasswordVisible ? 'text' : 'password'}
                  placeholder="Create a strong password"
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
                <PasswordStrengthIndicator password={password} />
              </Box>

              <Box>
                <InputLabel htmlFor="confirmPassword" sx={{ mb: 1, fontWeight: 500, color: '#374151' }}>
                  Confirm Password
                </InputLabel>
                <OutlinedInput
                  {...register('confirmPassword', { 
                    required: 'Please confirm your password',
                    validate: (value) => value === password || 'Passwords do not match'
                  })}
                  id="confirmPassword"
                  data-testid="input-confirm-password"
                  type={isConfirmPasswordVisible ? 'text' : 'password'}
                  placeholder="Confirm your password"
                  fullWidth
                  error={Boolean(errors.confirmPassword)}
                  endAdornment={
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setIsConfirmPasswordVisible(!isConfirmPasswordVisible)}
                        edge="end"
                        aria-label="toggle confirm password visibility"
                        sx={{ color: '#9ca3af' }}
                        data-testid="button-toggle-confirm-password"
                      >
                        {isConfirmPasswordVisible ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  }
                  sx={{
                    '& .MuiOutlinedInput-input': { py: 1.5 },
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: '#e5e7eb' },
                    '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#374151' }
                  }}
                />
                {errors.confirmPassword && (
                  <FormHelperText error sx={{ mt: 0.5 }}>
                    {errors.confirmPassword.message}
                  </FormHelperText>
                )}
              </Box>

              <FormControlLabel
                control={
                  <Checkbox
                    checked={acceptedTerms}
                    onChange={(e) => setAcceptedTerms(e.target.checked)}
                    size="small"
                    sx={{ color: '#9ca3af', '&.Mui-checked': { color: '#374151' } }}
                    data-testid="checkbox-terms"
                  />
                }
                label={
                  <Typography variant="body2" sx={{ color: '#64748b' }}>
                    I agree to the{' '}
                    <MuiLink href="#" underline="hover" sx={{ color: '#374151' }}>
                      Terms of Service
                    </MuiLink>{' '}
                    and{' '}
                    <MuiLink href="#" underline="hover" sx={{ color: '#374151' }}>
                      Privacy Policy
                    </MuiLink>
                  </Typography>
                }
              />

              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={signupMutation.isPending}
                data-testid="button-signup"
                sx={{
                  py: 1.5,
                  mt: 1,
                  textTransform: 'none',
                  fontWeight: 600,
                  fontSize: '1rem',
                  borderRadius: 2,
                  background: 'linear-gradient(135deg, #374151 0%, #1f2937 100%)',
                  boxShadow: '0 4px 14px rgba(25, 118, 210, 0.4)',
                  '&:hover': {
                    boxShadow: '0 6px 20px rgba(25, 118, 210, 0.5)',
                    transform: 'translateY(-1px)',
                    background: 'linear-gradient(135deg, #1f2937 0%, #111827 100%)'
                  },
                  '&:disabled': {
                    background: 'linear-gradient(135deg, #374151 0%, #1f2937 100%)',
                    opacity: 0.7
                  },
                  transition: 'all 0.2s ease-in-out'
                }}
              >
                {signupMutation.isPending ? (
                  <CircularProgress size={24} sx={{ color: 'white' }} />
                ) : (
                  'Create Account'
                )}
              </Button>
            </Stack>
          </Box>

          <Stack direction="row" justifyContent="center" spacing={1} sx={{ mt: 3 }}>
            <Typography variant="body2" sx={{ color: '#64748b' }}>
              Already have an account?
            </Typography>
            <MuiLink
              component="button"
              type="button"
              onClick={() => setLocation('/login')}
              underline="hover"
              variant="body2"
              data-testid="link-login"
              sx={{
                fontWeight: 600,
                color: '#374151',
                '&:hover': { color: '#1f2937' },
                cursor: 'pointer',
                background: 'none',
                border: 'none'
              }}
            >
              Sign in
            </MuiLink>
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
}
