import { alpha } from '@mui/material/styles';

export default function palette(mode: 'light' | 'dark') {
  const textPrimary = mode === 'dark' ? '#E1E1E6' : '#1B1B1F';
  const textSecondary = mode === 'dark' ? '#A1A1AA' : '#46464F';

  const secondaryMain = mode === 'dark' ? '#8B8DB0' : '#5A5C78';

  const divider = mode === 'dark' ? '#27272A' : '#EFEDF4';
  const background = mode === 'dark' ? '#09090B' : '#FFF';
  const paper = mode === 'dark' ? '#18181B' : '#FFF';

  const disabled = '#777680';
  const disabledBackground = mode === 'dark' ? '#27272A' : '#E4E1E6';

  return {
    mode,
    primary: {
      lighter: mode === 'dark' ? '#312E81' : '#E0E0FF',
      light: mode === 'dark' ? '#4338CA' : '#BDC2FF',
      main: '#606BDF',
      dark: '#3944B8',
      darker: '#000668',
      contrastText: '#FFFFFF'
    },
    secondary: {
      lighter: mode === 'dark' ? '#1E1E2E' : '#E0E0FF',
      light: mode === 'dark' ? '#3F3F5A' : '#C3C4E4',
      main: secondaryMain,
      dark: '#43455F',
      darker: '#171A31',
      contrastText: '#FFFFFF'
    },
    error: {
      lighter: mode === 'dark' ? '#450A0A' : '#FFEDEA',
      light: mode === 'dark' ? '#991B1B' : '#FFDAD6',
      main: '#DE3730',
      dark: '#BA1A1A',
      darker: '#690005',
      contrastText: '#FFFFFF'
    },
    warning: {
      lighter: mode === 'dark' ? '#451A03' : '#FFEEE1',
      light: mode === 'dark' ? '#92400E' : '#FFDCBE',
      main: '#AE6600',
      dark: '#8B5000',
      darker: '#4A2800',
      contrastText: '#FFFFFF'
    },
    success: {
      lighter: mode === 'dark' ? '#052E16' : '#C8FFC0',
      light: mode === 'dark' ? '#166534' : '#B6F2AF',
      main: '#22892F',
      dark: '#006E1C',
      darker: '#00390A',
      contrastText: '#FFFFFF'
    },
    info: {
      lighter: mode === 'dark' ? '#083344' : '#D4F7FF',
      light: mode === 'dark' ? '#0E7490' : '#A1EFFF',
      main: '#008394',
      dark: '#006876',
      darker: '#00363E',
      contrastText: '#FFFFFF'
    },
    grey: {
      50: mode === 'dark' ? '#18181B' : '#FBF8FF',
      100: mode === 'dark' ? '#27272A' : '#F5F2FA',
      200: mode === 'dark' ? '#3F3F46' : '#EFEDF4',
      300: mode === 'dark' ? '#52525B' : '#EAE7EF',
      400: mode === 'dark' ? '#71717A' : '#E4E1E6',
      500: mode === 'dark' ? '#A1A1AA' : '#DBD9E0',
      600: mode === 'dark' ? '#D4D4D8' : '#C7C5D0',
      700: disabled,
      800: textSecondary,
      900: textPrimary
    },
    text: {
      primary: textPrimary,
      secondary: textSecondary,
      disabled: disabled
    },
    divider,
    background: {
      default: background,
      paper: paper
    },
    action: {
      hover: alpha(secondaryMain, 0.08),
      selected: alpha(secondaryMain, 0.12),
      disabled: alpha(disabled, 0.6),
      disabledBackground: alpha(disabledBackground, 0.9)
    }
  };
}
