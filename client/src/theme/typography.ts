import { Theme } from '@mui/material/styles';

export default function typography(theme: Theme) {
  return {
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
    h1: {
      fontWeight: 700,
      fontSize: '2.25rem',
      lineHeight: 1.2,
      [theme.breakpoints.down('sm')]: {
        fontSize: '1.75rem'
      }
    },
    h2: {
      fontWeight: 700,
      fontSize: '1.875rem',
      lineHeight: 1.3,
      [theme.breakpoints.down('sm')]: {
        fontSize: '1.5rem'
      }
    },
    h3: {
      fontWeight: 600,
      fontSize: '1.5rem',
      lineHeight: 1.4,
      [theme.breakpoints.down('sm')]: {
        fontSize: '1.25rem'
      }
    },
    h4: {
      fontWeight: 600,
      fontSize: '1.25rem',
      lineHeight: 1.4
    },
    h5: {
      fontWeight: 600,
      fontSize: '1rem',
      lineHeight: 1.5
    },
    h6: {
      fontWeight: 600,
      fontSize: '0.875rem',
      lineHeight: 1.5
    },
    subtitle1: {
      fontWeight: 500,
      fontSize: '1rem',
      lineHeight: 1.5
    },
    subtitle2: {
      fontWeight: 500,
      fontSize: '0.875rem',
      lineHeight: 1.5
    },
    body1: {
      fontSize: '1rem',
      lineHeight: 1.5
    },
    body2: {
      fontSize: '0.875rem',
      lineHeight: 1.5
    },
    button: {
      fontWeight: 500,
      fontSize: '0.875rem',
      textTransform: 'none' as const
    },
    caption: {
      fontSize: '0.75rem',
      lineHeight: 1.5
    },
    overline: {
      fontSize: '0.75rem',
      fontWeight: 600,
      textTransform: 'uppercase' as const,
      letterSpacing: '0.08em'
    }
  };
}
