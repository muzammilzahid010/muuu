import { Theme, alpha } from '@mui/material/styles';

export default function customShadows(theme: Theme) {
  const isDark = theme.palette.mode === 'dark';
  const color = isDark ? '#000000' : '#8898aa';

  return {
    z1: `0 1px 2px 0 ${alpha(color, 0.05)}`,
    z4: `0 4px 8px 0 ${alpha(color, 0.1)}`,
    z8: `0 8px 16px 0 ${alpha(color, 0.1)}`,
    z12: `0 12px 24px 0 ${alpha(color, 0.12)}`,
    z16: `0 16px 32px 0 ${alpha(color, 0.14)}`,
    z20: `0 20px 40px 0 ${alpha(color, 0.16)}`,
    z24: `0 24px 48px 0 ${alpha(color, 0.18)}`,
    card: isDark 
      ? `0 0 0 1px ${alpha('#FFFFFF', 0.1)}` 
      : `0 0 0 1px ${alpha('#000000', 0.05)}`,
    dialog: `0 20px 40px -4px ${alpha(color, 0.24)}`,
    dropdown: `0 4px 12px 0 ${alpha(color, 0.15)}`
  };
}
