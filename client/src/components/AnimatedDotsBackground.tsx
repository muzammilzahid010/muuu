import React from 'react';
import { keyframes } from '@mui/material/styles';
import Box from '@mui/material/Box';

const floatDot = keyframes`
  0%, 100% {
    transform: translateY(0) translateX(0);
    opacity: 0.4;
  }
  25% {
    transform: translateY(-30px) translateX(15px);
    opacity: 0.7;
  }
  50% {
    transform: translateY(-50px) translateX(-20px);
    opacity: 0.5;
  }
  75% {
    transform: translateY(-20px) translateX(25px);
    opacity: 0.8;
  }
`;

const pulseDot = keyframes`
  0%, 100% {
    transform: scale(1) translateY(0);
    opacity: 0.5;
  }
  50% {
    transform: scale(1.5) translateY(-20px);
    opacity: 0.8;
  }
`;

const staticDots = Array.from({ length: 30 }, (_, i) => ({
  id: i,
  left: (i * 17 + 7) % 100,
  top: (i * 23 + 11) % 100,
  size: 4 + (i % 5) * 1.5,
  delay: (i % 8) * 0.5,
  duration: 4 + (i % 4),
  type: i % 2 === 0 ? 'float' : 'pulse'
}));

const AnimatedDotsBackground = React.memo(() => {
  return (
    <Box
      sx={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        overflow: 'hidden',
        pointerEvents: 'none',
        zIndex: 0,
        minHeight: '100vh'
      }}
    >
      {staticDots.map((dot) => (
        <Box
          key={dot.id}
          sx={{
            position: 'absolute',
            left: `${dot.left}%`,
            top: `${dot.top}%`,
            width: dot.size,
            height: dot.size,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #64748b 0%, #94a3b8 100%)',
            opacity: 0.5,
            animation: dot.type === 'float' 
              ? `${floatDot} ${dot.duration}s ease-in-out infinite`
              : `${pulseDot} ${dot.duration}s ease-in-out infinite`,
            animationDelay: `${dot.delay}s`,
            boxShadow: '0 0 8px rgba(100, 116, 139, 0.4)'
          }}
        />
      ))}
    </Box>
  );
});

AnimatedDotsBackground.displayName = 'AnimatedDotsBackground';

export default AnimatedDotsBackground;
