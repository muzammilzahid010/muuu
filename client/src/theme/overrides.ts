import { Theme, alpha } from '@mui/material/styles';

export default function componentOverrides(theme: Theme) {
  const isDark = theme.palette.mode === 'dark';

  return {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          scrollbarWidth: 'thin',
          scrollbarColor: `${theme.palette.grey[400]} transparent`,
          '&::-webkit-scrollbar': {
            width: 8,
            height: 8
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: theme.palette.grey[400],
            borderRadius: 4
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: 'transparent'
          }
        }
      }
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          textTransform: 'none',
          fontWeight: 500,
          boxShadow: 'none',
          '&:hover': {
            boxShadow: 'none'
          }
        },
        sizeLarge: {
          height: 48,
          fontSize: '1rem'
        },
        sizeMedium: {
          height: 40
        },
        sizeSmall: {
          height: 32,
          fontSize: '0.8125rem'
        },
        containedPrimary: {
          '&:hover': {
            backgroundColor: theme.palette.primary.dark
          }
        }
      }
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: isDark 
            ? `0 0 0 1px ${alpha('#FFFFFF', 0.1)}` 
            : `0 0 0 1px ${alpha('#000000', 0.05)}`,
          backgroundImage: 'none'
        }
      }
    },
    MuiCardContent: {
      styleOverrides: {
        root: {
          padding: 20,
          '&:last-child': {
            paddingBottom: 20
          }
        }
      }
    },
    MuiCardHeader: {
      styleOverrides: {
        root: {
          padding: 20
        }
      }
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: 8
          }
        }
      }
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          '&:hover .MuiOutlinedInput-notchedOutline': {
            borderColor: theme.palette.primary.main
          },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
            borderWidth: 2
          }
        },
        notchedOutline: {
          borderColor: theme.palette.divider
        }
      }
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none'
        },
        rounded: {
          borderRadius: 12
        }
      }
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          borderRadius: 16
        }
      }
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          borderRight: 'none'
        }
      }
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          marginBottom: 4,
          '&.Mui-selected': {
            backgroundColor: alpha(theme.palette.primary.main, 0.12),
            '&:hover': {
              backgroundColor: alpha(theme.palette.primary.main, 0.16)
            }
          }
        }
      }
    },
    MuiListItemIcon: {
      styleOverrides: {
        root: {
          minWidth: 40
        }
      }
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 6
        }
      }
    },
    MuiAvatar: {
      styleOverrides: {
        root: {
          fontSize: '0.875rem',
          fontWeight: 600
        }
      }
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          backgroundColor: isDark ? theme.palette.grey[700] : theme.palette.grey[800],
          borderRadius: 6,
          fontSize: '0.75rem'
        }
      }
    },
    MuiTabs: {
      styleOverrides: {
        indicator: {
          borderRadius: 2
        }
      }
    },
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 500,
          minHeight: 48
        }
      }
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: 8
        }
      }
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          borderRadius: 4,
          height: 6
        }
      }
    },
    MuiSwitch: {
      styleOverrides: {
        root: {
          width: 42,
          height: 26,
          padding: 0,
          '& .MuiSwitch-switchBase': {
            padding: 0,
            margin: 2,
            '&.Mui-checked': {
              transform: 'translateX(16px)',
              '& + .MuiSwitch-track': {
                backgroundColor: theme.palette.primary.main,
                opacity: 1
              }
            }
          },
          '& .MuiSwitch-thumb': {
            width: 22,
            height: 22
          },
          '& .MuiSwitch-track': {
            borderRadius: 13,
            backgroundColor: theme.palette.grey[400]
          }
        }
      }
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderColor: theme.palette.divider
        },
        head: {
          fontWeight: 600,
          backgroundColor: isDark ? theme.palette.grey[100] : theme.palette.grey[50]
        }
      }
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          '&:hover': {
            backgroundColor: alpha(theme.palette.primary.main, 0.04)
          }
        }
      }
    },
    MuiDivider: {
      styleOverrides: {
        root: {
          borderColor: theme.palette.divider
        }
      }
    }
  };
}
