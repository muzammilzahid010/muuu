import { Controller, Control } from 'react-hook-form';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import FormHelperText from '@mui/material/FormHelperText';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';

interface RHFSwitchProps {
  name: string;
  control: Control<any>;
  label?: string;
  description?: string;
  disabled?: boolean;
}

export default function RHFSwitch({ name, control, label, description, disabled }: RHFSwitchProps) {
  return (
    <Controller
      name={name}
      control={control}
      render={({ field, fieldState: { error } }) => (
        <Box>
          <FormControlLabel
            control={
              <Switch
                {...field}
                checked={field.value}
                disabled={disabled}
              />
            }
            label={
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>{label}</Typography>
                {description && (
                  <Typography variant="caption" color="text.secondary">{description}</Typography>
                )}
              </Box>
            }
          />
          {error && <FormHelperText error>{error.message}</FormHelperText>}
        </Box>
      )}
    />
  );
}
