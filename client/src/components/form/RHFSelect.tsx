import { Controller, Control } from 'react-hook-form';
import TextField from '@mui/material/TextField';
import MenuItem from '@mui/material/MenuItem';

interface Option {
  value: string;
  label: string;
}

interface RHFSelectProps {
  name: string;
  control: Control<any>;
  label?: string;
  options: Option[];
  disabled?: boolean;
  helperText?: string;
  fullWidth?: boolean;
  size?: 'small' | 'medium';
}

export default function RHFSelect({ 
  name, 
  control, 
  label, 
  options, 
  disabled, 
  helperText,
  fullWidth = true,
  size = 'medium'
}: RHFSelectProps) {
  return (
    <Controller
      name={name}
      control={control}
      render={({ field, fieldState: { error } }) => (
        <TextField
          {...field}
          select
          fullWidth={fullWidth}
          label={label}
          size={size}
          disabled={disabled}
          error={!!error}
          helperText={error?.message || helperText}
        >
          {options.map((option) => (
            <MenuItem key={option.value} value={option.value}>
              {option.label}
            </MenuItem>
          ))}
        </TextField>
      )}
    />
  );
}
