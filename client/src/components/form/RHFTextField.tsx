import { Controller, Control } from 'react-hook-form';
import TextField from '@mui/material/TextField';
import { TextFieldProps } from '@mui/material/TextField';

interface RHFTextFieldProps extends Omit<TextFieldProps, 'name'> {
  name: string;
  control: Control<any>;
}

export default function RHFTextField({ name, control, helperText, ...other }: RHFTextFieldProps) {
  return (
    <Controller
      name={name}
      control={control}
      render={({ field, fieldState: { error } }) => (
        <TextField
          {...field}
          fullWidth
          error={!!error}
          helperText={error?.message || helperText}
          {...other}
        />
      )}
    />
  );
}
