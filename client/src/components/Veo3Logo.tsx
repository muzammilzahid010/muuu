import veo3Logo from "@assets/353a7b8a-2fec-4a2e-9fd9-76aa79711acb_removalai_preview_1764969657371.png";

interface Veo3LogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

export default function Veo3Logo({ className = '', size = 'md' }: Veo3LogoProps) {
  const sizes = {
    sm: { width: 80, height: 32 },
    md: { width: 120, height: 48 },
    lg: { width: 160, height: 64 },
    xl: { width: 200, height: 80 }
  };

  const { width, height } = sizes[size];

  return (
    <img 
      src={veo3Logo}
      alt="VEO3"
      width={width}
      height={height}
      className={className}
      style={{ objectFit: 'contain' }}
    />
  );
}
