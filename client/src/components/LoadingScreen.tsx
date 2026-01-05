import Lottie from 'lottie-react';
import loadingAnimation from '@/assets/loading-animation.json';

interface LoadingScreenProps {
  isLoading: boolean;
}

export default function LoadingScreen({ isLoading }: LoadingScreenProps) {
  if (!isLoading) return null;

  return (
    <div 
      className="fixed inset-0 z-[9999] flex items-center justify-center bg-white dark:bg-gray-900 transition-opacity duration-500"
      style={{ opacity: isLoading ? 1 : 0 }}
    >
      <Lottie 
        animationData={loadingAnimation}
        loop={true}
        style={{ width: 200, height: 200 }}
      />
    </div>
  );
}
