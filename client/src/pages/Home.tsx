import { Link } from "wouter";
import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import Navbar from "@/components/Navbar";
import veo3LogoImage from "@assets/353a7b8a-2fec-4a2e-9fd9-76aa79711acb_removalai_preview_1764969657371.png";
import veo3DemoVideo from "@assets/veo3-video_1764787117176.mp4";
import { 
  Video, 
  Image, 
  Mic, 
  Users, 
  Wand2, 
  PlayCircle, 
  Sparkles,
  MessageSquare,
  Code,
  Layers,
  Zap,
  Camera,
  Film,
  Palette,
  FileText,
  Star,
  CheckCircle,
  ArrowRight
} from "lucide-react";

export default function Home() {
  const toolsSectionRef = useRef<HTMLDivElement>(null);
  const statsSectionRef = useRef<HTMLDivElement>(null);
  const whyChooseSectionRef = useRef<HTMLDivElement>(null);

  // Fetch total videos generated count
  const { data: statsData } = useQuery<{ totalVideosGenerated: number }>({
    queryKey: ["/api/stats"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Format number with K+ suffix for large numbers
  const formatVideoCount = (count: number): { number: string; suffix: string } => {
    if (count >= 1000) {
      const kValue = Math.floor(count / 1000);
      return { number: kValue.toString(), suffix: "K+" };
    }
    return { number: count.toString(), suffix: "+" };
  };

  const totalVideos = statsData?.totalVideosGenerated ?? 0;
  const videoStats = formatVideoCount(totalVideos);

  useEffect(() => {
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const revealElements = entry.target.querySelectorAll('.scroll-reveal, .scroll-reveal-scale');
          revealElements.forEach((el) => {
            el.classList.add('revealed');
          });
        }
      });
    }, observerOptions);

    if (toolsSectionRef.current) observer.observe(toolsSectionRef.current);
    if (statsSectionRef.current) observer.observe(statsSectionRef.current);
    if (whyChooseSectionRef.current) observer.observe(whyChooseSectionRef.current);

    return () => observer.disconnect();
  }, []);

  const tools = [
    { name: "VEO3.1 Video Generator", icon: Sparkles, href: "/veo-generator" },
    { name: "Text to Image AI", icon: Image, href: "/text-to-image" },
    { name: "Text to Speech", icon: Mic, href: "/script-creator" },
    { name: "Image to Video", icon: Video, href: "/image-to-video" },
    { name: "Script Creator", icon: Wand2, href: "/script-creator" },
    { name: "Character Videos", icon: Users, href: "/character-consistent" },
    { name: "Build Videos", icon: Layers, href: "/bulk-generator" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white">
      <Navbar />
      
      {/* Hero Section */}
      <section className="relative overflow-hidden pt-12 pb-20 lg:pt-20 lg:pb-32">
        {/* Full Background Animated Dots Pattern */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          {/* Grid of animated dots */}
          <div className="absolute inset-0" style={{ 
            backgroundImage: `radial-gradient(circle, #cbd5e1 2px, transparent 2px)`,
            backgroundSize: '35px 35px',
          }}>
          </div>
          
          {/* Animated floating dots overlay - larger and more visible */}
          {[...Array(30)].map((_, i) => (
            <div
              key={i}
              className="absolute rounded-full animate-dot-float"
              style={{
                width: `${6 + (i % 4) * 3}px`,
                height: `${6 + (i % 4) * 3}px`,
                backgroundColor: i % 3 === 0 ? 'rgba(107, 114, 128, 0.25)' : 'rgba(156, 163, 175, 0.5)',
                left: `${3 + (i * 3.2) % 94}%`,
                top: `${5 + (i * 5.5) % 85}%`,
                animationDelay: `${i * 0.2}s`,
                animationDuration: `${3 + (i % 4)}s`,
              }}
            />
          ))}
        </div>

        {/* Floating Icons - Left Side */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          {/* Top Left - Video Icon */}
          <div className="absolute top-24 left-[5%] w-14 h-14 bg-white rounded-2xl flex items-center justify-center shadow-lg border border-gray-100 animate-float-slow">
            <Video className="w-7 h-7 text-gray-600" />
          </div>
          
          {/* Left Upper - Zap Icon */}
          <div className="absolute top-[28%] left-[3%] w-11 h-11 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-float-delayed">
            <Zap className="w-5 h-5 text-yellow-500" />
          </div>
          
          {/* Left Middle - Image Icon */}
          <div className="absolute top-[42%] left-[6%] w-12 h-12 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-bounce-gentle">
            <Image className="w-6 h-6 text-pink-500" />
          </div>
          
          {/* Left Lower - Mic Icon */}
          <div className="absolute top-[56%] left-[2%] w-13 h-13 bg-white rounded-2xl flex items-center justify-center shadow-lg border border-gray-100 animate-float">
            <Mic className="w-6 h-6 text-amber-500" />
          </div>
          
          {/* Left Bottom - Camera Icon */}
          <div className="absolute top-[70%] left-[5%] w-11 h-11 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-float-slow">
            <Camera className="w-5 h-5 text-indigo-500" />
          </div>
          
          {/* Top Right - Users Icon */}
          <div className="absolute top-20 right-[8%] w-12 h-12 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-float-delayed">
            <Users className="w-6 h-6 text-cyan-500" />
          </div>
          
          {/* Right Upper - Star Icon */}
          <div className="absolute top-[30%] right-[4%] w-10 h-10 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-bounce-gentle">
            <Star className="w-5 h-5 text-orange-500" />
          </div>
          
          {/* Right Middle - MessageSquare Icon */}
          <div className="absolute top-[45%] right-[7%] w-14 h-14 bg-white rounded-2xl flex items-center justify-center shadow-lg border border-gray-100 animate-float-slow">
            <MessageSquare className="w-7 h-7 text-gray-500" />
          </div>
          
          {/* Right Lower - Code Icon */}
          <div className="absolute top-[58%] right-[2%] w-12 h-12 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-float">
            <Code className="w-6 h-6 text-green-500" />
          </div>
          
          {/* Right Bottom - Film Icon */}
          <div className="absolute top-[72%] right-[5%] w-11 h-11 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-float-delayed">
            <Film className="w-5 h-5 text-red-500" />
          </div>
          
          {/* Extra Icons - Palette */}
          <div className="absolute top-[85%] left-[8%] w-10 h-10 bg-white rounded-lg flex items-center justify-center shadow-lg border border-gray-100 animate-bounce-gentle hidden lg:flex">
            <Palette className="w-4 h-4 text-teal-500" />
          </div>
          
          {/* Extra Icons - FileText */}
          <div className="absolute top-[83%] right-[9%] w-10 h-10 bg-white rounded-lg flex items-center justify-center shadow-lg border border-gray-100 animate-float-slow hidden lg:flex">
            <FileText className="w-4 h-4 text-gray-400" />
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="text-center max-w-4xl mx-auto">
            {/* Badges */}
            <div className="flex items-center justify-center gap-3 mb-8 animate-fade-in-up animation-delay-100">
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-gray-100 text-gray-600 text-sm font-medium rounded-full">
                AI-Powered
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-gray-200 text-gray-700 text-sm font-medium rounded-full">
                <Sparkles className="w-4 h-4" />
                Creative Suite
              </span>
            </div>

            {/* Headline */}
            <h1 className="font-display text-4xl sm:text-5xl lg:text-6xl text-gray-900 leading-[1.1] mb-6 animate-fade-in-up animation-delay-200 text-balance">
              VEO3.1 AI Video Generator,{" "}
              <span className="text-gray-700">Image Creation</span> & Text to Speech Tools
            </h1>

            {/* Description */}
            <p className="font-body text-lg sm:text-xl text-gray-600 mb-10 max-w-3xl mx-auto leading-relaxed animate-fade-in-up animation-delay-300 text-balance">
              Transform your creative workflow with our comprehensive AI toolkit. Generate stunning videos using Google's VEO3.1 technology, create AI-powered images from text, convert text to natural-sounding speech, build character-consistent videos, and craft professional scripts—all in one powerful platform.
            </p>

            {/* CTA Button */}
            <div className="mb-12 animate-scale-fade-in animation-delay-400">
              <Link
                href="/veo-generator"
                className="font-heading inline-flex items-center gap-2 px-8 py-4 bg-gray-800 text-white text-lg rounded-full hover:bg-gray-900 transition-all shadow-lg hover:shadow-xl hover:-translate-y-0.5"
                data-testid="button-start-creating"
              >
                <Sparkles className="w-5 h-5" />
                Start Creating
              </Link>
            </div>

            {/* Tool Categories */}
            <div className="flex flex-wrap items-center justify-center gap-3">
              {tools.map((tool, index) => {
                const delayClass = `animation-delay-${(index + 1) * 100}`;
                return (
                  <Link
                    key={tool.name}
                    href={tool.href}
                    className={`font-body-medium inline-flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 text-gray-700 text-sm rounded-full hover:border-gray-400 hover:text-gray-900 transition-colors shadow-sm animate-slide-in-blur ${delayClass}`}
                  >
                    <tool.icon className="w-4 h-4" />
                    {tool.name}
                  </Link>
                );
              })}
            </div>
          </div>
        </div>

        {/* Video Preview Section with Decorative Curves */}
        <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 mt-16">
          {/* Left Curved Arrow with Icon */}
          <div className="absolute -left-4 lg:-left-16 top-1/2 -translate-y-1/2 pointer-events-none hidden md:block">
            <svg width="80" height="160" viewBox="0 0 80 160" fill="none" className="text-gray-400">
              <path d="M70 10 C 20 10, 10 40, 10 80 C 10 120, 20 150, 70 150" stroke="currentColor" strokeWidth="3" fill="none" strokeLinecap="round"/>
            </svg>
            <div className="absolute top-1/2 -translate-y-1/2 -left-2 w-10 h-10 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-float-slow">
              <Mic className="w-5 h-5 text-amber-500" />
            </div>
          </div>
          
          {/* Right Curved Arrow with Icon */}
          <div className="absolute -right-4 lg:-right-16 top-1/2 -translate-y-1/2 pointer-events-none hidden md:block">
            <svg width="80" height="160" viewBox="0 0 80 160" fill="none" className="text-gray-400">
              <path d="M10 10 C 60 10, 70 40, 70 80 C 70 120, 60 150, 10 150" stroke="currentColor" strokeWidth="3" fill="none" strokeLinecap="round"/>
            </svg>
            <div className="absolute top-1/2 -translate-y-1/2 -right-2 w-10 h-10 bg-white rounded-xl flex items-center justify-center shadow-lg border border-gray-100 animate-bounce-gentle">
              <Code className="w-5 h-5 text-green-500" />
            </div>
          </div>

          {/* Top Right Corner Curve with Icon */}
          <div className="absolute -right-8 lg:-right-20 -top-8 pointer-events-none hidden lg:block">
            <svg width="100" height="100" viewBox="0 0 100 100" fill="none" className="text-gray-400">
              <path d="M10 90 C 10 40, 50 10, 90 10" stroke="currentColor" strokeWidth="3" fill="none" strokeLinecap="round"/>
            </svg>
            <div className="absolute top-0 right-0 w-9 h-9 bg-white rounded-lg flex items-center justify-center shadow-lg border border-gray-100 animate-float-delayed">
              <MessageSquare className="w-4 h-4 text-gray-500" />
            </div>
          </div>

          {/* Video Container */}
          <div className="relative rounded-2xl overflow-hidden shadow-2xl border border-gray-200 bg-gray-900 aspect-video animate-fade-in-up animation-delay-500">
            <video 
              src={veo3DemoVideo}
              autoPlay
              loop
              muted
              playsInline
              className="w-full h-full object-cover"
              data-testid="video-demo"
            />
          </div>
        </div>
      </section>

      {/* Comprehensive AI Tools Section */}
      <section className="py-20 bg-gray-50" ref={toolsSectionRef}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12 scroll-reveal">
            <h2 className="font-heading text-3xl sm:text-4xl text-gray-900">
              Comprehensive AI Tools Powered by Veo3.pk
            </h2>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              {
                icon: Video,
                title: "VEO3.1 Video Generator",
                description: "Create stunning videos using Google's advanced VEO3.1 technology for professional-quality content generation.",
                href: "/veo-generator"
              },
              {
                icon: Image,
                title: "Text to Image AI",
                description: "Transform your text descriptions into beautiful, high-quality images with our powerful AI image generator.",
                href: "/text-to-image"
              },
              {
                icon: Mic,
                title: "Text to Speech",
                description: "Convert your text into natural-sounding speech with advanced AI-powered voice synthesis technology.",
                href: "/script-creator"
              },
              {
                icon: PlayCircle,
                title: "Image to Video",
                description: "Bring your static images to life by converting them into dynamic, engaging video content with AI.",
                href: "/image-to-video"
              },
              {
                icon: Wand2,
                title: "AI Script Creator",
                description: "Generate professional scripts and content with our intelligent AI script creator for your creative projects.",
                href: "/script-creator"
              },
              {
                icon: Users,
                title: "Character Consistent Videos",
                description: "Build character-consistent videos with AI technology that maintains visual coherence across your content.",
                href: "/character-consistent"
              },
            ].map((feature, index) => (
              <Link
                key={feature.title}
                href={feature.href}
                className={`group p-6 bg-white rounded-xl border border-gray-100 card-clickable ripple-effect scroll-reveal-scale stagger-${index + 1}`}
              >
                <div className="w-12 h-12 bg-gray-50 rounded-lg flex items-center justify-center mb-4 group-hover:bg-gray-100 transition-colors">
                  <feature.icon className="w-6 h-6 text-gray-400 group-hover:text-gray-700 transition-colors icon-bounce" />
                </div>
                <h3 className="font-heading text-lg text-gray-900 mb-2 group-hover:text-gray-700 transition-colors">
                  {feature.title}
                </h3>
                <p className="font-body text-sm text-gray-500 leading-relaxed">
                  {feature.description}
                </p>
              </Link>
            ))}
          </div>

          {/* Tagline */}
          <div className="text-center mt-12 scroll-reveal">
            <p className="font-body text-gray-500">
              Transform your creative workflow with cutting-edge AI technology for video, image, and content generation.
            </p>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-white border-t border-gray-100" ref={statsSectionRef}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12 scroll-reveal">
            <h2 className="font-heading text-3xl sm:text-4xl text-gray-900 mb-4">
              Powerful AI Tools for Content Creation
            </h2>
            <p className="font-body text-gray-500 max-w-2xl mx-auto">
              Transform your ideas into stunning videos, images, and audio with VEO3.pk's cutting-edge AI technology. Create professional content in minutes, not hours.
            </p>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {[
              { number: "10", suffix: "+", label: "AI Tools" },
              { number: videoStats.number, suffix: videoStats.suffix, label: "Videos Generated" },
              { number: "500", suffix: "+", label: "Active Users" },
              { number: "5000", suffix: "+", label: "Hours Saved" },
            ].map((stat, index) => (
              <div key={stat.label} className={`text-center p-6 scroll-reveal-scale stagger-${index + 1}`}>
                <div className="font-display text-4xl sm:text-5xl text-gray-900 mb-2">
                  {stat.number}<span className="text-gray-700">{stat.suffix}</span>
                </div>
                <p className="font-body-medium text-gray-500 text-sm">{stat.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why Choose VEO3.pk Section */}
      <section className="py-16 bg-gray-50" ref={whyChooseSectionRef}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
            {/* Left Content */}
            <div className="flex-1 scroll-reveal">
              {/* User Avatars & Rating */}
              <div className="flex items-center gap-3 mb-6">
                <div className="flex -space-x-2">
                  {[
                    "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=40&h=40&fit=crop&crop=face",
                    "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=40&h=40&fit=crop&crop=face",
                    "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=40&h=40&fit=crop&crop=face",
                    "https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=40&h=40&fit=crop&crop=face",
                    "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=40&h=40&fit=crop&crop=face",
                  ].map((src, i) => (
                    <img
                      key={i}
                      src={src}
                      alt={`User ${i + 1}`}
                      className="w-10 h-10 rounded-full border-2 border-white object-cover"
                    />
                  ))}
                </div>
                <div className="text-sm text-gray-600">
                  <span className="font-semibold text-gray-700">500+</span> Active Users (4.8 out of 5)
                </div>
              </div>

              {/* Decorative Wave */}
              <div className="mb-4">
                <svg width="120" height="12" viewBox="0 0 120 12" className="text-gray-300">
                  <path d="M0 6 Q 15 0, 30 6 T 60 6 T 90 6 T 120 6" stroke="currentColor" strokeWidth="2" fill="none"/>
                </svg>
              </div>

              {/* Headline */}
              <h2 className="font-heading text-3xl sm:text-4xl text-gray-900 mb-8 leading-tight">
                Why Choose VEO3.pk for AI Video<br />Generation & Content Creation?
              </h2>

              {/* Features Grid */}
              <div className="grid sm:grid-cols-2 gap-x-8 gap-y-3 mb-4">
                {[
                  "Google VEO3.1 Technology Powered",
                  `${videoStats.number}${videoStats.suffix} Videos Generated Successfully`,
                  "Advanced AI Image & Video Tools",
                  "24/7 Customer Support Available",
                  "Trusted by Content Creators Worldwide",
                  "Regular AI Model Updates",
                ].map((feature) => (
                  <div key={feature} className="flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-gray-400 flex-shrink-0" />
                    <span className="font-body-medium text-gray-600 text-sm">{feature}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Right CTA */}
            <div className="flex flex-col items-center lg:items-end gap-4 scroll-reveal stagger-2">
              <div className="text-right hidden lg:block">
                <span className="text-sm text-gray-500 italic">Explore</span>
                <span className="text-sm text-gray-500 italic block">Tools</span>
                <svg width="60" height="40" viewBox="0 0 60 40" className="text-gray-400 ml-auto mt-1">
                  <path d="M5 5 C 30 5, 45 20, 55 35" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round"/>
                  <path d="M45 30 L 55 35 L 50 25" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <Link
                href="/veo-generator"
                className="font-heading inline-flex items-center justify-center gap-2 px-8 py-4 bg-gray-800 text-white text-lg rounded-full hover:bg-gray-900 transition-all shadow-lg whitespace-nowrap card-clickable"
                data-testid="button-start-creating-now"
              >
                Start Creating Now
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 bg-white border-t border-gray-100">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <Link href="/" className="flex items-center">
              <img 
                src={veo3LogoImage} 
                alt="VEO3.pk" 
                className="h-14 w-auto"
                style={{ mixBlendMode: 'multiply' }}
                data-testid="img-footer-logo"
              />
            </Link>
            <p className="font-body text-sm text-gray-500">
              2024 VEO3.pk. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
