import { useState } from "react";
import { Link, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, Menu, X, Video, Image, FileText, Mic, Users, Wand2, PlayCircle } from "lucide-react";
import veo3LogoImage from "@assets/353a7b8a-2fec-4a2e-9fd9-76aa79711acb_removalai_preview_1764969657371.png";

export default function Navbar() {
  const [location] = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);

  const { data: session } = useQuery<{
    authenticated: boolean;
    user?: { username: string; isAdmin: boolean };
  }>({
    queryKey: ["/api/session"],
  });

  const videoGeneratorItems = [
    { name: "VEO3.1 Video Generator", href: "/veo-generator", icon: PlayCircle },
    { name: "Bulk Video Generator", href: "/bulk-generator", icon: Video },
    { name: "Image to Video", href: "/image-to-video", icon: Video },
    { name: "Character Videos", href: "/character-consistent", icon: Users },
  ];

  const textToolsItems = [
    { name: "Text to Image AI", href: "/text-to-image", icon: Image },
    { name: "Script Creator", href: "/script-creator", icon: FileText },
  ];

  const otherToolsItems = [
    { name: "Video History", href: "/history", icon: Video },
  ];

  const handleDropdownToggle = (dropdown: string) => {
    setActiveDropdown(activeDropdown === dropdown ? null : dropdown);
  };

  const handleMouseEnter = (dropdown: string) => {
    setActiveDropdown(dropdown);
  };

  const handleMouseLeave = () => {
    setActiveDropdown(null);
  };

  return (
    <nav className="bg-gray-50 z-50 w-full relative border-b border-gray-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex py-2 items-center justify-between">
          {/* Logo */}
          <div className="flex items-center">
            <Link href="/" className="flex items-center">
              <img 
                src={veo3LogoImage} 
                alt="VEO3" 
                className="h-12 w-auto"
                data-testid="img-navbar-logo"
              />
            </Link>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden lg:flex items-center gap-1 bg-gray-100 rounded-full px-2 py-1">
            <Link
              href="/"
              className={`px-5 py-2 rounded-full text-sm font-medium transition-all ${
                location === "/" 
                  ? "bg-white text-gray-900 shadow-sm" 
                  : "text-gray-600 hover:text-gray-900"
              }`}
            >
              Home
            </Link>

            {/* Video Generator Dropdown */}
            <div 
              className="relative"
              onMouseEnter={() => handleMouseEnter("video")}
              onMouseLeave={handleMouseLeave}
            >
              <button
                className={`inline-flex items-center gap-1 px-5 py-2 rounded-full text-sm font-medium transition-all ${
                  activeDropdown === "video" 
                    ? "bg-white text-gray-900 shadow-sm" 
                    : "text-gray-600 hover:text-gray-900"
                }`}
              >
                Video Generator
                <ChevronDown className={`w-4 h-4 transition-transform ${activeDropdown === "video" ? "rotate-180" : ""}`} />
              </button>
              {activeDropdown === "video" && (
                <div className="absolute top-full left-0 pt-2 z-50">
                  <div className="w-64 bg-white rounded-xl shadow-lg border border-gray-100 py-2">
                    {videoGeneratorItems.map((item) => (
                      <Link
                        key={item.href}
                        href={item.href}
                        className="flex items-center gap-3 px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <item.icon className="w-5 h-5 text-gray-600" />
                        {item.name}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Text Tools Dropdown */}
            <div 
              className="relative"
              onMouseEnter={() => handleMouseEnter("text")}
              onMouseLeave={handleMouseLeave}
            >
              <button
                className={`inline-flex items-center gap-1 px-5 py-2 rounded-full text-sm font-medium transition-all ${
                  activeDropdown === "text" 
                    ? "bg-white text-gray-900 shadow-sm" 
                    : "text-gray-600 hover:text-gray-900"
                }`}
              >
                Text Tools
                <ChevronDown className={`w-4 h-4 transition-transform ${activeDropdown === "text" ? "rotate-180" : ""}`} />
              </button>
              {activeDropdown === "text" && (
                <div className="absolute top-full left-0 pt-2 z-50">
                  <div className="w-56 bg-white rounded-xl shadow-lg border border-gray-100 py-2">
                    {textToolsItems.map((item) => (
                      <Link
                        key={item.href}
                        href={item.href}
                        className="flex items-center gap-3 px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <item.icon className="w-5 h-5 text-gray-600" />
                        {item.name}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Other Tools Dropdown */}
            <div 
              className="relative"
              onMouseEnter={() => handleMouseEnter("other")}
              onMouseLeave={handleMouseLeave}
            >
              <button
                className={`inline-flex items-center gap-1 px-5 py-2 rounded-full text-sm font-medium transition-all ${
                  activeDropdown === "other" 
                    ? "bg-white text-gray-900 shadow-sm" 
                    : "text-gray-600 hover:text-gray-900"
                }`}
              >
                Other Tools
                <ChevronDown className={`w-4 h-4 transition-transform ${activeDropdown === "other" ? "rotate-180" : ""}`} />
              </button>
              {activeDropdown === "other" && (
                <div className="absolute top-full left-0 pt-2 z-50">
                  <div className="w-48 bg-white rounded-xl shadow-lg border border-gray-100 py-2">
                    {otherToolsItems.map((item) => (
                      <Link
                        key={item.href}
                        href={item.href}
                        className="flex items-center gap-3 px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <item.icon className="w-5 h-5 text-gray-600" />
                        {item.name}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <Link
              href="/pricing"
              className={`px-5 py-2 rounded-full text-sm font-medium transition-all ${
                location === "/pricing" 
                  ? "bg-white text-gray-900 shadow-sm" 
                  : "text-gray-600 hover:text-gray-900"
              }`}
            >
              Pricing
            </Link>
          </div>

          {/* Right side buttons */}
          <div className="hidden lg:flex items-center gap-3">
            {session?.authenticated ? (
              <>
                {session.user?.isAdmin && (
                  <Link
                    href="/admin"
                    className="px-4 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 transition-colors"
                  >
                    Admin
                  </Link>
                )}
                <Link
                  href="/veo-generator"
                  className="px-5 py-2.5 bg-gray-800 text-white text-sm font-medium rounded-full hover:bg-gray-900 transition-colors shadow-md hover:shadow-lg"
                >
                  Dashboard
                </Link>
              </>
            ) : (
              <Link
                href="/login"
                className="px-5 py-2.5 bg-gray-800 text-white text-sm font-medium rounded-full hover:bg-gray-900 transition-colors shadow-md hover:shadow-lg"
              >
                Login
              </Link>
            )}
          </div>

          {/* Mobile menu button */}
          <button
            className="lg:hidden p-2 rounded-lg text-gray-600 hover:bg-gray-100"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile Navigation */}
        {mobileMenuOpen && (
          <div className="lg:hidden py-4 border-t border-gray-100">
            <div className="flex flex-col gap-2">
              <Link href="/" className="px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 rounded-lg">
                Home
              </Link>
              
              <div className="px-4 py-2">
                <button
                  onClick={() => handleDropdownToggle("mobile-video")}
                  className="flex items-center justify-between w-full text-sm font-medium text-gray-700"
                >
                  Video Generator
                  <ChevronDown className={`w-4 h-4 transition-transform ${activeDropdown === "mobile-video" ? "rotate-180" : ""}`} />
                </button>
                {activeDropdown === "mobile-video" && (
                  <div className="mt-2 pl-4 flex flex-col gap-1">
                    {videoGeneratorItems.map((item) => (
                      <Link
                        key={item.href}
                        href={item.href}
                        className="py-2 text-sm text-gray-600 hover:text-gray-900"
                      >
                        {item.name}
                      </Link>
                    ))}
                  </div>
                )}
              </div>

              <div className="px-4 py-2">
                <button
                  onClick={() => handleDropdownToggle("mobile-text")}
                  className="flex items-center justify-between w-full text-sm font-medium text-gray-700"
                >
                  Text Tools
                  <ChevronDown className={`w-4 h-4 transition-transform ${activeDropdown === "mobile-text" ? "rotate-180" : ""}`} />
                </button>
                {activeDropdown === "mobile-text" && (
                  <div className="mt-2 pl-4 flex flex-col gap-1">
                    {textToolsItems.map((item) => (
                      <Link
                        key={item.href}
                        href={item.href}
                        className="py-2 text-sm text-gray-600 hover:text-gray-900"
                      >
                        {item.name}
                      </Link>
                    ))}
                  </div>
                )}
              </div>

              <div className="px-4 py-2">
                <button
                  onClick={() => handleDropdownToggle("mobile-other")}
                  className="flex items-center justify-between w-full text-sm font-medium text-gray-700"
                >
                  Other Tools
                  <ChevronDown className={`w-4 h-4 transition-transform ${activeDropdown === "mobile-other" ? "rotate-180" : ""}`} />
                </button>
                {activeDropdown === "mobile-other" && (
                  <div className="mt-2 pl-4 flex flex-col gap-1">
                    {otherToolsItems.map((item) => (
                      <Link
                        key={item.href}
                        href={item.href}
                        className="py-2 text-sm text-gray-600 hover:text-gray-900"
                      >
                        {item.name}
                      </Link>
                    ))}
                  </div>
                )}
              </div>

              <Link href="/pricing" className="px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 rounded-lg">
                Pricing
              </Link>

              <div className="px-4 pt-4 flex flex-col gap-2 border-t border-gray-100 mt-2">
                {session?.authenticated ? (
                  <Link
                    href="/veo-generator"
                    className="w-full px-5 py-2.5 bg-gray-800 text-white text-sm font-medium rounded-full text-center"
                  >
                    Dashboard
                  </Link>
                ) : (
                  <Link
                    href="/login"
                    className="w-full px-5 py-2.5 bg-gray-800 text-white text-sm font-medium rounded-full text-center"
                  >
                    Login
                  </Link>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
}
