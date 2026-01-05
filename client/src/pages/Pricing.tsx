import { useQuery } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Check, 
  Crown, 
  Video, 
  Sparkles, 
  Wand2, 
  ImageIcon, 
  FileVideo, 
  Headphones, 
  CreditCard, 
  Wallet, 
  Smartphone, 
  Banknote, 
  Copy, 
  ArrowLeft, 
  Zap,
  X,
  Star,
  Shield,
  Clock,
  Infinity,
  MessageCircle,
  Users,
  Rocket,
  Gem
} from "lucide-react";
import { useLocation, Link } from "wouter";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

type PricingPlan = {
  id: string;
  name: string;
  subtitle: string | null;
  displayPrice: string;
  currency: string;
  period: string | null;
  alternatePrice: string | null;
  badge: string | null;
  badgeColor: string;
  iconType: string;
  highlightBorder: boolean;
  featuresIntro: string | null;
  features: string;
  buttonText: string;
  buttonAction: string;
  position: number;
  isActive: boolean;
};

type PlanFeature = {
  icon?: string;
  text: string;
  included: boolean;
  subtext?: string;
};

const getIconComponent = (iconType: string) => {
  const icons: Record<string, any> = {
    zap: Zap,
    crown: Crown,
    users: Users,
    star: Star,
    sparkles: Sparkles,
    shield: Shield,
    rocket: Rocket,
    gem: Gem,
  };
  return icons[iconType] || Zap;
};

const getIconGradient = (iconType: string, isHighlight: boolean) => {
  if (isHighlight) {
    return "from-amber-500 via-orange-500 to-rose-500";
  }
  const gradients: Record<string, string> = {
    zap: "from-blue-500 to-cyan-500",
    crown: "from-amber-500 via-orange-500 to-rose-500",
    users: "from-purple-500 via-violet-500 to-indigo-500",
    star: "from-emerald-500 to-teal-500",
    sparkles: "from-pink-500 to-rose-500",
    shield: "from-slate-500 to-gray-600",
    rocket: "from-red-500 to-orange-500",
    gem: "from-violet-500 to-purple-500",
  };
  return gradients[iconType] || "from-blue-500 to-cyan-500";
};

const getBadgeColor = (badgeColor: string) => {
  const colors: Record<string, string> = {
    default: "bg-gray-100 text-gray-600 border-gray-200",
    green: "bg-emerald-100 text-emerald-600 border-emerald-200",
    orange: "bg-orange-100 text-orange-600 border-orange-200",
    purple: "bg-purple-100 text-purple-600 border-purple-200",
    blue: "bg-blue-100 text-blue-600 border-blue-200",
  };
  return colors[badgeColor] || colors.default;
};

const getButtonGradient = (iconType: string, isHighlight: boolean) => {
  if (isHighlight) {
    return "from-amber-500 via-orange-500 to-rose-500 hover:from-amber-600 hover:via-orange-600 hover:to-rose-600 shadow-amber-500/25";
  }
  const gradients: Record<string, string> = {
    zap: "from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 shadow-blue-500/25",
    crown: "from-amber-500 via-orange-500 to-rose-500 hover:from-amber-600 hover:via-orange-600 hover:to-rose-600 shadow-amber-500/25",
    users: "from-purple-500 via-violet-500 to-indigo-500 hover:from-purple-600 hover:via-violet-600 hover:to-indigo-600 shadow-purple-500/25",
    star: "from-emerald-500 to-teal-500 hover:from-emerald-600 hover:to-teal-600 shadow-emerald-500/25",
    sparkles: "from-pink-500 to-rose-500 hover:from-pink-600 hover:to-rose-600 shadow-pink-500/25",
    shield: "from-slate-500 to-gray-600 hover:from-slate-600 hover:to-gray-700 shadow-slate-500/25",
    rocket: "from-red-500 to-orange-500 hover:from-red-600 hover:to-orange-600 shadow-red-500/25",
    gem: "from-violet-500 to-purple-500 hover:from-violet-600 hover:to-purple-600 shadow-violet-500/25",
  };
  return gradients[iconType] || gradients.zap;
};

const getFeatureIconBg = (iconType: string, included: boolean, isHighlight: boolean) => {
  if (!included) return "bg-gray-100";
  if (isHighlight) return "bg-amber-100";
  const colors: Record<string, string> = {
    zap: "bg-blue-100",
    crown: "bg-amber-100",
    users: "bg-purple-100",
    star: "bg-emerald-100",
    sparkles: "bg-pink-100",
    shield: "bg-gray-100",
    rocket: "bg-red-100",
    gem: "bg-violet-100",
  };
  return colors[iconType] || "bg-emerald-100";
};

const getFeatureCheckColor = (iconType: string, isHighlight: boolean) => {
  if (isHighlight) return "text-amber-600";
  const colors: Record<string, string> = {
    zap: "text-blue-600",
    crown: "text-amber-600",
    users: "text-purple-600",
    star: "text-emerald-600",
    sparkles: "text-pink-600",
    shield: "text-gray-600",
    rocket: "text-red-600",
    gem: "text-violet-600",
  };
  return colors[iconType] || "text-emerald-600";
};

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

type User = {
  id: string;
  username: string;
  isAdmin: boolean;
  planType: string;
  planStatus: string;
  planExpiry: string | null;
  dailyVideoCount: number;
};

type PaymentMethod = {
  id: string;
  name: string;
  icon: any;
  color: string;
  details: {
    accountTitle?: string;
    accountNumber?: string;
    iban?: string;
    binanceId?: string;
    bankName?: string;
  };
};

const paymentMethods: PaymentMethod[] = [
  {
    id: "bank_transfer",
    name: "Bank Transfer",
    icon: CreditCard,
    color: "from-gray-500 to-slate-600",
    details: {
      bankName: "UBL",
      accountTitle: "Muhammad Faizan",
      accountNumber: "0962323372811",
      iban: "PK96UNIL0109000323372811",
    },
  },
  {
    id: "binance",
    name: "Binance (USDT)",
    icon: Wallet,
    color: "from-amber-500 to-orange-600",
    details: {
      binanceId: "1052981795",
    },
  },
  {
    id: "easypaisa",
    name: "EasyPaisa",
    icon: Smartphone,
    color: "from-emerald-500 to-green-600",
    details: {
      accountTitle: "Muhammad Faizan",
      accountNumber: "03706250122",
    },
  },
  {
    id: "jazzcash",
    name: "JazzCash",
    icon: Banknote,
    color: "from-pink-500 to-rose-600",
    details: {
      accountTitle: "Muhammad Faizan",
      accountNumber: "03706250122",
    },
  },
];

const scaleFeatures = [
  { icon: Video, text: "Bulk Video Generation", included: true },
  { icon: Clock, text: "30s between batches", included: true, subtext: "Slow Speed" },
  { icon: Sparkles, text: "VEO 3 Video Generation", included: true },
  { icon: Shield, text: "1,000 videos/day limit", included: true },
  { icon: Wand2, text: "Script Generator", included: false },
  { icon: ImageIcon, text: "Text to Image", included: false },
  { icon: FileVideo, text: "Image to Video", included: false },
  { icon: Users, text: "Character Videos", included: false },
  { icon: Headphones, text: "VIP Support", included: false },
];

const empireFeatures = [
  { icon: Video, text: "Bulk Video Generation", included: true },
  { icon: Zap, text: "Fast Speed", included: true, subtext: "Priority Processing" },
  { icon: Sparkles, text: "VEO 3.1 Video Generation", included: true },
  { icon: Infinity, text: "Unlimited videos/day", included: true },
  { icon: Wand2, text: "Script Generator", included: true },
  { icon: ImageIcon, text: "Text to Image", included: true },
  { icon: FileVideo, text: "Image to Video", included: true },
  { icon: Users, text: "Character Videos", included: true },
  { icon: Headphones, text: "VIP Support", included: true },
];

export default function Pricing() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [showPaymentDialog, setShowPaymentDialog] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState<{ name: string; price: string } | null>(null);
  const [selectedPaymentMethod, setSelectedPaymentMethod] = useState<PaymentMethod | null>(null);
  
  const { data: session } = useQuery<{ authenticated: boolean; user?: User }>({
    queryKey: ["/api/session"],
  });

  const { data: planAvailabilityData } = useQuery<{ availability: { scalePlanAvailable: boolean; empirePlanAvailable: boolean } }>({
    queryKey: ["/api/plan-availability"],
  });

  const { data: whatsappData } = useQuery<{ settings?: { whatsappUrl?: string } }>({
    queryKey: ["/api/app-settings"],
  });

  const { data: customPlansData } = useQuery<{ plans: PricingPlan[] }>({
    queryKey: ["/api/pricing-plans"],
  });

  const customPlans = customPlansData?.plans?.filter(p => p.isActive) || [];

  const user = session?.user;
  const isAuthenticated = session?.authenticated;

  const handlePlanAction = (planId: string, planName: string, price: string) => {
    if (isAuthenticated && user?.planType === planId) {
      setLocation("/");
      return;
    }

    setSelectedPlan({ name: planName, price });
    setSelectedPaymentMethod(null);
    setShowPaymentDialog(true);
  };

  const handlePaymentMethodSelect = (method: PaymentMethod) => {
    setSelectedPaymentMethod(method);
  };

  const handleBackToMethods = () => {
    setSelectedPaymentMethod(null);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied!",
      description: `${label} copied to clipboard`,
    });
  };

  const isCurrentPlan = (planId: string) => user?.planType === planId;

  const handleCustomPlanAction = (plan: PricingPlan) => {
    if (plan.buttonAction === "disabled") return;
    if (plan.buttonAction === "current_plan" && isAuthenticated && isCurrentPlan(plan.name.toLowerCase())) {
      setLocation("/");
      return;
    }
    if (plan.buttonAction === "contact_sales" && whatsappData?.settings?.whatsappUrl) {
      window.open(whatsappData.settings.whatsappUrl, "_blank");
      return;
    }
    if (plan.buttonAction === "payment_dialog") {
      const priceDisplay = plan.alternatePrice 
        ? `${plan.displayPrice} ${plan.currency} / ${plan.alternatePrice}`
        : `${plan.displayPrice} ${plan.currency}`;
      setSelectedPlan({ name: plan.name, price: priceDisplay });
      setSelectedPaymentMethod(null);
      setShowPaymentDialog(true);
    }
  };

  const getButtonDisabled = (plan: PricingPlan) => {
    if (plan.buttonAction === "disabled") return true;
    if (plan.buttonAction === "current_plan" && isAuthenticated && isCurrentPlan(plan.name.toLowerCase())) return false;
    if (plan.buttonAction === "contact_sales" && !whatsappData?.settings?.whatsappUrl) return true;
    return false;
  };

  const getButtonText = (plan: PricingPlan) => {
    if (isAuthenticated && isCurrentPlan(plan.name.toLowerCase())) {
      return "Current Plan";
    }
    return plan.buttonText;
  };

  const renderDynamicPlanCard = (plan: PricingPlan) => {
    const IconComponent = getIconComponent(plan.iconType);
    const iconGradient = getIconGradient(plan.iconType, plan.highlightBorder);
    const buttonGradient = getButtonGradient(plan.iconType, plan.highlightBorder);
    
    let features: PlanFeature[] = [];
    try {
      features = JSON.parse(plan.features) || [];
    } catch {
      features = [];
    }

    return (
      <div key={plan.id} className="relative group" data-testid={`card-plan-${plan.name.toLowerCase()}`}>
        <div className={`absolute inset-0 bg-gradient-to-b ${plan.highlightBorder ? 'from-amber-500/30' : `from-${plan.iconType === 'users' ? 'purple' : 'blue'}-500/20`} to-transparent rounded-3xl blur-xl opacity-${plan.highlightBorder ? '50' : '0'} group-hover:opacity-100 transition-opacity duration-500`} />
        {plan.highlightBorder && (
          <div className="absolute -inset-[1px] bg-gradient-to-b from-amber-400 via-orange-400/50 to-transparent rounded-3xl" />
        )}
        
        <Card className={`relative bg-white ${plan.highlightBorder ? 'border-0' : 'border-gray-200 hover:border-blue-300 hover:shadow-xl hover:shadow-blue-500/10'} rounded-3xl overflow-hidden transition-all duration-500 h-full flex flex-col`}>
          {plan.badge && plan.highlightBorder && (
            <div className="absolute top-0 right-0 overflow-hidden w-32 h-32">
              <div className="absolute top-4 right-[-35px] transform rotate-45 bg-gradient-to-r from-amber-500 to-orange-500 text-white text-xs font-bold py-1.5 px-10 shadow-lg">
                {plan.badge}
              </div>
            </div>
          )}

          <div className="p-8 pb-6">
            <div className="flex items-start justify-between mb-6">
              <div>
                <div className={`inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br ${iconGradient} shadow-lg shadow-${plan.iconType === 'crown' ? 'amber' : 'blue'}-500/25 mb-4`}>
                  <IconComponent className="w-7 h-7 text-white" />
                </div>
                <h2 className="text-2xl font-bold text-gray-900">{plan.name}</h2>
                {plan.subtitle && <p className="text-gray-500 text-sm mt-1">{plan.subtitle}</p>}
              </div>
              {plan.badge && !plan.highlightBorder && (
                <Badge className={`${getBadgeColor(plan.badgeColor)} px-3 py-1`}>
                  {plan.badge}
                </Badge>
              )}
            </div>

            <div className="flex items-baseline gap-2 mb-1">
              <span className={`text-5xl font-bold ${plan.highlightBorder ? 'bg-gradient-to-r from-amber-500 to-orange-500 bg-clip-text text-transparent' : 'text-gray-900'}`}>
                {plan.displayPrice}
              </span>
              {plan.currency && <span className="text-xl text-gray-500">{plan.currency}</span>}
            </div>
            {plan.period && <p className="text-gray-500 text-sm">{plan.period}</p>}
            {plan.alternatePrice && (
              <div className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-50 border border-emerald-200 rounded-full">
                <span className="text-emerald-700 text-sm font-semibold">{plan.alternatePrice}</span>
              </div>
            )}
          </div>

          <div className="h-px bg-gradient-to-r from-transparent via-gray-200 to-transparent" />

          <div className="p-8 pt-6 flex-1 flex flex-col">
            {plan.featuresIntro && (
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-4">{plan.featuresIntro}</p>
            )}
            <div className="space-y-4 flex-1">
              {features.map((feature, index) => (
                <div key={index} className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${getFeatureIconBg(plan.iconType, feature.included, plan.highlightBorder)}`}>
                    {feature.included ? (
                      <Check className={`w-4 h-4 ${getFeatureCheckColor(plan.iconType, plan.highlightBorder)}`} />
                    ) : (
                      <X className="w-4 h-4 text-gray-400" />
                    )}
                  </div>
                  <div className="flex-1">
                    <span className={feature.included ? 'text-gray-700' : 'text-gray-400'}>
                      {feature.text}
                    </span>
                    {feature.subtext && (
                      <span className={`ml-2 text-xs px-2 py-0.5 rounded-full ${
                        feature.subtext.toLowerCase().includes('slow') 
                          ? 'bg-amber-100 text-amber-600' 
                          : 'bg-emerald-100 text-emerald-600'
                      }`}>
                        {feature.subtext}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            <Button
              className={`w-full mt-8 bg-gradient-to-r ${buttonGradient} text-white border-0 shadow-lg h-12 text-base font-semibold rounded-xl transition-all duration-300`}
              onClick={() => handleCustomPlanAction(plan)}
              disabled={getButtonDisabled(plan)}
              data-testid={`button-select-${plan.name.toLowerCase()}`}
            >
              {plan.buttonAction === "contact_sales" && <MessageCircle className="w-4 h-4 mr-2" />}
              {getButtonText(plan)}
            </Button>
          </div>
        </Card>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-white">
      {/* Background Effects - Light Theme */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-blue-100/50 rounded-full blur-[120px]" />
        <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-purple-100/50 rounded-full blur-[120px]" />
      </div>

      {/* Header */}
      <header className="relative z-50 border-b border-gray-200 bg-white/80 backdrop-blur-xl sticky top-0">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-[#374151] to-[#1f2937] shadow-lg">
              <Crown className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-gray-900">Pricing Plans</h1>
              <p className="text-xs text-gray-500">Choose your perfect plan</p>
            </div>
          </div>
          <Link href="/">
            <Button 
              variant="outline" 
              size="sm" 
              className="border-gray-300 bg-white text-gray-700 hover:bg-gray-50 hover:text-gray-900 transition-all duration-300"
              data-testid="link-home"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back
            </Button>
          </Link>
        </div>
      </header>

      {/* Main Content */}
      <div className="relative z-10 container mx-auto px-4 py-16 md:py-24">
        {/* Hero Section */}
        <div className="text-center mb-16 md:mb-20">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-gray-100 border border-gray-200 mb-6">
            <Star className="w-4 h-4 text-amber-500" />
            <span className="text-sm text-gray-600">Trusted by 1000+ content creators</span>
          </div>
          
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-gray-900 leading-tight">
            Simple, Transparent
            <br />
            <span className="bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 bg-clip-text text-transparent">
              Pricing
            </span>
          </h1>
          
          <p className="text-lg text-gray-600 max-w-2xl mx-auto mb-8">
            Choose the plan that fits your needs. Upgrade or downgrade anytime.
            No hidden fees, no surprises.
          </p>

          {isAuthenticated && user && (
            <div className="inline-flex items-center gap-3 px-5 py-3 rounded-2xl bg-gray-100 border border-gray-200">
              <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-gray-600">
                Current Plan: <span className="font-semibold text-gray-900">{user.planType.charAt(0).toUpperCase() + user.planType.slice(1)}</span>
              </span>
            </div>
          )}
        </div>

        {/* Pricing Cards */}
        <div className={`grid ${customPlans.length > 0 ? (customPlans.length === 1 ? 'lg:grid-cols-1 max-w-md' : customPlans.length === 2 ? 'lg:grid-cols-2 max-w-4xl' : 'lg:grid-cols-3 max-w-6xl') : 'lg:grid-cols-3 max-w-6xl'} gap-6 lg:gap-8 mx-auto`}>
          
          {customPlans.length > 0 ? (
            customPlans.map(plan => renderDynamicPlanCard(plan))
          ) : (
            <>
          {/* Scale Plan */}
          <div className="relative group" data-testid="card-plan-scale">
            <div className="absolute inset-0 bg-gradient-to-b from-blue-500/20 to-transparent rounded-3xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            
            <Card className="relative bg-white border-gray-200 rounded-3xl overflow-hidden hover:border-blue-300 hover:shadow-xl hover:shadow-blue-500/10 transition-all duration-500">
              {/* Card Header */}
              <div className="p-8 pb-6">
                <div className="flex items-start justify-between mb-6">
                  <div>
                    <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-500 shadow-lg shadow-blue-500/25 mb-4">
                      <Zap className="w-7 h-7 text-white" />
                    </div>
                    <h2 className="text-2xl font-bold text-gray-900">Scale</h2>
                    <p className="text-gray-500 text-sm mt-1">For starters</p>
                  </div>
                  <Badge className="bg-blue-100 text-blue-600 border-blue-200 px-3 py-1">
                    Popular
                  </Badge>
                </div>

                <div className="flex items-baseline gap-2 mb-2">
                  <span className="text-5xl font-bold text-gray-900">900</span>
                  <span className="text-xl text-gray-500">PKR</span>
                </div>
                <p className="text-gray-500 text-sm">per 10 days</p>
              </div>

              {/* Divider */}
              <div className="h-px bg-gradient-to-r from-transparent via-gray-200 to-transparent" />

              {/* Features List */}
              <div className="p-8 pt-6">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-4">What's included</p>
                <div className="space-y-4">
                  {scaleFeatures.map((feature, index) => {
                    const Icon = feature.icon;
                    return (
                      <div key={index} className="flex items-center gap-3">
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                          feature.included 
                            ? 'bg-emerald-100' 
                            : 'bg-gray-100'
                        }`}>
                          {feature.included ? (
                            <Check className="w-4 h-4 text-emerald-600" />
                          ) : (
                            <X className="w-4 h-4 text-gray-400" />
                          )}
                        </div>
                        <div className="flex-1">
                          <span className={feature.included ? 'text-gray-700' : 'text-gray-400'}>
                            {feature.text}
                          </span>
                          {feature.subtext && (
                            <span className={`ml-2 text-xs px-2 py-0.5 rounded-full ${
                              feature.subtext === 'Slow Speed' 
                                ? 'bg-amber-100 text-amber-600' 
                                : 'bg-emerald-100 text-emerald-600'
                            }`}>
                              {feature.subtext}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <Button
                  className="w-full mt-8 bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 text-white border-0 shadow-lg shadow-blue-500/25 h-12 text-base font-semibold rounded-xl transition-all duration-300"
                  onClick={() => handlePlanAction("scale", "Scale", "900 PKR")}
                  disabled={isCurrentPlan("scale") || !planAvailabilityData?.availability?.scalePlanAvailable}
                  data-testid="button-select-scale"
                >
                  {isCurrentPlan("scale") 
                    ? "Current Plan" 
                    : planAvailabilityData?.availability?.scalePlanAvailable === false 
                      ? "Not Available" 
                      : "Get Started"}
                </Button>
              </div>
            </Card>
          </div>

          {/* Empire Plan */}
          <div className="relative group" data-testid="card-plan-empire">
            <div className="absolute inset-0 bg-gradient-to-b from-amber-500/30 to-transparent rounded-3xl blur-xl opacity-50 group-hover:opacity-100 transition-opacity duration-500" />
            <div className="absolute -inset-[1px] bg-gradient-to-b from-amber-400 via-orange-400/50 to-transparent rounded-3xl" />
            
            <Card className="relative bg-white border-0 rounded-3xl overflow-hidden">
              {/* Best Value Badge */}
              <div className="absolute top-0 right-0 overflow-hidden w-32 h-32">
                <div className="absolute top-4 right-[-35px] transform rotate-45 bg-gradient-to-r from-amber-500 to-orange-500 text-white text-xs font-bold py-1.5 px-10 shadow-lg">
                  BEST VALUE
                </div>
              </div>

              {/* Card Header */}
              <div className="p-8 pb-6">
                <div className="flex items-start justify-between mb-6">
                  <div>
                    <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-amber-500 via-orange-500 to-rose-500 shadow-lg shadow-amber-500/25 mb-4">
                      <Crown className="w-7 h-7 text-white" />
                    </div>
                    <h2 className="text-2xl font-bold text-gray-900">Empire</h2>
                    <p className="text-gray-500 text-sm mt-1">For professionals</p>
                  </div>
                </div>

                <div className="flex items-baseline gap-2 mb-1">
                  <span className="text-5xl font-bold bg-gradient-to-r from-amber-500 to-orange-500 bg-clip-text text-transparent">1500</span>
                  <span className="text-xl text-gray-500">PKR</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-500 text-sm">per 10 days</span>
                </div>
                <div className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-50 border border-emerald-200 rounded-full">
                  <span className="text-emerald-700 text-sm font-semibold">$10 USD</span>
                  <span className="text-emerald-600 text-xs">for International</span>
                </div>
              </div>

              {/* Divider */}
              <div className="h-px bg-gradient-to-r from-transparent via-amber-300 to-transparent" />

              {/* Features List */}
              <div className="p-8 pt-6">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-4">Everything in Scale, plus</p>
                <div className="space-y-4">
                  {empireFeatures.map((feature, index) => {
                    const Icon = feature.icon;
                    return (
                      <div key={index} className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-amber-100">
                          <Check className="w-4 h-4 text-amber-600" />
                        </div>
                        <div className="flex-1">
                          <span className="text-gray-700">{feature.text}</span>
                          {feature.subtext && (
                            <span className="ml-2 text-xs px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-600">
                              {feature.subtext}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <Button
                  className="w-full mt-8 bg-gradient-to-r from-amber-500 via-orange-500 to-rose-500 hover:from-amber-600 hover:via-orange-600 hover:to-rose-600 text-white border-0 shadow-lg shadow-amber-500/25 h-12 text-base font-semibold rounded-xl transition-all duration-300"
                  onClick={() => handlePlanAction("empire", "Empire", "1500 PKR / $10")}
                  disabled={isCurrentPlan("empire") || !planAvailabilityData?.availability?.empirePlanAvailable}
                  data-testid="button-select-empire"
                >
                  {isCurrentPlan("empire") 
                    ? "Current Plan" 
                    : planAvailabilityData?.availability?.empirePlanAvailable === false 
                      ? "Not Available" 
                      : "Upgrade to Empire"}
                </Button>
              </div>
            </Card>
          </div>

          {/* Enterprise Plan */}
          <div className="relative group" data-testid="card-plan-enterprise">
            <div className="absolute inset-0 bg-gradient-to-b from-purple-500/20 to-transparent rounded-3xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            
            <Card className="relative bg-white border-gray-200 rounded-3xl overflow-hidden hover:border-purple-300 hover:shadow-xl hover:shadow-purple-500/10 transition-all duration-500 h-full flex flex-col">
              {/* Card Header */}
              <div className="p-8 pb-6">
                <div className="flex items-start justify-between mb-6">
                  <div>
                    <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-purple-500 via-violet-500 to-indigo-500 shadow-lg shadow-purple-500/25 mb-4">
                      <Users className="w-7 h-7 text-white" />
                    </div>
                    <h2 className="text-2xl font-bold text-gray-900">Enterprise</h2>
                    <p className="text-gray-500 text-sm mt-1">For businesses</p>
                  </div>
                </div>

                <div className="flex items-baseline gap-2 mb-2">
                  <span className="text-3xl font-bold text-gray-900">Custom</span>
                </div>
                <p className="text-gray-500 text-sm">Tailored to your needs</p>
              </div>

              {/* Divider */}
              <div className="h-px bg-gradient-to-r from-transparent via-purple-300 to-transparent" />

              {/* Features List */}
              <div className="p-8 pt-6 flex-1 flex flex-col">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-4">Everything in Empire, plus</p>
                <div className="space-y-4 flex-1">
                  {[
                    { text: "Custom video limits", included: true },
                    { text: "Dedicated API tokens", included: true },
                    { text: "Priority queue access", included: true },
                    { text: "Custom billing options", included: true },
                    { text: "Dedicated support", included: true },
                    { text: "Custom integrations", included: true },
                  ].map((feature, index) => (
                    <div key={index} className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-purple-100">
                        <Check className="w-4 h-4 text-purple-600" />
                      </div>
                      <span className="text-gray-700">{feature.text}</span>
                    </div>
                  ))}
                </div>

                {whatsappData?.settings?.whatsappUrl ? (
                  <a 
                    href={whatsappData.settings.whatsappUrl} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="w-full mt-8"
                  >
                    <Button
                      className="w-full bg-gradient-to-r from-purple-500 via-violet-500 to-indigo-500 hover:from-purple-600 hover:via-violet-600 hover:to-indigo-600 text-white border-0 shadow-lg shadow-purple-500/25 h-12 text-base font-semibold rounded-xl transition-all duration-300"
                      data-testid="button-contact-enterprise"
                    >
                      <MessageCircle className="w-4 h-4 mr-2" />
                      Contact Sales
                    </Button>
                  </a>
                ) : (
                  <Button
                    className="w-full mt-8 bg-gradient-to-r from-purple-500 via-violet-500 to-indigo-500 hover:from-purple-600 hover:via-violet-600 hover:to-indigo-600 text-white border-0 shadow-lg shadow-purple-500/25 h-12 text-base font-semibold rounded-xl transition-all duration-300"
                    disabled
                    data-testid="button-contact-enterprise"
                  >
                    <MessageCircle className="w-4 h-4 mr-2" />
                    Contact Us
                  </Button>
                )}
              </div>
            </Card>
          </div>
            </>
          )}
        </div>

        {/* FAQ / Contact Section */}
        <div className="mt-24 text-center">
          <div className="inline-flex flex-col items-center gap-4 p-8 rounded-3xl bg-gray-50 border border-gray-200">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-[#374151] to-[#1f2937] flex items-center justify-center">
              <MessageCircle className="w-7 h-7 text-white" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-gray-900 mb-2">Have Questions?</h3>
              <p className="text-gray-600 mb-4">Our team is here to help you choose the right plan</p>
            </div>
            {whatsappData?.settings?.whatsappUrl && (
              <a 
                href={whatsappData.settings.whatsappUrl} 
                target="_blank" 
                rel="noopener noreferrer"
              >
                <Button className="bg-emerald-500 hover:bg-emerald-600 text-white px-6">
                  <MessageCircle className="w-4 h-4 mr-2" />
                  Chat on WhatsApp
                </Button>
              </a>
            )}
          </div>
        </div>
      </div>

      {/* Payment Method Dialog */}
      <Dialog open={showPaymentDialog} onOpenChange={setShowPaymentDialog}>
        <DialogContent className="bg-white border-gray-200 text-gray-900 max-w-md max-h-[90vh] flex flex-col rounded-2xl">
          {!selectedPaymentMethod ? (
            <>
              <DialogHeader>
                <DialogTitle className="text-xl font-bold text-gray-900 mb-1">
                  Select Payment Method
                </DialogTitle>
                <p className="text-gray-500 text-sm">
                  {selectedPlan?.name} plan - {selectedPlan?.price}
                </p>
              </DialogHeader>

              <div className="grid grid-cols-2 gap-4 mt-6">
                {paymentMethods.map((method) => {
                  const Icon = method.icon;
                  return (
                    <button
                      key={method.id}
                      onClick={() => handlePaymentMethodSelect(method)}
                      className="flex flex-col items-center gap-3 p-5 rounded-xl bg-gray-50 border border-gray-200 hover:border-gray-400 hover:bg-gray-100 transition-all duration-300 group"
                      data-testid={`button-payment-${method.id}`}
                    >
                      <div className={`w-14 h-14 rounded-xl bg-gradient-to-br ${method.color} flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300`}>
                        <Icon className="w-7 h-7 text-white" />
                      </div>
                      <span className="text-gray-700 font-medium text-sm text-center">{method.name}</span>
                    </button>
                  );
                })}
              </div>

              <div className="mt-6 text-center">
                <Link href="/">
                  <Button variant="ghost" className="text-gray-500 hover:text-gray-900" data-testid="link-back-home">
                    Cancel
                  </Button>
                </Link>
              </div>
            </>
          ) : (
            <>
              <DialogHeader className="flex-shrink-0">
                <div className="flex items-center gap-3 mb-2">
                  <button
                    onClick={handleBackToMethods}
                    className="p-2.5 rounded-xl bg-gray-100 hover:bg-gray-200 transition-colors"
                    data-testid="button-back-to-methods"
                  >
                    <ArrowLeft className="w-4 h-4 text-gray-600" />
                  </button>
                  <div>
                    <DialogTitle className="text-xl font-bold text-gray-900">
                      {selectedPaymentMethod.name}
                    </DialogTitle>
                    <p className="text-gray-500 text-xs">
                      {selectedPlan?.name} plan - {selectedPlan?.price}
                    </p>
                  </div>
                </div>
              </DialogHeader>

              <div className="space-y-3 mt-4 overflow-y-auto flex-1">
                {selectedPaymentMethod.details.bankName && (
                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                    <label className="text-gray-500 text-xs block mb-1.5">Bank Name</label>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-gray-900 font-medium">{selectedPaymentMethod.details.bankName}</span>
                      <Button
                        onClick={() => copyToClipboard(selectedPaymentMethod.details.bankName!, "Bank Name")}
                        size="icon"
                        variant="ghost"
                        className="text-gray-500 hover:text-gray-900 h-8 w-8"
                        data-testid="button-copy-bank-name"
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {selectedPaymentMethod.details.accountTitle && (
                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                    <label className="text-gray-500 text-xs block mb-1.5">Account Title</label>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-gray-900 font-medium">{selectedPaymentMethod.details.accountTitle}</span>
                      <Button
                        onClick={() => copyToClipboard(selectedPaymentMethod.details.accountTitle!, "Account Title")}
                        size="icon"
                        variant="ghost"
                        className="text-gray-500 hover:text-gray-900 h-8 w-8"
                        data-testid="button-copy-account-title"
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {selectedPaymentMethod.details.accountNumber && (
                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                    <label className="text-gray-500 text-xs block mb-1.5">Account Number</label>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-gray-900 font-medium font-mono">{selectedPaymentMethod.details.accountNumber}</span>
                      <Button
                        onClick={() => copyToClipboard(selectedPaymentMethod.details.accountNumber!, "Account Number")}
                        size="icon"
                        variant="ghost"
                        className="text-gray-500 hover:text-gray-900 h-8 w-8"
                        data-testid="button-copy-account-number"
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {selectedPaymentMethod.details.iban && (
                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                    <label className="text-gray-500 text-xs block mb-1.5">IBAN Number</label>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-gray-900 font-medium font-mono text-sm">{selectedPaymentMethod.details.iban}</span>
                      <Button
                        onClick={() => copyToClipboard(selectedPaymentMethod.details.iban!, "IBAN")}
                        size="icon"
                        variant="ghost"
                        className="text-gray-500 hover:text-gray-900 h-8 w-8"
                        data-testid="button-copy-iban"
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {selectedPaymentMethod.details.binanceId && (
                  <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                    <label className="text-gray-500 text-xs block mb-1.5">Binance Pay ID</label>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-gray-900 font-medium font-mono">{selectedPaymentMethod.details.binanceId}</span>
                      <Button
                        onClick={() => copyToClipboard(selectedPaymentMethod.details.binanceId!, "Binance ID")}
                        size="icon"
                        variant="ghost"
                        className="text-gray-500 hover:text-gray-900 h-8 w-8"
                        data-testid="button-copy-binance-id"
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {/* Instructions */}
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mt-4">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-lg bg-amber-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Shield className="w-4 h-4 text-amber-600" />
                    </div>
                    <div>
                      <p className="text-amber-700 font-medium text-sm mb-1">Important</p>
                      <p className="text-gray-600 text-xs leading-relaxed">
                        After payment, send screenshot on WhatsApp with your username to activate your plan within 24 hours.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* WhatsApp Button */}
              {whatsappData?.settings?.whatsappUrl && (
                <div className="mt-4 flex-shrink-0">
                  <a 
                    href={whatsappData.settings.whatsappUrl} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="block"
                  >
                    <Button 
                      className="w-full bg-emerald-500 hover:bg-emerald-600 text-white h-12 text-base font-semibold rounded-xl"
                      data-testid="button-whatsapp-contact"
                    >
                      <MessageCircle className="w-5 h-5 mr-2" />
                      Send Payment Proof on WhatsApp
                    </Button>
                  </a>
                </div>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
