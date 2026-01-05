import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useEffect, useState, useMemo, useRef } from "react";
import { SystemMonitor } from "@/components/SystemMonitor";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";


import { Shield, LogOut, UserPlus, Home, Edit, Key, Calendar, RefreshCw, TrendingUp, CheckCircle, XCircle, Clock, AlertCircle, Trash2, XOctagon, MessageCircle, Wrench, Users, Settings, DollarSign, History as HistoryIcon, FileText, Activity, ImageIcon, Copy, Check, Shuffle, Eraser, X, Save, Plus, Power, Zap, Download, Database, RotateCcw, Eye, HardDrive, Mic } from "lucide-react";

const createUserSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  isAdmin: z.boolean().default(false),
  planType: z.enum(["free", "scale", "empire", "enterprise"]).default("free"),
  dailyVideoLimit: z.number().int().min(0).optional(),
  expiryDays: z.number().int().min(1).optional(),
  bulkMaxBatch: z.number().int().min(1).optional(),
  bulkDelaySeconds: z.number().int().min(0).optional(),
  bulkMaxPrompts: z.number().int().min(1).optional(),
});

const updatePlanSchema = z.object({
  planType: z.enum(["free", "scale", "empire", "enterprise"]),
  planStatus: z.enum(["active", "expired", "cancelled"]),
  planExpiry: z.string().optional(),
  dailyVideoLimit: z.number().int().min(0).optional(),
  expiryDays: z.number().int().min(1).optional(),
  bulkMaxBatch: z.number().int().min(1).optional(),
  bulkDelaySeconds: z.number().int().min(0).optional(),
  bulkMaxPrompts: z.number().int().min(1).optional(),
});

const updateTokenSchema = z.object({
  apiToken: z.string().min(1, "API token is required"),
});

const addApiTokenSchema = z.object({
  token: z.string().min(1, "Token is required"),
  label: z.string().min(1, "Label is required"),
});

const tokenRotationSettingsSchema = z.object({
  rotationEnabled: z.boolean(),
  rotationIntervalMinutes: z.string().min(1, "Interval is required"),
  maxRequestsPerToken: z.string().min(1, "Max requests is required"),
  videosPerBatch: z.string().min(1, "Videos per batch is required"),
  batchDelaySeconds: z.string().min(1, "Batch delay is required"),
});

const bulkReplaceTokensSchema = z.object({
  tokens: z.string().min(1, "Please enter at least one token"),
});

const planAvailabilitySchema = z.object({
  scalePlanAvailable: z.boolean(),
  empirePlanAvailable: z.boolean(),
});

const appSettingsSchema = z.object({
  whatsappUrl: z.string().url("Please enter a valid URL"),
  scriptApiKey: z.string().optional(),
  geminiApiKey: z.string().optional(),
  cloudinaryCloudName: z.string().min(1, "Cloudinary cloud name is required"),
  cloudinaryUploadPreset: z.string().min(1, "Cloudinary upload preset is required"),
  enableVideoMerge: z.boolean().optional(),
  logoUrl: z.string().optional(),
  browserPoolMaxContexts: z.coerce.number().min(1).max(200).optional(),
  browserPoolMaxPerUser: z.coerce.number().min(1).max(50).optional(),
  googleDriveCredentials: z.string().optional(),
  googleDriveFolderId: z.string().optional(),
  storageMethod: z.enum(["cloudinary", "google_drive", "cloudinary_with_fallback", "direct_to_user", "local_disk"]).optional(),
});

const toolMaintenanceSchema = z.object({
  veoGeneratorActive: z.boolean(),
  bulkGeneratorActive: z.boolean(),
  textToImageActive: z.boolean(),
  imageToVideoActive: z.boolean(),
  scriptCreatorActive: z.boolean(),
  characterConsistencyActive: z.boolean(),
});

type CreateUserFormData = z.infer<typeof createUserSchema>;
type UpdatePlanFormData = z.infer<typeof updatePlanSchema>;
type UpdateTokenFormData = z.infer<typeof updateTokenSchema>;
type AddApiTokenFormData = z.infer<typeof addApiTokenSchema>;
type TokenRotationSettingsFormData = z.infer<typeof tokenRotationSettingsSchema>;
type BulkReplaceTokensFormData = z.infer<typeof bulkReplaceTokensSchema>;
type PlanAvailabilityFormData = z.infer<typeof planAvailabilitySchema>;
type AppSettingsFormData = z.infer<typeof appSettingsSchema>;
type ToolMaintenanceFormData = z.infer<typeof toolMaintenanceSchema>;

interface UserData {
  id: string;
  username: string;
  isAdmin: boolean;
  planType: string;
  planStatus: string;
  planExpiry: string | null;
  apiToken: string | null;
  allowedIp1: string | null;
  allowedIp2: string | null;
  isAccountActive: boolean;
  dailyVideoLimit: number | null;
  bulkMaxBatch: number | null;
  bulkDelaySeconds: number | null;
  bulkMaxPrompts: number | null;
  videoStats: {
    completed: number;
    failed: number;
    pending: number;
    total: number;
  };
}

interface ApiTokenData {
  id: string;
  token: string;
  label: string;
  isActive: boolean;
  lastUsedAt: string | null;
  requestCount: string;
  createdAt: string;
}

interface TokenRotationSettings {
  id: string;
  rotationEnabled: boolean;
  rotationIntervalMinutes: string;
  maxRequestsPerToken: string;
  videosPerBatch: string;
  batchDelaySeconds: string;
}


export default function Admin() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [editingTokenUserId, setEditingTokenUserId] = useState<string | null>(null);
  const [viewingTokenErrors, setViewingTokenErrors] = useState<string | null>(null);
  const [showCredentialsDialog, setShowCredentialsDialog] = useState(false);
  const [copiedCredentials, setCopiedCredentials] = useState(false);
  const [createdUserData, setCreatedUserData] = useState<{
    username: string;
    password: string;
    planType: string;
    planExpiry: string | null;
  } | null>(null);

  const { data: session, isLoading: isLoadingSession } = useQuery<{
    authenticated: boolean;
    user?: { id: string; username: string; isAdmin: boolean };
  }>({
    queryKey: ["/api/session"],
  });

  const isAdmin = session?.authenticated && session?.user?.isAdmin;

  const { data: usersData, isLoading: isLoadingUsers } = useQuery<{ users: UserData[] }>({
    queryKey: ["/api/users"],
    enabled: isAdmin === true,
    staleTime: 5 * 60 * 1000, // 5 minutes - users don't change frequently
  });

  const { data: tokensData, isLoading: isLoadingTokens } = useQuery<{ tokens: ApiTokenData[] }>({
    queryKey: ["/api/tokens"],
    enabled: isAdmin === true,
    staleTime: 5 * 60 * 1000, // 5 minutes - tokens don't change frequently
  });

  const { data: tokenSettingsData } = useQuery<{ settings: TokenRotationSettings }>({
    queryKey: ["/api/token-settings"],
    enabled: isAdmin === true,
    staleTime: 10 * 60 * 1000, // 10 minutes - settings rarely change
  });

  const { data: planAvailabilityData } = useQuery<{ availability: { scalePlanAvailable: boolean; empirePlanAvailable: boolean } }>({
    queryKey: ["/api/plan-availability"],
    enabled: isAdmin === true,
    staleTime: 10 * 60 * 1000, // 10 minutes - plans rarely change
  });

  const { data: appSettingsData } = useQuery<{ 
    settings: { 
      whatsappUrl: string; 
      scriptApiKey?: string; 
      geminiApiKey?: string;
      cloudinaryCloudName?: string; 
      cloudinaryUploadPreset?: string;
      enableVideoMerge?: boolean;
      logoUrl?: string;
      browserPoolMaxContexts?: number;
      browserPoolMaxPerUser?: number;
      googleDriveCredentials?: string;
      googleDriveFolderId?: string;
      storageMethod?: "cloudinary" | "google_drive" | "cloudinary_with_fallback" | "direct_to_user" | "local_disk";
    } 
  }>({
    queryKey: ["/api/admin/app-settings"],
    enabled: isAdmin === true,
    staleTime: 10 * 60 * 1000, // 10 minutes - settings rarely change
  });

  // Logo upload state
  const [logoUploading, setLogoUploading] = useState(false);
  const [logoPreview, setLogoPreview] = useState<string | null>(null);
  const logoInputRef = useRef<HTMLInputElement>(null);

  const { data: toolMaintenanceData } = useQuery<{ maintenance: ToolMaintenanceFormData }>({
    queryKey: ["/api/tool-maintenance"],
    enabled: isAdmin === true,
    staleTime: 5 * 60 * 1000, // 5 minutes - maintenance status doesn't change often
  });


  // Fetch lightweight dashboard stats from server (much faster than fetching all videos)
  const { data: dashboardStatsData, isLoading: isLoadingStats, refetch: refetchStats } = useQuery<{
    todayStats: {
      total: number;
      completed: number;
      failed: number;
      pending: number;
    };
    tokenStats: Array<{
      tokenId: string;
      label: string;
      total: number;
      completed: number;
      failed: number;
    }>;
    recentVideoCount: number;
  }>({
    queryKey: ["/api/admin/dashboard-stats"],
    enabled: isAdmin === true,
    staleTime: 30 * 1000, // 30 seconds - stats update frequently
  });

  // Use server-calculated stats instead of client-side calculations
  const todayStats = dashboardStatsData?.todayStats || null;
  const tokenStats = dashboardStatsData?.tokenStats || [];

  // Keep video history query for History tab (with pagination)
  const { data: allVideoHistory } = useQuery<{ videos: Array<{
    id: string;
    userId: string;
    prompt: string;
    aspectRatio: string;
    videoUrl: string | null;
    status: string;
    createdAt: string;
    title: string | null;
    tokenUsed: string | null;
    errorMessage: string | null;
    retryCount: number;
  }> }>({
    queryKey: ["/api/admin/video-history"],
    enabled: isAdmin === true,
    staleTime: 60 * 1000, // 1 minute - video history updates regularly
  });

  useEffect(() => {
    if (isLoadingSession) return;
    
    if (!session?.authenticated || !session?.user?.isAdmin) {
      toast({
        variant: "destructive",
        title: "Access denied",
        description: "You must be an admin to access this page",
      });
      setLocation("/login");
    }
  }, [session, isLoadingSession, setLocation, toast]);

  useEffect(() => {
    if (tokenSettingsData?.settings) {
      rotationSettingsForm.reset({
        rotationEnabled: tokenSettingsData.settings.rotationEnabled,
        rotationIntervalMinutes: tokenSettingsData.settings.rotationIntervalMinutes,
        maxRequestsPerToken: tokenSettingsData.settings.maxRequestsPerToken,
        videosPerBatch: tokenSettingsData.settings.videosPerBatch,
        batchDelaySeconds: tokenSettingsData.settings.batchDelaySeconds,
      });
    }
  }, [tokenSettingsData]);

  useEffect(() => {
    if (planAvailabilityData?.availability) {
      planAvailabilityForm.reset({
        scalePlanAvailable: planAvailabilityData.availability.scalePlanAvailable,
        empirePlanAvailable: planAvailabilityData.availability.empirePlanAvailable,
      });
    }
  }, [planAvailabilityData]);

  const createForm = useForm<CreateUserFormData>({
    resolver: zodResolver(createUserSchema),
    defaultValues: {
      username: "",
      password: "",
      isAdmin: false,
      planType: "free",
      dailyVideoLimit: undefined,
      expiryDays: 30,
      bulkMaxBatch: undefined,
      bulkDelaySeconds: undefined,
      bulkMaxPrompts: undefined,
    },
  });
  
  const selectedPlanType = createForm.watch("planType");

  const planForm = useForm<UpdatePlanFormData>({
    resolver: zodResolver(updatePlanSchema),
    defaultValues: {
      planType: "free",
      planStatus: "active",
      planExpiry: "",
      dailyVideoLimit: undefined,
      expiryDays: undefined,
      bulkMaxBatch: undefined,
      bulkDelaySeconds: undefined,
      bulkMaxPrompts: undefined,
    },
  });
  
  const selectedEditPlanType = planForm.watch("planType");

  const [userToDelete, setUserToDelete] = useState<UserData | null>(null);
  const [userToRemovePlan, setUserToRemovePlan] = useState<UserData | null>(null);
  const [userSearchQuery, setUserSearchQuery] = useState<string>("");

  const tokenForm = useForm<UpdateTokenFormData>({
    resolver: zodResolver(updateTokenSchema),
    defaultValues: {
      apiToken: "",
    },
  });

  const addTokenForm = useForm<AddApiTokenFormData>({
    resolver: zodResolver(addApiTokenSchema),
    defaultValues: {
      token: "",
      label: "",
    },
  });

  const rotationSettingsForm = useForm<TokenRotationSettingsFormData>({
    resolver: zodResolver(tokenRotationSettingsSchema),
    defaultValues: {
      rotationEnabled: false,
      rotationIntervalMinutes: "60",
      maxRequestsPerToken: "1000",
      videosPerBatch: "5",
      batchDelaySeconds: "20",
    },
  });

  const bulkReplaceForm = useForm<BulkReplaceTokensFormData>({
    resolver: zodResolver(bulkReplaceTokensSchema),
    defaultValues: {
      tokens: "",
    },
  });

  const planAvailabilityForm = useForm<PlanAvailabilityFormData>({
    resolver: zodResolver(planAvailabilitySchema),
    defaultValues: {
      scalePlanAvailable: true,
      empirePlanAvailable: true,
    },
  });

  const appSettingsForm = useForm<AppSettingsFormData>({
    resolver: zodResolver(appSettingsSchema),
    defaultValues: {
      whatsappUrl: "",
      scriptApiKey: "",
      geminiApiKey: "",
      cloudinaryCloudName: "dfk0nvgff",
      cloudinaryUploadPreset: "demo123",
      enableVideoMerge: true,
      logoUrl: "",
      browserPoolMaxContexts: 50,
      browserPoolMaxPerUser: 5,
      googleDriveCredentials: "",
      googleDriveFolderId: "",
      storageMethod: "cloudinary_with_fallback",
    },
  });

  const toolMaintenanceForm = useForm<ToolMaintenanceFormData>({
    resolver: zodResolver(toolMaintenanceSchema),
    defaultValues: {
      veoGeneratorActive: true,
      bulkGeneratorActive: true,
      textToImageActive: true,
      imageToVideoActive: true,
      scriptCreatorActive: true,
      characterConsistencyActive: true,
    },
  });

  useEffect(() => {
    if (appSettingsData?.settings) {
      appSettingsForm.reset({
        whatsappUrl: appSettingsData.settings.whatsappUrl,
        scriptApiKey: appSettingsData.settings.scriptApiKey || "",
        geminiApiKey: appSettingsData.settings.geminiApiKey || "",
        cloudinaryCloudName: appSettingsData.settings.cloudinaryCloudName || "dfk0nvgff",
        cloudinaryUploadPreset: appSettingsData.settings.cloudinaryUploadPreset || "demo123",
        enableVideoMerge: appSettingsData.settings.enableVideoMerge ?? true,
        logoUrl: appSettingsData.settings.logoUrl || "",
        browserPoolMaxContexts: appSettingsData.settings.browserPoolMaxContexts ?? 50,
        browserPoolMaxPerUser: appSettingsData.settings.browserPoolMaxPerUser ?? 5,
        googleDriveCredentials: appSettingsData.settings.googleDriveCredentials || "",
        googleDriveFolderId: appSettingsData.settings.googleDriveFolderId || "",
        storageMethod: appSettingsData.settings.storageMethod || "cloudinary_with_fallback",
      });
    }
  }, [appSettingsData]);

  useEffect(() => {
    if (toolMaintenanceData?.maintenance) {
      toolMaintenanceForm.reset(toolMaintenanceData.maintenance);
    }
  }, [toolMaintenanceData]);

  const [showBulkConfirmation, setShowBulkConfirmation] = useState(false);

  const createUserMutation = useMutation({
    mutationFn: async (data: CreateUserFormData) => {
      const response = await apiRequest("POST", "/api/users", data);
      const result = await response.json();
      return { result: result as { success: boolean; user: UserData }, password: data.password };
    },
    onSuccess: ({ result, password }) => {
      toast({
        title: "User created successfully",
        description: `${result.user.username} has been added${result.user.isAdmin ? " as an admin" : ""}`,
      });
      
      // Store user data for credentials dialog
      setCreatedUserData({
        username: result.user.username,
        password: password,
        planType: result.user.planType || 'free',
        planExpiry: result.user.planExpiry || null,
      });
      setShowCredentialsDialog(true);
      setCopiedCredentials(false);
      
      createForm.reset();
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to create user",
        description: error.message || "An error occurred",
      });
    },
  });

  const updatePlanMutation = useMutation({
    mutationFn: async ({ userId, data }: { userId: string; data: UpdatePlanFormData }) => {
      const response = await apiRequest("PATCH", `/api/users/${userId}/plan`, data);
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Plan updated successfully",
      });
      setEditingUserId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update plan",
        description: error.message || "An error occurred",
      });
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("DELETE", `/api/users/${userId}`, {});
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "User deleted successfully",
      });
      setUserToDelete(null);
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to delete user",
        description: error.message || "An error occurred",
      });
    },
  });

  const removePlanMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("DELETE", `/api/users/${userId}/plan`, {});
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Plan removed successfully",
        description: "User has been reset to free plan",
      });
      setUserToRemovePlan(null);
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to remove plan",
        description: error.message || "An error occurred",
      });
    },
  });

  const updateTokenMutation = useMutation({
    mutationFn: async ({ userId, data }: { userId: string; data: UpdateTokenFormData }) => {
      const response = await apiRequest("PATCH", `/api/users/${userId}/token`, data);
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "API token updated successfully",
      });
      setEditingTokenUserId(null);
      tokenForm.reset();
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update token",
        description: error.message || "An error occurred",
      });
    },
  });

  const reactivateUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("POST", `/api/users/${userId}/reactivate`, {});
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "IP limit reset successfully",
        description: "User account has been reactivated and IP restrictions cleared",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to reset IP limit",
        description: error.message || "An error occurred",
      });
    },
  });

  const extendAllExpiryMutation = useMutation({
    mutationFn: async (days: number) => {
      const response = await apiRequest("POST", "/api/admin/extend-all-expiry", { days });
      const result = await response.json();
      return { ...result, days };
    },
    onSuccess: (data: any) => {
      const action = data.days > 0 ? "extended" : "reduced";
      toast({
        title: `Expiry ${action} successfully`,
        description: data.message || `${action} expiry for ${data.updatedCount} users`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update expiry",
        description: error.message || "An error occurred",
      });
    },
  });

  const resetVideoCountMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("POST", `/api/users/${userId}/reset-video-count`, {});
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Video count reset successfully",
        description: "Daily video generation count has been reset to 0",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to reset video count",
        description: error.message || "An error occurred",
      });
    },
  });

  const clearUserDataMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("POST", `/api/admin/clear-user-data/${userId}`);
      const text = await response.text();
      try {
        return JSON.parse(text);
      } catch {
        console.error("Clear user data response:", text);
        throw new Error("Invalid response from server");
      }
    },
    onSuccess: (data: any) => {
      toast({
        title: "User data cleared successfully",
        description: `Deleted ${data.deletedCount || 0} non-completed videos. Completed videos preserved.`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to clear user data",
        description: error.message || "An error occurred",
      });
    },
  });

  const clearPendingVideosMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("POST", `/api/admin/clear-pending-videos/${userId}`);
      const text = await response.text();
      try {
        return JSON.parse(text);
      } catch {
        console.error("Clear pending videos response:", text);
        throw new Error("Invalid response from server");
      }
    },
    onSuccess: (data: any) => {
      toast({
        title: "Pending videos cleared",
        description: `Deleted ${data.deletedCount || 0} pending/generating videos.`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to clear pending videos",
        description: error.message || "An error occurred",
      });
    },
  });

  const forceResetQueueMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("POST", `/api/admin/force-reset-queue/${userId}`);
      const text = await response.text();
      try {
        return JSON.parse(text);
      } catch {
        console.error("Force reset queue response:", text);
        throw new Error("Invalid response from server");
      }
    },
    onSuccess: (data: any) => {
      toast({
        title: "Queue Reset Complete",
        description: `Bulk queue for ${data.username || 'user'} has been force reset. They can now start new generations.`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to reset queue",
        description: error.message || "An error occurred",
      });
    },
  });

  const addTokenMutation = useMutation({
    mutationFn: async (data: AddApiTokenFormData) => {
      const response = await apiRequest("POST", "/api/tokens", data);
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Token added successfully",
      });
      addTokenForm.reset();
      queryClient.invalidateQueries({ queryKey: ["/api/tokens"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to add token",
        description: error.message || "An error occurred",
      });
    },
  });


  const deleteTokenMutation = useMutation({
    mutationFn: async (tokenId: string) => {
      const response = await apiRequest("DELETE", `/api/tokens/${tokenId}`, {});
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Token deleted successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/tokens"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to delete token",
        description: error.message || "An error occurred",
      });
    },
  });

  const toggleTokenMutation = useMutation({
    mutationFn: async ({ tokenId, isActive }: { tokenId: string; isActive: boolean }) => {
      const response = await apiRequest("PATCH", `/api/tokens/${tokenId}/toggle`, { isActive });
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/tokens"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update token status",
        description: error.message || "An error occurred",
      });
    },
  });

  const updateRotationSettingsMutation = useMutation({
    mutationFn: async (data: TokenRotationSettingsFormData) => {
      const response = await apiRequest("PUT", "/api/token-settings", {
        rotationEnabled: data.rotationEnabled,
        rotationIntervalMinutes: data.rotationIntervalMinutes,
        maxRequestsPerToken: data.maxRequestsPerToken,
        videosPerBatch: data.videosPerBatch,
        batchDelaySeconds: data.batchDelaySeconds,
      });
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Settings updated successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/token-settings"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update settings",
        description: error.message || "An error occurred",
      });
    },
  });

  const updatePlanAvailabilityMutation = useMutation({
    mutationFn: async (data: PlanAvailabilityFormData) => {
      const response = await apiRequest("PUT", "/api/plan-availability", data);
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Plan availability updated successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/plan-availability"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update plan availability",
        description: error.message || "An error occurred",
      });
    },
  });

  const updateAppSettingsMutation = useMutation({
    mutationFn: async (data: AppSettingsFormData) => {
      const response = await apiRequest("PUT", "/api/app-settings", data);
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Settings updated successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/app-settings"] });
      queryClient.invalidateQueries({ queryKey: ["/api/logo"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update settings",
        description: error.message || "An error occurred",
      });
    },
  });

  // Logo upload handler
  const handleLogoUpload = async (file: File) => {
    if (!file) return;
    
    // Validate file type
    if (!file.type.startsWith('image/')) {
      toast({
        variant: "destructive",
        title: "Invalid file type",
        description: "Please upload an image file (PNG, JPG, etc.)",
      });
      return;
    }

    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      toast({
        variant: "destructive",
        title: "File too large",
        description: "Logo must be less than 5MB",
      });
      return;
    }

    // Validate Cloudinary config exists
    const cloudName = appSettingsData?.settings?.cloudinaryCloudName;
    const uploadPreset = appSettingsData?.settings?.cloudinaryUploadPreset;
    
    if (!cloudName || !uploadPreset) {
      toast({
        variant: "destructive",
        title: "Cloudinary not configured",
        description: "Please configure Cloudinary Cloud Name and Upload Preset first.",
      });
      return;
    }

    setLogoUploading(true);

    try {
      // Upload to Cloudinary
      const formData = new FormData();
      formData.append('file', file);
      formData.append('upload_preset', uploadPreset);
      formData.append('folder', 'logos');

      const uploadResponse = await fetch(
        `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
        { method: 'POST', body: formData }
      );

      const uploadResult = await uploadResponse.json();

      if (uploadResult.error) {
        // Check for content moderation error
        if (uploadResult.error.message?.includes('PUBLIC_ERROR_MINOR_UPLOAD') || 
            uploadResult.error.message?.includes('moderation')) {
          throw new Error('The image you are trying to upload contains inappropriate content (kids or sexual content) and cannot be used.');
        }
        throw new Error(uploadResult.error.message || 'Upload failed');
      }

      const newLogoUrl = uploadResult.secure_url;
      setLogoPreview(newLogoUrl);

      // Save logo URL to app settings
      const currentSettings = appSettingsData?.settings;
      const response = await apiRequest("PUT", "/api/app-settings", {
        whatsappUrl: currentSettings?.whatsappUrl || "https://api.whatsapp.com/send?phone=&text=Contact Support",
        scriptApiKey: currentSettings?.scriptApiKey || "",
        cloudinaryCloudName: currentSettings?.cloudinaryCloudName,
        cloudinaryUploadPreset: currentSettings?.cloudinaryUploadPreset,
        enableVideoMerge: currentSettings?.enableVideoMerge ?? true,
        logoUrl: newLogoUrl,
      });

      if (!response.ok) {
        throw new Error('Failed to save logo settings');
      }

      queryClient.invalidateQueries({ queryKey: ["/api/admin/app-settings"] });
      queryClient.invalidateQueries({ queryKey: ["/api/logo"] });

      toast({
        title: "Logo updated successfully",
        description: "The new logo will appear across all pages.",
      });
    } catch (error: any) {
      console.error('Logo upload failed:', error);
      setLogoPreview(null);
      toast({
        variant: "destructive",
        title: "Logo upload failed",
        description: error.message || "An error occurred while uploading the logo",
      });
    } finally {
      setLogoUploading(false);
    }
  };

  // Remove logo handler
  const handleRemoveLogo = async () => {
    try {
      const currentSettings = appSettingsData?.settings;
      const response = await apiRequest("PUT", "/api/app-settings", {
        whatsappUrl: currentSettings?.whatsappUrl || "https://api.whatsapp.com/send?phone=&text=Contact Support",
        scriptApiKey: currentSettings?.scriptApiKey || "",
        cloudinaryCloudName: currentSettings?.cloudinaryCloudName || "dfk0nvgff",
        cloudinaryUploadPreset: currentSettings?.cloudinaryUploadPreset || "demo123",
        enableVideoMerge: currentSettings?.enableVideoMerge ?? true,
        logoUrl: undefined, // Clear logo
      });

      if (!response.ok) {
        throw new Error('Failed to remove logo');
      }

      setLogoPreview(null);
      queryClient.invalidateQueries({ queryKey: ["/api/admin/app-settings"] });
      queryClient.invalidateQueries({ queryKey: ["/api/logo"] });

      toast({
        title: "Logo removed",
        description: "Default logo will be used.",
      });
    } catch (error: any) {
      toast({
        variant: "destructive",
        title: "Failed to remove logo",
        description: error.message || "An error occurred",
      });
    }
  };

  const updateToolMaintenanceMutation = useMutation({
    mutationFn: async (data: ToolMaintenanceFormData) => {
      const response = await apiRequest("PUT", "/api/tool-maintenance", data);
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      toast({
        title: "Tool maintenance status updated successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/tool-maintenance"] });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Failed to update tool maintenance status",
        description: error.message || "An error occurred",
      });
    },
  });

  const bulkReplaceTokensMutation = useMutation({
    mutationFn: async (data: BulkReplaceTokensFormData) => {
      try {
        // Pre-validate: Count tokens before sending
        const tokenLines = data.tokens.trim().split('\n').filter(line => line.trim().length > 0);
        console.log('[Bulk Replace] Attempting to replace', tokenLines.length, 'tokens');
        
        if (tokenLines.length === 0) {
          throw new Error("No tokens found. Please enter at least one token.");
        }
        
        if (tokenLines.length > 500) {
          throw new Error(`Too many tokens (${tokenLines.length}). Maximum 500 tokens allowed per batch.`);
        }

        const response = await apiRequest("POST", "/api/tokens/bulk-replace", data);
        const result = await response.json();
        return result as { success: boolean; tokens: ApiTokenData[]; count: number };
      } catch (error: any) {
        console.error('[Bulk Replace] Error:', error);
        // Better error messages for common fetch failures
        if (error.message === 'Failed to fetch' || error.name === 'TypeError') {
          throw new Error('Network error: Could not connect to server. Please check your connection and try again.');
        }
        throw error;
      }
    },
    onSuccess: (data) => {
      toast({
        title: "Tokens replaced successfully",
        description: `Added ${data.count} new tokens. All previous tokens have been removed. ⚠️ All existing characters have been deleted.`,
      });
      bulkReplaceForm.reset();
      setShowBulkConfirmation(false);
      queryClient.invalidateQueries({ queryKey: ["/api/tokens"] });
    },
    onError: (error: any) => {
      console.error('[Bulk Replace] Mutation error:', error);
      toast({
        variant: "destructive",
        title: "Failed to replace tokens",
        description: error.message || "An unknown error occurred. Check console for details.",
      });
    },
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/logout", {});
      const result = await response.json();
      return result;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/session"] });
      toast({
        title: "Logged out successfully",
      });
      setLocation("/login");
    },
  });

  const handleEditPlan = (user: UserData) => {
    setEditingUserId(user.id);
    planForm.reset({
      planType: user.planType as "free" | "scale" | "empire" | "enterprise",
      planStatus: user.planStatus as "active" | "expired" | "cancelled",
      planExpiry: user.planExpiry || "",
      dailyVideoLimit: user.dailyVideoLimit ?? undefined,
      bulkMaxBatch: user.bulkMaxBatch ?? undefined,
      bulkDelaySeconds: user.bulkDelaySeconds ?? undefined,
      bulkMaxPrompts: user.bulkMaxPrompts ?? undefined,
    });
  };

  const handleEditToken = (user: UserData) => {
    setEditingTokenUserId(user.id);
    tokenForm.reset({
      apiToken: user.apiToken || "",
    });
  };

  // Filter users based on search query
  const filteredUsers = useMemo(() => {
    if (!usersData?.users) return [];
    if (!userSearchQuery.trim()) return usersData.users;
    
    const query = userSearchQuery.toLowerCase().trim();
    return usersData.users.filter(user => 
      user.username.toLowerCase().includes(query) ||
      user.planType.toLowerCase().includes(query) ||
      user.planStatus.toLowerCase().includes(query) ||
      (user.apiToken && user.apiToken.toLowerCase().includes(query)) ||
      (user.allowedIp1 && user.allowedIp1.includes(query)) ||
      (user.allowedIp2 && user.allowedIp2.includes(query))
    );
  }, [usersData?.users, userSearchQuery]);

  const onCreateSubmit = (data: CreateUserFormData) => {
    createUserMutation.mutate(data);
  };

  const onPlanSubmit = (data: UpdatePlanFormData) => {
    if (editingUserId) {
      updatePlanMutation.mutate({ userId: editingUserId, data });
    }
  };

  const onTokenSubmit = (data: UpdateTokenFormData) => {
    if (editingTokenUserId) {
      updateTokenMutation.mutate({ userId: editingTokenUserId, data });
    }
  };

  if (isLoadingSession) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#f9fafb]">
        <p className="text-[#374151]">Loading...</p>
      </div>
    );
  }

  if (!session?.authenticated || !session?.user?.isAdmin) {
    return null;
  }

  return (
    <div className="min-h-screen bg-[#f9fafb] p-4">
      <div className="max-w-7xl mx-auto py-8">
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[#374151] border border-[#4b5563]">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-[#1f2937]">Admin Panel</h1>
              <p className="text-[#6b7280]">
                Logged in as <span className="font-medium text-[#1f2937]">{session.user.username}</span>
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => setLocation("/")}
              data-testid="button-home"
              className="border-[#374151] text-[#374151] hover:bg-[#374151] hover:text-white"
            >
              <Home className="w-4 h-4 mr-2" />
              Home
            </Button>
            <Button
              variant="outline"
              onClick={() => logoutMutation.mutate()}
              disabled={logoutMutation.isPending}
              data-testid="button-logout"
              className="border-[#374151] text-[#374151] hover:bg-[#374151] hover:text-white"
            >
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>

        <Tabs defaultValue="dashboard" className="w-full">
          <TabsList className="grid w-full grid-cols-5 lg:grid-cols-10 gap-2 bg-white border border-[#e5e7eb] p-2 h-auto mb-6 rounded-lg shadow-sm">
            <TabsTrigger value="dashboard" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-dashboard">
              <TrendingUp className="w-4 h-4 mr-2" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="users" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-users">
              <Users className="w-4 h-4 mr-2" />
              Users
            </TabsTrigger>
            <TabsTrigger value="tokens" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-tokens">
              <Key className="w-4 h-4 mr-2" />
              Tokens
            </TabsTrigger>
            <TabsTrigger value="plans" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-plans">
              <Calendar className="w-4 h-4 mr-2" />
              Plans
            </TabsTrigger>
            <TabsTrigger value="whatsapp" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-whatsapp">
              <Settings className="w-4 h-4 mr-2" />
              Settings
            </TabsTrigger>
            <TabsTrigger value="maintenance" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-maintenance">
              <Wrench className="w-4 h-4 mr-2" />
              Maintenance
            </TabsTrigger>
            <TabsTrigger value="messages" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-messages">
              <MessageCircle className="w-4 h-4 mr-2" />
              Messages
            </TabsTrigger>
            <TabsTrigger value="monitor" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-monitor">
              <Activity className="w-4 h-4 mr-2" />
              Monitor
            </TabsTrigger>
            <TabsTrigger value="history" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-history">
              <HistoryIcon className="w-4 h-4 mr-2" />
              History
            </TabsTrigger>
            <TabsTrigger value="logs" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-logs">
              <FileText className="w-4 h-4 mr-2" />
              Logs
            </TabsTrigger>
            <TabsTrigger value="flow" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-flow">
              <Zap className="w-4 h-4 mr-2" />
              Flow
            </TabsTrigger>
            <TabsTrigger value="resellers" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-resellers">
              <DollarSign className="w-4 h-4 mr-2" />
              Resellers
            </TabsTrigger>
            <TabsTrigger value="zyphra" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-zyphra">
              <Mic className="w-4 h-4 mr-2" />
              Zyphra
            </TabsTrigger>
            <TabsTrigger value="pricing" className="text-[#6b7280] data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-pricing">
              <DollarSign className="w-4 h-4 mr-2" />
              Pricing
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard">
            {/* Today's Video Generation Statistics */}
            {todayStats && (
              <Card className="shadow-sm bg-white border border-[#e5e7eb] mb-6">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-5 h-5 text-[#374151]" />
                  <CardTitle className="text-[#1f2937]">Today's Video Generation Statistics</CardTitle>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="border-[#374151] text-[#374151] hover:bg-[#374151] hover:text-white"
                  onClick={() => refetchStats()}
                  disabled={isLoadingStats}
                  data-testid="button-refresh-stats"
                >
                  <RefreshCw className={`w-4 h-4 mr-2 ${isLoadingStats ? 'animate-spin' : ''}`} />
                  Refresh Stats
                </Button>
              </div>
              <CardDescription className="text-[#6b7280]">
                Overview of videos generated today
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 bg-[#374151]/10 border border-[#374151]/30 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <TrendingUp className="w-4 h-4 text-[#374151]" />
                    <p className="text-sm font-medium text-[#6b7280]">Total</p>
                  </div>
                  <p className="text-2xl font-bold text-[#1f2937]">{todayStats.total}</p>
                </div>
                <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="w-4 h-4 text-green-600" />
                    <p className="text-sm font-medium text-[#6b7280]">Completed</p>
                  </div>
                  <p className="text-2xl font-bold text-[#1f2937]">{todayStats.completed}</p>
                </div>
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <XCircle className="w-4 h-4 text-red-600" />
                    <p className="text-sm font-medium text-[#6b7280]">Failed</p>
                  </div>
                  <p className="text-2xl font-bold text-[#1f2937]">{todayStats.failed}</p>
                </div>
                <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Clock className="w-4 h-4 text-yellow-600" />
                    <p className="text-sm font-medium text-[#6b7280]">Pending</p>
                  </div>
                  <p className="text-2xl font-bold text-[#1f2937]">{todayStats.pending}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Per-Token Statistics */}
        {tokenStats.length > 0 && (
          <Card className="shadow-sm bg-white border border-[#e5e7eb] mb-6">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-[#374151]" />
                <CardTitle className="text-[#1f2937]">API Token Usage Statistics</CardTitle>
              </div>
              <CardDescription className="text-[#6b7280]">
                Video generation statistics per API token
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-[#e5e7eb]">
                      <TableHead className="text-[#374151]">Token Label</TableHead>
                      <TableHead className="text-[#374151]">Total Videos</TableHead>
                      <TableHead className="text-[#374151]">Completed</TableHead>
                      <TableHead className="text-[#374151]">Failed</TableHead>
                      <TableHead className="text-[#374151]">Success Rate</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tokenStats.map((stat) => {
                      const successRate = stat.total > 0 ? ((stat.completed / stat.total) * 100).toFixed(1) : '0.0';
                      return (
                        <TableRow key={stat.tokenId} className="border-[#e5e7eb]">
                          <TableCell className="font-medium text-[#1f2937]">
                            {stat.label}
                          </TableCell>
                          <TableCell className="text-[#374151]">
                            {stat.total}
                          </TableCell>
                          <TableCell className="text-[#374151]">
                            <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-100 text-green-800 text-sm rounded">
                              <CheckCircle className="w-3 h-3" />
                              {stat.completed}
                            </span>
                          </TableCell>
                          <TableCell className="text-[#374151]">
                            <button
                              onClick={() => stat.failed > 0 && setViewingTokenErrors(stat.tokenId)}
                              className={`inline-flex items-center gap-1 px-2 py-1 bg-red-100 text-red-800 text-sm rounded ${
                                stat.failed > 0 ? 'cursor-pointer hover:bg-red-200' : ''
                              }`}
                              disabled={stat.failed === 0}
                            >
                              <XCircle className="w-3 h-3" />
                              {stat.failed}
                            </button>
                          </TableCell>
                          <TableCell className="text-[#374151]">
                            <span className={`px-2 py-1 text-sm rounded ${
                              parseFloat(successRate) >= 80 
                                ? 'bg-green-100 text-green-800'
                                : parseFloat(successRate) >= 50
                                ? 'bg-yellow-100 text-yellow-800'
                                : 'bg-red-100 text-red-800'
                            }`}>
                              {successRate}%
                            </span>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Error Details Dialog */}
        <Dialog open={!!viewingTokenErrors} onOpenChange={(open) => !open && setViewingTokenErrors(null)}>
          <DialogContent className="max-w-4xl bg-white border-[#e5e7eb]">
            <DialogHeader>
              <DialogTitle className="text-[#1f2937] flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-red-500" />
                Failed Video Details
              </DialogTitle>
              <DialogDescription className="text-[#6b7280]">
                Error messages for failed video generations using {tokensData?.tokens.find(t => t.id === viewingTokenErrors)?.label || 'this token'}
              </DialogDescription>
            </DialogHeader>
            <ScrollArea className="max-h-[500px] pr-4">
              <div className="space-y-3">
                {allVideoHistory?.videos
                  .filter(v => v.tokenUsed === viewingTokenErrors && v.status === 'failed')
                  .map((video) => (
                    <div key={video.id} className="p-4 border border-gray-200 border-[#e5e7eb] rounded-lg bg-gray-50 bg-gray-50">
                      <div className="flex flex-col gap-2">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <p className="text-sm font-medium text-[#1f2937]">
                              {video.title || 'Untitled Video'}
                            </p>
                            <p className="text-xs text-[#6b7280] mt-1">
                              ID: {video.id}
                            </p>
                            <p className="text-xs text-[#6b7280]">
                              Created: {new Date(video.createdAt).toLocaleString()}
                            </p>
                          </div>
                          <Badge variant="destructive">Failed</Badge>
                        </div>
                        <div className="mt-2">
                          <p className="text-xs font-medium text-[#374151] mb-1">Prompt:</p>
                          <p className="text-xs text-[#6b7280] bg-white bg-white p-2 rounded border border-gray-200 border-[#e5e7eb]">
                            {video.prompt}
                          </p>
                        </div>
                        {video.errorMessage && (
                          <div className="mt-2">
                            <p className="text-xs font-medium text-red-700 text-red-700 mb-1 flex items-center gap-1">
                              <AlertCircle className="w-3 h-3" />
                              Error Message:
                            </p>
                            <p className="text-xs text-red-600 text-red-600 bg-red-50 bg-red-50 p-2 rounded border border-red-200 border-red-200">
                              {video.errorMessage}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                {allVideoHistory?.videos
                  .filter(v => v.tokenUsed === viewingTokenErrors && v.status === 'failed')
                  .length === 0 && (
                  <p className="text-center text-gray-500 text-[#6b7280] py-8">
                    No failed videos found for this token
                  </p>
                )}
              </div>
            </ScrollArea>
          </DialogContent>
        </Dialog>
          </TabsContent>

          <TabsContent value="users">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <Card className="shadow-xl bg-white border-[#e5e7eb]">
            <CardHeader>
              <div className="flex items-center gap-2">
                <UserPlus className="w-5 h-5 text-[#374151]" />
                <CardTitle className="text-[#1f2937]">Create New User</CardTitle>
              </div>
              <CardDescription className="text-[#6b7280]">
                Add a new user account to the system
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...createForm}>
                <form onSubmit={createForm.handleSubmit(onCreateSubmit)} className="space-y-4">
                  <FormField
                    control={createForm.control}
                    name="username"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-[#374151]">Username</FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            placeholder="Enter username"
                            data-testid="input-create-username"
                            className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                            disabled={createUserMutation.isPending}
                          />
                        </FormControl>
                        <FormMessage className="text-red-600" />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={createForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-[#374151]">Password</FormLabel>
                        <FormControl>
                          <div className="flex gap-2">
                            <Input
                              {...field}
                              type="password"
                              placeholder="Enter password"
                              data-testid="input-create-password"
                              className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                              disabled={createUserMutation.isPending}
                            />
                            <Button
                              type="button"
                              variant="outline"
                              size="icon"
                              onClick={() => {
                                const randomPassword = Math.random().toString(36).slice(-10) + Math.random().toString(36).slice(-10).toUpperCase() + Math.floor(Math.random() * 100);
                                createForm.setValue("password", randomPassword);
                                toast({
                                  title: "Random password generated!",
                                  description: "Password has been set",
                                });
                              }}
                              disabled={createUserMutation.isPending}
                              data-testid="button-generate-password"
                              className="border-[#e5e7eb] hover:bg-gray-100"
                            >
                              <Shuffle className="w-4 h-4" />
                            </Button>
                          </div>
                        </FormControl>
                        <FormMessage className="text-red-600" />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={createForm.control}
                    name="planType"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-[#374151]">Initial Plan</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]" data-testid="select-create-plan-type">
                              <SelectValue placeholder="Select plan type" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent className="bg-white border-[#e5e7eb]">
                            <SelectItem value="free">Free</SelectItem>
                            <SelectItem value="scale">Scale (900 PKR - 10 days)</SelectItem>
                            <SelectItem value="empire">Empire (1500 PKR - 10 days)</SelectItem>
                            <SelectItem value="enterprise">Enterprise (Custom)</SelectItem>
                          </SelectContent>
                        </Select>
                        <FormDescription className="text-[#6b7280]">
                          Plan can be changed later
                        </FormDescription>
                        <FormMessage className="text-red-600" />
                      </FormItem>
                    )}
                  />

                  {selectedPlanType === "enterprise" && (
                    <>
                      <FormField
                        control={createForm.control}
                        name="dailyVideoLimit"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-[#374151]">Daily Video Limit</FormLabel>
                            <FormControl>
                              <Input
                                {...field}
                                type="number"
                                min="0"
                                placeholder="Enter daily video limit (0 = unlimited)"
                                data-testid="input-daily-video-limit"
                                className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                                disabled={createUserMutation.isPending}
                                value={field.value ?? ""}
                                onChange={(e) => field.onChange(e.target.value === "" ? undefined : parseInt(e.target.value, 10))}
                              />
                            </FormControl>
                            <FormDescription className="text-[#6b7280]">
                              Set to 0 for unlimited videos per day
                            </FormDescription>
                            <FormMessage className="text-red-600" />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={createForm.control}
                        name="expiryDays"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-[#374151]">Plan Duration (Days)</FormLabel>
                            <FormControl>
                              <Input
                                {...field}
                                type="number"
                                min="1"
                                placeholder="Enter number of days"
                                data-testid="input-expiry-days"
                                className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                                disabled={createUserMutation.isPending}
                                value={field.value ?? ""}
                                onChange={(e) => field.onChange(e.target.value === "" ? undefined : parseInt(e.target.value, 10))}
                              />
                            </FormControl>
                            <FormDescription className="text-[#6b7280]">
                              How many days the plan will be active
                            </FormDescription>
                            <FormMessage className="text-red-600" />
                          </FormItem>
                        )}
                      />

                      <div className="border-t border-[#e5e7eb] pt-4 mt-4">
                        <h4 className="text-sm font-medium text-[#374151] mb-3">Bulk Generation Settings</h4>
                        
                        <FormField
                          control={createForm.control}
                          name="bulkMaxBatch"
                          render={({ field }) => (
                            <FormItem className="mb-3">
                              <FormLabel className="text-[#374151]">Max Batch Size</FormLabel>
                              <FormControl>
                                <Input
                                  {...field}
                                  type="number"
                                  min="1"
                                  placeholder="e.g., 50"
                                  data-testid="input-bulk-max-batch"
                                  className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                                  disabled={createUserMutation.isPending}
                                  value={field.value ?? ""}
                                  onChange={(e) => field.onChange(e.target.value === "" ? undefined : parseInt(e.target.value, 10))}
                                />
                              </FormControl>
                              <FormDescription className="text-[#6b7280] text-xs">
                                Videos processed per batch
                              </FormDescription>
                              <FormMessage className="text-red-600" />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={createForm.control}
                          name="bulkDelaySeconds"
                          render={({ field }) => (
                            <FormItem className="mb-3">
                              <FormLabel className="text-[#374151]">Batch Delay (Seconds)</FormLabel>
                              <FormControl>
                                <Input
                                  {...field}
                                  type="number"
                                  min="0"
                                  placeholder="e.g., 10"
                                  data-testid="input-bulk-delay-seconds"
                                  className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                                  disabled={createUserMutation.isPending}
                                  value={field.value ?? ""}
                                  onChange={(e) => field.onChange(e.target.value === "" ? undefined : parseInt(e.target.value, 10))}
                                />
                              </FormControl>
                              <FormDescription className="text-[#6b7280] text-xs">
                                Delay between batches
                              </FormDescription>
                              <FormMessage className="text-red-600" />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={createForm.control}
                          name="bulkMaxPrompts"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel className="text-[#374151]">Max Prompts</FormLabel>
                              <FormControl>
                                <Input
                                  {...field}
                                  type="number"
                                  min="1"
                                  placeholder="e.g., 200"
                                  data-testid="input-bulk-max-prompts"
                                  className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                                  disabled={createUserMutation.isPending}
                                  value={field.value ?? ""}
                                  onChange={(e) => field.onChange(e.target.value === "" ? undefined : parseInt(e.target.value, 10))}
                                />
                              </FormControl>
                              <FormDescription className="text-[#6b7280] text-xs">
                                Maximum prompts allowed per bulk job
                              </FormDescription>
                              <FormMessage className="text-red-600" />
                            </FormItem>
                          )}
                        />
                      </div>
                    </>
                  )}

                  <FormField
                    control={createForm.control}
                    name="isAdmin"
                    render={({ field }) => (
                      <FormItem className="flex flex-row items-center justify-between rounded-lg border border-gray-200 border-[#e5e7eb] p-4 bg-gray-50 bg-gray-50">
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#1f2937]">
                            Admin privileges
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            Grant administrator access
                          </FormDescription>
                        </div>
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-admin"
                            disabled={createUserMutation.isPending}
                          />
                        </FormControl>
                      </FormItem>
                    )}
                  />

                  <Button
                    type="submit"
                    className="w-full bg-[#374151] hover:bg-[#1f2937] text-white border-0"
                    disabled={createUserMutation.isPending}
                    data-testid="button-create-user"
                  >
                    {createUserMutation.isPending ? "Creating..." : "Create User"}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        </div>

        <Card className="shadow-xl bg-white border-[#e5e7eb]">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-[#374151]" />
                <CardTitle className="text-[#1f2937]">User Management</CardTitle>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => extendAllExpiryMutation.mutate(-1)}
                  disabled={extendAllExpiryMutation.isPending}
                  data-testid="button-reduce-all-expiry"
                  className="border-[#e5e7eb] text-[#374151]"
                >
                  <Calendar className="w-4 h-4 mr-2" />
                  {extendAllExpiryMutation.isPending ? "Reducing..." : "-1 Day All Users"}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => extendAllExpiryMutation.mutate(1)}
                  disabled={extendAllExpiryMutation.isPending}
                  data-testid="button-extend-all-expiry"
                  className="border-[#e5e7eb] text-[#374151]"
                >
                  <Calendar className="w-4 h-4 mr-2" />
                  {extendAllExpiryMutation.isPending ? "Extending..." : "+1 Day All Users"}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/users"] })}
                  data-testid="button-refresh-users"
                  className="border-[#e5e7eb] text-[#374151]"
                >
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Refresh
                </Button>
              </div>
            </div>
            <CardDescription className="text-[#6b7280]">
              Manage user plans and access tokens
            </CardDescription>
            <div className="mt-4">
              <Input
                placeholder="Search by username, plan, status, token, or IP..."
                value={userSearchQuery}
                onChange={(e) => setUserSearchQuery(e.target.value)}
                className="bg-white/5 border-white/20 text-[#1f2937] placeholder:text-gray-500"
                data-testid="input-search-users"
              />
            </div>
          </CardHeader>
          <CardContent>
            {isLoadingUsers ? (
              <p className="text-[#6b7280] text-center py-4">Loading users...</p>
            ) : !usersData?.users || usersData.users.length === 0 ? (
              <p className="text-[#6b7280] text-center py-4">No users found</p>
            ) : filteredUsers.length === 0 ? (
              <p className="text-[#6b7280] text-center py-4">No users match your search</p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-[#e5e7eb]">
                      <TableHead className="text-[#374151]">Username</TableHead>
                      <TableHead className="text-[#374151]">Role</TableHead>
                      <TableHead className="text-[#374151]">Plan</TableHead>
                      <TableHead className="text-[#374151]">Status</TableHead>
                      <TableHead className="text-[#374151]">Expiry</TableHead>
                      <TableHead className="text-[#374151]">Account Status</TableHead>
                      <TableHead className="text-[#374151] text-center">Videos</TableHead>
                      <TableHead className="text-[#374151]">IP Addresses</TableHead>
                      <TableHead className="text-[#374151]">API Token</TableHead>
                      <TableHead className="text-[#374151]">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredUsers.map((user) => (
                      <TableRow key={user.id} className="border-[#e5e7eb]" data-testid={`row-user-${user.id}`}>
                        <TableCell className="font-medium text-[#1f2937]" data-testid={`text-username-${user.id}`}>
                          {user.username}
                        </TableCell>
                        <TableCell className="text-[#374151]">
                          {user.isAdmin ? (
                            <span className="px-2 py-1 bg-gray-200 text-[#374151] text-xs rounded-full">
                              Admin
                            </span>
                          ) : (
                            <span className="px-2 py-1 bg-gray-50 text-[#374151] text-xs rounded-full">
                              User
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-[#374151] capitalize" data-testid={`text-plan-${user.id}`}>
                          {user.planType}
                        </TableCell>
                        <TableCell className="text-[#374151]">
                          <span className={`px-2 py-1 text-xs rounded-full ${
                            user.planStatus === "active" 
                              ? "bg-green-100 bg-green-100 text-green-800 text-green-800"
                              : user.planStatus === "expired"
                              ? "bg-red-100 bg-red-100 text-red-800 text-red-800"
                              : "bg-gray-50 text-[#374151]"
                          }`} data-testid={`text-status-${user.id}`}>
                            {user.planStatus}
                          </span>
                        </TableCell>
                        <TableCell className="text-[#374151] text-sm" data-testid={`text-expiry-${user.id}`}>
                          {user.planExpiry || "—"}
                        </TableCell>
                        <TableCell className="text-[#374151]">
                          {user.isAccountActive ? (
                            <span className="px-2 py-1 bg-green-100 bg-green-100 text-green-800 text-green-800 text-xs rounded-full" data-testid={`text-account-status-${user.id}`}>
                              Active
                            </span>
                          ) : (
                            <span className="px-2 py-1 bg-red-100 bg-red-100 text-red-800 text-red-800 text-xs rounded-full" data-testid={`text-account-status-${user.id}`}>
                              Locked
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-[#374151]">
                          <div className="flex flex-col gap-1" data-testid={`video-stats-${user.id}`}>
                            <div className="flex items-center gap-2">
                              <Badge variant="secondary" className="bg-green-100 bg-green-100 text-green-800 text-green-800 text-xs">
                                <CheckCircle className="w-3 h-3 mr-1" />
                                {user.videoStats.completed}
                              </Badge>
                              <Badge variant="secondary" className="bg-red-100 bg-red-100 text-red-800 text-red-800 text-xs">
                                <XCircle className="w-3 h-3 mr-1" />
                                {user.videoStats.failed}
                              </Badge>
                              <Badge variant="secondary" className="bg-yellow-100 bg-yellow-100 text-yellow-800 text-yellow-800 text-xs">
                                <Clock className="w-3 h-3 mr-1" />
                                {user.videoStats.pending}
                              </Badge>
                            </div>
                            <span className="text-xs text-gray-500 text-[#6b7280]">
                              Total: {user.videoStats.total}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="text-[#374151] font-mono text-xs" data-testid={`text-ip-addresses-${user.id}`}>
                          <div className="space-y-1">
                            {user.allowedIp1 && (
                              <div className="text-xs">IP1: {user.allowedIp1}</div>
                            )}
                            {user.allowedIp2 && (
                              <div className="text-xs">IP2: {user.allowedIp2}</div>
                            )}
                            {!user.allowedIp1 && !user.allowedIp2 && "—"}
                            {(user.allowedIp1 || user.allowedIp2) && (
                              <Badge variant="secondary" className="text-xs">
                                {[user.allowedIp1, user.allowedIp2].filter(Boolean).length} IPs
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-[#374151] font-mono text-xs" data-testid={`text-token-${user.id}`}>
                          {user.apiToken ? `${user.apiToken.slice(0, 20)}...` : "—"}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-2 flex-wrap">
                            <Dialog open={editingUserId === user.id} onOpenChange={(open) => !open && setEditingUserId(null)}>
                              <DialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => handleEditPlan(user)}
                                  data-testid={`button-edit-plan-${user.id}`}
                                  className="border-[#e5e7eb] text-[#374151]"
                                >
                                  <Edit className="w-3 h-3 mr-1" />
                                  Plan
                                </Button>
                              </DialogTrigger>
                              <DialogContent className="bg-white border-[#e5e7eb]">
                                <DialogHeader>
                                  <DialogTitle className="text-[#1f2937]">Edit User Plan</DialogTitle>
                                  <DialogDescription className="text-[#6b7280]">
                                    Update plan settings for {user.username}
                                  </DialogDescription>
                                </DialogHeader>
                                <Form {...planForm}>
                                  <form onSubmit={planForm.handleSubmit(onPlanSubmit)} className="space-y-4">
                                    <FormField
                                      control={planForm.control}
                                      name="planType"
                                      render={({ field }) => (
                                        <FormItem>
                                          <FormLabel className="text-[#374151]">Plan Type</FormLabel>
                                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                                            <FormControl>
                                              <SelectTrigger className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]" data-testid="select-plan-type">
                                                <SelectValue placeholder="Select plan type" />
                                              </SelectTrigger>
                                            </FormControl>
                                            <SelectContent className="bg-white border-[#e5e7eb]">
                                              <SelectItem value="free">Free</SelectItem>
                                              <SelectItem value="scale">Scale (900 PKR - 10 days)</SelectItem>
                                              <SelectItem value="empire">Empire (1500 PKR - 10 days)</SelectItem>
                                              <SelectItem value="enterprise">Enterprise (Custom)</SelectItem>
                                            </SelectContent>
                                          </Select>
                                          <FormMessage className="text-red-600" />
                                        </FormItem>
                                      )}
                                    />

                                    <FormField
                                      control={planForm.control}
                                      name="planStatus"
                                      render={({ field }) => (
                                        <FormItem>
                                          <FormLabel className="text-[#374151]">Plan Status</FormLabel>
                                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                                            <FormControl>
                                              <SelectTrigger className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]" data-testid="select-plan-status">
                                                <SelectValue placeholder="Select status" />
                                              </SelectTrigger>
                                            </FormControl>
                                            <SelectContent className="bg-white border-[#e5e7eb]">
                                              <SelectItem value="active">Active</SelectItem>
                                              <SelectItem value="expired">Expired</SelectItem>
                                              <SelectItem value="cancelled">Cancelled</SelectItem>
                                            </SelectContent>
                                          </Select>
                                          <FormMessage className="text-red-600" />
                                        </FormItem>
                                      )}
                                    />

                                    <FormField
                                      control={planForm.control}
                                      name="planExpiry"
                                      render={({ field }) => (
                                        <FormItem>
                                          <FormLabel className="text-[#374151]">
                                            <Calendar className="w-4 h-4 inline mr-1" />
                                            Plan Expiry (optional)
                                          </FormLabel>
                                          <FormControl>
                                            <Input
                                              {...field}
                                              type="date"
                                              data-testid="input-plan-expiry"
                                              className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                                            />
                                          </FormControl>
                                          <FormMessage className="text-red-600" />
                                        </FormItem>
                                      )}
                                    />

                                    {selectedEditPlanType === "enterprise" && (
                                      <>
                                        <FormField
                                          control={planForm.control}
                                          name="dailyVideoLimit"
                                          render={({ field }) => (
                                            <FormItem>
                                              <FormLabel className="text-[#374151]">Daily Video Limit (0 = unlimited)</FormLabel>
                                              <FormControl>
                                                <Input
                                                  type="number"
                                                  min="0"
                                                  placeholder="e.g., 100"
                                                  data-testid="input-edit-daily-video-limit"
                                                  className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                                                  value={field.value ?? ""}
                                                  onChange={(e) => field.onChange(e.target.value ? parseInt(e.target.value) : undefined)}
                                                />
                                              </FormControl>
                                              <FormDescription className="text-[#6b7280] text-xs">
                                                Set a custom daily video generation limit
                                              </FormDescription>
                                              <FormMessage className="text-red-600" />
                                            </FormItem>
                                          )}
                                        />

                                        <FormField
                                          control={planForm.control}
                                          name="expiryDays"
                                          render={({ field }) => (
                                            <FormItem>
                                              <FormLabel className="text-[#374151]">Reset Duration (Days)</FormLabel>
                                              <FormControl>
                                                <Input
                                                  type="number"
                                                  min="1"
                                                  placeholder="e.g., 30"
                                                  data-testid="input-edit-expiry-days"
                                                  className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                                                  value={field.value ?? ""}
                                                  onChange={(e) => field.onChange(e.target.value ? parseInt(e.target.value) : undefined)}
                                                />
                                              </FormControl>
                                              <FormDescription className="text-[#6b7280] text-xs">
                                                Set new expiry from today (overrides Plan Expiry field)
                                              </FormDescription>
                                              <FormMessage className="text-red-600" />
                                            </FormItem>
                                          )}
                                        />

                                        <div className="border-t border-[#e5e7eb] pt-4 mt-4">
                                          <h4 className="text-sm font-medium text-[#374151] mb-3">Bulk Generation Settings</h4>
                                          
                                          <FormField
                                            control={planForm.control}
                                            name="bulkMaxBatch"
                                            render={({ field }) => (
                                              <FormItem className="mb-3">
                                                <FormLabel className="text-[#374151]">Max Batch Size</FormLabel>
                                                <FormControl>
                                                  <Input
                                                    type="number"
                                                    min="1"
                                                    placeholder="e.g., 50"
                                                    data-testid="input-edit-bulk-max-batch"
                                                    className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                                                    value={field.value ?? ""}
                                                    onChange={(e) => field.onChange(e.target.value ? parseInt(e.target.value) : undefined)}
                                                  />
                                                </FormControl>
                                                <FormDescription className="text-[#6b7280] text-xs">
                                                  Videos processed per batch
                                                </FormDescription>
                                                <FormMessage className="text-red-600" />
                                              </FormItem>
                                            )}
                                          />

                                          <FormField
                                            control={planForm.control}
                                            name="bulkDelaySeconds"
                                            render={({ field }) => (
                                              <FormItem className="mb-3">
                                                <FormLabel className="text-[#374151]">Batch Delay (Seconds)</FormLabel>
                                                <FormControl>
                                                  <Input
                                                    type="number"
                                                    min="0"
                                                    placeholder="e.g., 10"
                                                    data-testid="input-edit-bulk-delay-seconds"
                                                    className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                                                    value={field.value ?? ""}
                                                    onChange={(e) => field.onChange(e.target.value ? parseInt(e.target.value) : undefined)}
                                                  />
                                                </FormControl>
                                                <FormDescription className="text-[#6b7280] text-xs">
                                                  Delay between batches
                                                </FormDescription>
                                                <FormMessage className="text-red-600" />
                                              </FormItem>
                                            )}
                                          />

                                          <FormField
                                            control={planForm.control}
                                            name="bulkMaxPrompts"
                                            render={({ field }) => (
                                              <FormItem>
                                                <FormLabel className="text-[#374151]">Max Prompts</FormLabel>
                                                <FormControl>
                                                  <Input
                                                    type="number"
                                                    min="1"
                                                    placeholder="e.g., 200"
                                                    data-testid="input-edit-bulk-max-prompts"
                                                    className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                                                    value={field.value ?? ""}
                                                    onChange={(e) => field.onChange(e.target.value ? parseInt(e.target.value) : undefined)}
                                                  />
                                                </FormControl>
                                                <FormDescription className="text-[#6b7280] text-xs">
                                                  Maximum prompts allowed per bulk job
                                                </FormDescription>
                                                <FormMessage className="text-red-600" />
                                              </FormItem>
                                            )}
                                          />
                                        </div>
                                      </>
                                    )}

                                    <Button
                                      type="submit"
                                      className="w-full bg-[#374151] hover:bg-[#1f2937] text-white border-0"
                                      disabled={updatePlanMutation.isPending}
                                      data-testid="button-save-plan"
                                    >
                                      {updatePlanMutation.isPending ? "Saving..." : "Save Changes"}
                                    </Button>
                                  </form>
                                </Form>
                              </DialogContent>
                            </Dialog>

                            <Dialog open={editingTokenUserId === user.id} onOpenChange={(open) => !open && setEditingTokenUserId(null)}>
                              <DialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => handleEditToken(user)}
                                  data-testid={`button-edit-token-${user.id}`}
                                  className="border-[#e5e7eb] text-[#374151]"
                                >
                                  <Key className="w-3 h-3 mr-1" />
                                  Token
                                </Button>
                              </DialogTrigger>
                              <DialogContent className="bg-white border-[#e5e7eb]">
                                <DialogHeader>
                                  <DialogTitle className="text-[#1f2937]">Edit API Token</DialogTitle>
                                  <DialogDescription className="text-[#6b7280]">
                                    Update bearer token for {user.username}
                                  </DialogDescription>
                                </DialogHeader>
                                <Form {...tokenForm}>
                                  <form onSubmit={tokenForm.handleSubmit(onTokenSubmit)} className="space-y-4">
                                    <FormField
                                      control={tokenForm.control}
                                      name="apiToken"
                                      render={({ field }) => (
                                        <FormItem>
                                          <FormLabel className="text-[#374151]">
                                            <Key className="w-4 h-4 inline mr-1" />
                                            API Token
                                          </FormLabel>
                                          <FormControl>
                                            <Input
                                              {...field}
                                              placeholder="Enter API token"
                                              data-testid="input-api-token"
                                              className="font-mono bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                                            />
                                          </FormControl>
                                          <FormMessage className="text-red-600" />
                                        </FormItem>
                                      )}
                                    />

                                    <Button
                                      type="submit"
                                      className="w-full bg-[#374151] hover:bg-[#1f2937] text-white border-0"
                                      disabled={updateTokenMutation.isPending}
                                      data-testid="button-save-token"
                                    >
                                      {updateTokenMutation.isPending ? "Saving..." : "Save Token"}
                                    </Button>
                                  </form>
                                </Form>
                              </DialogContent>
                            </Dialog>

                            {!user.isAccountActive && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    data-testid={`button-reset-ip-${user.id}`}
                                    className=" border-green-500 text-green-700 hover:bg-green-50 "
                                  >
                                    <RefreshCw className="w-3 h-3 mr-1" />
                                    Reset IP
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent className="bg-white border-[#e5e7eb]">
                                  <AlertDialogHeader>
                                    <AlertDialogTitle className="text-[#1f2937]">Reset IP Limit</AlertDialogTitle>
                                    <AlertDialogDescription className="text-[#6b7280]">
                                      Are you sure you want to reset the IP limit for {user.username}? This will reactivate their account and clear all stored IP addresses, allowing them to log in from new locations.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel className="bg-gray-50 text-[#374151]">Cancel</AlertDialogCancel>
                                    <AlertDialogAction
                                      onClick={() => reactivateUserMutation.mutate(user.id)}
                                      className="bg-green-600 hover:bg-green-700 "
                                      data-testid={`button-confirm-reset-ip-${user.id}`}
                                    >
                                      Reset IP Limit
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}

                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  data-testid={`button-reset-video-count-${user.id}`}
                                  className=" border-blue-500 text-blue-700 hover:bg-blue-50 "
                                >
                                  <RefreshCw className="w-3 h-3 mr-1" />
                                  Reset Videos
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent className="bg-white border-[#e5e7eb]">
                                <AlertDialogHeader>
                                  <AlertDialogTitle className="text-[#1f2937]">Reset Video Count</AlertDialogTitle>
                                  <AlertDialogDescription className="text-[#6b7280]">
                                    Are you sure you want to reset the daily video generation count for {user.username}? This will set their daily video count to 0 and update the reset date.
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel className="bg-gray-50 text-[#374151]">Cancel</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() => resetVideoCountMutation.mutate(user.id)}
                                    className="bg-blue-600 hover:bg-blue-700 "
                                    data-testid={`button-confirm-reset-video-count-${user.id}`}
                                  >
                                    Reset Count
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>

                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  data-testid={`button-clear-user-data-${user.id}`}
                                  className=" border-[#374151] text-[#374151] hover:bg-gray-100 "
                                >
                                  <Eraser className="w-3 h-3 mr-1" />
                                  Clear Data
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent className="bg-white border-[#e5e7eb]">
                                <AlertDialogHeader>
                                  <AlertDialogTitle className="text-[#1f2937]">Clear User Data</AlertDialogTitle>
                                  <AlertDialogDescription className="text-[#6b7280]">
                                    This will delete ALL non-completed videos (pending, processing, failed, retrying) for {user.username}. Only completed videos will be preserved. The user's plan expiry date will NOT change. This action cannot be undone.
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel className="bg-gray-50 text-[#374151]">Cancel</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() => clearUserDataMutation.mutate(user.id)}
                                    className="bg-[#374151] hover:bg-[#1f2937] "
                                    data-testid={`button-confirm-clear-data-${user.id}`}
                                  >
                                    Clear Data
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>

                            {user.videoStats.pending > 0 && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    data-testid={`button-clear-pending-${user.id}`}
                                    className=" border-yellow-500 text-yellow-700 hover:bg-yellow-50 "
                                  >
                                    <Clock className="w-3 h-3 mr-1" />
                                    Clear Pending ({user.videoStats.pending})
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent className="bg-white border-[#e5e7eb]">
                                  <AlertDialogHeader>
                                    <AlertDialogTitle className="text-[#1f2937]">Clear Pending Videos</AlertDialogTitle>
                                    <AlertDialogDescription className="text-[#6b7280]">
                                      This will delete {user.videoStats.pending} pending/generating videos for {user.username}. This will also stop any active bulk processing queue. Completed and failed videos will NOT be affected. This action cannot be undone.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel className="bg-gray-50 text-[#374151]">Cancel</AlertDialogCancel>
                                    <AlertDialogAction
                                      onClick={() => clearPendingVideosMutation.mutate(user.id)}
                                      className="bg-yellow-600 hover:bg-yellow-700 "
                                      data-testid={`button-confirm-clear-pending-${user.id}`}
                                    >
                                      Clear Pending ({user.videoStats.pending})
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}

                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => forceResetQueueMutation.mutate(user.id)}
                              disabled={forceResetQueueMutation.isPending}
                              data-testid={`button-force-reset-queue-${user.id}`}
                              className="gap-1 border-blue-500 text-blue-700 hover:bg-blue-50"
                            >
                              <RotateCcw className="h-3 w-3" />
                              Reset Queue
                            </Button>

                            {user.planType !== "free" && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    data-testid={`button-remove-plan-${user.id}`}
                                    className=" border-orange-500 text-orange-700 hover:bg-orange-50 "
                                  >
                                    <XOctagon className="w-3 h-3 mr-1" />
                                    Remove
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent className="bg-white border-[#e5e7eb]">
                                  <AlertDialogHeader>
                                    <AlertDialogTitle className="text-[#1f2937]">Remove Plan</AlertDialogTitle>
                                    <AlertDialogDescription className="text-[#6b7280]">
                                      Are you sure you want to remove {user.username}'s plan? This will reset them to the free plan and clear their daily video count.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel className="bg-gray-50 text-[#374151]">Cancel</AlertDialogCancel>
                                    <AlertDialogAction
                                      onClick={() => removePlanMutation.mutate(user.id)}
                                      className="bg-orange-600 hover:bg-orange-700 "
                                      data-testid={`button-confirm-remove-plan-${user.id}`}
                                    >
                                      Remove Plan
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}

                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  data-testid={`button-delete-user-${user.id}`}
                                  className=" text-red-700 border-red-500 text-red-700 hover:bg-red-50 "
                                >
                                  <Trash2 className="w-3 h-3 mr-1" />
                                  Delete
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent className="bg-white border-[#e5e7eb]">
                                <AlertDialogHeader>
                                  <AlertDialogTitle className="text-[#1f2937]">Delete User</AlertDialogTitle>
                                  <AlertDialogDescription className="text-[#6b7280]">
                                    Are you sure you want to delete {user.username}? This action cannot be undone. All video history will be permanently deleted.
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel className="bg-gray-50 text-[#374151]">Cancel</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() => deleteUserMutation.mutate(user.id)}
                                    className="bg-red-600 hover:bg-red-700 "
                                    data-testid={`button-confirm-delete-${user.id}`}
                                  >
                                    Delete User
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
          </TabsContent>

          <TabsContent value="tokens">
        {/* Token Rotation Management */}
        <Card className="shadow-xl border-[#e5e7eb] bg-white">
          <CardHeader className="bg-[#374151]/10 border-b border-[#e5e7eb]">
            <CardTitle className="flex items-center gap-2 text-[#1f2937]">
              <RefreshCw className="w-5 h-5" />
              API Token Rotation
            </CardTitle>
            <CardDescription className="text-[#6b7280]">
              Manage multiple API tokens for load balancing and automatic rotation
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-6 bg-white">
            {/* Rotation Settings */}
            <div className="mb-6 p-4 bg-gray-50 bg-gray-50 rounded-lg">
              <h3 className="font-semibold mb-3 text-[#1f2937]">Rotation Settings</h3>
              <Form {...rotationSettingsForm}>
                <form
                  onSubmit={rotationSettingsForm.handleSubmit((data) =>
                    updateRotationSettingsMutation.mutate(data)
                  )}
                  className="space-y-4"
                >
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <FormField
                      control={rotationSettingsForm.control}
                      name="rotationEnabled"
                      render={({ field }) => (
                        <FormItem className="flex items-center gap-2">
                          <FormControl>
                            <Switch
                              checked={field.value}
                              onCheckedChange={field.onChange}
                              data-testid="switch-rotation-enabled"
                            />
                          </FormControl>
                          <FormLabel className="text-[#374151] mb-0">
                            Enable Rotation
                          </FormLabel>
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={rotationSettingsForm.control}
                      name="rotationIntervalMinutes"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-[#374151]">
                            Interval (minutes)
                          </FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              type="number"
                              data-testid="input-rotation-interval"
                              className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                            />
                          </FormControl>
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={rotationSettingsForm.control}
                      name="maxRequestsPerToken"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-[#374151]">
                            Max Requests/Token
                          </FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              type="number"
                              data-testid="input-max-requests"
                              className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                            />
                          </FormControl>
                        </FormItem>
                      )}
                    />
                  </div>

                  {/* Batch Processing Settings */}
                  <div className="mt-6 pt-4 border-t border-gray-200 border-[#e5e7eb]">
                    <h4 className="font-semibold mb-3 text-[#1f2937]">Batch Processing Configuration</h4>
                    <p className="text-sm text-[#6b7280] mb-4">
                      Configure how many videos are sent to the VEO API in each batch and the delay between batches to optimize generation performance.
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <FormField
                        control={rotationSettingsForm.control}
                        name="videosPerBatch"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-[#374151]">
                              Videos per Batch (1-50)
                            </FormLabel>
                            <FormControl>
                              <Input
                                {...field}
                                type="number"
                                min="1"
                                max="50"
                                data-testid="input-videos-per-batch"
                                className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                              />
                            </FormControl>
                            <FormDescription className="text-xs text-gray-500 text-[#6b7280]">
                              Number of videos sent in parallel in each batch
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={rotationSettingsForm.control}
                        name="batchDelaySeconds"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-[#374151]">
                              Batch Delay (10-120 seconds)
                            </FormLabel>
                            <FormControl>
                              <Input
                                {...field}
                                type="number"
                                min="10"
                                max="120"
                                data-testid="input-batch-delay"
                                className="bg-gray-50 border-[#e5e7eb] text-[#1f2937]"
                              />
                            </FormControl>
                            <FormDescription className="text-xs text-gray-500 text-[#6b7280]">
                              Delay in seconds between processing batches
                            </FormDescription>
                          </FormItem>
                        )}
                      />
                    </div>
                  </div>

                  <Button
                    type="submit"
                    className="bg-[#374151] hover:bg-[#1f2937] text-white border-0"
                    disabled={updateRotationSettingsMutation.isPending}
                    data-testid="button-save-rotation-settings"
                  >
                    {updateRotationSettingsMutation.isPending ? "Saving..." : "Save Settings"}
                  </Button>
                </form>
              </Form>
            </div>

            {/* Bulk Replace Tokens */}
            <div className="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
              <h3 className="font-semibold mb-2 text-[#1f2937] flex items-center gap-2">
                <svg className="w-5 h-5 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Bulk Replace All Tokens
              </h3>
              <p className="text-sm text-[#6b7280] mb-3">
                ⚠️ This will DELETE all existing tokens and replace them with new ones. "Bearer " prefix will be automatically removed.
              </p>
              <Form {...bulkReplaceForm}>
                <form
                  onSubmit={bulkReplaceForm.handleSubmit((data) => setShowBulkConfirmation(true))}
                  className="space-y-4"
                >
                  <FormField
                    control={bulkReplaceForm.control}
                    name="tokens"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-[#374151]">
                          Paste Tokens (one per line)
                        </FormLabel>
                        <FormControl>
                          <textarea
                            {...field}
                            rows={6}
                            placeholder="ya29.a0ARrdaM_example1&#10;Bearer ya29.a0ARrdaM_example2&#10;ya29.a0ARrdaM_example3"
                            className="w-full px-3 py-2 rounded-md border border-gray-300 border-[#e5e7eb] bg-white bg-gray-50 text-[#1f2937] font-mono text-sm resize-vertical"
                            data-testid="textarea-bulk-tokens"
                          />
                        </FormControl>
                        <FormMessage className="text-red-600" />
                      </FormItem>
                    )}
                  />
                  <Button
                    type="submit"
                    className="bg-yellow-600 hover:bg-yellow-700  text-white"
                    data-testid="button-bulk-replace"
                  >
                    Replace All Tokens
                  </Button>
                </form>
              </Form>
              
              {/* Confirmation Dialog */}
              {showBulkConfirmation && (
                <Dialog open={showBulkConfirmation} onOpenChange={setShowBulkConfirmation}>
                  <DialogContent className="bg-white">
                    <DialogHeader>
                      <DialogTitle className="text-red-600 text-red-600">Confirm Token Replacement</DialogTitle>
                      <DialogDescription className="text-[#374151]">
                        Are you sure you want to replace ALL existing tokens? This action cannot be undone.
                        All current tokens will be permanently deleted.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="flex gap-3 justify-end mt-4">
                      <Button
                        variant="outline"
                        onClick={() => setShowBulkConfirmation(false)}
                        data-testid="button-cancel-bulk"
                      >
                        Cancel
                      </Button>
                      <Button
                        className="bg-red-600 hover:bg-red-700 text-white "
                        onClick={() => bulkReplaceTokensMutation.mutate(bulkReplaceForm.getValues())}
                        disabled={bulkReplaceTokensMutation.isPending}
                        data-testid="button-confirm-bulk"
                      >
                        {bulkReplaceTokensMutation.isPending ? "Replacing..." : "Yes, Replace All"}
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              )}
            </div>

            {/* Add New Token */}
            <div className="mb-6 p-4 bg-gray-50 bg-gray-50 rounded-lg">
              <h3 className="font-semibold mb-3 text-[#1f2937]">Add New Token</h3>
              <Form {...addTokenForm}>
                <form
                  onSubmit={addTokenForm.handleSubmit((data) => addTokenMutation.mutate(data))}
                  className="space-y-4"
                >
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <FormField
                      control={addTokenForm.control}
                      name="label"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-[#374151]">Label</FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              placeholder="e.g., Primary Token"
                              data-testid="input-token-label"
                              className="bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                            />
                          </FormControl>
                          <FormMessage className="text-red-600" />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={addTokenForm.control}
                      name="token"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-[#374151]">Token</FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              placeholder="Enter API bearer token"
                              data-testid="input-new-token"
                              className="font-mono bg-gray-50 border-[#e5e7eb] text-[#1f2937] placeholder-[#9ca3af]"
                            />
                          </FormControl>
                          <FormMessage className="text-red-600" />
                        </FormItem>
                      )}
                    />
                  </div>
                  <Button
                    type="submit"
                    className="bg-[#374151] hover:bg-[#1f2937] text-white border-0"
                    disabled={addTokenMutation.isPending}
                    data-testid="button-add-token"
                  >
                    {addTokenMutation.isPending ? "Adding..." : "Add Token"}
                  </Button>
                </form>
              </Form>
            </div>

            {/* Token Summary */}
            {tokensData && tokensData.tokens.length > 0 && (
              <div className="mb-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-blue-600/10 border border-blue-500/30 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Key className="w-4 h-4 text-blue-400" />
                    <p className="text-sm font-medium text-[#6b7280]">Total Tokens</p>
                  </div>
                  <p className="text-2xl font-bold text-[#1f2937]" data-testid="stat-total-tokens">
                    {tokensData.tokens.length}
                  </p>
                </div>
                <div className="p-4 bg-green-600/10 border border-green-500/30 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    <p className="text-sm font-medium text-[#6b7280]">Active Tokens</p>
                  </div>
                  <p className="text-2xl font-bold text-[#1f2937]" data-testid="stat-active-tokens">
                    {tokensData.tokens.filter(t => t.isActive).length}
                  </p>
                </div>
                <div className="p-4 bg-red-600/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <XOctagon className="w-4 h-4 text-red-400" />
                    <p className="text-sm font-medium text-[#6b7280]">Disabled Tokens</p>
                  </div>
                  <p className="text-2xl font-bold text-[#1f2937]" data-testid="stat-disabled-tokens">
                    {tokensData.tokens.filter(t => !t.isActive).length}
                  </p>
                </div>
              </div>
            )}

            {/* Token List */}
            {isLoadingTokens ? (
              <p className="text-center py-4 text-[#6b7280]">Loading tokens...</p>
            ) : tokensData?.tokens.length === 0 ? (
              <p className="text-center py-4 text-[#6b7280]">
                No tokens added yet. Add a token above to start.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-[#e5e7eb]">
                      <TableHead className="text-[#374151]">Label</TableHead>
                      <TableHead className="text-[#374151]">Token</TableHead>
                      <TableHead className="text-[#374151]">Status</TableHead>
                      <TableHead className="text-[#374151]">Requests</TableHead>
                      <TableHead className="text-[#374151]">Last Used</TableHead>
                      <TableHead className="text-[#374151]">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tokensData?.tokens.map((token) => (
                      <TableRow key={token.id} className="border-[#e5e7eb]">
                        <TableCell className="font-medium text-[#1f2937]" data-testid={`token-label-${token.id}`}>
                          {token.label}
                        </TableCell>
                        <TableCell className="font-mono text-sm text-[#374151]" data-testid={`token-value-${token.id}`}>
                          {token.token.substring(0, 20)}...
                        </TableCell>
                        <TableCell data-testid={`token-status-${token.id}`}>
                          <Switch
                            checked={token.isActive}
                            onCheckedChange={(checked) =>
                              toggleTokenMutation.mutate({ tokenId: token.id, isActive: checked })
                            }
                            data-testid={`switch-token-status-${token.id}`}
                          />
                          <span className={`ml-2 text-sm ${token.isActive ? 'text-green-600' : 'text-gray-500'}`}>
                            {token.isActive ? "Active" : "Inactive"}
                          </span>
                        </TableCell>
                        <TableCell className="text-[#374151]" data-testid={`token-requests-${token.id}`}>
                          {token.requestCount}
                        </TableCell>
                        <TableCell className="text-[#374151]" data-testid={`token-last-used-${token.id}`}>
                          {token.lastUsedAt ? new Date(token.lastUsedAt).toLocaleString() : "Never"}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => deleteTokenMutation.mutate(token.id)}
                            disabled={deleteTokenMutation.isPending}
                            data-testid={`button-delete-token-${token.id}`}
                            className=""
                          >
                            Delete
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
          </TabsContent>

          <TabsContent value="plans">
        {/* Plan Availability Settings */}
        <Card className="shadow-xl border-[#e5e7eb] bg-white">
          <CardHeader className="bg-[#374151]/10 border-b border-[#e5e7eb]">
            <CardTitle className="flex items-center gap-2 text-[#1f2937]">
              <Shield className="w-5 h-5" />
              Plan Availability
            </CardTitle>
            <CardDescription className="text-[#6b7280]">
              Control which subscription plans are available for purchase
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-6 bg-white">
            <Form {...planAvailabilityForm}>
              <form
                onSubmit={planAvailabilityForm.handleSubmit((data) =>
                  updatePlanAvailabilityMutation.mutate(data)
                )}
                className="space-y-4"
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={planAvailabilityForm.control}
                    name="scalePlanAvailable"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-scale-plan-available"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            Scale Plan Available
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            Enable/disable the Scale plan (900 PKR)
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={planAvailabilityForm.control}
                    name="empirePlanAvailable"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-empire-plan-available"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            Empire Plan Available
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            Enable/disable the Empire plan (1500 PKR / $10)
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                </div>
                <Button
                  type="submit"
                  className="bg-[#374151] hover:bg-[#1f2937] text-white border-0"
                  disabled={updatePlanAvailabilityMutation.isPending}
                  data-testid="button-save-plan-availability"
                >
                  {updatePlanAvailabilityMutation.isPending ? "Saving..." : "Save Settings"}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
          </TabsContent>

          <TabsContent value="whatsapp">
        {/* WhatsApp Settings */}
        <Card className="shadow-xl border-[#e5e7eb] bg-white">
          <CardHeader className="bg-[#374151]/10 border-b border-[#e5e7eb]">
            <CardTitle className="flex items-center gap-2 text-[#1f2937]">
              <Settings className="w-5 h-5" />
              App Settings
            </CardTitle>
            <CardDescription className="text-[#6b7280]">
              Configure WhatsApp contact and Script Generation API key
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-6 bg-white">
            <Form {...appSettingsForm}>
              <form
                onSubmit={appSettingsForm.handleSubmit((data) =>
                  updateAppSettingsMutation.mutate(data)
                )}
                className="space-y-4"
              >
                <FormField
                  control={appSettingsForm.control}
                  name="whatsappUrl"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-[#374151]">WhatsApp Redirect URL</FormLabel>
                      <FormControl>
                        <Input
                          {...field}
                          placeholder="https://api.whatsapp.com/send?phone=..."
                          className="bg-gray-50 text-[#1f2937] border-[#e5e7eb]"
                          data-testid="input-whatsapp-url"
                        />
                      </FormControl>
                      <FormDescription className="text-[#6b7280]">
                        Full WhatsApp API URL with phone number and optional message
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={appSettingsForm.control}
                  name="scriptApiKey"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-[#374151] flex items-center gap-2">
                        <Key className="w-4 h-4" />
                        Script Generator API Key
                      </FormLabel>
                      <FormControl>
                        <Input
                          {...field}
                          type="password"
                          placeholder="sk-proj-..."
                          className="bg-gray-50 text-[#1f2937] border-[#e5e7eb] font-mono"
                          data-testid="input-script-api-key"
                        />
                      </FormControl>
                      <FormDescription className="text-[#6b7280]">
                        OpenAI-compatible API key for megallm.io script generation (optional - falls back to environment variable)
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={appSettingsForm.control}
                  name="geminiApiKey"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-[#374151] flex items-center gap-2">
                        <Key className="w-4 h-4" />
                        Gemini API Key
                      </FormLabel>
                      <FormControl>
                        <Input
                          {...field}
                          type="password"
                          placeholder="AIza..."
                          className="bg-gray-50 text-[#1f2937] border-[#e5e7eb] font-mono"
                          data-testid="input-gemini-api-key"
                        />
                      </FormControl>
                      <FormDescription className="text-[#6b7280]">
                        Google Gemini API key for Script to Frames feature (converts scripts to image prompts)
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={appSettingsForm.control}
                  name="cloudinaryCloudName"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-[#374151] flex items-center gap-2">
                        <ImageIcon className="w-4 h-4" />
                        Cloudinary Cloud Name
                      </FormLabel>
                      <FormControl>
                        <Input
                          {...field}
                          placeholder="dfk0nvgff"
                          className="bg-gray-50 text-[#1f2937] border-[#e5e7eb]"
                          data-testid="input-cloudinary-cloud-name"
                        />
                      </FormControl>
                      <FormDescription className="text-[#6b7280]">
                        Your Cloudinary cloud name for video/image uploads
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={appSettingsForm.control}
                  name="cloudinaryUploadPreset"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-[#374151] flex items-center gap-2">
                        <ImageIcon className="w-4 h-4" />
                        Cloudinary Upload Preset
                      </FormLabel>
                      <FormControl>
                        <Input
                          {...field}
                          placeholder="demo123"
                          className="bg-gray-50 text-[#1f2937] border-[#e5e7eb]"
                          data-testid="input-cloudinary-upload-preset"
                        />
                      </FormControl>
                      <FormDescription className="text-[#6b7280]">
                        Your Cloudinary upload preset name
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Storage Method Section */}
                <div className="border-t pt-6 mt-6 border-[#e5e7eb]">
                  <h3 className="text-lg font-semibold text-[#374151] mb-4 flex items-center gap-2">
                    <HardDrive className="w-5 h-5" />
                    Video Storage Settings
                  </h3>
                  
                  <FormField
                    control={appSettingsForm.control}
                    name="storageMethod"
                    render={({ field }) => (
                      <FormItem className="mb-6">
                        <FormLabel className="text-[#374151]">Storage Method</FormLabel>
                        <Select onValueChange={field.onChange} value={field.value}>
                          <FormControl>
                            <SelectTrigger className="bg-gray-50 text-[#1f2937] border-[#e5e7eb]" data-testid="select-storage-method">
                              <SelectValue placeholder="Select storage method" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="local_disk">Local Disk (VPS Storage)</SelectItem>
                            <SelectItem value="cloudinary">Cloudinary Only</SelectItem>
                            <SelectItem value="google_drive">Google Drive Only</SelectItem>
                            <SelectItem value="cloudinary_with_fallback">Cloudinary + Drive Fallback</SelectItem>
                            <SelectItem value="direct_to_user">Direct to User (No Upload)</SelectItem>
                          </SelectContent>
                        </Select>
                        <FormDescription className="text-[#6b7280]">
                          Choose how videos are stored after generation.
                          <br />
                          <span className="text-xs">
                            <strong>Local Disk (VPS):</strong> Store on your VPS disk. Videos auto-delete after 3 hours.
                            <br />
                            <strong>Cloudinary Only:</strong> Fast CDN delivery, may have limits.
                            <br />
                            <strong>Google Drive Only:</strong> Unlimited storage with service account.
                            <br />
                            <strong>Cloudinary + Drive Fallback:</strong> Uses Cloudinary first, falls back to Drive if it fails.
                            <br />
                            <strong>Direct to User:</strong> Video shown directly without uploading anywhere. Video will be lost after page refresh.
                          </span>
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={appSettingsForm.control}
                    name="googleDriveCredentials"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-[#374151] flex items-center gap-2">
                          <HardDrive className="w-4 h-4" />
                          Google Drive Service Account JSON
                        </FormLabel>
                        <FormControl>
                          <Textarea
                            {...field}
                            placeholder='{"type": "service_account", "project_id": "...", ...}'
                            className="bg-gray-50 text-[#1f2937] border-[#e5e7eb] font-mono text-xs min-h-[120px]"
                            data-testid="input-google-drive-credentials"
                          />
                        </FormControl>
                        <FormDescription className="text-[#6b7280]">
                          Required for Google Drive storage. Paste the complete service account JSON here.
                          <br />
                          <span className={appSettingsData?.settings?.googleDriveCredentials ? "text-green-600 font-medium" : "text-amber-600 font-medium"}>
                            {appSettingsData?.settings?.googleDriveCredentials ? "Connected" : "Not Connected"}
                          </span>
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={appSettingsForm.control}
                    name="googleDriveFolderId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-[#374151] flex items-center gap-2">
                          <HardDrive className="w-4 h-4" />
                          Google Drive Folder/Shared Drive ID
                        </FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            placeholder="0AA_GJi95SjbdUk9PVA"
                            className="bg-gray-50 text-[#1f2937] border-[#e5e7eb] font-mono"
                            data-testid="input-google-drive-folder-id"
                          />
                        </FormControl>
                        <FormDescription className="text-[#6b7280]">
                          Enter the Shared Drive ID or Folder ID where videos will be uploaded.
                          <br />
                          <span className="text-xs">
                            Find this in your Google Drive URL: drive.google.com/drive/folders/<strong>FOLDER_ID</strong>
                          </span>
                          <br />
                          <span className={appSettingsData?.settings?.googleDriveFolderId ? "text-green-600 font-medium" : "text-amber-600 font-medium"}>
                            {appSettingsData?.settings?.googleDriveFolderId ? `Configured: ${appSettingsData.settings.googleDriveFolderId}` : "Not Configured (using default)"}
                          </span>
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                {/* Logo Upload Section */}
                <div className="border-t pt-6 mt-6 border-[#e5e7eb]">
                  <div className="space-y-4">
                    <div>
                      <Label className="text-[#374151] flex items-center gap-2 mb-2">
                        <ImageIcon className="w-4 h-4" />
                        Application Logo
                      </Label>
                      <p className="text-sm text-[#6b7280] mb-4">
                        Upload a custom logo that will appear on Login, Signup, and other pages. Recommended size: 200x200px (PNG or JPG).
                      </p>
                    </div>
                    
                    <div className="flex items-center gap-4">
                      {/* Current Logo Preview */}
                      <div className="w-24 h-24 rounded-lg border border-[#e5e7eb] bg-gray-50 flex items-center justify-center overflow-hidden">
                        <img 
                          src={logoPreview || appSettingsData?.settings?.logoUrl || "/veo3-logo.png"} 
                          alt="Current Logo" 
                          className="max-w-full max-h-full object-contain"
                        />
                      </div>
                      
                      <div className="flex flex-col gap-2">
                        <input
                          type="file"
                          ref={logoInputRef}
                          accept="image/*"
                          className="hidden"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (file) handleLogoUpload(file);
                          }}
                          data-testid="input-logo-upload"
                        />
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => logoInputRef.current?.click()}
                          disabled={logoUploading}
                          className="border-[#374151] text-[#374151]"
                          data-testid="button-upload-logo"
                        >
                          {logoUploading ? (
                            <>
                              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                              Uploading...
                            </>
                          ) : (
                            <>
                              <ImageIcon className="w-4 h-4 mr-2" />
                              Upload New Logo
                            </>
                          )}
                        </Button>
                        
                        {(appSettingsData?.settings?.logoUrl || logoPreview) && (
                          <Button
                            type="button"
                            variant="outline"
                            onClick={handleRemoveLogo}
                            className="border-red-500 text-red-500 hover:bg-red-50"
                            data-testid="button-remove-logo"
                          >
                            <Trash2 className="w-4 h-4 mr-2" />
                            Remove Logo
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Enable/Disable Video Merge Feature */}
                <div className="border-t pt-6 mt-6 border-[#e5e7eb]">
                  <FormField
                    control={appSettingsForm.control}
                    name="enableVideoMerge"
                    render={({ field }) => (
                      <FormItem className="flex flex-row items-center justify-between rounded-md border p-4 border-[#e5e7eb]">
                        <div className="space-y-0.5">
                          <FormLabel className="text-[#374151]">Enable Video Merge Feature</FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            Show or hide the merge videos option in user video history
                          </FormDescription>
                        </div>
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-enable-video-merge"
                          />
                        </FormControl>
                      </FormItem>
                    )}
                  />
                </div>

                {/* Browser Pool Settings for VPS */}
                <div className="border-t pt-6 mt-6 border-[#e5e7eb]">
                  <div className="flex items-center gap-2 mb-4">
                    <Settings className="w-5 h-5 text-[#374151]" />
                    <h3 className="font-semibold text-[#1f2937]">Browser Pool Settings (VPS)</h3>
                  </div>
                  <p className="text-sm text-[#6b7280] mb-4">
                    Configure browser pool limits for optimal VPS performance. For 64GB VPS, recommended: 50-100 max contexts, 5-10 per user.
                  </p>
                  <div className="grid grid-cols-2 gap-4">
                    <FormField
                      control={appSettingsForm.control}
                      name="browserPoolMaxContexts"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-[#374151]">Max Browser Contexts (Global)</FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              type="number"
                              min="1"
                              max="200"
                              className="bg-gray-50 text-[#1f2937] border-[#e5e7eb]"
                              data-testid="input-browser-pool-max-contexts"
                            />
                          </FormControl>
                          <FormDescription className="text-[#6b7280]">
                            Total browser contexts allowed (1-200)
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={appSettingsForm.control}
                      name="browserPoolMaxPerUser"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-[#374151]">Max Contexts Per User</FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              type="number"
                              min="1"
                              max="50"
                              className="bg-gray-50 text-[#1f2937] border-[#e5e7eb]"
                              data-testid="input-browser-pool-max-per-user"
                            />
                          </FormControl>
                          <FormDescription className="text-[#6b7280]">
                            Per-user limit for fairness (1-50)
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                </div>

                <Button
                  type="submit"
                  className="bg-gradient-to-r from-green-600 to-emerald-600 text-white border-0"
                  disabled={updateAppSettingsMutation.isPending}
                  data-testid="button-save-whatsapp-settings"
                >
                  {updateAppSettingsMutation.isPending ? "Saving..." : "Save Settings"}
                </Button>
              </form>
            </Form>

            {/* Database Backup Section */}
            <div className="border-t pt-6 mt-6 border-[#e5e7eb]">
              <div className="flex items-center gap-2 mb-2">
                <Database className="w-5 h-5 text-[#374151]" />
                <h3 className="font-semibold text-[#1f2937]">Database Backup</h3>
              </div>
              <p className="text-sm text-[#6b7280] mb-4">
                Download a complete backup of all database tables. Choose your preferred format below. Video history is excluded due to size.
              </p>
              <div className="flex flex-wrap gap-3">
                <Button
                  type="button"
                  variant="outline"
                  className="border-[#374151] text-[#374151]"
                  onClick={() => {
                    window.open('/api/admin/database-backup', '_blank');
                    toast({
                      title: "JSON Download Started",
                      description: "Your database backup (JSON format) is being downloaded",
                    });
                  }}
                  data-testid="button-download-backup-json"
                >
                  <Download className="w-4 h-4 mr-2" />
                  JSON Format
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="border-[#374151] text-[#374151]"
                  onClick={() => {
                    window.open('/api/admin/database-backup-sql', '_blank');
                    toast({
                      title: "SQL Download Started",
                      description: "Your database backup (SQL format) is being downloaded",
                    });
                  }}
                  data-testid="button-download-backup-sql"
                >
                  <Download className="w-4 h-4 mr-2" />
                  SQL Format
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="border-[#374151] text-[#374151]"
                  onClick={() => {
                    window.open('/api/admin/database-backup-csv', '_blank');
                    toast({
                      title: "CSV Download Started",
                      description: "Your database backup (CSV files in ZIP) is being downloaded",
                    });
                  }}
                  data-testid="button-download-backup-csv"
                >
                  <Download className="w-4 h-4 mr-2" />
                  CSV Format (ZIP)
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
          </TabsContent>

          <TabsContent value="maintenance">
        {/* Tool Maintenance Settings */}
        <Card className="shadow-xl border-[#e5e7eb] bg-white">
          <CardHeader className="bg-[#374151]/10 border-b border-[#e5e7eb]">
            <CardTitle className="flex items-center gap-2 text-[#1f2937]">
              <Wrench className="w-5 h-5" />
              Tool Maintenance
            </CardTitle>
            <CardDescription className="text-[#6b7280]">
              Mark tools as under maintenance to temporarily disable them for users
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-6 bg-white">
            <Form {...toolMaintenanceForm}>
              <form
                onSubmit={toolMaintenanceForm.handleSubmit((data) =>
                  updateToolMaintenanceMutation.mutate(data)
                )}
                className="space-y-4"
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={toolMaintenanceForm.control}
                    name="veoGeneratorActive"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-veo-generator-active"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            VEO 3.1 Video Generator
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            {field.value ? "Active" : "Under Maintenance"}
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={toolMaintenanceForm.control}
                    name="bulkGeneratorActive"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-bulk-generator-active"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            Bulk Video Generator
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            {field.value ? "Active" : "Under Maintenance"}
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={toolMaintenanceForm.control}
                    name="textToImageActive"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-text-to-image-active"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            Text to Image Generator
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            {field.value ? "Active" : "Under Maintenance"}
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={toolMaintenanceForm.control}
                    name="imageToVideoActive"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-image-to-video-active"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            Image to Video
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            {field.value ? "Active" : "Under Maintenance"}
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={toolMaintenanceForm.control}
                    name="scriptCreatorActive"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-script-creator-active"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            Script Creator
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            {field.value ? "Active" : "Under Maintenance"}
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={toolMaintenanceForm.control}
                    name="characterConsistencyActive"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-3 space-y-0 rounded-md border p-4 border-[#e5e7eb]">
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-character-consistency-active"
                          />
                        </FormControl>
                        <div className="space-y-0.5">
                          <FormLabel className="text-base text-[#374151]">
                            Character Consistency
                          </FormLabel>
                          <FormDescription className="text-[#6b7280]">
                            {field.value ? "Active" : "Under Maintenance"}
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                </div>
                <Button
                  type="submit"
                  className="bg-gradient-to-r from-orange-600 to-red-600 text-white border-0"
                  disabled={updateToolMaintenanceMutation.isPending}
                  data-testid="button-save-tool-maintenance"
                >
                  {updateToolMaintenanceMutation.isPending ? "Saving..." : "Save Maintenance Settings"}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
          </TabsContent>

          <TabsContent value="monitor">
            <SystemMonitor />
          </TabsContent>

          <TabsContent value="history">
            <Card className="shadow-xl bg-white border-[#e5e7eb]">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <HistoryIcon className="w-5 h-5 text-blue-600 text-[#374151]" />
                  <CardTitle className="text-[#1f2937]">All Video History</CardTitle>
                </div>
                <CardDescription className="text-[#6b7280]">
                  Complete history of all generated videos across all users
                </CardDescription>
              </CardHeader>
              <CardContent>
                {allVideoHistory && allVideoHistory.videos.length > 0 ? (
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-[#e5e7eb]">
                          <TableHead className="text-[#374151]">Title</TableHead>
                          <TableHead className="text-[#374151]">User</TableHead>
                          <TableHead className="text-[#374151]">Status</TableHead>
                          <TableHead className="text-[#374151]">Error</TableHead>
                          <TableHead className="text-[#374151]">Retries</TableHead>
                          <TableHead className="text-[#374151]">Created</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {allVideoHistory.videos.slice(0, 100).map((video) => (
                          <TableRow key={video.id} className="border-[#e5e7eb]">
                            <TableCell className="font-medium text-[#1f2937] max-w-xs truncate" data-testid={`video-title-${video.id}`}>
                              {video.title || video.prompt.substring(0, 50) + '...'}
                            </TableCell>
                            <TableCell className="text-[#374151]" data-testid={`video-user-${video.id}`}>
                              {video.userId}
                            </TableCell>
                            <TableCell data-testid={`video-status-${video.id}`}>
                              {video.status === 'completed' && (
                                <Badge variant="default" className="bg-green-600">Completed</Badge>
                              )}
                              {video.status === 'pending' && (
                                <Badge variant="secondary" className="bg-yellow-600">Pending</Badge>
                              )}
                              {video.status === 'failed' && (
                                <Badge variant="destructive">Failed</Badge>
                              )}
                            </TableCell>
                            <TableCell className="text-[#374151] max-w-md" data-testid={`video-error-${video.id}`}>
                              {video.status === 'failed' && video.errorMessage ? (
                                <div className="flex items-start gap-2">
                                  <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                                  <span className="text-xs text-red-600 text-red-600 truncate" title={video.errorMessage}>
                                    {video.errorMessage}
                                  </span>
                                </div>
                              ) : (
                                <span className="text-gray-400">-</span>
                              )}
                            </TableCell>
                            <TableCell className="text-[#374151]" data-testid={`video-retries-${video.id}`}>
                              {video.retryCount || 0}/10
                            </TableCell>
                            <TableCell className="text-[#374151] text-sm" data-testid={`video-created-${video.id}`}>
                              {new Date(video.createdAt).toLocaleString()}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <p className="text-center py-8 text-gray-500 text-[#6b7280]">
                    No video history available
                  </p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="logs">
            <LogsViewer />
          </TabsContent>

          <TabsContent value="messages">
            <AdminMessagesTab />
          </TabsContent>

          <TabsContent value="flow">
            <FlowCookiesTab />
          </TabsContent>

          <TabsContent value="resellers">
            <AdminResellersTab />
          </TabsContent>

          <TabsContent value="zyphra">
            <ZyphraTokensTab />
          </TabsContent>

          <TabsContent value="pricing">
            <PricingPlansTab />
          </TabsContent>
        </Tabs>
      </div>

      {/* User Credentials Dialog */}
      <Dialog open={showCredentialsDialog} onOpenChange={setShowCredentialsDialog}>
        <DialogContent className="max-w-md bg-white border-[#374151]">
          <DialogHeader>
            <DialogTitle className="text-2xl font-bold text-center text-[#1f2937]">
              🎉 User Created Successfully!
            </DialogTitle>
            <DialogDescription className="text-center text-[#6b7280]">
              Share these credentials with the user
            </DialogDescription>
          </DialogHeader>
          
          {createdUserData && (() => {
            // Format expiry date as DD/MM/YYYY
            let formattedExpiry = "N/A";
            if (createdUserData.planExpiry) {
              const expiryDate = new Date(createdUserData.planExpiry);
              const day = expiryDate.getDate();
              const month = expiryDate.getMonth() + 1;
              const year = expiryDate.getFullYear();
              formattedExpiry = `${day}/${month}/${year}`;
            }

            // Format plan name with capital letter
            const planName = createdUserData.planType.charAt(0).toUpperCase() + createdUserData.planType.slice(1);

            const credentialsMessage = `🎉 *Veo3 Subscription Active!*

Khareedne ka shukriya. ❤️

🆔 *User:* ${createdUserData.username}
🔑 *Pass:* ${createdUserData.password}
📦 *Plan:* ${planName}
📅 *Expiry:* ${formattedExpiry}

⚠️ *Warning:* Max 2 devices allowed. Is se zyada par login karne se account *Ban* ho jayega.

🔗 *Login:* https://veo3.pk
📲 *Support Group (Must Join):* https://chat.whatsapp.com/G0bBQkFbtmQ6HspRB26tFC`;

            const handleCopyCredentials = async () => {
              try {
                await navigator.clipboard.writeText(credentialsMessage);
                setCopiedCredentials(true);
                toast({
                  title: "Copied to clipboard!",
                  description: "Credentials message copied successfully",
                });
                setTimeout(() => setCopiedCredentials(false), 2000);
              } catch (error) {
                toast({
                  variant: "destructive",
                  title: "Failed to copy",
                  description: "Please copy manually",
                });
              }
            };

            return (
              <div className="space-y-4">
                <div className="bg-black/30 rounded-lg p-4 border border-white/10">
                  <pre className="text-xs sm:text-sm text-gray-200 whitespace-pre-wrap font-mono leading-relaxed">
                    {credentialsMessage}
                  </pre>
                </div>

                <Button
                  onClick={handleCopyCredentials}
                  className="w-full bg-[#374151] hover:bg-[#1f2937] text-white border-0"
                  data-testid="button-copy-credentials"
                >
                  {copiedCredentials ? (
                    <>
                      <Check className="w-4 h-4 mr-2" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4 mr-2" />
                      Copy Credentials
                    </>
                  )}
                </Button>

                <div className="flex gap-2">
                  <Button
                    onClick={() => setShowCredentialsDialog(false)}
                    variant="outline"
                    className="flex-1 border-white/20 text-white hover:bg-white/10"
                    data-testid="button-close-credentials"
                  >
                    Close
                  </Button>
                </div>
              </div>
            );
          })()}
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface AdminMessageData {
  id: string;
  title: string;
  message: string;
  isActive: boolean;
  createdAt: string;
}

function AdminMessagesTab() {
  const { toast } = useToast();
  const [newTitle, setNewTitle] = useState("");
  const [newMessage, setNewMessage] = useState("");
  const [editingMessage, setEditingMessage] = useState<AdminMessageData | null>(null);
  const [editTitle, setEditTitle] = useState("");
  const [editMessageContent, setEditMessageContent] = useState("");
  const [editIsActive, setEditIsActive] = useState(true);

  const { data: messagesData, isLoading, refetch } = useQuery<{ messages: AdminMessageData[] }>({
    queryKey: ['/api/admin/messages'],
  });

  const createMutation = useMutation({
    mutationFn: async (data: { title: string; message: string }) => {
      const res = await fetch('/api/admin/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error('Failed to create message');
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Message created", description: "Admin message created successfully" });
      setNewTitle("");
      setNewMessage("");
      queryClient.invalidateQueries({ queryKey: ['/api/admin/messages'] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to create message", variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (data: { id: string; title: string; message: string; isActive: boolean }) => {
      const res = await fetch(`/api/admin/messages/${data.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ title: data.title, message: data.message, isActive: data.isActive }),
      });
      if (!res.ok) throw new Error('Failed to update message');
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Message updated", description: "Admin message updated successfully" });
      setEditingMessage(null);
      queryClient.invalidateQueries({ queryKey: ['/api/admin/messages'] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to update message", variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`/api/admin/messages/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      if (!res.ok) throw new Error('Failed to delete message');
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Message deleted", description: "Admin message deleted successfully" });
      queryClient.invalidateQueries({ queryKey: ['/api/admin/messages'] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to delete message", variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async (data: { id: string; isActive: boolean }) => {
      const res = await fetch(`/api/admin/messages/${data.id}/toggle`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ isActive: data.isActive }),
      });
      if (!res.ok) throw new Error('Failed to toggle message');
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Status updated", description: "Message status updated successfully" });
      queryClient.invalidateQueries({ queryKey: ['/api/admin/messages'] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to toggle message status", variant: "destructive" });
    },
  });

  const handleCreateMessage = () => {
    if (!newTitle.trim() || !newMessage.trim()) {
      toast({ title: "Error", description: "Title and message are required", variant: "destructive" });
      return;
    }
    createMutation.mutate({ title: newTitle, message: newMessage });
  };

  const handleUpdateMessage = () => {
    if (!editingMessage || !editTitle.trim() || !editMessageContent.trim()) {
      toast({ title: "Error", description: "Title and message are required", variant: "destructive" });
      return;
    }
    updateMutation.mutate({ id: editingMessage.id, title: editTitle, message: editMessageContent, isActive: editIsActive });
  };

  const startEditing = (msg: AdminMessageData) => {
    setEditingMessage(msg);
    setEditTitle(msg.title);
    setEditMessageContent(msg.message);
    setEditIsActive(msg.isActive);
  };

  return (
    <div className="space-y-6">
      <Card className="shadow-sm bg-white border border-[#e5e7eb]">
        <CardHeader>
          <div className="flex items-center gap-2">
            <MessageCircle className="w-5 h-5 text-[#374151]" />
            <CardTitle className="text-[#1f2937]">Create New Message</CardTitle>
          </div>
          <CardDescription className="text-[#6b7280]">
            Send notifications to all users. Messages will appear in the notification bell.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-[#374151]">Title</Label>
            <Input
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="Message title..."
              className="mt-1"
              data-testid="input-message-title"
            />
          </div>
          <div>
            <Label className="text-[#374151]">Message</Label>
            <Textarea
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              placeholder="Your message to users..."
              className="mt-1 min-h-[100px]"
              data-testid="input-message-content"
            />
          </div>
          <Button
            onClick={handleCreateMessage}
            disabled={createMutation.isPending || !newTitle.trim() || !newMessage.trim()}
            className="bg-[#374151] text-white hover:bg-[#1f2937]"
            data-testid="button-create-message"
          >
            {createMutation.isPending ? (
              <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> Creating...</>
            ) : (
              <><Plus className="w-4 h-4 mr-2" /> Create Message</>
            )}
          </Button>
        </CardContent>
      </Card>

      <Card className="shadow-sm bg-white border border-[#e5e7eb]">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <MessageCircle className="w-5 h-5 text-[#374151]" />
              <CardTitle className="text-[#1f2937]">All Messages</CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              className="border-[#374151] text-[#374151] hover:bg-[#374151] hover:text-white"
              data-testid="button-refresh-messages"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
          </div>
          <CardDescription className="text-[#6b7280]">
            Manage admin messages. Toggle active status to show/hide from users.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center p-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
            </div>
          ) : messagesData?.messages?.length === 0 ? (
            <p className="text-center py-8 text-[#6b7280]">No messages yet. Create your first message above.</p>
          ) : (
            <div className="space-y-4">
              {messagesData?.messages?.map((msg) => (
                <div
                  key={msg.id}
                  className={`p-4 rounded-lg border ${msg.isActive ? 'border-green-200 bg-green-50' : 'border-gray-200 bg-gray-50'}`}
                  data-testid={`message-card-${msg.id}`}
                >
                  {editingMessage?.id === msg.id ? (
                    <div className="space-y-3">
                      <Input
                        value={editTitle}
                        onChange={(e) => setEditTitle(e.target.value)}
                        placeholder="Title"
                        data-testid="input-edit-title"
                      />
                      <Textarea
                        value={editMessageContent}
                        onChange={(e) => setEditMessageContent(e.target.value)}
                        placeholder="Message"
                        className="min-h-[80px]"
                        data-testid="input-edit-message"
                      />
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={editIsActive}
                          onCheckedChange={setEditIsActive}
                          data-testid="switch-edit-active"
                        />
                        <Label className="text-sm text-[#6b7280]">Active</Label>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          onClick={handleUpdateMessage}
                          disabled={updateMutation.isPending}
                          className="bg-[#374151] text-white hover:bg-[#1f2937]"
                          data-testid="button-save-edit"
                        >
                          <Save className="w-4 h-4 mr-1" /> Save
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setEditingMessage(null)}
                          data-testid="button-cancel-edit"
                        >
                          <X className="w-4 h-4 mr-1" /> Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <h4 className="font-semibold text-[#1f2937]">{msg.title}</h4>
                            <Badge variant={msg.isActive ? "default" : "secondary"} className={msg.isActive ? 'bg-green-500' : ''}>
                              {msg.isActive ? 'Active' : 'Inactive'}
                            </Badge>
                          </div>
                          <p className="text-[#6b7280] text-sm whitespace-pre-wrap">{msg.message}</p>
                          <p className="text-xs text-[#9ca3af] mt-2">
                            Created: {new Date(msg.createdAt).toLocaleString()}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => toggleMutation.mutate({ id: msg.id, isActive: !msg.isActive })}
                            disabled={toggleMutation.isPending}
                            data-testid={`button-toggle-${msg.id}`}
                          >
                            <Power className={`w-4 h-4 ${msg.isActive ? 'text-green-500' : 'text-gray-400'}`} />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => startEditing(msg)}
                            data-testid={`button-edit-${msg.id}`}
                          >
                            <Edit className="w-4 h-4 text-[#374151]" />
                          </Button>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button
                                size="icon"
                                variant="ghost"
                                data-testid={`button-delete-${msg.id}`}
                              >
                                <Trash2 className="w-4 h-4 text-red-500" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Delete Message</AlertDialogTitle>
                                <AlertDialogDescription>
                                  Are you sure you want to delete this message? This action cannot be undone.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                  onClick={() => deleteMutation.mutate(msg.id)}
                                  className="bg-red-500 hover:bg-red-600"
                                >
                                  Delete
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function LogsViewer() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lines, setLines] = useState(500);
  const scrollRef = useRef<HTMLDivElement>(null);
  
  const { data: logs, isLoading, refetch } = useQuery<{ logs: string }>({
    queryKey: [`/api/admin/logs?lines=${lines}`],
    refetchInterval: autoRefresh ? 3000 : false, // Auto-refresh every 3 seconds if enabled
  });

  // Auto-scroll to bottom when logs update
  useEffect(() => {
    if (scrollRef.current && autoRefresh) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, autoRefresh]);

  return (
    <Card className="shadow-sm bg-white border border-[#e5e7eb]">
      <CardHeader>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-[#374151]" />
            <CardTitle className="text-[#1f2937]">Server Logs</CardTitle>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <label className="text-sm text-[#6b7280]">Lines:</label>
              <Select value={lines.toString()} onValueChange={(val) => setLines(parseInt(val))}>
                <SelectTrigger className="w-24 bg-white/5 border-white/10 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="100">100</SelectItem>
                  <SelectItem value="200">200</SelectItem>
                  <SelectItem value="500">500</SelectItem>
                  <SelectItem value="1000">1000</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                checked={autoRefresh}
                onCheckedChange={setAutoRefresh}
                data-testid="switch-auto-refresh"
              />
              <label className="text-sm text-[#6b7280]">Auto-scroll (3s)</label>
            </div>
            <Button
              onClick={() => refetch()}
              variant="outline"
              size="sm"
              className="border-white/20 text-white hover:bg-white/10"
              data-testid="button-refresh-logs"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
          </div>
        </div>
        <CardDescription className="text-[#6b7280]">
          Real-time application logs (last {lines} lines) • Auto-scrolling to latest
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center p-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
          </div>
        ) : (
          <div 
            ref={scrollRef}
            className="h-[600px] w-full rounded-md border border-white/10 bg-black/40 p-4 overflow-y-auto"
          >
            <pre className="text-xs font-mono text-[#6b7280] whitespace-pre-wrap break-words">
              {logs?.logs || "No logs available"}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Flow Cookies Tab Component
interface FlowCookieData {
  id: string;
  label: string;
  cookieData: string;
  isActive: boolean;
  lastUsedAt: string | null;
  successCount: number;
  failCount: number;
  expiredCount: number;
  createdAt: string;
}

interface ValidationResult {
  id: string;
  label: string;
  email: string;
  valid: boolean;
  error?: string;
}

interface ValidationResponse {
  success: boolean;
  total: number;
  valid: number;
  expired: number;
  results: ValidationResult[];
}

function FlowCookiesTab() {
  const { toast } = useToast();
  const [bulkCookies, setBulkCookies] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [newCookieData, setNewCookieData] = useState("");
  const [viewingCookie, setViewingCookie] = useState<FlowCookieData | null>(null);
  const [validationResults, setValidationResults] = useState<ValidationResponse | null>(null);
  const [isValidating, setIsValidating] = useState(false);

  const { data: cookiesData, isLoading, refetch } = useQuery<{ cookies: FlowCookieData[] }>({
    queryKey: ["/api/admin/flow-cookies"],
  });

  const handleValidateAllCookies = async () => {
    setIsValidating(true);
    setValidationResults(null);
    
    try {
      toast({ title: "Validation Started", description: "Checking all cookies... This may take a few minutes." });
      
      const res = await fetch("/api/admin/flow-cookies/validate-all", {
        method: "POST",
        credentials: "include",
      });
      
      if (!res.ok) throw new Error("Validation failed");
      
      const data: ValidationResponse = await res.json();
      setValidationResults(data);
      
      toast({ 
        title: "Validation Complete", 
        description: `${data.valid} valid, ${data.expired} expired out of ${data.total} cookies` 
      });
      
      queryClient.invalidateQueries({ queryKey: ["/api/admin/flow-cookies"] });
    } catch (error) {
      toast({ title: "Error", description: "Failed to validate cookies", variant: "destructive" });
    } finally {
      setIsValidating(false);
    }
  };

  const addBulkMutation = useMutation({
    mutationFn: async (cookies: string) => {
      const res = await fetch("/api/admin/flow-cookies/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ cookies }),
      });
      if (!res.ok) throw new Error("Failed to add cookies");
      return res.json();
    },
    onSuccess: (data) => {
      toast({ title: "Cookies Added", description: `Added ${data.count} cookies successfully` });
      setBulkCookies("");
      queryClient.invalidateQueries({ queryKey: ["/api/admin/flow-cookies"] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to add cookies", variant: "destructive" });
    },
  });

  const addSingleMutation = useMutation({
    mutationFn: async (data: { label: string; cookieData: string }) => {
      const res = await fetch("/api/admin/flow-cookies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error("Failed to add cookie");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Cookie Added", description: "Flow cookie added successfully" });
      setNewLabel("");
      setNewCookieData("");
      queryClient.invalidateQueries({ queryKey: ["/api/admin/flow-cookies"] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to add cookie", variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async (data: { id: string; isActive: boolean }) => {
      const res = await fetch(`/api/admin/flow-cookies/${data.id}/toggle`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ isActive: data.isActive }),
      });
      if (!res.ok) throw new Error("Failed to toggle cookie");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Status Updated", description: "Cookie status updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/flow-cookies"] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to update status", variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`/api/admin/flow-cookies/${id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete cookie");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Deleted", description: "Cookie deleted successfully" });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/flow-cookies"] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to delete cookie", variant: "destructive" });
    },
  });

  const deleteAllMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/admin/flow-cookies", {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete all cookies");
      return res.json();
    },
    onSuccess: (data) => {
      toast({ title: "All Deleted", description: `Deleted ${data.deletedCount} cookies` });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/flow-cookies"] });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to delete all cookies", variant: "destructive" });
    },
  });

  const handleBulkAdd = () => {
    if (!bulkCookies.trim()) {
      toast({ title: "Error", description: "Please enter cookies", variant: "destructive" });
      return;
    }
    addBulkMutation.mutate(bulkCookies);
  };

  const handleAddSingle = () => {
    if (!newLabel.trim() || !newCookieData.trim()) {
      toast({ title: "Error", description: "Label and cookie data required", variant: "destructive" });
      return;
    }
    addSingleMutation.mutate({ label: newLabel, cookieData: newCookieData });
  };

  return (
    <div className="space-y-6">
      {/* Bulk Add Cookies */}
      <Card className="shadow-sm bg-white border border-[#e5e7eb]">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-[#374151]" />
            <CardTitle className="text-[#1f2937]">Bulk Add Flow Cookies</CardTitle>
          </div>
          <CardDescription className="text-[#6b7280]">
            Paste multiple cookies line by line. Format: email|[JSON cookies] or just cookie data
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder={`Paste cookies here, one per line...\n\nFormat: email|[JSON cookies]\n\nExample:\nuser@email.com|[{"name":"__Host-next-auth.csrf-token","value":"xxx",...}]\nanother@email.com|[{"name":"__Host-next-auth.csrf-token","value":"yyy",...}]`}
            value={bulkCookies}
            onChange={(e) => setBulkCookies(e.target.value)}
            className="min-h-[150px] font-mono text-sm"
            data-testid="textarea-bulk-cookies"
          />
          <div className="flex gap-2">
            <Button
              onClick={handleBulkAdd}
              disabled={addBulkMutation.isPending}
              className="bg-[#374151] text-white"
              data-testid="button-add-bulk-cookies"
            >
              <Plus className="w-4 h-4 mr-2" />
              {addBulkMutation.isPending ? "Adding..." : "Add All Cookies"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Single Cookie Add */}
      <Card className="shadow-sm bg-white border border-[#e5e7eb]">
        <CardHeader>
          <CardTitle className="text-[#1f2937]">Add Single Cookie</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <Label className="text-[#374151]">Label</Label>
              <Input
                placeholder="Account 1"
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
                data-testid="input-cookie-label"
              />
            </div>
            <div>
              <Label className="text-[#374151]">Cookie Data</Label>
              <Input
                placeholder="Paste cookie JSON or string..."
                value={newCookieData}
                onChange={(e) => setNewCookieData(e.target.value)}
                data-testid="input-cookie-data"
              />
            </div>
          </div>
          <Button
            onClick={handleAddSingle}
            disabled={addSingleMutation.isPending}
            variant="outline"
            className="border-[#374151] text-[#374151]"
            data-testid="button-add-single-cookie"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Cookie
          </Button>
        </CardContent>
      </Card>

      {/* Cookie Validator Tool */}
      <Card className="shadow-sm bg-white border border-[#e5e7eb]">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[#374151]" />
            <CardTitle className="text-[#1f2937]">Cookie Validator Tool</CardTitle>
          </div>
          <CardDescription className="text-[#6b7280]">
            Check all cookies to find expired accounts. This will test each cookie by navigating to Flow.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button
            onClick={handleValidateAllCookies}
            disabled={isValidating || !cookiesData?.cookies?.length}
            className="bg-orange-600 text-white"
            data-testid="button-validate-all-cookies"
          >
            {isValidating ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                Validating... (This takes time)
              </>
            ) : (
              <>
                <Shield className="w-4 h-4 mr-2" />
                Validate All {cookiesData?.cookies?.length || 0} Cookies
              </>
            )}
          </Button>
          
          {validationResults && (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="p-3 bg-gray-100 rounded-md text-center">
                  <div className="text-2xl font-bold text-[#374151]">{validationResults.total}</div>
                  <div className="text-sm text-[#6b7280]">Total Cookies</div>
                </div>
                <div className="p-3 bg-green-100 rounded-md text-center">
                  <div className="text-2xl font-bold text-green-700">{validationResults.valid}</div>
                  <div className="text-sm text-green-600">Valid</div>
                </div>
                <div className="p-3 bg-red-100 rounded-md text-center">
                  <div className="text-2xl font-bold text-red-700">{validationResults.expired}</div>
                  <div className="text-sm text-red-600">Expired</div>
                </div>
              </div>
              
              {validationResults.expired > 0 && (
                <div className="mt-4">
                  <h4 className="font-semibold text-red-700 mb-2">Expired Accounts ({validationResults.expired}):</h4>
                  <div className="bg-red-50 border border-red-200 rounded-md p-4 max-h-[400px] overflow-y-auto">
                    <div className="space-y-1 font-mono text-sm">
                      {validationResults.results
                        .filter(r => !r.valid)
                        .map((r, idx) => (
                          <div key={r.id} className="text-red-700" data-testid={`expired-email-${idx}`}>
                            {idx + 1}. {r.email} ({r.label})
                          </div>
                        ))}
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2"
                    onClick={() => {
                      const expiredEmails = validationResults.results
                        .filter(r => !r.valid)
                        .map(r => r.email)
                        .join('\n');
                      navigator.clipboard.writeText(expiredEmails);
                      toast({ title: "Copied", description: "Expired emails copied to clipboard" });
                    }}
                    data-testid="button-copy-expired-emails"
                  >
                    <Copy className="w-4 h-4 mr-2" />
                    Copy Expired Emails
                  </Button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Cookies List */}
      <Card className="shadow-sm bg-white border border-[#e5e7eb]">
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-[#374151]" />
              <CardTitle className="text-[#1f2937]">
                Flow Cookies ({cookiesData?.cookies?.length || 0})
              </CardTitle>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={() => refetch()}
                variant="outline"
                size="sm"
                className="border-[#374151] text-[#374151]"
                data-testid="button-refresh-cookies"
              >
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </Button>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    variant="destructive"
                    size="sm"
                    disabled={!cookiesData?.cookies?.length}
                    data-testid="button-delete-all-cookies"
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Delete All
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent className="bg-white">
                  <AlertDialogHeader>
                    <AlertDialogTitle>Delete All Cookies?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This will permanently delete all {cookiesData?.cookies?.length || 0} cookies. This action cannot be undone.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      onClick={() => deleteAllMutation.mutate()}
                      className="bg-red-600 hover:bg-red-700"
                    >
                      Delete All
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center p-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
            </div>
          ) : cookiesData?.cookies && cookiesData.cookies.length > 0 ? (
            <ScrollArea className="h-[600px]">
              <Table>
                <TableHeader>
                  <TableRow className="bg-[#f9fafb]">
                    <TableHead className="text-[#374151]">Label</TableHead>
                    <TableHead className="text-[#374151]">Cookie Data</TableHead>
                    <TableHead className="text-[#374151]">Status</TableHead>
                    <TableHead className="text-[#374151]">Success</TableHead>
                    <TableHead className="text-[#374151]">Failed</TableHead>
                    <TableHead className="text-[#374151]">Expired</TableHead>
                    <TableHead className="text-[#374151]">Last Used</TableHead>
                    <TableHead className="text-[#374151]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {cookiesData.cookies.map((cookie) => (
                    <TableRow key={cookie.id}>
                      <TableCell className="text-[#374151] font-medium" data-testid={`cookie-label-${cookie.id}`}>
                        {cookie.label}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setViewingCookie(cookie)}
                          className="text-xs"
                          data-testid={`button-view-cookie-${cookie.id}`}
                        >
                          <Eye className="w-3 h-3 mr-1" />
                          View ({cookie.cookieData?.length || 0} chars)
                        </Button>
                      </TableCell>
                      <TableCell>
                        <Badge className={cookie.isActive ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}>
                          {cookie.isActive ? "Active" : "Inactive"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-green-600 font-medium">
                        {cookie.successCount}
                      </TableCell>
                      <TableCell className="text-red-600 font-medium">
                        {cookie.failCount}
                      </TableCell>
                      <TableCell className="text-orange-600 font-medium">
                        {cookie.expiredCount || 0}
                      </TableCell>
                      <TableCell className="text-[#6b7280] text-sm">
                        {cookie.lastUsedAt ? new Date(cookie.lastUsedAt).toLocaleString() : "Never"}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => toggleMutation.mutate({ id: cookie.id, isActive: !cookie.isActive })}
                            data-testid={`button-toggle-cookie-${cookie.id}`}
                          >
                            <Power className={`w-4 h-4 ${cookie.isActive ? "text-red-500" : "text-green-500"}`} />
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => deleteMutation.mutate(cookie.id)}
                            data-testid={`button-delete-cookie-${cookie.id}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          ) : (
            <p className="text-center py-8 text-[#6b7280]">
              No cookies added yet. Add cookies above to enable video generation.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Cookie Data View Dialog */}
      <Dialog open={!!viewingCookie} onOpenChange={() => setViewingCookie(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] bg-white">
          <DialogHeader>
            <DialogTitle className="text-[#1f2937]">
              Cookie Data: {viewingCookie?.label}
            </DialogTitle>
            <DialogDescription className="text-[#6b7280]">
              Full cookie data for this account ({viewingCookie?.cookieData?.length || 0} characters)
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-center gap-4 text-sm text-[#6b7280]">
              <span>Status: <Badge className={viewingCookie?.isActive ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}>{viewingCookie?.isActive ? "Active" : "Inactive"}</Badge></span>
              <span>Success: <span className="text-green-600 font-medium">{viewingCookie?.successCount}</span></span>
              <span>Failed: <span className="text-red-600 font-medium">{viewingCookie?.failCount}</span></span>
            </div>
            <Textarea
              value={viewingCookie?.cookieData || ""}
              readOnly
              className="min-h-[300px] font-mono text-xs"
              data-testid="textarea-view-cookie-data"
            />
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => {
                  if (viewingCookie?.cookieData) {
                    navigator.clipboard.writeText(viewingCookie.cookieData);
                    toast({ title: "Copied", description: "Cookie data copied to clipboard" });
                  }
                }}
                data-testid="button-copy-cookie-data"
              >
                <Copy className="w-4 h-4 mr-2" />
                Copy to Clipboard
              </Button>
              <Button variant="ghost" onClick={() => setViewingCookie(null)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface ResellerData {
  id: string;
  username: string;
  creditBalance: number;
  isActive: boolean;
  createdAt: string;
}

interface ResellerLedgerEntry {
  id: string;
  resellerId: string;
  creditChange: number;
  balanceAfter: number;
  reason: string;
  createdAt: string;
}

interface ResellerUser {
  id: string;
  resellerId: string;
  userId: string;
  creditCost: number;
  planType: string;
  createdAt: string;
  user?: {
    id: string;
    username: string;
    planType: string;
    planStatus: string;
    isAccountActive: boolean;
  };
}

const createResellerSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  creditBalance: z.coerce.number().min(0, "Credits must be 0 or more").default(0),
});

const addCreditsSchema = z.object({
  amount: z.coerce.number().positive("Amount must be positive"),
  reason: z.string().optional(),
});

type CreateResellerFormData = z.infer<typeof createResellerSchema>;
type AddCreditsFormData = z.infer<typeof addCreditsSchema>;

function AdminResellersTab() {
  const { toast } = useToast();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showAddCreditsDialog, setShowAddCreditsDialog] = useState(false);
  const [showRemoveCreditsDialog, setShowRemoveCreditsDialog] = useState(false);
  const [showLedgerDialog, setShowLedgerDialog] = useState(false);
  const [showUsersDialog, setShowUsersDialog] = useState(false);
  const [selectedReseller, setSelectedReseller] = useState<ResellerData | null>(null);

  const createForm = useForm<CreateResellerFormData>({
    resolver: zodResolver(createResellerSchema),
    defaultValues: {
      username: "",
      password: "",
      creditBalance: 0,
    },
  });

  const addCreditsForm = useForm<AddCreditsFormData>({
    resolver: zodResolver(addCreditsSchema),
    defaultValues: {
      amount: 0,
      reason: "",
    },
  });

  const removeCreditsForm = useForm<AddCreditsFormData>({
    resolver: zodResolver(addCreditsSchema),
    defaultValues: {
      amount: 0,
      reason: "",
    },
  });

  const { data: resellersData, isLoading: loadingResellers, refetch: refetchResellers } = useQuery<{ resellers: ResellerData[] }>({
    queryKey: ["/api/admin/resellers"],
  });

  const { data: ledgerData, isLoading: loadingLedger } = useQuery<{ ledger: ResellerLedgerEntry[] }>({
    queryKey: ["/api/admin/resellers", selectedReseller?.id, "ledger"],
    enabled: !!selectedReseller && showLedgerDialog,
  });

  const { data: usersData, isLoading: loadingUsers } = useQuery<{ users: ResellerUser[] }>({
    queryKey: ["/api/admin/resellers", selectedReseller?.id, "users"],
    enabled: !!selectedReseller && showUsersDialog,
  });

  const createResellerMutation = useMutation({
    mutationFn: async (data: CreateResellerFormData) => {
      const response = await apiRequest("POST", "/api/admin/resellers", data);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Reseller created successfully" });
      setShowCreateDialog(false);
      createForm.reset();
      queryClient.invalidateQueries({ queryKey: ["/api/admin/resellers"] });
    },
    onError: (error: any) => {
      toast({ variant: "destructive", title: error.message || "Failed to create reseller" });
    },
  });

  const addCreditsMutation = useMutation({
    mutationFn: async (data: AddCreditsFormData) => {
      const response = await apiRequest("POST", `/api/admin/resellers/${selectedReseller?.id}/add-credits`, data);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Credits added successfully" });
      setShowAddCreditsDialog(false);
      addCreditsForm.reset();
      queryClient.invalidateQueries({ queryKey: ["/api/admin/resellers"] });
    },
    onError: (error: any) => {
      toast({ variant: "destructive", title: error.message || "Failed to add credits" });
    },
  });

  const removeCreditsMutation = useMutation({
    mutationFn: async (data: AddCreditsFormData) => {
      const response = await apiRequest("POST", `/api/admin/resellers/${selectedReseller?.id}/remove-credits`, data);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Credits removed successfully" });
      setShowRemoveCreditsDialog(false);
      removeCreditsForm.reset();
      queryClient.invalidateQueries({ queryKey: ["/api/admin/resellers"] });
    },
    onError: (error: any) => {
      toast({ variant: "destructive", title: error.message || "Failed to remove credits" });
    },
  });

  const toggleStatusMutation = useMutation({
    mutationFn: async ({ id, isActive }: { id: string; isActive: boolean }) => {
      const response = await apiRequest("PATCH", `/api/admin/resellers/${id}/toggle`, { isActive });
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Reseller status updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/resellers"] });
    },
    onError: (error: any) => {
      toast({ variant: "destructive", title: error.message || "Failed to update status" });
    },
  });

  const deleteResellerMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiRequest("DELETE", `/api/admin/resellers/${id}`);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Reseller deleted successfully" });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/resellers"] });
    },
    onError: (error: any) => {
      toast({ variant: "destructive", title: error.message || "Failed to delete reseller" });
    },
  });

  const handleOpenLedger = (reseller: ResellerData) => {
    setSelectedReseller(reseller);
    setShowLedgerDialog(true);
  };

  const handleOpenUsers = (reseller: ResellerData) => {
    setSelectedReseller(reseller);
    setShowUsersDialog(true);
  };

  const handleOpenAddCredits = (reseller: ResellerData) => {
    setSelectedReseller(reseller);
    addCreditsForm.reset();
    setShowAddCreditsDialog(true);
  };

  const handleOpenRemoveCredits = (reseller: ResellerData) => {
    setSelectedReseller(reseller);
    removeCreditsForm.reset();
    setShowRemoveCreditsDialog(true);
  };

  return (
    <Card className="shadow-sm bg-white border border-[#e5e7eb]">
      <CardHeader>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <DollarSign className="w-5 h-5 text-[#374151]" />
            <CardTitle className="text-[#1f2937]">Reseller Management</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetchResellers()}
              className="border-[#374151] text-[#374151] hover:bg-[#374151] hover:text-white"
              data-testid="button-refresh-resellers"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Button
              size="sm"
              onClick={() => setShowCreateDialog(true)}
              className="bg-[#374151] hover:bg-[#1f2937] text-white"
              data-testid="button-create-reseller"
            >
              <Plus className="w-4 h-4 mr-2" />
              Create Reseller
            </Button>
          </div>
        </div>
        <CardDescription className="text-[#6b7280]">
          Manage resellers who can create Scale (900 credits) and Empire (1500 credits) plan users
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loadingResellers ? (
          <div className="flex items-center justify-center p-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
          </div>
        ) : resellersData?.resellers && resellersData.resellers.length > 0 ? (
          <div className="overflow-x-auto rounded-lg border border-[#e5e7eb]">
            <Table>
              <TableHeader>
                <TableRow className="bg-[#f9fafb]">
                  <TableHead className="text-[#374151] font-semibold">Username</TableHead>
                  <TableHead className="text-[#374151] font-semibold">Credits</TableHead>
                  <TableHead className="text-[#374151] font-semibold">Status</TableHead>
                  <TableHead className="text-[#374151] font-semibold">Created</TableHead>
                  <TableHead className="text-[#374151] font-semibold text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resellersData.resellers.map((reseller) => (
                  <TableRow key={reseller.id} className="hover:bg-gray-50" data-testid={`row-reseller-${reseller.id}`}>
                    <TableCell className="text-[#374151] font-medium" data-testid={`reseller-username-${reseller.id}`}>
                      {reseller.username}
                    </TableCell>
                    <TableCell data-testid={`reseller-credits-${reseller.id}`}>
                      <Badge className={reseller.creditBalance > 0 ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-800"}>
                        {reseller.creditBalance.toLocaleString()} credits
                      </Badge>
                    </TableCell>
                    <TableCell data-testid={`reseller-status-${reseller.id}`}>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={reseller.isActive}
                          onCheckedChange={(checked) => toggleStatusMutation.mutate({ id: reseller.id, isActive: checked })}
                          data-testid={`switch-reseller-status-${reseller.id}`}
                        />
                        <span className={reseller.isActive ? "text-green-600" : "text-red-600"}>
                          {reseller.isActive ? "Active" : "Inactive"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-[#6b7280] text-sm" data-testid={`reseller-created-${reseller.id}`}>
                      {new Date(reseller.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleOpenAddCredits(reseller)}
                          className="border-green-500 text-green-600 hover:bg-green-50"
                          data-testid={`button-add-credits-${reseller.id}`}
                        >
                          <Plus className="w-3 h-3" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleOpenRemoveCredits(reseller)}
                          className="border-red-500 text-red-600 hover:bg-red-50"
                          data-testid={`button-remove-credits-${reseller.id}`}
                        >
                          <X className="w-3 h-3" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleOpenLedger(reseller)}
                          className="border-[#374151] text-[#374151] hover:bg-gray-100"
                          data-testid={`button-view-ledger-${reseller.id}`}
                        >
                          <HistoryIcon className="w-3 h-3" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleOpenUsers(reseller)}
                          className="border-[#374151] text-[#374151] hover:bg-gray-100"
                          data-testid={`button-view-users-${reseller.id}`}
                        >
                          <Users className="w-3 h-3" />
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              size="sm"
                              variant="outline"
                              className="border-red-500 text-red-600 hover:bg-red-50"
                              data-testid={`button-delete-reseller-${reseller.id}`}
                            >
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent className="bg-white">
                            <AlertDialogHeader>
                              <AlertDialogTitle className="text-[#1f2937]">Delete Reseller?</AlertDialogTitle>
                              <AlertDialogDescription className="text-[#6b7280]">
                                This will permanently delete the reseller "{reseller.username}" and all their data. This action cannot be undone.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel className="border-[#374151] text-[#374151]">Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deleteResellerMutation.mutate(reseller.id)}
                                className="bg-red-600 hover:bg-red-700 text-white"
                                data-testid={`button-confirm-delete-${reseller.id}`}
                              >
                                Delete
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <p className="text-center py-8 text-[#6b7280]">No resellers found. Create one to get started.</p>
        )}
      </CardContent>

      {/* Create Reseller Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="bg-white border-[#374151]">
          <DialogHeader>
            <DialogTitle className="text-[#1f2937]">Create New Reseller</DialogTitle>
            <DialogDescription className="text-[#6b7280]">
              Create a new reseller account with initial credits
            </DialogDescription>
          </DialogHeader>
          <Form {...createForm}>
            <form onSubmit={createForm.handleSubmit((data) => createResellerMutation.mutate(data))} className="space-y-4">
              <FormField
                control={createForm.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Username</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="reseller_username" className="border-[#e5e7eb]" data-testid="input-reseller-username" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={createForm.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Password</FormLabel>
                    <FormControl>
                      <Input {...field} type="password" placeholder="Password" className="border-[#e5e7eb]" data-testid="input-reseller-password" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={createForm.control}
                name="creditBalance"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Initial Credits</FormLabel>
                    <FormControl>
                      <Input {...field} type="number" placeholder="0" className="border-[#e5e7eb]" data-testid="input-reseller-credits" />
                    </FormControl>
                    <FormDescription className="text-[#6b7280]">
                      Scale plan costs 900 credits, Empire plan costs 1500 credits
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowCreateDialog(false)}
                  className="border-[#374151] text-[#374151]"
                  data-testid="button-cancel-create-reseller"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="bg-[#374151] hover:bg-[#1f2937] text-white"
                  disabled={createResellerMutation.isPending}
                  data-testid="button-submit-create-reseller"
                >
                  {createResellerMutation.isPending ? "Creating..." : "Create Reseller"}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      {/* Add Credits Dialog */}
      <Dialog open={showAddCreditsDialog} onOpenChange={setShowAddCreditsDialog}>
        <DialogContent className="bg-white border-[#374151]">
          <DialogHeader>
            <DialogTitle className="text-[#1f2937]">Add Credits to {selectedReseller?.username}</DialogTitle>
            <DialogDescription className="text-[#6b7280]">
              Current balance: {selectedReseller?.creditBalance.toLocaleString()} credits
            </DialogDescription>
          </DialogHeader>
          <Form {...addCreditsForm}>
            <form onSubmit={addCreditsForm.handleSubmit((data) => addCreditsMutation.mutate(data))} className="space-y-4">
              <FormField
                control={addCreditsForm.control}
                name="amount"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Amount</FormLabel>
                    <FormControl>
                      <Input {...field} type="number" placeholder="Enter credits amount" className="border-[#e5e7eb]" data-testid="input-add-credits-amount" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={addCreditsForm.control}
                name="reason"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Reason (Optional)</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Payment received, bonus, etc." className="border-[#e5e7eb]" data-testid="input-add-credits-reason" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowAddCreditsDialog(false)}
                  className="border-[#374151] text-[#374151]"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="bg-green-600 hover:bg-green-700 text-white"
                  disabled={addCreditsMutation.isPending}
                  data-testid="button-submit-add-credits"
                >
                  {addCreditsMutation.isPending ? "Adding..." : "Add Credits"}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      {/* Remove Credits Dialog */}
      <Dialog open={showRemoveCreditsDialog} onOpenChange={setShowRemoveCreditsDialog}>
        <DialogContent className="bg-white border-[#374151]">
          <DialogHeader>
            <DialogTitle className="text-[#1f2937]">Remove Credits from {selectedReseller?.username}</DialogTitle>
            <DialogDescription className="text-[#6b7280]">
              Current balance: {selectedReseller?.creditBalance.toLocaleString()} credits
            </DialogDescription>
          </DialogHeader>
          <Form {...removeCreditsForm}>
            <form onSubmit={removeCreditsForm.handleSubmit((data) => removeCreditsMutation.mutate(data))} className="space-y-4">
              <FormField
                control={removeCreditsForm.control}
                name="amount"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Amount</FormLabel>
                    <FormControl>
                      <Input {...field} type="number" placeholder="Enter credits amount" className="border-[#e5e7eb]" data-testid="input-remove-credits-amount" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={removeCreditsForm.control}
                name="reason"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Reason (Optional)</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Refund, correction, etc." className="border-[#e5e7eb]" data-testid="input-remove-credits-reason" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowRemoveCreditsDialog(false)}
                  className="border-[#374151] text-[#374151]"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="bg-red-600 hover:bg-red-700 text-white"
                  disabled={removeCreditsMutation.isPending}
                  data-testid="button-submit-remove-credits"
                >
                  {removeCreditsMutation.isPending ? "Removing..." : "Remove Credits"}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      {/* Credit Ledger Dialog */}
      <Dialog open={showLedgerDialog} onOpenChange={setShowLedgerDialog}>
        <DialogContent className="bg-white border-[#374151] max-w-2xl">
          <DialogHeader>
            <DialogTitle className="text-[#1f2937]">Credit Ledger - {selectedReseller?.username}</DialogTitle>
            <DialogDescription className="text-[#6b7280]">
              Transaction history for this reseller
            </DialogDescription>
          </DialogHeader>
          <ScrollArea className="max-h-[400px]">
            {loadingLedger ? (
              <div className="flex items-center justify-center p-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
              </div>
            ) : ledgerData?.ledger && ledgerData.ledger.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow className="bg-[#f9fafb]">
                    <TableHead className="text-[#374151]">Date</TableHead>
                    <TableHead className="text-[#374151]">Amount</TableHead>
                    <TableHead className="text-[#374151]">Balance</TableHead>
                    <TableHead className="text-[#374151]">Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ledgerData.ledger.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="text-[#6b7280] text-sm">
                        {new Date(entry.createdAt).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <span className={(entry.creditChange ?? 0) >= 0 ? "text-green-600" : "text-red-600"}>
                          {(entry.creditChange ?? 0) >= 0 ? "+" : ""}{(entry.creditChange ?? 0).toLocaleString()}
                        </span>
                      </TableCell>
                      <TableCell className="text-[#374151]">
                        {(entry.balanceAfter ?? 0).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-[#6b7280] text-sm max-w-[200px] truncate">
                        {entry.reason}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-center py-8 text-[#6b7280]">No transactions found</p>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>

      {/* Reseller Users Dialog */}
      <Dialog open={showUsersDialog} onOpenChange={setShowUsersDialog}>
        <DialogContent className="bg-white border-[#374151] max-w-3xl">
          <DialogHeader>
            <DialogTitle className="text-[#1f2937]">Users Created by {selectedReseller?.username}</DialogTitle>
            <DialogDescription className="text-[#6b7280]">
              List of users created by this reseller
            </DialogDescription>
          </DialogHeader>
          <ScrollArea className="max-h-[400px]">
            {loadingUsers ? (
              <div className="flex items-center justify-center p-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
              </div>
            ) : usersData?.users && usersData.users.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow className="bg-[#f9fafb]">
                    <TableHead className="text-[#374151]">Username</TableHead>
                    <TableHead className="text-[#374151]">Plan</TableHead>
                    <TableHead className="text-[#374151]">Cost</TableHead>
                    <TableHead className="text-[#374151]">Status</TableHead>
                    <TableHead className="text-[#374151]">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {usersData.users.map((resellerUser) => (
                    <TableRow key={resellerUser.id}>
                      <TableCell className="text-[#374151] font-medium">
                        {resellerUser.user?.username || "Unknown"}
                      </TableCell>
                      <TableCell>
                        <Badge className={resellerUser.planType === "empire" ? "bg-purple-100 text-purple-800" : "bg-blue-100 text-blue-800"}>
                          {resellerUser.planType.charAt(0).toUpperCase() + resellerUser.planType.slice(1)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-[#374151]">
                        {resellerUser.creditCost.toLocaleString()} credits
                      </TableCell>
                      <TableCell>
                        <Badge className={resellerUser.user?.isAccountActive ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}>
                          {resellerUser.user?.isAccountActive ? "Active" : "Inactive"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-[#6b7280] text-sm">
                        {new Date(resellerUser.createdAt).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-center py-8 text-[#6b7280]">No users created by this reseller yet</p>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface PricingPlanData {
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
  dailyCharactersLimit: number | null;
}

interface PlanFeature {
  icon: string;
  text: string;
  included: boolean;
  subtext?: string;
}

const ICON_OPTIONS = [
  { value: "zap", label: "Zap (Lightning)" },
  { value: "crown", label: "Crown" },
  { value: "users", label: "Users" },
  { value: "star", label: "Star" },
  { value: "sparkles", label: "Sparkles" },
  { value: "shield", label: "Shield" },
  { value: "rocket", label: "Rocket" },
  { value: "gem", label: "Gem" },
];

const BADGE_COLOR_OPTIONS = [
  { value: "default", label: "Default (Gray)" },
  { value: "green", label: "Green" },
  { value: "orange", label: "Orange" },
  { value: "purple", label: "Purple" },
  { value: "blue", label: "Blue" },
];

const BUTTON_ACTION_OPTIONS = [
  { value: "payment_dialog", label: "Show Payment Dialog" },
  { value: "contact_sales", label: "Contact Sales (WhatsApp)" },
  { value: "disabled", label: "Disabled" },
  { value: "current_plan", label: "Current Plan (for logged-in users)" },
];

function PricingPlansTab() {
  const { toast } = useToast();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [editingPlan, setEditingPlan] = useState<PricingPlanData | null>(null);
  const [features, setFeatures] = useState<PlanFeature[]>([]);
  
  // Form state
  const [formData, setFormData] = useState({
    name: "",
    subtitle: "",
    displayPrice: "",
    currency: "PKR",
    period: "per 10 days",
    alternatePrice: "",
    badge: "",
    badgeColor: "default",
    iconType: "zap",
    highlightBorder: false,
    featuresIntro: "WHAT'S INCLUDED",
    buttonText: "Get Started",
    buttonAction: "payment_dialog",
    dailyCharactersLimit: "" as string | number,
  });

  const { data: plansData, isLoading, refetch } = useQuery<{ plans: PricingPlanData[] }>({
    queryKey: ["/api/admin/pricing-plans"],
  });

  const plans = plansData?.plans || [];

  const resetForm = () => {
    setFormData({
      name: "",
      subtitle: "",
      displayPrice: "",
      currency: "PKR",
      period: "per 10 days",
      alternatePrice: "",
      badge: "",
      badgeColor: "default",
      iconType: "zap",
      highlightBorder: false,
      featuresIntro: "WHAT'S INCLUDED",
      buttonText: "Get Started",
      buttonAction: "payment_dialog",
      dailyCharactersLimit: "",
    });
    setFeatures([]);
    setEditingPlan(null);
  };

  const openEditDialog = (plan: PricingPlanData) => {
    setEditingPlan(plan);
    setFormData({
      name: plan.name,
      subtitle: plan.subtitle || "",
      displayPrice: plan.displayPrice,
      currency: plan.currency,
      period: plan.period || "",
      alternatePrice: plan.alternatePrice || "",
      badge: plan.badge || "",
      badgeColor: plan.badgeColor || "default",
      iconType: plan.iconType,
      highlightBorder: plan.highlightBorder,
      featuresIntro: plan.featuresIntro || "",
      buttonText: plan.buttonText,
      buttonAction: plan.buttonAction,
      dailyCharactersLimit: plan.dailyCharactersLimit ?? "",
    });
    try {
      setFeatures(JSON.parse(plan.features) || []);
    } catch {
      setFeatures([]);
    }
    setShowAddDialog(true);
  };

  const createPlanMutation = useMutation({
    mutationFn: async () => {
      const payload = {
        ...formData,
        features: JSON.stringify(features),
        dailyCharactersLimit: formData.dailyCharactersLimit === "" ? null : Number(formData.dailyCharactersLimit),
      };
      const response = await apiRequest("POST", "/api/admin/pricing-plans", payload);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Plan Created", description: "Pricing plan has been created" });
      resetForm();
      setShowAddDialog(false);
      refetch();
      queryClient.invalidateQueries({ queryKey: ["/api/pricing-plans"] });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to create plan", variant: "destructive" });
    },
  });

  const updatePlanMutation = useMutation({
    mutationFn: async () => {
      if (!editingPlan) return;
      const payload = {
        ...formData,
        features: JSON.stringify(features),
        dailyCharactersLimit: formData.dailyCharactersLimit === "" ? null : Number(formData.dailyCharactersLimit),
      };
      const response = await apiRequest("PATCH", `/api/admin/pricing-plans/${editingPlan.id}`, payload);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Plan Updated", description: "Pricing plan has been updated" });
      resetForm();
      setShowAddDialog(false);
      refetch();
      queryClient.invalidateQueries({ queryKey: ["/api/pricing-plans"] });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to update plan", variant: "destructive" });
    },
  });

  const deletePlanMutation = useMutation({
    mutationFn: async (planId: string) => {
      const response = await apiRequest("DELETE", `/api/admin/pricing-plans/${planId}`);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Plan Deleted", description: "Pricing plan has been deleted" });
      refetch();
      queryClient.invalidateQueries({ queryKey: ["/api/pricing-plans"] });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to delete plan", variant: "destructive" });
    },
  });

  const togglePlanMutation = useMutation({
    mutationFn: async ({ planId, isActive }: { planId: string; isActive: boolean }) => {
      const response = await apiRequest("PATCH", `/api/admin/pricing-plans/${planId}`, { isActive });
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Plan Updated", description: "Plan visibility has been updated" });
      refetch();
      queryClient.invalidateQueries({ queryKey: ["/api/pricing-plans"] });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to update plan", variant: "destructive" });
    },
  });

  const movePlanMutation = useMutation({
    mutationFn: async (planIds: string[]) => {
      const response = await apiRequest("POST", "/api/admin/pricing-plans/reorder", { planIds });
      return response.json();
    },
    onSuccess: () => {
      refetch();
      queryClient.invalidateQueries({ queryKey: ["/api/pricing-plans"] });
    },
  });

  const movePlan = (index: number, direction: "up" | "down") => {
    const newIndex = direction === "up" ? index - 1 : index + 1;
    if (newIndex < 0 || newIndex >= plans.length) return;
    
    const newOrder = [...plans];
    const temp = newOrder[index];
    newOrder[index] = newOrder[newIndex];
    newOrder[newIndex] = temp;
    
    movePlanMutation.mutate(newOrder.map(p => p.id));
  };

  const addFeature = () => {
    setFeatures([...features, { icon: "check", text: "", included: true }]);
  };

  const updateFeature = (index: number, updates: Partial<PlanFeature>) => {
    const updated = [...features];
    updated[index] = { ...updated[index], ...updates };
    setFeatures(updated);
  };

  const removeFeature = (index: number) => {
    setFeatures(features.filter((_, i) => i !== index));
  };

  const handleSubmit = () => {
    if (!formData.name || !formData.displayPrice) {
      toast({ title: "Error", description: "Name and price are required", variant: "destructive" });
      return;
    }
    if (editingPlan) {
      updatePlanMutation.mutate();
    } else {
      createPlanMutation.mutate();
    }
  };

  return (
    <Card className="shadow-xl border-[#e5e7eb] bg-white">
      <CardHeader className="bg-[#374151]/10 border-b border-[#e5e7eb]">
        <div className="flex items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-[#1f2937]">
              <DollarSign className="w-5 h-5" />
              Pricing Plans
            </CardTitle>
            <CardDescription className="text-[#6b7280]">
              Create and manage pricing plans displayed on the pricing page
            </CardDescription>
          </div>
          <Button
            onClick={() => { resetForm(); setShowAddDialog(true); }}
            className="bg-[#374151] text-white hover:bg-[#4b5563]"
            data-testid="button-add-pricing-plan"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Plan
          </Button>
        </div>
      </CardHeader>
      <CardContent className="pt-6 bg-white">
        {isLoading ? (
          <div className="text-center py-8">Loading plans...</div>
        ) : plans.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow className="border-[#e5e7eb]">
                <TableHead className="text-[#374151]">Order</TableHead>
                <TableHead className="text-[#374151]">Name</TableHead>
                <TableHead className="text-[#374151]">Price</TableHead>
                <TableHead className="text-[#374151]">Badge</TableHead>
                <TableHead className="text-[#374151]">Status</TableHead>
                <TableHead className="text-[#374151]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {plans.map((plan, index) => (
                <TableRow key={plan.id} className="border-[#e5e7eb]">
                  <TableCell className="text-[#374151]">
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => movePlan(index, "up")}
                        disabled={index === 0}
                        className="h-6 w-6"
                      >
                        <span className="text-xs">^</span>
                      </Button>
                      <span>{index + 1}</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => movePlan(index, "down")}
                        disabled={index === plans.length - 1}
                        className="h-6 w-6"
                      >
                        <span className="text-xs">v</span>
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell className="text-[#374151] font-medium">
                    <div>
                      {plan.name}
                      {plan.subtitle && <span className="text-sm text-[#6b7280] block">{plan.subtitle}</span>}
                    </div>
                  </TableCell>
                  <TableCell className="text-[#374151]">
                    {plan.displayPrice} {plan.currency}
                    {plan.period && <span className="text-sm text-[#6b7280] block">{plan.period}</span>}
                  </TableCell>
                  <TableCell>
                    {plan.badge ? (
                      <Badge variant="secondary" className="text-xs">{plan.badge}</Badge>
                    ) : (
                      <span className="text-[#9ca3af]">-</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={plan.isActive}
                      onCheckedChange={(checked) => togglePlanMutation.mutate({ planId: plan.id, isActive: checked })}
                      data-testid={`switch-plan-active-${plan.id}`}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => openEditDialog(plan)}
                        data-testid={`button-edit-plan-${plan.id}`}
                      >
                        <Edit className="w-4 h-4" />
                      </Button>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-red-600 hover:text-red-800"
                            data-testid={`button-delete-plan-${plan.id}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent className="bg-white">
                          <AlertDialogHeader>
                            <AlertDialogTitle className="text-[#1f2937]">Delete Plan?</AlertDialogTitle>
                            <AlertDialogDescription className="text-[#6b7280]">
                              This will permanently delete the "{plan.name}" pricing plan. This action cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel className="border-[#e5e7eb]">Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => deletePlanMutation.mutate(plan.id)}
                              className="bg-red-600 text-white hover:bg-red-700"
                            >
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="text-center py-8">
            <DollarSign className="w-12 h-12 mx-auto text-gray-300 mb-4" />
            <p className="text-[#6b7280]">No pricing plans configured</p>
            <p className="text-sm text-[#9ca3af] mt-1">Add a plan to display on the pricing page</p>
          </div>
        )}

        {/* Add/Edit Plan Dialog */}
        <Dialog open={showAddDialog} onOpenChange={(open) => { if (!open) resetForm(); setShowAddDialog(open); }}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto bg-white">
            <DialogHeader>
              <DialogTitle className="text-[#1f2937]">
                {editingPlan ? "Edit Pricing Plan" : "Add Pricing Plan"}
              </DialogTitle>
              <DialogDescription className="text-[#6b7280]">
                Configure the pricing plan details and features
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-[#374151]">Plan Name *</Label>
                  <Input
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="e.g., Scale, Empire"
                    className="border-[#e5e7eb]"
                    data-testid="input-plan-name"
                  />
                </div>
                <div>
                  <Label className="text-[#374151]">Subtitle</Label>
                  <Input
                    value={formData.subtitle}
                    onChange={(e) => setFormData({ ...formData, subtitle: e.target.value })}
                    placeholder="e.g., For starters"
                    className="border-[#e5e7eb]"
                    data-testid="input-plan-subtitle"
                  />
                </div>
              </div>

              {/* Pricing */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label className="text-[#374151]">Price *</Label>
                  <Input
                    value={formData.displayPrice}
                    onChange={(e) => setFormData({ ...formData, displayPrice: e.target.value })}
                    placeholder="e.g., 900 or Custom"
                    className="border-[#e5e7eb]"
                    data-testid="input-plan-price"
                  />
                </div>
                <div>
                  <Label className="text-[#374151]">Currency</Label>
                  <Input
                    value={formData.currency}
                    onChange={(e) => setFormData({ ...formData, currency: e.target.value })}
                    placeholder="PKR"
                    className="border-[#e5e7eb]"
                    data-testid="input-plan-currency"
                  />
                </div>
                <div>
                  <Label className="text-[#374151]">Period</Label>
                  <Input
                    value={formData.period}
                    onChange={(e) => setFormData({ ...formData, period: e.target.value })}
                    placeholder="per 10 days"
                    className="border-[#e5e7eb]"
                    data-testid="input-plan-period"
                  />
                </div>
              </div>

              <div>
                <Label className="text-[#374151]">Alternate Price (optional)</Label>
                <Input
                  value={formData.alternatePrice}
                  onChange={(e) => setFormData({ ...formData, alternatePrice: e.target.value })}
                  placeholder="e.g., $10 USD for International"
                  className="border-[#e5e7eb]"
                  data-testid="input-plan-alternate-price"
                />
              </div>

              {/* Appearance */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label className="text-[#374151]">Badge</Label>
                  <Input
                    value={formData.badge}
                    onChange={(e) => setFormData({ ...formData, badge: e.target.value })}
                    placeholder="e.g., Popular"
                    className="border-[#e5e7eb]"
                    data-testid="input-plan-badge"
                  />
                </div>
                <div>
                  <Label className="text-[#374151]">Badge Color</Label>
                  <Select value={formData.badgeColor} onValueChange={(v) => setFormData({ ...formData, badgeColor: v })}>
                    <SelectTrigger className="border-[#e5e7eb]" data-testid="select-plan-badge-color">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {BADGE_COLOR_OPTIONS.map(opt => (
                        <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-[#374151]">Icon</Label>
                  <Select value={formData.iconType} onValueChange={(v) => setFormData({ ...formData, iconType: v })}>
                    <SelectTrigger className="border-[#e5e7eb]" data-testid="select-plan-icon">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {ICON_OPTIONS.map(opt => (
                        <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <Switch
                  checked={formData.highlightBorder}
                  onCheckedChange={(checked) => setFormData({ ...formData, highlightBorder: checked })}
                  data-testid="switch-plan-highlight"
                />
                <Label className="text-[#374151]">Highlight Border (for featured plans)</Label>
              </div>

              {/* Button */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-[#374151]">Button Text</Label>
                  <Input
                    value={formData.buttonText}
                    onChange={(e) => setFormData({ ...formData, buttonText: e.target.value })}
                    placeholder="Get Started"
                    className="border-[#e5e7eb]"
                    data-testid="input-plan-button-text"
                  />
                </div>
                <div>
                  <Label className="text-[#374151]">Button Action</Label>
                  <Select value={formData.buttonAction} onValueChange={(v) => setFormData({ ...formData, buttonAction: v })}>
                    <SelectTrigger className="border-[#e5e7eb]" data-testid="select-plan-button-action">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {BUTTON_ACTION_OPTIONS.map(opt => (
                        <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Daily Characters Limit */}
              <div>
                <Label className="text-[#374151]">Daily Characters Limit (for Voice Features)</Label>
                <Input
                  type="number"
                  value={formData.dailyCharactersLimit}
                  onChange={(e) => setFormData({ ...formData, dailyCharactersLimit: e.target.value })}
                  placeholder="Leave empty for unlimited"
                  className="border-[#e5e7eb]"
                  data-testid="input-plan-daily-characters-limit"
                />
                <p className="text-xs text-[#6b7280] mt-1">Set the maximum characters per day users on this plan can use. Leave empty for no limit.</p>
              </div>

              {/* Features */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <Label className="text-[#374151]">Features Intro Text</Label>
                </div>
                <Input
                  value={formData.featuresIntro}
                  onChange={(e) => setFormData({ ...formData, featuresIntro: e.target.value })}
                  placeholder="e.g., WHAT'S INCLUDED"
                  className="border-[#e5e7eb] mb-4"
                  data-testid="input-plan-features-intro"
                />

                <div className="flex items-center justify-between mb-2">
                  <Label className="text-[#374151]">Features</Label>
                  <Button variant="outline" size="sm" onClick={addFeature} data-testid="button-add-feature">
                    <Plus className="w-4 h-4 mr-1" /> Add Feature
                  </Button>
                </div>
                
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {features.map((feature, index) => (
                    <div key={index} className="flex items-center gap-2 p-2 bg-gray-50 rounded">
                      <Switch
                        checked={feature.included}
                        onCheckedChange={(checked) => updateFeature(index, { included: checked })}
                        data-testid={`switch-feature-included-${index}`}
                      />
                      <Input
                        value={feature.text}
                        onChange={(e) => updateFeature(index, { text: e.target.value })}
                        placeholder="Feature text"
                        className="flex-1 border-[#e5e7eb]"
                        data-testid={`input-feature-text-${index}`}
                      />
                      <Input
                        value={feature.subtext || ""}
                        onChange={(e) => updateFeature(index, { subtext: e.target.value })}
                        placeholder="Subtext (optional)"
                        className="w-32 border-[#e5e7eb]"
                        data-testid={`input-feature-subtext-${index}`}
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeFeature(index)}
                        className="text-red-600 h-8 w-8"
                        data-testid={`button-remove-feature-${index}`}
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => { resetForm(); setShowAddDialog(false); }}>
                Cancel
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={createPlanMutation.isPending || updatePlanMutation.isPending}
                className="bg-[#374151] text-white hover:bg-[#4b5563]"
                data-testid="button-save-plan"
              >
                {createPlanMutation.isPending || updatePlanMutation.isPending ? "Saving..." : (editingPlan ? "Update Plan" : "Create Plan")}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}

interface ZyphraTokenData {
  id: string;
  apiKey: string;
  label: string;
  isActive: boolean;
  minutesUsed: number;
  maxMinutes: number;
  hasError: boolean;
  lastError: string | null;
  lastUsedAt: string | null;
  createdAt: string;
}

function ZyphraTokensTab() {
  const { toast } = useToast();
  const [newLabel, setNewLabel] = useState("");
  const [newApiKey, setNewApiKey] = useState("");
  const [editingToken, setEditingToken] = useState<ZyphraTokenData | null>(null);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [showBulkAddDialog, setShowBulkAddDialog] = useState(false);
  const [bulkKeys, setBulkKeys] = useState("");

  const { data: tokensData, isLoading, refetch } = useQuery<{ tokens: ZyphraTokenData[] }>({
    queryKey: ["/api/admin/zyphra-tokens"],
  });

  const addTokenMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/admin/zyphra-tokens", {
        apiKey: newApiKey,
        label: newLabel,
      });
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Token Added", description: "Zyphra API token has been added" });
      setNewLabel("");
      setNewApiKey("");
      setShowAddDialog(false);
      refetch();
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to add token", variant: "destructive" });
    },
  });

  const bulkAddMutation = useMutation({
    mutationFn: async (keys: string[]) => {
      const response = await apiRequest("POST", "/api/admin/zyphra-tokens/bulk", { tokens: keys.join('\n') });
      return response.json();
    },
    onSuccess: (data: any) => {
      toast({ 
        title: "Bulk Add Complete", 
        description: `Added ${data.totalAdded} tokens${data.totalErrors > 0 ? `, ${data.totalErrors} failed/duplicates` : ''}` 
      });
      setBulkKeys("");
      setShowBulkAddDialog(false);
      refetch();
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to bulk add tokens", variant: "destructive" });
    },
  });

  const handleBulkAdd = () => {
    const keys = bulkKeys
      .split('\n')
      .map(k => k.trim())
      .filter(k => k.length > 0 && k.startsWith('zsk-'));
    
    if (keys.length === 0) {
      toast({ title: "Error", description: "No valid keys found. Keys should start with 'zsk-'", variant: "destructive" });
      return;
    }
    
    bulkAddMutation.mutate(keys);
  };

  const toggleTokenMutation = useMutation({
    mutationFn: async ({ id, isActive }: { id: string; isActive: boolean }) => {
      const response = await apiRequest("PATCH", `/api/admin/zyphra-tokens/${id}`, { isActive });
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Token Updated", description: "Token status has been updated" });
      refetch();
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to update token", variant: "destructive" });
    },
  });

  const deleteTokenMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiRequest("DELETE", `/api/admin/zyphra-tokens/${id}`);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Token Deleted", description: "Zyphra API token has been removed" });
      refetch();
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to delete token", variant: "destructive" });
    },
  });

  const resetTokenMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiRequest("POST", `/api/admin/zyphra-tokens/${id}/reset`);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Token Reset", description: "Token usage has been reset" });
      refetch();
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to reset token", variant: "destructive" });
    },
  });

  return (
    <Card className="shadow-sm bg-white border border-[#e5e7eb]">
      <CardHeader>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <Mic className="w-5 h-5 text-[#374151]" />
            <CardTitle className="text-[#1f2937]">Zyphra API Tokens</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              className="border-[#374151] text-[#374151]"
              data-testid="button-refresh-zyphra"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
              <DialogTrigger asChild>
                <Button size="sm" className="bg-[#374151] text-white" data-testid="button-add-zyphra-token">
                  <Plus className="w-4 h-4 mr-2" />
                  Add Token
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-white border-[#374151]">
                <DialogHeader>
                  <DialogTitle className="text-[#1f2937]">Add Zyphra API Token</DialogTitle>
                  <DialogDescription className="text-[#6b7280]">
                    Add a new Zyphra API key for voice cloning and TTS
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label className="text-[#374151]">Label</Label>
                    <Input
                      placeholder="e.g., Primary Key"
                      value={newLabel}
                      onChange={(e) => setNewLabel(e.target.value)}
                      className="border-[#e5e7eb]"
                      data-testid="input-zyphra-label"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[#374151]">API Key</Label>
                    <Input
                      placeholder="Enter Zyphra API key"
                      type="password"
                      value={newApiKey}
                      onChange={(e) => setNewApiKey(e.target.value)}
                      className="border-[#e5e7eb]"
                      data-testid="input-zyphra-key"
                    />
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    onClick={() => addTokenMutation.mutate()}
                    disabled={!newLabel.trim() || !newApiKey.trim() || addTokenMutation.isPending}
                    className="bg-[#374151] text-white"
                    data-testid="button-save-zyphra-token"
                  >
                    {addTokenMutation.isPending ? "Adding..." : "Add Token"}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
            <Dialog open={showBulkAddDialog} onOpenChange={setShowBulkAddDialog}>
              <DialogTrigger asChild>
                <Button size="sm" variant="outline" className="border-[#374151] text-[#374151]" data-testid="button-bulk-add-zyphra">
                  <Plus className="w-4 h-4 mr-2" />
                  Bulk Add
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-white border-[#374151]">
                <DialogHeader>
                  <DialogTitle className="text-[#1f2937]">Bulk Add Zyphra API Tokens</DialogTitle>
                  <DialogDescription className="text-[#6b7280]">
                    Paste multiple API keys (one per line). Keys should start with 'zsk-'
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label className="text-[#374151]">API Keys (one per line)</Label>
                    <Textarea
                      placeholder="zsk-xxxxx...&#10;zsk-yyyyy...&#10;zsk-zzzzz..."
                      value={bulkKeys}
                      onChange={(e) => setBulkKeys(e.target.value)}
                      className="border-[#e5e7eb] min-h-[200px] font-mono text-sm"
                      data-testid="input-bulk-zyphra-keys"
                    />
                    <p className="text-xs text-[#6b7280]">
                      {bulkKeys.split('\n').filter(k => k.trim().startsWith('zsk-')).length} valid keys detected
                    </p>
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    onClick={handleBulkAdd}
                    disabled={!bulkKeys.trim() || bulkAddMutation.isPending}
                    className="bg-[#374151] text-white"
                    data-testid="button-save-bulk-zyphra"
                  >
                    {bulkAddMutation.isPending ? "Adding..." : "Add All Keys"}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>
        <CardDescription className="text-[#6b7280]">
          Manage Zyphra API keys for voice cloning and text-to-speech. Each key has a 100 minute limit.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center p-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
          </div>
        ) : tokensData?.tokens && tokensData.tokens.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow className="bg-[#f9fafb]">
                <TableHead className="text-[#374151]">Label</TableHead>
                <TableHead className="text-[#374151]">API Key</TableHead>
                <TableHead className="text-[#374151]">Usage</TableHead>
                <TableHead className="text-[#374151]">Status</TableHead>
                <TableHead className="text-[#374151]">Last Used</TableHead>
                <TableHead className="text-[#374151]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokensData.tokens.map((token) => (
                <TableRow key={token.id}>
                  <TableCell className="text-[#374151] font-medium">{token.label}</TableCell>
                  <TableCell className="text-[#6b7280] font-mono text-sm">
                    {token.apiKey.slice(0, 10)}...{token.apiKey.slice(-4)}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-2 bg-gray-200 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${token.minutesUsed >= token.maxMinutes ? 'bg-red-500' : 'bg-green-500'}`}
                            style={{ width: `${Math.min((token.minutesUsed / token.maxMinutes) * 100, 100)}%` }}
                          />
                        </div>
                        <span className="text-sm text-[#6b7280]">
                          {token.minutesUsed.toFixed(1)}/{token.maxMinutes} min
                        </span>
                      </div>
                      <span className="text-xs text-green-600 dark:text-green-400" data-testid={`text-remaining-${token.id}`}>
                        Remaining: {Math.max(0, token.maxMinutes - token.minutesUsed).toFixed(1)} min
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={token.isActive}
                        onCheckedChange={(checked) => toggleTokenMutation.mutate({ id: token.id, isActive: checked })}
                        data-testid={`switch-zyphra-${token.id}`}
                      />
                      {token.hasError && (
                        <Badge className="bg-red-100 text-red-800">Error</Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-[#6b7280] text-sm">
                    {token.lastUsedAt ? new Date(token.lastUsedAt).toLocaleString() : "Never"}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => resetTokenMutation.mutate(token.id)}
                        title="Reset Usage"
                        data-testid={`button-reset-zyphra-${token.id}`}
                      >
                        <RotateCcw className="w-4 h-4" />
                      </Button>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-red-600 hover:text-red-800"
                            data-testid={`button-delete-zyphra-${token.id}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent className="bg-white">
                          <AlertDialogHeader>
                            <AlertDialogTitle className="text-[#1f2937]">Delete Token?</AlertDialogTitle>
                            <AlertDialogDescription className="text-[#6b7280]">
                              This will permanently delete the Zyphra API token "{token.label}". This action cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel className="border-[#e5e7eb]">Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => deleteTokenMutation.mutate(token.id)}
                              className="bg-red-600 text-white hover:bg-red-700"
                            >
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="text-center py-8">
            <Mic className="w-12 h-12 mx-auto text-gray-300 mb-4" />
            <p className="text-[#6b7280]">No Zyphra API tokens configured</p>
            <p className="text-sm text-[#9ca3af] mt-1">Add a token to enable voice cloning and TTS features</p>
          </div>
        )}

        {/* Quick Links */}
        <div className="mt-6 pt-6 border-t border-[#e5e7eb]">
          <h3 className="text-sm font-medium text-[#374151] mb-3">Zyphra Tools</h3>
          <div className="flex gap-2 flex-wrap">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.href = "/admin/voice-cloning"}
              className="border-[#374151] text-[#374151]"
              data-testid="button-goto-voice-cloning"
            >
              <Mic className="w-4 h-4 mr-2" />
              Voice Cloning
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.href = "/admin/text-to-speech"}
              className="border-[#374151] text-[#374151]"
              data-testid="button-goto-tts"
            >
              <Mic className="w-4 h-4 mr-2" />
              Text to Speech
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.href = "/admin/top-voices"}
              className="border-[#374151] text-[#374151]"
              data-testid="button-goto-top-voices"
            >
              <Mic className="w-4 h-4 mr-2" />
              Top Voices
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
