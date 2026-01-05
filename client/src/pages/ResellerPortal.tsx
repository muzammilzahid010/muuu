import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DollarSign, Users, LogOut, Plus, History, RefreshCw, Check, Copy, Eye, EyeOff } from "lucide-react";

interface ResellerSession {
  authenticated: boolean;
  reseller?: {
    id: string;
    username: string;
    creditBalance: number;
  };
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
  username: string;
}

const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

const createUserSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  planType: z.enum(["scale", "empire"]),
});

type LoginFormData = z.infer<typeof loginSchema>;
type CreateUserFormData = z.infer<typeof createUserSchema>;

function ResellerLogin({ onSuccess }: { onSuccess: () => void }) {
  const { toast } = useToast();
  const [showPassword, setShowPassword] = useState(false);
  
  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  });

  const loginMutation = useMutation({
    mutationFn: async (data: LoginFormData) => {
      const response = await apiRequest("POST", "/api/reseller/login", data);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Login successful" });
      onSuccess();
    },
    onError: (error: any) => {
      toast({ variant: "destructive", title: error.message || "Login failed" });
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-[#1f2937] to-[#111827] p-4">
      <Card className="w-full max-w-md bg-white border-[#e5e7eb] shadow-xl">
        <CardHeader className="text-center">
          <div className="mx-auto w-16 h-16 bg-[#374151] rounded-full flex items-center justify-center mb-4">
            <DollarSign className="w-8 h-8 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold text-[#1f2937]">Reseller Portal</CardTitle>
          <CardDescription className="text-[#6b7280]">
            Login to manage your users and credits
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit((data) => loginMutation.mutate(data))} className="space-y-4">
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Username</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Enter your username" className="border-[#e5e7eb]" data-testid="input-reseller-login-username" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input 
                          {...field} 
                          type={showPassword ? "text" : "password"} 
                          placeholder="Enter your password" 
                          className="border-[#e5e7eb] pr-10" 
                          data-testid="input-reseller-login-password" 
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                          onClick={() => setShowPassword(!showPassword)}
                          data-testid="button-toggle-password"
                        >
                          {showPassword ? <EyeOff className="w-4 h-4 text-[#6b7280]" /> : <Eye className="w-4 h-4 text-[#6b7280]" />}
                        </Button>
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button
                type="submit"
                className="w-full bg-[#374151] hover:bg-[#1f2937] text-white"
                disabled={loginMutation.isPending}
                data-testid="button-reseller-login"
              >
                {loginMutation.isPending ? "Logging in..." : "Login"}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}

function ResellerDashboard({ session, onLogout }: { session: ResellerSession; onLogout: () => void }) {
  const { toast } = useToast();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [createdUser, setCreatedUser] = useState<{ username: string; password: string; planType: string } | null>(null);
  const [showCredentialsDialog, setShowCredentialsDialog] = useState(false);
  const [copiedCredentials, setCopiedCredentials] = useState(false);

  const createForm = useForm<CreateUserFormData>({
    resolver: zodResolver(createUserSchema),
    defaultValues: {
      username: "",
      password: "",
      planType: "scale",
    },
  });

  const { data: creditsData, refetch: refetchCredits } = useQuery<{ creditBalance: number }>({
    queryKey: ["/api/reseller/credits"],
  });

  const { data: usersData, isLoading: loadingUsers, refetch: refetchUsers } = useQuery<{ users: ResellerUser[] }>({
    queryKey: ["/api/reseller/users"],
  });

  const { data: ledgerData, isLoading: loadingLedger } = useQuery<{ ledger: ResellerLedgerEntry[] }>({
    queryKey: ["/api/reseller/ledger"],
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/reseller/logout");
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Logged out successfully" });
      onLogout();
    },
  });

  const createUserMutation = useMutation({
    mutationFn: async (data: CreateUserFormData) => {
      const response = await apiRequest("POST", "/api/reseller/users", data);
      return response.json();
    },
    onSuccess: (data, variables) => {
      toast({ title: "User created successfully" });
      setShowCreateDialog(false);
      setCreatedUser({
        username: variables.username,
        password: variables.password,
        planType: variables.planType,
      });
      setShowCredentialsDialog(true);
      createForm.reset();
      refetchCredits();
      queryClient.invalidateQueries({ queryKey: ["/api/reseller/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/reseller/ledger"] });
    },
    onError: (error: any) => {
      toast({ variant: "destructive", title: error.message || "Failed to create user" });
    },
  });

  const handleCopyCredentials = async () => {
    if (!createdUser) return;
    
    const planName = createdUser.planType.charAt(0).toUpperCase() + createdUser.planType.slice(1);
    const credentialsMessage = `🎉 *Veo3 Subscription Active!*

Khareedne ka shukriya. ❤️

🆔 *User:* ${createdUser.username}
🔑 *Pass:* ${createdUser.password}
📦 *Plan:* ${planName}

⚠️ *Warning:* Max 2 devices allowed. Is se zyada par login karne se account *Ban* ho jayega.

🔗 *Login:* https://veo3.pk
📲 *Support Group (Must Join):* https://chat.whatsapp.com/G0bBQkFbtmQ6HspRB26tFC`;

    try {
      await navigator.clipboard.writeText(credentialsMessage);
      setCopiedCredentials(true);
      toast({ title: "Copied to clipboard!" });
      setTimeout(() => setCopiedCredentials(false), 2000);
    } catch (error) {
      toast({ variant: "destructive", title: "Failed to copy" });
    }
  };

  const creditBalance = creditsData?.creditBalance ?? session.reseller?.creditBalance ?? 0;

  return (
    <div className="min-h-screen bg-gradient-to-b from-[#1f2937] to-[#111827]">
      {/* Header */}
      <header className="bg-[#374151] border-b border-[#4b5563] px-4 py-3">
        <div className="max-w-6xl mx-auto flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white/10 rounded-full flex items-center justify-center">
              <DollarSign className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-white font-semibold">Reseller Portal</h1>
              <p className="text-white/60 text-sm">{session.reseller?.username}</p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => logoutMutation.mutate()}
            className="border-white/20 text-white hover:bg-white/10"
            disabled={logoutMutation.isPending}
            data-testid="button-reseller-logout"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-6xl mx-auto p-4 space-y-6">
        {/* Credit Balance Card */}
        <Card className="bg-gradient-to-r from-[#374151] to-[#4b5563] border-0 text-white">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white/60 text-sm mb-1">Available Credits</p>
                <p className="text-4xl font-bold">{creditBalance.toLocaleString()}</p>
                <p className="text-white/60 text-sm mt-2">
                  Scale: 900 credits | Empire: 1500 credits
                </p>
              </div>
              <Button
                onClick={() => setShowCreateDialog(true)}
                className="bg-white text-[#374151] hover:bg-white/90"
                data-testid="button-create-user"
              >
                <Plus className="w-4 h-4 mr-2" />
                Create User
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Tabs */}
        <Tabs defaultValue="users" className="w-full">
          <TabsList className="bg-[#374151]/50 border border-[#4b5563]">
            <TabsTrigger value="users" className="text-white/60 data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-users">
              <Users className="w-4 h-4 mr-2" />
              My Users
            </TabsTrigger>
            <TabsTrigger value="ledger" className="text-white/60 data-[state=active]:bg-[#374151] data-[state=active]:text-white" data-testid="tab-ledger">
              <History className="w-4 h-4 mr-2" />
              Credit History
            </TabsTrigger>
          </TabsList>

          <TabsContent value="users" className="mt-4">
            <Card className="bg-white border-[#e5e7eb]">
              <CardHeader>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <CardTitle className="text-[#1f2937]">Created Users</CardTitle>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => refetchUsers()}
                    className="border-[#374151] text-[#374151] hover:bg-[#374151] hover:text-white"
                    data-testid="button-refresh-users"
                  >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                  </Button>
                </div>
                <CardDescription className="text-[#6b7280]">
                  Users you have created with your reseller credits
                </CardDescription>
              </CardHeader>
              <CardContent>
                {loadingUsers ? (
                  <div className="flex items-center justify-center p-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
                  </div>
                ) : usersData?.users && usersData.users.length > 0 ? (
                  <div className="overflow-x-auto rounded-lg border border-[#e5e7eb]">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-[#f9fafb]">
                          <TableHead className="text-[#374151] font-semibold">Username</TableHead>
                          <TableHead className="text-[#374151] font-semibold">Plan</TableHead>
                          <TableHead className="text-[#374151] font-semibold">Cost</TableHead>
                          <TableHead className="text-[#374151] font-semibold">Status</TableHead>
                          <TableHead className="text-[#374151] font-semibold">Created</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {usersData.users.map((resellerUser) => (
                          <TableRow key={resellerUser.id} data-testid={`row-user-${resellerUser.id}`}>
                            <TableCell className="text-[#374151] font-medium" data-testid={`user-username-${resellerUser.id}`}>
                              {resellerUser.username}
                            </TableCell>
                            <TableCell data-testid={`user-plan-${resellerUser.id}`}>
                              <Badge className={resellerUser.planType === "empire" ? "bg-purple-100 text-purple-800" : "bg-blue-100 text-blue-800"}>
                                {resellerUser.planType.charAt(0).toUpperCase() + resellerUser.planType.slice(1)}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-[#374151]" data-testid={`user-cost-${resellerUser.id}`}>
                              {resellerUser.creditCost.toLocaleString()} credits
                            </TableCell>
                            <TableCell data-testid={`user-status-${resellerUser.id}`}>
                              <Badge className="bg-green-100 text-green-800">
                                Active
                              </Badge>
                            </TableCell>
                            <TableCell className="text-[#6b7280] text-sm" data-testid={`user-created-${resellerUser.id}`}>
                              {new Date(resellerUser.createdAt).toLocaleDateString()}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <p className="text-center py-8 text-[#6b7280]">No users created yet. Click "Create User" to get started.</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="ledger" className="mt-4">
            <Card className="bg-white border-[#e5e7eb]">
              <CardHeader>
                <CardTitle className="text-[#1f2937]">Credit History</CardTitle>
                <CardDescription className="text-[#6b7280]">
                  Your credit transaction history
                </CardDescription>
              </CardHeader>
              <CardContent>
                {loadingLedger ? (
                  <div className="flex items-center justify-center p-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#374151]"></div>
                  </div>
                ) : ledgerData?.ledger && ledgerData.ledger.length > 0 ? (
                  <ScrollArea className="max-h-[400px]">
                    <div className="overflow-x-auto rounded-lg border border-[#e5e7eb]">
                      <Table>
                        <TableHeader>
                          <TableRow className="bg-[#f9fafb]">
                            <TableHead className="text-[#374151] font-semibold">Date</TableHead>
                            <TableHead className="text-[#374151] font-semibold">Amount</TableHead>
                            <TableHead className="text-[#374151] font-semibold">Balance</TableHead>
                            <TableHead className="text-[#374151] font-semibold">Reason</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {ledgerData.ledger.map((entry) => (
                            <TableRow key={entry.id} data-testid={`row-ledger-${entry.id}`}>
                              <TableCell className="text-[#6b7280] text-sm">
                                {new Date(entry.createdAt).toLocaleString()}
                              </TableCell>
                              <TableCell>
                                <span className={entry.creditChange >= 0 ? "text-green-600 font-medium" : "text-red-600 font-medium"}>
                                  {entry.creditChange >= 0 ? "+" : ""}{entry.creditChange.toLocaleString()}
                                </span>
                              </TableCell>
                              <TableCell className="text-[#374151] font-medium">
                                {entry.balanceAfter.toLocaleString()}
                              </TableCell>
                              <TableCell className="text-[#6b7280] text-sm max-w-[250px] truncate">
                                {entry.reason}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </ScrollArea>
                ) : (
                  <p className="text-center py-8 text-[#6b7280]">No transactions yet.</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Create User Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="bg-white border-[#374151]">
          <DialogHeader>
            <DialogTitle className="text-[#1f2937]">Create New User</DialogTitle>
            <DialogDescription className="text-[#6b7280]">
              Create a new user account. Credits will be deducted from your balance.
            </DialogDescription>
          </DialogHeader>
          <Form {...createForm}>
            <form onSubmit={createForm.handleSubmit((data) => createUserMutation.mutate(data))} className="space-y-4">
              <FormField
                control={createForm.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Username</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Enter username" className="border-[#e5e7eb]" data-testid="input-create-username" />
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
                      <Input {...field} type="text" placeholder="Enter password" className="border-[#e5e7eb]" data-testid="input-create-password" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={createForm.control}
                name="planType"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-[#374151]">Plan Type</FormLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl>
                        <SelectTrigger className="border-[#e5e7eb]" data-testid="select-plan-type">
                          <SelectValue placeholder="Select a plan" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="scale" data-testid="option-scale">
                          Scale - 900 credits
                        </SelectItem>
                        <SelectItem value="empire" data-testid="option-empire">
                          Empire - 1500 credits
                        </SelectItem>
                      </SelectContent>
                    </Select>
                    <FormDescription className="text-[#6b7280]">
                      Your balance: {creditBalance.toLocaleString()} credits
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
                  data-testid="button-cancel-create"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="bg-[#374151] hover:bg-[#1f2937] text-white"
                  disabled={createUserMutation.isPending}
                  data-testid="button-submit-create"
                >
                  {createUserMutation.isPending ? "Creating..." : "Create User"}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      {/* Credentials Dialog */}
      <Dialog open={showCredentialsDialog} onOpenChange={setShowCredentialsDialog}>
        <DialogContent className="bg-white border-[#e5e7eb] max-w-md sm:max-w-lg">
          <DialogHeader className="pb-2">
            <DialogTitle className="text-xl font-bold text-center text-[#1f2937]">
              User Created Successfully!
            </DialogTitle>
            <DialogDescription className="text-center text-[#6b7280]">
              Share these credentials with the user
            </DialogDescription>
          </DialogHeader>
          {createdUser && (
            <div className="space-y-4 pt-2">
              <div className="bg-[#f9fafb] rounded-lg p-4 border border-[#e5e7eb]">
                <pre className="text-sm text-[#374151] whitespace-pre-wrap font-mono leading-relaxed break-words">
{`*Veo3 Subscription Active!*

Khareedne ka shukriya.

*User:* ${createdUser.username}
*Pass:* ${createdUser.password}
*Plan:* ${createdUser.planType.charAt(0).toUpperCase() + createdUser.planType.slice(1)}

*Warning:* Max 2 devices allowed. Is se zyada par login karne se account *Ban* ho jayega.

*Login:* https://veo3.pk
*Support Group (Must Join):*
https://chat.whatsapp.com/G0bBQkFbtmQ6HspRB26tFC`}
                </pre>
              </div>

              <div className="flex flex-col gap-2">
                <Button
                  onClick={handleCopyCredentials}
                  className="w-full bg-[#374151] hover:bg-[#1f2937] text-white"
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

                <Button
                  onClick={() => setShowCredentialsDialog(false)}
                  variant="outline"
                  className="w-full border-[#e5e7eb] text-[#374151]"
                  data-testid="button-close-credentials"
                >
                  Close
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function ResellerPortal() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const { data: sessionData, isLoading } = useQuery<ResellerSession>({
    queryKey: ["/api/reseller/session"],
    refetchOnWindowFocus: false,
  });

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-[#1f2937] to-[#111827]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white"></div>
      </div>
    );
  }

  const isAuthenticated = sessionData?.authenticated || isLoggedIn;

  if (!isAuthenticated) {
    return (
      <ResellerLogin 
        onSuccess={() => {
          setIsLoggedIn(true);
          queryClient.invalidateQueries({ queryKey: ["/api/reseller/session"] });
        }} 
      />
    );
  }

  return (
    <ResellerDashboard 
      session={sessionData!}
      onLogout={() => {
        setIsLoggedIn(false);
        queryClient.invalidateQueries({ queryKey: ["/api/reseller/session"] });
      }}
    />
  );
}
