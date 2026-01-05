import { useState, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { TopVoice } from "@shared/schema";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Loader2, Plus, Trash2, Edit, Play, Pause, ArrowLeft, Upload } from "lucide-react";
import { useLocation } from "wouter";

export default function AdminTopVoices() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [editingVoice, setEditingVoice] = useState<TopVoice | null>(null);
  const [playingId, setPlayingId] = useState<string | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [demoAudioUrl, setDemoAudioUrl] = useState("");
  const [demoAudioBase64, setDemoAudioBase64] = useState("");
  const [sortOrder, setSortOrder] = useState(0);

  const { data: voices = [], isLoading } = useQuery<TopVoice[]>({
    queryKey: ["/api/admin/top-voices"],
  });

  const addMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/admin/top-voices", {
        name,
        description,
        demoAudioUrl,
        demoAudioBase64,
        sortOrder,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/top-voices"] });
      toast({ title: "Voice Added", description: "Top voice added successfully" });
      resetForm();
      setIsAddDialogOpen(false);
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (data: { id: string; updates: Partial<TopVoice> }) => {
      const response = await apiRequest("PATCH", `/api/admin/top-voices/${data.id}`, data.updates);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/top-voices"] });
      toast({ title: "Voice Updated" });
      setEditingVoice(null);
      resetForm();
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/admin/top-voices/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/top-voices"] });
      toast({ title: "Voice Deleted" });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const resetForm = () => {
    setName("");
    setDescription("");
    setDemoAudioUrl("");
    setDemoAudioBase64("");
    setSortOrder(0);
  };

  const openEditDialog = (voice: TopVoice) => {
    setEditingVoice(voice);
    setName(voice.name);
    setDescription(voice.description || "");
    setDemoAudioUrl(voice.demoAudioUrl);
    setDemoAudioBase64(voice.demoAudioBase64 || "");
    setSortOrder(voice.sortOrder);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith("audio/")) {
      toast({ title: "Invalid File", description: "Please upload an audio file", variant: "destructive" });
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const base64 = (reader.result as string).split(",")[1];
      setDemoAudioBase64(base64);
      // Create a blob URL for preview
      const blob = new Blob([file], { type: file.type });
      setDemoAudioUrl(URL.createObjectURL(blob));
    };
    reader.readAsDataURL(file);
  };

  const playAudio = (url: string, id: string) => {
    if (playingId === id) {
      audioRef.current?.pause();
      setPlayingId(null);
    } else {
      if (audioRef.current) {
        audioRef.current.pause();
      }
      const audio = new Audio(url);
      audioRef.current = audio;
      audio.onended = () => setPlayingId(null);
      audio.play();
      setPlayingId(id);
    }
  };

  const handleSave = () => {
    if (editingVoice) {
      updateMutation.mutate({
        id: editingVoice.id,
        updates: { name, description, demoAudioUrl, demoAudioBase64, sortOrder },
      });
    } else {
      addMutation.mutate();
    }
  };

  const toggleActive = (voice: TopVoice) => {
    updateMutation.mutate({
      id: voice.id,
      updates: { isActive: !voice.isActive },
    });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-8 h-8 animate-spin text-gray-600" />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setLocation("/admin")}
            data-testid="button-back"
          >
            <ArrowLeft className="w-5 h-5" />
          </Button>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100" data-testid="text-page-title">
            Manage Top Voices
          </h1>
        </div>

        <Dialog open={isAddDialogOpen || !!editingVoice} onOpenChange={(open) => {
          if (!open) {
            setIsAddDialogOpen(false);
            setEditingVoice(null);
            resetForm();
          }
        }}>
          <DialogTrigger asChild>
            <Button onClick={() => setIsAddDialogOpen(true)} data-testid="button-add-voice">
              <Plus className="w-4 h-4 mr-2" />
              Add Voice
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>{editingVoice ? "Edit Voice" : "Add New Voice"}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-4">
              <div className="space-y-2">
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., Professional Male"
                  data-testid="input-name"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description (Optional)</Label>
                <Textarea
                  id="description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief description of the voice..."
                  rows={2}
                  data-testid="input-description"
                />
              </div>

              <div className="space-y-2">
                <Label>Demo Audio</Label>
                <div className="flex gap-2">
                  <Input
                    value={demoAudioUrl}
                    onChange={(e) => setDemoAudioUrl(e.target.value)}
                    placeholder="Audio URL or upload file"
                    data-testid="input-audio-url"
                  />
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => fileInputRef.current?.click()}
                    data-testid="button-upload"
                  >
                    <Upload className="w-4 h-4" />
                  </Button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="audio/*"
                    className="hidden"
                    onChange={handleFileUpload}
                  />
                </div>
                {demoAudioUrl && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => playAudio(demoAudioUrl, "preview")}
                    data-testid="button-preview-audio"
                  >
                    {playingId === "preview" ? <Pause className="w-4 h-4 mr-2" /> : <Play className="w-4 h-4 mr-2" />}
                    Preview
                  </Button>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="sortOrder">Sort Order</Label>
                <Input
                  id="sortOrder"
                  type="number"
                  value={sortOrder}
                  onChange={(e) => setSortOrder(parseInt(e.target.value) || 0)}
                  data-testid="input-sort-order"
                />
              </div>

              <Button
                onClick={handleSave}
                disabled={!name || !demoAudioUrl || addMutation.isPending || updateMutation.isPending}
                className="w-full"
                data-testid="button-save"
              >
                {addMutation.isPending || updateMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  editingVoice ? "Update Voice" : "Add Voice"
                )}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Top Voices ({voices.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {voices.length === 0 ? (
            <p className="text-center text-gray-500 py-8">No voices added yet</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Demo</TableHead>
                  <TableHead>Order</TableHead>
                  <TableHead>Active</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {voices.map((voice) => (
                  <TableRow key={voice.id} data-testid={`row-voice-${voice.id}`}>
                    <TableCell className="font-medium">{voice.name}</TableCell>
                    <TableCell className="max-w-[200px] truncate">
                      {voice.description || "-"}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => playAudio(voice.demoAudioUrl, voice.id)}
                        data-testid={`button-play-${voice.id}`}
                      >
                        {playingId === voice.id ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                      </Button>
                    </TableCell>
                    <TableCell>{voice.sortOrder}</TableCell>
                    <TableCell>
                      <Switch
                        checked={voice.isActive}
                        onCheckedChange={() => toggleActive(voice)}
                        data-testid={`switch-active-${voice.id}`}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openEditDialog(voice)}
                          data-testid={`button-edit-${voice.id}`}
                        >
                          <Edit className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => deleteMutation.mutate(voice.id)}
                          data-testid={`button-delete-${voice.id}`}
                        >
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
