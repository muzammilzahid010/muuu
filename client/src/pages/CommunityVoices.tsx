import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { CommunityVoice, User } from "@shared/schema";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Loader2, Play, Pause, Download, Volume2, Mic, Heart, Plus, Trophy, User as UserIcon, Clock, Trash2, Upload, Filter } from "lucide-react";

interface VoicesResponse {
  voices: CommunityVoice[];
  likedIds: string[];
}

interface SessionResponse {
  authenticated: boolean;
  user?: User;
}

export default function CommunityVoices() {
  const { toast } = useToast();
  const [selectedVoice, setSelectedVoice] = useState<CommunityVoice | null>(null);
  const [text, setText] = useState("");
  const [speakingRate, setSpeakingRate] = useState(10);
  const [generatedAudioId, setGeneratedAudioId] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [demoPlaying, setDemoPlaying] = useState<string | null>(null);
  const demoAudioRef = useRef<HTMLAudioElement | null>(null);
  
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newVoiceName, setNewVoiceName] = useState("");
  const [newVoiceDescription, setNewVoiceDescription] = useState("");
  const [newVoiceLanguage, setNewVoiceLanguage] = useState("English");
  const [newVoiceGender, setNewVoiceGender] = useState<"Male" | "Female">("Male");
  const [newVoiceAudio, setNewVoiceAudio] = useState<string | null>(null);
  const [newVoiceAudioDuration, setNewVoiceAudioDuration] = useState(0);
  const [newVoiceAudioSize, setNewVoiceAudioSize] = useState(0);
  const [newVoiceFileName, setNewVoiceFileName] = useState("");
  
  const [filterLanguage, setFilterLanguage] = useState<string>("all");
  const [filterGender, setFilterGender] = useState<string>("all");
  
  const LANGUAGES = ["English", "Hindi", "Urdu", "Arabic", "Spanish", "French", "German", "Chinese", "Japanese", "Korean", "Portuguese", "Russian", "Other"];

  const { data: sessionData } = useQuery<SessionResponse>({
    queryKey: ["/api/session"],
  });

  const { data: allVoicesData, isLoading: isLoadingAll } = useQuery<VoicesResponse>({
    queryKey: ["/api/community-voices"],
  });

  const { data: topVoicesData, isLoading: isLoadingTop } = useQuery<VoicesResponse>({
    queryKey: ["/api/community-voices/top"],
  });

  const currentUser = sessionData?.user;
  const voices = allVoicesData?.voices || [];
  const topVoices = topVoicesData?.voices || [];
  const likedIds = allVoicesData?.likedIds || [];
  
  // Check if user can delete a voice (their own voice OR admin)
  const canDeleteVoice = (voice: CommunityVoice) => {
    if (!currentUser) return false;
    return voice.creatorId === currentUser.id || currentUser.isAdmin;
  };

  const createMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/community-voices", {
        name: newVoiceName,
        description: newVoiceDescription || undefined,
        language: newVoiceLanguage,
        gender: newVoiceGender,
        demoAudioBase64: newVoiceAudio,
        durationSeconds: newVoiceAudioDuration,
        fileSizeBytes: newVoiceAudioSize,
      });
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Voice Created", description: "Your voice has been added to the community!" });
      setShowCreateDialog(false);
      setNewVoiceName("");
      setNewVoiceDescription("");
      setNewVoiceLanguage("English");
      setNewVoiceGender("Male");
      setNewVoiceAudio(null);
      setNewVoiceFileName("");
      queryClient.invalidateQueries({ queryKey: ["/api/community-voices"] });
      queryClient.invalidateQueries({ queryKey: ["/api/community-voices/top"] });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to create voice", variant: "destructive" });
    },
  });

  const likeMutation = useMutation({
    mutationFn: async (voiceId: string) => {
      const response = await apiRequest("POST", `/api/community-voices/${voiceId}/like`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/community-voices"] });
      queryClient.invalidateQueries({ queryKey: ["/api/community-voices/top"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (voiceId: string) => {
      const response = await apiRequest("DELETE", `/api/community-voices/${voiceId}`);
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Voice Deleted" });
      if (selectedVoice) setSelectedVoice(null);
      queryClient.invalidateQueries({ queryKey: ["/api/community-voices"] });
      queryClient.invalidateQueries({ queryKey: ["/api/community-voices/top"] });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to delete voice", variant: "destructive" });
    },
  });

  const generateMutation = useMutation({
    mutationFn: async (voiceId: string) => {
      const response = await apiRequest("POST", `/api/community-voices/${voiceId}/generate`, {
        text,
        speakingRate,
      });
      return response.json();
    },
    onSuccess: (data) => {
      setGeneratedAudioId(data.audioId);
      toast({ title: "Audio Generated", description: `Voice: ${data.voiceName}` });
    },
    onError: (error: any) => {
      toast({ title: "Generation Failed", description: error.message || "Failed to generate audio", variant: "destructive" });
    },
  });

  useEffect(() => {
    if (generatedAudioId && audioRef.current) {
      audioRef.current.src = `/api/community-voices/audio/${generatedAudioId}`;
      audioRef.current.load();
    }
  }, [generatedAudioId]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      toast({ title: "Error", description: "File must be less than 5MB", variant: "destructive" });
      return;
    }

    const audio = new Audio();
    audio.onloadedmetadata = () => {
      if (audio.duration < 10) {
        toast({ title: "Error", description: "Audio must be at least 10 seconds", variant: "destructive" });
        return;
      }
      setNewVoiceAudioDuration(Math.floor(audio.duration));
      setNewVoiceAudioSize(file.size);
      setNewVoiceFileName(file.name);

      const reader = new FileReader();
      reader.onload = () => {
        const base64 = (reader.result as string).split(",")[1];
        setNewVoiceAudio(base64);
      };
      reader.readAsDataURL(file);
    };
    audio.src = URL.createObjectURL(file);
  };

  const handlePlayPause = () => {
    if (!audioRef.current) return;
    if (isPlaying) {
      audioRef.current.pause();
    } else {
      audioRef.current.play();
    }
    setIsPlaying(!isPlaying);
  };

  const handleTimeUpdate = () => {
    if (audioRef.current) {
      setCurrentTime(audioRef.current.currentTime);
    }
  };

  const handleLoadedMetadata = () => {
    if (audioRef.current) {
      setDuration(audioRef.current.duration);
    }
  };

  const handleSeek = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!audioRef.current || !duration) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const pos = (e.clientX - rect.left) / rect.width;
    audioRef.current.currentTime = pos * duration;
  };

  const handleDownload = () => {
    if (!generatedAudioId) return;
    const link = document.createElement("a");
    link.href = `/api/community-voices/audio/${generatedAudioId}`;
    link.download = `${selectedVoice?.name || "voice"}_audio.wav`;
    link.click();
  };

  const formatTime = (time: number) => {
    const mins = Math.floor(time / 60);
    const secs = Math.floor(time % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  const playDemoAudio = (voice: CommunityVoice) => {
    if (demoPlaying === voice.id) {
      demoAudioRef.current?.pause();
      setDemoPlaying(null);
    } else {
      if (demoAudioRef.current) {
        demoAudioRef.current.pause();
      }
      // Try multiple audio formats - browser will use what works
      const audioDataUrl = `data:audio/mpeg;base64,${voice.demoAudioBase64}`;
      const audio = new Audio();
      audio.onerror = () => {
        // Fallback to wav if mpeg fails
        audio.src = `data:audio/wav;base64,${voice.demoAudioBase64}`;
        audio.play().catch(() => {
          // Try webm as last resort
          audio.src = `data:audio/webm;base64,${voice.demoAudioBase64}`;
          audio.play().catch(console.error);
        });
      };
      audio.src = audioDataUrl;
      demoAudioRef.current = audio;
      audio.onended = () => setDemoPlaying(null);
      audio.play().catch(() => {
        // If initial play fails, try fallbacks
        audio.src = `data:audio/wav;base64,${voice.demoAudioBase64}`;
        audio.play().catch(console.error);
      });
      setDemoPlaying(voice.id);
    }
  };

  const VoiceCard = ({ voice, showRank }: { voice: CommunityVoice; showRank?: number }) => {
    const isLiked = likedIds.includes(voice.id);
    return (
      <Card
        key={voice.id}
        className={`cursor-pointer transition-all ${
          selectedVoice?.id === voice.id ? "ring-2 ring-gray-800 dark:ring-gray-200" : "hover-elevate"
        }`}
        onClick={() => setSelectedVoice(voice)}
        data-testid={`card-community-voice-${voice.id}`}
      >
        <CardContent className="p-4">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                {showRank && (
                  <Badge variant="secondary" className="shrink-0">
                    #{showRank}
                  </Badge>
                )}
                <h3 className="font-medium text-gray-900 dark:text-gray-100 truncate">{voice.name}</h3>
              </div>
              <div className="flex items-center gap-2 mt-1 text-sm text-gray-500 dark:text-gray-400">
                <UserIcon className="w-3 h-3" />
                <span className="truncate">{voice.creatorName}</span>
              </div>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline" className="text-xs">{voice.language}</Badge>
                <Badge variant="outline" className="text-xs">{voice.gender}</Badge>
              </div>
              {voice.description && (
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">{voice.description}</p>
              )}
            </div>
            <div className="flex flex-col items-end gap-2 shrink-0">
              <Button
                size="icon"
                variant="ghost"
                disabled={likeMutation.isPending}
                onClick={(e) => {
                  e.stopPropagation();
                  if (!likeMutation.isPending) {
                    likeMutation.mutate(voice.id);
                  }
                }}
                data-testid={`button-like-${voice.id}`}
              >
                {likeMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Heart className={`w-4 h-4 ${isLiked ? "fill-red-500 text-red-500" : ""}`} />
                )}
              </Button>
              <span className="text-xs text-gray-500">{voice.likesCount}</span>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-3">
            <Button
              size="sm"
              variant="outline"
              onClick={(e) => {
                e.stopPropagation();
                playDemoAudio(voice);
              }}
              data-testid={`button-play-demo-${voice.id}`}
            >
              {demoPlaying === voice.id ? <Pause className="w-3 h-3 mr-1" /> : <Play className="w-3 h-3 mr-1" />}
              Demo
            </Button>
            <Badge variant="outline" className="text-xs">
              <Clock className="w-3 h-3 mr-1" />
              {voice.durationSeconds}s
            </Badge>
          </div>
        </CardContent>
      </Card>
    );
  };

  if (isLoadingAll) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-8 h-8 animate-spin text-gray-600" />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100" data-testid="text-page-title">
            Community Voices
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Create and share voice presets with the community
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button data-testid="button-create-voice">
              <Plus className="w-4 h-4 mr-2" />
              Create Voice
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Community Voice</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label>Voice Name</Label>
                <Input
                  value={newVoiceName}
                  onChange={(e) => setNewVoiceName(e.target.value)}
                  placeholder="Enter voice name"
                  data-testid="input-voice-name"
                />
              </div>
              <div>
                <Label>Description (optional)</Label>
                <Textarea
                  value={newVoiceDescription}
                  onChange={(e) => setNewVoiceDescription(e.target.value)}
                  placeholder="Describe this voice..."
                  data-testid="input-voice-description"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Language</Label>
                  <Select value={newVoiceLanguage} onValueChange={setNewVoiceLanguage}>
                    <SelectTrigger className="mt-1" data-testid="select-voice-language">
                      <SelectValue placeholder="Select language" />
                    </SelectTrigger>
                    <SelectContent>
                      {LANGUAGES.map((lang) => (
                        <SelectItem key={lang} value={lang}>{lang}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Gender</Label>
                  <Select value={newVoiceGender} onValueChange={(v) => setNewVoiceGender(v as "Male" | "Female")}>
                    <SelectTrigger className="mt-1" data-testid="select-voice-gender">
                      <SelectValue placeholder="Select gender" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Male">Male</SelectItem>
                      <SelectItem value="Female">Female</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label>Demo Audio (10+ seconds, max 5MB)</Label>
                <div className="mt-2">
                  <label className="flex items-center justify-center w-full h-24 border-2 border-dashed rounded-md cursor-pointer hover:border-gray-400 transition-colors">
                    <input
                      type="file"
                      accept="audio/*"
                      onChange={handleFileUpload}
                      className="hidden"
                      data-testid="input-voice-audio"
                    />
                    <div className="text-center">
                      {newVoiceFileName ? (
                        <div className="flex items-center gap-2">
                          <Volume2 className="w-5 h-5 text-green-500" />
                          <span className="text-sm">{newVoiceFileName}</span>
                          <Badge variant="outline">{newVoiceAudioDuration}s</Badge>
                        </div>
                      ) : (
                        <div className="flex flex-col items-center text-gray-500">
                          <Upload className="w-6 h-6 mb-1" />
                          <span className="text-sm">Click to upload audio</span>
                        </div>
                      )}
                    </div>
                  </label>
                </div>
              </div>
              <Button
                onClick={() => createMutation.mutate()}
                disabled={!newVoiceName || !newVoiceAudio || createMutation.isPending}
                className="w-full"
                data-testid="button-submit-voice"
              >
                {createMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
                Create Voice
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Tabs defaultValue="all">
        <TabsList>
          <TabsTrigger value="all" data-testid="tab-all-voices">All Voices</TabsTrigger>
          <TabsTrigger value="top" data-testid="tab-top-voices">
            <Trophy className="w-4 h-4 mr-1" />
            Top Ranked
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="mt-4">
          {voices.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Mic className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                <p className="text-gray-500">No community voices yet. Be the first to create one!</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Community Voices</h2>
                <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2">
                  {voices.map((voice) => (
                    <VoiceCard key={voice.id} voice={voice} />
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Generate Audio</h2>
                {selectedVoice ? (
                  <Card>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between gap-2">
                        <CardTitle className="text-lg">{selectedVoice.name}</CardTitle>
                        {canDeleteVoice(selectedVoice) && (
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => {
                              if (confirm("Delete this voice?")) {
                                deleteMutation.mutate(selectedVoice.id);
                              }
                            }}
                            data-testid="button-delete-voice"
                          >
                            <Trash2 className="w-4 h-4 text-red-500" />
                          </Button>
                        )}
                      </div>
                      <p className="text-sm text-gray-500">by {selectedVoice.creatorName}</p>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div>
                        <Label>Text to Speak</Label>
                        <Textarea
                          value={text}
                          onChange={(e) => setText(e.target.value)}
                          placeholder="Enter text to convert to speech..."
                          className="mt-2"
                          rows={4}
                          maxLength={10000}
                          data-testid="input-tts-text"
                        />
                        <p className={`text-xs mt-1 ${text.length > 9000 ? 'text-orange-500' : 'text-muted-foreground'}`}>{text.length.toLocaleString()} / 10,000 characters</p>
                      </div>
                      <div>
                        <Label>Speaking Rate: {speakingRate}</Label>
                        <Slider
                          value={[speakingRate]}
                          onValueChange={(v) => setSpeakingRate(v[0])}
                          min={5}
                          max={25}
                          step={1}
                          className="mt-2"
                          data-testid="slider-speaking-rate"
                        />
                      </div>
                      <Button
                        onClick={() => generateMutation.mutate(selectedVoice.id)}
                        disabled={!text.trim() || generateMutation.isPending}
                        className="w-full"
                        data-testid="button-generate-audio"
                      >
                        {generateMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Volume2 className="w-4 h-4 mr-2" />}
                        Generate Audio
                      </Button>

                      {generatedAudioId && (
                        <div className="space-y-3 pt-4 border-t">
                          <audio
                            ref={audioRef}
                            onTimeUpdate={handleTimeUpdate}
                            onLoadedMetadata={handleLoadedMetadata}
                            onEnded={() => setIsPlaying(false)}
                          />
                          <div className="flex items-center gap-2">
                            <Button size="icon" variant="outline" onClick={handlePlayPause} data-testid="button-play-pause">
                              {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                            </Button>
                            <div
                              className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full cursor-pointer"
                              onClick={handleSeek}
                              data-testid="progress-bar"
                            >
                              <div
                                className="h-full bg-gray-800 dark:bg-gray-200 rounded-full"
                                style={{ width: duration ? `${(currentTime / duration) * 100}%` : "0%" }}
                              />
                            </div>
                            <span className="text-xs text-gray-500 w-20 text-right">
                              {formatTime(currentTime)} / {formatTime(duration)}
                            </span>
                            <Button size="icon" variant="outline" onClick={handleDownload} data-testid="button-download">
                              <Download className="w-4 h-4" />
                            </Button>
                          </div>

                        </div>
                      )}
                    </CardContent>
                  </Card>
                ) : (
                  <Card>
                    <CardContent className="py-12 text-center">
                      <Mic className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                      <p className="text-gray-500">Select a voice to generate audio</p>
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>
          )}
        </TabsContent>

        <TabsContent value="top" className="mt-4">
          {isLoadingTop ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-gray-600" />
            </div>
          ) : topVoices.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Trophy className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                <p className="text-gray-500">No ranked voices yet. Like some voices to see them here!</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Top Ranked Voices</h2>
                  <div className="flex items-center gap-2 flex-wrap">
                    <Select value={filterLanguage} onValueChange={setFilterLanguage}>
                      <SelectTrigger className="w-[130px]" data-testid="filter-language">
                        <Filter className="w-3 h-3 mr-1" />
                        <SelectValue placeholder="Language" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Languages</SelectItem>
                        {LANGUAGES.map((lang) => (
                          <SelectItem key={lang} value={lang}>{lang}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Select value={filterGender} onValueChange={setFilterGender}>
                      <SelectTrigger className="w-[100px]" data-testid="filter-gender">
                        <SelectValue placeholder="Gender" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All</SelectItem>
                        <SelectItem value="Male">Male</SelectItem>
                        <SelectItem value="Female">Female</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2">
                  {topVoices
                    .filter((voice) => filterLanguage === "all" || voice.language === filterLanguage)
                    .filter((voice) => filterGender === "all" || voice.gender === filterGender)
                    .map((voice, index) => (
                      <VoiceCard key={voice.id} voice={voice} showRank={index + 1} />
                    ))}
                  {topVoices.filter((v) => (filterLanguage === "all" || v.language === filterLanguage) && (filterGender === "all" || v.gender === filterGender)).length === 0 && (
                    <p className="text-center text-gray-500 py-4">No voices match the selected filters</p>
                  )}
                </div>
              </div>

              <div className="space-y-4">
                <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Generate Audio</h2>
                {selectedVoice ? (
                  <Card>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between gap-2">
                        <CardTitle className="text-lg">{selectedVoice.name}</CardTitle>
                        {canDeleteVoice(selectedVoice) && (
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => {
                              if (confirm("Delete this voice?")) {
                                deleteMutation.mutate(selectedVoice.id);
                              }
                            }}
                            data-testid="button-delete-voice-top"
                          >
                            <Trash2 className="w-4 h-4 text-red-500" />
                          </Button>
                        )}
                      </div>
                      <p className="text-sm text-gray-500">by {selectedVoice.creatorName}</p>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div>
                        <Label>Text to Speak</Label>
                        <Textarea
                          value={text}
                          onChange={(e) => setText(e.target.value)}
                          placeholder="Enter text to convert to speech..."
                          className="mt-2"
                          rows={4}
                          maxLength={10000}
                          data-testid="input-tts-text-top"
                        />
                        <p className={`text-xs mt-1 ${text.length > 9000 ? 'text-orange-500' : 'text-muted-foreground'}`}>{text.length.toLocaleString()} / 10,000 characters</p>
                      </div>
                      <div>
                        <Label>Speaking Rate: {speakingRate}</Label>
                        <Slider
                          value={[speakingRate]}
                          onValueChange={(v) => setSpeakingRate(v[0])}
                          min={5}
                          max={25}
                          step={1}
                          className="mt-2"
                          data-testid="slider-speaking-rate-top"
                        />
                      </div>
                      <Button
                        onClick={() => generateMutation.mutate(selectedVoice.id)}
                        disabled={!text.trim() || generateMutation.isPending}
                        className="w-full"
                        data-testid="button-generate-audio-top"
                      >
                        {generateMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Volume2 className="w-4 h-4 mr-2" />}
                        Generate Audio
                      </Button>

                      {generatedAudioId && (
                        <div className="space-y-3 pt-4 border-t">
                          <audio
                            ref={audioRef}
                            onTimeUpdate={handleTimeUpdate}
                            onLoadedMetadata={handleLoadedMetadata}
                            onEnded={() => setIsPlaying(false)}
                          />
                          <div className="flex items-center gap-2">
                            <Button size="icon" variant="outline" onClick={handlePlayPause} data-testid="button-play-pause-top">
                              {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                            </Button>
                            <div
                              className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full cursor-pointer"
                              onClick={handleSeek}
                              data-testid="progress-bar-top"
                            >
                              <div
                                className="h-full bg-gray-800 dark:bg-gray-200 rounded-full"
                                style={{ width: duration ? `${(currentTime / duration) * 100}%` : "0%" }}
                              />
                            </div>
                            <span className="text-xs text-gray-500 w-20 text-right">
                              {formatTime(currentTime)} / {formatTime(duration)}
                            </span>
                            <Button size="icon" variant="outline" onClick={handleDownload} data-testid="button-download-top">
                              <Download className="w-4 h-4" />
                            </Button>
                          </div>

                        </div>
                      )}
                    </CardContent>
                  </Card>
                ) : (
                  <Card>
                    <CardContent className="py-12 text-center">
                      <Mic className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                      <p className="text-gray-500">Select a voice to generate audio</p>
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
