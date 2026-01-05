import { useState, useRef, useEffect } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { useToast } from "@/hooks/use-toast";
import { Upload, Mic, Download, Loader2, Play, Pause, Volume2 } from "lucide-react";
import UserPanelLayout from "@/layouts/UserPanelLayout";

interface VoiceCloneResponse {
  success: boolean;
  audioId?: string;
  mimeType?: string;
  minutesUsed?: number;
  tokenRemaining?: number;
  tokenLabel?: string;
  error?: string;
}

interface VoicesData {
  voices: { name: string; description: string }[];
  languages: { code: string; name: string }[];
}

export default function AdminVoiceCloning() {
  const { toast } = useToast();
  const audioRef = useRef<HTMLAudioElement>(null);
  const [text, setText] = useState("");
  const [referenceAudio, setReferenceAudio] = useState<string | null>(null);
  const [referenceFileName, setReferenceFileName] = useState<string>("");
  const [speakingRate, setSpeakingRate] = useState(10);
  const [language, setLanguage] = useState("en-us");
  const [model, setModel] = useState<"zonos-v0.1-transformer" | "zonos-v0.1-hybrid">("zonos-v0.1-transformer");
  const [outputFormat, setOutputFormat] = useState<"audio/wav" | "audio/webm" | "audio/ogg" | "audio/mp3">("audio/wav");
  const [generatedAudio, setGeneratedAudio] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [tokenInfo, setTokenInfo] = useState<{ remaining: number; label: string; used: number } | null>(null);

  const { data: voicesData } = useQuery<VoicesData>({
    queryKey: ["/api/veo3_tts/voices"],
  });

  const cloneVoiceMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/veo3_tts/clone-voice", {
        text,
        referenceAudioBase64: referenceAudio,
        speakingRate,
        languageIsoCode: language,
        mimeType: outputFormat,
        model,
      });
      return response.json() as Promise<VoiceCloneResponse>;
    },
    onSuccess: (data) => {
      if (data.success && data.audioId) {
        const audioUrl = `/api/veo3_tts/audio/${data.audioId}`;
        setGeneratedAudio(audioUrl);
        setTokenInfo({
          remaining: data.tokenRemaining || 0,
          label: data.tokenLabel || "Unknown",
          used: data.minutesUsed || 0,
        });
        toast({
          title: "Voice Cloned Successfully",
          description: `Audio generated (${data.minutesUsed?.toFixed(2)} min used)`,
        });
      } else {
        toast({
          title: "Generation Failed",
          description: data.error || "Failed to clone voice",
          variant: "destructive",
        });
      }
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to clone voice",
        variant: "destructive",
      });
    },
  });

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 10 * 1024 * 1024) {
      toast({
        title: "File Too Large",
        description: "Maximum file size is 10MB",
        variant: "destructive",
      });
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const base64 = (reader.result as string).split(",")[1];
      setReferenceAudio(base64);
      setReferenceFileName(file.name);
    };
    reader.readAsDataURL(file);
  };

  // Reload audio element when source changes and setup event listeners
  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;

    if (generatedAudio) {
      audio.load();
    }

    const handleTimeUpdate = () => setCurrentTime(audio.currentTime);
    const handleLoadedMetadata = () => setDuration(audio.duration);
    const handleEnded = () => {
      setIsPlaying(false);
      setCurrentTime(0);
    };

    audio.addEventListener("timeupdate", handleTimeUpdate);
    audio.addEventListener("loadedmetadata", handleLoadedMetadata);
    audio.addEventListener("ended", handleEnded);

    return () => {
      audio.removeEventListener("timeupdate", handleTimeUpdate);
      audio.removeEventListener("loadedmetadata", handleLoadedMetadata);
      audio.removeEventListener("ended", handleEnded);
    };
  }, [generatedAudio]);

  // Format time as MM:SS
  const formatTime = (time: number) => {
    if (!isFinite(time) || isNaN(time)) return "0:00";
    const minutes = Math.floor(time / 60);
    const seconds = Math.floor(time % 60);
    return `${minutes}:${seconds.toString().padStart(2, "0")}`;
  };

  // Handle progress bar click
  const handleProgressClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!audioRef.current || !duration) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const newTime = (clickX / rect.width) * duration;
    audioRef.current.currentTime = newTime;
    setCurrentTime(newTime);
  };

  const togglePlayPause = () => {
    if (audioRef.current) {
      if (isPlaying) {
        audioRef.current.pause();
      } else {
        audioRef.current.play().catch(err => {
          console.error("Error playing audio:", err);
          toast({
            title: "Playback Error",
            description: "Could not play audio. Try downloading instead.",
            variant: "destructive",
          });
        });
      }
      setIsPlaying(!isPlaying);
    }
  };

  const downloadAudio = () => {
    if (generatedAudio) {
      const link = document.createElement("a");
      link.href = generatedAudio;
      link.download = `cloned-voice.${outputFormat.split("/")[1]}`;
      link.click();
    }
  };

  return (
    <UserPanelLayout>
      <div className="p-6 max-w-4xl mx-auto space-y-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
            <Mic className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Voice Cloning</h1>
            <p className="text-muted-foreground">Clone any voice with AI-powered text-to-speech</p>
          </div>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Reference Voice</CardTitle>
              <CardDescription>Upload an audio sample of the voice you want to clone (max 10MB)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="border-2 border-dashed border-muted-foreground/25 rounded-lg p-6 text-center">
                <input
                  type="file"
                  accept="audio/*"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="audio-upload"
                  data-testid="input-audio-upload"
                />
                <label htmlFor="audio-upload" className="cursor-pointer">
                  <Upload className="w-10 h-10 mx-auto text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">
                    {referenceFileName || "Click to upload audio file"}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">MP3, WAV, M4A, OGG (max 10MB)</p>
                </label>
              </div>

              {referenceAudio && (
                <div className="flex items-center gap-2 p-3 bg-muted rounded-lg">
                  <Volume2 className="w-4 h-4 text-green-600" />
                  <span className="text-sm truncate flex-1">{referenceFileName}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setReferenceAudio(null);
                      setReferenceFileName("");
                    }}
                    data-testid="button-remove-audio"
                  >
                    Remove
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Settings</CardTitle>
              <CardDescription>Configure voice generation parameters</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Language</Label>
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger data-testid="select-language">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {voicesData?.languages?.map((lang) => (
                      <SelectItem key={lang.code} value={lang.code}>
                        {lang.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Model</Label>
                <Select value={model} onValueChange={(v) => setModel(v as any)}>
                  <SelectTrigger data-testid="select-model">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="zonos-v0.1-transformer">Transformer (Emotion Support)</SelectItem>
                    <SelectItem value="zonos-v0.1-hybrid">Hybrid (Better for Japanese)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Output Format</Label>
                <Select value={outputFormat} onValueChange={(v) => setOutputFormat(v as any)}>
                  <SelectTrigger data-testid="select-format">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="audio/wav">WAV</SelectItem>
                    <SelectItem value="audio/mp3">MP3</SelectItem>
                    <SelectItem value="audio/webm">WebM</SelectItem>
                    <SelectItem value="audio/ogg">OGG</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Speaking Rate: {speakingRate}</Label>
                <Slider
                  value={[speakingRate]}
                  onValueChange={(v) => setSpeakingRate(v[0])}
                  min={5}
                  max={35}
                  step={1}
                  data-testid="slider-speaking-rate"
                />
                <p className="text-xs text-muted-foreground">5 = slow, 35 = fast</p>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Text to Speak</CardTitle>
            <CardDescription>Enter the text you want to convert to speech with the cloned voice</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              placeholder="Enter your text here..."
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={5}
              maxLength={10000}
              data-testid="textarea-text"
            />
            <div className="flex justify-between items-center">
              <span className={`text-sm ${text.length > 9000 ? 'text-orange-500' : 'text-muted-foreground'}`}>{text.length.toLocaleString()} / 10,000 characters</span>
              <Button
                onClick={() => cloneVoiceMutation.mutate()}
                disabled={!text.trim() || !referenceAudio || cloneVoiceMutation.isPending}
                data-testid="button-generate"
              >
                {cloneVoiceMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Mic className="w-4 h-4 mr-2" />
                    Clone Voice
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {generatedAudio && (
          <Card>
            <CardHeader>
              <CardTitle>Generated Audio</CardTitle>
              <CardDescription>Your cloned voice audio is ready</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <audio
                ref={audioRef}
                src={generatedAudio}
                className="hidden"
              />
              <div className="flex items-center gap-4">
                <Button
                  variant="outline"
                  size="icon"
                  onClick={togglePlayPause}
                  data-testid="button-play-pause"
                >
                  {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                </Button>
                <div className="flex-1 space-y-1">
                  <div 
                    className="h-2 bg-muted rounded-full cursor-pointer relative overflow-hidden"
                    onClick={handleProgressClick}
                    data-testid="progress-bar"
                  >
                    <div 
                      className="h-full bg-primary rounded-full transition-all duration-100" 
                      style={{ width: duration > 0 ? `${(currentTime / duration) * 100}%` : "0%" }}
                    />
                  </div>
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span data-testid="text-current-time">{formatTime(currentTime)}</span>
                    <span data-testid="text-duration">{formatTime(duration)}</span>
                  </div>
                </div>
                <Button onClick={downloadAudio} data-testid="button-download">
                  <Download className="w-4 h-4 mr-2" />
                  Download
                </Button>
              </div>
              {tokenInfo && (
                <div className="flex items-center justify-between text-sm pt-2 border-t">
                  <div className="flex items-center gap-4">
                    <span className="text-muted-foreground">
                      Duration: <span className="font-medium text-foreground" data-testid="text-audio-duration">{formatTime(duration)}</span>
                    </span>
                    <span className="text-muted-foreground">
                      Used: <span className="font-medium text-foreground" data-testid="text-minutes-used">{tokenInfo.used.toFixed(2)} min</span>
                    </span>
                  </div>
                  <div className="text-muted-foreground">
                    API Key: <span className="font-medium text-foreground" data-testid="text-token-label">{tokenInfo.label}</span>
                    <span className="mx-2">|</span>
                    Remaining: <span className="font-medium text-green-600 dark:text-green-400" data-testid="text-token-remaining">{tokenInfo.remaining.toFixed(1)} min</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </UserPanelLayout>
  );
}
