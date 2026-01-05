import { useState, useRef, useEffect } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { Volume2, Download, Loader2, Play, Pause, AudioLines, BarChart3 } from "lucide-react";
import UserPanelLayout from "@/layouts/UserPanelLayout";

interface VoiceCharacterUsage {
  used: number;
  limit: number;
  remaining: number;
  resetDate: string | null;
  resetDays: number;
  planType: string;
  isAdmin: boolean;
}

interface TTSResponse {
  success: boolean;
  audioId?: string;
  mimeType?: string;
  minutesUsed?: number;
  tokenRemaining?: number;
  tokenLabel?: string;
  voiceCharacterUsage?: VoiceCharacterUsage;
  error?: string;
}

interface VoicesData {
  voices: { name: string; description: string }[];
  languages: { code: string; name: string }[];
}

export default function AdminTextToSpeech() {
  const { toast } = useToast();
  const audioRef = useRef<HTMLAudioElement>(null);
  const [text, setText] = useState("");
  const [speakingRate, setSpeakingRate] = useState(10);
  const [language, setLanguage] = useState("en-us");
  const [defaultVoice, setDefaultVoice] = useState("american_female");
  const [model, setModel] = useState<"zonos-v0.1-transformer" | "zonos-v0.1-hybrid">("zonos-v0.1-transformer");
  const [outputFormat, setOutputFormat] = useState<"audio/wav" | "audio/webm" | "audio/ogg" | "audio/mp3">("audio/wav");
  const [generatedAudio, setGeneratedAudio] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [tokenInfo, setTokenInfo] = useState<{ remaining: number; label: string; used: number } | null>(null);

  const [happiness, setHappiness] = useState(0.6);
  const [sadness, setSadness] = useState(0.05);
  const [anger, setAnger] = useState(0.05);
  const [neutral, setNeutral] = useState(0.6);

  const { data: voicesData } = useQuery<VoicesData>({
    queryKey: ["/api/veo3_tts/voices"],
  });

  // Fetch initial voice character usage
  const { data: voiceUsage } = useQuery<VoiceCharacterUsage>({
    queryKey: ["/api/user/voice-usage"],
  });

  const ttsMutation = useMutation({
    mutationFn: async () => {
      const emotion = model === "zonos-v0.1-transformer" ? {
        happiness,
        sadness,
        anger,
        neutral,
        disgust: 0.05,
        fear: 0.05,
        surprise: 0.05,
        other: 0.5,
      } : undefined;

      const response = await apiRequest("POST", "/api/veo3_tts/tts", {
        text,
        speakingRate,
        languageIsoCode: language,
        mimeType: outputFormat,
        model,
        defaultVoiceName: defaultVoice,
        emotion,
      });
      return response.json() as Promise<TTSResponse>;
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
        // Refresh voice usage after successful generation
        queryClient.invalidateQueries({ queryKey: ["/api/user/voice-usage"] });
        toast({
          title: "Audio Generated",
          description: `Audio generated (${data.minutesUsed?.toFixed(2)} min used)`,
        });
      } else {
        toast({
          title: "Generation Failed",
          description: data.error || "Failed to generate audio",
          variant: "destructive",
        });
      }
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to generate audio",
        variant: "destructive",
      });
    },
  });

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
      link.download = `tts-audio.${outputFormat.split("/")[1]}`;
      link.click();
    }
  };

  return (
    <UserPanelLayout>
      <div className="p-6 max-w-4xl mx-auto space-y-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <AudioLines className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Text to Speech</h1>
            <p className="text-muted-foreground">Convert text to natural-sounding speech with emotion control</p>
          </div>
        </div>

        {/* Voice Character Usage Display - only show for non-admins with finite limits */}
        {voiceUsage && !voiceUsage.isAdmin && voiceUsage.limit > 0 && (
          <Card className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950/30 dark:to-indigo-950/30 border-blue-200 dark:border-blue-800">
            <CardContent className="py-4">
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <BarChart3 className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  <div>
                    <p className="text-sm font-medium text-foreground">Character Usage</p>
                    <p className="text-xs text-muted-foreground">
                      {voiceUsage.used.toLocaleString()} / {voiceUsage.limit.toLocaleString()} characters used
                    </p>
                  </div>
                </div>
                <div className="flex-1 min-w-[200px] max-w-[400px]">
                  <Progress 
                    value={voiceUsage.limit > 0 ? Math.min(100, (voiceUsage.used / voiceUsage.limit) * 100) : 0} 
                    className="h-2"
                    data-testid="progress-voice-usage"
                  />
                  <div className="flex justify-between mt-1">
                    <span className="text-xs text-muted-foreground">
                      {voiceUsage.remaining.toLocaleString()} remaining
                    </span>
                    {voiceUsage.resetDate && (
                      <span className="text-xs text-muted-foreground">
                        Resets: {new Date(voiceUsage.resetDate).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Voice Settings</CardTitle>
              <CardDescription>Choose voice and language</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Default Voice</Label>
                <Select value={defaultVoice} onValueChange={setDefaultVoice}>
                  <SelectTrigger data-testid="select-voice">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {voicesData?.voices?.map((voice) => (
                      <SelectItem key={voice.name} value={voice.name}>
                        {voice.description}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

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
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Emotion Control</CardTitle>
              <CardDescription>Adjust emotional tone (Transformer model only)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Happiness: {happiness.toFixed(2)}</Label>
                <Slider
                  value={[happiness]}
                  onValueChange={(v) => setHappiness(v[0])}
                  min={0}
                  max={1}
                  step={0.05}
                  disabled={model !== "zonos-v0.1-transformer"}
                  data-testid="slider-happiness"
                />
              </div>

              <div className="space-y-2">
                <Label>Sadness: {sadness.toFixed(2)}</Label>
                <Slider
                  value={[sadness]}
                  onValueChange={(v) => setSadness(v[0])}
                  min={0}
                  max={1}
                  step={0.05}
                  disabled={model !== "zonos-v0.1-transformer"}
                  data-testid="slider-sadness"
                />
              </div>

              <div className="space-y-2">
                <Label>Anger: {anger.toFixed(2)}</Label>
                <Slider
                  value={[anger]}
                  onValueChange={(v) => setAnger(v[0])}
                  min={0}
                  max={1}
                  step={0.05}
                  disabled={model !== "zonos-v0.1-transformer"}
                  data-testid="slider-anger"
                />
              </div>

              <div className="space-y-2">
                <Label>Neutral: {neutral.toFixed(2)}</Label>
                <Slider
                  value={[neutral]}
                  onValueChange={(v) => setNeutral(v[0])}
                  min={0}
                  max={1}
                  step={0.05}
                  disabled={model !== "zonos-v0.1-transformer"}
                  data-testid="slider-neutral"
                />
              </div>

              {model !== "zonos-v0.1-transformer" && (
                <p className="text-xs text-muted-foreground">
                  Emotion control is only available with the Transformer model
                </p>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Text to Speak</CardTitle>
            <CardDescription>Enter the text you want to convert to speech</CardDescription>
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
                onClick={() => ttsMutation.mutate()}
                disabled={!text.trim() || ttsMutation.isPending}
                data-testid="button-generate"
              >
                {ttsMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Volume2 className="w-4 h-4 mr-2" />
                    Generate Speech
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
              <CardDescription>Your audio is ready to play or download</CardDescription>
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
