import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { TopVoice } from "@shared/schema";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { Loader2, Play, Pause, Download, Volume2, Mic } from "lucide-react";

export default function TopVoices() {
  const { toast } = useToast();
  const [selectedVoice, setSelectedVoice] = useState<TopVoice | null>(null);
  const [text, setText] = useState("");
  const [speakingRate, setSpeakingRate] = useState(10);
  const [generatedAudioId, setGeneratedAudioId] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [demoPlaying, setDemoPlaying] = useState<string | null>(null);
  const demoAudioRef = useRef<HTMLAudioElement | null>(null);

  const { data: voices = [], isLoading } = useQuery<TopVoice[]>({
    queryKey: ["/api/top-voices"],
  });

  const generateMutation = useMutation({
    mutationFn: async (voiceId: string) => {
      const response = await apiRequest("POST", `/api/top-voices/${voiceId}/generate`, {
        text,
        speakingRate,
      });
      return response.json();
    },
    onSuccess: (data) => {
      setGeneratedAudioId(data.audioId);
      toast({
        title: "Audio Generated",
        description: `Voice: ${data.voiceName}`,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Generation Failed",
        description: error.message || "Failed to generate audio",
        variant: "destructive",
      });
    },
  });

  useEffect(() => {
    if (generatedAudioId && audioRef.current) {
      audioRef.current.src = `/api/top-voices/audio/${generatedAudioId}`;
      audioRef.current.load();
    }
  }, [generatedAudioId]);

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
    link.href = `/api/top-voices/audio/${generatedAudioId}`;
    link.download = `${selectedVoice?.name || "voice"}_audio.wav`;
    link.click();
  };

  const formatTime = (time: number) => {
    const mins = Math.floor(time / 60);
    const secs = Math.floor(time % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  const playDemoAudio = (voice: TopVoice) => {
    if (demoPlaying === voice.id) {
      demoAudioRef.current?.pause();
      setDemoPlaying(null);
    } else {
      if (demoAudioRef.current) {
        demoAudioRef.current.pause();
      }
      const audio = new Audio(voice.demoAudioUrl);
      demoAudioRef.current = audio;
      audio.onended = () => setDemoPlaying(null);
      audio.play();
      setDemoPlaying(voice.id);
    }
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
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100" data-testid="text-page-title">
          Top Voices
        </h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Select a voice and generate audio with your text
        </p>
      </div>

      {voices.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Mic className="w-12 h-12 mx-auto text-gray-400 mb-4" />
            <p className="text-gray-500">No voices available yet</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Available Voices</h2>
            <div className="space-y-3">
              {voices.map((voice) => (
                <Card
                  key={voice.id}
                  className={`cursor-pointer transition-all ${
                    selectedVoice?.id === voice.id
                      ? "ring-2 ring-gray-800 dark:ring-gray-200"
                      : "hover-elevate"
                  }`}
                  onClick={() => setSelectedVoice(voice)}
                  data-testid={`card-voice-${voice.id}`}
                >
                  <CardContent className="p-4 flex items-center justify-between gap-4">
                    <div className="flex-1">
                      <h3 className="font-medium text-gray-900 dark:text-gray-100">{voice.name}</h3>
                      {voice.description && (
                        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{voice.description}</p>
                      )}
                    </div>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        playDemoAudio(voice);
                      }}
                      data-testid={`button-play-demo-${voice.id}`}
                    >
                      {demoPlaying === voice.id ? (
                        <Pause className="w-4 h-4" />
                      ) : (
                        <Play className="w-4 h-4" />
                      )}
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>

          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Generate Audio</h2>
            <Card>
              <CardContent className="p-6 space-y-4">
                {selectedVoice ? (
                  <>
                    <div className="flex items-center gap-2 mb-4">
                      <Badge variant="secondary">{selectedVoice.name}</Badge>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="text">Text to speak</Label>
                      <Textarea
                        id="text"
                        placeholder="Enter the text you want to convert to speech..."
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        rows={4}
                        maxLength={10000}
                        data-testid="input-text"
                      />
                      <p className={`text-xs ${text.length > 9000 ? 'text-orange-500' : 'text-muted-foreground'}`}>{text.length.toLocaleString()} / 10,000 characters</p>
                    </div>

                    <div className="space-y-2">
                      <Label>Speaking Rate: {speakingRate}</Label>
                      <Slider
                        value={[speakingRate]}
                        onValueChange={(v) => setSpeakingRate(v[0])}
                        min={5}
                        max={25}
                        step={1}
                        data-testid="slider-speaking-rate"
                      />
                    </div>

                    <Button
                      onClick={() => generateMutation.mutate(selectedVoice.id)}
                      disabled={!text.trim() || generateMutation.isPending}
                      className="w-full"
                      data-testid="button-generate"
                    >
                      {generateMutation.isPending ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Volume2 className="w-4 h-4 mr-2" />
                          Generate Audio
                        </>
                      )}
                    </Button>

                    {generatedAudioId && (
                      <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg space-y-3">
                        <audio
                          ref={audioRef}
                          onTimeUpdate={handleTimeUpdate}
                          onLoadedMetadata={handleLoadedMetadata}
                          onEnded={() => setIsPlaying(false)}
                        />
                        
                        <div className="flex items-center gap-3">
                          <Button
                            size="icon"
                            variant="outline"
                            onClick={handlePlayPause}
                            data-testid="button-play-generated"
                          >
                            {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                          </Button>
                          
                          <div
                            className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded cursor-pointer"
                            onClick={handleSeek}
                          >
                            <div
                              className="h-full bg-gray-800 dark:bg-gray-200 rounded"
                              style={{ width: `${duration ? (currentTime / duration) * 100 : 0}%` }}
                            />
                          </div>
                          
                          <span className="text-sm text-gray-500 min-w-[80px]">
                            {formatTime(currentTime)} / {formatTime(duration)}
                          </span>
                          
                          <Button
                            size="icon"
                            variant="outline"
                            onClick={handleDownload}
                            data-testid="button-download"
                          >
                            <Download className="w-4 h-4" />
                          </Button>
                        </div>

                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <Mic className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>Select a voice to get started</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
