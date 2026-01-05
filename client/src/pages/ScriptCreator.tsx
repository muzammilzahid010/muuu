import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import AnimatedDotsBackground from "@/components/AnimatedDotsBackground";

import { alpha } from '@mui/material/styles';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import LinearProgress from '@mui/material/LinearProgress';
import Alert from '@mui/material/Alert';
import Chip from '@mui/material/Chip';
import Slider from '@mui/material/Slider';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardMedia from '@mui/material/CardMedia';
import CardContent from '@mui/material/CardContent';
import IconButton from '@mui/material/IconButton';
import { FileText, Sparkles, Copy, Download, Image as ImageIcon, Wand2 } from "lucide-react";

interface GeneratedImage {
  prompt: string;
  imageUrl: string;
}

export default function ScriptCreator() {
  const [storyAbout, setStoryAbout] = useState("");
  const [numberOfPrompts, setNumberOfPrompts] = useState(10);
  const [finalStep, setFinalStep] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedScript, setGeneratedScript] = useState<string | null>(null);
  const [isGeneratingImages, setIsGeneratingImages] = useState(false);
  const [generatedImages, setGeneratedImages] = useState<GeneratedImage[]>([]);
  const [imageProgress, setImageProgress] = useState(0);
  const [selectedModel, setSelectedModel] = useState<"whisk" | "nanoBana" | "nanoBanaPro" | "imagen4">("whisk");
  const { toast } = useToast();
  const [, setLocation] = useLocation();

  const { data: session, isLoading: sessionLoading } = useQuery<{
    authenticated: boolean;
    user?: { id: string; username: string; isAdmin: boolean };
  }>({
    queryKey: ["/api/session"],
  });

  useEffect(() => {
    if (!sessionLoading && session && !session.authenticated) {
      toast({
        title: "Authentication required",
        description: "Please log in to use the script creator.",
        variant: "destructive",
      });
      setLocation("/login");
    }
  }, [session, sessionLoading, setLocation, toast]);

  const handleGenerate = async () => {
    if (!storyAbout.trim()) {
      toast({ title: "Story required", description: "Please describe what your story is about", variant: "destructive" });
      return;
    }

    if (!finalStep.trim()) {
      toast({ title: "Final step required", description: "Please describe what the final step should be", variant: "destructive" });
      return;
    }

    setIsGenerating(true);
    setGeneratedScript(null);

    try {
      const response = await fetch('/api/generate-script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ storyAbout, numberOfPrompts, finalStep }),
      });

      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Failed to generate script');

      setGeneratedScript(result.script);
      toast({ title: "Script generated!", description: "Your storyboard has been created successfully." });
    } catch (error) {
      toast({ title: "Generation failed", description: error instanceof Error ? error.message : "An error occurred", variant: "destructive" });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopyScript = () => {
    if (generatedScript) {
      navigator.clipboard.writeText(generatedScript);
      toast({ title: "Copied!", description: "Script copied to clipboard" });
    }
  };

  const handleGenerateImages = async () => {
    if (!generatedScript) return;

    const lines = generatedScript.split('\n').filter(line => line.trim());
    setIsGeneratingImages(true);
    setGeneratedImages([]);
    setImageProgress(0);

    for (let i = 0; i < lines.length; i++) {
      try {
        const response = await fetch('/api/generate-image', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ prompt: lines[i], aspectRatio: 'IMAGE_ASPECT_RATIO_LANDSCAPE', model: selectedModel }),
        });

        if (response.ok) {
          const data = await response.json();
          setGeneratedImages(prev => [...prev, { prompt: lines[i], imageUrl: data.imageUrl }]);
        }
      } catch (error) {
        console.error('Failed to generate image:', error);
      }
      setImageProgress(((i + 1) / lines.length) * 100);
    }

    setIsGeneratingImages(false);
    toast({ title: "Images generated!", description: `Created ${lines.length} images from your script.` });
  };

  if (sessionLoading) {
    return (
      <UserPanelLayout>
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress />
        </Box>
      </UserPanelLayout>
    );
  }

  return (
    <UserPanelLayout>
      <Box sx={{ position: 'relative', minHeight: '100vh' }}>
        <AnimatedDotsBackground />
        <Box sx={{ position: 'relative', zIndex: 1, maxWidth: 1200, mx: 'auto' }}>
          <Stack spacing={3}>
            <Box>
            <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }}>
              <Box
                sx={{
                  p: 1.5,
                  borderRadius: 2,
                  background: 'linear-gradient(135deg, #374151 0%, #4b5563 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 4px 12px rgba(55, 65, 81, 0.3)'
                }}
              >
                <FileText size={24} color="white" />
              </Box>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#1a1a2e' }}>
                  Script Creator
                </Typography>
                <Typography variant="body2" sx={{ color: '#64748b' }}>
                  Generate AI-powered storyboards for your videos
                </Typography>
              </Box>
            </Stack>
          </Box>

          <Paper elevation={0} sx={{ p: { xs: 3, md: 4 }, borderRadius: 3, border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff' }}>
            <Stack spacing={3}>
              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: '#374151' }}>
                  What is your story about?
                  <Chip label="Required" size="small" sx={{ ml: 1, height: 20, fontSize: '0.7rem', bgcolor: alpha('#374151', 0.1), color: '#374151' }} />
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  rows={3}
                  placeholder="e.g., A young entrepreneur starting a tech company..."
                  value={storyAbout}
                  onChange={(e) => setStoryAbout(e.target.value)}
                  disabled={isGenerating}
                  data-testid="input-story"
                  sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
                />
              </Box>

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: '#374151' }}>
                  What should be the final step/scene?
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  rows={2}
                  placeholder="e.g., The entrepreneur celebrating the company's IPO..."
                  value={finalStep}
                  onChange={(e) => setFinalStep(e.target.value)}
                  disabled={isGenerating}
                  data-testid="input-final"
                  sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2 } }}
                />
              </Box>

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: '#374151' }}>
                  Number of Prompts: {numberOfPrompts}
                </Typography>
                <Slider
                  value={numberOfPrompts}
                  onChange={(_, value) => setNumberOfPrompts(value as number)}
                  min={5}
                  max={30}
                  step={1}
                  disabled={isGenerating}
                  sx={{ color: '#374151' }}
                />
              </Box>

              <Button
                variant="contained"
                size="large"
                onClick={handleGenerate}
                disabled={isGenerating || !storyAbout.trim() || !finalStep.trim()}
                startIcon={isGenerating ? <CircularProgress size={18} sx={{ color: 'white' }} /> : <Wand2 size={18} />}
                data-testid="button-generate"
                sx={{
                  width: '100%',
                  py: 1.5,
                  borderRadius: 2,
                  textTransform: 'none',
                  fontWeight: 600,
                  fontSize: '1rem',
                  color: 'white',
                  bgcolor: '#374151',
                  '&:hover': {
                    bgcolor: '#1f2937',
                  },
                  '&:disabled': { 
                    bgcolor: '#9ca3af',
                    color: 'rgba(255,255,255,0.7)',
                  },
                }}
              >
                {isGenerating ? 'Generating Script...' : 'Generate Script'}
              </Button>
            </Stack>
          </Paper>

          {generatedScript && (
            <Paper elevation={0} sx={{ p: { xs: 3, md: 4 }, borderRadius: 3, border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff' }}>
              <Stack spacing={3}>
                <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={1}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e' }}>Generated Script</Typography>
                  <Stack direction="row" spacing={1}>
                    <Button variant="outlined" size="small" onClick={handleCopyScript} startIcon={<Copy size={16} />} sx={{ borderRadius: 2, textTransform: 'none', borderColor: '#e5e7eb' }}>
                      Copy
                    </Button>
                  </Stack>
                </Stack>

                <Paper elevation={0} sx={{ p: 2, bgcolor: '#f8fafc', borderRadius: 2, maxHeight: 300, overflow: 'auto' }}>
                  <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', color: '#374151' }}>
                    {generatedScript}
                  </Typography>
                </Paper>

                <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" gap={1}>
                  <FormControl size="small" sx={{ minWidth: 150 }}>
                    <InputLabel>Model</InputLabel>
                    <Select value={selectedModel} label="Model" onChange={(e) => setSelectedModel(e.target.value as any)} sx={{ borderRadius: 2 }}>
                      <MenuItem value="whisk">Whisk</MenuItem>
                      <MenuItem value="nanoBana">NanoBana</MenuItem>
                      <MenuItem value="nanoBanaPro">NanoBana Pro</MenuItem>
                      <MenuItem value="imagen4">Imagen 4</MenuItem>
                    </Select>
                  </FormControl>
                  <Button
                    variant="contained"
                    onClick={handleGenerateImages}
                    disabled={isGeneratingImages}
                    startIcon={isGeneratingImages ? <CircularProgress size={18} sx={{ color: 'white' }} /> : <ImageIcon size={18} />}
                    sx={{ borderRadius: 2, textTransform: 'none', fontWeight: 600, bgcolor: '#374151', '&:hover': { bgcolor: '#1f2937' } }}
                  >
                    {isGeneratingImages ? 'Generating Images...' : 'Generate Images from Script'}
                  </Button>
                </Stack>

                {isGeneratingImages && (
                  <Box>
                    <LinearProgress variant="determinate" value={imageProgress} sx={{ height: 8, borderRadius: 4, bgcolor: alpha('#374151', 0.1), '& .MuiLinearProgress-bar': { borderRadius: 4, bgcolor: '#374151' } }} />
                    <Typography variant="caption" sx={{ color: '#64748b', mt: 0.5 }}>{Math.round(imageProgress)}% complete</Typography>
                  </Box>
                )}
              </Stack>
            </Paper>
          )}

          {generatedImages.length > 0 && (
            <Paper elevation={0} sx={{ p: { xs: 3, md: 4 }, borderRadius: 3, border: '1px solid rgba(0,0,0,0.08)', backgroundColor: '#ffffff' }}>
              <Typography variant="h6" sx={{ fontWeight: 600, color: '#1a1a2e', mb: 3 }}>Generated Images ({generatedImages.length})</Typography>
              <Grid container spacing={2}>
                {generatedImages.map((img, index) => (
                  <Grid size={{ xs: 12, sm: 6, md: 4 }} key={index}>
                    <Card elevation={0} sx={{ border: '1px solid rgba(0,0,0,0.08)', borderRadius: 2 }}>
                      <CardMedia component="img" height="180" image={img.imageUrl} alt={`Scene ${index + 1}`} sx={{ objectFit: 'cover' }} />
                      <CardContent sx={{ p: 2 }}>
                        <Typography variant="caption" sx={{ color: '#64748b', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                          {img.prompt}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          )}
          </Stack>
        </Box>
      </Box>
    </UserPanelLayout>
  );
}
