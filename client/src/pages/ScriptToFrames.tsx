import { useState, useRef, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import UserPanelLayout from "@/layouts/UserPanelLayout";
import AnimatedDotsBackground from "@/components/AnimatedDotsBackground";
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { 
  FileText, Sparkles, Copy, Check, Image, ArrowRight, Film, Loader2, 
  Info, ShieldAlert, User, Archive, RefreshCw, Play, X,
  ImagePlus, Link2, Unlink
} from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Switch } from "@/components/ui/switch";

interface ScenePrompt {
  sceneNumber: number;
  prompt: string;
  description: string;
}

interface SceneWithImages extends ScenePrompt {
  startImageUrl?: string;
  endImageUrl?: string;
  videoPrompt?: string;
  imageStatus: 'pending' | 'generating' | 'success' | 'failed';
  error?: string;
  // Video generation fields
  videoStatus?: 'pending' | 'uploading' | 'generating' | 'processing' | 'completed' | 'failed';
  videoUrl?: string;
  operationName?: string;
  videoError?: string;
}

const styleOptions = [
  { value: "disney_pixar_3d", label: "Disney Pixar 3D Animation" },
  { value: "anime", label: "Anime Style" },
  { value: "realistic", label: "Photorealistic" },
  { value: "cartoon", label: "2D Cartoon" },
  { value: "watercolor", label: "Watercolor Illustration" },
  { value: "cinematic", label: "Cinematic Film" },
  { value: "fantasy", label: "Fantasy Art" },
  { value: "minimalist", label: "Minimalist" },
];

const aspectRatioOptions = [
  { value: "IMAGE_ASPECT_RATIO_LANDSCAPE", label: "Landscape (16:9)" },
  { value: "IMAGE_ASPECT_RATIO_PORTRAIT", label: "Portrait (9:16)" },
  { value: "IMAGE_ASPECT_RATIO_SQUARE", label: "Square (1:1)" },
];

export default function ScriptToFrames() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [script, setScript] = useState("");
  const [numberOfScenes, setNumberOfScenes] = useState("5");
  const [style, setStyle] = useState("disney_pixar_3d");
  const [aspectRatio, setAspectRatio] = useState("IMAGE_ASPECT_RATIO_LANDSCAPE");
  const [generatedScenes, setGeneratedScenes] = useState<SceneWithImages[]>([]);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  
  // Character description feature
  const [characterDescription, setCharacterDescription] = useState("");
  const [useCharacterReference, setUseCharacterReference] = useState(false);
  const [characterPortraitUrl, setCharacterPortraitUrl] = useState<string | null>(null);
  const [isGeneratingCharacter, setIsGeneratingCharacter] = useState(false);
  
  // Image generation state
  const [isGeneratingImages, setIsGeneratingImages] = useState(false);
  const [imageProgress, setImageProgress] = useState({ current: 0, total: 0 });
  const [isDownloadingZip, setIsDownloadingZip] = useState(false);
  
  // Alignment view state
  const [showAlignment, setShowAlignment] = useState(true);
  
  // Video generation state
  const [isGeneratingVideos, setIsGeneratingVideos] = useState(false);
  const [videoProgress, setVideoProgress] = useState({ current: 0, total: 0 });
  const [videoAbortController, setVideoAbortController] = useState<AbortController | null>(null);
  const [isDownloadingVideosZip, setIsDownloadingVideosZip] = useState(false);

  // Use ref to track latest scenes during streaming to avoid stale closures
  const scenesRef = useRef<SceneWithImages[]>([]);
  scenesRef.current = generatedScenes;

  const { data: session, isLoading: isLoadingSession } = useQuery<{
    authenticated: boolean;
    user?: { id: string; username: string; isAdmin: boolean };
  }>({
    queryKey: ["/api/session"],
  });

  const isAdmin = session?.authenticated && session?.user?.isAdmin;

  // Generate prompts from script
  const generatePromptsMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/script-to-prompts", {
        script,
        numberOfScenes: parseInt(numberOfScenes),
        style,
        characterDescription: useCharacterReference && characterDescription ? characterDescription : undefined
      });
      return response.json();
    },
    onSuccess: (data: { prompts: ScenePrompt[] }) => {
      const scenesWithImages: SceneWithImages[] = data.prompts.map((p) => ({
        ...p,
        imageStatus: 'pending' as const,
        videoPrompt: p.prompt,
      }));
      setGeneratedScenes(scenesWithImages);
      toast({
        title: "Prompts Generated",
        description: `Successfully created ${data.prompts.length} scene prompts from your script.`,
      });
    },
    onError: (error: any) => {
      toast({
        variant: "destructive",
        title: "Generation Failed",
        description: error.message || "Failed to generate prompts.",
      });
    },
  });

  // Convert image URL to base64
  const convertUrlToBase64 = useCallback(async (url: string): Promise<{ base64: string; mimeType: string } | null> => {
    try {
      if (url.startsWith('data:')) {
        const mimeType = url.split(';')[0].split(':')[1];
        const base64 = url.split(',')[1];
        return { base64, mimeType };
      }
      const response = await fetch(url);
      const blob = await response.blob();
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => {
          const result = reader.result as string;
          const base64 = result.split(',')[1];
          resolve({ base64, mimeType: blob.type });
        };
        reader.onerror = reject;
        reader.readAsDataURL(blob);
      });
    } catch (error) {
      console.error('Failed to convert image to base64:', error);
      return null;
    }
  }, []);

  // Generate character portrait with white background
  const generateCharacterPortrait = async () => {
    if (!characterDescription.trim()) {
      toast({
        variant: "destructive",
        title: "Description Required",
        description: "Please enter a character description first.",
      });
      return;
    }

    setIsGeneratingCharacter(true);
    try {
      const portraitPrompt = `Character portrait on a pure white background: ${characterDescription}. Full body view, centered composition, clean white background, high quality, detailed character design, consistent style for animation.`;
      
      const response = await fetch('/api/text-to-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          prompt: portraitPrompt,
          aspectRatio: "IMAGE_ASPECT_RATIO_PORTRAIT",
          model: "whisk"
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to generate character portrait');
      }

      const data = await response.json();
      setCharacterPortraitUrl(data.imageUrl);
      toast({
        title: "Character Portrait Generated",
        description: "Your character reference image is ready.",
      });
    } catch (error: any) {
      toast({
        variant: "destructive",
        title: "Portrait Generation Failed",
        description: error.message || "Failed to generate character portrait.",
      });
    } finally {
      setIsGeneratingCharacter(false);
    }
  };

  // Generate all images using STREAMING batch endpoint (shows images as they complete like TextToImage)
  // SPECIAL: Scene 1 gets TWO images (start + end), other scenes only get end (start = prev scene's end)
  const handleGenerateAllImages = async () => {
    const currentScenes = scenesRef.current;
    if (currentScenes.length === 0) {
      toast({ variant: "destructive", title: "No Scenes", description: "Please generate prompts first." });
      return;
    }

    // Check if character reference is enabled but no portrait exists
    if (useCharacterReference && !characterPortraitUrl) {
      toast({
        variant: "destructive",
        title: "Character Portrait Required",
        description: "Please generate a character portrait first, or disable character reference.",
      });
      return;
    }

    setIsGeneratingImages(true);
    // Total images = N + 1 (extra start image for Scene 1)
    const totalImages = currentScenes.length + 1;
    setImageProgress({ current: 0, total: totalImages });

    // Mark all scenes as generating
    setGeneratedScenes(prev => prev.map(s => ({ ...s, imageStatus: 'generating' as const, error: undefined })));

    try {
      // Prepare reference image data if character portrait exists
      let referenceImagesData: { base64: string; mimeType: string }[] | undefined;
      
      if (useCharacterReference && characterPortraitUrl) {
        const converted = await convertUrlToBase64(characterPortraitUrl);
        if (converted) {
          referenceImagesData = [converted];
        }
      }

      // Build prompts array: 
      // Index 0: Scene 1 START frame (opening scene)
      // Index 1: Scene 1 END frame
      // Index 2: Scene 2 END frame = Scene 2's end, Scene 3's start
      // ...and so on
      const prompts: string[] = [];
      
      // First prompt: Scene 1's START frame (add "opening shot" context)
      const scene1StartPrompt = `Opening scene establishing shot: ${currentScenes[0].prompt}`;
      prompts.push(scene1StartPrompt);
      
      // Then add END frame prompts for all scenes
      currentScenes.forEach(s => {
        prompts.push(s.prompt);
      });
      
      const requestBody: any = {
        prompts,
        aspectRatio,
        model: "nanoBanaPro",
      };

      if (referenceImagesData) {
        requestBody.referenceImagesData = referenceImagesData;
      }

      // Use STREAMING batch endpoint with SSE (shows images as they complete)
      const response = await fetch('/api/text-to-image/batch-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (!reader) throw new Error('No response body');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        // Use index-based loop to properly track event/data pairs
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.startsWith('event: ')) {
            const eventType = line.slice(7);
            // Next line should be data
            if (i + 1 < lines.length && lines[i + 1].startsWith('data: ')) {
              const dataStr = lines[i + 1].slice(6);
              i++; // Skip the data line in next iteration
              try {
                const data = JSON.parse(dataStr);
                
                if (eventType === 'image') {
                  // Update progress
                  setImageProgress({ current: data.progress?.current || 0, total: data.progress?.total || totalImages });
                  
                  // Map image index to scene:
                  // Index 0 = Scene 1's START image
                  // Index 1 = Scene 1's END image
                  // Index 2 = Scene 2's END image (Scene 2's start = Scene 1's end)
                  // etc.
                  const imgIndex = data.index;
                  const isSuccess = data.status === 'success' && data.imageUrl;
                  
                  if (imgIndex === 0) {
                    // Scene 1's START image
                    setGeneratedScenes(prev => {
                      const updated = [...prev];
                      if (updated.length > 0) {
                        updated[0] = {
                          ...updated[0],
                          startImageUrl: isSuccess ? data.imageUrl : undefined,
                        };
                      }
                      return updated;
                    });
                    console.log(`[ScriptToFrames] Scene 1 START image received: ${data.status}`);
                  } else {
                    // Index 1+ are END images for scenes 1, 2, 3...
                    const sceneIdx = imgIndex - 1; // Scene index (0-based)
                    
                    setGeneratedScenes(prev => {
                      const updated = [...prev];
                      if (sceneIdx >= 0 && sceneIdx < updated.length) {
                        updated[sceneIdx] = {
                          ...updated[sceneIdx],
                          imageStatus: isSuccess ? 'success' : 'failed',
                          endImageUrl: isSuccess ? data.imageUrl : undefined,
                          error: data.error,
                        };
                        // Set next scene's START image = this scene's END image
                        if (isSuccess && sceneIdx + 1 < updated.length) {
                          updated[sceneIdx + 1] = {
                            ...updated[sceneIdx + 1],
                            startImageUrl: data.imageUrl,
                          };
                        }
                      }
                      return updated;
                    });
                    console.log(`[ScriptToFrames] Scene ${sceneIdx + 1} END image received: ${data.status}`);
                  }
                } else if (eventType === 'complete') {
                  console.log(`[ScriptToFrames] Streaming complete: ${data.summary?.success}/${data.summary?.total}`);
                } else if (eventType === 'error') {
                  throw new Error(data.error);
                }
              } catch (e) {
                // Ignore parse errors for incomplete data
              }
            }
          } else if (line.startsWith('data: ')) {
            // Handle data without event prefix
            try {
              const data = JSON.parse(line.slice(6));
              if (data.index !== undefined) {
                const imgIndex = data.index;
                const isSuccess = data.status === 'success' && data.imageUrl;
                
                if (imgIndex === 0) {
                  // Scene 1's START image
                  setGeneratedScenes(prev => {
                    const updated = [...prev];
                    if (updated.length > 0) {
                      updated[0] = { ...updated[0], startImageUrl: isSuccess ? data.imageUrl : undefined };
                    }
                    return updated;
                  });
                } else {
                  const sceneIdx = imgIndex - 1;
                  setGeneratedScenes(prev => {
                    const updated = [...prev];
                    if (sceneIdx >= 0 && sceneIdx < updated.length) {
                      updated[sceneIdx] = {
                        ...updated[sceneIdx],
                        imageStatus: isSuccess ? 'success' : 'failed',
                        endImageUrl: isSuccess ? data.imageUrl : undefined,
                        error: data.error,
                      };
                      if (isSuccess && sceneIdx + 1 < updated.length) {
                        updated[sceneIdx + 1] = { ...updated[sceneIdx + 1], startImageUrl: data.imageUrl };
                      }
                    }
                    return updated;
                  });
                }
                if (data.progress) {
                  setImageProgress({ current: data.progress.current, total: data.progress.total });
                }
              }
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }

      // Final alignment pass - ensure all scenes have proper start/end alignment
      setGeneratedScenes(prev => {
        const final = [...prev];
        // Scene 1 already has its unique start image, just ensure chain for rest
        for (let i = 1; i < final.length; i++) {
          if (final[i - 1].imageStatus === 'success' && final[i - 1].endImageUrl) {
            final[i] = { ...final[i], startImageUrl: final[i - 1].endImageUrl };
          }
        }
        return final;
      });

      const successCount = scenesRef.current.filter(s => s.imageStatus === 'success').length;
      toast({
        title: "Image Generation Complete",
        description: `Generated ${successCount}/${currentScenes.length} scene images (+ Scene 1 start frame).`,
      });
    } catch (error: any) {
      console.error('Batch generation error:', error);
      
      // Mark remaining generating scenes as failed
      setGeneratedScenes(prev => prev.map(s => 
        s.imageStatus === 'generating' 
          ? { ...s, imageStatus: 'failed' as const, error: error.message }
          : s
      ));
      
      toast({
        variant: "destructive",
        title: "Generation Failed",
        description: error.message || "Failed to generate images.",
      });
    } finally {
      setIsGeneratingImages(false);
    }
  };

  // Retry failed images using STREAMING batch endpoint
  const handleRetryFailed = async () => {
    const currentScenes = scenesRef.current;
    const failedIndices: number[] = [];
    currentScenes.forEach((s, idx) => {
      if (s.imageStatus === 'failed') failedIndices.push(idx);
    });

    if (failedIndices.length === 0) return;

    // Check character reference
    if (useCharacterReference && !characterPortraitUrl) {
      toast({
        variant: "destructive",
        title: "Character Portrait Required",
        description: "Please generate a character portrait first, or disable character reference.",
      });
      return;
    }

    setIsGeneratingImages(true);
    
    // Mark failed as generating
    setGeneratedScenes(prev => prev.map((s, idx) => 
      failedIndices.includes(idx) ? { ...s, imageStatus: 'generating' as const, error: undefined } : s
    ));

    try {
      let referenceImagesData: { base64: string; mimeType: string }[] | undefined;
      
      if (useCharacterReference && characterPortraitUrl) {
        const converted = await convertUrlToBase64(characterPortraitUrl);
        if (converted) {
          referenceImagesData = [converted];
        }
      }

      const failedPrompts = failedIndices.map(idx => currentScenes[idx].prompt);
      
      const requestBody: any = {
        prompts: failedPrompts,
        aspectRatio,
        model: "nanoBanaPro",
        isRetry: true,
      };

      if (referenceImagesData) {
        requestBody.referenceImagesData = referenceImagesData;
      }

      // Use STREAMING batch endpoint for retry too
      const response = await fetch('/api/text-to-image/batch-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Retry failed');
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (!reader) throw new Error('No response body');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.startsWith('event: ')) {
            const eventType = line.slice(7);
            // Next line should be data
            if (i + 1 < lines.length && lines[i + 1].startsWith('data: ')) {
              const dataStr = lines[i + 1].slice(6);
              i++; // Skip the data line in next iteration
              try {
                const data = JSON.parse(dataStr);
                
                if (eventType === 'image') {
                  const originalIndex = failedIndices[data.index];
                  
                  setGeneratedScenes(prev => {
                    const updated = [...prev];
                    if (originalIndex >= 0 && originalIndex < updated.length) {
                      const isSuccess = data.status === 'success' && data.imageUrl;
                      updated[originalIndex] = {
                        ...updated[originalIndex],
                        imageStatus: isSuccess ? 'success' : 'failed',
                        endImageUrl: data.imageUrl,
                        error: data.error,
                      };
                      
                      // Update next scene's start image
                      if (isSuccess && originalIndex + 1 < updated.length) {
                        updated[originalIndex + 1] = {
                          ...updated[originalIndex + 1],
                          startImageUrl: data.imageUrl,
                        };
                      }
                    }
                    return updated;
                  });
                  console.log(`[ScriptToFrames Retry] Image ${data.index + 1} received: ${data.status}`);
                }
              } catch (e) {
                // Ignore parse errors
              }
            }
          } else if (line.startsWith('data: ')) {
            // Handle data without event prefix
            try {
              const data = JSON.parse(line.slice(6));
              if (data.index !== undefined) {
                const originalIndex = failedIndices[data.index];
                setGeneratedScenes(prev => {
                  const updated = [...prev];
                  if (originalIndex >= 0 && originalIndex < updated.length) {
                    const isSuccess = data.status === 'success' && data.imageUrl;
                    updated[originalIndex] = {
                      ...updated[originalIndex],
                      imageStatus: isSuccess ? 'success' : 'failed',
                      endImageUrl: data.imageUrl,
                      error: data.error,
                    };
                    if (isSuccess && originalIndex + 1 < updated.length) {
                      updated[originalIndex + 1] = { ...updated[originalIndex + 1], startImageUrl: data.imageUrl };
                    }
                  }
                  return updated;
                });
              }
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }

      // Final alignment pass
      setGeneratedScenes(prev => {
        const final = [...prev];
        for (let i = 1; i < final.length; i++) {
          if (final[i - 1].imageStatus === 'success' && final[i - 1].endImageUrl) {
            final[i] = { ...final[i], startImageUrl: final[i - 1].endImageUrl };
          }
        }
        return final;
      });
      
      const successCount = scenesRef.current.filter((s, idx) => 
        failedIndices.includes(idx) && s.imageStatus === 'success'
      ).length;
      toast({ 
        title: "Retry Complete", 
        description: `Regenerated ${successCount}/${failedIndices.length} failed images.` 
      });
    } catch (error: any) {
      // Mark retried ones as failed
      setGeneratedScenes(prev => prev.map((s, idx) => 
        failedIndices.includes(idx) && s.imageStatus === 'generating' 
          ? { ...s, imageStatus: 'failed' as const, error: error.message } 
          : s
      ));
      toast({ variant: "destructive", title: "Retry Failed", description: error.message });
    } finally {
      setIsGeneratingImages(false);
    }
  };

  // Download all images as ZIP
  const handleDownloadAllAsZip = async () => {
    const currentScenes = scenesRef.current;
    const successfulScenes = currentScenes.filter(s => s.imageStatus === 'success' && s.endImageUrl);
    
    if (successfulScenes.length === 0) {
      toast({ variant: "destructive", title: "No Images", description: "No images available to download." });
      return;
    }

    setIsDownloadingZip(true);
    
    try {
      const zip = new JSZip();
      
      await Promise.all(
        successfulScenes.map(async (scene) => {
          if (scene.endImageUrl) {
            try {
              if (scene.endImageUrl.startsWith('data:')) {
                const base64Data = scene.endImageUrl.split(',')[1];
                const binaryData = atob(base64Data);
                const bytes = new Uint8Array(binaryData.length);
                for (let i = 0; i < binaryData.length; i++) {
                  bytes[i] = binaryData.charCodeAt(i);
                }
                zip.file(`scene_${scene.sceneNumber}_end.png`, bytes);
              } else {
                const response = await fetch(scene.endImageUrl);
                const blob = await response.blob();
                zip.file(`scene_${scene.sceneNumber}_end.png`, blob);
              }
            } catch (error) {
              console.error(`Failed to add scene ${scene.sceneNumber} to zip:`, error);
            }
          }
        })
      );

      // Add character portrait if exists
      if (characterPortraitUrl) {
        try {
          if (characterPortraitUrl.startsWith('data:')) {
            const base64Data = characterPortraitUrl.split(',')[1];
            const binaryData = atob(base64Data);
            const bytes = new Uint8Array(binaryData.length);
            for (let i = 0; i < binaryData.length; i++) {
              bytes[i] = binaryData.charCodeAt(i);
            }
            zip.file('character_portrait.png', bytes);
          }
        } catch (error) {
          console.error('Failed to add character portrait to zip:', error);
        }
      }

      const zipBlob = await zip.generateAsync({ 
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 1 }
      });

      saveAs(zipBlob, `script_frames_${Date.now()}.zip`);
      toast({ title: "Download Complete!", description: `${successfulScenes.length} scene images downloaded.` });
    } catch (error) {
      console.error('Failed to create zip:', error);
      toast({ title: "Download Failed", description: "Failed to create ZIP file.", variant: "destructive" });
    } finally {
      setIsDownloadingZip(false);
    }
  };

  const handleCopyPrompt = async (prompt: string, index: number) => {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
      toast({ title: "Copied", description: "Prompt copied to clipboard" });
    } catch {
      toast({ variant: "destructive", title: "Copy Failed", description: "Failed to copy prompt" });
    }
  };

  const handleCopyAllPrompts = async () => {
    try {
      const allPrompts = generatedScenes.map((p) => `Scene ${p.sceneNumber}:\n${p.prompt}`).join("\n\n---\n\n");
      await navigator.clipboard.writeText(allPrompts);
      toast({ title: "All Prompts Copied", description: "All prompts have been copied to clipboard" });
    } catch {
      toast({ variant: "destructive", title: "Copy Failed", description: "Failed to copy prompts" });
    }
  };

  // Align all scenes - each scene's end becomes next scene's start
  const handleAlignAllScenes = () => {
    if (generatedScenes.length === 0) return;
    
    setGeneratedScenes(prev => {
      const aligned = [...prev];
      for (let i = 1; i < aligned.length; i++) {
        // Scene i's start = Scene i-1's end
        if (aligned[i - 1].endImageUrl) {
          aligned[i] = {
            ...aligned[i],
            startImageUrl: aligned[i - 1].endImageUrl
          };
        }
      }
      return aligned;
    });
    
    toast({ 
      title: "Scenes Aligned", 
      description: "All scene transitions have been synchronized." 
    });
  };

  // Generate all videos using start/end images
  const handleGenerateAllVideos = async () => {
    const currentScenes = scenesRef.current;
    
    // Filter scenes that have both start and end images
    const scenesWithImages = currentScenes.filter(s => 
      s.startImageUrl && s.endImageUrl && s.videoPrompt
    );
    
    if (scenesWithImages.length === 0) {
      toast({ 
        variant: "destructive", 
        title: "No Ready Scenes", 
        description: "Generate images first. Each scene needs both start and end images." 
      });
      return;
    }

    setIsGeneratingVideos(true);
    setVideoProgress({ current: 0, total: scenesWithImages.length });

    // Mark scenes as pending for video
    setGeneratedScenes(prev => prev.map(s => ({
      ...s,
      videoStatus: s.startImageUrl && s.endImageUrl ? 'pending' : undefined,
      videoError: undefined,
    })));

    const abortController = new AbortController();
    setVideoAbortController(abortController);

    try {
      // Convert images to base64 for each scene
      const scenesData = await Promise.all(scenesWithImages.map(async (scene) => {
        const startData = await convertUrlToBase64(scene.startImageUrl!);
        const endData = await convertUrlToBase64(scene.endImageUrl!);
        
        if (!startData || !endData) {
          throw new Error(`Failed to convert images for scene ${scene.sceneNumber}`);
        }
        
        return {
          sceneNumber: scene.sceneNumber,
          videoPrompt: scene.videoPrompt || scene.prompt,
          startImageBase64: startData.base64,
          startImageMimeType: startData.mimeType,
          endImageBase64: endData.base64,
          endImageMimeType: endData.mimeType,
        };
      }));

      // Determine aspect ratio from current setting
      const videoAspectRatio = aspectRatio.includes('LANDSCAPE') ? 'landscape' : 'portrait';

      const response = await fetch('/api/script-to-frames/generate-videos-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          scenes: scenesData,
          aspectRatio: videoAspectRatio,
        }),
        signal: abortController.signal,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (!reader) throw new Error('No response body');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.startsWith('event: ')) {
            const eventType = line.slice(7);
            if (i + 1 < lines.length && lines[i + 1].startsWith('data: ')) {
              const dataStr = lines[i + 1].slice(6);
              try {
                const data = JSON.parse(dataStr);

                if (eventType === 'status') {
                  // Update scene video status
                  setGeneratedScenes(prev => prev.map(s => 
                    s.sceneNumber === data.sceneNumber 
                      ? { ...s, videoStatus: data.status as any }
                      : s
                  ));
                  if (data.progress) {
                    setVideoProgress({ current: data.progress.current, total: data.progress.total });
                  }
                } else if (eventType === 'video') {
                  // Update scene with video result (completed or failed)
                  setGeneratedScenes(prev => prev.map(s => 
                    s.sceneNumber === data.sceneNumber 
                      ? { 
                          ...s, 
                          videoStatus: data.status === 'completed' ? 'completed' : 'failed',
                          operationName: data.operationName,
                          videoUrl: data.videoUrl,
                          videoError: data.error,
                        }
                      : s
                  ));
                  if (data.progress) {
                    setVideoProgress({ current: data.progress.current, total: data.progress.total });
                  }
                  console.log(`[Video] Scene ${data.sceneNumber}: ${data.status}${data.videoUrl ? ' - URL received' : ''}`);
                } else if (eventType === 'complete') {
                  console.log(`[Video Complete] ${data.summary?.success}/${data.summary?.total}`);
                } else if (eventType === 'error') {
                  throw new Error(data.error);
                }
              } catch (e) {
                // Ignore parse errors
              }
            }
          }
        }
      }

      const successCount = scenesRef.current.filter(s => s.videoStatus === 'processing').length;
      toast({
        title: "Video Generation Started",
        description: `Started ${successCount}/${scenesWithImages.length} videos. Check History for progress.`,
      });
    } catch (error: any) {
      if (error.name === 'AbortError') {
        toast({ title: "Cancelled", description: "Video generation was cancelled." });
      } else {
        console.error('Video generation error:', error);
        setGeneratedScenes(prev => prev.map(s => 
          s.videoStatus === 'pending' || s.videoStatus === 'uploading' || s.videoStatus === 'generating'
            ? { ...s, videoStatus: 'failed' as const, videoError: error.message }
            : s
        ));
        toast({
          variant: "destructive",
          title: "Video Generation Failed",
          description: error.message || "Failed to generate videos.",
        });
      }
    } finally {
      setIsGeneratingVideos(false);
      setVideoAbortController(null);
    }
  };

  // Stop video generation
  const handleStopVideoGeneration = () => {
    if (videoAbortController) {
      videoAbortController.abort();
    }
  };

  // Download all completed videos as ZIP
  const handleDownloadAllVideosAsZip = async () => {
    const completedVideos = generatedScenes.filter(s => s.videoStatus === 'completed' && s.videoUrl);
    
    if (completedVideos.length === 0) {
      toast({ variant: "destructive", title: "No Videos", description: "No completed videos to download." });
      return;
    }

    setIsDownloadingVideosZip(true);
    
    try {
      const zip = new JSZip();
      let downloadedCount = 0;
      const failedScenes: number[] = [];
      
      // Download videos in sequence order
      for (const scene of completedVideos) {
        try {
          const response = await fetch(scene.videoUrl!);
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }
          const blob = await response.blob();
          zip.file(`Scene_${scene.sceneNumber}.mp4`, blob);
          downloadedCount++;
          console.log(`[Video ZIP] Added Scene ${scene.sceneNumber}`);
        } catch (err) {
          console.error(`Failed to download video for scene ${scene.sceneNumber}:`, err);
          failedScenes.push(scene.sceneNumber);
        }
      }
      
      if (downloadedCount === 0) {
        toast({ variant: "destructive", title: "Download Failed", description: "Could not download any videos." });
        return;
      }
      
      const zipBlob = await zip.generateAsync({ type: 'blob' });
      saveAs(zipBlob, `script-to-frames-videos-${Date.now()}.zip`);
      
      if (failedScenes.length > 0) {
        toast({ 
          title: "Partial Download", 
          description: `Downloaded ${downloadedCount}/${completedVideos.length} videos. Failed: Scene ${failedScenes.join(', ')}`,
          variant: "destructive"
        });
      } else {
        toast({ 
          title: "Download Complete", 
          description: `Downloaded ${downloadedCount} videos as ZIP.` 
        });
      }
    } catch (error: any) {
      console.error('Failed to create videos zip:', error);
      toast({ title: "Download Failed", description: "Failed to create ZIP file.", variant: "destructive" });
    } finally {
      setIsDownloadingVideosZip(false);
    }
  };

  // Download all video URLs as text file (one URL per line)
  const handleDownloadVideoLinks = () => {
    const completedVideos = generatedScenes
      .filter(s => s.videoStatus === 'completed' && s.videoUrl)
      .sort((a, b) => a.sceneNumber - b.sceneNumber);
    
    if (completedVideos.length === 0) {
      toast({ variant: "destructive", title: "No Videos", description: "No completed videos to download." });
      return;
    }
    
    // Create text content with one URL per line
    const linksContent = completedVideos
      .map(scene => scene.videoUrl)
      .join('\n');
    
    // Create and download the text file
    const blob = new Blob([linksContent], { type: 'text/plain' });
    saveAs(blob, `video-links-${Date.now()}.txt`);
    
    toast({ 
      title: "Links Downloaded", 
      description: `${completedVideos.length} video URLs saved to text file.` 
    });
  };

  // Compute counts from current state
  const successCount = generatedScenes.filter(s => s.imageStatus === 'success').length;
  const failedCount = generatedScenes.filter(s => s.imageStatus === 'failed').length;
  const generatingCount = generatedScenes.filter(s => s.imageStatus === 'generating').length;
  const pendingCount = generatedScenes.filter(s => s.imageStatus === 'pending').length;

  if (isLoadingSession) {
    return (
      <UserPanelLayout>
        <div className="flex justify-center items-center min-h-[60vh]">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </UserPanelLayout>
    );
  }

  if (!isAdmin) {
    return (
      <UserPanelLayout>
        <div className="flex justify-center items-center min-h-[60vh]">
          <Alert variant="destructive" className="max-w-md">
            <ShieldAlert className="h-4 w-4" />
            <AlertDescription>
              <span className="font-semibold block mb-1">Access Denied</span>
              This tool is only available to administrators.
            </AlertDescription>
          </Alert>
        </div>
      </UserPanelLayout>
    );
  }

  return (
    <UserPanelLayout>
      <div className="relative min-h-screen">
        <AnimatedDotsBackground />
        
        <div className="relative z-10 max-w-6xl mx-auto space-y-6">
          <Card className="bg-white/95 dark:bg-gray-900/95 backdrop-blur-sm">
            <CardHeader>
              <div className="flex items-center gap-4 flex-wrap">
                <div className="w-12 h-12 rounded-lg flex items-center justify-center bg-gradient-to-br from-gray-700 to-gray-900">
                  <FileText className="h-6 w-6 text-white" />
                </div>
                <div className="flex-1">
                  <CardTitle className="text-xl text-gray-900 dark:text-gray-100">Script to Frames</CardTitle>
                  <CardDescription>Convert your script into images with seamless scene transitions</CardDescription>
                </div>
                <Badge variant="secondary" className="ml-auto">Admin Only</Badge>
              </div>
            </CardHeader>
            
            <CardContent className="space-y-6">
              <Alert>
                <Info className="h-4 w-4" />
                <AlertDescription>
                  This tool converts your script into scene images. Each scene generates an END frame that becomes the next scene's START frame, creating seamless video transitions.
                </AlertDescription>
              </Alert>

              {/* Character Description Section */}
              <Collapsible>
                <div className="flex items-center justify-between gap-4 p-4 bg-muted/30 rounded-lg">
                  <div className="flex items-center gap-3">
                    <User className="h-5 w-5 text-muted-foreground" />
                    <div>
                      <p className="font-medium text-sm">Character Reference (Optional)</p>
                      <p className="text-xs text-muted-foreground">Generate a consistent character to appear in all scenes</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Switch
                      checked={useCharacterReference}
                      onCheckedChange={setUseCharacterReference}
                      data-testid="switch-character-reference"
                    />
                    <CollapsibleTrigger asChild>
                      <Button variant="ghost" size="sm" data-testid="button-expand-character">
                        {useCharacterReference ? "Configure" : "Expand"}
                      </Button>
                    </CollapsibleTrigger>
                  </div>
                </div>
                
                <CollapsibleContent className="pt-4">
                  <div className="space-y-4 p-4 border rounded-lg">
                    <div className="space-y-2">
                      <Label htmlFor="character-description">Character Description</Label>
                      <Textarea
                        id="character-description"
                        placeholder="Describe your character in detail (e.g., 'A young girl with red hair, wearing a blue dress, green eyes, cheerful expression')..."
                        rows={3}
                        value={characterDescription}
                        onChange={(e) => setCharacterDescription(e.target.value)}
                        className="resize-none"
                        data-testid="input-character-description"
                      />
                    </div>
                    
                    <div className="flex items-start gap-4 flex-wrap">
                      <Button
                        onClick={generateCharacterPortrait}
                        disabled={!characterDescription.trim() || isGeneratingCharacter}
                        variant="outline"
                        data-testid="button-generate-character"
                      >
                        {isGeneratingCharacter ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Generating...
                          </>
                        ) : (
                          <>
                            <ImagePlus className="mr-2 h-4 w-4" />
                            Generate Portrait
                          </>
                        )}
                      </Button>
                      
                      {characterPortraitUrl && (
                        <div className="relative">
                          <img 
                            src={characterPortraitUrl} 
                            alt="Character Portrait" 
                            className="w-24 h-32 object-cover rounded-md border"
                          />
                          <Button
                            size="icon"
                            variant="ghost"
                            className="absolute -top-2 -right-2 h-6 w-6 bg-destructive text-destructive-foreground rounded-full"
                            onClick={() => setCharacterPortraitUrl(null)}
                            data-testid="button-remove-character"
                          >
                            <X className="h-3 w-3" />
                          </Button>
                          <Badge className="absolute -bottom-2 left-1/2 -translate-x-1/2" variant="secondary">
                            Reference
                          </Badge>
                        </div>
                      )}
                    </div>
                    
                    {useCharacterReference && !characterPortraitUrl && (
                      <Alert>
                        <Info className="h-4 w-4" />
                        <AlertDescription>
                          Generate a character portrait first. This image will be used as a reference for all scene images to maintain character consistency.
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </CollapsibleContent>
              </Collapsible>

              {/* Script Input Section */}
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="script">Your Script</Label>
                  <Textarea
                    id="script"
                    placeholder="Enter your story script here. The AI will break it down into visual scenes..."
                    rows={8}
                    value={script}
                    onChange={(e) => setScript(e.target.value)}
                    className="resize-none"
                    data-testid="input-script"
                  />
                </div>

                <div className="flex flex-col md:flex-row gap-4 flex-wrap">
                  <div className="space-y-2 w-full md:w-40">
                    <Label htmlFor="scenes">Number of Scenes</Label>
                    <Select value={numberOfScenes} onValueChange={setNumberOfScenes}>
                      <SelectTrigger id="scenes" data-testid="select-scenes">
                        <SelectValue placeholder="Select scenes" />
                      </SelectTrigger>
                      <SelectContent>
                        {[...Array(20)].map((_, i) => (
                          <SelectItem key={i + 1} value={String(i + 1)} data-testid={`option-scenes-${i + 1}`}>
                            {i + 1} {i === 0 ? 'Scene' : 'Scenes'}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2 w-full md:w-56">
                    <Label htmlFor="style">Art Style</Label>
                    <Select value={style} onValueChange={setStyle}>
                      <SelectTrigger id="style" data-testid="select-style">
                        <SelectValue placeholder="Select style" />
                      </SelectTrigger>
                      <SelectContent>
                        {styleOptions.map((option) => (
                          <SelectItem key={option.value} value={option.value} data-testid={`option-style-${option.value}`}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2 w-full md:w-48">
                    <Label htmlFor="aspect">Image Aspect Ratio</Label>
                    <Select value={aspectRatio} onValueChange={setAspectRatio}>
                      <SelectTrigger id="aspect" data-testid="select-aspect">
                        <SelectValue placeholder="Select ratio" />
                      </SelectTrigger>
                      <SelectContent>
                        {aspectRatioOptions.map((option) => (
                          <SelectItem key={option.value} value={option.value} data-testid={`option-aspect-${option.value}`}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="flex items-end">
                    <Button
                      onClick={() => generatePromptsMutation.mutate()}
                      disabled={!script.trim() || generatePromptsMutation.isPending}
                      className="bg-gradient-to-r from-gray-700 to-gray-900"
                      data-testid="button-generate-prompts"
                    >
                      {generatePromptsMutation.isPending ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Sparkles className="mr-2 h-4 w-4" />
                          Generate Prompts
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </div>

              {/* Generated Scenes Section */}
              {generatedScenes.length > 0 && (
                <>
                  <Separator className="my-6" />

                  {/* Action Bar */}
                  <div className="flex flex-wrap justify-between items-center gap-3 mb-4">
                    <div className="flex items-center gap-3 flex-wrap">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                        Generated Scenes ({generatedScenes.length})
                      </h3>
                      {successCount > 0 && (
                        <Badge variant="default" className="bg-green-600">{successCount} Generated</Badge>
                      )}
                      {failedCount > 0 && (
                        <Badge variant="destructive">{failedCount} Failed</Badge>
                      )}
                      {generatingCount > 0 && (
                        <Badge variant="secondary">{generatingCount} Generating</Badge>
                      )}
                    </div>
                    
                    <div className="flex gap-2 flex-wrap items-center">
                      {/* Alignment Toggle */}
                      <div className="flex items-center gap-2 px-2 py-1 bg-muted/50 rounded-md">
                        <Switch
                          checked={showAlignment}
                          onCheckedChange={setShowAlignment}
                          data-testid="switch-show-alignment"
                        />
                        <span className="text-xs text-muted-foreground">
                          {showAlignment ? <Link2 className="h-3 w-3 inline mr-1" /> : <Unlink className="h-3 w-3 inline mr-1" />}
                          Alignment
                        </span>
                      </div>
                      
                      {/* Align All Button */}
                      {successCount >= 2 && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={handleAlignAllScenes}
                          data-testid="button-align-all"
                        >
                          <Link2 className="mr-2 h-4 w-4" />
                          Align All
                        </Button>
                      )}
                      
                      <Button variant="outline" size="sm" onClick={handleCopyAllPrompts} data-testid="button-copy-all">
                        <Copy className="mr-2 h-4 w-4" />
                        Copy All
                      </Button>
                      
                      {!isGeneratingImages && (pendingCount > 0 || failedCount > 0) && (
                        <Button
                          size="sm"
                          onClick={handleGenerateAllImages}
                          className="bg-gradient-to-r from-blue-600 to-blue-800"
                          data-testid="button-generate-all-images"
                        >
                          <Image className="mr-2 h-4 w-4" />
                          Generate All Images
                        </Button>
                      )}
                      
                      {failedCount > 0 && !isGeneratingImages && (
                        <Button size="sm" variant="outline" onClick={handleRetryFailed} data-testid="button-retry-failed">
                          <RefreshCw className="mr-2 h-4 w-4" />
                          Retry Failed ({failedCount})
                        </Button>
                      )}
                      
                      {successCount > 0 && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={handleDownloadAllAsZip}
                          disabled={isDownloadingZip}
                          data-testid="button-download-zip"
                        >
                          {isDownloadingZip ? (
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          ) : (
                            <Archive className="mr-2 h-4 w-4" />
                          )}
                          Download ZIP
                        </Button>
                      )}
                      
                      {/* Generate All Videos Button */}
                      {successCount >= 2 && !isGeneratingVideos && (
                        <Button
                          size="sm"
                          onClick={handleGenerateAllVideos}
                          className="bg-gradient-to-r from-purple-600 to-purple-800"
                          data-testid="button-generate-all-videos"
                        >
                          <Film className="mr-2 h-4 w-4" />
                          Generate All Videos
                        </Button>
                      )}
                      
                      {isGeneratingVideos && (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={handleStopVideoGeneration}
                          data-testid="button-stop-video-generation"
                        >
                          <X className="mr-2 h-4 w-4" />
                          Stop Videos
                        </Button>
                      )}
                      
                      {/* Download All Videos as ZIP */}
                      {generatedScenes.filter(s => s.videoStatus === 'completed' && s.videoUrl).length > 0 && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={handleDownloadAllVideosAsZip}
                          disabled={isDownloadingVideosZip}
                          className="bg-gradient-to-r from-green-600 to-green-800 text-white border-0"
                          data-testid="button-download-all-videos"
                        >
                          {isDownloadingVideosZip ? (
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          ) : (
                            <Archive className="mr-2 h-4 w-4" />
                          )}
                          Download All Videos
                        </Button>
                      )}
                      
                      {/* Download Video Links as Text File */}
                      {generatedScenes.filter(s => s.videoStatus === 'completed' && s.videoUrl).length > 0 && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={handleDownloadVideoLinks}
                          className="bg-gradient-to-r from-blue-600 to-blue-800 text-white border-0"
                          data-testid="button-download-video-links"
                        >
                          <Link2 className="mr-2 h-4 w-4" />
                          Download Links
                        </Button>
                      )}
                    </div>
                  </div>

                  {/* Image Progress Bar */}
                  {isGeneratingImages && (
                    <div className="space-y-2 mb-4">
                      <div className="flex justify-between text-sm text-muted-foreground">
                        <span>Generating images...</span>
                        <span>{imageProgress.current}/{imageProgress.total}</span>
                      </div>
                      <Progress value={(imageProgress.current / Math.max(imageProgress.total, 1)) * 100} />
                    </div>
                  )}
                  
                  {/* Video Progress Bar */}
                  {isGeneratingVideos && (
                    <div className="space-y-2 mb-4">
                      <div className="flex justify-between text-sm text-muted-foreground">
                        <span>Starting video generation...</span>
                        <span>{videoProgress.current}/{videoProgress.total}</span>
                      </div>
                      <Progress value={(videoProgress.current / Math.max(videoProgress.total, 1)) * 100} />
                    </div>
                  )}

                  {/* Scenes Grid - Simple layout like Batch Gen */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {generatedScenes.map((scene, index) => (
                      <Card key={scene.sceneNumber} className="overflow-visible" data-testid={`card-scene-${scene.sceneNumber}`}>
                        <CardContent className="pt-4 space-y-3">
                          {/* Scene Header */}
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge variant="secondary">Scene {scene.sceneNumber}</Badge>
                            
                            {scene.imageStatus === 'generating' && (
                              <Badge variant="outline" className="animate-pulse">
                                <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                Generating
                              </Badge>
                            )}
                            {scene.imageStatus === 'success' && (
                              <Badge className="bg-green-600">
                                <Check className="mr-1 h-3 w-3" />
                                Done
                              </Badge>
                            )}
                            {scene.imageStatus === 'failed' && (
                              <Badge variant="destructive">Failed</Badge>
                            )}
                            
                            <Button
                              size="icon"
                              variant="ghost"
                              onClick={() => handleCopyPrompt(scene.prompt, index)}
                              className={`ml-auto ${copiedIndex === index ? "text-green-600" : ""}`}
                              data-testid={`button-copy-${scene.sceneNumber}`}
                            >
                              {copiedIndex === index ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                            </Button>
                          </div>

                          {/* Prompt */}
                          <div className="p-2 bg-muted/50 rounded-md">
                            <p className="text-xs text-muted-foreground line-clamp-3">{scene.prompt}</p>
                          </div>

                          {/* Generated Image - with Alignment View (ALL scenes including Scene 1) */}
                          {showAlignment ? (
                            <div className="space-y-2">
                              {/* Start/End Frame Labels */}
                              <div className="flex gap-2">
                                {/* Start Frame */}
                                <div className="flex-1">
                                  <div className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                                    <ArrowRight className="h-3 w-3" />
                                    Start Frame
                                  </div>
                                  <div className="aspect-video bg-muted/30 rounded-md flex items-center justify-center border border-blue-500/30 overflow-hidden">
                                    {scene.startImageUrl ? (
                                      <img 
                                        src={scene.startImageUrl} 
                                        alt={`Scene ${scene.sceneNumber} Start`} 
                                        className="w-full h-full object-cover"
                                      />
                                    ) : index === 0 ? (
                                      <div className="flex flex-col items-center gap-1 p-1">
                                        <Sparkles className="h-4 w-4 text-muted-foreground/50" />
                                        <span className="text-[10px] text-muted-foreground text-center">Opening Frame</span>
                                      </div>
                                    ) : (
                                      <div className="flex flex-col items-center gap-1 p-1">
                                        <Link2 className="h-4 w-4 text-muted-foreground/50" />
                                        <span className="text-[10px] text-muted-foreground text-center">From Scene {scene.sceneNumber - 1}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                                
                                {/* End Frame (this scene's generated image) */}
                                <div className="flex-1">
                                  <div className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                                    <Film className="h-3 w-3" />
                                    End Frame
                                  </div>
                                  <div className="aspect-video bg-muted/30 rounded-md flex items-center justify-center border border-green-500/30 overflow-hidden">
                                    {scene.imageStatus === 'generating' ? (
                                      <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                                    ) : scene.imageStatus === 'success' && scene.endImageUrl ? (
                                      <img 
                                        src={scene.endImageUrl} 
                                        alt={`Scene ${scene.sceneNumber} End`} 
                                        className="w-full h-full object-cover"
                                      />
                                    ) : scene.imageStatus === 'failed' ? (
                                      <X className="h-5 w-5 text-destructive" />
                                    ) : (
                                      <Image className="h-5 w-5 text-muted-foreground/50" />
                                    )}
                                  </div>
                                </div>
                              </div>
                            </div>
                          ) : (
                            <div className="aspect-video bg-muted/30 rounded-md flex items-center justify-center border border-muted-foreground/20 overflow-hidden">
                              {scene.imageStatus === 'generating' ? (
                                <div className="flex flex-col items-center gap-2">
                                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                                  <span className="text-xs text-muted-foreground">Generating...</span>
                                </div>
                              ) : scene.imageStatus === 'success' && scene.endImageUrl ? (
                                <img 
                                  src={scene.endImageUrl} 
                                  alt={`Scene ${scene.sceneNumber}`} 
                                  className="w-full h-full object-cover"
                                />
                              ) : scene.imageStatus === 'failed' ? (
                                <div className="flex flex-col items-center gap-2 p-2">
                                  <X className="h-6 w-6 text-destructive" />
                                  <span className="text-xs text-destructive text-center">{scene.error || 'Failed'}</span>
                                </div>
                              ) : (
                                <div className="flex flex-col items-center gap-2">
                                  <Image className="h-8 w-8 text-muted-foreground/50" />
                                  <span className="text-xs text-muted-foreground">Click "Generate All Images"</span>
                                </div>
                              )}
                            </div>
                          )}
                          
                          {/* Video Section */}
                          {scene.videoStatus && (
                            <div className="mt-3 pt-3 border-t">
                              <div className="flex items-center gap-2 mb-2">
                                <Film className="h-4 w-4 text-muted-foreground" />
                                <span className="text-xs font-medium">Video</span>
                                {scene.videoStatus === 'pending' && (
                                  <Badge variant="outline" className="text-xs">Pending</Badge>
                                )}
                                {scene.videoStatus === 'uploading' && (
                                  <Badge variant="outline" className="text-xs animate-pulse">
                                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                    Uploading
                                  </Badge>
                                )}
                                {scene.videoStatus === 'generating' && (
                                  <Badge variant="outline" className="text-xs animate-pulse">
                                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                    Starting
                                  </Badge>
                                )}
                                {scene.videoStatus === 'processing' && (
                                  <Badge variant="secondary" className="text-xs animate-pulse">
                                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                    Processing (~2 min)
                                  </Badge>
                                )}
                                {scene.videoStatus === 'completed' && (
                                  <Badge className="bg-green-600 text-xs">
                                    <Check className="mr-1 h-3 w-3" />
                                    Ready
                                  </Badge>
                                )}
                                {scene.videoStatus === 'failed' && (
                                  <Badge variant="destructive" className="text-xs">Failed</Badge>
                                )}
                              </div>
                              
                              {/* Video Player */}
                              {scene.videoStatus === 'completed' && scene.videoUrl && (
                                <div className="aspect-video bg-black rounded-md overflow-hidden">
                                  <video 
                                    src={scene.videoUrl} 
                                    controls 
                                    className="w-full h-full"
                                    data-testid={`video-scene-${scene.sceneNumber}`}
                                  />
                                </div>
                              )}
                              
                              {/* Processing indicator */}
                              {(scene.videoStatus === 'processing' || scene.videoStatus === 'generating' || scene.videoStatus === 'uploading') && (
                                <div className="aspect-video bg-muted/30 rounded-md flex flex-col items-center justify-center gap-2">
                                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                                  <span className="text-xs text-muted-foreground">
                                    {scene.videoStatus === 'uploading' ? 'Uploading images...' : 
                                     scene.videoStatus === 'generating' ? 'Starting generation...' : 
                                     'Video processing (1-2 minutes)...'}
                                  </span>
                                </div>
                              )}
                              
                              {/* Error message */}
                              {scene.videoStatus === 'failed' && scene.videoError && (
                                <div className="text-xs text-destructive bg-destructive/10 p-2 rounded-md">
                                  {scene.videoError}
                                </div>
                              )}
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </div>

                  {/* Success Message */}
                  {successCount === generatedScenes.length && generatedScenes.length > 0 && (
                    <Alert className="mt-6 bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800">
                      <Check className="h-4 w-4 text-green-600" />
                      <AlertDescription className="text-green-800 dark:text-green-200">
                        All scene frames have been generated! Download the ZIP to get all images, or use them in the VEO Generator for video creation.
                        <ul className="list-disc ml-5 mt-2">
                          <li>Each scene's END frame becomes the next scene's START frame</li>
                          <li>Use the video prompts in VEO Generator with start/end image references</li>
                        </ul>
                      </AlertDescription>
                    </Alert>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </UserPanelLayout>
  );
}
