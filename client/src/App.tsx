import { useState, useEffect } from "react";
import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { WhatsAppButton } from "@/components/WhatsAppButton";
import LoadingScreen from "@/components/LoadingScreen";
import ThemeProvider from "@/theme/ThemeProvider";
import Home from "@/pages/Home";
import Login from "@/pages/Login";
import Signup from "@/pages/Signup";
import Admin from "@/pages/Admin";
import Pricing from "@/pages/Pricing";
import VeoGenerator from "@/pages/VeoGenerator";
import BulkGenerator from "@/pages/BulkGenerator";
import ScriptCreator from "@/pages/ScriptCreator";
import History from "@/pages/History";
import TextToImage from "@/pages/TextToImage";
import ImageToVideo from "@/pages/ImageToVideo";
import CharacterConsistent from "@/pages/CharacterConsistent";
import ResellerPortal from "@/pages/ResellerPortal";
import ScriptToFrames from "@/pages/ScriptToFrames";
import AdminVoiceCloning from "@/pages/AdminVoiceCloning";
import AdminTextToSpeech from "@/pages/AdminTextToSpeech";
import AdminTopVoices from "@/pages/AdminTopVoices";
import TopVoices from "@/pages/TopVoices";
import CommunityVoices from "@/pages/CommunityVoices";
import NotFound from "@/pages/not-found";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/login" component={Login} />
      <Route path="/signup" component={Signup} />
      <Route path="/admin" component={Admin} />
      <Route path="/pricing" component={Pricing} />
      <Route path="/veo-generator" component={VeoGenerator} />
      <Route path="/bulk-generator" component={BulkGenerator} />
      <Route path="/script-creator" component={ScriptCreator} />
      <Route path="/history" component={History} />
      <Route path="/text-to-image" component={TextToImage} />
      <Route path="/image-to-video" component={ImageToVideo} />
      <Route path="/character-consistent" component={CharacterConsistent} />
      <Route path="/reseller" component={ResellerPortal} />
      <Route path="/script-to-frames" component={ScriptToFrames} />
      <Route path="/voice-cloning" component={AdminVoiceCloning} />
      <Route path="/text-to-speech" component={AdminTextToSpeech} />
      <Route path="/admin/voice-cloning" component={AdminVoiceCloning} />
      <Route path="/admin/text-to-speech" component={AdminTextToSpeech} />
      <Route path="/admin/top-voices" component={AdminTopVoices} />
      <Route path="/top-voices" component={TopVoices} />
      <Route path="/community-voices" component={CommunityVoices} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 2000);

    return () => clearTimeout(timer);
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <LoadingScreen isLoading={isLoading} />
          <div style={{ opacity: isLoading ? 0 : 1, transition: 'opacity 0.5s ease-in-out' }}>
            <Toaster />
            <Router />
            <WhatsAppButton />
          </div>
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
