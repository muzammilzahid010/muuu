import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Activity, Cpu, HardDrive, Wifi, Zap, RefreshCw, AlertCircle, Video } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, Area, AreaChart } from 'recharts';

interface GPUInfo {
  index: number;
  name: string;
  utilization: number;
  memoryTotal: number;
  memoryUsed: number;
  memoryFree: number;
  memoryPercent: number;
  temperature: number;
  powerDraw: number;
  processes: Array<{
    pid: string;
    name: string;
    memory: string;
  }>;
}

interface SystemMetrics {
  timestamp: string;
  cpu: {
    usage: number;
    cores: Array<{ core: number; usage: number }>;
    temperature: number | null;
    speed: number;
  };
  memory: {
    total: number;
    used: number;
    free: number;
    usagePercent: number;
  };
  disk: {
    total: number;
    used: number;
    free: number;
    usagePercent: number;
  };
  network: {
    rx_sec: number;
    tx_sec: number;
  };
  processes: Array<{
    pid: number;
    name: string;
    cpu: number;
    mem: number;
  }>;
  gpu: GPUInfo[] | null;
  hasGPU: boolean;
  localVideoStorage: {
    totalVideos: number;
    totalSizeMB: number;
    oldestVideoAge: string | null;
  } | null;
}

interface HistoricalDataPoint {
  time: string;
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  networkRx: number;
  networkTx: number;
  gpuUsage?: number;
  gpuMemory?: number;
  gpuTemp?: number;
}

const MAX_HISTORY_POINTS = 60; // Keep last 60 data points (3 minutes at 3-second intervals)

export function SystemMonitor() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [history, setHistory] = useState<HistoricalDataPoint[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [usePolling, setUsePolling] = useState(false);
  const { toast } = useToast();

  // Update history with metrics data
  const updateHistory = (data: SystemMetrics) => {
    const timeStr = new Date(data.timestamp).toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
    
    const dataPoint: HistoricalDataPoint = {
      time: timeStr,
      cpuUsage: data.cpu.usage,
      memoryUsage: data.memory.usagePercent,
      diskUsage: data.disk.usagePercent,
      networkRx: data.network.rx_sec,
      networkTx: data.network.tx_sec,
    };
    
    // Add GPU data if available
    if (data.hasGPU && data.gpu && data.gpu.length > 0) {
      dataPoint.gpuUsage = data.gpu[0].utilization;
      dataPoint.gpuMemory = data.gpu[0].memoryPercent;
      dataPoint.gpuTemp = data.gpu[0].temperature;
    }
    
    setHistory(prev => {
      const newHistory = [...prev, dataPoint];
      if (newHistory.length > MAX_HISTORY_POINTS) {
        return newHistory.slice(-MAX_HISTORY_POINTS);
      }
      return newHistory;
    });
  };

  // Polling fallback
  useEffect(() => {
    if (!usePolling) return;
    
    let pollInterval: NodeJS.Timeout;
    
    const fetchMetrics = async () => {
      try {
        const response = await fetch('/api/admin/system-metrics', {
          credentials: 'include'
        });
        if (response.ok) {
          const data = await response.json();
          setMetrics(data);
          updateHistory(data);
          setIsConnected(true);
          setError(null);
        }
      } catch (err) {
        console.error('Polling error:', err);
        setIsConnected(false);
      }
    };
    
    fetchMetrics();
    pollInterval = setInterval(fetchMetrics, 3000);
    
    return () => clearInterval(pollInterval);
  }, [usePolling]);

  // SSE connection
  useEffect(() => {
    if (usePolling) return;
    
    let eventSource: EventSource | null = null;
    let reconnectTimeout: NodeJS.Timeout;
    let sseFailCount = 0;

    const connect = () => {
      try {
        eventSource = new EventSource('/api/admin/system-metrics/stream', {
          withCredentials: true,
        });

        eventSource.onopen = () => {
          setIsConnected(true);
          setError(null);
          sseFailCount = 0;
          console.log('Connected to system metrics stream');
        };

        eventSource.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            setMetrics(data);
            updateHistory(data);
          } catch (err) {
            console.error('Error parsing metrics:', err);
          }
        };

        eventSource.onerror = (err) => {
          console.error('EventSource error:', err);
          setIsConnected(false);
          eventSource?.close();
          sseFailCount++;
          
          // After 3 SSE failures, switch to polling
          if (sseFailCount >= 3) {
            console.log('SSE failed 3 times, switching to polling mode');
            setUsePolling(true);
            setError(null);
            return;
          }
          
          setError('Connection lost. Reconnecting...');
          reconnectTimeout = setTimeout(() => {
            connect();
          }, 3000);
        };
      } catch (err) {
        console.error('Error creating EventSource:', err);
        setError('Failed to connect, using polling...');
        setUsePolling(true);
      }
    };

    connect();

    return () => {
      if (eventSource) {
        eventSource.close();
      }
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
    };
  }, [usePolling]);

  const getUsageColor = (percentage: number) => {
    if (percentage >= 90) return 'bg-red-500';
    if (percentage >= 70) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const getChartColor = (percentage: number) => {
    if (percentage >= 90) return '#ef4444';
    if (percentage >= 70) return '#eab308';
    return '#22c55e';
  };

  if (!metrics) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-purple-400 animate-spin mx-auto mb-4" />
          <p className="text-white text-lg">Loading system metrics...</p>
          <p className="text-gray-400 text-sm mt-2">Connecting to monitoring stream</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} data-testid="indicator-connection-status" />
          <span className="text-white text-sm">
            {isConnected ? 'Live Monitoring' : 'Disconnected'}
          </span>
          {metrics && (
            <span className="text-gray-400 text-xs">
              Updated: {new Date(metrics.timestamp).toLocaleTimeString()}
            </span>
          )}
        </div>
        {error && (
          <div className="flex items-center gap-2 text-yellow-400">
            <AlertCircle className="w-4 h-4" />
            <span className="text-sm">{error}</span>
          </div>
        )}
      </div>

      {/* Performance Charts */}
      {history.length > 1 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* CPU & Memory Chart */}
          <Card className="shadow-xl bg-[#1e2838] dark:bg-[#181e2a] border border-white/10">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-blue-400" />
                CPU & Memory Usage
              </CardTitle>
              <CardDescription className="text-gray-300">Real-time performance trends</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={history}>
                  <defs>
                    <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1}/>
                    </linearGradient>
                    <linearGradient id="colorMemory" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22c55e" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#22c55e" stopOpacity={0.1}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis 
                    dataKey="time" 
                    stroke="#9ca3af" 
                    tick={{ fontSize: 12 }}
                    interval="preserveStartEnd"
                  />
                  <YAxis stroke="#9ca3af" tick={{ fontSize: 12 }} domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#1f2937', 
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#fff'
                    }}
                    formatter={(value: number) => `${value.toFixed(1)}%`}
                  />
                  <Legend />
                  <Area 
                    type="monotone" 
                    dataKey="cpuUsage" 
                    stroke="#3b82f6" 
                    fillOpacity={1}
                    fill="url(#colorCpu)"
                    name="CPU %" 
                  />
                  <Area 
                    type="monotone" 
                    dataKey="memoryUsage" 
                    stroke="#22c55e" 
                    fillOpacity={1}
                    fill="url(#colorMemory)"
                    name="RAM %" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Network Chart */}
          <Card className="shadow-xl bg-[#1e2838] dark:bg-[#181e2a] border border-white/10">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Wifi className="w-5 h-5 text-cyan-400" />
                Network Traffic
              </CardTitle>
              <CardDescription className="text-gray-300">Download & Upload rates</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={history}>
                  <defs>
                    <linearGradient id="colorRx" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.1}/>
                    </linearGradient>
                    <linearGradient id="colorTx" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.1}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis 
                    dataKey="time" 
                    stroke="#9ca3af" 
                    tick={{ fontSize: 12 }}
                    interval="preserveStartEnd"
                  />
                  <YAxis stroke="#9ca3af" tick={{ fontSize: 12 }} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#1f2937', 
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#fff'
                    }}
                    formatter={(value: number) => `${value.toFixed(2)} KB/s`}
                  />
                  <Legend />
                  <Area 
                    type="monotone" 
                    dataKey="networkRx" 
                    stroke="#06b6d4" 
                    fillOpacity={1}
                    fill="url(#colorRx)"
                    name="Download" 
                  />
                  <Area 
                    type="monotone" 
                    dataKey="networkTx" 
                    stroke="#f59e0b" 
                    fillOpacity={1}
                    fill="url(#colorTx)"
                    name="Upload" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* GPU Chart (if available) */}
          {metrics.hasGPU && metrics.gpu && (
            <Card className="shadow-xl bg-[#1e2838] dark:bg-[#181e2a] border border-white/10 lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-400" />
                  GPU Performance
                </CardTitle>
                <CardDescription className="text-gray-300">Utilization, VRAM & Temperature</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={history}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis 
                      dataKey="time" 
                      stroke="#9ca3af" 
                      tick={{ fontSize: 12 }}
                      interval="preserveStartEnd"
                    />
                    <YAxis stroke="#9ca3af" tick={{ fontSize: 12 }} domain={[0, 100]} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: '#fff'
                      }}
                    />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="gpuUsage" 
                      stroke="#eab308" 
                      strokeWidth={2}
                      dot={false}
                      name="GPU Usage %" 
                    />
                    <Line 
                      type="monotone" 
                      dataKey="gpuMemory" 
                      stroke="#a855f7" 
                      strokeWidth={2}
                      dot={false}
                      name="VRAM %" 
                    />
                    <Line 
                      type="monotone" 
                      dataKey="gpuTemp" 
                      stroke="#ef4444" 
                      strokeWidth={2}
                      dot={false}
                      name="Temperature °C" 
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* GPU Cards */}
      {metrics.hasGPU && metrics.gpu && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {metrics.gpu.map((gpu) => (
            <Card key={gpu.index} className="shadow-xl bg-gradient-to-br from-purple-900/30 to-purple-700/20 border border-purple-500/30">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-white flex items-center gap-2">
                      <Zap className="w-5 h-5 text-yellow-400" />
                      GPU {gpu.index}: {gpu.name}
                    </CardTitle>
                    <CardDescription className="text-gray-300 mt-1">
                      {gpu.temperature}°C • {gpu.powerDraw.toFixed(1)}W
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* GPU Utilization */}
                <div>
                  <div className="flex justify-between text-sm mb-2">
                    <span className="text-gray-300">GPU Utilization</span>
                    <span className="text-white font-bold" data-testid={`text-gpu-${gpu.index}-utilization`}>{gpu.utilization.toFixed(1)}%</span>
                  </div>
                  <div className="w-full bg-white/10 rounded-full h-3 overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${getUsageColor(gpu.utilization)}`}
                      style={{ width: `${gpu.utilization}%` }}
                      data-testid={`progress-gpu-${gpu.index}-utilization`}
                    />
                  </div>
                </div>

                {/* Memory */}
                <div>
                  <div className="flex justify-between text-sm mb-2">
                    <span className="text-gray-300">VRAM</span>
                    <span className="text-white font-bold" data-testid={`text-gpu-${gpu.index}-memory`}>
                      {gpu.memoryUsed.toFixed(0)} / {gpu.memoryTotal.toFixed(0)} MB ({gpu.memoryPercent.toFixed(1)}%)
                    </span>
                  </div>
                  <div className="w-full bg-white/10 rounded-full h-3 overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${getUsageColor(gpu.memoryPercent)}`}
                      style={{ width: `${gpu.memoryPercent}%` }}
                      data-testid={`progress-gpu-${gpu.index}-memory`}
                    />
                  </div>
                </div>

                {/* GPU Processes */}
                {gpu.processes.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-white/10">
                    <h4 className="text-sm font-semibold text-white mb-2">Running Processes ({gpu.processes.length})</h4>
                    <div className="space-y-1">
                      {gpu.processes.map((proc, i) => (
                        <div key={i} className="flex justify-between items-center bg-white/5 rounded px-3 py-2">
                          <span className="text-xs text-gray-300 truncate flex-1">{proc.name}</span>
                          <span className="text-xs text-white ml-2">PID: {proc.pid}</span>
                          <span className="text-xs text-purple-400 ml-2">{proc.memory}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* System Resources Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* CPU Card */}
        <Card className="shadow-xl bg-gradient-to-br from-blue-200 to-blue-100 dark:from-blue-900/30 dark:to-blue-700/20 border border-blue-300 dark:border-blue-500/30">
          <CardHeader>
            <CardTitle className="text-blue-900 dark:text-white flex items-center gap-2">
              <Cpu className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              CPU
            </CardTitle>
            <CardDescription className="text-blue-700 dark:text-gray-300">
              {metrics.cpu.speed.toFixed(2)} GHz
              {metrics.cpu.temperature && ` • ${metrics.cpu.temperature.toFixed(1)}°C`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-blue-700 dark:text-gray-300">Overall Usage</span>
                  <span className="text-blue-900 dark:text-white font-bold" data-testid="text-cpu-usage">{metrics.cpu.usage.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-blue-300/50 dark:bg-white/10 rounded-full h-3 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${getUsageColor(metrics.cpu.usage)}`}
                    style={{ width: `${metrics.cpu.usage}%` }}
                    data-testid="progress-cpu-usage"
                  />
                </div>
              </div>
              <div className="text-xs text-blue-600 dark:text-gray-400">
                {metrics.cpu.cores.length} cores
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Memory Card */}
        <Card className="shadow-xl bg-gradient-to-br from-green-200 to-green-100 dark:from-green-900/30 dark:to-green-700/20 border border-green-300 dark:border-green-500/30">
          <CardHeader>
            <CardTitle className="text-green-900 dark:text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-green-600 dark:text-green-400" />
              RAM
            </CardTitle>
            <CardDescription className="text-green-700 dark:text-gray-300">
              {metrics.memory.used.toFixed(2)} / {metrics.memory.total.toFixed(2)} GB
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-green-700 dark:text-gray-300">Usage</span>
                  <span className="text-green-900 dark:text-white font-bold" data-testid="text-memory-usage">{metrics.memory.usagePercent.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-green-300/50 dark:bg-white/10 rounded-full h-3 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${getUsageColor(metrics.memory.usagePercent)}`}
                    style={{ width: `${metrics.memory.usagePercent}%` }}
                    data-testid="progress-memory-usage"
                  />
                </div>
              </div>
              <div className="text-xs text-green-600 dark:text-gray-400">
                Free: {metrics.memory.free.toFixed(2)} GB
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Disk Card */}
        <Card className="shadow-xl bg-gradient-to-br from-orange-200 to-orange-100 dark:from-orange-900/30 dark:to-orange-700/20 border border-orange-300 dark:border-orange-500/30">
          <CardHeader>
            <CardTitle className="text-orange-900 dark:text-white flex items-center gap-2">
              <HardDrive className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              Disk
            </CardTitle>
            <CardDescription className="text-orange-700 dark:text-gray-300">
              {metrics.disk.used.toFixed(2)} / {metrics.disk.total.toFixed(2)} GB
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-orange-700 dark:text-gray-300">Usage</span>
                  <span className="text-orange-900 dark:text-white font-bold" data-testid="text-disk-usage">{metrics.disk.usagePercent.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-orange-300/50 dark:bg-white/10 rounded-full h-3 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${getUsageColor(metrics.disk.usagePercent)}`}
                    style={{ width: `${metrics.disk.usagePercent}%` }}
                    data-testid="progress-disk-usage"
                  />
                </div>
              </div>
              <div className="text-xs text-orange-600 dark:text-gray-400">
                Free: {metrics.disk.free.toFixed(2)} GB
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Network Card */}
        <Card className="shadow-xl bg-gradient-to-br from-cyan-200 to-cyan-100 dark:from-cyan-900/30 dark:to-cyan-700/20 border border-cyan-300 dark:border-cyan-500/30">
          <CardHeader>
            <CardTitle className="text-cyan-900 dark:text-white flex items-center gap-2">
              <Wifi className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
              Network
            </CardTitle>
            <CardDescription className="text-cyan-700 dark:text-gray-300">
              Real-time I/O
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-cyan-700 dark:text-gray-300">Download</span>
                <span className="text-cyan-900 dark:text-white font-bold" data-testid="text-network-rx">{metrics.network.rx_sec.toFixed(2)} KB/s</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-cyan-700 dark:text-gray-300">Upload</span>
                <span className="text-cyan-900 dark:text-white font-bold" data-testid="text-network-tx">{metrics.network.tx_sec.toFixed(2)} KB/s</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Local Video Storage Card */}
      {metrics.localVideoStorage && (
        <Card className="shadow-xl bg-gradient-to-br from-purple-200 to-purple-100 dark:from-purple-900/30 dark:to-purple-700/20 border border-purple-300 dark:border-purple-500/30">
          <CardHeader>
            <CardTitle className="text-purple-900 dark:text-white flex items-center gap-2">
              <Video className="w-5 h-5 text-purple-600 dark:text-purple-400" />
              Local Video Storage
            </CardTitle>
            <CardDescription className="text-purple-700 dark:text-gray-300">
              Temporary videos on disk (3-hour expiry)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-900 dark:text-white" data-testid="text-video-count">
                  {metrics.localVideoStorage.totalVideos}
                </div>
                <div className="text-xs text-purple-600 dark:text-gray-400">Videos</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-900 dark:text-white" data-testid="text-video-size">
                  {metrics.localVideoStorage.totalSizeMB.toFixed(1)}
                </div>
                <div className="text-xs text-purple-600 dark:text-gray-400">MB Used</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-900 dark:text-white" data-testid="text-video-oldest">
                  {metrics.localVideoStorage.oldestVideoAge || '-'}
                </div>
                <div className="text-xs text-purple-600 dark:text-gray-400">Oldest Video</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Top Processes */}
      <Card className="shadow-xl bg-[#1e2838] dark:bg-[#181e2a] border border-white/10">
        <CardHeader>
          <CardTitle className="text-white">Top Processes by CPU</CardTitle>
          <CardDescription className="text-gray-300">
            Showing top 10 CPU-intensive processes
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-gray-400 font-medium py-3 px-4">PID</th>
                  <th className="text-left text-gray-400 font-medium py-3 px-4">Process Name</th>
                  <th className="text-right text-gray-400 font-medium py-3 px-4">CPU %</th>
                  <th className="text-right text-gray-400 font-medium py-3 px-4">Memory %</th>
                </tr>
              </thead>
              <tbody>
                {metrics.processes.map((proc, index) => (
                  <tr key={proc.pid} className="border-b border-white/5 hover:bg-white/5" data-testid={`row-process-${index}`}>
                    <td className="text-gray-300 py-3 px-4">{proc.pid}</td>
                    <td className="text-white py-3 px-4 font-mono truncate max-w-xs">{proc.name}</td>
                    <td className="text-right text-white py-3 px-4">{proc.cpu.toFixed(2)}%</td>
                    <td className="text-right text-white py-3 px-4">{proc.mem.toFixed(2)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
