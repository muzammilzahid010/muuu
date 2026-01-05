import { exec } from 'child_process';
import { promisify } from 'util';
import si from 'systeminformation';

const execAsync = promisify(exec);

export interface GPUInfo {
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

export interface SystemMetrics {
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

/**
 * Get GPU information using nvidia-smi
 */
async function getGPUInfo(): Promise<GPUInfo[] | null> {
  try {
    const { stdout } = await execAsync(
      'nvidia-smi --query-gpu=index,name,utilization.gpu,memory.total,memory.used,memory.free,temperature.gpu,power.draw --format=csv,noheader,nounits'
    );

    const lines = stdout.trim().split('\n');
    const gpus: GPUInfo[] = [];

    for (const line of lines) {
      const [index, name, util, memTotal, memUsed, memFree, temp, power] = line.split(', ');
      
      // Get GPU processes
      let processes: Array<{ pid: string; name: string; memory: string }> = [];
      try {
        const { stdout: procStdout } = await execAsync(
          `nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv,noheader,nounits --id=${index}`
        );
        
        if (procStdout.trim()) {
          const procLines = procStdout.trim().split('\n');
          processes = procLines.map(procLine => {
            const [pid, procName, mem] = procLine.split(', ');
            return { pid, name: procName, memory: mem + ' MB' };
          });
        }
      } catch (procError) {
        // No processes running on this GPU
        console.log(`No GPU processes for GPU ${index}`);
      }

      gpus.push({
        index: parseInt(index),
        name,
        utilization: parseFloat(util),
        memoryTotal: parseFloat(memTotal),
        memoryUsed: parseFloat(memUsed),
        memoryFree: parseFloat(memFree),
        memoryPercent: (parseFloat(memUsed) / parseFloat(memTotal)) * 100,
        temperature: parseFloat(temp),
        powerDraw: parseFloat(power),
        processes,
      });
    }

    return gpus;
  } catch (error) {
    // NVIDIA GPU not available or nvidia-smi not installed
    return null;
  }
}

/**
 * Get comprehensive system metrics
 */
async function getLocalVideoStorageStats(): Promise<{ totalVideos: number; totalSizeMB: number; oldestVideoAge: string | null } | null> {
  try {
    const { getStorageStats } = await import('./localDiskStorage');
    const stats = await getStorageStats();
    
    let oldestVideoAge: string | null = null;
    if (stats.oldestVideo) {
      const ageMs = Date.now() - stats.oldestVideo.getTime();
      const ageMinutes = Math.floor(ageMs / 60000);
      if (ageMinutes < 60) {
        oldestVideoAge = `${ageMinutes}m`;
      } else {
        const hours = Math.floor(ageMinutes / 60);
        const mins = ageMinutes % 60;
        oldestVideoAge = `${hours}h ${mins}m`;
      }
    }
    
    return {
      totalVideos: stats.totalVideos,
      totalSizeMB: stats.totalSizeMB,
      oldestVideoAge
    };
  } catch (error) {
    return null;
  }
}

export async function getSystemMetrics(): Promise<SystemMetrics> {
  try {
    const [cpuLoad, mem, diskLayout, networkStats, processes, cpuTemp, cpuSpeed, gpuInfo, localVideoStorage] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize(),
      si.networkStats(),
      si.processes(),
      si.cpuTemperature(),
      si.cpu(),
      getGPUInfo(),
      getLocalVideoStorageStats(),
    ]);

    // Calculate CPU usage
    const cpuUsage = cpuLoad.currentLoad;
    const cores = cpuLoad.cpus.map((core, index) => ({
      core: index,
      usage: parseFloat(core.load.toFixed(2)),
    }));

    // Memory metrics
    const memory = {
      total: Math.round(mem.total / (1024 ** 3) * 100) / 100, // GB
      used: Math.round(mem.used / (1024 ** 3) * 100) / 100,
      free: Math.round(mem.free / (1024 ** 3) * 100) / 100,
      usagePercent: parseFloat(((mem.used / mem.total) * 100).toFixed(2)),
    };

    // Disk metrics (primary disk)
    const primaryDisk = diskLayout[0];
    const disk = primaryDisk ? {
      total: Math.round(primaryDisk.size / (1024 ** 3) * 100) / 100, // GB
      used: Math.round(primaryDisk.used / (1024 ** 3) * 100) / 100,
      free: Math.round((primaryDisk.size - primaryDisk.used) / (1024 ** 3) * 100) / 100,
      usagePercent: parseFloat(primaryDisk.use.toFixed(2)),
    } : {
      total: 0,
      used: 0,
      free: 0,
      usagePercent: 0,
    };

    // Network metrics (first active interface)
    const activeNetwork = networkStats[0];
    const network = activeNetwork ? {
      rx_sec: Math.round(activeNetwork.rx_sec / 1024 * 100) / 100, // KB/s
      tx_sec: Math.round(activeNetwork.tx_sec / 1024 * 100) / 100,
    } : {
      rx_sec: 0,
      tx_sec: 0,
    };

    // Top processes by CPU usage
    const topProcesses = processes.list
      .sort((a, b) => b.cpu - a.cpu)
      .slice(0, 10)
      .map(proc => ({
        pid: proc.pid,
        name: proc.name,
        cpu: parseFloat(proc.cpu.toFixed(2)),
        mem: parseFloat(proc.mem.toFixed(2)),
      }));

    return {
      timestamp: new Date().toISOString(),
      cpu: {
        usage: parseFloat(cpuUsage.toFixed(2)),
        cores,
        temperature: cpuTemp.main || null,
        speed: cpuSpeed.speed,
      },
      memory,
      disk,
      network,
      processes: topProcesses,
      gpu: gpuInfo,
      hasGPU: gpuInfo !== null && gpuInfo.length > 0,
      localVideoStorage,
    };
  } catch (error) {
    console.error('Error collecting system metrics:', error);
    throw error;
  }
}

/**
 * Check if NVIDIA GPU is available
 */
export async function checkGPUAvailability(): Promise<boolean> {
  try {
    await execAsync('nvidia-smi --version');
    return true;
  } catch (error) {
    return false;
  }
}
