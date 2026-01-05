module.exports = {
  apps: [{
    name: 'videoapp',
    script: 'npm',
    args: 'run dev',
    cwd: '/root/videoapp',
    
    // Memory management - restart if exceeds 12GB (out of 16GB)
    max_memory_restart: '12G',
    
    // Auto-restart settings
    autorestart: true,
    watch: false,
    max_restarts: 10,
    min_uptime: '10s',
    restart_delay: 5000,
    
    // Environment
    env: {
      NODE_ENV: 'production',
      PORT: 5000
    },
    
    // Logging
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    error_file: '/root/videoapp/logs/error.log',
    out_file: '/root/videoapp/logs/out.log',
    merge_logs: true,
    
    // Graceful shutdown
    kill_timeout: 30000,
    wait_ready: true,
    listen_timeout: 60000,
    
    // Instance management for multi-core (optional - use 1 for simplicity)
    instances: 1,
    exec_mode: 'fork'
  }]
};
