/**
 * PM2 Ecosystem Configuration for VPS Deployment
 * 
 * This file configures how PM2 runs the application on your VPS server.
 * 
 * Usage:
 * 1. Upload this file to /root/videoapp/ on your VPS
 * 2. Run: pm2 start ecosystem.config.cjs
 * 3. Run: pm2 save
 */

module.exports = {
  apps: [{
    name: 'videoapp',
    script: 'dist/index.js',
    cwd: '/root/videoapp',
    
    // PERFORMANCE: Use all CPU cores with cluster mode
    instances: 'max',  // Uses all available CPUs (4 in your case)
    exec_mode: 'cluster',  // Enable cluster mode for load balancing
    
    autorestart: true,
    watch: false,
    max_memory_restart: '2G',  // Increased for video processing
    
    env: {
      NODE_ENV: 'production',
      // Optimize Node.js for production
      UV_THREADPOOL_SIZE: '16',  // More threads for async I/O
    },
    
    error_file: '/var/log/pm2/videoapp-error.log',
    out_file: '/var/log/pm2/videoapp-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    
    // Restart settings
    min_uptime: '10s',
    max_restarts: 10,
    
    // Advanced features for zero-downtime reload
    kill_timeout: 5000,
    listen_timeout: 8000,  // Increased for cluster startup
    wait_ready: true,  // Wait for 'ready' signal
    shutdown_with_message: false
  }]
};
