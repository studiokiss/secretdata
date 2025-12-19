module.exports = {
  apps: [
    {
      name: "secretdata",                      // le nom du process
      script: "node_modules/next/dist/bin/next",
      args: "start -p 3000",                  // port d’écoute
      cwd: "./",                              // répertoire de l’app
      instances: "max",                       // 1, 2… ou "max" pour tous les CPU
      exec_mode: "cluster",                   // cluster = multi-process pour Next.js
      env: {
        NODE_ENV: "production",
        PORT: "3000"
        // Ajoute ici tes variables (NEXT_PUBLIC_*, DB_URL, etc.)
      },
      // Sécurité/fiabilité
      max_restarts: 10,
      exp_backoff_restart_delay: 200,         // backoff si crash en boucle
      out_file: "./logs/out.log",
      error_file: "./logs/error.log",
      merge_logs: true
    }
  ]
}
