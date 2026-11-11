import os

# Production Gunicorn configuration for Render deployment
# Binds to 0.0.0.0 and port assigned by the platform (default 5000)
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# Worker processes (1-2 workers recommended for free-tier memory constraints)
workers = int(os.environ.get("WEB_CONCURRENCY", 1))
threads = int(os.environ.get("PYTHON_GET_THREADS", 2))

# Extended timeout to allow multi-tool agent verification and DNS queries
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 120))
keepalive = 5

# Logging to standard output/error for platform log collection
accesslog = "-"
errorlog = "-"
loglevel = "info"
