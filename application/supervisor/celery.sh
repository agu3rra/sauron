echo "Starting Celery"
cd /sauron/application
celery worker -A app.py \
    --loglevel=info \
    --concurrency=4 \
    --time-limit=3600 \
    --logfile=/sauron/application/supervisor/logs/celery.log \
    --queues=celery \
    -E
