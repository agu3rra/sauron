FROM python:3.6-alpine
COPY . /sauron
WORKDIR /sauron

USER root
# Create non root user and change permissions on main app folder
RUN addgroup -S mordor && \ 
    adduser -S sauron -G mordor && \
    chown sauron /sauron && \
    chgrp mordor /sauron && \
    chmod 770 -R /sauron

# Install python3 and pip
RUN apk update

# Setup requirements file according to deployment option (set on ENV)
RUN if [ "$THIS_DEPLOYMENT_ENVRIONMENT" = "DEV" ]; \
    then REQUIREMENTS_FILE="requirements-dev.txt"; \
    else REQUIREMENTS_FILE="requirements.txt"; fi && \
    echo "Using $REQUIREMENTS_FILE for installing requirements." && \
    python3 -m pip install pip --upgrade && \
    cd requirements && \
    pip3 install -r $REQUIREMENTS_FILE

# Change to non root user
USER sauron

EXPOSE 2099
# Start processes using supervisor
CMD supervisord \
    --nodaemon \
    -c /sauron/application/supervisor/supervisor.conf \
    --loglevel=info \
    --logfile=/sauron/application/supervisor/logs/supervisord.log
