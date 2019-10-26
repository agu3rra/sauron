FROM ubuntu:latest
COPY . /sauron
WORKDIR /sauron

USER root
# Create non root user and change permissions on main app folder
RUN useradd -U sauron && \
    chown sauron /sauron && \
    chgrp sauron /sauron && \
    chmod 770 -R /sauron

# Setup requirements file according to deployment option (set on ENV)
RUN if [ "$THIS_DEPLOYMENT_ENVRIONMENT" = "DEV" ]; \
    then REQUIREMENTS_FILE="requirements-dev.txt"; \
    else REQUIREMENTS_FILE="requirements.txt"; fi && \
    echo $REQUIREMENTS_FILE

# Install python3 and pip
RUN apt-get update && \
    apt-get install python3 python3-pip -y

# Install dependencies
RUN cd requirements && \
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
