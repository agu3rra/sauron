FROM ubuntu:latest
COPY . /sauron
WORKDIR /sauron
ENV ENVIRONMENT "DEV"
USER root

# Create non root user and change permissions on main app folder
RUN addgroup mordor && \
    useradd sauron -g mordor && \
    chown sauron /sauron && \
    chgrp mordor /sauron && \
    chmod 770 -R /sauron

# Install python3 and pip
RUN apt-get update -y && \
    apt-get install -y python3 python3-pip

# Setup requirements file according to deployment option (set on ENV)
RUN if [ "$ENVIRONMENT" == "DEV" ]; \
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
