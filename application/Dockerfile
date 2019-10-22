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
RUN if $DEPLOYMENT -eq 'DEV'; \
    then $REQUIREMENTS_FILE='requirements-dev.txt' \
    else $REQUIREMENTS_FILE='requirements-prd.txt' \
    fi

# Install dependencies
RUN cd requirements && \
    pip install -r $REQUIREMENTS_FILE

# Change to non root user
USER sauron

EXPOSE 2099
# Start processes using supervisor
CMD supervisord \
    --nodaemon \
    -c /sauron/application/supervisor/supervisor.conf \
    --loglevel=info \
    --logfile=/sauron/application/supervisor/logs/supervisord.log
