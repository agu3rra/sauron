FROM python:3.8.1-alpine3.11
COPY . /sauron
WORKDIR /sauron
USER root

# Create non root user and change permissions on main app folder
RUN addgroup mordor && \
    useradd sauron -g mordor && \
    chown sauron /sauron && \
    chgrp mordor /sauron && \
    chmod 770 -R /sauron

# Setup requirements file according to deployment option (set on ENV)
RUN python -m pip install pip --upgrade && \
    pip install pipenv && \
    pipenv lock --requirements > requirements.txt && \
    pip install -r requirements.txt

# Change to non root user
USER sauron
EXPOSE 2099
# Start processes using supervisor
CMD supervisord \
    --nodaemon \
    -c /sauron/application/supervisor/supervisor.conf \
    --loglevel=info \
    --logfile=/sauron/application/supervisor/logs/supervisord.log
