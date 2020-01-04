FROM ubuntu:19.10
COPY . /sauron
WORKDIR /sauron
USER root

ENV FLASK_APP app

# Create non root user and change permissions on main app folder
RUN addgroup mordor && \
    useradd sauron -g mordor && \
    chown -R sauron /sauron && \
    chgrp -R mordor /sauron && \
    chmod 770 -R /sauron

# Setup requirements file according to deployment option (set on ENV)
RUN apt-get update -y && \
    apt-get install -y python3 python3-pip && \
    python3 -m pip install pip --upgrade && \
    pip3 install pipenv && \
    pipenv lock --requirements > requirements.txt && \
    pip3 install -r requirements.txt

# Change to non root user
USER sauron
EXPOSE 5000
# Start processes using supervisor
CMD supervisord \
    --nodaemon \
    -c /sauron/supervisor/supervisor.conf \
    --loglevel=info \
    --logfile=/sauron/supervisor/logs/supervisord.log
