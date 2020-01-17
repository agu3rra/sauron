# Sauron Security Scanner
The eye that sees security vulnerabilities in web applications.

![eye](docs/images/eye.jpg)

<!-- TOC -->

- [Sauron Security Scanner](#sauron-security-scanner)
- [Features](#features)
- [Documentation](#documentation)
- [Deployment options](#deployment-options)
    - [Docker-compose](#docker-compose)
    - [Kubernetes](#kubernetes)
    - [As a service](#as-a-service)
- [References](#references)

<!-- /TOC -->

# Features
1. TLS protocol check.
1. Encryption cipher suite check

# Documentation
Check out our Postman [collection](docs/postman/Sauron.postman_collection.json)! If you don't have [Postman](https://www.getpostman.com/), make sure you get it. :)

[sample scan output](docs/sample_output.json)

# Deployment options

## Docker-compose
If you don't want to call our internet hosted server, feel free to run one of your own using [Docker](https://www.docker.com/). Download our [docker-compose.yml](deployment/dockerhub-build/docker-compose.yml) and run the following command (assumes you have docker installed):
> docker-compose up

The service is served on http://127.0.0.1:8080/ by default.

In this model, your target needs to be in the same network as that of docker computer.

## Kubernetes
**TO BE IMPLEMENTED**  

## As a service
**TO BE IMPLEMENTED**  
Make an API call (HTTP POST) to https://sauron.com/scan. Use the above documentation as reference.

PS: your target host must be reachable from the internet.

# References
* This application uses a wrapper on top of the [SSLYZE package](https://github.com/nabla-c0d3/sslyze). Thank you, Alban Diquet!