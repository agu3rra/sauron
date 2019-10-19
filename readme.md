# Sauron Security Scanner (Work in progress...)
The eye that sees security vulnerabilities in web applications.

# Features
1. TLS protocol check.
1. Encryption cipher suite check

# Deployment options
## As a service
Simply make an API call (HTTP POST) to https://sauron.com/api/scan containing the following body:
```json
{
    "target_host":"example.com",
    "target_port":443
}
```

Sample response:
```json
{
    "status":"Fail",
    "results":{
        "tls1.0":"We've detected the TLS protocol version 1.0 is enabled in your target host/port. Ensure only 1.2 or above are switched on."
    }
}
```

PS: your target host must be reachable from the internet.

## Docker container
If you don't want to call our internet hosted server, feel free to run one of your own using [Docker](https://www.docker.com/).
> docker run -p 2099:8080 sauron

In this model, your target needs to be in the same network as that of your container.