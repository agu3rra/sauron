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
    "status":False,
    "results":{
        "encryption":{
            "ssl2.0":{
                "status":True,
                "info":"You have passed this check."
            },
            "ssl3.0":{
                "status":True,
                "info":"You have passed this check."
            },
            "tls1.0":{
                "status":False,
                "info":"You have failed this check. Disable all versions of the TLS protocol prior to 1.2."
            },
            "tls1.1":{
                "status":False,
                "info":"You have failed this check. Disable all versions of the TLS protocol prior to 1.2."
            },
            "tls1.2":{
                "status":False,
                "info":"You have failed this check. Eventhough TLS version 1.2 is considered secure, we've detected the use of the following SHA-1 cipher suites: xxxxxxx. Disable them in order to ensure proper encryption is used for your application."
            }
        }
    }
}
```

PS: your target host must be reachable from the internet.

## Docker container
If you don't want to call our internet hosted server, feel free to run one of your own using [Docker](https://www.docker.com/).
> docker run -p 2099:8080 sauron

In this model, your target needs to be in the same network as that of your container.

# References
* This application uses a wrapper on top of the [SSLYZE package](https://github.com/nabla-c0d3/sslyze). Thank you, Alban     Diquet!