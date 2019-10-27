# Sauron Security Scanner (Work in progress...)
The eye that sees security vulnerabilities in web applications.

![eye](docs/images/eye.jpg)

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
    "response":False,
    "results":[
        {
            "category":"encryption",
            "result":False,
            "title":"Weak Encryption",
            "description":"The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required. A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources. Additional information: https://cwe.mitre.org/data/definitions/311.html",
            "cwe":326,
            "checks":[
                {
                    "name":"ssl2.0",
                    "result":True,
                    "info":"You have passed this check."
                },
                {
                    "name":"ssl3.0",
                    "result":True,
                    "info":"You have passed this check."
                },
                {
                    "name":"tls1.0",
                    "result":False,
                    "info":"You have failed this check. Disable all versions of the TLS protocol prior to 1.2."
                },
                {
                    "name":"tls1.1",
                    "result":False,
                    "info":"You have failed this check. Disable all versions of the TLS protocol prior to 1.2."
                },
                {
                    "name":"tls1.2",
                    "result":False,
                    "info":"You have failed this check. Eventhough TLS version 1.2 is considered secure, we've detected the use of the following SHA-1 cipher suites: xxxxxxx. Disable them in order to ensure proper encryption is used for your application."
                },
                {
                    "name":"tls1.3",
                    "result":True,
                    "info":"You have passed this check."
                },
            ]
        }
    ]
}
```

PS: your target host must be reachable from the internet.

## Docker container
If you don't want to call our internet hosted server, feel free to run one of your own using [Docker](https://www.docker.com/).
> docker run -p 2099:8080 sauron

In this model, your target needs to be in the same network as that of your container.

# References
* This application uses a wrapper on top of the [SSLYZE package](https://github.com/nabla-c0d3/sslyze). Thank you, Alban Diquet!