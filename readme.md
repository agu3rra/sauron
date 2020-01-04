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
    "result": false,
    "results": [
        {
            "category": "encryption",
            "result": false,
            "title": "Weak Encryption",
            "description": "The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required. A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources. Additional information: https://cwe.mitre.org/data/definitions/326.html",
            "cwe": 326,
            "checks": [
                {
                    "name": "tls1.3",
                    "result": false,
                    "info": "This TLS protocol version is ok to use, but you '                            'have selected a set of insecure ciphers: TLS_CHACHA20_POLY1305_SHA256; TLS_AES_256_GCM_SHA384; TLS_AES_128_GCM_SHA256; ",
                    "details": {
                        "protocol": "tls1.3",
                        "is_supported": true,
                        "is_allowed": true,
                        "has_passed": false,
                        "ciphers_supported": [
                            "TLS_CHACHA20_POLY1305_SHA256",
                            "TLS_AES_256_GCM_SHA384",
                            "TLS_AES_128_GCM_SHA256"
                        ],
                        "problematic_ciphers": [
                            "TLS_CHACHA20_POLY1305_SHA256",
                            "TLS_AES_256_GCM_SHA384",
                            "TLS_AES_128_GCM_SHA256"
                        ]
                    }
                },
                {
                    "name": "tls1.2",
                    "result": false,
                    "info": "This TLS protocol version is ok to use, but you '                            'have selected a set of insecure ciphers: TLS_RSA_WITH_AES_256_CBC_SHA; TLS_RSA_WITH_AES_128_CBC_SHA; TLS_RSA_WITH_3DES_EDE_CBC_SHA; TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256; TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA; TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA; TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256; ",
                    "details": {
                        "protocol": "tls1.2",
                        "is_supported": true,
                        "is_allowed": true,
                        "has_passed": false,
                        "ciphers_supported": [
                            "TLS_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                        ],
                        "problematic_ciphers": [
                            "TLS_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                        ]
                    }
                },
                {
                    "name": "tls1.1",
                    "result": false,
                    "info": "Encryption protocol version is insecure.",
                    "details": {
                        "protocol": "tls1.1",
                        "is_supported": true,
                        "is_allowed": false,
                        "has_passed": false,
                        "ciphers_supported": [
                            "TLS_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
                        ],
                        "problematic_ciphers": [
                            "TLS_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
                        ]
                    }
                },
                {
                    "name": "tls1.0",
                    "result": false,
                    "info": "Encryption protocol version is insecure.",
                    "details": {
                        "protocol": "tls1.0",
                        "is_supported": true,
                        "is_allowed": false,
                        "has_passed": false,
                        "ciphers_supported": [
                            "TLS_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
                        ],
                        "problematic_ciphers": [
                            "TLS_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
                        ]
                    }
                },
                {
                    "name": "ssl3.0",
                    "result": true,
                    "info": "Application has passed this check successfully.",
                    "details": {
                        "protocol": "ssl3.0",
                        "is_supported": false,
                        "is_allowed": false,
                        "has_passed": true,
                        "ciphers_supported": [],
                        "problematic_ciphers": []
                    }
                },
                {
                    "name": "ssl2.0",
                    "result": true,
                    "info": "Application has passed this check successfully.",
                    "details": {
                        "protocol": "ssl2.0",
                        "is_supported": false,
                        "is_allowed": false,
                        "has_passed": true,
                        "ciphers_supported": [],
                        "problematic_ciphers": []
                    }
                }
            ]
        }
    ]
 }
```

PS: your target host must be reachable from the internet.

## Docker container
If you don't want to call our internet hosted server, feel free to run one of your own using [Docker](https://www.docker.com/).
> docker run -p 5000:5000 agu3rra/sauron:20.01.1

In this model, your target needs to be in the same network as that of your container.

# References
* This application uses a wrapper on top of the [SSLYZE package](https://github.com/nabla-c0d3/sslyze). Thank you, Alban Diquet!