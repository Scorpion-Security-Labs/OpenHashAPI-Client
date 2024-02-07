# OpenHashAPI Client

OpenHashAPI (OHA) is designed to store and maintain hashes and plaintext in a centralized database. OHA is written in Go and designed for containerized deployment.

OpenHashAPI provides a secure method of communicating hashes over HTTPS and enables lightweight workflows for security practitioners and enthusiasts. OpenHashAPI focuses on extracting value from plaintext and recycles values into newly generated resources such as wordlists, masks, and rules. OHA is designed to target common human password patterns and assess the security of human-generated passwords.

- RESTful API
- JWT Authentication
- HTTPS Communication
- Centralized Database
- Containerized Deployment
- Upload and Search API
- User Administration
- Server Logging
- Quality Control Filtering
- Async Database Validation
- Async Wordlist Generation
- Async Masks Generation
- Async Rules Generation
- Automatic Upload Rehashing
- Remote Download Resource Files
- Multibyte and `$HEX[...]` handling
- Private file hosting
- Browser-based documentation

## Getting Started:
 - [About](#about)
 - [Install](#install)
 - [Usage & API](#usage-&-api)
 - [OpenHashAPI Server](#openhashapi-server)

## About:
- OpenHashAPI was created out of a need to generate hash-cracking materials using
  data. Using discovered material as the foundation for new resources
  often offers better results for security teams. OpenHashAPI provides a method to
  store, quality control, and validate (select non-salted algorithms) large amounts of hash data.
- The application offers features to upload and store found material as well as
  ensuring material meets quality standards through regex filtering.
- The application features several asynchronous processes to generate new
  material and host it for download. Generated material is sorted by frequency.
- This tool was designed to be used by small-security teams and enthusiasts
  within private networks.

## Install
- The client application can be ran within a container or by compiling locally
- The container installation consists of setting up the `Dockerfile` with the correct
  information, building the agent, and deploying it.
- The golang installation consists of building from source then creating a JSON
  configuration file at `~/.oha`.

### Docker Intall

First, configure the settings within the `Dockerfile`:
```
ENV SERVER_URL="0.0.0.0"
ENV SERVER_PORT="8080"
ENV SERVER_API="/api"
ENV CLIENT_USERNAME="username_you_created_on_the_api"
ENV CLIENT_PASSWORD="password"
```

Next, Build the image:
```
docker build . -t ohaclient
```

Finally, run the client:
```
docker run -it --rm --volume ${PWD}:/data ohaclient
```

### Golang Install

First, create a configuration file at `~/.oha`:
```
{
    "server-url":"0.0.0.0",
    "server-port":"8080",
    "server-api-route":"/api",
    "client-username":"username",
    "client-password":"password",
}
```

Next, install using Go or build the binary locally:
```
go install github.com/Scorpion-Security-Labs/ohaclient@latest
```

Finally, run the client:
```
ohaclient
```

## Usage & API
- The API definitions are in the [OpenHashAPI Server](https://github.com/Scorpion-Security-Labs/OpenHashAPI) repo.

The following are defined API endpoints:
- `/api/register`
- `/api/login`
- `/api/health`
- `/api/found`
- `/api/search`
- `/api/manage`
- `/api/status`
- `/api/download/FILE/NUM`
- `/api/lists`
- `/api/lists/LISTNAME`

After building the client, the routes generally follow the following syntax:

```
docker run -it --rm --volume ${PWD}:/data ohaclient [COMMAND] [OPTIONS]
```


## OpenHashAPI Server
- This is a client for the API.
- The entire server can be found at [OpenHashAPI Server](https://github.com/Scorpion-Security-Labs/OpenHashAPI).
