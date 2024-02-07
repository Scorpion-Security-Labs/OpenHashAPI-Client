# Build Go Layer
FROM golang:1.22-bookworm as go-build-env
RUN mkdir src/app
WORKDIR /src/app
COPY ./main.go .
COPY ./go.mod .
COPY ./internal ./internal
RUN go build .

# Select Deployment Image
FROM ubuntu

# Configuration
# Please consider a secrets manager for the password deployment
# 0.0.0.0
ENV SERVER_URL=""
# 8080
ENV SERVER_PORT=""
# /api
ENV SERVER_API=""
# username_you_created_on_the_api
ENV CLIENT_USERNAME=""
# password_you_created_on_the_api
ENV CLIENT_PASSWORD=""

# Update and Install Packages
RUN apt-get update && apt-get install -y --no-install-recommends tini && \
     rm -rf /var/lib/apt/lists/* 

# Start Application
COPY --from=go-build-env /src/app/ohaclient /sbin/ohaclient
WORKDIR /data

# COMMENT THIS LINE TO STOP AUTO START
ENTRYPOINT ["/usr/bin/tini", "--", "/sbin/ohaclient"]
