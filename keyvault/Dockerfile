FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod main.go lockbox.py ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o keyvault .

FROM alpine:3.20
RUN adduser -D -u 1000 vault && mkdir -p /data && chown -R vault:vault /data
COPY --from=build /src/keyvault /usr/local/bin/keyvault
USER vault
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["keyvault"]
