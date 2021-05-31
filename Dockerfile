FROM golang:alpine AS build

RUN apk --update add ca-certificates

WORKDIR /opt/src

COPY . .

RUN --mount=type=cache,target=/go CGO_ENABLED=0 go build -o /opt/bin/oauth-pkce-proxy .


FROM scratch

COPY --from=build /opt/bin/oauth-pkce-proxy /opt/bin/oauth-pkce-proxy
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/opt/bin/oauth-pkce-proxy"]
