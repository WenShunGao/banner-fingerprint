FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY fingerprint ./fingerprint
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /client ./cmd/client

FROM scratch AS server
WORKDIR /app
COPY --from=build /server /server
COPY rules.json ./rules.json
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]

FROM scratch AS client
WORKDIR /app
COPY --from=build /client /client
COPY sample.json ./sample.json
USER 65532:65532
ENTRYPOINT ["/client"]
