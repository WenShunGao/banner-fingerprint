# Banner fingerprint

Go client/server for batch recognition of scan banners. No active scanning or external dependencies.

## Run

```sh
docker compose up --build
```

The one-shot client prints the 20 sample results and exits; the server remains running. `GET http://127.0.0.1:8080/health` and `POST http://127.0.0.1:8080/fingerprint` are available on the host loopback only. Containers communicate over the private Compose network via `server:8080`; the client waits for the server's real HTTP health check.

For another input file, start the stack and run the client locally:

```sh
go run ./cmd/client -file my-input.json -url http://127.0.0.1:8080/fingerprint
```

Or override the Compose client's command and mount a file read-only. The input is a JSON array of `{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}` records. JSON uses `\u0000` for NUL and `\r\n` for CRLF; `\xNN` is not valid JSON. A result per input retains `ip` and `port`, and adds `protocol`, `product`, `version`, `os_hint`, `confidence`. Unrecognized banners return `protocol: "unknown"` with empty details and confidence 0. Malformed requests return HTTP 4xx; the request body limit is 4 MiB.

Rules in `rules.json` are ordered (specific before generic), compiled at startup and use Go regular expressions with optional named captures `version` and `os`. The MySQL binary handshake requires a small parser in Go. A match based on product and version has higher confidence than a generic protocol response; confidence is a heuristic, not a statistical probability. Edit rules and rebuild the server image to add products; no HTTP handler changes are needed.

`go test ./...` checks the complete sample, including variants and unknown records. The server image is static and minimal, runs without root or Linux capabilities, and uses a read-only filesystem. The service only publishes to localhost; no target host is contacted.
