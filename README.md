# TLS-Enabled-Secure-Client-Server-Communication-using-OpenSSL
Secure client-server communication in C using TCP sockets and OpenSSL, implementing the full TLS handshake, certificate-based authentication, and encrypted data exchange.
# How to Build and Run

You'll need `libssl-dev` (or equivalent) installed for the OpenSSL headers.

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev build-essential

# Fedora/RHEL
sudo dnf install openssl-devel gcc
```

## 1. Generate the self-signed certificate + private key (one-time, offline step)

```bash
make cert
```

This runs:
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
    -days 365 -nodes -subj "/CN=localhost"
```

This creates two files:
- `server.key` — the server's private key (never shared)
- `server.crt` — the self-signed certificate (sent to the client during the handshake, and also pre-loaded by the client as its trusted cert — see Section 8 of the notes / the comments in `client.c`)

## 2. Compile

```bash
make
```

This produces two binaries: `server` and `client`.

## 3. Run — two terminals

**Terminal 1:**
```bash
./server
```

**Terminal 2:**
```bash
./client
```

## Expected output

**Server terminal:**
```
[SERVER] Listening on port 4433 ...

[SERVER] Waiting for a TCP connection...
[SERVER] TCP connection accepted from 127.0.0.1:xxxxx
[SERVER] TLS handshake successful. Cipher used: TLS_AES_256_GCM_SHA384
[SERVER] Received (decrypted) from client: "Hello Server, this is the client speaking securely!"
[SERVER] Sent (will be encrypted on the wire): "Hello Client, this message is TLS-encrypted!"
[SERVER] Connection closed.
```

**Client terminal:**
```
[CLIENT] TCP connection established to 127.0.0.1:4433
[CLIENT] TLS handshake successful. Cipher used: TLS_AES_256_GCM_SHA384
[CLIENT] Peer certificate Subject: /CN=localhost
[CLIENT] Peer certificate Issuer : /CN=localhost
[CLIENT] Certificate verification: PASSED
[CLIENT] Sent (will be encrypted on the wire): "Hello Server, this is the client speaking securely!"
[CLIENT] Received (decrypted) from server: "Hello Client, this message is TLS-encrypted!"
[CLIENT] Connection closed.
```

Notice `Subject` and `Issuer` are identical — that's the self-signed cert, exactly as discussed (Q11 in your interview bank).

## 4. Verify it for real (Section 10 of your notes)

While `./server` is running, in a third terminal:

```bash
# Confirm the handshake and see the negotiated cipher, independent of your own client
openssl s_client -connect 127.0.0.1:4433 -CAfile server.crt
```

Or capture on loopback with Wireshark (`sudo wireshark`, interface `lo`, filter `tcp.port == 4433`) — you'll see the ClientHello/ServerHello/Certificate messages in plaintext, and your actual message payloads will show up only as opaque `Application Data`.

## Mapping code back to theory — quick index

| Theory concept | Where in the code |
|---|---|
| SSL_CTX (factory, created once) | `create_context()` in both files, called once in `main()` |
| SSL (per-connection object) | `SSL_new(ctx)` — inside the `while(1)` loop in server.c (fresh per client), once in client.c |
| Certificate loading (server) | `configure_context()` in server.c — `SSL_CTX_use_certificate_file` / `SSL_CTX_use_PrivateKey_file` |
| Trust store setup (client) | `configure_context()` in client.c — `SSL_CTX_load_verify_locations` + `SSL_CTX_set_verify` |
| Plain TCP setup [SOCKET] | `create_tcp_socket()` / `connect_tcp()` — untouched by TLS |
| Handshake steps 1–9 | Single call: `SSL_accept(ssl)` (server) / `SSL_connect(ssl)` (client) |
| Certificate signature verification | Happens *inside* `SSL_connect()`, because `SSL_CTX_set_verify` was set — confirmed afterward via `SSL_get_verify_result()` |
| Session keys | Derived internally during `SSL_accept`/`SSL_connect` — never appear as a variable in your code, OpenSSL manages them internally |
| Application data phase | `SSL_read()` / `SSL_write()` calls |
| Graceful shutdown | `SSL_shutdown()` → `close(fd)` → `SSL_free()` → `SSL_CTX_free()` (once, at the very end) |

Author
Kishan Soya
