/*
 * ============================================================================
 * TLS SERVER  --  server.c
 * ============================================================================
 * This file is commented in two layers:
 *
 *   [SOCKET]  -> plain TCP/socket programming you already know
 *   [TLS-n]   -> maps to a specific step in the TLS 1.2 handshake diagram
 *                (n = 1,2,3,4,5,6,7,8,9 -- same numbering as your notes)
 *   [THEORY]  -> connects the code line to a concept you already learned
 *                (SSL_CTX vs SSL, session keys, certificates, etc.)
 *
 * Read this top to bottom -- it follows the exact order of execution.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT        4433
#define CERT_FILE   "server.crt"   /* [THEORY] the self-signed certificate  */
#define KEY_FILE    "server.key"   /* [THEORY] the server's PRIVATE key.    */
                                    /*          Never sent over the wire.   */

/*
 * ----------------------------------------------------------------------
 * create_context()
 * ----------------------------------------------------------------------
 * [THEORY] This builds the SSL_CTX -- the "template/factory" object.
 *          Recall: SSL_CTX is created ONCE for the whole program.
 *          It is NOT per-connection. Every client that connects will
 *          later get its own SSL* object built FROM this one context.
 *
 * TLS_server_method() tells OpenSSL "this context is going to be used
 * for the SERVER side of the handshake" (as opposed to client side).
 * It does NOT pin a specific TLS version -- OpenSSL will negotiate the
 * best mutually supported version with whoever connects (this is what
 * happens live during ClientHello/ServerHello, [TLS-1]/[TLS-2] below).
 * ----------------------------------------------------------------------
 */
static SSL_CTX *create_context(void)
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        fprintf(stderr, "Unable to create SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

/*
 * ----------------------------------------------------------------------
 * configure_context()
 * ----------------------------------------------------------------------
 * [THEORY] This is where the server loads the artifacts that will be
 *          used DURING the handshake:
 *            - server.crt -> sent to the client in [TLS-3] (Certificate)
 *            - server.key -> used internally in [TLS-5] (ClientKeyExchange)
 *              to decrypt/derive the shared secret. NEVER transmitted.
 *
 * This happens ONCE at startup -- exactly like your notes said:
 * "certificate creation/loading is NOT a per-connection, per-message
 *  event -- it's a one-time setup step."
 * ----------------------------------------------------------------------
 */
static void configure_context(SSL_CTX *ctx)
{
    /* Load the certificate (public info: server's identity + public key) */
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate file: %s\n", CERT_FILE);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Load the matching PRIVATE key (secret: proves ownership of the cert) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key file: %s\n", KEY_FILE);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*
     * [THEORY] Sanity check: does this private key actually match the
     * public key embedded inside server.crt? If someone mismatched the
     * files, the handshake would fail later in a confusing way -- this
     * catches it immediately, at startup, with a clear error.
     */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}

/*
 * ----------------------------------------------------------------------
 * create_tcp_socket()
 * ----------------------------------------------------------------------
 * [SOCKET] Nothing TLS-specific here at all. This is the EXACT same
 *          socket()/bind()/listen() sequence you already know from
 *          plain TCP servers. TLS does not change this part -- it only
 *          gets involved AFTER a TCP connection already exists.
 * ----------------------------------------------------------------------
 */
static int create_tcp_socket(void)
{
    int sockfd;
    struct sockaddr_in addr;
    int reuse = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Allow quick restart of the server without "Address already in use" */
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("[SERVER] Listening on port %d ...\n", PORT);
    return sockfd;
}

/*
 * ============================================================================
 * main()
 * ============================================================================
 */
int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    SSL_CTX *ctx;
    SSL     *ssl;

    /*
     * [THEORY] One-time OpenSSL library initialisation.
     * Modern OpenSSL (1.1.0+) mostly auto-initialises, but calling this
     * explicitly is still common/clear practice and loads error strings
     * so ERR_print_errors_fp() below gives human-readable messages
     * instead of raw error codes.
     */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* ---- Build the ONE reusable SSL_CTX for this whole server process ---- */
    ctx = create_context();
    configure_context(ctx);   /* loads server.crt + server.key, see above */

    /* ---- Plain TCP setup -- identical to a non-TLS server [SOCKET] ---- */
    server_fd = create_tcp_socket();

    /*
     * --------------------------------------------------------------
     * Loop: accept one client, serve it, close it, go back and wait
     * for the next one. (A real production server would fork()/thread
     * per client or use epoll -- kept single-connection here so the
     * flow stays easy to trace against the theory.)
     * --------------------------------------------------------------
     */
    while (1) {
        printf("\n[SERVER] Waiting for a TCP connection...\n");

        /* [SOCKET] Plain TCP accept -- same as any non-TLS server.
         * At this point we ONLY have a raw, UNENCRYPTED TCP connection.
         * No TLS handshake has happened yet. */
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        printf("[SERVER] TCP connection accepted from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        /*
         * [THEORY] Create a brand-new SSL object for THIS connection.
         * Recall: SSL_CTX = shared config (created once, above).
         *         SSL     = per-connection state (created fresh, every time).
         * If a second client connects while this loop runs again, it gets
         * its OWN SSL object -- session keys, handshake state, etc. are
         * never shared between connections.
         */
        ssl = SSL_new(ctx);

        /* [THEORY] Bind this SSL object to the TCP fd we just accepted.
         * From this point on, OpenSSL will do its reads/writes through
         * this fd internally (via its BIO layer) whenever we call
         * SSL_accept / SSL_read / SSL_write. */
        SSL_set_fd(ssl, client_fd);

        /*
         * ====================================================================
         * [TLS-1] through [TLS-9]  --  THE ENTIRE HANDSHAKE HAPPENS HERE
         * ====================================================================
         * SSL_accept() is a SINGLE function call, but internally it drives
         * every step of the handshake diagram you learned:
         *
         *   [TLS-1] Receives ClientHello       (client's random + cipher list)
         *   [TLS-2] Sends ServerHello           (chosen version/cipher + server random)
         *   [TLS-3] Sends Certificate           (sends server.crt, loaded above)
         *   [TLS-4] Sends ServerHelloDone
         *   [TLS-5] Receives ClientKeyExchange  (uses server.key to derive
         *                                        the shared Pre-Master Secret)
         *           --> Internally computes Master_Secret and Session_Keys
         *               via PRF(Pre-Master Secret, Client_Random, Server_Random)
         *               EXACTLY as you worked out earlier.
         *   [TLS-6],[TLS-7] Receives client's ChangeCipherSpec + Finished,
         *                   verifies the handshake-integrity hash
         *   [TLS-8],[TLS-9] Sends its own ChangeCipherSpec + Finished
         *
         * You will NOT see these 9 steps as separate function calls --
         * that is the whole point of the OpenSSL API: it hides the
         * message-by-message protocol machinery behind one blocking call.
         * If you want to actually SEE these messages, that's what
         * Wireshark is for (Section 10 of your notes).
         * ====================================================================
         */
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "[SERVER] TLS handshake failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        printf("[SERVER] TLS handshake successful. Cipher used: %s\n",
               SSL_get_cipher(ssl));
        /* ^ This prints the negotiated cipher suite -- e.g.
         *   TLS_AES_256_GCM_SHA384 -- the same thing you'd see with
         *   `openssl s_client` from Section 10.2 of your notes. */

        /*
         * ====================================================================
         * APPLICATION DATA PHASE  (after the handshake -- Section 9)
         * ====================================================================
         * From here on, session keys are already established (both sides
         * derived them independently, nothing was sent over the wire).
         * SSL_read/SSL_write handle, PER MESSAGE:
         *    - encryption/decryption using the session key
         *    - computing/verifying the auth tag (tamper detection)
         *    - TLS record framing (the plaintext header you learned about)
         * None of this involves the certificate or private key anymore --
         * that part of the job finished when SSL_accept() returned.
         * ====================================================================
         */
        {
            char buf[1024] = {0};
            int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);

            if (bytes > 0) {
                buf[bytes] = '\0';
                printf("[SERVER] Received (decrypted) from client: \"%s\"\n", buf);

                const char *reply = "Hello Client, this message is TLS-encrypted!";
                SSL_write(ssl, reply, strlen(reply));
                printf("[SERVER] Sent (will be encrypted on the wire): \"%s\"\n", reply);
            } else {
                int err = SSL_get_error(ssl, bytes);
                fprintf(stderr, "[SERVER] SSL_read failed, SSL_get_error=%d\n", err);
            }
        }

        /*
         * ====================================================================
         * GRACEFUL SHUTDOWN
         * ====================================================================
         * [THEORY] SSL_shutdown() sends a TLS-level "close_notify" alert.
         * This is DIFFERENT from just closing the TCP socket -- it tells
         * the peer "I am ending this conversation on purpose", so the
         * peer can distinguish a clean close from a connection that was
         * abruptly cut off (which could indicate a truncation attack).
         *
         * Order matters (Section 6 of your notes):
         *   1. SSL_shutdown(ssl)   -- TLS-level close
         *   2. close(client_fd)    -- TCP-level close
         *   3. SSL_free(ssl)       -- free the per-connection SSL object
         * (SSL_CTX_free() happens once, only when the whole server exits)
         */
        SSL_shutdown(ssl);
        close(client_fd);
        SSL_free(ssl);
        printf("[SERVER] Connection closed.\n");
    }

    /* Unreachable in this infinite loop, but shown for completeness:
     * SSL_CTX_free() is called ONCE, when the server process is shutting
     * down entirely -- not per connection. */
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
