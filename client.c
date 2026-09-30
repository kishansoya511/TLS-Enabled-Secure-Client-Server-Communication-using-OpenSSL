/*
 * ============================================================================
 * TLS CLIENT  --  client.c
 * ============================================================================
 * Same commenting scheme as server.c:
 *   [SOCKET]  -> plain TCP/socket programming you already know
 *   [TLS-n]   -> maps to a step in the TLS 1.2 handshake diagram
 *   [THEORY]  -> connects the code to a concept you already learned
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
#include <openssl/x509.h>

#define SERVER_IP   "127.0.0.1"
#define PORT        4433

/*
 * [THEORY] This is the certificate the client will EXPLICITLY trust.
 *
 * Recall from your PKI notes: in the real world, the client's OS/browser
 * already ships with ~100-150 trusted root CA certificates, and it walks
 * a chain (leaf -> intermediate -> root) to find a match.
 *
 * In THIS project, the server's certificate is self-signed -- there is
 * no CA chain to walk. So instead of searching a big trust store, we
 * manually tell OpenSSL: "trust this EXACT certificate file directly."
 * This is the one deliberate shortcut this project takes, and you should
 * be able to say so plainly in an interview.
 */
#define TRUSTED_CERT_FILE "server.crt"

/*
 * ----------------------------------------------------------------------
 * create_context()
 * ----------------------------------------------------------------------
 * [THEORY] Same idea as the server: SSL_CTX is the reusable "factory"
 * object, created once. TLS_client_method() marks this context for use
 * on the CLIENT side of the handshake (it will call SSL_connect, not
 * SSL_accept, later).
 * ----------------------------------------------------------------------
 */
static SSL_CTX *create_context(void)
{
    const SSL_METHOD *method = TLS_client_method();
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
 * [THEORY] This is where the client sets up WHO it is willing to trust,
 * before any connection is even attempted -- exactly like your notes:
 * "the trust store is something the client already has, decided in
 *  advance, before the handshake starts."
 *
 * SSL_CTX_load_verify_locations() loads server.crt into this client's
 * local trust store (acting as if it were a trusted CA cert, since it's
 * self-signed).
 *
 * SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL) turns ON certificate
 * verification. Without this, OpenSSL will still encrypt the connection,
 * but will NOT check whether the certificate is trustworthy at all --
 * which would defeat the entire authentication purpose of TLS and open
 * the door to a MITM attack (Section 1 / Q5 of your notes).
 * ----------------------------------------------------------------------
 */
static void configure_context(SSL_CTX *ctx)
{
    if (SSL_CTX_load_verify_locations(ctx, TRUSTED_CERT_FILE, NULL) != 1) {
        fprintf(stderr, "Failed to load trusted certificate: %s\n", TRUSTED_CERT_FILE);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

/*
 * ----------------------------------------------------------------------
 * connect_tcp()
 * ----------------------------------------------------------------------
 * [SOCKET] Plain TCP client connect -- identical to any non-TLS client.
 * TLS has not started yet; this only establishes the raw TCP channel
 * that the handshake will later run on top of.
 * ----------------------------------------------------------------------
 */
static int connect_tcp(void)
{
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    printf("[CLIENT] TCP connection established to %s:%d\n", SERVER_IP, PORT);
    return sockfd;
}

/*
 * ============================================================================
 * main()
 * ============================================================================
 */
int main(void)
{
    int sockfd;
    SSL_CTX *ctx;
    SSL     *ssl;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* ---- Build the reusable SSL_CTX for this client process ---- */
    ctx = create_context();
    configure_context(ctx);   /* loads trusted cert + turns on verification */

    /* ---- Plain TCP connect [SOCKET] -- no TLS involved yet ---- */
    sockfd = connect_tcp();

    /* [THEORY] Create the per-connection SSL object and bind it to the
     * TCP fd we just connected -- same pattern as the server side. */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    /*
     * ====================================================================
     * [TLS-1] through [TLS-9]  --  THE HANDSHAKE, FROM THE CLIENT'S SIDE
     * ====================================================================
     * SSL_connect() drives:
     *   [TLS-1] Sends ClientHello           (generates Client_Random NOW,
     *                                        sends supported versions/ciphers)
     *   [TLS-2] Receives ServerHello        (chosen version/cipher,
     *                                        Server_Random)
     *   [TLS-3] Receives Certificate        --> THIS is where the client
     *           runs the signature-verification process you already
     *           understand in depth:
     *             1. hash the cert's data fields
     *             2. decrypt the cert's Signature field using the trusted
     *                public key (from server.crt, loaded via
     *                SSL_CTX_load_verify_locations above)
     *             3. compare the two hashes
     *           If this fails, SSL_connect() below will fail and the
     *           handshake aborts -- OpenSSL does all of this internally,
     *           you never call a separate "verify cert" function yourself
     *           (SSL_CTX_set_verify already told it to do this).
     *   [TLS-4] Receives ServerHelloDone
     *   [TLS-5] Sends ClientKeyExchange     (generates Pre-Master Secret,
     *                                        encrypts it using the SERVER'S
     *                                        PUBLIC KEY taken from the
     *                                        certificate just verified)
     *           --> Internally computes Master_Secret and Session_Keys,
     *               exactly like the server does, independently.
     *   [TLS-6],[TLS-7] Sends its own ChangeCipherSpec + Finished
     *   [TLS-8],[TLS-9] Receives server's ChangeCipherSpec + Finished,
     *                   verifies handshake integrity
     * ====================================================================
     */
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[CLIENT] TLS handshake failed (cert verification "
                        "or other TLS error)\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("[CLIENT] TLS handshake successful. Cipher used: %s\n",
           SSL_get_cipher(ssl));

    /*
     * [THEORY] Extra, explicit proof of what just happened during
     * [TLS-3] -- pull the verified certificate back out and print its
     * Subject/Issuer fields. Notice Subject == Issuer here, because the
     * cert is self-signed (Section 8 of your notes).
     */
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert) {
        char subject[256], issuer[256];
        X509_NAME_oneline(X509_get_subject_name(peer_cert), subject, sizeof(subject));
        X509_NAME_oneline(X509_get_issuer_name(peer_cert), issuer, sizeof(issuer));
        printf("[CLIENT] Peer certificate Subject: %s\n", subject);
        printf("[CLIENT] Peer certificate Issuer : %s\n", issuer);

        /* Belt-and-suspenders check: did the chain-of-trust check
         * (run automatically inside SSL_connect because of
         * SSL_CTX_set_verify) actually pass? */
        if (SSL_get_verify_result(ssl) == X509_V_OK) {
            printf("[CLIENT] Certificate verification: PASSED\n");
        } else {
            printf("[CLIENT] Certificate verification: FAILED\n");
        }
        X509_free(peer_cert);
    }

    /*
     * ====================================================================
     * APPLICATION DATA PHASE (Section 9)
     * ====================================================================
     * Session keys already exist on both sides now. SSL_write() below
     * will, per message:
     *    - encrypt the plaintext with the session key
     *    - attach an authentication tag
     *    - wrap it in a TLS record with a plaintext length/type header
     * SSL_read() does the reverse. Neither call touches the certificate
     * or private key anymore -- that job is done.
     * ====================================================================
     */
    {
        const char *msg = "Hello Server, this is the client speaking securely!";
        SSL_write(ssl, msg, strlen(msg));
        printf("[CLIENT] Sent (will be encrypted on the wire): \"%s\"\n", msg);

        char buf[1024] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("[CLIENT] Received (decrypted) from server: \"%s\"\n", buf);
        } else {
            int err = SSL_get_error(ssl, bytes);
            fprintf(stderr, "[CLIENT] SSL_read failed, SSL_get_error=%d\n", err);
        }
    }

    /*
     * ====================================================================
     * GRACEFUL SHUTDOWN -- same ordering discipline as the server:
     *   1. SSL_shutdown()  -- TLS-level close_notify
     *   2. close(sockfd)   -- TCP-level close
     *   3. SSL_free()      -- free per-connection SSL object
     *   4. SSL_CTX_free()  -- free the context (once, at program end)
     * ====================================================================
     */
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf("[CLIENT] Connection closed.\n");
    return 0;
}
