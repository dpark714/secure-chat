#include <gtk/gtk.h>

#include <glib/gunicode.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <netdb.h>

#include <openssl/evp.h>

#include <openssl/hmac.h>

#include <openssl/aes.h>

#include <openssl/rand.h>

#include <openssl/err.h>

#include <openssl/dh.h>

#include <openssl/bn.h>

#include <string.h>

#include <pthread.h>

#include <unistd.h>

#include <getopt.h>

#include "dh.h"

#include "keys.h"



#ifndef PATH_MAX

#define PATH_MAX 1024

#endif



#define AES_KEYLEN 256

#define BUFFER_SIZE 4096



typedef struct {

    EVP_CIPHER_CTX *enc_ctx;

    EVP_CIPHER_CTX *dec_ctx;

    unsigned char aes_key[32]; // 256-bit key

    unsigned char hmac_key[EVP_MAX_MD_SIZE];

    unsigned char iv[AES_BLOCK_SIZE];

    EVP_PKEY *dhkey;

} SessionKeys;



static SessionKeys sessionKeys;

static GtkTextBuffer* tbuf; /* transcript buffer */

static GtkTextBuffer* mbuf; /* message buffer */

static GtkTextView* tview;  /* view for transcript */

static GtkTextMark* mark;   /* used for scrolling to end of transcript, etc */

static int sockfd;          // Socket file descriptor

static int listensock;      // Listening socket file descriptor



// Prototypes

void init_crypto();

void cleanup_crypto();

void generate_keys();

void derive_keys(unsigned char *shared_secret, size_t secret_len);

int encrypt_message(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);

int decrypt_message(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

void error(const char *msg);

int initServerNet(int port);

int initClientNet(char *hostname, int port);

int shutdownNetwork();

void* recvMsg(void*);

static void sendMessage(GtkWidget* w, gpointer data);



// Error handling

void error(const char *msg) {

    perror(msg);

    exit(EXIT_FAILURE);

}



void print_openssl_error(const char *msg) {

    unsigned long err = ERR_get_error();

    fprintf(stderr, "%s: %s\n", msg, ERR_reason_error_string(err));

}



// Initialize cryptographic components

void init_crypto() {

    OpenSSL_add_all_algorithms();

    ERR_load_crypto_strings();

    sessionKeys.enc_ctx = EVP_CIPHER_CTX_new();

    sessionKeys.dec_ctx = EVP_CIPHER_CTX_new();

    generate_keys();

}



// Cleanup cryptographic components

void cleanup_crypto() {

    EVP_CIPHER_CTX_free(sessionKeys.enc_ctx);

    EVP_CIPHER_CTX_free(sessionKeys.dec_ctx);

    EVP_PKEY_free(sessionKeys.dhkey);

    ERR_free_strings();

}



// Generate Diffie-Hellman parameters and keys

void generate_keys() {

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);

    if (!pctx) {

        print_openssl_error("EVP_PKEY_CTX_new_id failed");

        error("EVP_PKEY_CTX_new_id failed");

    }



    if (EVP_PKEY_paramgen_init(pctx) <= 0) {

        print_openssl_error("EVP_PKEY_paramgen_init failed");

        EVP_PKEY_CTX_free(pctx);

        error("EVP_PKEY_paramgen_init failed");

    }



    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048) <= 0) {

        print_openssl_error("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed");

        EVP_PKEY_CTX_free(pctx);

        error("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed");

    }



    EVP_PKEY *params = NULL;

    if (EVP_PKEY_paramgen(pctx, &params) <= 0) {

        print_openssl_error("EVP_PKEY_paramgen failed");

        EVP_PKEY_CTX_free(pctx);

        error("EVP_PKEY_paramgen failed");

    }



    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);

    if (!kctx) {

        print_openssl_error("EVP_PKEY_CTX_new failed");

        EVP_PKEY_free(params);

        EVP_PKEY_CTX_free(pctx);

        error("EVP_PKEY_CTX_new failed");

    }



    if (EVP_PKEY_keygen_init(kctx) <= 0) {

        print_openssl_error("EVP_PKEY_keygen_init failed");

        EVP_PKEY_free(params);

        EVP_PKEY_CTX_free(pctx);

        EVP_PKEY_CTX_free(kctx);

        error("EVP_PKEY_keygen_init failed");

    }



    if (EVP_PKEY_keygen(kctx, &sessionKeys.dhkey) <= 0) {

        print_openssl_error("EVP_PKEY_keygen failed");

        EVP_PKEY_free(params);

        EVP_PKEY_CTX_free(pctx);

        EVP_PKEY_CTX_free(kctx);

        error("EVP_PKEY_keygen failed");

    }



    EVP_PKEY_CTX_free(pctx);

    EVP_PKEY_CTX_free(kctx);

    EVP_PKEY_free(params);

}



// Derived AES and HMAC keys from shared secret

void derive_keys(unsigned char *shared_secret, size_t secret_len) {

    if (secret_len < (AES_KEYLEN / 8 + EVP_MAX_MD_SIZE)) {

        error("Shared secret is too short to derive keys");

    }

    memcpy(sessionKeys.aes_key, shared_secret, AES_KEYLEN / 8);

    memcpy(sessionKeys.hmac_key, shared_secret + AES_KEYLEN / 8, EVP_MAX_MD_SIZE);

}



// Encrypt messages before sending

int encrypt_message(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {

    int len, ciphertext_len;

    if(1 != EVP_EncryptInit_ex(sessionKeys.enc_ctx, EVP_aes_256_cbc(), NULL, sessionKeys.aes_key, sessionKeys.iv))

        error("Encrypt init failed");



    if(1 != EVP_EncryptUpdate(sessionKeys.enc_ctx, ciphertext, &len, plaintext, plaintext_len))

        error("Encrypt update failed");

    ciphertext_len = len;



    if(1 != EVP_EncryptFinal_ex(sessionKeys.enc_ctx, ciphertext + len, &len))

        error("Encrypt final failed");

    ciphertext_len += len;



    return ciphertext_len;

}



// Decrypt received messages

int decrypt_message(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {

    int len, plaintext_len;

    if(1 != EVP_DecryptInit_ex(sessionKeys.dec_ctx, EVP_aes_256_cbc(), NULL, sessionKeys.aes_key, sessionKeys.iv))

        error("Decrypt init failed");



    if(1 != EVP_DecryptUpdate(sessionKeys.dec_ctx, plaintext, &len, ciphertext, ciphertext_len))

        error("Decrypt update failed");

    plaintext_len = len;



    if(1 != EVP_DecryptFinal_ex(sessionKeys.dec_ctx, plaintext + len, &len))

        error("Decrypt final failed");

    plaintext_len += len;



    return plaintext_len;

}



// Initialize server network

int initServerNet(int port) {

    int reuse = 1;

    struct sockaddr_in serv_addr;

    listensock = socket(AF_INET, SOCK_STREAM, 0);

    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (listensock < 0)

        error("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    serv_addr.sin_addr.s_addr = INADDR_ANY;

    serv_addr.sin_port = htons(port);

    if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)

        error("ERROR on binding");

    fprintf(stderr, "listening on port %i...\n", port);

    listen(listensock, 1);

    socklen_t clilen;

    struct sockaddr_in cli_addr;

    sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);

    if (sockfd < 0)

        error("error on accept");

    close(listensock);

    fprintf(stderr, "connection made, starting session...\n");

    return 0;

}



// Initialize client network

int initClientNet(char *hostname, int port) {

    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct hostent *server;

    if (sockfd < 0)

        error("ERROR opening socket");

    server = gethostbyname(hostname);

    if (server == NULL) {

        fprintf(stderr, "ERROR, no such host\n");

        exit(0);

    }

    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)

        error("ERROR connecting");

    return 0;

}



// Shutdown network connections

int shutdownNetwork() {

    shutdown(sockfd, 2);

    unsigned char dummy[64];

    ssize_t r;

    do {

        r = recv(sockfd, dummy, 64, 0);

    } while (r != 0 && r != -1);

    close(sockfd);

    return 0;

}



// Main function

int main(int argc, char *argv[]) {

    // Initialize crypto library

    init_crypto();



    static struct option long_opts[] = {

        {"connect", required_argument, 0, 'c'},

        {"listen", no_argument, 0, 'l'},

        {"port", required_argument, 0, 'p'},

        {"help", no_argument, 0, 'h'},

        {0, 0, 0, 0}

    };

    int port = 1337;

    char hostname[HOST_NAME_MAX + 1] = "localhost";

    int isclient = 1;

    int opt_index = 0;

    char c;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {

        switch (c) {

            case 'c':

                if (strnlen(optarg, HOST_NAME_MAX))

                    strncpy(hostname, optarg, HOST_NAME_MAX);

                break;

            case 'l':

                isclient = 0;

                break;

            case 'p':

                port = atoi(optarg);

                break;

            case 'h':

                printf("Usage: %s [OPTIONS]...\n"

                       "Secure chat (CCNY computer security project).\n\n"

                       "   -c, --connect HOST  Attempt a connection to HOST.\n"

                       "   -l, --listen        Listen for new connections.\n"

                       "   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"

                       "   -h, --help          show this message and exit.\n",

                       argv[0]);

                return 0;

            case '?':

                printf("Usage: %s [OPTIONS]...\n"

                       "Secure chat (CCNY computer security project).\n\n"

                       "   -c, --connect HOST  Attempt a connection to HOST.\n"

                       "   -l, --listen        Listen for new connections.\n"

                       "   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"

                       "   -h, --help          show this message and exit.\n",

                       argv[0]);

                return 1;

        }

    }



    if (isclient) {

        initClientNet(hostname, port);

    } else {

        initServerNet(port);

    }



    // GTK initialization and setup...

    GtkBuilder* builder;

    GObject* window;

    GObject* button;

    GObject* transcript;

    GObject* message;

    GError* error = NULL;



    gtk_init(&argc, &argv);

    builder = gtk_builder_new();

    if (gtk_builder_add_from_file(builder, "layout.ui", &error) == 0) {

        g_printerr("Error reading %s\n", error->message);

        g_clear_error(&error);

        return 1;

    }



    mark = gtk_text_mark_new(NULL, TRUE);

    window = gtk_builder_get_object(builder, "window");

    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    transcript = gtk_builder_get_object(builder, "transcript");

    tview = GTK_TEXT_VIEW(transcript);

    message = gtk_builder_get_object(builder, "message");

    tbuf = gtk_text_view_get_buffer(tview);

    mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));

    button = gtk_builder_get_object(builder, "send");

    g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));

    gtk_widget_grab_focus(GTK_WIDGET(message));

    GtkCssProvider* css = gtk_css_provider_new();

    gtk_css_provider_load_from_path(css, "colors.css", NULL);

    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),

        GTK_STYLE_PROVIDER(css),

        GTK_STYLE_PROVIDER_PRIORITY_USER);



    // Setup styling tags for transcript text buffer

    gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "font", "italic", NULL);

    gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "font", "bold", NULL);

    gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "font", "bold", NULL);



    // Start receiver thread:

    pthread_t trecv;

    if (pthread_create(&trecv, 0, recvMsg, 0)) {

        fprintf(stderr, "Failed to create update thread.\n");

    }



    gtk_main();

    shutdownNetwork();

    cleanup_crypto();

    return 0;

}



// Append message to transcript with optional styling

static void tsappend(char* message, char** tagnames, int ensurenewline) {

    GtkTextIter t0;

    gtk_text_buffer_get_end_iter(tbuf, &t0);

    size_t len = g_utf8_strlen(message, -1);

    if (ensurenewline && message[len - 1] != '\n')

        message[len++] = '\n';

    gtk_text_buffer_insert(tbuf, &t0, message, len);

    GtkTextIter t1;

    gtk_text_buffer_get_end_iter(tbuf, &t1);

    t0 = t1;

    gtk_text_iter_backward_chars(&t0, len);

    if (tagnames) {

        char** tag = tagnames;

        while (*tag) {

            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);

            tag++;

        }

    }

    if (!ensurenewline) return;

    gtk_text_buffer_add_mark(tbuf, mark, &t1);

    gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);

    gtk_text_buffer_delete_mark(tbuf, mark);

}



// Send message function

static void sendMessage(GtkWidget* w, gpointer data) {

    char* tags[2] = { "self", NULL };

    tsappend("me: ", tags, 0);

    GtkTextIter mstart;

    GtkTextIter mend;

    gtk_text_buffer_get_start_iter(mbuf, &mstart);

    gtk_text_buffer_get_end_iter(mbuf, &mend);

    char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);

    size_t len = g_utf8_strlen(message, -1);



    // Encrypt the message

    unsigned char ciphertext[BUFFER_SIZE];

    int ciphertext_len = encrypt_message((unsigned char*)message, len, ciphertext);



    // Send the encrypted message

    ssize_t nbytes;

    if ((nbytes = send(sockfd, ciphertext, ciphertext_len, 0)) == -1)

        error("send failed");



    tsappend(message, NULL, 1);

    free(message);

    gtk_text_buffer_delete(mbuf, &mstart, &mend);

    gtk_widget_grab_focus(GTK_WIDGET(message));

}



// Show new message function

static gboolean shownewmessage(gpointer msg) {

    char* tags[2] = { "friend", NULL };

    char* friendname = "mr. friend: ";

    tsappend(friendname, tags, 0);

    char* message = (char*)msg;

    tsappend(message, NULL, 1);

    free(message);

    return 0;

}



// Receive message function

void* recvMsg(void*) {

    size_t maxlen = 512;

    unsigned char msg[maxlen + 2];

    ssize_t nbytes;

    while (1) {

        if ((nbytes = recv(sockfd, msg, maxlen, 0)) == -1)

            error("recv failed");

        if (nbytes == 0) {

            return 0;

        }

        char* decrypted_msg = (char*)malloc(maxlen + 2);

        if (!decrypted_msg) {

            error("malloc failed");

        }



        // Decrypt the received message

        int decrypted_len = decrypt_message(msg, nbytes, (unsigned char*)decrypted_msg);

        decrypted_msg[decrypted_len] = '\0'; // Null-terminate the decrypted message



        g_main_context_invoke(NULL, shownewmessage, (gpointer)strdup(decrypted_msg));

        free(decrypted_msg);

    }

    return 0;

}

