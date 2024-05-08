#include <gtk/gtk.h>

#include <glib/gunicode.h> /* for utf8 strlen */

#include <sys/socket.h>

#include <netinet/in.h>

#include <netdb.h>

#include <openssl/rand.h>

#include <openssl/aes.h>

#include <openssl/hmac.h>

#include <pthread.h>

#include <getopt.h>

#include "dh.h"

#include "keys.h"



#ifndef PATH_MAX

#define PATH_MAX 1024

#define AES_KEYLEN 128  // Key length for AES encryption (in bits)

#define HMAC_KEYLEN 256  // Key length for HMAC (in bits)

#define BLOCK_SIZE 16  // AES block size (in bytes)

#define SHA256_DIGEST_LENGTH 32  // Length of SHA256 digest (in bytes)

#define MAX_USERS 10 // Maximum number of users in the chat

#endif



unsigned char key[256];

unsigned char iv[256];





static GtkTextBuffer* tbuf; /* transcript buffer */

static GtkTextBuffer* mbuf; /* message buffer */

static GtkTextView*  tview; /* view for transcript */

static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */



static pthread_t trecv;     /* wait for incoming messages and post to queue */

void* recvMsg(void*);       /* for trecv */



#define max(a, b)         \

    ({ typeof(a) _a = a;    \

     typeof(b) _b = b;    \

     _a > _b ? _a : _b; })



/* network stuff... */



static int listensock, sockfd;

static int isclient = 1;



static void error(const char *msg)

{

    perror(msg);

    exit(EXIT_FAILURE);

}



int initServerNet(int port)

{

    int reuse = 1;

    struct sockaddr_in serv_addr;

    listensock = socket(AF_INET, SOCK_STREAM, 0);

    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* NOTE: might not need the above if you make sure the client closes first */

    if (listensock < 0)

        error("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    serv_addr.sin_addr.s_addr = INADDR_ANY;

    serv_addr.sin_port = htons(port);

    if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)

        error("ERROR on binding");

    fprintf(stderr, "listening on port %i...\n",port);

    listen(listensock,1);

    socklen_t clilen;

    struct sockaddr_in  cli_addr;

    sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);

    if (sockfd < 0)

        error("error on accept");

    close(listensock);

    fprintf(stderr, "connection made, starting session...\n");

    /* at this point, should be able to send/recv on sockfd */

    return 0;

}



static int initClientNet(char* hostname, int port)

{

    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct hostent *server;

    if (sockfd < 0)

        error("ERROR opening socket");

    server = gethostbyname(hostname);

    if (server == NULL) {

        fprintf(stderr,"ERROR, no such host\n");

        exit(0);

    }

    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

    serv_addr.sin_port = htons(port);

    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)

        error("ERROR connecting");

    /* at this point, should be able to send/recv on sockfd */

    return 0;

}



static int shutdownNetwork()

{

    shutdown(sockfd,2);

    unsigned char dummy[64];

    ssize_t r;

    do {

        r = recv(sockfd,dummy,64,0);

    } while (r != 0 && r != -1);

    close(sockfd);

    return 0;

}



/* end network stuff. */



typedef struct {

    char name[MAX_NAME];

    dhKey keyPair; // Diffie-Hellman key pair

} User;



User users[MAX_USERS]; // Array to store users



void initializeUsers() {

    for (int i = 0; i < MAX_USERS; i++) {

        strcpy(users[i].name, "User"); // Default user name

        initKey(&(users[i].keyPair)); // Initialize key pair for each user

    }

}





static const char* usage =

"Usage: %s [OPTIONS]...\n"

"Secure chat (CCNY computer security project).\n\n"

"   -c, --connect HOST  Attempt a connection to HOST.\n"

"   -l, --listen        Listen for new connections.\n"

"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"

"   -h, --help          show this message and exit.\n";



/* Append message to transcript with optional styling.  NOTE: tagnames, if not

 * NULL, must have it's last pointer be NULL to denote its end.  We also require

 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then

 * a newline may be added at the end of the string (possibly overwriting the \0

 * char!) and the view will be scrolled to ensure the added line is visible.  */

static void tsappend(char* message, char** tagnames, int ensurenewline)

{

    GtkTextIter t0;

    gtk_text_buffer_get_end_iter(tbuf,&t0);

    size_t len = g_utf8_strlen(message,-1);

    if (ensurenewline && message[len-1] != '\n')

        message[len++] = '\n';

    gtk_text_buffer_insert(tbuf,&t0,message,len);

    GtkTextIter t1;

    gtk_text_buffer_get_end_iter(tbuf,&t1);

    /* Insertion of text may have invalidated t0, so recompute: */

    t0 = t1;

    gtk_text_iter_backward_chars(&t0,len);

    if (tagnames) {

        char** tag = tagnames;

        while (*tag) {

            gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);

            tag++;

        }

    }

    if (!ensurenewline) return;

    gtk_text_buffer_add_mark(tbuf,mark,&t1);

    gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);

    gtk_text_buffer_delete_mark(tbuf,mark);

}



// Function to generate a random key

static void generateRandomKey(unsigned char *key, size_t keylen) {

    RAND_bytes(key, keylen);

}



// Function to encrypt plaintext using AES in CBC mode

static int encryptAES(const unsigned char *plaintext, size_t plaintext_len, unsigned char *key,

                      unsigned char *iv, unsigned char *ciphertext) {

    AES_KEY aesKey;

    if (AES_set_encrypt_key(key, AES_KEYLEN, &aesKey) < 0) {

        return -1;

    }

    AES_cbc_encrypt(plaintext, ciphertext, plaintext_len, &aesKey, iv, AES_ENCRYPT);

    return 0;

}



// Function to decrypt ciphertext using AES in CBC mode

static int decryptAES(const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key,

                      unsigned char *iv, unsigned char *plaintext) {

    AES_KEY aesKey;

    if (AES_set_decrypt_key(key, AES_KEYLEN, &aesKey) < 0) {

        return -1;

    }

    AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &aesKey, iv, AES_DECRYPT);

    return 0;

}



// Function to generate a message authentication code (HMAC) for the given message and key

static int generateMAC(const unsigned char *message, size_t message_len, unsigned char *key,

                       unsigned char *mac, unsigned int *mac_len) {

    HMAC(EVP_sha256(), key, HMAC_KEYLEN, message, message_len, mac, mac_len);

    return 0;

}



// Function to verify the message authentication code (HMAC) for the given message and key

static int verifyMAC(const unsigned char *message, size_t message_len, unsigned char *key,

                     unsigned char *mac, unsigned int mac_len) {

    unsigned char calculatedMac[EVP_MAX_MD_SIZE];

    unsigned int calculatedMacLen;

    HMAC(EVP_sha256(), key, HMAC_KEYLEN, message, message_len, calculatedMac, &calculatedMacLen);

    if (calculatedMacLen != mac_len) {

        return 0; // MAC length mismatch

    }

    return CRYPTO_memcmp(mac, calculatedMac, mac_len) == 0;

}



// Function to perform encryption and MAC on the message

static int encryptAndAuthenticate(const unsigned char *plaintext, size_t plaintext_len,

                                   unsigned char *encryptionKey, unsigned char *hmacKey,

                                   unsigned char *iv, unsigned char *ciphertext, unsigned char *mac) {

    // Encrypt the plaintext

    if (encryptAES(plaintext, plaintext_len, encryptionKey, iv, ciphertext) < 0) {

        return -1;

    }

    // Generate HMAC

    generateMAC(ciphertext, plaintext_len, hmacKey, mac, NULL);

    return 0;

}



// Function to verify authenticity and decrypt the message

static int authenticateAndDecrypt(const unsigned char *ciphertext, size_t ciphertext_len,

                                   unsigned char *encryptionKey, unsigned char *hmacKey,

                                   unsigned char *iv, unsigned char *plaintext, unsigned char *receivedMac) {

    // Verify HMAC

    if (!verifyMAC(ciphertext, ciphertext_len, hmacKey, receivedMac, SHA256_DIGEST_LENGTH)) {

        return -1; // Message authentication failed

    }

    // Decrypt the ciphertext

    if (decryptAES(ciphertext, ciphertext_len, encryptionKey, iv, plaintext) < 0) {

        return -1;

    }

    return 0;

}



// Initialize encryption and HMAC keys

unsigned char encryptionKey[AES_KEYLEN / 8];

unsigned char hmacKey[HMAC_KEYLEN / 8];



// Append message to transcript with optional styling

static void tsappend(char* message, char** tagnames, int ensurenewline) {

    GtkTextIter t0;

	gtk_text_buffer_get_end_iter(tbuf,&t0);

	size_t len = g_utf8_strlen(message,-1);

	if (ensurenewline && message[len-1] != '\n')

		message[len++] = '\n';

	gtk_text_buffer_insert(tbuf,&t0,message,len);

	GtkTextIter t1;

	gtk_text_buffer_get_end_iter(tbuf,&t1);

	/* Insertion of text may have invalidated t0, so recompute: */

	t0 = t1;

	gtk_text_iter_backward_chars(&t0,len);

	if (tagnames) {

		char** tag = tagnames;

		while (*tag) {

			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);

			tag++;

		}

	}

	if (!ensurenewline) return;

	gtk_text_buffer_add_mark(tbuf,mark,&t1);

	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);

	gtk_text_buffer_delete_mark(tbuf,mark);

}



// Send encrypted message

static void sendEncryptedMessage(const unsigned char *plaintext, size_t plaintext_len) {

    unsigned char iv[BLOCK_SIZE];

    unsigned char ciphertext[plaintext_len];

    unsigned char mac[SHA256_DIGEST_LENGTH];

    generateRandomKey(iv, BLOCK_SIZE);



    // Encrypt and authenticate the message

    if (encryptAndAuthenticate(plaintext, plaintext_len, encryptionKey, hmacKey, iv, ciphertext, mac) < 0) {

        fprintf(stderr, "Failed to encrypt and authenticate message.\n");

        return;

    }



    // Send the ciphertext and MAC

    ssize_t nbytes;

    if ((nbytes = send(sockfd, ciphertext, plaintext_len, 0)) == -1) {

        error("send failed");

    }

    if ((nbytes = send(sockfd, mac, SHA256_DIGEST_LENGTH, 0)) == -1) {

        error("send failed");

    }



    // Append the message to the transcript

    tsappend("me (encrypted): ", NULL, 0);

    tsappend((char *)ciphertext, NULL, 0);

}



// Receive and decrypt message

static void receiveAndDecryptMessage() {

    size_t maxlen = 512;

    unsigned char iv[BLOCK_SIZE];

    unsigned char ciphertext[maxlen];

    unsigned char plaintext[maxlen];

    unsigned char receivedMac[SHA256_DIGEST_LENGTH];

    ssize_t nbytes;



    // Receive the ciphertext

    if ((nbytes = recv(sockfd, ciphertext, maxlen, 0)) == -1) {

        error("recv failed");

    }

    // Receive the MAC

    if ((nbytes = recv(sockfd, receivedMac, SHA256_DIGEST_LENGTH, 0)) == -1) {

        error("recv failed");

    }



    // Decrypt and authenticate the message

    if (authenticateAndDecrypt(ciphertext, nbytes, encryptionKey, hmacKey, iv, plaintext, receivedMac) < 0) {

        fprintf(stderr, "Failed to authenticate and decrypt message.\n");

        return;

    }



    // Append the decrypted message to the transcript

    tsappend("friend (decrypted): ", NULL, 0);

    tsappend((char *)plaintext, NULL, 0);

}



static void sendMessage(GtkWidget* w, gpointer data)

{

    char* tags[2] = {"self", NULL};

    tsappend("me: ", tags, 0);

    GtkTextIter mstart; // start of message pointer

    GtkTextIter mend;   // end of message pointer

    gtk_text_buffer_get_start_iter(mbuf, &mstart);

    gtk_text_buffer_get_end_iter(mbuf, &mend);

    char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);

    size_t len = g_utf8_strlen(message, -1);

    // XXX we should probably do the actual network stuff in a different

    // thread and have it call this once the message is actually sent.

    ssize_t nbytes;

    if ((nbytes = send(sockfd, message, len, 0)) == -1)

        error("send failed");



    tsappend(message, NULL, 1);

    free(message);

    // clear message text and reset focus

    gtk_text_buffer_delete(mbuf, &mstart, &mend);

    gtk_widget_grab_focus(w);

}



static gboolean shownewmessage(gpointer msg)

{

    char* tags[2] = {"friend", NULL};

    char* friendname = "mr. friend: ";

    tsappend(friendname, tags, 0);

    char* message = (char*)msg;

    tsappend(message, NULL, 1);

    free(message);

    return 0;

}



int main(int argc, char *argv[])

{

    initializeUsers(); // Initialize users and their key pairs



    if (init("params") != 0) {

        fprintf(stderr, "could not read DH params from file 'params'\n");

        return 1;

    }

    // define long options

    static struct option long_opts[] = {

        {"connect",  required_argument, 0, 'c'},

        {"listen",   no_argument,       0, 'l'},

        {"port",     required_argument, 0, 'p'},

        {"help",     no_argument,       0, 'h'},

        {0,0,0,0}

    };

    // process options:

    char c;

    int opt_index = 0;

    int port = 1337;

    char hostname[HOST_NAME_MAX+1] = "localhost";

    hostname[HOST_NAME_MAX] = 0;

    



    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {

        switch (c) {

            case 'c':

                if (strnlen(optarg,HOST_NAME_MAX))

                    strncpy(hostname,optarg,HOST_NAME_MAX);

                break;

            case 'l':

                isclient = 0;

                break;

            case 'p':

                port = atoi(optarg);

                break;

            case 'h':

                printf(usage,argv[0]);

                return 0;

            case '?':

                printf(usage,argv[0]);

                return 1;

        }

    }

    /* NOTE: might want to start this after gtk is initialized so you can

     * show the messages in the main window instead of stderr/stdout.  If

     * you decide to give that a try, this might be of use:

     * https://docs.gtk.org/gtk4/func.is_initialized.html */

    if (isclient) {

        initClientNet(hostname,port);

    } else {

        initServerNet(port);

    }



    // Initialize encryption and HMAC keys

    generateRandomKey(encryptionKey, AES_KEYLEN / 8);

    generateRandomKey(hmacKey, HMAC_KEYLEN / 8);



    /* setup GTK... */

    GtkBuilder* builder;

    GObject* window;

    GObject* button;

    GObject* transcript;

    GObject* message;

    GError* error = NULL;

    gtk_init(&argc, &argv);

    builder = gtk_builder_new();

    if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {

        g_printerr("Error reading %s\n", error->message);

        g_clear_error(&error);

        return 1;

    }

    mark  = gtk_text_mark_new(NULL,TRUE);

    window = gtk_builder_get_object(builder,"window");

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

    gtk_css_provider_load_from_path(css,"colors.css",NULL);

    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),

            GTK_STYLE_PROVIDER(css),

            GTK_STYLE_PROVIDER_PRIORITY_USER);



    /* setup styling tags for transcript text buffer */

    gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);

    gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);

    gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);



    /* start receiver thread: */

    if (pthread_create(&trecv,0,recvMsg,0)) {

        fprintf(stderr, "Failed to create update thread.\n");

    }



    gtk_main();



    shutdownNetwork();

    return 0;

}



/* thread function to listen for new messages and post them to the gtk

 * main loop for processing: */

void* recvMsg(void*)

{

    size_t maxlen = 512;

    char msg[maxlen+2]; /* might add \n and \0 char */

    ssize_t nbytes;

    while (1) {

        if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)

            error("recv failed");

        if (nbytes == 0) {

            /* XXX maybe show in a status message that the other

             * side has disconnected. */

            return 0;

        }

        char* m = malloc(maxlen+2);

        memcpy(m,msg,nbytes);

        if (m[nbytes-1] != '\n')

            m[nbytes++] = '\n';

        m[nbytes] = 0;

        g_main_context_invoke(NULL,shownewmessage,(gpointer)m);

    }

    return 0;

}

