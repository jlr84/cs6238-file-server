#include <stdio.h>  
#include <string.h>
#include <unistd.h>
#include <errno.h>  
#include <assert.h>  
#include <sys/socket.h>  
#include <stdlib.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h>  
#include <openssl/err.h>  
  
#define BUF_SIZE   (4 * 1024)  
static char buffer[BUF_SIZE + 1];
#define NAME_SIZE  32
static char CLIENT_NAME[NAME_SIZE];
 
#define CA_CERT_FILE     "cert/ca.pem"  
#define printk printf
#define OK       0
#define NO_INPUT 1
#define TOO_LONG 2

char *menu[] = {
    "a - Check-in",
    "b - Check-out",
    "c - Delegate",
    "d - Safe-delete",
    "q - Terminate",
    NULL,
};

char *imenu[] = {
    "a - Init-session",
    "q - Terminate",
    NULL,
};


static int getLine (char *prmpt, char *buff, size_t sz) {
    int ch, extra;

    // Get line with buffer overrun protection.
    if (prmpt != NULL) {
        printf ("%s", prmpt);
        fflush (stdout);
    }
    if (fgets (buff, sz, stdin) == NULL)
        return NO_INPUT;

    // If it was too long, there'll be no newline. In that case, we flush
    // to end of line so that excess doesn't affect the next call.
    if (buff[strlen(buff)-1] != '\n') {
        extra = 0;
        while (((ch = getchar()) != '\n') && (ch != EOF))
            extra = 1;
        return (extra == 1) ? TOO_LONG : OK;
    }

    // Otherwise remove newline and give string back to caller.
    buff[strlen(buff)-1] = '\0';
    return OK;
}

/* Function to get user input up to size 'max */
void getInput(char *input, char *greet, int max)
{
    int rc = 1;
 
    while (rc > 0) { 
    	printf("%s: \n(Max size %d)\n", greet, max);

        rc = getLine ("Enter input> ", input, max);
        if (rc == NO_INPUT) {
            // Extra NL since my system doesn't output that on EOF.
            printf ("\nNo input\n");
        }
        if (rc == TOO_LONG) {
            printf ("Input too long [%s]\n", input);
        }
	else {
            printf ("OK [%s]\n", input);
	}
    }
    printf("You entered: %s\n", input);
   // return name;
}

void ShowCerts(SSL * ssl)  
{  
    X509 *cert;  
    char *line;  
  
    cert = SSL_get_peer_certificate(ssl);  
    if (cert != NULL) {  
        printf("certificate info:\n");  
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  
        printf("certificate: %s\n", line);  
        free(line);  
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);  
        printf("author: %s\n", line);  
        free(line);  
        X509_free(cert);  
    } else {  
        printf("nothing\n");  
    }  
}

char getchoice(char *greet, char *choices[])
{
    int chosen = 0;
    char selected;
    char **option;

    do {
        printf("Choice: %s\n",greet);
        option = choices;
        while(*option) {
            printf("%s\n",*option);
            option++;
        }
        selected = getchar();
        getchar();
        option = choices;
        while(*option) {
            //printf("The option is %c\n", *option[0]);
            if(selected == *option[0]) {
                chosen = 1;
                break;
            }
            option++;
        }
        if(!chosen) {
            printf("Incorrect choice, select again\n");
        }
    } while(!chosen);
    return selected;
}

void choiceProcess (BIO *sslbio, char *buffer, char choice)
{
    int length;

    memset(buffer, '\0', BUF_SIZE);
    buffer[0] = choice;
    BIO_write(sslbio, buffer, strlen(buffer));
    length = BIO_read(sslbio, buffer, BUF_SIZE);
    if(length <= 0)
    {
        strcpy(buffer, "No message");
        length = strlen(buffer);
    }
    buffer[length] = '\0';
    printf("%s\n", buffer);
}

void clientTerminate (BIO *sslbio, char *buffer)
{
    buffer[0] = 'q';
    BIO_write(sslbio, buffer, strlen(buffer));
    memset(buffer, '\0', BUF_SIZE);
}

// This is a function helper that sends the buffer 
int send_buffer(SSL* ssl, const unsigned char* buffer, int buf_len){
   int ret;

   /* Sending the buffer length */
/*   ret = SSL_write(ssl, &buf_len, sizeof(buf_len));
   if(ret < sizeof(buf_len)){
      fprintf(stderr, "Error: SSL_write returned %d\n", ret);
      fprintf(stderr, "SSL_get_error -> %d\n", SSL_get_error(ssl, ret));
      return 1;
   }
*/
   /* Sending the buffer content */
   ret = SSL_write(ssl, buffer, buf_len);
   if(ret < buf_len){
      fprintf(stderr, "Error: SSL_write returned %d\n", ret);
      fprintf(stderr, "SSL_get_error -> %d\n", SSL_get_error(ssl, ret));
      return 1;
   }

   return 0;
}
  

// This is a function that sends a file to the server
// - INPUT file_name = name of the file to be sent
// - INPUT sk = socket through which the file is sent
// - RETURNS 0 in case of success, 1 otherwise
int send_file(const char* file_name, SSL* ssl) {

   FILE* file;      // pointer to the file to be sent
   int msg_size;          // size of the file to be sent

   unsigned char* clear_buf; // buffer containing the plaintext
 //  BIO* bio;
 //  SSL_CTX* ctx;
 //  SSL* ssl;

   int ret;

   /* Open the file to be sent */
   file = fopen(file_name, "r");
   if(file == NULL) {
      fprintf(stderr, "File not found: '%s'\n", file_name);
      return 1;
   }

   /* Retrieve the file size */
   fseek(file, 0, SEEK_END);
   msg_size = ftell(file);
   fseek(file, 0, SEEK_SET);

   /* Reading the file to be sent */
   clear_buf = malloc(msg_size + 1);
   ret = fread(clear_buf, 1, msg_size, file);
   if(ret < msg_size) {
      fprintf(stderr, "Error reading the file\n");
      return 1;
   }
   clear_buf[msg_size] = '\0';
   fclose(file);

   printf("\nPlaintext to be sent:\n%s\n", clear_buf);


   //SSL_set_bio(ssl, bio, bio);

   /* Sending the file name */
   ret = send_buffer(ssl, (unsigned char*)file_name, strlen(file_name));
   if(ret != 0){
      fprintf(stderr, "Error trasmitting the file name\n ");
      return 1;
   }

   /* Sending the file */
   ret = send_buffer(ssl, clear_buf, msg_size);
   if(ret != 0) {
      fprintf(stderr, "Error transmitting the file\n ");
      return 1;
   }

   printf("\nFile %s sent:\n   original size is %d bytes.\n", file_name, msg_size);

   return 0;
}

// This is a function that checks out a file from the serverr
// - RETURNS 0 in case of success, 1 otherwise
int checkout_file(SSL* ssl) {

   FILE* file;            // pointer to the file to be received
   int ret;

   /* Sending the client name */
   ret = send_buffer(ssl, (unsigned char*)CLIENT_NAME, strlen(CLIENT_NAME));
   if(ret != 0){
      fprintf(stderr, "Error trasmitting the client name\n ");
      return 1;
   }

   return 0;
}
  
int main(int argc, char **argv)  
{
    BIO *sslbio;
    SSL_CTX *ctx;  
    SSL *ssl;  
    //SSL_METHOD *meth;  
    unsigned long totl;  
    int i, p;
    char hostname[BUF_SIZE + 1];
    char server[16];
    char choice;
    int ret;    

  
    if (argc != 2) {  
        printf("Usage: %s ClientName\n", argv[0]);  
        printf("eg: '%s client1'\n", argv[0]);  
        return -1;  
    }

    if( gethostname(hostname,sizeof(hostname)) )
    {
        printf("gethostname error\n");
        return -1;
    }
    printf("localhost name:%s\n",hostname);
    
    if (strlen(argv[0]) >= NAME_SIZE) {
        fprintf(stderr, "%s is too long! \nPick a shorter client name. (32 characters or less)\n",argv[1]);
    } else {
        strcpy(CLIENT_NAME, argv[1]);    
    }
    printf("client name: %s\n", CLIENT_NAME);

    /* Formatting required certificates for client ...
       certificates are matched to client with file names */
    char CLIENT_CERT_FILE[strlen(CLIENT_NAME + 10)];
    strcpy(CLIENT_CERT_FILE, "cert/");
    strcat(CLIENT_CERT_FILE, CLIENT_NAME);
    strcat(CLIENT_CERT_FILE, ".pem");
    printf("This client cert file is required: %s\n", CLIENT_CERT_FILE);
    /* Checking for required certificate */
    if( access( CLIENT_CERT_FILE, F_OK ) != -1 ) {
    // file exists
	printf("CERT file verified present\n");
    } else {
    // file doesn't exist
	printf("CERT NOT FOUND....\n"
		"Perhaps this client does not have valid\n"
		"certificates present at this location\n"
		">>> ./%s\n",CLIENT_CERT_FILE);
	exit(4);
    }
    char CLIENT_KEY_FILE[strlen(CLIENT_NAME + 10)];
    strcpy(CLIENT_KEY_FILE, "cert/");
    strcat(CLIENT_KEY_FILE, CLIENT_NAME);
    strcat(CLIENT_KEY_FILE, ".key");
    printf("This client KEY file is required: %s\n", CLIENT_KEY_FILE);
    /* Checking for required certificate */
    if( access( CLIENT_KEY_FILE, F_OK ) != -1 ) {
    // file exists
	printf("KEY file verified present\n");
    } else {
    // file doesn't exist
	printf("KEY NOT FOUND....\n"
		"Perhaps this client does not have valid"
		"certificates present at this location\n"
		">>> ./%s\n",CLIENT_KEY_FILE);
	exit(4);
    }


    /* Give initial menu to user; get hostname for connection */
    choice = getchoice("Please select an action", imenu);
    printf("You have chosen: %c\n", choice);
    if (choice == 'q')
    {
	printf("Ending Program... Goodbye.\n");
    } 
    else // choice == 'a' 
    {
	printf("Initializing connection...\n");
    
	// NOTE: 45 is the max length of a IPv4 address
        getInput(server, "Enter hostname to connect \n (e.g., '127.0.0.1')", 15);

    	SSL_library_init();  
    	ERR_load_BIO_strings();
    	ERR_load_SSL_strings();  
    	SSL_load_error_strings();
    	OpenSSL_add_all_algorithms();

    	ctx = SSL_CTX_new(SSLv3_client_method());
    	  
    	//ctx = SSL_CTX_new(meth);  
    	assert(ctx != NULL);  
          
    	/* Verify the server */  
    	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  
      
    	/* Load CA Certificate */  
    	if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)) {  
            printf("Load CA file failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
        }  
  
      
    	/* Load Client Certificate with Public Key */  
    	if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {  
            ERR_print_errors_fp(stdout);  
            printf("ssl_ctx_use_certificate_file failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;  
        }  
  
      
    	/* Load Private Key */  
    	if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {  
            ERR_print_errors_fp(stdout);  
            printf("ssl_ctx_use_privatekey_file failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
        }  
  
      
    	/* Check the validity of Private Key */  
    	if (!SSL_CTX_check_private_key(ctx)) {  
            ERR_print_errors_fp(stdout);  
            printf("ssl_ctx_check_private_key failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;  
    	}

    	/* Create the connection */
    	sslbio = BIO_new_ssl_connect(ctx);
    	/* Get SSL from sslbio */
    	BIO_get_ssl(sslbio, &ssl);
    	/* Set the SSL mode into SSL_MODE_AUTO_RETRY */
    	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
 
    	//////////////////////////////////////////////////
    	// NOTE: Port# hardcoded here; change if necessary
    	////////////////////////////////////////////////// 
    	BIO_set_conn_port(sslbio, "7777");
    	BIO_set_conn_hostname(sslbio, server);
	
	/* Request Connection */
	if(BIO_do_connect(sslbio) <= 0)
    	{
            fprintf(stderr, "Error attempting to connect\n");
            ERR_print_errors_fp(stderr);
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
    	}
    	else
    	{
            printf("connent to server successful!\n");
    	}

    	/* Verify Server Certificate Validity */
    	if(SSL_get_verify_result(ssl) != X509_V_OK)
    	{
            printf("Certificate Verification Error: %ld\n", SSL_get_verify_result(ssl));
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
    	}
    	else
    	{
    	    printf("verify server cert successful\n");
    	}

    	//Send hostname to server
    	printf("Send hostname to server:\n");
    	BIO_write(sslbio, hostname, strlen(hostname));
  
    	do
    	{
    	    choice = getchoice("Please select an action", menu);
    	    printf("You have chosen: %c\n", choice);
	
	    if (choice == 'a')
	    {
        	printf("Check-in function will be executed\n");
                choiceProcess (sslbio, buffer, choice);
                ret = send_file("testFile.txt", ssl);
            }
            else if (choice == 'b')
            {
                printf("Check-out function will be executed\n");
                choiceProcess (sslbio, buffer, choice);
		ret = checkout_file(ssl);
            }
            else if (choice == 'c')
            {
                printf("Delegate function will be executed\n");
                choiceProcess (sslbio, buffer, choice);
            }
            else if (choice == 'd')
            {
                printf("Safe-delete function will be executed\n");
                choiceProcess (sslbio, buffer, choice);
            }
            else
            {
                printf("Terminate function will be executed\n");
            }

        } while (choice != 'q');

        /* Terminate the connection by sending message */
        clientTerminate (sslbio, buffer);

        /* Close the connection and free the context */
        BIO_ssl_shutdown(sslbio);
        BIO_free_all(sslbio);
    	SSL_CTX_free(ctx);
    }

    return 0;  
} 
