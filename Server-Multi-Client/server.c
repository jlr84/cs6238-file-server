#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/wait.h>  
#include <unistd.h>  
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>  
#include <openssl/err.h>
#include <pthread.h>
  
#define MAXBUF 1024  
#define NUMT 10
  
#define SERVER_CERT_FILE "cert/server.pem"  
#define SERVER_KEY_FILE  "cert/server.key"

static void *recv_data(SSL *ssl, BIO *client)
{
    char buffer[MAXBUF];
    int len = 0;

    //Get Client hostname for use
    memset(buffer,0,1024);
    len = BIO_read(client,buffer,1024);
    printf("%s\n",buffer);

    for(;;)
    {
        memset(buffer,0,1024);
        len = BIO_read(client,buffer,1024);
        switch(SSL_get_error(ssl,len))
        {
            case SSL_ERROR_NONE:
                break;
            default:
                printf("Read Problem!\n");
                exit(0);
        }
        if(!strcmp(buffer,"\r\n")||!strcmp(buffer,"\n"))
        {
            break;
        }
        if(buffer[0]=='q') 
        {
            break;
        }                       
        BIO_write(client,buffer,len);
        printf("%s\n",buffer);
    }
} 
      
int main(int argc, char **argv)  
{  
    char buf[MAXBUF + 1];
    char *hostname;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sslbio, *accept, *client;
    pid_t pid;
    int len;
  
    /* SSL Initialization */  
    SSL_library_init();  
    /* Load SSL algorithm */  
    OpenSSL_add_all_algorithms();  
    /* Load SSL error message */  
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();  
    /* Generate SSL_CTX with SSLV2 or SSLV3 (SSL Content Text) */   
    ctx = SSL_CTX_new(SSLv23_server_method());  
  
    if (ctx == NULL) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  
    /* Load Certificate for Client */  
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  
    /* Load Private Key */  
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  
    /* Check Private Key Validity */  
    if (!SSL_CTX_check_private_key(ctx)) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  

    printf("Attempting to create BIO object... ");
    /* 0 indicate using server mode */
    ssl=SSL_new(ctx);//added
    sslbio = BIO_new_ssl(ctx, 0);
    accept = BIO_new_accept("7777");
    if(sslbio == NULL)
    {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }

    printf("Attempting to set up BIO for SSL...\n");
    //BIO_get_ssl(sslbio, &ssl);
    BIO_set_accept_bios(accept,sslbio);

    if (BIO_do_accept(accept) <= 0)
    {
        printf("Error binding server socket");
    }

    printf("Waiting for incoming connection...\n");

    
    while(1)
    {
    	/*Waiting for a new connection to establish*/
        if(BIO_do_accept(accept) <= 0)
    	{
                    printf("BIO_do_accept(accept) <= 0\n");
        	    ERR_print_errors_fp(stdout);
        	    SSL_CTX_free(ctx);
        	    BIO_free_all(sslbio);
        	    BIO_free_all(accept);
        	    return 1;
    	}
    	client = BIO_pop(accept);

        pid = fork();
        if (pid == -1)
            printf("fork error\n");
        else if (pid == 0)
        {
            if(BIO_do_handshake(client) <= 0)
    	    {
        		printf("Handshake failed.\n");
        		ERR_print_errors_fp(stdout);
        		SSL_CTX_free(ctx);
        		BIO_free_all(sslbio);
        		BIO_free_all(accept);
        		return 1;
    	    }

            recv_data(ssl, client);
        }

        BIO_free(client);
    	BIO_ssl_shutdown(sslbio);
    	//exit(0);
    }
    
    BIO_ssl_shutdown(sslbio);
    BIO_free_all(sslbio);
    BIO_free_all(accept);
    SSL_CTX_free(ctx);
    return 0;  
} 
