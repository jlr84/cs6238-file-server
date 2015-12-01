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
  
#define CA_CERT_FILE     "cert/ca.pem"  
#define CLIENT_KEY_FILE  "cert/client.key"  
#define CLIENT_CERT_FILE "cert/client.pem"  
  
#define printk printf

char *menu[] = {
    "a - Check-in",
    "b - Check-out",
    "c - Delegate",
    "d - Safe-delete",
    "q - Terminate",
    NULL,
};

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

  
int main(int argc, char **argv)  
{
    BIO *sslbio;
    SSL_CTX *ctx;  
    SSL *ssl;  
    //SSL_METHOD *meth;  
    unsigned long totl;  
    int i, p;
    char hostname[BUF_SIZE + 1];
    char choice;
    int ret;    

  
    if (argc != 4) {  
        printf("Usage: %s IP port sslv3|tls\n", argv[0]);  
        printf("eg: 192.168.201.94 7777 sslv3\n");  
        return -1;  
    }

    if( gethostname(hostname,sizeof(hostname)) )
    {
        printf("gethostname error\n");
        return -1;
    }
    printf("localhost name:%s\n",hostname);
      
    SSL_library_init();  
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();  
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    //sslbio = BIO_new(BIO_s_connect());
      
    if (strcmp(argv[3], "sslv3") == 0) {  
        //meth = SSLv3_client_method();
        ctx = SSL_CTX_new(SSLv3_client_method());
    } else if (strcmp(argv[3], "tls") == 0) {  
        //meth = TLSv1_client_method();  
        ctx = SSL_CTX_new(SSLv3_client_method());
    } else {  
        printf("Unknow command.\r\n");  
        return -1;  
    }  
      
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
  
    BIO_set_conn_hostname(sslbio, "127.0.0.1:7777");
    //unsigned long ladd = inet_addr("127.0.0.1");
    //BIO_set_conn_ip(sslbio, &ladd);
    //BIO_set_conn_port(sslbio, "7777");
    //BIO_set_conn_hostname(sslbio, "localhost");

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
  
    /*for (i = 0; i < 5; i++)
    {
        printf("Please input:\n");
	scanf("%s",&buffer[0]);
        BIO_write(sslbio, buffer, strlen(buffer));
        p = BIO_read(sslbio, buffer, BUF_SIZE);
        if(p <= 0)
        {
            break;
        }
        buffer[p] = '\0';
        printf("%s\n", buffer);
        memset(buffer, '\0', BUF_SIZE);
    }*/

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
    return 0;  
} 
