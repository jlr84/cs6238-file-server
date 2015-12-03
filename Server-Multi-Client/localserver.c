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
#include <my_global.h>
#include <mysql.h>
  
#define MAXBUF 1024  
#define NUMT 10

#define MYSQL_USER       "project2user"  
#define SERVER_CERT_FILE "cert/server.pem"  
#define SERVER_KEY_FILE  "cert/server.key"

////////////////////////////////
//CLIENT-SIDE CODE INSERTED HERE
////////////////////////////////

#define BUF_SIZE (4 * 1024)
static char buffer[BUF_SIZE + 1];

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

//////////////////////////////////
//END OF CLIENT-SIDE CODE INSERTED
//////////////////////////////////
void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);        
}

static void process_input(MYSQL *con, SSL *ssl, BIO *client, char *choice)
{
    char buffer[MAXBUF];
    int len = 0;
    char query1[] = "SELECT Id, Name FROM Files WHERE Owner=";


    if (choice[0] == 'a')
    {
        printf("Check-in function executing\n");
        // Get the file name //
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
        BIO_write(client,buffer,len);
        printf("The file name being checked in:\n");
        printf("%s\n",buffer);
	// Get the file contents //
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
        BIO_write(client,buffer,len);
        printf("File contents:\n");
        printf("%s\n",buffer);

    }
    else if (choice[0] == 'b')
    {
        printf("Check-out function will be executed\n");
        // Get the client name //
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
        BIO_write(client,buffer,len);
        printf("The client name asking to check out file:\n");
        printf("%s\n",buffer);
	//Make query
	char newquery[strlen(buffer) + strlen(query1) +3];
        strcpy(newquery,query1);
	strcat(newquery,"'");
	strcat(newquery,buffer);
	strcat(newquery,"'");
  	if (mysql_query(con, newquery)) 
  	{
      	    finish_with_error(con);
        }
  	MYSQL_RES *result = mysql_store_result(con);
  	if (result == NULL) 
  	{
      	    finish_with_error(con);
  	}
        int num_fields = mysql_num_fields(result);
        MYSQL_ROW row;
  	while ((row = mysql_fetch_row(result))) 
  	{ 
	    int i;
            for( i = 0; i < num_fields; i++) 
      	    { 
          	printf("%s ", row[i] ? row[i] : "NULL"); 
      	    } 
            printf("\n"); 
  	}
    	mysql_free_result(result);


    }
    else if (choice[0] == 'c')
    {
        printf("Delegate function will be executed\n");
    }
    else if (choice[0] == 'd')
    {
        printf("Safe-delete function will be executed\n");
    } 
    else 
    {
	printf("UNKNOWN OPTION\n");
    }
}

static void *recv_data(MYSQL *con, SSL *ssl, BIO *client)
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
        printf("The buffer was the following:\n");
        printf("%s\n",buffer);
        process_input(con, ssl, client, buffer);
        printf("That was the end of the buffer.\n");
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

    if (argc != 2) {  
        printf("Usage: %s MysqlPassword\n", argv[0]);  
        printf("eg: '%s pr0ject2p@$$word'\n", argv[0]); 
        printf("(Reminder: You selected this on initial Project 2 install)\n"); 
        return -1;  
    }

    /* Mysql Initialization */
    printf("Connecting to database\n");
    MYSQL *con = mysql_init(NULL);
    if (con == NULL) 
    {
        fprintf(stderr, "%s\n", mysql_error(con));
        exit(1);
    }  

    if (mysql_real_connect(con, "localhost", MYSQL_USER, argv[1], 
          "filedata", 0, NULL, 0) == NULL) 
    {
        finish_with_error(con);
    }

  
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
        printf("Error binding server socket\n");
    }

    
    printf("Waiting for incoming connection...\n");
    while(1)
    {
    	//Waiting for a new connection to establish//
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

            recv_data(con, ssl, client);
        }

        BIO_free(client);
    	BIO_ssl_shutdown(sslbio);
    	//exit(0);
    }
    

////////////////////////////////////
// CLIENT-SIDE CODE INSERTED HERE //
////////////////////////////////////
/*    char choice;

    do
    {
        choice = getchoice("Please select an action", menu);
        printf("You have chosen: %c\n", choice);

        if (choice == 'a')
        {
            printf("Check-in function will be executed\n");
            choiceProcess (sslbio, buffer, choice);

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
/////////////////////////////
// END OF CLIENT-SIDE CODE //
/////////////////////////////
*/
    BIO_ssl_shutdown(sslbio);
    BIO_free_all(sslbio);
    BIO_free_all(accept);
    SSL_CTX_free(ctx);
    mysql_close(con);
    return 0;  
} 
