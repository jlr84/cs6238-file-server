#include <my_global.h>
#include <mysql.h>
#include <string.h>
#include <stdlib.h>

void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);        
}

///ALTERNATE STRING SPLIT - Splits string to tokens based on delimiter
char **str_split_alt(const char* str, const char* delim, size_t* numtokens) {

    // copy the original string so that we don't overwrite parts of it
    // (don't do this if you don't need to keep the old line,
    // as this is less efficient)
    char *s = strdup(str);

    // these three variables are part of a very common idiom to
    // implement a dynamically-growing array

    size_t tokens_alloc = 1;
    size_t tokens_used = 0;
    char **tokens = calloc(tokens_alloc, sizeof(char*));
    char *token, *strtok_ctx;
    for (token = strtok_r(s, delim, &strtok_ctx);
            token != NULL;
            token = strtok_r(NULL, delim, &strtok_ctx)) {
        // check if we need to allocate more space for tokens
        if (tokens_used == tokens_alloc) {
            tokens_alloc *= 2;
            tokens = realloc(tokens, tokens_alloc * sizeof(char*));
        }
        tokens[tokens_used++] = strdup(token);
    }

    // cleanup
    if (tokens_used == 0) {
        free(tokens);
        tokens = NULL;
    } else {
        tokens = realloc(tokens, tokens_used * sizeof(char*));
    }
    *numtokens = tokens_used;
    free(s);
    return tokens;
}

///STRING SPLIT to Integer - Split comma separated string into integers
int str_to_ints(char* fstring, int features[]) {

    //char *line = "18,10,-2,20,10,4,2,8,6,17,23,20,27,7";
//    size_t linelen;

    char **tokens2;
    size_t numtokens;

    tokens2 = str_split_alt(fstring, ";", &numtokens);

    size_t i;
    for ( i = 0; i < numtokens; i++) {
//        printf("    token: \"%s\"\n", tokens2[i]);
        features[i] = atoi(tokens2[i]);
        free(tokens2[i]);
    }

    return numtokens;
}



int main(int argc, char **argv)
{      
  MYSQL *con = mysql_init(NULL);
  
  if (con == NULL)
  {
      fprintf(stderr, "mysql_init() failed\n");
      exit(1);
  }  
  
  if (mysql_real_connect(con, "localhost", "user12", "34klq*", 
          "testdb", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }    
  
  if (mysql_query(con, "SELECT * FROM Cars")) 
  {
      finish_with_error(con);
  }
  
  MYSQL_RES *result = mysql_store_result(con);
  
  if (result == NULL) 
  {
      finish_with_error(con);
  }

  int num_fields = mysql_num_fields(result);
  int num_rows = mysql_num_rows(result);
  printf("Num_Rows: %d\n", num_rows);

  MYSQL_ROW row;
  char onerow[1048];
  onerow[0] = '\0';
  int car_id, car_cost;
  char car_name[1048];
  char list[1048];
  memset(list, '\0', sizeof(list));
  
  while ((row = mysql_fetch_row(result))) 
  { 
      memset(onerow, '\0', sizeof(onerow));

      strncat(list, row[0], strlen(row[0]) + 1);
      strncat(list, ";", 2);
      for(int i = 0; i < num_fields; i++) 
      { 
          printf("%s ", row[i] ? row[i] : "NULL");
          strncat(onerow, row[i], strlen(row[i]) +2);
	  strncat(onerow, ") ", 3);
      } 
          printf("\n"); 
          printf("Onerow: %s\n",onerow);
      printf("LIST: \n%s\n",list);
//      snprintf(list, sizeof(list), "%d) %s) %d)", car_id, car_name, car_cost);
   } 
    int features[1048];

    int numtokens = str_to_ints(list, features);
    printf("Number of Tokens: %d\n",numtokens);
    int i;
    for ( i = 0; i < numtokens; i++) {
        printf("Integer %d: %d\n",i+1,features[i]);
    }   


  
   
  mysql_free_result(result);
  mysql_close(con);
  
  exit(0);
}
