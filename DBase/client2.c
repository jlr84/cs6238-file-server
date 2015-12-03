#include <stdio.h>
#include <mysql.h>
#define def_host_name "localhost"
#define def_user_name "root"
#define def_password "rootpwd"
#define def_db_name NULL

MYSQL *conn;

int main (int argc, char *argv[])
{
    conn = mysql_init (NULL);
    if (conn == NULL)
    {
	fprintf (stderr, “mysql_init() failed (probably out of memory)\n”);
	exit (1);
    }
    if (mysql_real_connect (
	conn,
	def_host_name,
	def_user_name,
	def_password,
	def_db_name,
	0,
	NULL,
	0)
	== NULL)
    {
	fprintf (stderr, “mysql_real_connect() failed:\nError %u (%s)\n”, 
				mysql_errno (conn), mysql_error (conn));
	exit (1);
    }
    mysql_close (conn);
    exit (0);
}
