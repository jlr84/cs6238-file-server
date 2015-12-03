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
    mysql_real_connect (
	conn,
	def_host_name,
	def_user_name,
	def_password,
	def_db_name,
	0,
	NULL,
	0);
    mysql_close (conn);
    exit (0);
}
