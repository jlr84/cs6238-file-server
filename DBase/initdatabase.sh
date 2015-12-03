#!/bin/bash

# Filename: initdatabase.sh | Script for initialization of mysql database for Project2
# Created by James Roberts on 2 December 2015
# Last Updated: 2 December 2015

# This installs the necessary dependencies for mysql required for CS6238 Project 2
# This is written assuming the user has NOT previously installed mysql on the host system.
# NOTE: This was configured for use on Ubuntu (specifically Ubuntu 14.04 LTS, 32-bit). 
# Recommned updating Ubuntu with "sudo apt-get update" prior to running this script. 

clear
printf "Configuring MySql for Project 2.\n"
printf "Note: 'sudo' is required, so you will be asked for your SUDO password during the configuration.\n"
printf "Press Enter to proceed: ...\n"
read
printf ": Current Working Directory is: \n"
pwd
printf "\n: Installing dependencies.\n\n"
sudo apt-get install libmysqlclient-dev mysql-server
printf "\n: Installs complete. Moving on.\n\n"

printf ": Starting MySQL.\n"
sudo service mysql start

printf "\n: Setting up MySQL.\n"
printf ": ... Running MySQL secure installaion\n"
printf ": NOTE: Enter settings here to configure MySQL securely.\n"
printf ": ... Recommend setting root password, removing anonymous users, disallowing root login remotely, removing test database, and reloading the privilege tables.\n"
printf "Press Enter to proceed: ...\n"
read
sudo mysql_secure_installation
printf "\n\n: MySQL secure installation complete.\n\n"

printf "\n: Applying Project 2-specific configurations to MySQL.\n\n"
printf ": Creating/updating MySQL user 'project2user' and creating/updating database 'filedata' for use within Project2.\n\n"
while true; do
    printf "SELECT MySQL password for user 'project2user': \n"
    read -s USER_PASSWORD
    printf "CONFIRM password for user 'project2user': \n"
    read -s USER_VERIFY
    if [ $USER_PASSWORD == $USER_VERIFY ]; then
        printf "Passwords match. REMEMBER THIS PASSWORD.\n Continuing.\n\n"
        break
    else
        printf "Passwords do not match. Try again.\n"
    fi
done
printf "ENTER MYSQL ROOT PASSWORD to commit changes:\n"
printf "(creation/update of MySQL user 'project2user' and database 'filedata')\n"
while true; do
    mysql -uroot -p <<EOF
create database if not exists filedata;
\! printf ": Database 'filedata' created (or already present).\n"
grant all privileges on filedata.* to 'project2user'@'localhost' identified by '$USER_PASSWORD';
\! printf ": User created/updated and privileges granted to 'filedata' database.\n"
EOF
    if [ "$?" -ne "0" ]; then
        printf "MySQL root password incorrect.\n"
        printf "Re-try MySQL root password.\n"
    else
        break
    fi
done
printf "\n: MySQL configuration complete. \n Project 2 database and user initialized. \n REMEMBER, you will need the password for 'project2user' you just created when running the Project 2 'server' that is part of this project.\n\n"

