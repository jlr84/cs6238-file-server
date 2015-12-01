# CS6238-Distributed-System
# README.md
# CS6238, Project II, Distributed System
# Last Updated: 15 Nov 2015
# James Roberts | Lei Zhang

This is a project folder for CS6238, Fall Semester 2015; any students currently taking this course who happen to find this github repository should use their own work. If any of this is utilzed, please cite this source. 


Here are step by step instructions for compiling and running this program:
1) Install OPENSSL Library, if not already installed:
  $sudo apt-get install libssl-dev

2) Compile "server.c" and "client.c" program, using flags for ssl, and crypto libraries; or using Makefile:
  $gcc server.c -lssl -lcrypto -o server
  $gcc client.c -lssl -lcrypto -o client
  $make

3) Generate keys and certificates for CA, server, and clients in directory cert with linux bash script cert.sh:
  $./cert.sh

4) Execute program:
  a) Start server:
  $./server

  b) Start client:
    $./client 127.0.0.1 7777 sslv3
