#!/bin/bash

#Define directory and file location 
caPath="./demoCA/"
certPath="./demoCA/newcerts/"
caKey="../cert/ca.key"
caCRT="../cert/ca.crt"
caPEM="../cert/ca.pem"
serverKey="../cert/server.key"
serverCSR="../cert/server.csr"
serverCRT="../cert/server.crt"
serverPEM="../cert/server.pem"
clientKey="../cert/client.key"
clientCSR="../cert/client.csr"
clientCRT="../cert/client.crt"
clientPEM="../cert/client.pem"

#Required
commonname="CA"
sercommonname="Server"
clicommonname="Client"

#Change to your details
country=US
state=Georgia
city=Atlanta
organization=GATech
organizationalunit=MASTER
email=gatech@gatech.edu

#Optional
password=mypassword

if [ ! -d "$caPath" ]; then  
    mkdir "$caPath"
    mkdir "$certPath"
    touch "./demoCA/index.txt"
    touch "./demoCA/serial"
    echo 01 > "./demoCA/serial"
fi

#CA Key and Certificate Generation Process

if [ ! -f "$caKey" ]; then
    #Generate a key
    echo "Generating key request for CA"
    openssl genrsa -des3 -passout pass:$password -out $caKey 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $caKey -passin pass:$password -out $caKey  
fi

if [ ! -f "$caCRT" ]; then  
    #Generate CA Certificate
    echo "Generate CA Certificate"
    openssl req -new -x509 -key $caKey -out $caCRT -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
fi

if [ ! -f "$caPEM" ]; then  
    #Generate PEM Certificate
    echo "Generate PEM Certificate"
    cat $caCRT $caKey > $caPEM
fi

#Server Key and Certificate Generation Process

if [ ! -f "$serverKey" ]; then
    #Generate a key
    echo "Generating key request for Server"
    openssl genrsa -des3 -passout pass:$password -out $serverKey 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $serverKey -passin pass:$password -out $serverKey  
fi

if [ ! -f "$serverCSR" ]; then  
    #Generate Server CSR File
    echo "Generate Server CSR"
    openssl req -new -key $serverKey -out $serverCSR -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$sercommonname/emailAddress=$email"
fi

if [ ! -f "$serverCRT" ]; then  
    #Generate Server CSR File
    echo "Generate Server Certificate Signed by CA"
    echo -e 'y\ny' | openssl ca -in $serverCSR -out $serverCRT -cert $caCRT -keyfile $caKey
fi

if [ ! -f "$serverPEM" ]; then  
    #Generate PEM Certificate
    echo "Generate Server PEM Certificate"
    cat $serverCRT $serverKey > $serverPEM
fi

#Client Key and Certificate Generation Process
if [ ! -f "$clientKey" ]; then
    #Generate a key
    echo "Generating key request for Client"
    openssl genrsa -des3 -passout pass:$password -out $clientKey 2048 -noout

    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $clientKey -passin pass:$password -out $clientKey  
fi

if [ ! -f "$clientCSR" ]; then  
    #Generate Client CSR File
    echo "Generate Client CSR"
    openssl req -new -key $clientKey -out $clientCSR -days 3650 -subj "/C=$country/ST=$state/L=$city/O=$organization/OU=$organizationalunit/CN=$clicommonname/emailAddress=$email"
fi

if [ ! -f "$clientCRT" ]; then  
    #Generate Client CRT File
    echo "Generate Client Certificate Signed by CA"
    echo -e 'y\ny' | openssl ca -in $clientCSR -out $clientCRT -cert $caCRT -keyfile $caKey
fi

if [ ! -f "$clientPEM" ]; then  
    #Generate PEM Certificate
    echo "Generate Client PEM Certificate"
    cat $clientCRT $clientKey > $clientPEM
fi

echo "Start to delete redundant files"
rm -rf $caCRT $serverCSR $serverCRT $clientCSR $clientCRT $caPath
