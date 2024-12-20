#!/bin/bash
echo '[+] Building the container...'
docker build -t pwnpatrol .
echo '[+] Starting the container...'
docker run -d --name pwnpatrol pwnpatrol
echo '[+] Setting up the database...'
docker exec -it pwnpatrol /bin/bash -c 'mariadb < /install/setup_script.sql'
echo '[+] Entering the container...'
docker exec -it pwnpatrol /bin/bash
