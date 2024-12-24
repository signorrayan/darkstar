#!/bin/bash

echo '[+] Building the container...'
docker build -t pwnpatrol .

if [ "$(docker ps -aq -f name=pwnpatrol)" ]; then
    echo '[+] Container with name pwnpatrol already exists. Starting the container...'
    docker start pwnpatrol
else
    echo '[+] Starting a new container...'
    docker run -d --name pwnpatrol pwnpatrol
fi
sleep 5
if [ "$1" == "install" ]; then
    echo '[+] Setting up the database...'
    docker exec -it pwnpatrol /bin/bash -c 'mariadb < /install/setup_script.sql'
else
    echo 'Please run with `install` to set up the database.'
fi

echo '[+] Entering the container...'
docker exec -it pwnpatrol /bin/bash
