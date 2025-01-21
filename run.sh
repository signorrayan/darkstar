#!/bin/bash

#? Setup the docker 
echo '[+] Building the pwnpatrol docker with all the tools inside'
docker compose -f docker-compose.yaml up -d --build

#? Setup openvas docker
echo '[+] Building the OpenVAS docker'
docker compose -f docker-compose.openvas.yaml up -d --build

#? Start the custom api service
echo '[+] Starting API Service OpenVAS'
docker exec automatic-propagation-gvmd-1 /bin/sh -c "apt update && apt install python3-pip -y && python3 -m pip install gvm-tools Flask requests && python3 /opt/openvas_api.py && tail -f /dev/null" &

echo '[+] Cleaning up'
sleep 5
clear

echo '[+] Starting interactive shell inside the container'
docker exec -it pwnpatrol /bin/bash