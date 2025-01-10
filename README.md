# Automatic propagation
Vulnerability Scanning tool

Tools needed for installation
- docker
- docker compose (https://docs.docker.com/compose/install/)

## Setup with docker
1. `chmod +x run.sh`
2. `./run.sh`

### Inside the container
For this setup the database name needs to be `test` it will fail otherwise or you need to create a new database, see [setup_script](setup/setup_script.sql) only change the name of the database.
To run the tool you could use a command like this:
`python3 main.py -t example.com -m 2 -d test`