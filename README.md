

# vmwcerts

This webapp retrieves certifications for different candidates from CertMetrics portal using native APIs and builds a graphical representation of current status of certifications within the organization.

It is built to run in a Docker container, but can be easily run anywhere Python is installed, locally on a PC or on a remote server.

# Install

### Run in Docker

Use provided docker-compose.yml and specify the following Environmental Variables:

* HOST: FQDN for the application (if you're using Traefik)
* PATH: folder on your docker server where to save stateful data


### Run locally

Simply run `python3 serve.py` and open browser at `http://localhost:8765`