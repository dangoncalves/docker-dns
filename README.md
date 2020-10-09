# Docker DNS

Docker DNS is a DNS server that resolve Docker's container name into
A record to retrieve IPv4 associated.

## Installation configuration and execution

First you need to clone this repository

```
git clone https://github.com/dangoncalves/docker-dns
```

Then change directory and install dependencies

```
cd docker-dns
poetry install
```

Execute the script as root (to bind on port 53)

```
python3 docker-dns.py
```

Finally you can edit `/etc/resolv.conf` and put that line at the file's begining
(don't remove other nameserver entries)

```
nameserver 127.0.0.1
```

## Options

There are three options you can use to customize execution:

 * `--port` customize the port docker-dns will listen on (default 53)
 * `--listen-address` customize the address docker-dns will listen on
   (default 127.0.0.1)
 * `--forwarders` dns forwarders' list (coma separated list)

## License

This project is under WTFPL

## TODO - Roadmap

The project's goal is just to resolve docker containers' name into IP address.
This first version do the job, but there are still some things to do like:
 * add a Dockerfile to start the server
 * add tests
 * add networks support
 * add AAAA queries support
 * add PTR queries support
 * add SRV queries support
 * add HEALTH CHECK support (do not resolve a container that is not healthy)
 * automate installation
 * improve documentation
 * add Windows and Mac OS support (tested only on Linux for now)
