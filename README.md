# sshz-python

<p align="center">
  <img src="https://github.com/Mytai20100/sshz-python/blob/main/resource/logo.png" alt="SSHZ Logo" width="400"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.14+-blue.svg" alt="Python Version"/>
  <img src="https://img.shields.io/badge/version-0.1--alpha-orange.svg" alt="Version"/>
  <img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status"/>
  <img src="https://img.shields.io/badge/tests-passing-brightgreen.svg" alt="Tests"/>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"/>
</p>

## Overview

SSHZ is a lightweight SSH tunnel server that creates temporary SSH access points. It allows you to establish SSH connections through a custom control protocol, making it easy to create on-demand SSH tunnels.

## Features

- Dynamic SSH tunnel creation
- Real PTY support with shell execution
- Multiple simultaneous connections
- Automatic credential generation
- Terminal resize support
- Low latency I/O forwarding

## Requirements

- Python 3.8 or higher
- paramiko library

## Installation

```bash
git clone https://github.com/Mytai20100/sshz-python.git
cd sshz-python
pip3 install -r requirements.txt
```

## Usage

### Start the Server

```bash
python3 server.py
```

The server will start on:
- SSH Port: 2223
- Control Port: 7777

### Connect with Client

```bash
python3 index.py <server_ip> <control_port>
```

Example:
```bash
python3 index.py 127.0.0.1 7777
```

The client will display SSH credentials:
```
Tunnel ready: ssh t4f95e427ca@127.0.0.1 -p 2223
Password: d0a198975098
```

### Connect via SSH

Use any SSH client to connect:
```bash
ssh <username>@<server_ip> -p 2223
```

Or use PuTTY, SecureCRT, or any other SSH client.

## Configuration

Edit the `TUNNEL_CONFIG` dictionary in `server.py`:

```python
TUNNEL_CONFIG = {
    'host': '0.0.0.0',
    'ssh_port': 2223,
    'control_port': 7777,
    'buffer_size': 65536,
    'enable_logging': True,
    'select_timeout': 0.01,
    'keepalive_interval': 30,
    'idle_timeout': 3600,
}
```

## Architecture

```
┌─────────────────┐         ┌──────────────────┐
│  Control Client │         │   SSHZ Server    │
│   (index.py)    │◄───────►│   - SSH Server   │
│                 │  Socket │   - PTY Manager  │
└─────────────────┘         │   - Shell Fork   │
                            └────────┬─────────┘
                                     │
                            ┌────────▼─────────┐
                            │   SSH Clients    │
                            │  (PuTTY, etc.)   │
                            └──────────────────┘
```

## How It Works

1. Control client connects to the server
2. Server generates temporary credentials
3. Server creates PTY and forks shell process
4. SSH clients can connect using generated credentials
5. All I/O is forwarded between SSH client, PTY, and control client
6. Multiple clients can interact with the same shell session

## Security Notes

This is an alpha version intended for development and testing purposes. For production use:
- Use strong authentication
- Enable firewall rules
- Use encrypted connections
- Implement rate limiting
- Add access control lists

## License

[MIT License](https://github.com/Mytai20100/sshz-python/blob/main/LICENSE)

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## Author

[mytai20100](https://github.com/mytai20100)

## Support

For issues and questions, please open an issue on GitHub.
