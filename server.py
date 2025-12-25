#!/usr/bin/env python3

import socket
import threading
import json
import time
import uuid
import os
import pty
import select
import logging
import sys
import subprocess
import fcntl
import struct
import termios

try:
    import paramiko
    from paramiko import ServerInterface, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED
except ImportError:
    print("Error: pip3 install paramiko")
    sys.exit(1)

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

logging.basicConfig(
    level=logging.DEBUG if TUNNEL_CONFIG['enable_logging'] else logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def get_server_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '0.0.0.0'


def bind_listen_socket(host, port, stream=True, backlog=200, retries=10):
    for i in range(retries + 1):
        p = port + i
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if stream else socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if stream:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.bind((host, p))
            if stream:
                sock.listen(backlog)
            return sock, p
        except OSError as e:
            if e.errno == 98:
                try:
                    sock.close()
                except:
                    pass
                continue
            raise
    raise OSError(f"Ports {port}-{port+retries} unavailable")


class TunnelManager:
    def __init__(self):
        self.tunnels = {}
        self.lock = threading.Lock()

    def create_tunnel(self, client_addr, client_socket):
        username = f"t{uuid.uuid4().hex[:10]}"
        password = uuid.uuid4().hex[:12]
        tunnel = {
            'id': uuid.uuid4().hex[:8],
            'username': username,
            'password': password,
            'client_socket': client_socket,
            'active': True,
            'ssh_connections': {},
            'lock': threading.Lock(),
        }
        with self.lock:
            self.tunnels[username] = tunnel
        logger.info(f"Tunnel created: {username}")
        return tunnel

    def get_tunnel(self, username):
        with self.lock:
            return self.tunnels.get(username)

    def remove_tunnel(self, username):
        with self.lock:
            tunnel = self.tunnels.pop(username, None)
            if tunnel:
                tunnel['active'] = False
                for conn_id, conn_data in list(tunnel['ssh_connections'].items()):
                    try:
                        if 'channel' in conn_data:
                            conn_data['channel'].close()
                        if 'shell_pid' in conn_data:
                            os.kill(conn_data['shell_pid'], 9)
                    except:
                        pass
                try:
                    tunnel['client_socket'].close()
                except:
                    pass
                logger.info(f"Tunnel removed: {username}")


class SSHServer(ServerInterface):
    def __init__(self, tunnel_manager):
        self.tunnel_manager = tunnel_manager
        self.username = None
        self.tunnel = None
        self.auth_event = threading.Event()
        self.channel_event = threading.Event()

    def check_auth_password(self, username, password):
        tunnel = self.tunnel_manager.get_tunnel(username)
        if tunnel and tunnel['password'] == password:
            self.username = username
            self.tunnel = tunnel
            self.auth_event.set()
            logger.info(f"Auth success: {username}")
            return AUTH_SUCCESSFUL
        logger.warning(f"Auth failed: {username}")
        return AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        logger.debug(f"PTY request: {term} {width}x{height}")
        return True

    def check_channel_shell_request(self, channel):
        self.channel_event.set()
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        logger.debug(f"Window resize: {width}x{height}")
        return True


class SSHHandler:
    def __init__(self, client, addr, tunnel_manager, host_key):
        self.client = client
        self.addr = addr
        self.manager = tunnel_manager
        self.host_key = host_key
        self.running = True
        self.conn_id = uuid.uuid4().hex[:6]
        try:
            self.client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)
            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 524288)
        except:
            pass

    def handle(self):
        transport = None
        channel = None
        tunnel = None
        try:
            logger.info(f"SSH connection: {self.addr}")
            transport = paramiko.Transport(self.client)
            transport.add_server_key(self.host_key)
            transport.set_keepalive(TUNNEL_CONFIG['keepalive_interval'])
            transport.window_size = 2097152
            transport.max_packet_size = 32768
            server = SSHServer(self.manager)
            transport.start_server(server=server)
            if not server.auth_event.wait(30):
                return
            tunnel = server.tunnel
            channel = transport.accept(30)
            if not channel:
                return
            if not server.channel_event.wait(30):
                return

            # Create PTY and fork shell
            master_fd, slave_fd = pty.openpty()
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            shell_pid = os.fork()
            if shell_pid == 0:
                os.close(master_fd)
                os.setsid()
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                if slave_fd > 2:
                    os.close(slave_fd)
                env = os.environ.copy()
                env['TERM'] = 'xterm-256color'
                shell = env.get('SHELL', '/bin/bash')
                os.execve(shell, [shell, '-l'], env)
            
            os.close(slave_fd)
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            conn_data = {
                'channel': channel,
                'master_fd': master_fd,
                'shell_pid': shell_pid,
            }
            with tunnel['lock']:
                tunnel['ssh_connections'][self.conn_id] = conn_data
            logger.info(f"Shell started: PID {shell_pid}")
            self._send_to_client(tunnel, {
                'type': 'connected',
                'conn_id': self.conn_id
            })
            self._io_loop(channel, master_fd, tunnel)
        except Exception as e:
            logger.error(f"SSH error: {e}", exc_info=True)
        finally:
            self._cleanup(tunnel, channel, transport)

    def _send_to_client(self, tunnel, msg):
        try:
            data = json.dumps(msg).encode('utf-8') + b'\n'
            tunnel['client_socket'].sendall(data)
        except Exception as e:
            logger.debug(f"Send error: {e}")

    def _io_loop(self, channel, master_fd, tunnel):
        last_activity = time.time()
        try:
            channel.setblocking(0)
        except:
            pass
        while self.running and not channel.closed and tunnel['active']:
            try:
                r_list = [channel, master_fd]
                r, _, _ = select.select(r_list, [], [], TUNNEL_CONFIG['select_timeout'])

                # PTY output -> SSH channel + control client
                if master_fd in r:
                    try:
                        chunks = []
                        while True:
                            try:
                                data = os.read(master_fd, 4096)
                                if not data:
                                    break
                                chunks.append(data)
                            except (BlockingIOError, OSError):
                                break
                        if chunks:
                            all_data = b''.join(chunks)
                            # Send to SSH client
                            if not channel.closed:
                                try:
                                    sent = 0
                                    while sent < len(all_data):
                                        n = channel.send(all_data[sent:])
                                        if n <= 0:
                                            break
                                        sent += n
                                except Exception as e:
                                    logger.debug(f"Channel send error: {e}")
                            # Send to control client
                            msg = {
                                'type': 'input',
                                'conn_id': self.conn_id,
                                'data': all_data.decode('utf-8', errors='replace')
                            }
                            self._send_to_client(tunnel, msg)
                            last_activity = time.time()
                    except Exception as e:
                        logger.debug(f"PTY read error: {e}")
                        break

                # SSH channel input -> PTY
                if channel in r and not channel.closed:
                    try:
                        chunks = []
                        while channel.recv_ready():
                            data = channel.recv(4096)
                            if not data:
                                break
                            chunks.append(data)
                        if chunks:
                            all_data = b''.join(chunks)
                            os.write(master_fd, all_data)
                            last_activity = time.time()
                    except Exception as e:
                        logger.debug(f"Channel read error: {e}")
                        break

                if time.time() - last_activity > TUNNEL_CONFIG['idle_timeout']:
                    logger.info(f"Idle timeout: {self.conn_id}")
                    break
            except Exception as e:
                logger.debug(f"Select error: {e}")
                break

    def _cleanup(self, tunnel, channel, transport):
        self.running = False
        if tunnel:
            with tunnel['lock']:
                conn_data = tunnel['ssh_connections'].pop(self.conn_id, None)
                if conn_data:
                    try:
                        if 'master_fd' in conn_data:
                            os.close(conn_data['master_fd'])
                    except:
                        pass
                    try:
                        if 'shell_pid' in conn_data:
                            os.kill(conn_data['shell_pid'], 9)
                            os.waitpid(conn_data['shell_pid'], os.WNOHANG)
                    except:
                        pass
                    self._send_to_client(tunnel, {
                        'type': 'disconnected',
                        'conn_id': self.conn_id
                    })
        for obj in [channel, transport, self.client]:
            if obj:
                try:
                    obj.close()
                except:
                    pass
        logger.info(f"Cleaned up: {self.conn_id}")


class ControlHandler:
    def __init__(self, conn, addr, tunnel_manager):
        self.conn = conn
        self.addr = addr
        self.manager = tunnel_manager
        self.running = True
        self.tunnel = None

    def handle(self):
        try:
            logger.info(f"Control client: {self.addr}")
            self.tunnel = self.manager.create_tunnel(self.addr, self.conn)
            response = {
                'type': 'tunnel_created',
                'tunnel_id': self.tunnel['id'],
                'username': self.tunnel['username'],
                'password': self.tunnel['password'],
                'ssh_host': get_server_ip(),
                'ssh_port': TUNNEL_CONFIG['ssh_port']
            }
            self.conn.sendall(json.dumps(response).encode('utf-8') + b'\n')
            buffer = b''
            while self.running and self.tunnel['active']:
                try:
                    r, _, _ = select.select([self.conn], [], [], 0.1)
                    if r:
                        data = self.conn.recv(65536)
                        if not data:
                            break
                        buffer += data
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            if not line:
                                continue
                            try:
                                msg = json.loads(line)
                                msg_type = msg.get('type')
                                if msg_type == 'output':
                                    conn_id = msg.get('conn_id')
                                    output = msg.get('data', '')
                                    with self.tunnel['lock']:
                                        conn_data = self.tunnel['ssh_connections'].get(conn_id)
                                        if conn_data and 'master_fd' in conn_data:
                                            try:
                                                data_bytes = output.encode('utf-8')
                                                os.write(conn_data['master_fd'], data_bytes)
                                                logger.debug(f"Wrote to PTY: {len(data_bytes)} bytes")
                                            except Exception as e:
                                                logger.error(f"PTY write error: {e}")
                                elif msg_type == 'resize':
                                    conn_id = msg.get('conn_id')
                                    rows = msg.get('rows', 24)
                                    cols = msg.get('cols', 80)
                                    with self.tunnel['lock']:
                                        conn_data = self.tunnel['ssh_connections'].get(conn_id)
                                        if conn_data and 'master_fd' in conn_data:
                                            try:
                                                fcntl.ioctl(
                                                    conn_data['master_fd'],
                                                    termios.TIOCSWINSZ,
                                                    struct.pack('HHHH', rows, cols, 0, 0)
                                                )
                                                logger.debug(f"PTY resized: {cols}x{rows}")
                                            except Exception as e:
                                                logger.debug(f"Resize error: {e}")
                                elif msg_type == 'pong':
                                    pass
                            except json.JSONDecodeError:
                                pass
                except Exception as e:
                    logger.debug(f"Control loop error: {e}")
                    break
        except Exception as e:
            logger.error(f"Control error: {e}", exc_info=True)
        finally:
            self._cleanup()

    def _cleanup(self):
        self.running = False
        if self.tunnel:
            self.manager.remove_tunnel(self.tunnel['username'])


class SSHZServer:
    def __init__(self):
        self.tunnel_manager = TunnelManager()
        self.running = False
        self.host_key = self._setup_host_key()

    def _setup_host_key(self):
        key_path = 'tunnel_host_key'
        try:
            if os.path.exists(key_path):
                return paramiko.RSAKey.from_private_key_file(key_path)
            else:
                key = paramiko.RSAKey.generate(2048)
                key.write_private_key_file(key_path)
                logger.info("Generated host key")
                return key
        except Exception as e:
            logger.error(f"Host key error: {e}")
            sys.exit(1)

    def _start_ssh_server(self):
        try:
            sock, port = bind_listen_socket(TUNNEL_CONFIG['host'], TUNNEL_CONFIG['ssh_port'])
            logger.info(f"SSH Server: port {port}")
            while self.running:
                try:
                    client, addr = sock.accept()
                    handler = SSHHandler(client, addr, self.tunnel_manager, self.host_key)
                    thread = threading.Thread(target=handler.handle, daemon=True)
                    thread.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
        except Exception as e:
            logger.error(f"SSH server error: {e}")

    def _start_control_server(self):
        try:
            sock, port = bind_listen_socket(TUNNEL_CONFIG['host'], TUNNEL_CONFIG['control_port'])
            logger.info(f"Control Server: port {port}")
            while self.running:
                try:
                    conn, addr = sock.accept()
                    handler = ControlHandler(conn, addr, self.tunnel_manager)
                    thread = threading.Thread(target=handler.handle, daemon=True)
                    thread.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
        except Exception as e:
            logger.error(f"Control server error: {e}")

    def start(self):
        self.running = True
        print("\n" + "=" * 60)
        print("SSHZ TUNNEL SERVER")
        print("=" * 60)
        print(f"IP: {get_server_ip()}")
        print(f"SSH: {TUNNEL_CONFIG['ssh_port']}")
        print(f"Control: {TUNNEL_CONFIG['control_port']}")
        print("=" * 60 + "\n")
        ssh_thread = threading.Thread(target=self._start_ssh_server, daemon=True)
        control_thread = threading.Thread(target=self._start_control_server, daemon=True)
        ssh_thread.start()
        control_thread.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutdown...")
            self.running = False


if __name__ == "__main__":
    server = SSHZServer()
    server.start()