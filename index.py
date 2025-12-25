#!/usr/bin/env python3

import socket
import json
import os
import sys
import time
import select
import termios
import struct
import fcntl
import signal

class SSHZClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.original_tty = None
        self.tunnel_info = None
        self.conn_id = None
        self.running = True

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 524288)
            self.socket.connect((self.server_host, self.server_port))
            data = self.socket.recv(65536).decode('utf-8')
            for line in data.split('\n'):
                if line:
                    try:
                        msg = json.loads(line)
                        if msg.get('type') == 'tunnel_created':
                            self.tunnel_info = msg
                            break
                    except:
                        pass
            if not self.tunnel_info:
                print("Error: Invalid tunnel info")
                return False
            print(f"\nTunnel ready: ssh {self.tunnel_info['username']}@{self.tunnel_info['ssh_host']} -p {self.tunnel_info['ssh_port']}")
            print(f"Password: {self.tunnel_info['password']}\n")
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def get_terminal_size(self):
        try:
            size = struct.unpack('HHHH', fcntl.ioctl(sys.stdin, termios.TIOCGWINSZ, b'\0' * 8))
            return size[0], size[1]
        except:
            return 24, 80

    def setup_tty(self):
        try:
            self.original_tty = termios.tcgetattr(sys.stdin)
            attrs = termios.tcgetattr(sys.stdin)
            attrs[0] &= ~(termios.BRKINT | termios.ICRNL | termios.ISTRIP | termios.IXON)
            attrs[1] &= ~(termios.OPOST)
            attrs[2] &= ~(termios.CSIZE | termios.CSTOPB | termios.PARENB)
            attrs[2] |= (termios.CS8)
            attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
            attrs[6][termios.VMIN] = 1
            attrs[6][termios.VTIME] = 0
            termios.tcsetattr(sys.stdin, termios.TCSANOW, attrs)
            signal.signal(signal.SIGWINCH, self.handle_sigwinch)
        except Exception as e:
            print(f"Warning: Could not setup TTY: {e}")

    def handle_sigwinch(self, _signum, _frame):
        rows, cols = self.get_terminal_size()
        if self.conn_id and self.socket:
            try:
                msg = json.dumps({
                    'type': 'resize',
                    'conn_id': self.conn_id,
                    'rows': rows,
                    'cols': cols
                }) + '\n'
                self.socket.sendall(msg.encode())
            except:
                pass

    def restore_tty(self):
        if self.original_tty:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSAFLUSH, self.original_tty)
            except:
                pass

    def run(self):
        if not self.connect():
            return
        self.setup_tty()
        print("Waiting for SSH connection...")
        buffer = ''
        try:
            while self.running:
                r_list = [self.socket]
                if self.conn_id:
                    r_list.append(sys.stdin)
                r, _, _ = select.select(r_list, [], [], 0.01)

                # Receive from server
                if self.socket in r:
                    try:
                        data = self.socket.recv(65536).decode('utf-8')
                        if not data:
                            break
                        buffer += data
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            if not line:
                                continue
                            try:
                                msg = json.loads(line)
                                msg_type = msg.get('type')
                                if msg_type == 'input':
                                    output = msg.get('data', '')
                                    if output:
                                        sys.stdout.write(output)
                                        sys.stdout.flush()
                                elif msg_type == 'connected':
                                    self.conn_id = msg.get('conn_id')
                                    print("\rSSH connected. Ready.\n")
                                    sys.stdout.flush()
                                elif msg_type == 'disconnected':
                                    if msg.get('conn_id') == self.conn_id:
                                        print("\nSSH disconnected.")
                                        self.conn_id = None
                                        break
                                elif msg_type == 'ping':
                                    self.socket.sendall(b'{"type":"pong"}\n')
                            except json.JSONDecodeError:
                                pass
                    except Exception as e:
                        print(f"\nSocket error: {e}")
                        break

                # Send user input to server
                if sys.stdin in r and self.conn_id:
                    try:
                        data = os.read(sys.stdin.fileno(), 4096)
                        if data:
                            msg = json.dumps({
                                'type': 'output',
                                'conn_id': self.conn_id,
                                'data': data.decode('utf-8', errors='replace')
                            }) + '\n'
                            self.socket.sendall(msg.encode())
                    except Exception as e:
                        print(f"\nstdin error: {e}")
                        break
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.cleanup()

    def cleanup(self):
        self.running = False
        self.restore_tty()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 index.py <server_ip> <server_port>")
        sys.exit(1)
    client = SSHZClient(sys.argv[1], int(sys.argv[2]))
    client.run()


if __name__ == "__main__":
    main()