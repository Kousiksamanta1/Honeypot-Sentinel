"""Raw TCP SSH decoy listener."""

import socket
import threading

from config import HONEYPOT_HOST, SSH_PORT
from honeypot.listener_utils import ThreadLimitedTCPListenerMixin
from honeypot.logger import event_logger


class SSHListener(ThreadLimitedTCPListenerMixin):
    service = "SSH"

    def __init__(self, host=HONEYPOT_HOST, port=SSH_PORT):
        self.host = host
        self.port = port
        self._socket = None
        self._stop_event = threading.Event()
        self._init_client_limiter()

    def serve_forever(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(1)
        try:
            server.bind((self.host, self.port))
            server.listen(100)
            self._socket = server
            event_logger.info(f"SSH honeypot listening on {self.host}:{self.port}")
            while not self._stop_event.is_set():
                try:
                    client, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not self._stop_event.is_set():
                        event_logger.warning("SSH listener accept failed")
                    break
                self._start_client_thread(client, address)
        except OSError as exc:
            event_logger.warning(
                f"SSH honeypot could not bind to {self.host}:{self.port}: {exc}"
            )
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._socket = None

    def _handle_client(self, client, address):
        raw_chunks = []
        username = ""
        password = ""
        commands = []
        client.settimeout(12)
        try:
            client.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
            while len(raw_chunks) < 20:
                try:
                    data = client.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                raw_chunks.append(data)
                decoded = data.decode("utf-8", errors="replace").strip()
                printable_lines = [
                    line.strip()
                    for line in decoded.replace("\x00", "").splitlines()
                    if line.strip()
                ]
                for line in printable_lines:
                    if not username:
                        username = line[:256]
                    elif not password:
                        password = line[:256]
                    else:
                        commands.append(line[:1024])
                try:
                    client.sendall(b"Authentication failed\r\n")
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            raw_data = b"".join(raw_chunks).decode("utf-8", errors="replace")
            event_logger.log_event(
                address[0],
                self.port,
                self.service,
                username_tried=username,
                password_tried=password,
                command_tried="; ".join(commands),
                raw_data=raw_data,
            )
            try:
                client.close()
            except OSError:
                pass

    def stop(self):
        self._stop_event.set()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
