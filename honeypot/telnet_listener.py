"""Telnet login decoy listener."""

import socket
import threading

from config import HONEYPOT_HOST, TELNET_PORT
from honeypot.listener_utils import ThreadLimitedTCPListenerMixin
from honeypot.logger import event_logger


class TelnetListener(ThreadLimitedTCPListenerMixin):
    service = "TELNET"

    def __init__(self, host=HONEYPOT_HOST, port=TELNET_PORT):
        self.host = host
        self.port = port
        self._socket = None
        self._stop_event = threading.Event()
        self._init_client_limiter()

    @staticmethod
    def _read_line(client, maximum=4096):
        data = bytearray()
        while len(data) < maximum:
            chunk = client.recv(1)
            if not chunk or chunk in (b"\n", b"\x00"):
                break
            if chunk != b"\r" and chunk[0] >= 32:
                data.extend(chunk)
        return data.decode("utf-8", errors="replace").strip()

    def serve_forever(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(1)
        try:
            server.bind((self.host, self.port))
            server.listen(100)
            self._socket = server
            event_logger.info(f"Telnet honeypot listening on {self.host}:{self.port}")
            while not self._stop_event.is_set():
                try:
                    client, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not self._stop_event.is_set():
                        event_logger.warning("Telnet listener accept failed")
                    break
                self._start_client_thread(client, address)
        except OSError as exc:
            event_logger.warning(
                f"Telnet honeypot could not bind to {self.host}:{self.port}: {exc}"
            )
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._socket = None

    def _handle_client(self, client, address):
        username = ""
        password = ""
        raw_lines = []
        client.settimeout(20)
        try:
            client.sendall(b"Ubuntu 22.04 LTS\r\nlogin: ")
            username = self._read_line(client)[:256]
            raw_lines.append(username)
            client.sendall(b"Password: ")
            password = self._read_line(client)[:256]
            raw_lines.append(password)
            client.sendall(b"\r\nLogin incorrect\r\n")
        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            pass
        finally:
            event_logger.log_event(
                address[0],
                self.port,
                self.service,
                username_tried=username,
                password_tried=password,
                raw_data="\n".join(raw_lines),
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
