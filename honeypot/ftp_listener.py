"""FTP credential decoy listener."""

import socket
import threading

from config import FTP_PORT, HONEYPOT_HOST, MAX_RAW_DATA_LENGTH
from honeypot.listener_utils import ThreadLimitedTCPListenerMixin
from honeypot.logger import event_logger


class FTPListener(ThreadLimitedTCPListenerMixin):
    service = "FTP"

    def __init__(self, host=HONEYPOT_HOST, port=FTP_PORT):
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
            event_logger.info(f"FTP honeypot listening on {self.host}:{self.port}")
            while not self._stop_event.is_set():
                try:
                    client, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not self._stop_event.is_set():
                        event_logger.warning("FTP listener accept failed")
                    break
                self._start_client_thread(client, address)
        except OSError as exc:
            event_logger.warning(
                f"FTP honeypot could not bind to {self.host}:{self.port}: {exc}"
            )
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._socket = None

    def _handle_client(self, client, address):
        raw_lines = []
        username = ""
        password = ""
        commands = []
        client.settimeout(20)
        try:
            client.sendall(b"220 FTP Server Ready\r\n")
            buffer = b""
            while len(raw_lines) < 50:
                data = client.recv(4096)
                if not data:
                    break
                buffer += data
                if len(buffer) > MAX_RAW_DATA_LENGTH:
                    raw_lines.append(
                        buffer[:MAX_RAW_DATA_LENGTH].decode(
                            "utf-8", errors="replace"
                        )
                    )
                    break
                while b"\n" in buffer:
                    line_bytes, buffer = buffer.split(b"\n", 1)
                    line = line_bytes.rstrip(b"\r").decode(
                        "utf-8", errors="replace"
                    )
                    raw_lines.append(line)
                    command, _, argument = line.partition(" ")
                    command = command.upper()
                    if command == "USER":
                        username = argument[:256]
                        client.sendall(b"331 Password required\r\n")
                    elif command == "PASS":
                        password = argument[:256]
                        client.sendall(b"530 Login incorrect\r\n")
                    elif command == "QUIT":
                        client.sendall(b"221 Goodbye\r\n")
                        return
                    else:
                        commands.append(line[:1024])
                        client.sendall(b"530 Please login with USER and PASS\r\n")
        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            pass
        finally:
            event_logger.log_event(
                address[0],
                self.port,
                self.service,
                username_tried=username,
                password_tried=password,
                command_tried="; ".join(commands),
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
