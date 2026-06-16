"""Minimal HTTP admin-login decoy listener."""

import json
import socket
import threading
from urllib.parse import parse_qs

from config import HONEYPOT_HOST, HTTP_MAX_BODY_BYTES, HTTP_MAX_HEADER_BYTES, HTTP_PORT
from honeypot.listener_utils import ThreadLimitedTCPListenerMixin
from honeypot.logger import event_logger


LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>System Administration</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f2f4f7; }
    .login { width: 340px; margin: 10vh auto; padding: 28px;
             background: white; border: 1px solid #ccd0d5; border-radius: 6px; }
    input { width: 100%; box-sizing: border-box; margin: 8px 0; padding: 10px; }
    button { width: 100%; padding: 10px; background: #286090; color: white;
             border: 0; border-radius: 3px; }
  </style>
</head>
<body>
  <form class="login" method="post">
    <h2>Administrator Login</h2>
    <input name="username" autocomplete="username" placeholder="Username">
    <input name="password" type="password" autocomplete="current-password"
           placeholder="Password">
    <button type="submit">Sign in</button>
  </form>
</body>
</html>"""


class HTTPListener(ThreadLimitedTCPListenerMixin):
    service = "HTTP"

    def __init__(self, host=HONEYPOT_HOST, port=HTTP_PORT):
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
            event_logger.info(f"HTTP honeypot listening on {self.host}:{self.port}")
            while not self._stop_event.is_set():
                try:
                    client, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not self._stop_event.is_set():
                        event_logger.warning("HTTP listener accept failed")
                    break
                self._start_client_thread(client, address)
        except OSError as exc:
            event_logger.warning(
                f"HTTP honeypot could not bind to {self.host}:{self.port}: {exc}"
            )
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._socket = None

    @staticmethod
    def _read_request(client):
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < HTTP_MAX_HEADER_BYTES:
            chunk = client.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return bytes(data)

        headers = data[:header_end].decode("iso-8859-1", errors="replace")
        content_length = 0
        for line in headers.split("\r\n")[1:]:
            if line.lower().startswith("content-length:"):
                try:
                    content_length = min(
                        max(int(line.split(":", 1)[1].strip()), 0),
                        HTTP_MAX_BODY_BYTES,
                    )
                except ValueError:
                    content_length = 0
        body_start = header_end + 4
        while len(data) - body_start < content_length:
            chunk = client.recv(min(4096, content_length - (len(data) - body_start)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def _credentials(headers, body):
        content_type = headers.get("content-type", "")
        fields = {}
        if "application/json" in content_type:
            try:
                parsed = json.loads(body or "{}")
                if isinstance(parsed, dict):
                    fields = {str(key): str(value) for key, value in parsed.items()}
            except (json.JSONDecodeError, TypeError):
                fields = {}
        else:
            fields = {
                key: values[-1] if values else ""
                for key, values in parse_qs(
                    body, keep_blank_values=True, errors="replace"
                ).items()
            }
        username = next(
            (
                fields[key]
                for key in ("username", "user", "email", "login")
                if key in fields
            ),
            "",
        )
        password = next(
            (
                fields[key]
                for key in ("password", "pass", "passwd", "pwd")
                if key in fields
            ),
            "",
        )
        return username[:256], password[:256]

    def _handle_client(self, client, address):
        raw_request = b""
        method = ""
        path = ""
        username = ""
        password = ""
        client.settimeout(10)
        try:
            raw_request = self._read_request(client)
            header_bytes, _, body_bytes = raw_request.partition(b"\r\n\r\n")
            header_text = header_bytes.decode("iso-8859-1", errors="replace")
            lines = header_text.split("\r\n")
            if lines:
                parts = lines[0].split()
                if len(parts) >= 2:
                    method, path = parts[0].upper(), parts[1]
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            body = body_bytes.decode("utf-8", errors="replace")
            if method == "POST":
                username, password = self._credentials(headers, body)

            response_body = LOGIN_PAGE.encode("utf-8")
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.54 (Ubuntu)\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                "Connection: close\r\n"
                "X-Frame-Options: SAMEORIGIN\r\n"
                "\r\n"
            ).encode("ascii") + response_body
            client.sendall(response)
        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            pass
        finally:
            event_logger.log_event(
                address[0],
                self.port,
                self.service,
                username_tried=username,
                password_tried=password,
                command_tried=f"{method} {path}".strip(),
                raw_data=raw_request.decode("utf-8", errors="replace"),
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
