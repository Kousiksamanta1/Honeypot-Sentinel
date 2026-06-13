# Legal disclaimer: Deploy only on systems and networks you own or are explicitly
# authorized to monitor. You are responsible for complying with all applicable laws.
"""Honeypot Sentinel application entry point."""

import signal
import threading

from api import create_app
from config import (
    FLASK_HOST,
    FLASK_PORT,
    FTP_PORT,
    HONEYPOT_HOST,
    HTTP_PORT,
    SSH_PORT,
    TELNET_PORT,
)
from honeypot.ftp_listener import FTPListener
from honeypot.http_listener import HTTPListener
from honeypot.logger import event_logger
from honeypot.ssh_listener import SSHListener
from honeypot.telnet_listener import TelnetListener


def _banner():
    print(
        rf"""
 _   _                                  _     ____             _   _            _
| | | | ___  _ __   ___ _   _ _ __   ___ | |_  / ___|  ___ _ __ | |_(_)_ __   ___| |
| |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _ \| __| \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
|  _  | (_) | | | |  __/ |_| | |_) | (_) | |_   ___) |  __/ | | | |_| | | | |  __/ |
|_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__| |____/ \___|_| |_|\__|_|_| |_|\___|_|
                        |___/|_|

  SSH      {HONEYPOT_HOST}:{SSH_PORT}
  HTTP     {HONEYPOT_HOST}:{HTTP_PORT}
  FTP      {HONEYPOT_HOST}:{FTP_PORT}
  TELNET   {HONEYPOT_HOST}:{TELNET_PORT}
  Dashboard http://{FLASK_HOST}:{FLASK_PORT}
"""
    )


def main():
    event_logger.start()
    listeners = [
        SSHListener(),
        HTTPListener(),
        FTPListener(),
        TelnetListener(),
    ]
    listener_threads = []
    stopping = threading.Event()

    for listener in listeners:
        thread = threading.Thread(
            target=listener.serve_forever,
            name=f"{listener.service.lower()}-listener",
            daemon=True,
        )
        thread.start()
        listener_threads.append(thread)

    def shutdown():
        if stopping.is_set():
            return
        stopping.set()
        print("\nStopping Honeypot Sentinel...")
        for active_listener in listeners:
            active_listener.stop()

    def handle_signal(_signum, _frame):
        shutdown()
        raise KeyboardInterrupt

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, handle_signal)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, handle_signal)

    _banner()
    app = create_app()
    try:
        app.run(
            host=FLASK_HOST,
            port=FLASK_PORT,
            threaded=True,
            debug=False,
            use_reloader=False,
        )
    except KeyboardInterrupt:
        shutdown()
    finally:
        shutdown()
        for thread in listener_threads:
            thread.join(timeout=2)
        event_logger.stop()
        print("Honeypot Sentinel stopped.")


if __name__ == "__main__":
    main()
