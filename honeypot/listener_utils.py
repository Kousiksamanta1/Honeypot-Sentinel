"""Shared listener helpers."""

import threading

from config import MAX_CLIENT_THREADS
from honeypot.logger import event_logger


def close_client(client):
    try:
        client.close()
    except OSError:
        pass


class ThreadLimitedTCPListenerMixin:
    def _init_client_limiter(self):
        self._client_slots = threading.BoundedSemaphore(MAX_CLIENT_THREADS)

    def _start_client_thread(self, client, address):
        if not self._client_slots.acquire(blocking=False):
            event_logger.warning(
                "%s listener refused %s: client limit reached",
                self.service,
                address[0] if address else "unknown",
            )
            close_client(client)
            return

        def run_client():
            try:
                self._handle_client(client, address)
            finally:
                self._client_slots.release()

        threading.Thread(
            target=run_client,
            daemon=True,
            name=f"{self.service.lower()}-client-{address[0]}",
        ).start()
