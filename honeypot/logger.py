"""Event capture, rotating audit logging, and asynchronous enrichment."""

import json
import logging
import os
import queue
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from config import (
    ENRICHMENT_QUEUE_SIZE,
    LOG_BACKUP_COUNT,
    LOG_PATH,
    MAX_EVENT_FIELD_LENGTH,
    MAX_LOG_SIZE,
    MAX_RAW_DATA_LENGTH,
    STORE_SENSITIVE_VALUES,
)
from database import models
from enrichment.abuseipdb import check_ip
from enrichment.geoip import lookup_ip
from enrichment.profiler import update_attacker_profile


REDACTED_VALUE = "<redacted>"


def _bounded_text(value, maximum):
    if value is None:
        return ""
    text = str(value)
    if len(text) <= maximum:
        return text
    return text[: max(0, maximum - 14)] + "...[truncated]"


def _captured_secret(value, maximum):
    if value in (None, ""):
        return ""
    if STORE_SENSITIVE_VALUES:
        return _bounded_text(value, maximum)
    return REDACTED_VALUE


def _safe_port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class HoneypotLogger:
    def __init__(self, worker_count=2):
        models.init_db()
        self._queue = queue.Queue(maxsize=ENRICHMENT_QUEUE_SIZE)
        self._worker_count = worker_count
        self._workers = []
        self._start_lock = threading.Lock()
        self._started = False
        self._logger = self._build_file_logger()

    @staticmethod
    def _build_file_logger():
        logger = logging.getLogger("honeypot-sentinel")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            handler = RotatingFileHandler(
                LOG_PATH,
                maxBytes=MAX_LOG_SIZE,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            )
            logger.addHandler(handler)
        return logger

    def start(self):
        with self._start_lock:
            if self._started:
                return
            self._started = True
            for index in range(self._worker_count):
                worker = threading.Thread(
                    target=self._enrichment_worker,
                    name=f"enrichment-{index + 1}",
                    daemon=True,
                )
                worker.start()
                self._workers.append(worker)

    def stop(self):
        with self._start_lock:
            if not self._started:
                return
            for _ in self._workers:
                try:
                    self._queue.put(None, timeout=1)
                except queue.Full:
                    self._logger.warning("Enrichment queue full during shutdown")
            for worker in self._workers:
                worker.join(timeout=6)
            self._workers.clear()
            self._started = False

    def info(self, message):
        self._logger.info(message)

    def warning(self, message):
        self._logger.warning(message)

    def error(self, message):
        self._logger.error(message)

    def log_event(
        self,
        ip_address,
        port,
        service,
        username_tried="",
        password_tried="",
        command_tried="",
        raw_data="",
    ):
        self.start()
        ip_text = _bounded_text(ip_address, 45)
        service_name = _bounded_text(service, 32).upper() or "UNKNOWN"
        username = _bounded_text(username_tried, 256)
        password = _captured_secret(password_tried, 256)
        command = _bounded_text(command_tried, MAX_EVENT_FIELD_LENGTH)
        raw_payload = _captured_secret(raw_data, MAX_RAW_DATA_LENGTH)
        port_number = _safe_port(port)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip_address": ip_text,
            "port": port_number,
            "service": service_name,
            "username_tried": username,
            "password_tried": password,
            "command_tried": command,
            "raw_data": raw_payload,
            "country": "",
            "country_code": "",
            "city": "",
            "region": "",
            "timezone": "",
            "zip_code": "",
            "latitude": None,
            "longitude": None,
            "isp": "",
            "org": "",
            "country_flag": "",
            "abuse_score": 0,
            "is_known_attacker": 0,
        }
        event_id = models.insert_event(event)
        try:
            is_flagged = update_attacker_profile(event)
            event["is_known_attacker"] = int(is_flagged)
            if is_flagged:
                models.mark_event_known(event_id, True)
        except Exception:
            self._logger.exception("Failed to create attacker profile")
        self._logger.info(
            "EVENT %s",
            json.dumps(
                {
                    "id": event_id,
                    "ip_address": ip_text,
                    "port": port_number,
                    "service": service_name,
                    "username_tried": username,
                    "password_tried": REDACTED_VALUE if password else "",
                    "command_tried": command,
                    "raw_data_length": len(str(raw_data or "")),
                },
                ensure_ascii=True,
            ),
        )
        try:
            self._queue.put_nowait((event_id, event))
        except queue.Full:
            self._logger.warning("Skipped enrichment for event %s: queue full", event_id)
        return event_id

    def _enrichment_worker(self):
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                event_id, event = item
                geo_data = lookup_ip(event["ip_address"])
                abuse_data = check_ip(event["ip_address"])
                event.update(geo_data)
                event["abuse_score"] = int(
                    abuse_data.get("abuseConfidenceScore", 0) or 0
                )
                initially_known = (
                    event["abuse_score"] > 50
                    or bool(event.get("is_known_attacker"))
                )
                models.update_event_enrichment(event_id, event, initially_known)
                is_flagged = update_attacker_profile(event, increment=False)
                if is_flagged and not initially_known:
                    models.mark_event_known(event_id, True)
            except Exception:
                self._logger.exception("Failed to enrich event")
            finally:
                self._queue.task_done()


event_logger = HoneypotLogger()
