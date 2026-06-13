"""Event capture, rotating audit logging, and asynchronous enrichment."""

import json
import logging
import os
import queue
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from config import LOG_BACKUP_COUNT, LOG_PATH, MAX_LOG_SIZE
from database import models
from enrichment.abuseipdb import check_ip
from enrichment.geoip import lookup_ip
from enrichment.profiler import update_attacker_profile


class HoneypotLogger:
    def __init__(self, worker_count=2):
        models.init_db()
        self._queue = queue.Queue()
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
                self._queue.put(None)
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
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip_address": ip_address,
            "port": int(port),
            "service": service.upper(),
            "username_tried": username_tried or "",
            "password_tried": password_tried or "",
            "command_tried": command_tried or "",
            "raw_data": raw_data or "",
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
                    "ip_address": ip_address,
                    "port": port,
                    "service": service.upper(),
                    "username_tried": username_tried or "",
                    "password_tried": password_tried or "",
                    "command_tried": command_tried or "",
                    "raw_data": raw_data or "",
                },
                ensure_ascii=True,
            ),
        )
        self._queue.put((event_id, event))
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
