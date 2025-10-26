# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
mitmservice.py — менеджер локальных mitmdump воркеров для upstream-прокси.

Особенности:
- цветной консольный лог, лог в файл (utf-8)
- маскировка паролей в логах
- аннотации типов в стиле PEP-484
- компактные periodical status reports
"""

from typing import Dict, Optional, Tuple, List
import sqlite3
import subprocess
import threading
import time
import socket
import signal
import sys
import os
import logging
from pathlib import Path
import shutil
import urllib3
import ctypes
import requests

# ----------------------------
# Конфигурация (аннотированы)
# ----------------------------
DB_PATH: str = "PROXIES.db"
MITMDUMP_PATH: str = "mitmdump"
TEST_URL: str = "https://jsonip.com"
CHECK_TIMEOUT: int = 10
PORT_CHECK_RETRIES: int = 10
PORT_CHECK_DELAY: float = 0.4
STARTUP_GRACE: float = 2.0
LOG_FILE: str = "mitm_manager.log"
AUTO_RETRY_ON_START: int = 0
MAX_RESTARTS_ON_CRASH: int = 3
TAIL_LINES: int = 150
POLL_INTERVAL: float = 10.0
STATUS_INTERVAL: float = 60.0  # seconds between status reports
# ----------------------------

# Отключаем SSL-предупреждения для тестовых запросов
urllib3.disable_warnings()

# Включаем ANSI-цвета в Windows-консоли (VT processing)
if os.name == "nt":
    kernel32 = ctypes.windll.kernel32
    _h_console: int = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE = -11
    _mode = ctypes.c_uint()
    if kernel32.GetConsoleMode(_h_console, ctypes.byref(_mode)):
        kernel32.SetConsoleMode(_h_console, ctypes.c_uint(_mode.value | 0x0004))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING

# ----------------------------
# Colored logging setup
# ----------------------------
class ColoredFormatter(logging.Formatter):
    RESET: str = "\x1b[0m"
    COLORS: Dict[int, str] = {
        logging.DEBUG: "\x1b[38;5;250m",
        logging.INFO: "\x1b[38;5;81m",
        logging.WARNING: "\x1b[38;5;214m",
        logging.ERROR: "\x1b[38;5;196m",
        logging.CRITICAL: str("\x1b[38;5;196;1m"),
    }

    def format(self, record: logging.LogRecord) -> str:
        color: str = self.COLORS.get(record.levelno, "")
        prefix: str = f"{color}{record.levelname:<7}{self.RESET}"
        asctime: str = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        msg: str = super().format(record)
        return f"{asctime} {prefix} {msg}"


def mask_upstream_auth_in_cmd(cmd_list: List[str]) -> str:
    """
    Возвращает строковое представление команды, где значение после --upstream-auth замаскировано.
    Также пытается маскировать user:pass@host внутри одного аргумента.
    """
    safe: List[str] = []
    skip_next_mask: bool = False
    for part in cmd_list:
        if skip_next_mask:
            safe.append("******")
            skip_next_mask = False
            continue
        if part == "--upstream-auth":
            safe.append(part)
            skip_next_mask = True
            continue
        # обработка http://user:pass@host:port
        if part.startswith("http") and "@" in part and ":" in part:
            try:
                scheme, rest = part.split("://", 1)
                if "@" in rest:
                    userinfo, host = rest.rsplit("@", 1)
                    if ":" in userinfo:
                        user, pwd = userinfo.split(":", 1)
                        safe.append(f"{scheme}://{user}:******@{host}")
                        continue
            except Exception:
                pass
        safe.append(part)
    return " ".join(safe)


# logger (global)
logger: logging.Logger = logging.getLogger("mitm_manager")
logger.setLevel(logging.DEBUG)

# file handler — utf-8, plain (no ANSI)
fh: logging.FileHandler = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG)
file_fmt: logging.Formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
fh.setFormatter(file_fmt)
logger.addHandler(fh)

# console handler — colored
ch: logging.StreamHandler = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
console_fmt: ColoredFormatter = ColoredFormatter("%(message)s")
ch.setFormatter(console_fmt)
logger.addHandler(ch)

# ----------------------------
# Globals / state (аннотированы)
# ----------------------------
stop_event: threading.Event = threading.Event()
workers_lock: threading.Lock = threading.Lock()
workers: Dict[int, "MitmWorker"] = {}  # port -> MitmWorker
# ----------------------------


# ----------------------------
# DB helpers
# ----------------------------
def ensure_worker_column(conn: sqlite3.Connection) -> None:
    cur: sqlite3.Cursor = conn.cursor()
    cur.execute("PRAGMA table_info(PROXIES)")
    cols: List[str] = [r[1] for r in cur.fetchall()]
    if "WORKER_STATUS" not in cols:
        logger.info("Добавляю колонку WORKER_STATUS в таблицу PROXIES")
        cur.execute("ALTER TABLE PROXIES ADD COLUMN WORKER_STATUS TEXT")
        conn.commit()


def fetch_valid_proxies(conn: sqlite3.Connection):
    cur: sqlite3.Cursor = conn.cursor()
    cur.execute(
        "SELECT rowid, PROXY, PORT, STATUS, WORKER_STATUS FROM PROXIES WHERE STATUS = 'VALID'"
    )
    return cur.fetchall()


def update_row_status(
    conn: sqlite3.Connection, rowid: int, status: Optional[str] = None, worker_status: Optional[str] = None
) -> None:
    cur: sqlite3.Cursor = conn.cursor()
    updates: List[str] = []
    params: List[object] = []
    if status is not None:
        updates.append("STATUS=?")
        params.append(status)
    if worker_status is not None:
        updates.append("WORKER_STATUS=?")
        params.append(worker_status)
    if not updates:
        return
    params.append(rowid)
    sql: str = f"UPDATE PROXIES SET {', '.join(updates)} WHERE rowid=?"
    cur.execute(sql, params)
    conn.commit()


# ----------------------------
# Util helpers
# ----------------------------
def parse_proxy_string(proxy_str: str) -> Tuple[str, Optional[str], str]:
    """
    Принимает: "login:password@ip:port" или "ip:port"
    Возвращает: (upstream_spec, upstream_auth_or_None, original)
    upstream_spec всегда вида http://ip:port
    """
    if "@" in proxy_str:
        creds, hostpart = proxy_str.rsplit("@", 1)
        if ":" in creds:
            user, pwd = creds.split(":", 1)
            upstream: str = f"http://{hostpart}"
            auth: str = f"{user}:{pwd}"
            return upstream, auth, proxy_str
        else:
            upstream = f"http://{hostpart}"
            return upstream, None, proxy_str
    return f"http://{proxy_str}", None, proxy_str


def wait_for_port(host: str, port: int, retries: int = PORT_CHECK_RETRIES, delay: float = PORT_CHECK_DELAY) -> bool:
    for _ in range(retries):
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except Exception:
            time.sleep(delay)
    return False


# ----------------------------
# Worker
# ----------------------------
class MitmWorker(threading.Thread):
    rowid: int
    proxy_spec: str
    listen_port: int
    db_path: str
    mitmdump_path: str
    process: Optional[subprocess.Popen]
    _stop_requested: threading.Event
    _pending_upstream_auth: Optional[str]
    last_validated_at: Optional[float]

    def __init__(
        self,
        rowid: int,
        proxy_spec: str,
        listen_port: int,
        db_path: str,
        mitmdump_path: str = MITMDUMP_PATH,
    ) -> None:
        super().__init__(daemon=True)
        self.rowid = rowid
        self.proxy_spec = proxy_spec
        self.listen_port = listen_port
        self.db_path = db_path
        self.mitmdump_path = mitmdump_path
        self.process = None
        self._stop_requested = threading.Event()
        self._pending_upstream_auth = None
        self.last_validated_at = None

    def _tail_log(self, logfile_path: str, n_lines: int = TAIL_LINES) -> str:
        try:
            p = Path(logfile_path)
            if not p.exists():
                return f"(log {logfile_path} not found)"
            with p.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                block_size = 1024
                data = bytearray()
                while size > 0 and len(data) < block_size * n_lines:
                    read_size = min(block_size, size)
                    f.seek(size - read_size)
                    data[:0] = f.read(read_size)
                    size -= read_size
            try:
                text: str = data.decode(errors="replace")
            except Exception:
                text = repr(data)
            lines: List[str] = text.splitlines()
            return "\n".join(lines[-n_lines:])
        except Exception as e:
            return f"(failed reading log {logfile_path}: {e})"

    def run(self) -> None:
        logger.info(f"[{self.listen_port}] \x1b[1mWorker starting\x1b[0m for rowid={self.rowid}, upstream={self.proxy_spec}")
        upstream, upstream_auth, raw = parse_proxy_string(self.proxy_spec)
        self._pending_upstream_auth = upstream_auth

        attempt: int = 0
        while attempt <= AUTO_RETRY_ON_START and not self._stop_requested.is_set():
            attempt += 1
            try:
                self._start_mitmdump(upstream)
                # Если глобальный стоп уже выставлен — не помечаем INVALID
                if stop_event.is_set() or self._stop_requested.is_set():
                    logger.info(f"[{self.listen_port}] Startup aborted due to stop_event; cleaning up")
                    self._kill_process()
                    return

                ok: bool = self._wait_and_check()
                if ok:
                    self.last_validated_at = time.time()
                    self._set_db(worker_status="IN PROGRESS")
                    logger.info(f"[{self.listen_port}] \x1b[38;5;82mProxy validated and worker IN PROGRESS\x1b[0m")
                    break
                else:
                    logger.warning(f"[{self.listen_port}] Validation failed on attempt {attempt}")
                    self._kill_process()
                    if attempt > AUTO_RETRY_ON_START:
                        self._set_db(status="INVALID", worker_status="ERROR")
                        logger.error(f"[{self.listen_port}] Marked INVALID after failed attempts")
                        return
                    time.sleep(1.0)
            except Exception as e:
                logger.exception(f"[{self.listen_port}] Exception during start/validate: {e}")
                self._kill_process()
                self._set_db(status="INVALID", worker_status="ERROR")
                return

        logfile_path: str = f"mitmdump_port_{self.listen_port}.log"
        restart_count: int = 0
        while not self._stop_requested.is_set():
            if self.process is None:
                break
            ret = self.process.poll()
            if ret is not None:
                tail: str = self._tail_log(logfile_path)
                logger.error(f"[{self.listen_port}] mitmdump exited with code {ret}. Last log lines:\n{tail}")
                if restart_count < MAX_RESTARTS_ON_CRASH:
                    restart_count += 1
                    delay: float = 5 * (2 ** restart_count)
                    logger.warning(f"[{self.listen_port}] Restarting mitmdump (attempt {restart_count}) after {delay}s")
                    time.sleep(delay)
                    self._start_mitmdump(upstream)
                    continue
                else:
                    logger.error(f"[{self.listen_port}] Too many restarts, marking INVALID")
                    self._set_db(status="INVALID", worker_status="ERROR")
                    return
            time.sleep(1.0)

        logger.info(f"[{self.listen_port}] Stop requested, terminating mitmdump")
        self._kill_process()
        self._set_db(worker_status="NOT STARTED")
        logger.info(f"[{self.listen_port}] Worker stopped")

    def _start_mitmdump(self, upstream: str) -> None:
        # проверка наличия бинаря
        if shutil.which(self.mitmdump_path) is None:
            if not os.path.isfile(self.mitmdump_path) or not os.access(self.mitmdump_path, os.X_OK):
                raise RuntimeError(f"mitmdump not found or not executable: {self.mitmdump_path}")

        cmd: List[str] = [
            self.mitmdump_path,
            "--listen-port", str(self.listen_port),
            "--mode", f"upstream:{upstream}",
            "--set", "console_eventlog_verbosity=error",
        ]
        if self._pending_upstream_auth:
            cmd += ["--upstream-auth", self._pending_upstream_auth]

        masked: str = mask_upstream_auth_in_cmd(cmd)
        logger.debug(f"[{self.listen_port}] Starting mitmdump: {masked}")
        # write masked to file log as well
        fh_log = logging.getLogger("mitm_manager").handlers[0]  # type: ignore
        fh_log.acquire()
        try:
            fh_log.stream.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [DEBUG] [{self.listen_port}] Starting mitmdump: {masked}\n")
            fh_log.flush()
        finally:
            fh_log.release()

        logfile_path: str = f"mitmdump_port_{self.listen_port}.log"
        logfile = open(logfile_path, "ab")
        self.process = subprocess.Popen(cmd, stdout=logfile, stderr=logfile, start_new_session=True, close_fds=True)
        time.sleep(STARTUP_GRACE)

    def _wait_and_check(self) -> bool:
        if not wait_for_port("127.0.0.1", self.listen_port):
            logger.error(f"[{self.listen_port}] Local mitmproxy port did not open in time")
            return False
        proxies: Dict[str, str] = {"https": f"http://127.0.0.1:{self.listen_port}"}
        try:
            logger.debug(f"[{self.listen_port}] Sending test request to {TEST_URL} through local mitm")
            r = requests.get(TEST_URL, proxies=proxies, timeout=CHECK_TIMEOUT, verify=False)
            logger.debug(f"[{self.listen_port}] Test request status {r.status_code}")
            return r.status_code == 200
        except Exception as e:
            logger.warning(f"[{self.listen_port}] Test request error: {e}")
            return False

    def _kill_process(self) -> None:
        if self.process is None:
            return
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
            logger.info(f"[{self.listen_port}] mitmdump process terminated")
        except Exception as e:
            logger.exception(f"[{self.listen_port}] Error terminating process: {e}")
        finally:
            self.process = None

    def stop(self, reason: Optional[str] = None) -> None:
        """
        Request worker to stop. Optional reason is logged.
        """
        self._stop_requested.set()
        if reason:
            logger.info(f"[{self.listen_port}] Stop requested ({reason})")
        else:
            logger.info(f"[{self.listen_port}] Stop requested")

    def _set_db(self, status: Optional[str] = None, worker_status: Optional[str] = None) -> None:
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            update_row_status(conn, self.rowid, status=status, worker_status=worker_status)
            conn.close()
        except Exception:
            logger.exception(f"[{self.listen_port}] Failed to update DB status")


# ----------------------------
# Manager functions (less noisy)
# ----------------------------
def load_and_start_workers(db_path: str, mitmdump_path: str) -> None:
    conn = sqlite3.connect(db_path, timeout=10)
    ensure_worker_column(conn)
    rows = fetch_valid_proxies(conn)
    conn.close()

    if not rows:
        logger.info("No VALID proxies found in DB.")
        return

    for row in rows:
        rowid, proxy_str, port, status, worker_status = row
        if port is None:
            logger.warning(f"Row {rowid} has no PORT, skipping")
            continue
        try:
            port_int: int = int(port)
        except Exception:
            logger.warning(f"Row {rowid} has invalid PORT value: {port}, skipping")
            continue

        with workers_lock:
            existing = workers.get(port_int)
            if existing is not None:
                alive: bool = existing.is_alive()
                proc_alive: bool = False
                try:
                    if existing.process is not None and existing.process.poll() is None:
                        proc_alive = True
                except Exception:
                    proc_alive = False

                if alive and proc_alive:
                    # тихо: healthy — не спамим логами
                    continue
                else:
                    logger.warning(f"[{port_int}] Detected dead/failed worker (thread_alive={alive}, proc_alive={proc_alive}). Restarting for row {rowid}")
                    try:
                        existing.stop(reason="restart detected")
                        if existing.is_alive():
                            existing.join(timeout=2.0)
                    except Exception:
                        logger.exception(f"[{port_int}] Error while stopping dead worker")
                    workers.pop(port_int, None)

            try:
                conn = sqlite3.connect(db_path, timeout=10)
                update_row_status(conn, rowid, worker_status="NOT STARTED")
                conn.close()
            except Exception:
                logger.exception(f"[{port_int}] Failed to set NOT STARTED in DB for row {rowid}")

            w = MitmWorker(rowid=rowid, proxy_spec=proxy_str, listen_port=port_int, db_path=db_path, mitmdump_path=mitmdump_path)
            workers[port_int] = w
            w.start()
            logger.info(f"[{port_int}] Worker thread started for row {rowid}")


def shutdown_all() -> None:
    logger.info("Shutting down all workers...")
    with workers_lock:
        for port, w in list(workers.items()):
            try:
                w.stop(reason="global shutdown")
            except Exception:
                logger.exception(f"Error stopping worker on port {port}")
    time.sleep(1.0)
    with workers_lock:
        for port, w in list(workers.items()):
            if w.is_alive():
                logger.info(f"[{port}] waiting for thread to finish")
                w.join(timeout=5.0)
            workers.pop(port, None)
    logger.info("Shutdown complete.")


# ----------------------------
# Status reporter
# ----------------------------
class StatusReporter(threading.Thread):
    interval: float

    def __init__(self, interval: float = STATUS_INTERVAL) -> None:
        super().__init__(daemon=True)
        self.interval = interval
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            self.report()
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()

    def report(self) -> None:
        lines: List[str] = []
        with workers_lock:
            for port, w in sorted(workers.items()):
                thread_alive: bool = w.is_alive()
                proc_alive: bool = False
                try:
                    if w.process is not None and w.process.poll() is None:
                        proc_alive = True
                except Exception:
                    proc_alive = False
                last_val: Optional[float] = w.last_validated_at
                if last_val:
                    last_s: str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_val))
                else:
                    last_s = "never"
                try:
                    host: str = w.proxy_spec.rsplit("@", 1)[-1]
                except Exception:
                    host = w.proxy_spec
                status: str = ("RUN" if proc_alive else "DOWN")
                t_status: str = ("alive" if thread_alive else "dead")
                lines.append(f"[{port}] {status:4} {t_status:5} host={host} last_ok={last_s}")
        if lines:
            logger.info("\x1b[1mStatus report:\x1b[0m")
            for l in lines:
                logger.info(l)


# ----------------------------
# Signal handling
# ----------------------------
def handle_signal(sig, frame) -> None:
    logger.info("Received signal, stopping...")
    stop_event.set()
    shutdown_all()
    sys.exit(0)


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


# ----------------------------
# Entrypoint
# ----------------------------
def main() -> None:
    logger.info("\x1b[1mmitm_manager starting\x1b[0m")
    if not os.path.exists(DB_PATH):
        logger.error(f"DB file not found: {DB_PATH}")
        return

    status_reporter = StatusReporter(interval=STATUS_INTERVAL)
    status_reporter.start()

    try:
        load_and_start_workers(DB_PATH, MITMDUMP_PATH)
    except Exception:
        logger.exception("Error during initial load")

    try:
        while not stop_event.is_set():
            try:
                load_and_start_workers(DB_PATH, MITMDUMP_PATH)
            except Exception:
                logger.exception("Error while loading additional workers")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt, shutting down")
    finally:
        status_reporter.stop()
        shutdown_all()


if __name__ == "__main__":
    main()
