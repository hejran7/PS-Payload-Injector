import os
import socket
import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional


class InjectionStatus(IntEnum):
    OK      = 0
    FAILED  = 1
    TIMEOUT = 2


@dataclass
class InjectionResult:
    status:  InjectionStatus
    message: str
    mode:    str = ""
    ip:      str = ""
    port:    int = 0


class PayloadInjector:
    def __init__(self, ip: str, port: int, timeout: float = 5.0):
        self.ip      = ip
        self.port    = port
        self.timeout = timeout

    def inject_file(self, path: str,
                    callback: Callable[[InjectionResult], None],
                    mode: str = "Payload") -> threading.Thread:
        def _run():
            if not os.path.isfile(path):
                callback(InjectionResult(
                    InjectionStatus.FAILED,
                    f"File not found: {path}", mode, self.ip, self.port
                ))
                return
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except Exception as e:
                callback(InjectionResult(
                    InjectionStatus.FAILED,
                    f"Read error: {e}", mode, self.ip, self.port
                ))
                return
            self._send(data, callback, mode)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t

    def _send(self, data: bytes,
               callback: Callable[[InjectionResult], None],
               mode: str):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.ip, self.port))
                s.sendall(data)
            callback(InjectionResult(
                InjectionStatus.OK, "Payload sent", mode, self.ip, self.port
            ))
        except socket.timeout:
            callback(InjectionResult(
                InjectionStatus.TIMEOUT, "Payload failed", mode, self.ip, self.port
            ))
        except (ConnectionRefusedError, OSError):
            callback(InjectionResult(
                InjectionStatus.FAILED, "Payload failed", mode, self.ip, self.port
            ))


class InjectionEngine:
    def __init__(self, ip: str = "", payload_port: int = 9090, timeout: float = 5.0):
        self.ip           = ip
        self.payload_port = payload_port
        self.timeout      = timeout

    def configure(self, ip: str, payload_port: int = 9090):
        self.ip           = ip
        self.payload_port = payload_port

    def send_payload(self, path: str,
                     callback: Callable[[InjectionResult], None],
                     mode: str = "Payload") -> threading.Thread:
        inj = PayloadInjector(self.ip, self.payload_port, self.timeout)
        return inj.inject_file(path, callback, mode)
