"""
exception_handler.py — web-ready exception-handling decorators for network automation.

Web-integration goals:
- No sys.exit() by default
- Raise typed exceptions so API/UI layers can handle them cleanly
- Keep retry behavior (auth retries) without prompting (caller can re-call with new creds)
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

from paramiko.ssh_exception import SSHException
from jnpr.junos.exception import (
    ConnectRefusedError,
    ConnectTimeoutError,
    ConnectUnknownHostError,
    ConnectAuthError,
    ConnectClosedError,
    ConnectError,
    RpcTimeoutError,
)

from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadException,
    ReadTimeout,
    ConnectionException,
)


T = TypeVar("T")


# -----------------------------
# Exceptions (typed)
# -----------------------------

@dataclass(frozen=True)
class NetworkErrorDetails:
    host: str
    operation: str
    message: str


class NetworkAutomationError(RuntimeError):
    """
    Base exception for network automation errors.
    Includes basic context useful for a web UI.
    """
    def __init__(self, details: NetworkErrorDetails, *, cause: Optional[BaseException] = None):
        super().__init__(details.message)
        self.details = details
        self.__cause__ = cause


class AuthenticationError(NetworkAutomationError):
    pass


class TimeoutError(NetworkAutomationError):
    pass


class DnsResolutionError(NetworkAutomationError):
    pass


class ConnectionRefusedError(NetworkAutomationError):
    pass


class ConnectionClosedError(NetworkAutomationError):
    pass


class RpcError(NetworkAutomationError):
    pass


class PermissionDeniedError(NetworkAutomationError):
    pass


class ConnectionFailedError(NetworkAutomationError):
    pass


# -----------------------------
# Helpers
# -----------------------------

def _host_from_args(args: tuple, kwargs: dict) -> str:
    for key in ("host", "hostname", "ip", "device", "target"):
        if key in kwargs and kwargs[key]:
            return str(kwargs[key])
    if args:
        return str(args[0])
    return "Unknown host"


def _raise(details: NetworkErrorDetails, exc_cls: type[NetworkAutomationError], cause: BaseException | None = None) -> None:
    raise exc_cls(details, cause=cause)


# -----------------------------
# Decorator factories
# -----------------------------

class ExceptionHandler:
    """
    Centralized exception handling for Junos PyEZ / NETCONF and Netmiko workflows.

    For web apps, use exit_on_error=False (default below) and handle the raised
    exceptions at the API layer.
    """

    @staticmethod
    def junos_exceptions(
        max_auth_retries: int = 0,
        exit_on_error: bool = False,   # kept for API compatibility; no sys.exit used
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """
        Wrap a function that connects to Juniper device and/or executes RPCs.

        Notes for web integration:
        - We do NOT prompt for passwords here.
        - If auth fails and max_auth_retries > 0, we simply retry the same call
          (useful if caller swaps credentials between retries externally).
        """

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> T:
                host = _host_from_args(args, kwargs)
                operation = func.__name__
                retries = 0

                while True:
                    try:
                        return func(*args, **kwargs)

                    except ConnectRefusedError as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"NETCONF refused on {host} (NETCONF disabled or too many sessions).",
                            ),
                            ConnectionRefusedError,
                            cause=e,
                        )

                    except (ConnectTimeoutError, SSHException, socket.timeout) as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Connection timeout to {host}.",
                            ),
                            TimeoutError,
                            cause=e,
                        )

                    except ConnectUnknownHostError as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Hostname {host} cannot be resolved (DNS failure).",
                            ),
                            DnsResolutionError,
                            cause=e,
                        )

                    except ConnectClosedError as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Connection to {host} closed unexpectedly.",
                            ),
                            ConnectionClosedError,
                            cause=e,
                        )

                    except RpcTimeoutError as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"RPC timeout from {host}.",
                            ),
                            RpcError,
                            cause=e,
                        )

                    except PermissionError as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Permission denied invoking RPC on {host}.",
                            ),
                            PermissionDeniedError,
                            cause=e,
                        )

                    except ConnectAuthError as e:
                        if retries < max_auth_retries:
                            retries += 1
                            continue
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Authentication to {host} failed.",
                            ),
                            AuthenticationError,
                            cause=e,
                        )

                    except ConnectError as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Connection error to {host}.",
                            ),
                            ConnectionFailedError,
                            cause=e,
                        )

                    except KeyboardInterrupt as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message="Operation cancelled by user.",
                            ),
                            NetworkAutomationError,
                            cause=e,
                        )

            return wrapper

        return decorator

    @staticmethod
    def netmiko_exceptions(
        max_auth_retries: int = 0,
        exit_on_error: bool = False,   # kept for API compatibility; no sys.exit used
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """
        Wrap a function that connects via Netmiko and/or executes CLI commands.

        Notes for web integration:
        - No prompting.
        - Retrying re-runs the same call.
        """

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> T:
                host = _host_from_args(args, kwargs)
                operation = func.__name__
                retries = 0

                while True:
                    try:
                        return func(*args, **kwargs)

                    except NetmikoAuthenticationException as e:
                        if retries < max_auth_retries:
                            retries += 1
                            continue
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Authentication to {host} failed.",
                            ),
                            AuthenticationError,
                            cause=e,
                        )

                    except (NetmikoTimeoutException, SSHException, socket.timeout) as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Connection timeout to {host}.",
                            ),
                            TimeoutError,
                            cause=e,
                        )

                    except (ReadException, ReadTimeout) as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Netmiko read failure on {host}.",
                            ),
                            NetworkAutomationError,
                            cause=e,
                        )

                    except ConnectUnknownHostError as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Hostname {host} cannot be resolved (DNS failure).",
                            ),
                            DnsResolutionError,
                            cause=e,
                        )

                    except ConnectionException as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message=f"Connection error to {host}.",
                            ),
                            ConnectionFailedError,
                            cause=e,
                        )

                    except KeyboardInterrupt as e:
                        _raise(
                            NetworkErrorDetails(
                                host=host,
                                operation=operation,
                                message="Operation cancelled by user.",
                            ),
                            NetworkAutomationError,
                            cause=e,
                        )

            return wrapper

        return decorator