"""Verify the three exception families inherit UserActionableError so that
web/UI layers can use a single isinstance() check to bypass sanitisation.
"""
from ted_tools.errors import UserActionableError
from ted_tools.exception_handler import (
    NetworkAutomationError,
    NetworkErrorDetails,
    AuthenticationError,
    ConnectionRefusedError,
)
from ted_tools.ted_graph import TedGraphError, InvalidAdjacencyDbError
from ted_tools.ted_handler import (
    TedHandlerError,
    NodeNotFoundError,
    EmptyTedDataError,
)


def _network_error():
    return ConnectionRefusedError(
        NetworkErrorDetails(host="x", operation="connect", message="msg")
    )


def test_network_automation_error_is_actionable():
    assert isinstance(_network_error(), UserActionableError)


def test_network_subclass_is_actionable():
    e = AuthenticationError(NetworkErrorDetails(host="x", operation="auth", message="msg"))
    assert isinstance(e, UserActionableError)


def test_ted_graph_error_is_actionable():
    assert isinstance(TedGraphError("no path"), UserActionableError)


def test_ted_graph_subclass_is_actionable():
    assert isinstance(InvalidAdjacencyDbError("bad schema"), UserActionableError)


def test_ted_handler_error_is_actionable():
    assert isinstance(TedHandlerError("generic"), UserActionableError)


def test_ted_handler_subclasses_are_actionable():
    assert isinstance(NodeNotFoundError("N1 not found"), UserActionableError)
    assert isinstance(EmptyTedDataError("empty"), UserActionableError)


def test_unrelated_exception_is_not_actionable():
    assert not isinstance(ValueError("x"), UserActionableError)
    assert not isinstance(RuntimeError("y"), UserActionableError)


def test_network_error_still_subclasses_runtime_error():
    """Multi-inheritance must not break the existing RuntimeError ancestry."""
    assert isinstance(_network_error(), RuntimeError)
    assert isinstance(_network_error(), Exception)
