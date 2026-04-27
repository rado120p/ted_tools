"""Cross-cutting exception infrastructure for ted_tools.

UserActionableError is a marker base class. Exceptions that inherit from it
declare their messages safe to show directly to end users — no stack traces,
no file paths, no credentials in `str(e)` (or, for structured exceptions like
NetworkAutomationError, in the equivalent message field e.g. details.message).

Web/UI layers can use `isinstance(e, UserActionableError)` to surface the
exception's message directly instead of sanitising it. See
ted_webapp_ide/app/errors.py for the consumer-side dispatch.

Adding a new actionable exception family: subclass UserActionableError (or
any of its subclasses) and ensure str(e) — or your equivalent structured
message field — does not include sensitive content. The marker is opt-in
on purpose: by default exceptions are sanitised at the web boundary.
"""


class UserActionableError(Exception):
    """Marker: subclasses' messages are safe to show to end users."""
