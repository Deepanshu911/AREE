"""
visitor package — Manages zero-install visitor sessions and client-side device diagnostics.
"""
from visitor.session import VisitorSession, generate_visitor_id

__all__ = ["VisitorSession", "generate_visitor_id"]
