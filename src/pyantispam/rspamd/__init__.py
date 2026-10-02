"""Shadow integration with rspamd (observes, never decides)"""

from .shadow_classifier import RspamdShadowClassifier

__all__ = ["RspamdShadowClassifier"]
