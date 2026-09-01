"""coldsend-lint: pre-send linting for cold-email campaigns.

Two axes, one CLI: sending-domain deliverability (DNS) and legal/copy
compliance (CAN-SPAM, GDPR/ePrivacy, PECR, LSSI-CE, CASL).

NOT LEGAL ADVICE. See ``coldsend_lint.report.DISCLAIMER``.
"""

from .findings import Finding, exit_code
from .message import Message, load_message, parse_message
from .report import DISCLAIMER

__version__ = "0.1.0"
__all__ = [
    "DISCLAIMER",
    "Finding",
    "Message",
    "exit_code",
    "load_message",
    "parse_message",
    "__version__",
]
