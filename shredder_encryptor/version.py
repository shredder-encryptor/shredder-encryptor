__version__ = "2026.8.1-beta1-pr5"


def _get_pre(ver: str) -> bool:
    return "pre" in ver


def _get_beta(ver: str) -> bool:
    return "beta" in ver


PRE = _get_pre(__version__)
BETA = _get_beta(__version__)
RELEASE = not _get_pre(__version__) or not _get_beta(__version__)
