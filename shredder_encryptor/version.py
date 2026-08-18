__version_tuple__ = (
    2026,  # Major
    8,  # Minor
    1,  # Build
    False,  # Is pre version
    0,  # Pre version x
    True,  # Is beta version
    2,  # Beta major version
    2,  # Beta minor version
    True,  # Is post‑release (pr)
    3,  # Post number
)

vt = __version_tuple__
(major, minor, build, is_pre, pre_x, is_beta, beta_maj, beta_min, is_post, post_x) = vt

base = f"{major}.{minor}.{build}"
suffix_parts = []

if is_beta:
    suffix_parts.append(f"beta{beta_maj}")
if is_pre:
    suffix_parts.append(f"pre{pre_x}")
if is_post:
    suffix_parts.append(f"pr{post_x}")

if suffix_parts:
    __version__ = f"{base}-{'.'.join(suffix_parts)}"
else:
    __version__ = base

del (
    vt,
    major,
    minor,
    build,
    is_pre,
    pre_x,
    is_beta,
    beta_maj,
    beta_min,
    is_post,
    post_x,
    base,
)


def _get_pre(ver: str) -> bool:
    return "pre" in ver


def _get_beta(ver: str) -> bool:
    return "beta" in ver


PRE = _get_pre(__version__)
BETA = _get_beta(__version__)
RELEASE = not _get_pre(__version__) or not _get_beta(__version__)

if __name__ == "__main__":
    print(__version__)
