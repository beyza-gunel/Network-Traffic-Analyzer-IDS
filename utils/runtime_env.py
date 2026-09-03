import os
from pathlib import Path


def configure_runtime():
    base_dir = Path(
        os.environ.get("LOCALAPPDATA")
        or Path.home()
    )

    cache_dir = (
        base_dir
        / "NetworkTrafficAnalyzer"
        / "cache"
    )

    cache_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    os.environ["XDG_CACHE_HOME"] = str(
        cache_dir
    )

    return cache_dir