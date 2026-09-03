import os
import sys
from pathlib import Path


cache_dir = (
    Path(os.environ.get("LOCALAPPDATA", Path.home()))
    / "NetworkTrafficAnalyzer"
    / "cache"
)

cache_dir.mkdir(
    parents=True,
    exist_ok=True
)

os.environ.setdefault(
    "XDG_CACHE_HOME",
    str(cache_dir)
)


from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow


def main():

    app = QApplication(
        sys.argv
    )

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )


if __name__ == "__main__":
    main()