import sys

from utils.runtime_env import configure_runtime

# Scapy ve diğer kütüphaneler yüklenmeden önce
# uygulamaya ait cache klasörünü hazırla.
configure_runtime()

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
