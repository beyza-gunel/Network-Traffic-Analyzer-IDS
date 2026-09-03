from PySide6.QtCore import QObject, Signal, Slot

from services.analysis_service import AnalysisService


class AnalysisWorker(QObject):

    finished = Signal(object)
    failed = Signal(str)
    stage_changed = Signal(str)

    def __init__(self, file_path):
        super().__init__()

        self.file_path = file_path

    @Slot()
    def run(self):
        try:
            self.stage_changed.emit(
                "PCAP analizi başlatılıyor..."
            )

            service = AnalysisService()

            self.stage_changed.emit(
                "Paketler analiz ediliyor..."
            )

            result = service.analyze(
                self.file_path
            )

            self.stage_changed.emit(
                "Analiz tamamlandı."
            )

            self.finished.emit(
                result
            )

        except Exception as error:
            self.failed.emit(
                str(error)
            )