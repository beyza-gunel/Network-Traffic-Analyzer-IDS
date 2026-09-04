from dataclasses import dataclass
from pathlib import Path


ALLOWED_EXTENSIONS = {
    ".pcap",
    ".pcapng",
}

PCAP_MAGIC_VALUES = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}

PCAPNG_MAGIC = (
    b"\x0a\x0d\x0d\x0a"
)

LARGE_FILE_WARNING_BYTES = (
    250
    * 1024
    * 1024
)


class PcapValidationError(
    ValueError
):
    pass


@dataclass
class PcapValidationResult:
    path: Path
    size_bytes: int
    extension: str
    is_large: bool
    format_name: str


def _detect_capture_format(
    path: Path,
):
    try:
        with path.open(
            "rb"
        ) as handle:
            magic = handle.read(
                4
            )
    except OSError as error:
        raise PcapValidationError(
            "PCAP dosyasının başlığı "
            "okunamadı."
        ) from error

    if magic in PCAP_MAGIC_VALUES:
        return "PCAP"

    if magic == PCAPNG_MAGIC:
        return "PCAPNG"

    raise PcapValidationError(
        "Dosya geçerli bir PCAP/PCAPNG "
        "başlığı içermiyor."
    )


def validate_pcap_file(
    file_path,
):
    path = Path(
        file_path
    ).expanduser()

    try:
        path = path.resolve(
            strict=True
        )
    except FileNotFoundError as error:
        raise PcapValidationError(
            "Seçilen dosya bulunamadı."
        ) from error

    if not path.is_file():
        raise PcapValidationError(
            "Seçilen yol bir dosya değil."
        )

    extension = (
        path.suffix
        .lower()
    )

    if extension not in ALLOWED_EXTENSIONS:
        raise PcapValidationError(
            "Yalnızca .pcap ve .pcapng "
            "dosyaları desteklenir."
        )

    try:
        size_bytes = (
            path.stat()
            .st_size
        )
    except OSError as error:
        raise PcapValidationError(
            "Dosya boyutu okunamadı."
        ) from error

    if size_bytes <= 0:
        raise PcapValidationError(
            "PCAP dosyası boş."
        )

    if size_bytes < 4:
        raise PcapValidationError(
            "Dosya geçerli bir PCAP "
            "başlığı için çok küçük."
        )

    format_name = (
        _detect_capture_format(
            path
        )
    )

    return PcapValidationResult(
        path=path,
        size_bytes=size_bytes,
        extension=extension,
        is_large=(
            size_bytes
            >= LARGE_FILE_WARNING_BYTES
        ),
        format_name=format_name,
    )


def format_file_size(
    size_bytes,
):
    value = float(
        size_bytes
    )

    for unit in (
        "B",
        "KB",
        "MB",
        "GB",
    ):
        if value < 1024:
            return (
                f"{value:.2f} "
                f"{unit}"
            )

        value /= 1024

    return (
        f"{value:.2f} TB"
    )
