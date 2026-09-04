from pathlib import Path


output_path = (
    Path(
        "data/test_pcaps"
    )
    / "malformed_test.pcap"
)

output_path.parent.mkdir(
    parents=True,
    exist_ok=True,
)

output_path.write_bytes(
    b"NOT_A_VALID_PCAP_FILE"
)

print(
    "Malformed PCAP test file created:"
)
print(
    output_path
)
