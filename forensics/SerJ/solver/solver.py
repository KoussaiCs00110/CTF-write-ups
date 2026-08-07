import argparse
import json
import re
import subprocess
import zlib
from pathlib import Path

from scapy.all import bind_layers, load_layer, sniff
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import TCP
from scapy.sessions import TCPSession


C2_PORT = 5000
AES_KEY = b"itc{oushou_n_takhsayt_??!_YESSSS}"


def get_token(value):
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")

    match = re.match(
        r"Bearer\s+([A-Za-z0-9.*-]+)",
        str(value)
    )

    if match:
        return match.group(1)

    return None
def extract_chunks(pcap_file):
    load_layer("http")

    bind_layers(TCP, HTTP, dport=C2_PORT)
    bind_layers(TCP, HTTP, sport=C2_PORT)

    packets = sniff(
        offline=str(pcap_file),
        session=TCPSession,
        store=True
    )

    parts = []

    for packet in packets:

        if HTTPRequest not in packet:
            continue

        request = packet[HTTPRequest]

        path = request.getfieldval("Path")

        if not path.startswith(b"/inbox"):
            continue

        authorization = request.getfieldval("Authorization")

        token = get_token(authorization)

        if token is None:
            continue

        token_parts = token.split(".")

        if len(token_parts) != 3:
            continue

        parts.extend(token_parts)

    data = "".join(parts)

    compressed = bytes.fromhex(data)

    json_data = zlib.decompress(compressed)

    return json.loads(json_data)


def decrypt_document(payload):

    encrypted = bytes.fromhex(payload["data"])

    iv = encrypted[:16]
    ciphertext = encrypted[16:]

    result = subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-d",
            "-K",
            AES_KEY.hex(),
            "-iv",
            iv.hex()
        ],
        input=ciphertext,
        capture_output=True
    )

    return result.stdout


def main(pcap_file, output_dir):

    payload = extract_chunks(pcap_file)

    recovered = decrypt_document(payload)

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = output_dir / "recovered_document.bin"

    output_file.write_bytes(recovered)

    print("Recovered:", output_file)
    print("Size:", len(recovered), "bytes")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "pcap",
        type=Path
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("recovered_files")
    )

    args = parser.parse_args()

    main(args.pcap, args.output)
