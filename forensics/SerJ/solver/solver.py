

import argparse
import json
import re
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCAPY_DIR = ROOT / "scapy"
if str(SCAPY_DIR) not in sys.path:
    sys.path.insert(0, str(SCAPY_DIR))

from scapy.all import bind_layers, load_layer, sniff
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import TCP
from scapy.sessions import TCPSession

AES_KEY = b"itc{oushou_n_takhsayt_??!_YESSSS"


def _strip_bearer_token(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode("ascii", "ignore")
    else:
        text = str(value)
    match = re.match(r"Bearer\s+([A-Za-z0-9._-]+)", text)
    if not match:
        return None
    return match.group(1)


def extract_chunks(pcap_file):
    load_layer("http")
    bind_layers(TCP, HTTP, dport=5000)
    bind_layers(TCP, HTTP, sport=5000)

    packets = sniff(
        offline=str(pcap_file),
        session=TCPSession,
        store=True,
    )

    token_parts = []
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        if not packet.haslayer(HTTPRequest):
            continue
        if packet[TCP].dport != 5000:
            continue

        request = packet[HTTPRequest]
        path = request.getfieldval("Path")
        if path is None or not path.startswith(b"/inbox"):
            continue

        authorization = request.getfieldval("Authorization")
        token = _strip_bearer_token(authorization)
        if token is None:
            continue

        parts = token.split(".")
        if len(parts) != 3:
            continue

        token_parts.extend(parts)

    if not token_parts:
        raise ValueError("No chunked Authorization tokens found in the capture")

    encoded = "".join(token_parts)
    if len(encoded) % 2:
        raise ValueError(f"Odd-length exfil payload: {len(encoded)}")

    try:
        compressed = bytes.fromhex(encoded)
        json_blob = zlib.decompress(compressed)
    except Exception as error:
        raise ValueError(f"Failed to reconstruct exfil stream: {error}") from error

    return json.loads(json_blob)


def decrypt_document(payload):
    if not isinstance(payload, dict):
        raise ValueError("Recovered payload is not a JSON object")

    data = payload.get("data")
    if not isinstance(data, str):
        raise ValueError("Recovered payload does not contain a hex-encoded data field")

    encrypted = bytes.fromhex(data)
    if len(encrypted) < 16:
        raise ValueError("Recovered payload is too short to contain an IV")

    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    try:
        result = subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-256-cbc",
                "-d",
                "-K",
                AES_KEY.hex(),
                "-iv",
                iv.hex(),
            ],
            input=ciphertext,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("OpenSSL is required to decrypt the exfiltrated payload") from error

    if result.returncode != 0:
        error_text = result.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"AES decryption failed: {error_text.strip() or result.stdout[:80]!r}")

    return result.stdout


def choose_extension(blob):
    if blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if blob.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if blob.startswith(b"PK\x03\x04"):
        return ".zip"
    if blob.startswith(b"%PDF"):
        return ".pdf"
    return ".bin"


def main(pcap_file, output_dir):
    pcap_file = Path(pcap_file)
    output_dir = Path(output_dir)

    if not pcap_file.exists():
        print(f"PCAP file not found: {pcap_file}")
        return 1

    if not pcap_file.is_file():
        print(f"PCAP path is not a file: {pcap_file}")
        return 1

    try:
        payload = extract_chunks(pcap_file)
        recovered = decrypt_document(payload)
    except Exception as error:
        print(f"Failed to read PCAP: {error}")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    filename = output_dir / f"recovered_document{choose_extension(recovered)}"
    filename.write_bytes(recovered)
    print(f"Recovered {filename} ({len(recovered)} bytes)")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "pcap",
        type=Path,
        help="capture.pcapng",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("recovered_files"),
        help="Output directory, default: recovered_files",
    )

    arguments = parser.parse_args()

    raise SystemExit(
        main(
            arguments.pcap,
            arguments.output,
        )
    )


