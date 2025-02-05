import os
import re
from time import strftime, localtime
from scapy.all import rdpcap, sniff

# Precompiled regexes for matching Player IDs and names.
ID_PATTERN = re.compile(r"[56][0-9a-f]0100[0-9a-f]{4}")
NAME_PATTERN = re.compile(r"^[A-Z][a-zA-Z0-9_]{2,15}$")


def decode_string(data):
    """Decode bytes using latin-1 and strip null characters."""
    return data.decode("latin-1").replace("\x00", "")


def extract_string(hex_str, offset, max_length):
    """
    Attempt to extract a string from a hexadecimal string.

    If the extracted substring (up to max_length characters) meets the expected
    pattern (based on null-termination rules), decode and return it; otherwise,
    return -1.
    """
    # If the first byte (2 hex digits) is "00", nothing to extract.
    if hex_str[offset : offset + 2] == "00":
        return -1

    actual_length = max_length
    # Check every 2-byte segment (4 hex digits) for a null terminator.
    for pos in range(offset + 2, offset + max_length - 2, 4):
        # If the previous two hex digits are "00", we have reached the terminator.
        if hex_str[pos - 2 : pos] == "00":
            actual_length = pos - offset
            break
        # If the current two hex digits are not "00", the format is invalid.
        if hex_str[pos : pos + 2] != "00":
            return -1

    # Ensure we do not overrun the string.
    segment = hex_str[offset : offset + min(len(hex_str) - offset, actual_length)]
    try:
        return decode_string(bytes.fromhex(segment))
    except ValueError:
        return -1


# Keep leftover payload from previous packets.
last_payload = ""


def handle_packet(pkt):
    """Process one packet: extract matching data and print log lines."""
    global last_payload

    # Skip packets that do not have the needed IP/TCP payload.
    if "IP" not in pkt or "TCP" not in pkt or not hasattr(pkt["TCP"].payload, "load"):
        return

    # Combine leftover payload from previous packet(s) with the current payload.
    hex_payload = last_payload + bytes(pkt["TCP"].payload).hex()
    payload_length = len(hex_payload)
    pos = 0

    # Find all indices in the hex payload that match the ID pattern.
    id_indices = [m.start() for m in ID_PATTERN.finditer(hex_payload)]
    current_match = 0

    # Process the payload in 600-character chunks.
    while pos + 600 <= payload_length:
        # Skip past any ID matches that occur before our current position.
        while current_match < len(id_indices) and id_indices[current_match] < pos:
            current_match += 1
        if current_match >= len(id_indices):
            break

        # Choose the candidate: the last ID match within the next 600 characters.
        candidate = id_indices[current_match]
        while (
                current_match + 1 < len(id_indices)
                and id_indices[current_match + 1] < candidate + 600
        ):
            current_match += 1
            candidate = id_indices[current_match]
        pos = candidate

        # If there isn’t enough data left, stop processing.
        if pos + 600 > payload_length:
            break

        segment = hex_payload[pos : pos + 600]
        names = []
        i = 0
        # Look for valid names in 64-character blocks.
        while i < 600:
            s = extract_string(segment, i, 64)
            if s == -1:
                i += 1
                continue
            if NAME_PATTERN.match(s):
                names.append(f"{s} {i}")
                i += 64
            else:
                i += 1

        # If exactly 5 valid names were found, print a log line
        if len(names) == 5:
            timestamp = strftime("%I:%M:%S", localtime(int(pkt.time)))
            print(f"{segment[:10]},{timestamp},{','.join(names)},{segment}", flush=True)
            pos += 600
        else:
            pos += 1

    # Save any leftover hex payload for the next packet.
    last_payload = hex_payload[pos:]


def open_pcap(file_path):
    """Process the given pcap file."""
    if not file_path or not os.path.isfile(file_path):
        print("Invalid file")
        return

    print(f"Reading {file_path}")
    if os.name == "nt":
        print("Loading file into RAM. This may take a while.")
        for pkt in rdpcap(file_path):
            handle_packet(pkt)
    else:
        sniff(offline=file_path, filter="tcp", prn=handle_packet, store=0)

    print("Finished processing pcap. You can close this window now.")

# Run the pcap processor.
if __name__ == "__main__":
    file_path = input("Enter the path to the pcap file: ").strip()
    open_pcap(file_path)