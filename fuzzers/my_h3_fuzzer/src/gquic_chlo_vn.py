#!/usr/bin/env python3
import argparse
import binascii
import ipaddress
import os
import socket
import struct
import time
from typing import List, Sequence, Tuple, Optional


DEFAULT_PACKET_TYPE = 0xC3           # Match the working sample
DEFAULT_VERSION = "Q046"
DEFAULT_PACKET_NUMBER = 1
DEFAULT_PACKET_LEN = 1250
DEFAULT_STREAM_FRAME_TYPE = 0x80     # non-v41: stream, no fin, no data len, no offset, 1-byte stream id
DEFAULT_STREAM_ID = 0x01             # crypto stream
DEFAULT_CID_LEN_BYTE = 0x50          # literal from the working sample; 0x50 is the cleaner logical value


def normalize_tag(tag: str | bytes) -> bytes:
    if isinstance(tag, str):
        tag = tag.encode("ascii")
    if len(tag) != 4:
        raise ValueError(f"tag must be exactly 4 bytes: {tag!r}")
    return tag


def normalize_version(version: str | bytes) -> bytes:
    raw = normalize_tag(version)
    if raw[0:1] != b"Q" and raw != b"ZZZZ":
        # keep permissive for probing
        pass
    return raw


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hx:<{width*3}}  {asc}")
    return "\n".join(lines)


def le_u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xffffffff)


def be_u32(v: int) -> bytes:
    return struct.pack(">I", v & 0xffffffff)


def be_u64(v: int) -> bytes:
    return struct.pack(">Q", v & 0xffffffffffffffff)


def maybe_default_sni(host: str) -> Optional[str]:
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def tag_sort_key(tag: bytes) -> int:
    return struct.unpack("<I", tag)[0]


def build_chlo(
    version: str,
    sni: Optional[str],
    pdmd: bytes = b"X509",
    icsl: int = 600,
    nonp: Optional[bytes] = None,
    mids: int = 0,
    csct: bytes = b"",
    cfcw: int = 0x0000F000,
    sfcw: int = 0x00006000,
) -> bytes:
    """
    Build a sample-like gQUIC CHLO:

        CHLO
        num_entries (LE16)
        padding 0
        repeated (tag, end_offset_le32)
        values blob

    Tag set aligned with the working sample:
        SNI\0, VER\0, PDMD, ICSL, NONP, MIDS, CSCT, CFCW, SFCW
    """
    if nonp is None:
        nonp = os.urandom(32)
    if len(nonp) != 32:
        raise ValueError("NONP must be 32 bytes")

    pairs: List[Tuple[bytes, bytes]] = []

    if sni is not None:
        pairs.append((b"SNI\x00", sni.encode("ascii")))
    pairs.append((b"VER\x00", normalize_version(version)))
    pairs.append((b"PDMD", pdmd))
    pairs.append((b"ICSL", le_u32(icsl)))
    pairs.append((b"NONP", nonp))
    pairs.append((b"MIDS", le_u32(mids)))
    pairs.append((b"CSCT", csct))
    pairs.append((b"CFCW", le_u32(cfcw)))
    pairs.append((b"SFCW", le_u32(sfcw)))

    pairs.sort(key=lambda kv: tag_sort_key(kv[0]))

    out = bytearray()
    out += b"CHLO"
    out += struct.pack("<H", len(pairs))
    out += b"\x00\x00"

    end_offset = 0
    values = bytearray()

    for tag, value in pairs:
        out += tag
        end_offset += len(value)
        out += le_u32(end_offset)
        values += value

    out += values
    return bytes(out)


def build_stream_frame_tail(chlo: bytes, stream_type: int = DEFAULT_STREAM_FRAME_TYPE, stream_id: int = DEFAULT_STREAM_ID) -> bytes:
    """
    Tail format in the working sample:
        0x80 0x01 CHLO...
    """
    if not 0 <= stream_type <= 0xff:
        raise ValueError("stream_type must be a byte")
    if not 0 <= stream_id <= 0xff:
        raise ValueError("stream_id must fit in 1 byte")
    return bytes([stream_type, stream_id]) + chlo


def build_sample_like_initial_packet(
    version: str,
    connection_id: int,
    packet_number: int,
    chlo: bytes,
    packet_len: int = DEFAULT_PACKET_LEN,
    packet_type: int = DEFAULT_PACKET_TYPE,
    cid_len_byte: int = DEFAULT_CID_LEN_BYTE,
) -> bytes:
    """
    Packet layout matched to the provided working sample:

        1B   type                  (0xc3 in the sample)
        4B   version               ("Q046")
        8B   destination CID       (big-endian, to match the sample)
        1B   CID length byte       (sample shows 0x59; configurable)
        4B   packet number         (big-endian)
        N    zero padding
        1B   stream frame type     (0x80)
        1B   stream id             (0x01)
        ...  CHLO

    Total UDP payload defaults to 1292 bytes.
    """
    version_bytes = normalize_version(version)
    if not 0 <= packet_type <= 0xff:
        raise ValueError("packet_type must be a byte")
    if not 0 <= cid_len_byte <= 0xff:
        raise ValueError("cid_len_byte must be a byte")

    header = bytearray()
    header.append(packet_type)
    header += version_bytes
    header.append(cid_len_byte)
    header += be_u64(connection_id)
    header += be_u32(packet_number)

    tail = build_stream_frame_tail(chlo)
    if len(header) + len(tail) > packet_len:
        raise ValueError(
            f"packet too small: header({len(header)}) + tail({len(tail)}) > packet_len({packet_len})"
        )

    pad_len = packet_len - len(header) - len(tail)
    payload = (b"\x00" * pad_len) + tail
    return bytes(header + payload)


def parse_possible_version_negotiation(data: bytes) -> Optional[List[str]]:
    """
    Lightweight parser for a possible response that starts with:
        type/versionish ... version tags...
    This is intentionally loose and only meant for quick inspection.
    """
    if len(data) < 8:
        return None

    versions = []
    for i in range(0, len(data) - 3):
        chunk = data[i:i + 4]
        if chunk[:1] == b"Q" and all(32 <= b <= 126 for b in chunk):
            try:
                versions.append(chunk.decode("ascii"))
            except UnicodeDecodeError:
                pass

    versions = list(dict.fromkeys(versions))
    return versions or None


def recv_some(sock: socket.socket, timeout: float, max_packets: int) -> None:
    deadline = time.time() + timeout
    count = 0

    while count < max_packets and time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sock.settimeout(remaining)

        try:
            data, peer = sock.recvfrom(65535)
        except socket.timeout:
            break

        count += 1
        print(f"[<] recv #{count} from {peer[0]}:{peer[1]}  len={len(data)}")
        print(hexdump(data))

        hinted = parse_possible_version_negotiation(data)
        if hinted:
            print(f"[+] possible version tags seen in response: {hinted}")

        for marker in (b"REJ", b"SHLO", b"CHLO", b"PRST"):
            if marker in data:
                print(f"[+] marker found: {marker!r}")
        print()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Build and send a sample-like gQUIC Q046 Initial packet with tail-padded CHLO"
    )
    ap.add_argument("host")
    ap.add_argument("port", type=int)

    ap.add_argument("--version", default=DEFAULT_VERSION, help="4-byte version tag, e.g. Q046")
    ap.add_argument("--sni", default=None, help="SNI value; default uses host if host is not an IP")
    ap.add_argument("--connection-id", default=None, help="64-bit CID in hex, e.g. 0x509086af2c8e197f")
    ap.add_argument("--packet-number", type=int, default=DEFAULT_PACKET_NUMBER)
    ap.add_argument("--packet-len", type=int, default=DEFAULT_PACKET_LEN)
    ap.add_argument("--packet-type", type=lambda x: int(x, 0), default=DEFAULT_PACKET_TYPE)
    ap.add_argument("--cid-len-byte", type=lambda x: int(x, 0), default=DEFAULT_CID_LEN_BYTE)

    ap.add_argument("--pdmd", default="X509")
    ap.add_argument("--icsl", type=int, default=600)
    ap.add_argument("--nonp", default=None, help="32-byte NONP as hex; default random")
    ap.add_argument("--mids", type=int, default=0)
    ap.add_argument("--cfcw", type=lambda x: int(x, 0), default=0x0000F000)
    ap.add_argument("--sfcw", type=lambda x: int(x, 0), default=0x00006000)
    ap.add_argument("--csct-hex", default="", help="hex bytes for CSCT value, default empty")

    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--recv-packets", type=int, default=3)
    ap.add_argument("--save-packet", default=None, help="save raw packet bytes to file")

    args = ap.parse_args()

    version = args.version
    normalize_version(version)

    sni = args.sni
    if sni is None:
        sni = maybe_default_sni(args.host)

    if args.connection_id is None:
        connection_id = struct.unpack(">Q", os.urandom(8))[0]
    else:
        connection_id = int(args.connection_id, 0)

    if args.nonp is None:
        nonp = os.urandom(32)
    else:
        nonp = binascii.unhexlify(args.nonp)
        if len(nonp) != 32:
            raise ValueError("--nonp must decode to exactly 32 bytes")

    csct = binascii.unhexlify(args.csct_hex) if args.csct_hex else b""
    pdmd = args.pdmd.encode("ascii")
    if len(pdmd) != 4:
        raise ValueError("--pdmd must be exactly 4 ASCII bytes")

    chlo = build_chlo(
        version=version,
        sni=sni,
        pdmd=pdmd,
        icsl=args.icsl,
        nonp=nonp,
        mids=args.mids,
        csct=csct,
        cfcw=args.cfcw,
        sfcw=args.sfcw,
    )

    packet = build_sample_like_initial_packet(
        version=version,
        connection_id=connection_id,
        packet_number=args.packet_number,
        chlo=chlo,
        packet_len=args.packet_len,
        packet_type=args.packet_type,
        cid_len_byte=args.cid_len_byte,
    )

    print(f"[+] target            = {args.host}:{args.port}")
    print(f"[+] version           = {version}")
    print(f"[+] sni               = {sni!r}")
    print(f"[+] connection_id     = 0x{connection_id:016x}")
    print(f"[+] packet_number     = {args.packet_number}")
    print(f"[+] packet_type       = 0x{args.packet_type:02x}")
    print(f"[+] cid_len_byte      = 0x{args.cid_len_byte:02x}")
    print(f"[+] packet_len        = {len(packet)}")
    print(f"[+] chlo_len          = {len(chlo)}")
    print(f"[+] nonp              = {nonp.hex()}")
    print()

    print("[+] CHLO bytes:")
    print(hexdump(chlo))
    print()

    print("[+] Full packet bytes:")
    print(hexdump(packet))
    print()

    if args.save_packet:
        with open(args.save_packet, "wb") as f:
            f.write(packet)
        print(f"[+] saved packet to {args.save_packet}")
        print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (args.host, args.port))
    print("[>] packet sent")
    print()

    recv_some(sock, timeout=args.timeout, max_packets=args.recv_packets)


if __name__ == "__main__":
    main()