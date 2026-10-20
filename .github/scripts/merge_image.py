#!/usr/bin/env python3
"""Write the esptool merge_bin arguments for one PlatformIO ESP32-S3 build.

Usage: merge_image.py <build_dir>

ESP-IDF writes <build_dir>/flash_args: the first line holds the flash options, then one "offset file" pair per
line. PlatformIO places the finished images at the top of the build dir under other names, so map them:
  bootloader image -> bootloader.bin, partition table -> partitions.bin, application -> firmware.bin.

Also validates binary partitions.bin directly:
  1. The 'factory' app partition offset in partitions.bin MUST match the app offset in flash_args.
  2. The custom 'part0' flash storage partition (type 0x40, subtype 0x01) MUST exist in partitions.bin
     (otherwise low_flash_init() crashes on boot before USB or LED initialisation).
Writes <build_dir>/merge_args.txt. Exits non-zero if anything is missing or mismatched.
"""
import os
import struct
import sys


def parse_partitions_bin(data: bytes) -> list[dict]:
    entries = []
    for pos in range(0, len(data), 32):
        chunk = data[pos : pos + 32]
        if len(chunk) < 32:
            break
        magic = chunk[0:2]
        if magic == b"\xeb\xeb" or magic == b"\xff\xff":
            break
        if magic != b"\xaa\x50":
            continue
        ptype, subtype, offset, size = struct.unpack("<BBII", chunk[2:12])
        name = chunk[12:28].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        entries.append(
            {
                "name": name,
                "type": ptype,
                "subtype": subtype,
                "offset": offset,
                "size": size,
            }
        )
    return entries


def main() -> int:
    build = sys.argv[1]
    with open(os.path.join(build, "flash_args")) as fp:
        lines = [line.split() for line in fp if line.strip()]
    opts, entries = lines[0], lines[1:]
    pairs = []
    app_offset = None
    for offset, name in entries:
        if "bootloader" in name:
            src = "bootloader.bin"
        elif "partition" in name:
            src = "partitions.bin"
        else:
            src = "firmware.bin" if os.path.exists(os.path.join(build, "firmware.bin")) else os.path.basename(name)
            app_offset = int(offset, 0)
        pairs += [offset, src]
    for src in pairs[1::2]:
        if not os.path.exists(os.path.join(build, src)):
            print("missing image file in build dir: " + src)
            return 1

    part_path = os.path.join(build, "partitions.bin")
    with open(part_path, "rb") as pfp:
        parts = parse_partitions_bin(pfp.read())

    factory_parts = [p for p in parts if p["type"] == 0x00 and p["name"] == "factory"]
    if not factory_parts:
        print("fatal: no 'factory' app partition found in partitions.bin:", parts)
        return 1
    if app_offset is not None and factory_parts[0]["offset"] != app_offset:
        print(
            f"fatal: factory partition offset in partitions.bin (0x{factory_parts[0]['offset']:x}) "
            f"!= app offset in flash_args (0x{app_offset:x})"
        )
        return 1

    part0_parts = [p for p in parts if p["type"] == 0x40 and p["subtype"] == 0x01 and p["name"] == "part0"]
    if not part0_parts:
        print("fatal: missing 'part0' (0x40/0x01) partition in partitions.bin — firmware will panic in low_flash_init()!", parts)
        return 1

    args = " ".join(opts + pairs)
    with open(os.path.join(build, "merge_args.txt"), "w") as fp:
        fp.write(args)
    print("verified partitions:", parts)
    print("merge args: " + args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
