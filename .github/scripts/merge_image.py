#!/usr/bin/env python3
"""Write the esptool merge_bin arguments for one PlatformIO ESP32-S3 build.

Usage: merge_image.py <build_dir>

ESP-IDF writes <build_dir>/flash_args: the first line holds the flash options, then one "offset file" pair per
line. The files named there sit in ESP-IDF sub-directories that PlatformIO does not link. PlatformIO places the
finished images at the top of the build dir under other names, so map them:
  bootloader image -> bootloader.bin, partition table -> partitions.bin, application -> firmware.bin.
Writes <build_dir>/merge_args.txt. Exits non-zero if an image is missing.
"""
import os
import sys


def main() -> int:
    build = sys.argv[1]
    with open(os.path.join(build, "flash_args")) as fp:
        lines = [line.split() for line in fp if line.strip()]
    opts, entries = lines[0], lines[1:]
    pairs = []
    for offset, name in entries:
        if "bootloader" in name:
            src = "bootloader.bin"
        elif "partition" in name:
            src = "partitions.bin"
        else:
            src = "firmware.bin" if os.path.exists(os.path.join(build, "firmware.bin")) else os.path.basename(name)
        pairs += [offset, src]
    for src in pairs[1::2]:
        if not os.path.exists(os.path.join(build, src)):
            print("missing image file in build dir: " + src)
            return 1
    args = " ".join(opts + pairs)
    with open(os.path.join(build, "merge_args.txt"), "w") as fp:
        fp.write(args)
    print("merge args: " + args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
